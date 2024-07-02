/*
 * Copyright (C) 2022 Jo-Philipp Wich <jo@mein.io>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <assert.h>
#include <fnmatch.h>

#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libubox/usock.h>
#include <libubox/utils.h>

#include "client.h"
#include "http.h"
#include "file.h"
#include "state.h"
#include "auth.h"
#include "log.h"
#include "script.h"
#include "config.h"
#include "io.h"

#define HTTP_METHOD(name) { #name, HTTP_##name }

/* NB: order must be in sync with uwsd_http_method_t of http.h */
static struct {
	const char *name;
	uwsd_http_method_t method;
} http_request_methods[] = {
	HTTP_METHOD(GET),
	HTTP_METHOD(POST),
	HTTP_METHOD(PUT),
	HTTP_METHOD(HEAD),
	HTTP_METHOD(OPTIONS),
	HTTP_METHOD(DELETE),
	HTTP_METHOD(TRACE),
	HTTP_METHOD(CONNECT),
};

#undef HTTP_METHOD

static const char *
http_state_name(uwsd_http_state_t state)
{
#ifndef NDEBUG
# define STATE(name)	#name
	const char *statenames[] = {
		HTTP_STATE_LIST
	};

	return statenames[state];
# undef STATE
#else
	return NULL;
#endif
}

static void
http_state_transition(uwsd_client_context_t *cl, uwsd_http_state_t state)
{
	uwsd_http_debug(cl, "state %s -> %s",
		http_state_name(cl->http.state),
		http_state_name(state));

	cl->http.state = state;
}

static void
http_state_reset(uwsd_client_context_t *cl, uwsd_http_state_t state)
{
	/* Free previous request data */
	while (cl->http_num_headers > 0)
		free(cl->http_headers[--cl->http_num_headers].name);

	free(cl->http_headers);
	free(cl->request_uri);

	cl->http_status = 0;
	cl->http_headers = NULL;
	cl->request_uri = NULL;
	cl->request_method = HTTP_GET;
	cl->request_length = 0;
	cl->head_length = 0;

	/* Reset buffer state */
	uwsd_io_reset(&cl->downstream);
	uwsd_io_reset(&cl->upstream);

	cl->http.request_flags = 0;
	cl->http.response_flags = 0;

	if (cl->http.pipebuf[0] > -1)
		close(cl->http.pipebuf[0]);

	if (cl->http.pipebuf[1] > -1)
		close(cl->http.pipebuf[1]);

	cl->http.pipebuf[0] = -1;
	cl->http.pipebuf[1] = -1;

	/* Transition to initial HTTP parsing state */
	http_state_transition(cl, state);
}

static bool
http_header_parse(uwsd_client_context_t *cl, char *line, size_t len)
{
	char *name, *value, *p, *e = line + len;
	uwsd_http_header_t *hdr = NULL;
	bool continuation;
	size_t i, j;

	/* Is a header line continuation? */
	if (*line == ' ' || *line == '\t') {
		if (cl->http_num_headers == 0)
			return false;

		hdr = &cl->http_headers[cl->http_num_headers - 1];
		value = line;
		continuation = true;
	}
	else {
		/* Is a normal header line */
		name = (char *)line;
		p = name + memcspn(name, e - name, ":");

		if (p == name || p == e || *p != ':')
			return false;

		/* Header name already seen? */
		for (i = 0; i < cl->http_num_headers; i++) {
			if (!strncasecmp(cl->http_headers[i].name, name, p - name) &&
			    cl->http_headers[i].name[p - name] == '\0') {
				hdr = &cl->http_headers[i];
				break;
			}
		}

		/* Not seen yet, add new header entry */
		if (!hdr) {
			cl->http_headers = xrealloc(cl->http_headers,
				sizeof(uwsd_http_header_t) * (cl->http_num_headers + 1));

			hdr = &cl->http_headers[cl->http_num_headers++];
			hdr->name = xalloc((p - name) + 1);
			hdr->value = NULL;

			for (i = 0; i < (size_t)(p - name); i++)
				hdr->name[i] = name[i];
		}

		value = (char *)++p;
		continuation = false;
	}

	/* Skip leading white space in value */
	for (; *value == ' ' || *value == '\t'; value++)
		;

	/* Skip trailing white space in value */
	for (; e > value && (e[-1] == ' ' || e[-1] == '\t'); e--)
		;

	/* If new header, set value... */
	if (!hdr->value) {
		i = strlen(hdr->name);
		hdr->name = xrealloc(hdr->name, i + 1 + (e - value) + 1);
		hdr->value = hdr->name + i + 1;
		memcpy(hdr->value, value, e - value);
		hdr->value[e - value] = '\0';
	}
	/* ... otherwise append */
	else {
		i = strlen(hdr->name);
		j = strlen(hdr->value);
		hdr->name = xrealloc(hdr->name, i + 1 + j + 2 + !continuation);
		hdr->value = hdr->name + i + 1;

		if (!continuation)
			hdr->value[j++] = ',';

		hdr->value[j++] = ' ';
		memcpy(hdr->value + j, value, e - value);
		hdr->value[j + (e - value)] = '\0';
	}

	return true;
}

static uint8_t
hex(uint8_t byte)
{
	if (byte <= '9')
		return byte - '0';

	if (byte <= 'F')
		return byte - 'A' + 10;

	return byte - 'a' + 10;
}

static bool
http_may_have_body(uint16_t code)
{
	switch (code) {
	case 204:
	case 205:
	case 304:
		return false;
	}

	return true;
}

static bool
http_is_hop_by_hop_header(uwsd_http_header_t *hdr)
{
	return (!strcasecmp(hdr->name, "Status") ||  /* only valid for CGI responses */
	        !strcasecmp(hdr->name, "Keep-Alive") ||
	        !strcasecmp(hdr->name, "Transfer-Encoding") ||
	        !strcasecmp(hdr->name, "TE") ||
	        !strcasecmp(hdr->name, "Connection") ||
	        !strcasecmp(hdr->name, "Trailer") ||
	        !strcasecmp(hdr->name, "Upgrade") ||
	        !strcasecmp(hdr->name, "Proxy-Authorization") ||
	        !strcasecmp(hdr->name, "Proxy-Authenticate"));
}

static bool
http_handle_body_data(uwsd_client_context_t *cl, uwsd_connection_t *conn, void *data, size_t len)
{
	uwsd_action_t *action = cl->action;
	size_t buflen;
	char *buf;

	uwsd_http_debug(cl, "%s body data chunk %zd bytes",
		conn->upstream ? "response" : "request",
		len);

	if (conn == &cl->upstream) {
		if (cl->http.response_flags & HTTP_SEND_CHUNKED) {
			uwsd_io_reset(&cl->downstream);
			uwsd_io_printf(&cl->downstream, "%zx\r\n\r\n", len);

			buf = uwsd_io_getbuf(&cl->downstream);
			buflen = uwsd_io_offset(&cl->downstream);

			uwsd_iov_put(cl, buf, buflen - 2, data, len, buf + buflen - 2, 2);
		}
		else {
			uwsd_iov_put(cl, data, len);
		}
	}
	else {
		if (!action || action->type != UWSD_ACTION_SCRIPT) {
			if (cl->http.request_flags & HTTP_SEND_CHUNKED) {
				uwsd_io_reset(&cl->upstream);
				uwsd_io_printf(&cl->upstream, "%zx\r\n\r\n", len);

				buf = uwsd_io_getbuf(&cl->upstream);
				buflen = uwsd_io_offset(&cl->upstream);

				uwsd_iov_put(cl, buf, buflen - 2, data, len, buf + buflen - 2, 2);
			}
			else {
				uwsd_iov_put(cl, data, len);
			}
		}
		else {
			return uwsd_script_bodydata(cl, data, len);
		}
	}

	return true;
}

static bool
http_determine_message_length(uwsd_client_context_t *cl, bool request)
{
	uint32_t *flags = request ? &cl->http.request_flags : &cl->http.response_flags;
	char *clen, *tenc, *e;
	size_t hlen;

	tenc = uwsd_http_header_lookup(cl, "Transfer-Encoding");
	clen = uwsd_http_header_lookup(cl, "Content-Length");

	if (cl->http_version <= 0x1000 || uwsd_http_header_contains(cl, "Connection", "close"))
		*flags |= HTTP_WANT_CLOSE;

	if (tenc) {
		hlen = strlen(tenc);

		if (hlen < strlen("chunked") ||
		    strncasecmp(tenc + hlen - strlen("chunked"), "chunked", strlen("chunked")) ||
		    (hlen > strlen("chunked") && !strchr(", \r\t\n", tenc[hlen - strlen("chunked") - 1])))
		{
			uwsd_http_error_return(cl, 400, "Bad Request", "Invalid transfer encoding\n");
		}

		http_state_transition(cl, STATE_HTTP_CHUNK_HEADER);
	}
	else if (clen) {
		hlen = strtoull(clen, &e, 10);

		if (e == clen || *e != '\0')
			uwsd_http_error_return(cl, 400, "Bad Request", "Invalid content length\n");

		cl->request_length = hlen;
		http_state_transition(cl, STATE_HTTP_BODY_KNOWN_LENGTH);
	}
	else if (cl->http_version <= 0x1000 && cl->request_method == HTTP_POST) {
		uwsd_http_error_return(cl, 400, "Bad Request", "Content-Length required\n");
	}
	else if ((!request && http_may_have_body(cl->http_status)) &&
	         (cl->http_version <= 0x0100 || cl->action->type == UWSD_ACTION_SCRIPT)) {
		http_state_transition(cl, STATE_HTTP_BODY_UNTIL_EOF);
	}
	else {
		http_state_transition(cl, STATE_HTTP_REQUEST_DONE);
	}

	return true;
}

static bool
http_chunked_recv(uwsd_client_context_t *cl, uwsd_connection_t *conn)
{
	char *data = uwsd_io_getpos(conn);
	int ch;

	while (true) {
		ch = uwsd_io_getc(conn);

		if (ch == EOF)
			break;

		switch (cl->http.state) {
		case STATE_HTTP_CHUNK_HEADER:
			if (isxdigit(ch)) {
				cl->request_length = cl->request_length * 16 + hex(ch);
			}
			else if (ch == ';') {
				http_state_transition(cl, STATE_HTTP_CHUNK_HEADER_EXT);
			}
			else if (ch == '\r') {
				http_state_transition(cl, STATE_HTTP_CHUNK_HEADER_LF);
			}
			else {
				client_free(cl, "invalid chunk header [%02x]", ch);

				return false;
			}

			break;

		case STATE_HTTP_CHUNK_HEADER_EXT:
			if (ch == '\r')
				http_state_transition(cl, STATE_HTTP_CHUNK_HEADER_LF);

			break;

		case STATE_HTTP_CHUNK_HEADER_LF:
			if (ch == '\n') {
				data = uwsd_io_getpos(conn);
				http_state_transition(cl, cl->request_length ? STATE_HTTP_CHUNK_DATA : STATE_HTTP_CHUNK_TRAILER);
			}
			else {
				client_free(cl, "invalid chunk header [%02x]", ch);

				return false;
			}

			break;

		case STATE_HTTP_CHUNK_DATA:
			if (--cl->request_length == 0) {
				if (!http_handle_body_data(cl, conn, data, uwsd_io_getpos(conn) - data))
					return false;

				http_state_transition(cl, STATE_HTTP_CHUNK_DATA_CR);

				return true;
			}

			break;

		case STATE_HTTP_CHUNK_DATA_CR:
			if (ch == '\r') {
				http_state_transition(cl, STATE_HTTP_CHUNK_DATA_LF);
			}
			else {
				client_free(cl, "invalid chunk trailer");

				return false;
			}

			break;

		case STATE_HTTP_CHUNK_DATA_LF:
			if (ch == '\n') {
				http_state_transition(cl, STATE_HTTP_CHUNK_HEADER);
			}
			else {
				client_free(cl, "invalid chunk trailer");

				return false;
			}

			break;

		case STATE_HTTP_CHUNK_TRAILER:
			if (ch == '\r')
				http_state_transition(cl, STATE_HTTP_CHUNK_TRAILER_LF);
			else
				http_state_transition(cl, STATE_HTTP_CHUNK_TRAILLINE);

			break;

		case STATE_HTTP_CHUNK_TRAILER_LF:
			if (ch == '\n') {
				http_state_transition(cl, STATE_HTTP_CHUNK_DONE);
			}
			else {
				client_free(cl, "invalid chunk trailer");

				return false;
			}

			break;

		case STATE_HTTP_CHUNK_TRAILLINE:
			if (ch == '\r')
				http_state_transition(cl, STATE_HTTP_CHUNK_TRAILLINE_LF);

			break;

		case STATE_HTTP_CHUNK_TRAILLINE_LF:
			if (ch == '\n') {
				http_state_transition(cl, STATE_HTTP_CHUNK_TRAILER);
			}
			else {
				client_free(cl, "invalid chunk trailer");

				return false;
			}

			break;

		default:
			client_free(cl, "Unexpected HTTP parse state: %s", http_state_name(cl->http.state));

			return false;
		}
	}

	if (cl->http.state == STATE_HTTP_CHUNK_DATA && uwsd_io_getpos(conn) > data)
		return http_handle_body_data(cl, conn, data, uwsd_io_getpos(conn) - data);

	return true;
}

static bool
http_contentlen_recv(uwsd_client_context_t *cl, uwsd_connection_t *conn)
{
	size_t rlen;

	rlen = size_t_min(uwsd_io_pending(conn), cl->request_length);

	if (rlen && !http_handle_body_data(cl, conn, uwsd_io_getpos(conn), rlen))
		return false;

	cl->request_length -= rlen;
	uwsd_io_consume(conn, rlen);

	if (cl->request_length == 0)
		http_state_transition(cl, STATE_HTTP_REQUEST_DONE);

	return true;
}

static bool
http_untileof_recv(uwsd_client_context_t *cl, uwsd_connection_t *conn)
{
	size_t rlen = uwsd_io_pending(conn);

	if (!rlen && uwsd_io_eof(conn))
		http_state_transition(cl, STATE_HTTP_REQUEST_DONE);

	if (!http_handle_body_data(cl, conn, uwsd_io_getpos(conn), rlen))
		return false;

	uwsd_io_consume(conn, rlen);

	return true;
}


static bool
http_request_recv(uwsd_client_context_t *cl)
{
	uwsd_connection_t *httpbuf = &cl->upstream;
	uwsd_connection_t *conn = &cl->downstream;
	size_t i, len;
	int ch;

	uwsd_http_debug(cl, "request receive, %zu byte pending", uwsd_io_pending(conn));

	switch (cl->http.state) {
	case STATE_HTTP_BODY_KNOWN_LENGTH:
		return http_contentlen_recv(cl, conn);

	case STATE_HTTP_CHUNK_HEADER:
	case STATE_HTTP_CHUNK_HEADER_EXT:
	case STATE_HTTP_CHUNK_HEADER_LF:
	case STATE_HTTP_CHUNK_DATA:
	case STATE_HTTP_CHUNK_DATA_CR:
	case STATE_HTTP_CHUNK_DATA_LF:
	case STATE_HTTP_CHUNK_TRAILER:
	case STATE_HTTP_CHUNK_TRAILLINE:
	case STATE_HTTP_CHUNK_TRAILLINE_LF:
	case STATE_HTTP_CHUNK_TRAILER_LF:
		return http_chunked_recv(cl, conn);

	case STATE_HTTP_CHUNK_DONE:
	case STATE_HTTP_REQUEST_DONE:
		http_state_transition(cl, STATE_HTTP_BODY_CLOSE);

		return http_handle_body_data(cl, conn, "", 0);

	case STATE_HTTP_BODY_CLOSE:
		uwsd_http_debug(cl, "Received %zd bytes after request message, pipeline request?",
			uwsd_io_pending(conn));

		return true;

	default:
		break;
	}

	while (true) {
		ch = uwsd_io_getc(conn);
		len = uwsd_io_offset(httpbuf);

		if (ch == EOF)
			break;

		if (cl->head_length++ == sizeof(httpbuf->buf.data))
			uwsd_http_error_return(cl, 431, "Request Header Fields Too Large", "Request header line too long\n");

		switch (cl->http.state) {
		case STATE_HTTP_REQUEST_METHOD:
			if (ch == ' ') {
				for (i = 0; i < ARRAY_SIZE(http_request_methods); i++) {
					if (!uwsd_io_strcmp(httpbuf, http_request_methods[i].name)) {
						cl->request_method = http_request_methods[i].method;
						break;
					}
				}

				if (i == ARRAY_SIZE(http_request_methods))
					uwsd_http_error_return(cl, 501, "Not Implemented", "Unsupported request method\n");

				http_state_transition(cl, STATE_HTTP_REQUEST_URI);
				uwsd_io_reset(httpbuf);
			}
			else {
				if (len >= strlen("CONNECT"))
					uwsd_http_error_return(cl, 501, "Not Implemented", "Unsupported request method\n");

				uwsd_io_putchar(httpbuf, ch);
			}

			break;

		case STATE_HTTP_REQUEST_URI:
			if (ch == '\n') {
				ch = '\r';
				uwsd_io_ungetc(conn);
			}

			if (ch == ' ' || ch == '\r') {
				assert(!cl->request_uri);

				cl->request_uri = uwsd_io_strdup(httpbuf);

				if (!cl->request_uri)
					uwsd_http_error_return(cl, 500, "Internal Server Error", "Out of memory\n");

				if (ch == '\r') {
					cl->http_version = 0x0009;
					http_state_transition(cl, STATE_HTTP_REQUESTLINE_LF);
				}
				else {
					http_state_transition(cl, STATE_HTTP_REQUEST_VERSION);
				}

				uwsd_io_reset(httpbuf);
			}
			else {
				if (len == 0 && isspace(ch))
					continue;

				if (!uwsd_io_putchar(httpbuf, ch))
					uwsd_http_error_return(cl, 414, "URI Too Long", "The reqested URI is too long\n");
			}

			break;

		case STATE_HTTP_REQUEST_VERSION:
			if (ch == '\n') {
				ch = '\r';
				uwsd_io_ungetc(conn);
			}

			if (ch == '\r') {
				if (!uwsd_io_strcmp(httpbuf, "HTTP/1.0"))
					cl->http_version = 0x0100;
				else if (!uwsd_io_strcmp(httpbuf, "HTTP/1.1"))
					cl->http_version = 0x0101;
				else
					uwsd_http_error_return(cl, 505, "HTTP Version Not Supported", "Requested protocol version not implemented\n");

				if (cl->http_version <= 0x0100 &&
				    cl->request_method != HTTP_GET &&
				    cl->request_method != HTTP_HEAD &&
				    cl->request_method != HTTP_POST)
					uwsd_http_error_return(cl, 501, "Not Implemented", "Request method not supported by HTTP/1.0\n");

				uwsd_http_info(cl, "> %s %s",
					http_request_methods[cl->request_method].name,
					cl->request_uri);

				http_state_transition(cl, STATE_HTTP_REQUESTLINE_LF);
				uwsd_io_reset(httpbuf);
			}
			else {
				if (len == 0 && isspace(ch))
					continue;

				if (len >= strlen("HTTP/1.1"))
					uwsd_http_error_return(cl, 505, "HTTP Version Not Supported", "Requested protocol version not implemented\n");

				uwsd_io_putchar(httpbuf, ch);
			}

			break;

		case STATE_HTTP_REQUESTLINE_LF:
			if (ch == '\n')
				http_state_transition(cl, STATE_HTTP_HEADERLINE);
			else
				uwsd_http_error_return(cl, 400, "Bad Request", "Invalid request line\n");

			break;

		case STATE_HTTP_HEADERLINE:
			if (ch == '\n') {
				ch = '\r';
				uwsd_io_ungetc(conn);
			}

			if (ch == '\r')
				http_state_transition(cl, STATE_HTTP_HEADERLINE_LF);
			else if (!uwsd_io_putchar(httpbuf, ch))
				uwsd_http_error_return(cl, 431, "Request Header Fields Too Large", "Request header line too long\n");

			break;

		case STATE_HTTP_HEADERLINE_LF:
			if (ch == '\n') {
				if (len) {
					if (!http_header_parse(cl, uwsd_io_getbuf(httpbuf), len))
						uwsd_http_error_return(cl, 400, "Bad Request", "Invalid header line\n");

					http_state_transition(cl, STATE_HTTP_HEADERLINE);
					uwsd_io_reset(httpbuf);
				}
				else {
					/* The following call will transition the state to body, chunked or done */
					return http_determine_message_length(cl, true);
				}
			}
			else {
				uwsd_http_error_return(cl, 400, "Bad Request", "Invalid header line\n");
			}

			break;

		default:
			client_free(cl, "Unexpected HTTP parse state: %s", http_state_name(cl->http.state));

			return false;
		}
	}

	return true;
}

static bool
http_response_recv(uwsd_client_context_t *cl)
{
	uwsd_connection_t *httpbuf = &cl->downstream;
	uwsd_connection_t *conn = &cl->upstream;
	size_t len;
	int ch;

	switch (cl->http.state) {
	case STATE_HTTP_BODY_UNTIL_EOF:
		return http_untileof_recv(cl, conn);

	case STATE_HTTP_BODY_KNOWN_LENGTH:
		return http_contentlen_recv(cl, conn);

	case STATE_HTTP_CHUNK_HEADER:
	case STATE_HTTP_CHUNK_HEADER_EXT:
	case STATE_HTTP_CHUNK_HEADER_LF:
	case STATE_HTTP_CHUNK_DATA:
	case STATE_HTTP_CHUNK_DATA_CR:
	case STATE_HTTP_CHUNK_DATA_LF:
	case STATE_HTTP_CHUNK_TRAILER:
	case STATE_HTTP_CHUNK_TRAILLINE:
	case STATE_HTTP_CHUNK_TRAILLINE_LF:
	case STATE_HTTP_CHUNK_TRAILER_LF:
		return http_chunked_recv(cl, conn);

	case STATE_HTTP_CHUNK_DONE:
	case STATE_HTTP_REQUEST_DONE:
		http_state_transition(cl, STATE_HTTP_BODY_CLOSE);

		return http_handle_body_data(cl, conn, "", 0);

	default:
		break;
	}

	while (true) {
		ch = uwsd_io_getc(conn);
		len = uwsd_io_offset(httpbuf);

		if (ch == EOF)
			break;

		if (cl->head_length++ == sizeof(httpbuf->buf.data))
			uwsd_http_error_return(cl, 502, "Bad Gateway",
				"Upstream response has too long header");

		switch (cl->http.state) {
		case STATE_HTTP_STATUS_VERSION:
			if (ch == ' ') {
				if (!uwsd_io_strcmp(httpbuf, "HTTP/1.0"))
					cl->http_version = 0x0100;
				else if (!uwsd_io_strcmp(httpbuf, "HTTP/1.1"))
					cl->http_version = 0x0101;
				else
					uwsd_http_error_return(cl, 502, "Bad Gateway",
						"Upstream response uses unsupported HTTP protocol version");

				http_state_transition(cl, STATE_HTTP_STATUS_CODE);
				uwsd_io_reset(httpbuf);
			}
			else {
				if (len == 0 && isspace(ch))
					continue;

				if (cl->action->type == UWSD_ACTION_SCRIPT &&
					len == 5 && uwsd_io_strcmp(httpbuf, "HTTP/"))
					http_state_transition(cl, STATE_HTTP_HEADERLINE);
				else if (len >= strlen("HTTP/1.1"))
					uwsd_http_error_return(cl, 502, "Bad Gateway",
						"Upstream response uses unsupported HTTP protocol version");

				uwsd_io_putchar(httpbuf, ch);
			}

			break;

		case STATE_HTTP_STATUS_CODE:
			if (ch == ' ') {
				http_state_transition(cl, STATE_HTTP_STATUS_MESSAGE);
				uwsd_io_reset(httpbuf);
			}
			else {
				if (len == 0 && isspace(ch))
					continue;

				if (len >= 3 || !isdigit(ch))
					uwsd_http_error_return(cl, 502, "Bad Gateway",
						"Upstream response contains invalid status code");

				cl->http_status = cl->http_status * 10 + (ch - '0');
			}

			break;

		case STATE_HTTP_STATUS_MESSAGE:
			if (ch == '\r') {
				assert(!cl->request_uri);

				cl->request_uri = uwsd_io_strdup(httpbuf);

				if (!cl->request_uri)
					uwsd_http_error_return(cl, 500, "Internal Server Error", "Out of memory");

				http_state_transition(cl, STATE_HTTP_STATUSLINE_LF);
				uwsd_io_reset(httpbuf);
			}
			else {
				if (len == 0 && isspace(ch))
					continue;

				if (!uwsd_io_putchar(httpbuf, ch))
					uwsd_http_error_return(cl, 502, "Bad Gateway",
						"Upstream response contains too long status message");
			}

			break;

		case STATE_HTTP_STATUSLINE_LF:
			if (ch == '\n') {
				uwsd_http_info(cl, "< %03hu %s", cl->http_status, cl->request_uri);
				http_state_transition(cl, STATE_HTTP_HEADERLINE);
			}
			else
				uwsd_http_error_return(cl, 502, "Bad Gateway",
					"Upstream response contains invalid HTTP status line");

			break;

		case STATE_HTTP_HEADERLINE:
			if (ch == '\r') {
				http_state_transition(cl, STATE_HTTP_HEADERLINE_LF);
			}
			else {
				if (!uwsd_io_putchar(httpbuf, ch))
					uwsd_http_error_return(cl, 502, "Bad Gateway",
						"Upstream response contains too long header line");
			}

			break;

		case STATE_HTTP_HEADERLINE_LF:
			if (ch == '\n') {
				if (len) {
					http_header_parse(cl, uwsd_io_getbuf(httpbuf), len);
					http_state_transition(cl, STATE_HTTP_HEADERLINE);
					uwsd_io_reset(httpbuf);
				}
				else {
					/* The following call will transition the state to body, chunked or done */
					return http_determine_message_length(cl, false);
				}
			}
			else {
				uwsd_http_error_return(cl, 502, "Bad Gateway",
					"Upstream response contains invalid header line");
			}

			break;

		default:
			client_free(cl, "Unexpected HTTP parse state: %s", http_state_name(cl->http.state));

			return false;
		}
	}

	return true;
}

static bool
http_connection_close(uwsd_client_context_t *cl)
{
	if (cl->http.request_flags & HTTP_WANT_CLOSE) {
		client_free(cl, "HTTP request initiated close");

		return true;
	}

	if (cl->http.response_flags & HTTP_WANT_CLOSE) {
		client_free(cl, "HTTP response initiated close");

		return true;
	}

	return false;
}

static bool
http_tx(uwsd_client_context_t *cl, uwsd_connection_state_t state)
{
	uwsd_connection_t *conn = &cl->downstream;
	uwsd_connection_t *file = &cl->upstream;
	ssize_t wlen;

	/* Sending buffered data to stream */
	if (!uwsd_iov_tx(conn, state))
		return false; /* failure or partial send */

	/* If we're not serving a HEAD request, then start transmitting file contents */
	if (cl->request_method != HTTP_HEAD) {
		/* Use sendfile(2) to transfer contents */
		if (cl->http.response_flags & HTTP_SEND_FILE) {
			wlen = client_sendfile(conn, file->ufd.fd, NULL, sizeof(conn->buf.data));

			if (wlen == -1) {
				/* The sendfile(2) facility is not implemented or not applicable,
				 * remain in send state but handle next iteration using simple
				 * buffer copy */
				if (errno == EINVAL || errno == ENOSYS) {
					uwsd_http_debug(cl, "sendfile(): %m - falling back to recv()/send()");

					cl->http.response_flags &= ~HTTP_SEND_FILE;
					cl->http.response_flags |= HTTP_SEND_COPY;
				}

				/* A fatal sendfile(2) error. Since we already sent the response
				 * header portion of the reply, simply drop the connection instead
				 * of emitting an HTTP 500 error */
				else if (errno != EAGAIN) {
					client_free(cl, "downstream sendfile error: %m");
				}

				return false; /* failure */
			}

			/* Remain in send state as long as sendfile(2) transferred data */
			if (wlen > 0)
				return false; /* partial send */
		}

		/* Use buffer copy to transfer contents */
		else if (cl->http.response_flags & HTTP_SEND_COPY) {
			do {
				if (!uwsd_io_recv(file))
					return false; /* failure */
			} while (errno == EINTR);

			/* Remain in send state as long as there is data to transmit */
			if (uwsd_io_pending(file)) {
				uwsd_iov_put(cl, uwsd_io_getbuf(file), uwsd_io_pending(file));

				return false; /* partial send */
			}
		}
	}

	/* Close connection? */
	if (http_connection_close(cl))
		return false; /* client context freed */

	http_state_reset(cl, STATE_HTTP_REQUEST_METHOD);
	uwsd_state_transition(cl, STATE_CONN_IDLE);
	uwsd_io_flush(conn);

	return true; /* all done */
}

__hidden char *
uwsd_http_header_lookup(uwsd_client_context_t *cl, const char *name)
{
	size_t i;

	for (i = 0; i < cl->http_num_headers; i++)
		if (!strcasecmp(cl->http_headers[i].name, name))
			return cl->http_headers[i].value;

	return NULL;
}

__hidden bool
uwsd_http_header_contains(uwsd_client_context_t *cl, const char *name, const char *token)
{
	const char *list = uwsd_http_header_lookup(cl, name), *p;
	size_t tlen = strlen(token);

	while (list && *list) {
		p = list + strcspn(list, ", \t\r\n");

		if ((size_t)(p - list) == tlen && !strncasecmp(list, token, tlen))
			return true;

		list = p + strspn(p, ", \t\r\n");
	}

	return false;
}

__hidden bool
uwsd_http_reply_send(uwsd_client_context_t *cl, uint32_t flags)
{
	uwsd_connection_t *conn = &cl->downstream;

	uwsd_iov_put(cl,
		uwsd_io_getbuf(conn), uwsd_io_offset(conn));

	cl->http.response_flags |= flags;

	return http_tx(cl, STATE_CONN_RESPONSE);
}

__hidden size_t __attribute__((__format__ (__printf__, 4, 0)))
uwsd_http_reply(uwsd_client_context_t *cl, uint16_t code,
                const char *reason, const char *msg, ...)
{
	uwsd_connection_t *conn = &cl->downstream;
	va_list ap;
	size_t len;

	uwsd_http_info(cl, "%c %03hu %s", (code < 400) ? 'R' : 'E', code, reason ? reason : "-");

	va_start(ap, msg);

	/* For HEAD requests we must not emit a body, consume away the msg format
	 * related arguments to only leave the additional headers in the ap_list,
	 * then replace the format string with the empty body marker... */
	if (cl->request_method == HTTP_HEAD) {
		vsnprintf(NULL, 0, msg, ap);
		msg = UWSD_HTTP_REPLY_EMPTY;
	}

	uwsd_io_reset(conn);

	len = uwsd_http_reply_buffer_varg(
		uwsd_io_getbuf(conn), uwsd_io_available(conn),
		cl->http_version == 0x0101 ? 1.1 : 1.0,
		code, reason, msg ? msg : UWSD_HTTP_REPLY_EMPTY, ap);

	va_end(ap);

	conn->buf.pos += len;
	conn->buf.end += len;

	return len;
}

__hidden size_t __attribute__((__format__ (__printf__, 6, 0)))
uwsd_http_reply_buffer_varg(char *buf, size_t buflen, double http_version,
                            uint16_t code, const char *reason, const char *fmt, va_list ap)
{
	enum { BARE, LONG, LLONG, DOUBLE, LDBL, INTMAX, SIZET, PTRDIFF } expect;
	char *pos = buf, *hname, *hvalue;
	bool has_ctype = false;
	int len, clen;
	const char *p;
	va_list ap1;

	len = snprintf(pos, buflen, "HTTP/%.1f %hu %s\r\n", http_version, code, reason);
	pos += len;
	buflen -= len;

	va_copy(ap1, ap);
	clen = (*fmt != '\127') ? vsnprintf(NULL, 0, fmt, ap1) : 0;
	va_end(ap1);

	va_copy(ap1, ap);

	/* Skip necessary amount of arguments by doing a naive parsing of the
	 * format string. Bail out on formats we do not understand. */
	for (p = fmt; *p; p++) {
		if (*p != '%')
			continue;

		p++;
		expect = BARE;

		/* skip flags */
		while (strchr("#0- +'I", *p))
			p++;

		/* width given in argument */
		if (*p == '*') {
			p++;
			va_arg(ap1, int);

			/* we do not handle argument positions */
			assert(!strchr("0123456789", *p));
		}

		/* skip width */
		else {
			while (strchr("0123456789", *p))
				p++;
		}

		/* precision */
		if (*p == '.') {
			p++;

			/* precision given in argument */
			if (*p == '*') {
				p++;
				va_arg(ap1, int);

				/* we do not handle argument positions */
				assert(!strchr("0123456789", *p));
			}

			/* skip precision */
			else {
				while (strchr("0123456789", *p))
					p++;
			}
		}

		/* length */
		switch (*p) {
		case 'h': p += (p[1] == 'h') ? 2 : 1;                   break;
		case 'l': p += (p[1] == 'l') ? 2 : 1; expect = LLONG;   break;
		case 'q': p++;                        expect = LLONG;   break;
		case 'L': p++;                        expect = LDBL;    break;
		case 'j': p++;                        expect = INTMAX;  break;
		case 'z': p++;                        expect = SIZET;   break;
		case 't': p++;                        expect = PTRDIFF; break;
		}

		if (strchr("diouxX", *p)) {
			switch (expect) {
			case BARE:    va_arg(ap1, int);         break;
			case LONG:    va_arg(ap1, long);        break;
			case LLONG:   va_arg(ap1, long long);   break;
			case INTMAX:  va_arg(ap1, intmax_t);    break;
			case SIZET:   va_arg(ap1, size_t);      break;
			case PTRDIFF: va_arg(ap1, ptrdiff_t);   break;
			default:      assert(0);                break;
			}
		}
		else if (strchr("eEfFgGaA", *p)) {
			switch (expect) {
			case BARE:    va_arg(ap1, double);      break;
			case LDBL:    va_arg(ap1, long double); break;
			default:      assert(0);                break;
			}
		}
		else if (strchr("sSpn", *p)) {
			switch (expect) {
			case BARE:
			case LONG:    va_arg(ap1, char *);      break;
			default:      assert(0);                break;
			}
		}
		else if (strchr("cC", *p)) {
			switch (expect) {
			case BARE:
			case LONG:    va_arg(ap1, int);         break;
			default:      assert(0);                break;
			}
		}
		else if (strchr("%m", *p)) {
			continue;
		}
		else {
			assert(0);
		}
	}

	while (true) {
		hname = va_arg(ap1, char *);

		if (!hname)
			break;

		hvalue = va_arg(ap1, char *);

		if (hvalue) {
			len = snprintf(pos, buflen, "%s: %s\r\n", hname, hvalue);
			pos += len;
			buflen -= len;
			has_ctype |= !strcasecmp(hname, "Content-Type");
		}
	}

	va_end(ap1);

	if (*fmt != '\127') {
		if (!has_ctype) {
			len = snprintf(pos, buflen, "Content-Type: text/plain\r\n");
			pos += len;
			buflen -= len;
		}

		len = snprintf(pos, buflen, "Content-Length: %d\r\n\r\n", clen);
		pos += len;
		buflen -= len;

		va_copy(ap1, ap);
		len = vsnprintf(pos, buflen, fmt, ap1);
		pos += len;
		buflen -= len;
		va_end(ap1);
	}
	else {
		len = snprintf(pos, buflen, "\r\n");
		pos += len;
		buflen -= len;
	}

	return pos - buf;
}

static bool
test_match(uwsd_client_context_t *cl, uwsd_match_t *match)
{
	char *val;

	switch (match->type) {
	case UWSD_MATCH_PROTOCOL:
		return (match->data.protocol == cl->protocol);

	case UWSD_MATCH_HOSTNAME:
		val = uwsd_http_header_lookup(cl, "Host");

		return (fnmatch(match->data.value, val ? val : cl->listener->hostname, FNM_CASEFOLD) == 0);

	case UWSD_MATCH_PATH:
		return (pathmatch(match->data.value, cl->request_uri) > 0);
	}

	return false;
}

static void
resolve_match(uwsd_client_context_t *cl, struct list_head *matches);

static void
resolve_match(uwsd_client_context_t *cl, struct list_head *matches)
{
	uwsd_match_t *match;

	list_for_each_entry(match, matches, list) {
		if (test_match(cl, match)) {
			if (match->default_action) {
				cl->action = match->default_action;

				if (match->type == UWSD_MATCH_PATH)
					cl->prefix = match->data.value;

				if (!list_empty(&match->auth))
					cl->auths = &match->auth;
			}

			resolve_match(cl, &match->matches);
			break;
		}
	}
}

static void
resolve_action(uwsd_client_context_t *cl)
{
	cl->prefix = "/";
	cl->action = cl->listener->default_action;

	if (!list_empty(&cl->listener->auth))
		cl->auths = &cl->listener->auth;

	resolve_match(cl, &cl->listener->matches);

	if (cl->action && cl->action->type == UWSD_ACTION_BACKEND)
		cl->action = cl->action->data.action;
}

static bool
http_proxy_connect(uwsd_client_context_t *cl)
{
	uwsd_action_t *action = cl->action;

	if (cl->upstream.ufd.fd == -1) {
		uwsd_http_debug(cl, "connecting to upstream HTTP server %s:%hu",
			action->data.proxy.hostname, action->data.proxy.port);

		cl->upstream.ufd.fd = usock(USOCK_TCP|USOCK_NONBLOCK,
			action->data.proxy.hostname,
			usock_port(action->data.proxy.port));

		if (cl->upstream.ufd.fd == -1)
			uwsd_http_error_return(cl, 502, "Bad Gateway",
				"Unable to connect to upstream server: %m\n");
	}

	if (action->data.proxy.ssl && !uwsd_ssl_client_init(cl))
		return false;

	uwsd_state_transition(cl, STATE_CONN_UPSTREAM_HS_SEND);

	return true;
}

static int
send_file(uwsd_client_context_t *cl, const char *path, const char *type, struct stat *s)
{
	char szbuf[sizeof("18446744073709551615")];
	char *cstype = NULL;
	uint32_t reply_flags = 0;

	if (!(s->st_mode & S_IROTH) || strrchr(path, '/')[1] == '.')
		return -EACCES;

	cl->upstream.ufd.fd = open(path, O_RDONLY);

	if (cl->upstream.ufd.fd == -1)
		return -errno;

	if (uwsd_file_if_range(cl, s) &&
	    uwsd_file_if_match(cl, s) &&
	    uwsd_file_if_modified_since(cl, s) &&
	    uwsd_file_if_none_match(cl, s) &&
	    uwsd_file_if_unmodified_since(cl, s))
	{
		snprintf(szbuf, sizeof(szbuf), "%zu", (size_t)s->st_size);

		if (!type || !*type)
			type = uwsd_file_mime_lookup(path);

		if (config->default_charset && !strncmp(type, "text/", 5) && !strcasestr(type, "charset="))
			asprintf(&cstype, "%s; charset=%s", type, config->default_charset);

		uwsd_http_reply(cl, 200, "OK", UWSD_HTTP_REPLY_EMPTY,
			"Content-Type", cstype ? cstype : type,
			"Content-Length", szbuf,
			"ETag", uwsd_file_mktag(s),
			"Last-Modified", uwsd_file_unix2date(s->st_mtime),
			"Connection", (cl->http.request_flags & HTTP_WANT_CLOSE) ? "close" : NULL,
			UWSD_HTTP_REPLY_EOH);

		reply_flags |= HTTP_SEND_FILE;

		free(cstype);
	}

	return uwsd_http_reply_send(cl, reply_flags);
}

static bool
http_file_serve(uwsd_client_context_t *cl)
{
	char *path = cl->action->data.file.path;
	struct stat s;
	int rv = 0;

	uwsd_state_transition(cl, STATE_CONN_RESPONSE);

	if (cl->request_method != HTTP_GET && cl->request_method != HTTP_HEAD)
		uwsd_http_error_return(cl, 405, "Method Not Allowed",
			"The used HTTP method is invalid for the requested resource\n");

	if (stat(path, &s) == -1) {
		switch (errno) {
		case EACCES: goto error403;
		default:     goto error404;
		}
	}

	if (!S_ISREG(s.st_mode)) {
		uwsd_http_debug(cl, "Path '%s' exists but does not point to a regular file", path);
		goto error404;
	}

	rv = send_file(cl, path, cl->action->data.file.content_type, &s);

	switch (rv) {
	case 1:       return true;
	case 0:       return false;
	case -EACCES: goto error403;
	case -ENOENT: goto error404;
	default:      goto error500;
	}

error403:
	uwsd_http_error_return(cl, 403, "Permission Denied",
		"Access to the requested path is forbidden");

error404:
	uwsd_http_error_return(cl, 404, "Not Found",
		"The requested path does not exist on this server");

error500:
	uwsd_http_error_return(cl, 500, "Internal Server Error",
		"Unable to serve requested path: %s\n", strerror(-rv));
}

static char *
find_index_file(uwsd_client_context_t *cl, const char *path, struct stat *s)
{
	char **candidates = cl->action->data.directory.index_filenames;
	char *indexfile = NULL;

	if (!candidates)
		candidates = (char *[]){ "index.html", "index.htm", "default.html", "default.htm", NULL };

	while (*candidates) {
		indexfile = pathexpand(*candidates, path);

		if (!indexfile)
			return NULL;

		if (stat(indexfile, s) == -1) {
			uwsd_http_debug(cl, "Unable to stat() index file candiate '%s': %m", indexfile);
			goto skip;
		}

		if (!S_ISREG(s->st_mode)) {
			uwsd_http_debug(cl, "Index file candiate '%s' is not a regular file", indexfile);
			goto skip;
		}

		if (!(s->st_mode & S_IROTH)) {
			uwsd_http_debug(cl, "Index file candiate '%s' is not world readable", indexfile);
			goto skip;
		}

		break;

skip:
		free(indexfile);
		indexfile = NULL;
		candidates++;
	}

	errno = 0;

	return indexfile;
}

static bool
http_directory_serve(uwsd_client_context_t *cl)
{
	const char *type = cl->action->data.directory.content_type;
	char *base = cl->action->data.directory.path;
	char *path = NULL, *url = NULL, *p;
	struct stat s;
	int rv = 0;

	uwsd_state_transition(cl, STATE_CONN_RESPONSE);

	if (cl->request_method != HTTP_GET && cl->request_method != HTTP_HEAD)
		uwsd_http_error_return(cl, 405, "Method Not Allowed",
			"The used HTTP method is invalid for the requested resource\n");

	url = pathclean(urldecode(cl->request_uri), -1);

	if (!base || !url)
		goto error500;

	if (*url != '/')
		goto error404;

	url[strcspn(url, "?")] = 0;
	path = pathexpand(url + strspn(url, "/"), base);

	if (!path)
		goto error500;

	if (!pathmatch(base, path))
		goto error403;

	if (stat(path, &s) == -1) {
		switch (errno) {
		case EACCES: goto error403;
		default:     goto error404;
		}
	}

	if (S_ISDIR(s.st_mode)) {
		if (!(s.st_mode & S_IXOTH))
			goto error403;

		p = find_index_file(cl, path, &s);

		if (!p) {
			if (errno)
				goto error500;

			if (!cl->action->data.directory.directory_listing)
				goto error403;

			rv = uwsd_file_directory_list(cl, path, url);
		}
		else {
			rv = send_file(cl, p, type, &s);
		}

		free(p);
	}
	else {
		rv = send_file(cl, path, NULL, &s);
	}

	switch (rv) {
	case 0:       goto success;
	case 1:       goto success;
	case -EACCES: goto error403;
	case -ENOENT: goto error404;
	default:      goto error500;
	}

error403:
	free(path);
	free(url);

	uwsd_http_error_return(cl, 403, "Permission Denied",
		"Access to the requested path is forbidden");

error404:
	free(path);
	free(url);

	uwsd_http_error_return(cl, 404, "Not Found",
		"The requested path does not exist on this server");

error500:
	free(path);
	free(url);

	uwsd_http_error_return(cl, 500, "Internal Server Error",
		"Unable to serve requested path: %s\n", strerror(-rv));

success:
	free(path);
	free(url);

	return (rv > 0);
}

static bool
http_script_connect(uwsd_client_context_t *cl)
{
	struct sockaddr_un *sun = &cl->action->data.script.sun;

	/* Close previous connections as script host does (yet) handle
	 * HTTP connection reuse */
	if (cl->upstream.ufd.fd != -1)
		close(cl->upstream.ufd.fd);

	uwsd_http_debug(cl, "connecting to script worker");

	cl->upstream.ufd.fd = socket(AF_UNIX, SOCK_STREAM, 0);

	if (cl->upstream.ufd.fd == -1)
		uwsd_http_error_return(cl, 502, "Bad Gateway",
			"Unable to spawn UNIX socket: %m\n");

	if (connect(cl->upstream.ufd.fd, (struct sockaddr *)sun, sizeof(*sun)) == -1 && errno != EINPROGRESS)
		uwsd_http_error_return(cl, 502, "Bad Gateway",
			"Unable to connect to script worker: %m");

	uwsd_state_transition(cl, STATE_CONN_UPSTREAM_CONNECT);

	return true;
}

static bool
http_is_websocket_handshake(uwsd_client_context_t *cl)
{
	char *p;

	if (!uwsd_http_header_contains(cl, "Connection", "Upgrade"))
		return false;

	p = uwsd_http_header_lookup(cl, "Upgrade");

	if (!p || strcasecmp(p, "WebSocket"))
		return false;

	return true;
}

/* accepting an HTTP connection */
__hidden void
uwsd_http_state_accept(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	if (!client_accept(cl)) {
		if (errno == ENODATA)
			return uwsd_state_transition(cl, STATE_CONN_ACCEPT_RECV); /* retry */

		if (errno == EAGAIN)
			return uwsd_state_transition(cl, STATE_CONN_ACCEPT_SEND); /* retry */

		return client_free(cl, "SSL handshake error: %s", strerror(errno));
	}

	uwsd_state_transition(cl, STATE_CONN_REQUEST);
}

/* reading an HTTP request header */
__hidden void
uwsd_http_state_request_recv(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	uwsd_action_t *old_action;
	bool ws;

	if (!uwsd_io_readahead(&cl->downstream))
		return; /* failure */

	if (!http_request_recv(cl))
		return; /* failure */

	if (cl->http.state < STATE_HTTP_BODY_KNOWN_LENGTH) {
		if (!uwsd_io_eof(&cl->downstream))
			uwsd_state_transition(cl, STATE_CONN_REQUEST);
		else
			client_free(cl, "downstream connection closed");

		return; /* incomplete */
	}

	ws = http_is_websocket_handshake(cl);
	cl->protocol = ws ? UWSD_PROTOCOL_WS : UWSD_PROTOCOL_HTTP;

	old_action = cl->action;

	resolve_action(cl);

	if (cl->action) {
		/* If endpoint changed since last request, make sure to close
		 * associated descriptor */
		if (old_action != cl->action)  {
			if (cl->upstream.ufd.fd != -1) {
				close(cl->upstream.ufd.fd);
				cl->upstream.ufd.fd = -1;
			}
		}

		if (!auth_check(cl))
			return;

		if (ws) {
			if (!uwsd_ws_connection_accept(cl))
				return;
		}
		else {
			if (cl->action->type == UWSD_ACTION_TCP_PROXY) {
				if (!http_proxy_connect(cl))
					return;
			}
			else if (cl->action->type == UWSD_ACTION_FILE) {
				if (!http_file_serve(cl))
					return;
			}
			else if (cl->action->type == UWSD_ACTION_DIRECTORY) {
				if (!http_directory_serve(cl))
					return;
			}
			else if (cl->action->type == UWSD_ACTION_SCRIPT) {
				if (!http_script_connect(cl))
					return;
			}
		}
	}
	else {
		uwsd_http_reply(cl, 404, "Not Found",
			"No matching endpoint for %s request to %s",
				ws ? "WebSocket" : "HTTP", cl->request_uri,
			UWSD_HTTP_REPLY_EOH);

		if (!uwsd_http_reply_send(cl, true))
			return;
	}

	if (cl->state == STATE_CONN_IDLE && http_connection_close(cl))
		return;
}

/* when persistent connection has been idle for too long */
__hidden void
uwsd_http_state_idle_timeout(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	client_free(cl, "client idle timeout");
}

/* when HTTP request cannot be received in time */
__hidden void
uwsd_http_state_request_timeout(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	client_free(cl, "client request header timeout");
}

/* when HTTP reply cannot be sent in time */
__hidden void
uwsd_http_state_response_timeout(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	client_free(cl, "client response send timeout");
}

/* when sending HTTP response */
__hidden void
uwsd_http_state_response_send(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	http_tx(cl, state);
}

/* when upstream connect takes too long */
__hidden void
uwsd_http_state_upstream_timeout(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	if (cl->http.state <= STATE_HTTP_STATUS_VERSION)
		uwsd_http_error_send(cl, 504, "Gateway Timeout", "Timeout while connecting to upstream server");
	else
		client_free(cl, "Timeout while reading upstream response");
}

static void
append_via_header(uwsd_connection_t *httpbuf, uwsd_client_context_t *cl, const char *previous_via)
{
	char addr[INET6_ADDRSTRLEN];
	uint16_t port;

	if (previous_via)
		uwsd_io_printf(httpbuf, "Via: %s, ", previous_via);
	else
		uwsd_io_printf(httpbuf, "Via: ");

	uwsd_io_printf(httpbuf, "%s ", (cl->http_version == 0x0101) ? "1.1" : "1.0");

	if (cl->sa_local.unspec.sa_family == AF_INET6) {
		if (IN6_IS_ADDR_V4MAPPED(&cl->sa_local.in6.sin6_addr)) {
			inet_ntop(AF_INET, &cl->sa_local.in6.sin6_addr.s6_addr[12], addr, sizeof(addr));
			uwsd_io_printf(httpbuf, "%s", addr);
		}
		else {
			inet_ntop(AF_INET6, &cl->sa_local.in6.sin6_addr, addr, sizeof(addr));
			uwsd_io_printf(httpbuf, "[%s]", addr);
		}
	}
	else {
		inet_ntop(AF_INET, &cl->sa_local.in.sin_addr, addr, sizeof(addr));
		uwsd_io_printf(httpbuf, "%s", addr);
	}

	port = ntohs(cl->sa_local.in.sin_port);

	if (port != 80)
		uwsd_io_printf(httpbuf, ":%hu", port);

	uwsd_io_printf(httpbuf, "\r\n");
}

__hidden void
uwsd_http_state_upstream_handshake(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	if (!client_connect(cl)) {
		if (errno == ENODATA)
			return uwsd_state_transition(cl, STATE_CONN_UPSTREAM_HS_RECV); /* retry */

		if (errno == EAGAIN)
			return uwsd_state_transition(cl, STATE_CONN_UPSTREAM_HS_SEND); /* retry */

		uwsd_http_error_send(cl, 502, "Bad Gateway",
			"SSL handshake with upstream server failed");

		return; /* failure */
	}

	uwsd_state_transition(cl, STATE_CONN_UPSTREAM_CONNECT);
}

__hidden void
uwsd_http_state_upstream_connected(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	uwsd_connection_t *httpbuf = &cl->upstream;
	uwsd_http_header_t *hdr;
	char *via = NULL;
	bool chunked;
	size_t i;

	if (cl->action->type == UWSD_ACTION_SCRIPT) {
		if (!uwsd_script_request(cl))
			return; /* failure */
	}
	else if (cl->action->type == UWSD_ACTION_TCP_PROXY) {
		uwsd_io_reset(httpbuf);
		uwsd_io_printf(httpbuf, "%s %s HTTP/%s\r\n",
			http_request_methods[cl->request_method].name, cl->request_uri,
			(cl->http_version == 0x0101) ? "1.1" : "1.0");

		chunked = (cl->http.state == STATE_HTTP_CHUNK_HEADER);

		if (chunked) {
			uwsd_io_printf(httpbuf, "Transfer-Encoding: chunked\r\n");
			cl->http.request_flags |= HTTP_SEND_CHUNKED;
		}

		for (i = 0; i < cl->http_num_headers; i++) {
			hdr = &cl->http_headers[i];

			if (http_is_hop_by_hop_header(hdr))
				continue;

			if (chunked && !strcasecmp(hdr->name, "Content-Length"))
				continue;

			if (!strcasecmp(hdr->name, "Via")) {
				via = hdr->value;
				continue;
			}

			uwsd_io_printf(httpbuf, "%s: %s\r\n",
				hdr->name, hdr->value);
		}

		append_via_header(httpbuf, cl, via);

		if (!uwsd_io_printf(httpbuf, "\r\n")) {
			uwsd_http_error_send(cl, 431,
				"Request Header Fields Too Large",
				"Request header too long\n");

			return;
		}

		/* Send header. XXX: Pipelining not handled yet. */
		uwsd_iov_put(cl, uwsd_io_getbuf(httpbuf), uwsd_io_offset(httpbuf));

		if (!uwsd_iov_tx(&cl->upstream, state))
			return; /* failure or partial send */
	}

	if (!http_request_recv(cl))
		return; /* failure */

	uwsd_state_transition(cl, STATE_CONN_UPSTREAM_SEND);
}

__hidden void
uwsd_http_state_upstream_send(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	while (true) {
		if (cl->action->type != UWSD_ACTION_SCRIPT &&
		    !uwsd_iov_tx(&cl->upstream, STATE_CONN_UPSTREAM_SEND))
			return; /* failure or partial send */

		if (!uwsd_io_pending(&cl->downstream) &&
		    cl->http.state != STATE_HTTP_CHUNK_DONE &&
		    cl->http.state != STATE_HTTP_REQUEST_DONE)
			break;

		if (!http_request_recv(cl))
			return; /* failure */
	}

	if (cl->http.state == STATE_HTTP_BODY_CLOSE) {
		http_state_reset(cl, STATE_HTTP_STATUS_VERSION);

		return uwsd_state_transition(cl, STATE_CONN_UPSTREAM_RECV);
	}

	return uwsd_state_transition(cl, STATE_CONN_DOWNSTREAM_RECV);
}

static bool
status_header_parse(uwsd_client_context_t *cl, uint16_t *code, char **message)
{
	char *status = uwsd_http_header_lookup(cl, "Status");

	if (!status) {
		*code = cl->http_status ? cl->http_status : 200;
		*message = cl->request_uri ? cl->request_uri : "OK";

		return true;
	}

	if (!isdigit(status[0]) || !isdigit(status[1]) ||
	    !isdigit(status[2]) || !isspace(status[3]))
		return false;

	*code = (status[0] - '0') * 100 + (status[1] - '0') * 10 + (status[2] - '0');

	for (*message = status + 4; isspace(**message); (*message)++)
		;

	return **message;
}

static void
append_host_header(uwsd_connection_t *httpbuf, uwsd_client_context_t *cl)
{
	char *host = uwsd_http_header_lookup(cl, "Host");
	char addr[INET6_ADDRSTRLEN];

	if (host) {
		uwsd_io_printf(httpbuf, "Host: %s\r\n", host);

		return;
	}

	uwsd_io_printf(httpbuf, "Host: ");

	if (cl->action && cl->action->type == UWSD_ACTION_TCP_PROXY) {
		uwsd_io_printf(httpbuf, "%s", cl->action->data.proxy.hostname);

		if (cl->action->data.proxy.port != 80)
			uwsd_io_printf(httpbuf, ":%hu", cl->action->data.proxy.port);
	}

	else {
		if (cl->listener->hostname && !isdigit(*cl->listener->hostname) && !strchr(cl->listener->hostname, ':')) {
			uwsd_io_printf(httpbuf, "%s", cl->listener->hostname);
		}
		else if (cl->sa_local.unspec.sa_family == AF_INET6) {
			if (IN6_IS_ADDR_V4MAPPED(&cl->sa_local.in6.sin6_addr)) {
				inet_ntop(AF_INET, &cl->sa_local.in6.sin6_addr.s6_addr[12], addr, sizeof(addr));
				uwsd_io_printf(httpbuf, "%s", addr);
			}
			else {
				inet_ntop(AF_INET6, &cl->sa_local.in6.sin6_addr, addr, sizeof(addr));
				uwsd_io_printf(httpbuf, "[%s]", addr);
			}
		}
		else {
			inet_ntop(AF_INET, &cl->sa_local.in.sin_addr, addr, sizeof(addr));
			uwsd_io_printf(httpbuf, "%s", addr);
		}

		if (ntohs(cl->sa_local.in.sin_port) != 80)
			uwsd_io_printf(httpbuf, ":%hu", ntohs(cl->sa_local.in.sin_port));
	}

	uwsd_io_printf(httpbuf, "\r\n");
}

static bool
http_use_splice_tx(uwsd_client_context_t *cl)
{
	return (cl->http.response_flags & HTTP_SEND_PLAIN) &&
	       (cl->downstream.ssl == NULL) && (cl->upstream.ssl == NULL) &&
	       (cl->http.state == STATE_HTTP_BODY_KNOWN_LENGTH) &&
	       (cl->request_length > 0);
}

__hidden void
uwsd_http_state_upstream_recv(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	bool has_clen = false, has_ctype = false, is_script = (cl->action->type == UWSD_ACTION_SCRIPT);
	uwsd_connection_t *httpbuf = &cl->downstream;
	uwsd_http_header_t *hdr;
	char *msg, *via = NULL;
	bool chunked, eof;
	uint16_t code;
	size_t i;

	if (http_use_splice_tx(cl)) {
		if (cl->http.pipebuf[1] == -1 && pipe(cl->http.pipebuf) == -1) {
			uwsd_http_error_send(cl, 500, "Internal Server Error",
				"Error spawning transfer pipe: %m\n");
			return;
		}

		ssize_t wlen = splice(
			cl->upstream.ufd.fd, NULL, cl->http.pipebuf[1], NULL,
			cl->request_length, SPLICE_F_NONBLOCK);

		/* unrecoverable error */
		if (wlen < 0) {
			uwsd_http_error_send(cl, 500, "Internal Server Error",
				"Error receiving upstream response: %m");

			return;
		}

		/* unexpected eof */
		else if (wlen == 0) {
			uwsd_http_warn(cl,
				"premature eof reading upstream response, "
				"%zu byte outstanding", cl->request_length);

			cl->request_length = 0;
		}

		/* data spliced */
		else {
			cl->request_length -= wlen;
		}

		cl->http.pipebuf_len += wlen;

		uwsd_state_transition(cl, STATE_CONN_DOWNSTREAM_SEND);
		return;
	}

	if (!uwsd_io_readahead(&cl->upstream))
		return; /* failure */

	if (!http_response_recv(cl))
		return; /* failure */

	/* The forced state transition below will clear the eof indicator,
	 * read and store it here and evaluate after */
	eof = cl->upstream.ufd.eof;

	/* We might've been invoked by pending socket buffer data so far
	 * without ever involving uloop. Force a state transition here to
	 * trigger uloop registration for subsequent read notifications */
	uwsd_state_transition(cl, state);

	if (cl->http.state < STATE_HTTP_BODY_KNOWN_LENGTH) {
		if (eof) {
			uwsd_http_error_send(cl, 502, "Bad Gateway",
				"The invoked program did not produce a valid response");

			return; /* failure */
		}

		return; /* await complete header */
	}

	if (!(cl->http.response_flags & (HTTP_SEND_PLAIN|HTTP_SEND_CHUNKED))) {
		if (is_script) {
			if (!status_header_parse(cl, &code, &msg)) {
				uwsd_http_error_send(cl, 502, "Bad Gateway",
					"The invoked program sent an invalid status header");

				return;
			}
		}
		else {
			code = cl->http_status;
			msg = cl->request_uri;
		}

		uwsd_io_reset(httpbuf);
		uwsd_io_printf(httpbuf, "HTTP/%s %03hu %s\r\n",
			(cl->http_version == 0x0101) ? "1.1" : "1.0",
			code, msg);

		append_host_header(httpbuf, cl);

		chunked = (cl->http.state == STATE_HTTP_CHUNK_HEADER);

		for (i = 0; i < cl->http_num_headers; i++) {
			hdr = &cl->http_headers[i];

			if (!strcasecmp(hdr->name, "Content-Length")) {
				if (chunked)
					continue;

				has_clen = true;
			}

			has_ctype |= !strcasecmp(hdr->name, "Content-Type");

			if (http_is_hop_by_hop_header(hdr))
				continue;

			if (!strcasecmp(hdr->name, "Host"))
				continue;

			if (!is_script && !strcasecmp(hdr->name, "Via")) {
				via = hdr->value;
				continue;
			}

			uwsd_io_printf(httpbuf, "%s: %s\r\n", hdr->name, hdr->value);
		}

		if (!has_ctype)
			uwsd_io_printf(httpbuf, "Content-Type: application/octet-stream\r\n");

		if (!has_clen && cl->http_version > 0x0100 && http_may_have_body(code)) {
			uwsd_io_printf(httpbuf, "Transfer-Encoding: chunked\r\n");
			cl->http.response_flags |= HTTP_SEND_CHUNKED;
		}
		else {
			if (cl->http_version <= 0x0100) {
				uwsd_io_printf(httpbuf, "Connection: close\r\n");
				cl->http.response_flags |= HTTP_WANT_CLOSE;
			}

			cl->http.response_flags |= HTTP_SEND_PLAIN;
		}

		if (!is_script)
			append_via_header(httpbuf, cl, via);

		if (!uwsd_io_printf(httpbuf, "\r\n")) {
			uwsd_http_error_send(cl, 502,
				"Bad Gateway",
				"Upstream response header too large\n");

			return;
		}

		uwsd_iov_put(cl,
			uwsd_io_getbuf(httpbuf), uwsd_io_offset(httpbuf));
	}

	uwsd_state_transition(cl, STATE_CONN_DOWNSTREAM_SEND);
}

__hidden void
uwsd_http_state_downstream_send(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	/* fastpath: use splice() to transfer buffer data */
	if (cl->http.pipebuf[0] > -1) {
		ssize_t wlen = splice(
			cl->http.pipebuf[0], NULL,
			cl->downstream.ufd.fd, NULL,
			cl->http.pipebuf_len, SPLICE_F_NONBLOCK);

		/* unrecoverable send error */
		if (wlen < 0)
			return client_free(cl, "downstream send error: %m");

		cl->http.pipebuf_len -= wlen;

		if (cl->http.pipebuf_len > 0)
			return; /* partial send */

		/* sender is done, there's no more data */
		if (cl->request_length == 0) {
			close(cl->http.pipebuf[0]);
			cl->http.pipebuf[0] = -1;

			close(cl->http.pipebuf[1]);
			cl->http.pipebuf[1] = -1;

			http_state_transition(cl, STATE_HTTP_BODY_CLOSE);
		}
	}

	/* slowpath: use readv/writev copy semantics */
	else {
		while (true) {
			if (!uwsd_iov_tx(&cl->downstream, STATE_CONN_DOWNSTREAM_SEND))
				return; /* failure or partial send */

			if (!uwsd_io_pending(&cl->upstream) &&
				cl->http.state != STATE_HTTP_CHUNK_DONE &&
				cl->http.state != STATE_HTTP_REQUEST_DONE)
				break;

			if (!http_response_recv(cl))
				return; /* failure */
		}
	}

	if (cl->http.state == STATE_HTTP_BODY_CLOSE) {
		if (http_connection_close(cl))
			return;

		http_state_reset(cl, STATE_HTTP_REQUEST_METHOD);

		if (cl->upstream.ufd.eof) {
			uwsd_script_close(cl);

			if (cl->upstream.ufd.fd != -1) {
				uwsd_http_debug(cl, "Closing connection to upstream server");

				close(cl->upstream.ufd.fd);
				cl->upstream.ufd.fd = -1;
			}

			cl->action = NULL;
		}

		uwsd_state_transition(cl, STATE_CONN_IDLE);
		uwsd_io_flush(&cl->downstream);
	}
	else {
		uwsd_state_transition(cl, STATE_CONN_UPSTREAM_RECV);
	}
}

__hidden void
uwsd_http_state_downstream_recv(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	if (!uwsd_io_readahead(&cl->downstream))
		return; /* failure */

	if (!http_request_recv(cl))
		return; /* failure */

	uwsd_state_transition(cl, STATE_CONN_UPSTREAM_SEND);
}

__hidden void
uwsd_http_state_downstream_timeout(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	client_free(cl, "client response send timeout");
}
