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
#include <assert.h>
#include <fnmatch.h>

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

#define HTTP_METHOD(name) { #name, sizeof(#name) - 1, HTTP_##name }

/* NB: order must be in sync with uwsd_http_method_t of http.h */
static struct {
	const char *name;
	size_t nlen;
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
	while (cl->http_num_headers > 0) {
		cl->http_num_headers--;
		free(cl->http_headers[cl->http_num_headers].name);
		free(cl->http_headers[cl->http_num_headers].value);
	}

	free(cl->http_headers);
	free(cl->request_uri);

	cl->http_status = 0;
	cl->http_headers = NULL;
	cl->request_uri = NULL;
	cl->request_method = HTTP_GET;

	/* Reset buffer state */
	cl->rxbuf.pos = cl->rxbuf.data;
	cl->rxbuf.end = cl->rxbuf.pos;
	cl->rxbuf.sent = cl->rxbuf.end;

	cl->txbuf.pos = cl->txbuf.data;
	cl->txbuf.end = cl->txbuf.pos;

	/* Transition to initial HTTP parsing state */
	http_state_transition(cl, state);
}

static bool
http_header_parse(uwsd_client_context_t *cl, char *line, size_t len, bool essential_only)
{
	char *name, *value, *p, *e = line + len;
	uwsd_http_header_t *hdr = NULL;
	bool continuation;
	size_t i;

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

		if (essential_only &&
		    !strncasecmp(name, "Content-Length", p - name) &&
		    !strncasecmp(name, "Transfer-Encoding", p - name))
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
		hdr->value = xalloc((e - value) + 1);
		memcpy(hdr->value, value, e - value);
	}
	/* ... otherwise append */
	else {
		i = strlen(hdr->value);
		hdr->value = xrealloc(hdr->value, i + (e - value) + 2 + !continuation);

		if (!continuation)
			hdr->value[i++] = ',';

		hdr->value[i++] = ' ';
		memcpy(hdr->value + i, value, e - value);
		hdr->value[i + (e - value)] = '\0';
	}

	return true;
}

#define http_failure(cl, ...)					\
	do {										\
		uwsd_http_error_send(cl, __VA_ARGS__);	\
		return false;							\
	} while (0)

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
http_has_message_body(uint16_t code)
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
http_request_data_callback(uwsd_client_context_t *cl, uwsd_connection_t *conn, void *data, size_t len)
{
	uwsd_action_t *action = cl->action;

	if (conn == &cl->upstream)
		return true;

	if (!action || action->type != UWSD_ACTION_SCRIPT)
		return true;

	return uwsd_script_bodydata(cl, data, len);
}

static bool
http_determine_message_length(uwsd_client_context_t *cl, bool request)
{
	char *clen, *tenc, *e;
	size_t hlen;

	tenc = uwsd_http_header_lookup(cl, "Transfer-Encoding");
	clen = uwsd_http_header_lookup(cl, "Content-Length");

	if (tenc) {
		hlen = strlen(tenc);

		if (hlen < strlen("chunked") ||
		    strncasecmp(tenc + hlen - strlen("chunked"), "chunked", strlen("chunked")) ||
		    (hlen > strlen("chunked") && !strchr(", \r\t\n", tenc[hlen - strlen("chunked") - 1])))
		{
			uwsd_http_error_send(cl, 400, "Bad Request", "Invalid transfer encoding");

			return false;
		}

		http_state_transition(cl, STATE_HTTP_CHUNK_HEADER);
	}
	else if (clen) {
		hlen = strtoull(clen, &e, 10);

		if (e == clen || *e != '\0') {
			uwsd_http_error_send(cl, 400, "Bad Request", "Invalid content length");

			return false;
		}

		cl->request_length = hlen;
		http_state_transition(cl, STATE_HTTP_BODY_KNOWN_LENGTH);
	}
	else if (!request && cl->http_version <= 0x0100 && http_has_message_body(cl->http_status)) {
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
	uint8_t *off, *data;
	ssize_t rlen;

	if (cl->rxbuf.pos == cl->rxbuf.end) {
		rlen = client_recv(conn, cl->rxbuf.data, sizeof(cl->rxbuf.data));

		if (rlen == -1) {
			client_free(cl, "%s recv error: %s",
				(conn == &cl->upstream) ? "upstream" : "downstream",
				strerror(errno));

			return false;
		}

		cl->rxbuf.pos = cl->rxbuf.data;
		cl->rxbuf.end = cl->rxbuf.pos + rlen;
		cl->rxbuf.sent = cl->rxbuf.pos;
	}

	for (off = cl->rxbuf.pos, data = off;
	     cl->http.state != STATE_HTTP_CHUNK_DONE && off < cl->rxbuf.end;
	     off++, cl->rxbuf.pos++)
	{
		switch (cl->http.state) {
		case STATE_HTTP_CHUNK_HEADER:
			if (isxdigit(*off)) {
				cl->http.chunk_len = cl->http.chunk_len * 16 + hex(*off);
			}
			else if (*off == ';') {
				http_state_transition(cl, STATE_HTTP_CHUNK_HEADER_EXT);
			}
			else if (*off == '\r') {
				http_state_transition(cl, STATE_HTTP_CHUNK_HEADER_LF);
			}
			else {
				client_free(cl, "invalid chunk header [%c]", *off);

				return false;
			}

			break;

		case STATE_HTTP_CHUNK_HEADER_EXT:
			if (*off == '\r')
				http_state_transition(cl, STATE_HTTP_CHUNK_HEADER_LF);

			break;

		case STATE_HTTP_CHUNK_HEADER_LF:
			if (*off == '\n') {
				data = off + 1;
				http_state_transition(cl, cl->http.chunk_len ? STATE_HTTP_CHUNK_DATA : STATE_HTTP_CHUNK_TRAILER);
			}
			else {
				client_free(cl, "invalid chunk header");

				return false;
			}

			break;

		case STATE_HTTP_CHUNK_DATA:
			if (--cl->http.chunk_len == 0) {
				if (!http_request_data_callback(cl, conn, data, off - data))
					return false;

				http_state_transition(cl, STATE_HTTP_CHUNK_DATA_CR);
			}

			break;

		case STATE_HTTP_CHUNK_DATA_CR:
			if (*off == '\r') {
				http_state_transition(cl, STATE_HTTP_CHUNK_DATA_LF);
			}
			else {
				client_free(cl, "invalid chunk trailer");

				return false;
			}

			break;

		case STATE_HTTP_CHUNK_DATA_LF:
			if (*off == '\n') {
				http_state_transition(cl, STATE_HTTP_CHUNK_HEADER);
			}
			else {
				client_free(cl, "invalid chunk trailer");

				return false;
			}

			break;

		case STATE_HTTP_CHUNK_TRAILER:
			if (*off == '\r')
				http_state_transition(cl, STATE_HTTP_CHUNK_TRAILER_LF);
			else
				http_state_transition(cl, STATE_HTTP_CHUNK_TRAILLINE);

			break;

		case STATE_HTTP_CHUNK_TRAILER_LF:
			if (*off == '\n') {
				if (!http_request_data_callback(cl, conn, "", 0))
					return false;

				http_state_transition(cl, STATE_HTTP_CHUNK_DONE);
			}
			else {
				client_free(cl, "invalid chunk trailer");

				return false;
			}

			break;

		case STATE_HTTP_CHUNK_TRAILLINE:
			if (*off == '\r')
				http_state_transition(cl, STATE_HTTP_CHUNK_TRAILLINE_LF);

			break;

		case STATE_HTTP_CHUNK_TRAILLINE_LF:
			if (*off == '\n') {
				http_state_transition(cl, STATE_HTTP_CHUNK_TRAILER);
			}
			else {
				client_free(cl, "invalid chunk trailer");

				return false;
			}

			break;

		default:
			return true;
		}
	}

	return true; //(cl->http.state == STATE_HTTP_CHUNK_DONE);
}

static bool
http_contentlen_recv(uwsd_client_context_t *cl, uwsd_connection_t *conn)
{
	ssize_t rlen;

	if (cl->rxbuf.pos == cl->rxbuf.end) {
		rlen = client_recv(conn, cl->rxbuf.data,
			size_t_min(sizeof(cl->rxbuf.data), cl->request_length));

		if (rlen == -1) {
			client_free(cl, "%s recv error: %s",
				(conn == &cl->downstream) ? "downstream" : "upstream",
				strerror(errno));

			return false;
		}

		cl->rxbuf.pos = cl->rxbuf.data + rlen;
		cl->rxbuf.end = cl->rxbuf.pos;
		cl->rxbuf.sent = cl->rxbuf.data;
		cl->request_length -= rlen;
	}
	else {
		rlen = size_t_min(cl->rxbuf.end - cl->rxbuf.pos, cl->request_length);

		cl->rxbuf.pos += rlen;
		cl->request_length -= rlen;
	}

	if (rlen && !http_request_data_callback(cl, conn, cl->rxbuf.pos - rlen, rlen))
		return false;

	if (cl->request_length == 0) {
		if (!http_request_data_callback(cl, conn, "", 0))
			return false;

		http_state_transition(cl, STATE_HTTP_REQUEST_DONE);
	}

	return true;
}

static bool
http_untileof_recv(uwsd_client_context_t *cl, uwsd_connection_t *conn)
{
	ssize_t rlen;

	if (cl->rxbuf.pos == cl->rxbuf.end) {
		rlen = client_recv(conn, cl->rxbuf.data, sizeof(cl->rxbuf.data));

		if (rlen == -1) {
			client_free(cl, "%s recv error: %s",
				(conn == &cl->downstream) ? "downstream" : "upstream",
				strerror(errno));

			return false;
		}

		if (rlen == 0)
			http_state_transition(cl, STATE_HTTP_REQUEST_DONE);

		cl->rxbuf.pos = cl->rxbuf.data;
		cl->rxbuf.end = cl->rxbuf.pos + rlen;
		cl->rxbuf.sent = cl->rxbuf.pos;
	}
	else {
		rlen = cl->rxbuf.end - cl->rxbuf.pos;
		cl->rxbuf.pos = cl->rxbuf.end;
	}

	return http_request_data_callback(cl, conn, cl->rxbuf.pos - rlen, rlen);
}


static bool
http_request_recv(uwsd_client_context_t *cl)
{
	size_t i, len;
	ssize_t rlen;
	uint8_t *off;

	if (cl->rxbuf.pos == cl->rxbuf.end) {
		if (cl->rxbuf.end == cl->rxbuf.data + sizeof(cl->rxbuf.data))
			http_failure(cl, 431, "Request Header Fields Too Large", "Request header too long");

		rlen = client_recv(&cl->downstream, cl->rxbuf.end,
			cl->rxbuf.data + sizeof(cl->rxbuf.data) - cl->rxbuf.end);

		if (rlen == -1) {
			client_free(cl, "downstream recv error: %s", strerror(errno));

			return false;
		}

		if (rlen == 0) {
			client_free(cl, "downstream connection closed");

			return false;
		}

		cl->rxbuf.end += rlen;
	}

	for (off = cl->rxbuf.pos; off < cl->rxbuf.end; off++, cl->rxbuf.pos++) {
		len = cl->txbuf.pos - cl->txbuf.data;

		switch (cl->http.state) {
		case STATE_HTTP_REQUEST_METHOD:
			if (*off == ' ') {
				for (i = 0; i < ARRAY_SIZE(http_request_methods); i++) {
					if (len == http_request_methods[i].nlen &&
					    !strncmp((char *)cl->txbuf.data, http_request_methods[i].name, len)) {
						cl->request_method = http_request_methods[i].method;
						break;
					}
				}

				if (i == ARRAY_SIZE(http_request_methods))
					http_failure(cl, 501, "Not Implemented", "Unsupported request method");

				http_state_transition(cl, STATE_HTTP_REQUEST_URI);
				cl->txbuf.pos = cl->txbuf.data;
			}
			else {
				if (len >= strlen("CONNECT"))
					http_failure(cl, 501, "Not Implemented", "Unsupported request method");

				*cl->txbuf.pos++ = *off;
			}

			break;

		case STATE_HTTP_REQUEST_URI:
			if (*off == ' ') {
				assert(!cl->request_uri);

				cl->request_uri = strndup((char *)cl->txbuf.data, len);

				if (!cl->request_uri)
					http_failure(cl, 500, "Internal Server Error", "Out of memory");

				http_state_transition(cl, STATE_HTTP_REQUEST_VERSION);
				cl->txbuf.pos = cl->txbuf.data;
			}
			else {
				if (len == 0 && isspace(*off))
					continue;

				if (len >= sizeof(cl->txbuf.data))
					http_failure(cl, 414, "URI Too Long", "The reqested URI is too long");

				*cl->txbuf.pos++ = *off;
			}

			break;

		case STATE_HTTP_REQUEST_VERSION:
			if (*off == '\r') {
				if (len == 8 && !strncmp((char *)cl->txbuf.data, "HTTP/0.9", 8))
					cl->http_version = 0x0009;
				else if (len == 8 && !strncmp((char *)cl->txbuf.data, "HTTP/1.0", 8))
					cl->http_version = 0x0100;
				else if (len == 8 && !strncmp((char *)cl->txbuf.data, "HTTP/1.1", 8))
					cl->http_version = 0x0101;
				else
					http_failure(cl, 505, "HTTP Version Not Supported", "Requested protocol version not implemented");

				uwsd_http_info(cl, "> %s %s",
					http_request_methods[cl->request_method].name,
					cl->request_uri);

				http_state_transition(cl, STATE_HTTP_REQUESTLINE_LF);
				cl->txbuf.pos = cl->txbuf.data;
			}
			else {
				if (len == 0 && isspace(*off))
					continue;

				if (len >= strlen("HTTP/1.1"))
					http_failure(cl, 505, "HTTP Version Not Supported", "Requested protocol version not implemented");

				*cl->txbuf.pos++ = *off;
			}

			break;

		case STATE_HTTP_REQUESTLINE_LF:
			if (*off == '\n')
				http_state_transition(cl, STATE_HTTP_HEADERLINE);
			else
				http_failure(cl, 400, "Bad Request", "Invalid request line");

			break;

		case STATE_HTTP_HEADERLINE:
			if (*off == '\r') {
				http_state_transition(cl, STATE_HTTP_HEADERLINE_LF);
			}
			else {
				if (len >= sizeof(cl->txbuf.data))
					http_failure(cl, 431, "Request Header Fields Too Large", "Request header line too long");

				*cl->txbuf.pos++ = *off;
			}

			break;

		case STATE_HTTP_HEADERLINE_LF:
			if (*off == '\n') {
				if (len) {
					if (!http_header_parse(cl, (char *)cl->txbuf.data, len, false))
						http_failure(cl, 400, "Bad Request", "Invalid header line");

					http_state_transition(cl, STATE_HTTP_HEADERLINE);
					cl->txbuf.pos = cl->txbuf.data;
				}
				else {
					/* The following call will transition the state to body, chunked or done */
					cl->rxbuf.pos++;

					return http_determine_message_length(cl, true);
				}
			}
			else {
				http_failure(cl, 400, "Bad Request", "Invalid header line");
			}

			break;

		default:
			return true;
		}
	}

	return true;
}

static bool
http_response_recv(uwsd_client_context_t *cl)
{
	uint8_t *off;
	ssize_t rlen;
	size_t len;

	if (cl->rxbuf.pos == cl->rxbuf.end) {
		rlen = client_recv(&cl->upstream, cl->rxbuf.data, sizeof(cl->rxbuf.data));

		if (rlen == -1)
			http_failure(cl, 502, "Bad Gateway",
				"Upstream receive error: %s", strerror(errno));

		if (rlen == 0) {
			uwsd_log_info(cl, "upstream closed connection");

			http_state_reset(cl, STATE_HTTP_REQUEST_METHOD);
			uwsd_script_close(cl);

			if (cl->upstream.ufd.fd == -1) {
				close(cl->upstream.ufd.fd);
				cl->upstream.ufd.fd = -1;
			}

			cl->action = NULL;

			uwsd_state_transition(cl, STATE_CONN_REQUEST);

			return false;
		}

		cl->rxbuf.pos = cl->rxbuf.data;
		cl->rxbuf.end = cl->rxbuf.pos + rlen;
		cl->rxbuf.sent = cl->rxbuf.pos;
	}

	for (off = cl->rxbuf.pos; off < cl->rxbuf.end; off++, cl->rxbuf.pos++) {
		len = cl->txbuf.pos - cl->txbuf.data;

		switch (cl->http.state) {
		case STATE_HTTP_STATUS_VERSION:
			if (*off == ' ') {
				if (len == 8 && !strncmp((char *)cl->txbuf.data, "HTTP/0.9", 8))
					cl->http_version = 0x0009;
				else if (len == 8 && !strncmp((char *)cl->txbuf.data, "HTTP/1.0", 8))
					cl->http_version = 0x0100;
				else if (len == 8 && !strncmp((char *)cl->txbuf.data, "HTTP/1.1", 8))
					cl->http_version = 0x0101;
				else
					http_failure(cl, 502, "Bad Gateway",
						"Upstream response uses unsupported HTTP protocol version");

				http_state_transition(cl, STATE_HTTP_STATUS_CODE);
				cl->txbuf.pos = cl->txbuf.data;
			}
			else {
				if (len == 0 && isspace(*off))
					continue;

				if (len >= strlen("HTTP/1.1"))
					http_failure(cl, 502, "Bad Gateway",
						"Upstream response uses unsupported HTTP protocol version");

				*cl->txbuf.pos++ = *off;
			}

			break;

		case STATE_HTTP_STATUS_CODE:
			if (*off == ' ') {
				http_state_transition(cl, STATE_HTTP_STATUS_MESSAGE);
				cl->txbuf.pos = cl->txbuf.data;
			}
			else {
				if (len == 0 && isspace(*off))
					continue;

				if (len >= 3 || !isdigit(*off))
					http_failure(cl, 502, "Bad Gateway",
						"Upstream response contains invalid status code");

				cl->http_status = cl->http_status * 10 + (*off - '0');
				cl->txbuf.pos++;
			}

			break;

		case STATE_HTTP_STATUS_MESSAGE:
			if (*off == '\r') {
				assert(!cl->request_uri);

				cl->request_uri = strndup((char *)cl->txbuf.data, len);

				if (!cl->request_uri)
					http_failure(cl, 500, "Internal Server Error", "Out of memory");

				http_state_transition(cl, STATE_HTTP_STATUSLINE_LF);
				cl->txbuf.pos = cl->txbuf.data;
			}
			else {
				if (len == 0 && isspace(*off))
					continue;

				if (len >= sizeof(cl->txbuf.data))
					http_failure(cl, 502, "Bad Gateway",
						"Upstream response contains too long status message");

				*cl->txbuf.pos++ = *off;
			}

			break;

		case STATE_HTTP_STATUSLINE_LF:
			if (*off == '\n') {
				uwsd_http_info(cl, "< %03hu %s", cl->http_status, cl->request_uri);
				http_state_transition(cl, STATE_HTTP_HEADERLINE);
			}
			else
				http_failure(cl, 502, "Bad Gateway",
					"Upstream response contains invalid HTTP status line");

			break;

		case STATE_HTTP_HEADERLINE:
			if (*off == '\r') {
				http_state_transition(cl, STATE_HTTP_HEADERLINE_LF);
			}
			else {
				if (len >= sizeof(cl->txbuf.data))
					http_failure(cl, 502, "Bad Gateway",
						"Upstream response contains too long header line");

				*cl->txbuf.pos++ = *off;
			}

			break;

		case STATE_HTTP_HEADERLINE_LF:
			if (*off == '\n') {
				if (len) {
					http_header_parse(cl, (char *)cl->txbuf.data, len, true);
					http_state_transition(cl, STATE_HTTP_HEADERLINE);
					cl->txbuf.pos = cl->txbuf.data;
				}
				else {
					/* The following call will transition the state to body, chunked or done */
					if (!http_determine_message_length(cl, false))
						return false;
				}
			}
			else {
				http_failure(cl, 502, "Bad Gateway",
					"Upstream response contains invalid header line");
			}

			break;

		case STATE_HTTP_BODY_KNOWN_LENGTH:
			return http_contentlen_recv(cl, &cl->upstream);

		case STATE_HTTP_BODY_UNTIL_EOF:
			return http_untileof_recv(cl, &cl->upstream);

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
			return http_chunked_recv(cl, &cl->upstream);

		case STATE_HTTP_CHUNK_DONE:
		case STATE_HTTP_REQUEST_DONE:
			return true;

		default:
			break;
		}
	}

	return true;
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

__hidden void
uwsd_http_reply_start(uwsd_client_context_t *cl, uint16_t code, const char *reason)
{
	size_t len;

	uwsd_http_info(cl, "R %03hu %s", code, reason ? reason : "-");

	len = snprintf((char *)cl->rxbuf.data, sizeof(cl->rxbuf.data),
		"HTTP/%hu.%hu %hu %s\r\n",
		cl->http_version >> 8,
		cl->http_version & 0xff,
		code, reason
	);

	cl->rxbuf.pos = cl->rxbuf.data;
	cl->rxbuf.end = cl->rxbuf.pos + len;
}

__hidden void
uwsd_http_reply_header(uwsd_client_context_t *cl, const char *name, const char *value)
{
	size_t len;

	len = snprintf((char *)cl->rxbuf.end, cl->rxbuf.data + sizeof(cl->rxbuf.data) - cl->rxbuf.end,
		"%s: %s\r\n", name, value);

	cl->rxbuf.end += len;
}

__hidden void
uwsd_http_reply_finish(uwsd_client_context_t *cl, const char *msg, ...)
{
	va_list ap;

	if (msg && cl->request_method != HTTP_HEAD) {
		va_start(ap, msg);
		cl->rxbuf.end += snprintf((char *)cl->rxbuf.end,
			cl->rxbuf.data + sizeof(cl->rxbuf.data) - cl->rxbuf.end,
			"Content-Type: text/plain\r\n"
			"Content-Length: %d\r\n\r\n",
			vsnprintf("", 0, msg, ap)
		);
		va_end(ap);

		va_start(ap, msg);
		cl->rxbuf.end += vsnprintf((char *)cl->rxbuf.end,
			cl->rxbuf.data + sizeof(cl->rxbuf.data) - cl->rxbuf.end,
			msg, ap);
		va_end(ap);
	}
	else {
		cl->rxbuf.end += snprintf((char *)cl->rxbuf.end,
			cl->rxbuf.data + sizeof(cl->rxbuf.data) - cl->rxbuf.end,
			"\r\n");
	}
}

__hidden bool
uwsd_http_reply_send(uwsd_client_context_t *cl, bool error)
{
	ssize_t len = cl->rxbuf.end - cl->rxbuf.pos;
	ssize_t wlen = client_send(&cl->downstream, cl->rxbuf.pos, len);

	if (wlen != len) {
		uwsd_http_debug(cl, "downstream congested, delay sending %zd bytes [%s]",
			len - (wlen > 0 ? wlen : 0),
			(wlen < 0) ? strerror(errno) : "short write");

		if (wlen > 0)
			cl->rxbuf.pos += wlen;

		uwsd_state_transition(cl, error ? STATE_CONN_ERROR_ASYNC : STATE_CONN_REPLY_ASYNC);

		return false;
	}

	if (error) {
		client_free(cl, "closing connection after HTTP error");

		return false;
	}

	http_state_reset(cl, STATE_HTTP_REQUEST_METHOD);
	uwsd_state_transition(cl, STATE_CONN_IDLE);

	return true;
}

__hidden void
uwsd_http_error_send(uwsd_client_context_t *cl, uint16_t code, const char *reason, const char *msg, ...)
{
	uint16_t version = cl->http_version ? cl->http_version : 0x0100;
	va_list ap;
	size_t len;

	uwsd_http_info(cl, "E %03hu %s", code, reason ? reason : "-");

	len = snprintf((char *)cl->rxbuf.data, sizeof(cl->rxbuf.data),
		"HTTP/%hu.%hu %hu %s\r\n"
		"Connection: close\r\n",
		version >> 8,
		version & 0xff,
		code, reason
	);

	if (msg && cl->request_method != HTTP_HEAD) {
		va_start(ap, msg);
		len += snprintf((char *)cl->rxbuf.data + len, sizeof(cl->rxbuf.data) - len,
			"Content-Type: text/plain\r\n"
			"Content-Length: %d\r\n\r\n",
			vsnprintf("", 0, msg, ap)
		);
		va_end(ap);

		va_start(ap, msg);
		len += vsnprintf((char *)cl->rxbuf.data + len, sizeof(cl->rxbuf.data) - len, msg, ap);
		va_end(ap);
	}
	else {
		len += snprintf((char *)cl->rxbuf.data + len, sizeof(cl->rxbuf.data) - len, "\r\n");
	}

	cl->rxbuf.pos = cl->rxbuf.data;
	cl->rxbuf.end = cl->rxbuf.data + len;

	if (uwsd_http_reply_send(cl, true))
		client_free(cl, "%hu (%s)", code, reason ? reason : "-");
}

static char *
determine_path(uwsd_client_context_t *cl)
{
	uwsd_action_t *action = cl->action;
	char *dst = (action->type == UWSD_ACTION_FILE) ? action->data.file : action->data.directory;
	size_t pfx_len = strlen(cl->prefix);
	char *url = NULL, *path = NULL, *base = NULL;
	size_t req_len = 0;

	url = urldecode(cl->request_uri);

	if (!url) {
		errno = ENOMEM;
		return NULL;
	}

	req_len = strcspn(url, "?");
	url[req_len] = 0;

	base = pathexpand(dst, NULL);

	if (!base) {
		errno = ENOMEM;
		free(url);
		return NULL;
	}

	/* destination is a directory */
	if (action->type == UWSD_ACTION_DIRECTORY) {
		/* backend path prefix is a directory */
		if (pfx_len && cl->prefix[pfx_len - 1] == '/') {
			if (req_len <= pfx_len)
				path = pathexpand("index.html", base);
			else
				path = pathexpand(url + pfx_len, base);
		}

		/* backend path prefix is a file */
		else {
			path = strrchr(url, '/');
			path = pathexpand(path ? path + 1 : url, base);
		}
	}

	/* destination is a file, ignore request url path */
	else {
		path = base;
		base = NULL;
	}

	if (base && path && !pathmatch(base, path)) {
		uwsd_http_debug(cl, "rejecting path: %s", path);
		free(path);
		path = NULL;
		errno = ENOENT;
	}
	else {
		uwsd_http_debug(cl, "resolved path: %s", path);
	}

	free(url);
	free(base);


	return path;
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

		if (cl->upstream.ufd.fd == -1) {
			uwsd_http_error_send(cl, 502, "Bad Gateway",
				"Unable to connect to upstream server: %s",
				strerror(errno));

			return false;
		}
	}

	uwsd_state_transition(cl, STATE_CONN_UPSTREAM_CONNECT);

	return true;
}

static bool
http_file_serve(uwsd_client_context_t *cl)
{
	char szbuf[sizeof("18446744073709551615")];
	char *path = determine_path(cl);
	struct stat s;

	if (cl->request_method != HTTP_GET && cl->request_method != HTTP_HEAD) {
		uwsd_http_error_send(cl, 405, "Method Not Allowed",
			"The used HTTP method is invalid for the requested resource\n");

		return false;
	}

	if (path && stat(path, &s) == 0)
		cl->upstream.ufd.fd = open(path, O_RDONLY);
	else
		cl->upstream.ufd.fd = -1;

	if (cl->upstream.ufd.fd == -1) {
		free(path);

		switch (errno) {
		case EACCES:
			uwsd_http_error_send(cl, 403, "Permission Denied",
				"Access to the requested file is forbidden\n");

			break;

		case ENOENT:
			uwsd_http_error_send(cl, 404, "Not Found",
				"The requested path does not exist on this server\n");

			break;

		default:
			uwsd_http_error_send(cl, 500, "Internal Server Error",
				"Unable to serve requested file: %s\n",
				strerror(errno));

			break;
		}

		return false;
	}

	if (uwsd_file_if_range(cl, &s) &&
	    uwsd_file_if_match(cl, &s) &&
	    uwsd_file_if_modified_since(cl, &s) &&
	    uwsd_file_if_none_match(cl, &s) &&
	    uwsd_file_if_unmodified_since(cl, &s))
	{
		snprintf(szbuf, sizeof(szbuf), "%zu", (size_t)s.st_size);

		uwsd_http_reply_start(cl, 200, "OK");
		uwsd_http_reply_header(cl, "Content-Type", uwsd_file_mime_lookup(path));
		uwsd_http_reply_header(cl, "Content-Length", szbuf);
		uwsd_http_reply_header(cl, "ETag", uwsd_file_mktag(&s));
		uwsd_http_reply_header(cl, "Last-Modified", uwsd_file_unix2date(s.st_mtime));

		if (uwsd_http_header_contains(cl, "Connection", "close"))
			uwsd_http_reply_header(cl, "Connection", "close");

		uwsd_http_reply_finish(cl, NULL);
	}

	free(path);

	uwsd_state_transition(cl, STATE_CONN_REPLY_SENDFILE);

	return true;
}

static bool
http_script_invoke(uwsd_client_context_t *cl)
{
	int scriptpipe[2];

	if (pipe(scriptpipe) == -1) {
		uwsd_http_error_send(cl, 500, "Internal Server Error",
			"Unable to spawn pipe: %s", strerror(errno));

		return false;
	}

	if (!uwsd_script_request(cl, scriptpipe[1])) {
		close(scriptpipe[0]);
		close(scriptpipe[1]);

		return false;
	}

	cl->upstream.ufd.fd = scriptpipe[0];

	uwsd_http_state_upstream_connected(cl, STATE_CONN_UPSTREAM_CONNECT, true);

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
		if (errno == EAGAIN)
			return; /* retry */

		return client_free(cl, "SSL handshake error: %s", strerror(errno));
	}

	uwsd_state_transition(cl, STATE_CONN_REQUEST);
}

/* reading an HTTP request header */
__hidden void
uwsd_http_state_request_header(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	uwsd_action_t *old_action;
	bool ws;

	if (!http_request_recv(cl))
		return; /* failure */

	if (cl->http.state < STATE_HTTP_BODY_KNOWN_LENGTH) {
		uwsd_state_transition(cl, STATE_CONN_REQUEST);

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
			else if (cl->action->type == UWSD_ACTION_FILE ||
			         cl->action->type == UWSD_ACTION_DIRECTORY) {
				if (!http_file_serve(cl))
					return;
			}
			else if (cl->action->type == UWSD_ACTION_SCRIPT) {
				if (!http_script_invoke(cl))
					return;
			}
		}
	}
	else {
		uwsd_http_reply_start(cl, 404, "Not Found");
		uwsd_http_reply_header(cl, "Content-Type", "text/plain");
		uwsd_http_reply_finish(cl,
			"No matching endpoint for %s request to %s",
			ws ? "WebSocket" : "HTTP", cl->request_uri);

		if (!uwsd_http_reply_send(cl, true))
			return;
	}

	if (cl->state == STATE_CONN_IDLE) {
		if (cl->http_version == 0x0100 || uwsd_http_header_contains(cl, "Connection", "close"))
			return client_free(cl, "closing connection");
	}
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
	/* Sending buffered data to stream */
	ssize_t len = cl->rxbuf.end - cl->rxbuf.pos;
	ssize_t wlen = client_send(&cl->downstream, cl->rxbuf.pos, len);

	if (wlen == -1) {
		/* Ignore retryable errors */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return;

		return client_free(cl, "downstream send error: %s", strerror(errno));
	}

	len -= wlen;
	cl->rxbuf.pos += wlen;

	/* Send buffer completely drained, restart recv notifications... */
	if (len == 0) {
		cl->rxbuf.pos = cl->rxbuf.data;
		cl->rxbuf.end = cl->rxbuf.pos;

		if (state == STATE_CONN_REPLY_FILECOPY && cl->request_method != HTTP_HEAD) {
			do {
				len = client_recv(&cl->upstream, cl->rxbuf.data, sizeof(cl->rxbuf.data));
			} while (len == -1 && errno == EINTR);

			if (len == -1)
				return client_free(cl, "file read error: %s", strerror(errno));

			cl->rxbuf.end += len;

			if (len > 0)
				return;
		}

		if (state == STATE_CONN_ERROR_ASYNC)
			return client_free(cl, "closing connection after HTTP error");

		/* Close connection? */
		if (cl->http_version == 0x0100 || uwsd_http_header_contains(cl, "Connection", "close"))
			return client_free(cl, "closing connection");

		http_state_reset(cl, STATE_HTTP_REQUEST_METHOD);
		uwsd_state_transition(cl, STATE_CONN_IDLE);
	}
}

/* when sending file contents via sendfile(2) */
__hidden void
uwsd_http_state_response_sendfile(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	/* Sending buffered data to stream */
	ssize_t wlen;

	if (cl->rxbuf.pos < cl->rxbuf.end) {
		wlen = client_send(&cl->downstream, cl->rxbuf.pos, cl->rxbuf.end - cl->rxbuf.pos);

		if (wlen == -1) {
			/* Ignore retryable errors */
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				return;

			return client_free(cl, "downstream send error: %s", strerror(errno));
		}

		cl->rxbuf.pos += wlen;

		return;
	}

	wlen = client_sendfile(&cl->downstream, cl->upstream.ufd.fd, NULL, sizeof(cl->rxbuf.data));

	if (wlen == -1) {
		if (errno == EINVAL || errno == ENOSYS) {
			uwsd_http_debug(cl, "sendfile(): %s - falling back to recv()/send()", strerror(errno));
			uwsd_state_transition(cl, STATE_CONN_REPLY_FILECOPY);
		}
		else if (errno != EAGAIN) {
			client_free(cl, "downstream sendfile error: %s", strerror(errno));
		}

		return;
	}

	if (wlen == 0) {
		/* Close connection? */
		if (cl->http_version == 0x0100 || uwsd_http_header_contains(cl, "Connection", "close"))
			return client_free(cl, "closing connection");

		http_state_reset(cl, STATE_HTTP_REQUEST_METHOD);
		uwsd_state_transition(cl, STATE_CONN_IDLE);
	}
}

/* when upstream connect takes too long */
__hidden void
uwsd_http_state_upstream_timeout(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	uwsd_http_error_send(cl, 504, "Gateway Timeout", "Timeout while connecting to upstream server");
}

__hidden void
uwsd_http_state_upstream_connected(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	/* request body partially buffered, flush out as well */
	if (cl->rxbuf.pos < cl->rxbuf.end) {
		if (cl->http.state == STATE_HTTP_BODY_KNOWN_LENGTH)
			http_contentlen_recv(cl, NULL);
		else if (cl->http.state == STATE_HTTP_BODY_UNTIL_EOF)
			http_untileof_recv(cl, NULL);
		else
			http_chunked_recv(cl, NULL);
	}
	else if (cl->http.state == STATE_HTTP_REQUEST_DONE) {
		if (!http_request_data_callback(cl, NULL, "", 0))
			return;
	}

	cl->rxbuf.sent = cl->rxbuf.data;

	/* we use a oneway pipe towards the script and won't ever get write readyness,
	 * so directly transition to upstream send callback */
	if (cl->action->type == UWSD_ACTION_SCRIPT)
		return uwsd_http_state_upstream_send(cl, STATE_CONN_UPSTREAM_SEND, true);

	uwsd_state_transition(cl, STATE_CONN_UPSTREAM_SEND);
}

__hidden void
uwsd_http_state_upstream_send(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	ssize_t wlen;

	if (cl->action->type != UWSD_ACTION_SCRIPT) {
		wlen = client_send(&cl->upstream, cl->rxbuf.sent, cl->rxbuf.pos - cl->rxbuf.sent);

		if (wlen == -1) {
			if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
				return;

			return uwsd_http_error_send(cl, 502, "Bad Gateway",
				"Error while sending request to upstream server: %s",
				strerror(errno));
		}

		cl->rxbuf.sent += wlen;
	}
	else {
		cl->rxbuf.sent = cl->rxbuf.pos;
	}

	if (cl->rxbuf.sent == cl->rxbuf.pos) {
		switch (cl->http.state) {
		case STATE_HTTP_BODY_KNOWN_LENGTH:
		case STATE_HTTP_BODY_UNTIL_EOF:
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
			return uwsd_state_transition(cl, STATE_CONN_DOWNSTREAM_RECV);

		case STATE_HTTP_CHUNK_DONE:
		case STATE_HTTP_REQUEST_DONE:
			http_state_transition(cl, STATE_HTTP_STATUS_VERSION);

			if (cl->rxbuf.pos != cl->rxbuf.end) {
				uwsd_http_debug(cl, "Remaining buffer contents (%zd), pipeline request?",
					cl->rxbuf.end - cl->rxbuf.pos);
			}

			http_state_reset(cl, STATE_HTTP_STATUS_VERSION);

			return uwsd_state_transition(cl, STATE_CONN_UPSTREAM_RECV);

		default:
			return client_free(cl, "Unexpected HTTP state: %s", http_state_name(cl->http.state));
		}
	}
}

__hidden void
uwsd_http_state_upstream_recv(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	if (!http_response_recv(cl))
		return; /* failure */

	uwsd_state_transition(cl, STATE_CONN_DOWNSTREAM_SEND);
}

__hidden void
uwsd_http_state_downstream_send(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	ssize_t wlen;

	wlen = client_send(&cl->downstream, cl->rxbuf.sent, cl->rxbuf.end - cl->rxbuf.sent);

	if (wlen == -1) {
		/* Ignore retryable errors */
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return;

		return client_free(cl, "downstream send error: %s", strerror(errno));
	}

	cl->rxbuf.sent += wlen;

	if (cl->rxbuf.sent == cl->rxbuf.end) {
		cl->rxbuf.pos = cl->rxbuf.end;

		if (cl->http.state == STATE_HTTP_CHUNK_DONE || cl->http.state == STATE_HTTP_REQUEST_DONE) {
			http_state_reset(cl, STATE_HTTP_REQUEST_METHOD);
			uwsd_state_transition(cl, STATE_CONN_IDLE);
		}
		else {
			uwsd_state_transition(cl, STATE_CONN_UPSTREAM_RECV);
		}
	}
}

__hidden void
uwsd_http_state_downstream_recv(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	bool ok;

	if (cl->http.state == STATE_HTTP_BODY_KNOWN_LENGTH)
		ok = http_contentlen_recv(cl, &cl->downstream);
	else
		ok = http_chunked_recv(cl, &cl->downstream);

	if (!ok)
		return;

	uwsd_state_transition(cl, STATE_CONN_UPSTREAM_SEND);
}

__hidden void
uwsd_http_state_downstream_timeout(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	client_free(cl, "client response send timeout");
}
