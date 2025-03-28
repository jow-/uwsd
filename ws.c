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
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

#include <sys/uio.h>
#include <sys/ioctl.h>

#include <libubox/usock.h>
#include <libubox/utils.h>

#include "client.h"
#include "http.h"
#include "ws.h"
#include "state.h"
#include "script.h"
#include "log.h"
#include "config.h"
#include "io.h"

#include "teeny-sha1.h"


#ifndef NDEBUG
static const char *
ws_state_name(uwsd_ws_state_t state)
{
# define STATE(name)	#name
	const char *statenames[] = {
		WS_STATE_LIST
	};

	return statenames[state];
# undef STATE
}
#endif

static void
ws_state_transition(uwsd_client_context_t *cl, uwsd_ws_state_t state)
{
	uwsd_ws_debug(cl, "state %s -> %s",
		ws_state_name(cl->ws.state),
		ws_state_name(state));

	cl->ws.state = state;
	cl->ws.buflen = 0;
}

static void __attribute__((format (printf, 3, 0)))
ws_terminate(uwsd_client_context_t *cl, uint16_t rcode, const char *msg, ...)
{
	va_list ap;
	char *s;

	cl->ws.error.code = rcode;

	va_start(ap, msg);
	xvasprintf(&s, msg, ap);
	va_end(ap);

	free(cl->ws.error.msg);
	cl->ws.error.msg = s;

	client_free(cl, cl->ws.error.msg);
}

/* Verify frame header */
static bool
ws_verify_frame(uwsd_client_context_t *cl)
{
	switch (cl->ws.header.opcode) {
	case OPCODE_PING:
	case OPCODE_PONG:
	case OPCODE_CLOSE:
		if (!cl->ws.header.fin) {
			uwsd_ws_connection_close(cl, STATUS_PROTOCOL_ERROR, "Control frames must not be fragmented");

			return false;
		}

		if (cl->ws.header.len > 0x7d) {
			uwsd_ws_connection_close(cl, STATUS_PROTOCOL_ERROR, "Control frame payload too long");

			return false;
		}

		break;

	case OPCODE_TEXT:
	case OPCODE_BINARY:
		if (cl->ws.fragments) {
			uwsd_ws_connection_close(cl, STATUS_PROTOCOL_ERROR, "Expecting continuation frame");

			return false;
		}

		cl->ws.fragments = !cl->ws.header.fin;
		break;

	case OPCODE_CONTINUATION:
		if (!cl->ws.fragments) {
			uwsd_ws_connection_close(cl, STATUS_PROTOCOL_ERROR, "Unexpected continuation frame");

			return false;
		}

		if (cl->ws.header.fin)
			cl->ws.fragments = 0;
		else
			cl->ws.fragments++;

		break;

	default:
		uwsd_ws_connection_close(cl, STATUS_PROTOCOL_ERROR, "Unrecognized opcode");

		return false;
	}

	return true;
}

/* One downstream RX operation */
static bool
ws_downstream_rx(uwsd_client_context_t *cl)
{
	uwsd_connection_t *conn = &cl->downstream;
	int ch;

	uwsd_iov_put(cl,
		uwsd_io_getpos(conn),
		size_t_min(cl->ws.len - cl->ws.buflen, uwsd_io_pending(conn)));

	while (cl->ws.state != STATE_WS_COMPLETE) {
		ch = uwsd_io_getc(&cl->downstream);

		if (ch == EOF)
			break;

		switch (cl->ws.state) {
		case STATE_WS_HEADER:
			cl->ws.buf.data[cl->ws.buflen++] = ch;

			if (cl->ws.buflen == sizeof(ws_frame_header_t)) {
				cl->ws.header = cl->ws.buf.frameheader.hdr;
				cl->ws.len = cl->ws.header.len;

				if (!cl->ws.header.mask) {
					uwsd_ws_connection_close(cl, STATUS_PROTOCOL_ERROR, "Client frames must be masked");

					return false;
				}

				if (cl->ws.buf.frameheader.hdr.len == 126)
					ws_state_transition(cl, STATE_WS_EXT_LEN16);
				else if (cl->ws.buf.frameheader.hdr.len == 127)
					ws_state_transition(cl, STATE_WS_EXT_LEN64);
				else
					ws_state_transition(cl, STATE_WS_MASK_KEY);
			}

			break;

		case STATE_WS_EXT_LEN16:
			cl->ws.buf.data[cl->ws.buflen++] = ch;

			if (cl->ws.buflen == sizeof(uint16_t)) {
				cl->ws.len = be16toh(cl->ws.buf.u16);

				if (cl->ws.len <= 0x7d) {
					uwsd_ws_connection_close(cl, STATUS_PROTOCOL_ERROR, "Invalid frame length encoding");

					return false;
				}

				ws_state_transition(cl, STATE_WS_MASK_KEY);
			}

			break;

		case STATE_WS_EXT_LEN64:
			cl->ws.buf.data[cl->ws.buflen++] = ch;

			if (cl->ws.buflen == sizeof(uint64_t)) {
				cl->ws.len = be64toh(cl->ws.buf.u64);

				if (cl->ws.len <= 0xffff || cl->ws.len >= 0x8000000000000000ULL) {
					uwsd_ws_connection_close(cl, STATUS_PROTOCOL_ERROR, "Invalid frame length encoding");

					return false;
				}

				ws_state_transition(cl, STATE_WS_MASK_KEY);
			}

			break;

		case STATE_WS_MASK_KEY:
			cl->ws.buf.data[cl->ws.buflen++] = ch;

			if (cl->ws.buflen == sizeof(cl->ws.buf.mask)) {
				memcpy(cl->ws.mask, cl->ws.buf.mask, sizeof(cl->ws.mask));

				if (!ws_verify_frame(cl))
					return false;

				uwsd_iov_put(cl,
					uwsd_io_getpos(conn), size_t_min(cl->ws.len, uwsd_io_pending(conn)));

				ws_state_transition(cl, cl->ws.len ? STATE_WS_PAYLOAD : STATE_WS_COMPLETE);
			}

			break;

		case STATE_WS_PAYLOAD:
			uwsd_io_getpos(conn)[-1] ^= cl->ws.mask[cl->ws.buflen++ % sizeof(cl->ws.mask)];

			if (cl->ws.buflen == cl->ws.len)
				ws_state_transition(cl, STATE_WS_COMPLETE);

			break;

		default:
			assert(0);
			break;
		}
	}

	return true;
}

static bool
ws_downstream_tx_iov(uwsd_client_context_t *cl)
{
	if (!uwsd_iov_tx(&cl->downstream, STATE_CONN_WS_DOWNSTREAM_SEND))
		return false; /* error or partial send */

	/* we completely sent a close message, tear down connection */
	if (cl->tx[1].iov_base && cl->ws.buf.frameheader.hdr.opcode == OPCODE_CLOSE) {
		if (cl->ws.error.code)
			ws_terminate(cl, cl->ws.error.code, "%s", cl->ws.error.msg ? cl->ws.error.msg : "");
		else
			ws_terminate(cl, STATUS_CONNECTION_CLOSING, "Connection closing");

		return false;
	}

	return true;
}

/* One downstream TX operation */
static bool
ws_downstream_tx(uwsd_client_context_t *cl, uwsd_ws_opcode_t opcode, bool add_header, const void *data, size_t len)
{
	size_t hlen = 0;

	if (add_header) {
		memset(&cl->ws.buf.frameheader, 0, sizeof(cl->ws.buf.frameheader));

		cl->ws.buf.frameheader.hdr.opcode = opcode;
		cl->ws.buf.frameheader.hdr.fin = true;

		if (len > 0xffff) {
			cl->ws.buf.frameheader.hdr.len = 127;
			cl->ws.buf.frameheader.ext.len64 = htobe64(len);
			hlen = sizeof(ws_frame_header_t) + sizeof(uint64_t);
		}
		else if (len > 0x7d) {
			cl->ws.buf.frameheader.hdr.len = 126;
			cl->ws.buf.frameheader.ext.len16 = htobe16(len);
			hlen = sizeof(ws_frame_header_t) + sizeof(uint16_t);
		}
		else {
			cl->ws.buf.frameheader.hdr.len = len;
			hlen = sizeof(ws_frame_header_t);
		}
	}

	uwsd_iov_put(cl,
		&cl->ws.buf.frameheader, hlen,
		data, len);

	errno = 0;

	if (!ws_downstream_tx_iov(cl))
		return false;

	uwsd_state_transition(cl, STATE_CONN_WS_IDLE);

	return true;
}

static bool
ws_script_connect(uwsd_client_context_t *cl)
{
	struct sockaddr_un *sun = &cl->action->data.script.sun;

	if (cl->upstream.ufd.fd == -1) {
		uwsd_http_debug(cl, "connecting to script worker");

		cl->upstream.ufd.fd = socket(AF_UNIX, SOCK_STREAM, 0);

		if (cl->upstream.ufd.fd == -1) {
			uwsd_http_error_send(cl, 502, "Bad Gateway",
				"Unable to spawn UNIX socket: %m");

			return false;
		}

		if (connect(cl->upstream.ufd.fd, (struct sockaddr *)sun, sizeof(*sun)) == -1 && errno != EINPROGRESS) {
			uwsd_http_error_send(cl, 502, "Bad Gateway",
				"Unable to connect to script worker: %m");

			return false;
		}
	}

	return true;
}

__hidden bool
uwsd_ws_connection_accept(uwsd_client_context_t *cl)
{
	const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	uwsd_action_t *action = cl->action;
	int socktype = -1;
	char *key, *buf;
	size_t len, rem;

	/* various request validity checks */
	if (cl->request_method != HTTP_GET) {
		uwsd_http_error_send(cl, 400, "Bad Request",
			"Invalid request method for WebSocket handshake");

		return false;
	}

	key = uwsd_http_header_lookup(cl, "Sec-WebSocket-Version");

	if (!key || strcmp(key, "13")) {
		uwsd_http_error_send(cl, 400, "Bad Request",
			"Missing or unsupported Sec-WebSocket-Version value");

		return false;
	}

	key = uwsd_http_header_lookup(cl, "Sec-WebSocket-Key");

	if (!key || strlen(key) != 24) {
		uwsd_http_error_send(cl, 400, "Bad Request",
			"Missing or invalid Sec-WebSocket-Key header");

		return false;
	}

	/* write client sent key + magic value into scratch buffer */
	buf = uwsd_io_getbuf(&cl->downstream);
	rem = uwsd_io_available(&cl->downstream);
	len = snprintf(buf + 20, rem - 20, "%s%s", key, magic);

	/* calculate binary digest and store it after input string in buffer */
	sha1digest((unsigned char *)buf, NULL, (uint8_t *)buf + 20, len);

	if (action->type == UWSD_ACTION_TCP_PROXY) {
		socktype = USOCK_TCP|USOCK_NONBLOCK;

		uwsd_ws_debug(cl, "connecting to upstream TCP server %s:%hu",
			action->data.proxy.hostname, action->data.proxy.port);
	}
	else if (action->type == UWSD_ACTION_UDP_PROXY) {
		socktype = USOCK_UDP|USOCK_NONBLOCK;

		uwsd_ws_debug(cl, "connecting to upstream UDP server %s:%hu",
			action->data.proxy.hostname, action->data.proxy.port);
	}
	else if (action->type == UWSD_ACTION_UNIX_PROXY) {
		uwsd_ws_debug(cl, "connecting to UNIX domain socket %s",
			action->data.proxy.hostname);

		socktype = USOCK_UNIX|USOCK_NONBLOCK;
	}

	if (socktype != -1) {
		cl->upstream.ufd.fd = usock(socktype,
			action->data.proxy.hostname,
			usock_port(action->data.proxy.port));

		if (cl->upstream.ufd.fd == -1) {
			uwsd_http_error_send(cl, 502, "Bad Gateway",
				"Unable to connect to upstream server: %s",
				strerror(errno));

			return false;
		}
	}
	else {
		if (!ws_script_connect(cl))
			return false;
	}

	uwsd_state_transition(cl, STATE_CONN_WS_UPSTREAM_CONNECT);

	return true;
}

__hidden void
uwsd_ws_state_upstream_connected(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	uwsd_connection_t *conn = &cl->downstream;
	char digest[B64_ENCODE_LEN(20)];

	/* Base64 encode digest */
	b64_encode(uwsd_io_getbuf(conn), 20, digest, sizeof(digest));

	/* NB: Script workers will deal with the HTTP upgrade reply themselves as
	 * it depends on subprotocol accepted by the onConnect() callback. */
	if (cl->action->type == UWSD_ACTION_SCRIPT) {
		if (!uwsd_script_connect(cl, digest))
			return;

		uwsd_state_transition(cl, STATE_CONN_WS_IDLE);
	}
	else {
		/* Format handshake reply */
		uwsd_http_reply(cl, 101, "Switching Protocols", UWSD_HTTP_REPLY_EMPTY,
			"Upgrade", "WebSocket",
			"Connection", "Upgrade",
			"Sec-WebSocket-Accept", digest,
			/* NB: We could probably do better here and reject the handshake if the
			 * configured subprotocol does not match the client proposal, however I
			 * couldn't figure out a best practice to do so. Simply reply with our
			 * statically configured subprotocol (or none at all) and let the client
			 * deal with it. */
			"Sec-WebSocket-Protocol", cl->action->data.proxy.subprotocol,
			UWSD_HTTP_REPLY_EOH);

		/* Send handshake reply */
		ws_downstream_tx(cl, 0, false, uwsd_io_getbuf(conn), uwsd_io_offset(conn));
	}
}

static bool
ws_handle_frame_payload(uwsd_client_context_t *cl)
{
	switch (cl->ws.header.opcode) {
	/* for control frames, aggregate payload into internal buffer */
	case OPCODE_PING:
	case OPCODE_PONG:
	case OPCODE_CLOSE:
		memcpy(cl->ws.buf.data + cl->ws.buflen, cl->tx[0].iov_base, cl->tx[0].iov_len);
		cl->ws.buflen += cl->tx[0].iov_len;

		cl->tx[0].iov_base += cl->tx[0].iov_len;
		cl->tx[0].iov_len = 0;

		return true;

	/* for other frames, forward payload upstream */
	default:
		if (cl->action->type == UWSD_ACTION_SCRIPT) {
			if (!uwsd_script_send(cl, cl->tx[0].iov_base, cl->tx[0].iov_len))
				return false; // XXX: switch to upstream TX mode on partial write

			cl->tx[0].iov_base += cl->tx[0].iov_len;
			cl->tx[0].iov_len = 0;

			return true;
		}

		return uwsd_iov_tx(&cl->upstream, STATE_CONN_WS_UPSTREAM_SEND);
	}
}

static bool
ws_handle_frame_completion(uwsd_client_context_t *cl, void *data, size_t len)
{
	switch (cl->ws.header.opcode) {
	/* echo PING payload back as PONG message */
	case OPCODE_PING:
		return uwsd_ws_reply_send(cl, OPCODE_PONG, data, len);

	/* echo CLOSE message, will trigger connection teardown */
	case OPCODE_CLOSE:
		if (len >= sizeof(uint16_t)) {
			free(cl->ws.error.msg);
			memcpy(&cl->ws.error.code, data, sizeof(uint16_t));
			cl->ws.error.code = be16toh(cl->ws.error.code);
			cl->ws.error.msg = strndup(data + sizeof(uint16_t), len - sizeof(uint16_t));
		}

		return uwsd_ws_reply_send(cl, OPCODE_CLOSE, data, len);

	/* nothing to do for other frames */
	default:
		return true;
	}
}

static void
uwsd_ws_state_upstream_send(uwsd_client_context_t *cl, uwsd_connection_state_t state)
{
	if (!uwsd_iov_tx(&cl->upstream, STATE_CONN_WS_UPSTREAM_SEND))
		return; /* partial write, connection closure or error */

	uwsd_io_flush(&cl->upstream);
	uwsd_state_transition(cl, STATE_CONN_WS_IDLE);
}

static void
uwsd_ws_state_upstream_recv(uwsd_client_context_t *cl, uwsd_connection_state_t state)
{
	bool done;

	if (!uwsd_io_readahead(&cl->upstream))
		return; /* error */

	if (cl->action->type == UWSD_ACTION_SCRIPT) {
		/* Assume that the worker already sent a close frame */
		if (!uwsd_io_pending(&cl->upstream))
			return client_free(cl, "Upstream closed connection");

		uwsd_iov_put(cl, uwsd_io_getpos(&cl->upstream), uwsd_io_pending(&cl->upstream));
		uwsd_io_consume(&cl->upstream, uwsd_io_pending(&cl->upstream));

		done = ws_downstream_tx_iov(cl);
	}
	else {
		if (!uwsd_io_pending(&cl->upstream))
			return uwsd_ws_connection_close(cl, STATUS_GOING_AWAY, "Upstream closed connection");

		done = ws_downstream_tx(cl,
			cl->action->data.proxy.binary ? OPCODE_BINARY : OPCODE_TEXT,
			true, uwsd_io_getpos(&cl->upstream), uwsd_io_pending(&cl->upstream));
	}

	if (!done)
		return; /* partial write, connection closure or error */

	/* reset IO timeouts */
	uwsd_state_transition(cl, STATE_CONN_WS_IDLE);
}

static void
uwsd_ws_state_downstream_send(uwsd_client_context_t *cl, uwsd_connection_state_t state)
{
	if (!ws_downstream_tx_iov(cl))
		return; /* partial write, connection closure or error */

	uwsd_io_flush(&cl->downstream);
	uwsd_state_transition(cl, STATE_CONN_WS_IDLE);
}

static void
uwsd_ws_state_downstream_recv(uwsd_client_context_t *cl, uwsd_connection_state_t state)
{
	size_t len;

	if (!uwsd_io_readahead(&cl->downstream))
		return; /* failure */

	while (uwsd_io_pending(&cl->downstream)) {
		if (!ws_downstream_rx(cl))
			return; /* failure */

		if (cl->ws.state < STATE_WS_PAYLOAD)
			return; /* await more data */

		if (cl->ws.state == STATE_WS_PAYLOAD) {
			if (!ws_handle_frame_payload(cl))
				return; /* partial send or error */
		}

		if (cl->ws.state == STATE_WS_COMPLETE) {
			len = cl->ws.buflen;

			ws_state_transition(cl, STATE_WS_HEADER); /* expect next frame */

			if (!ws_handle_frame_payload(cl))
				return; /* partial send or error */

			if (!ws_handle_frame_completion(cl, cl->ws.buf.data, len))
				return; /* partial send or error */
		}
	}
}

__hidden bool
uwsd_ws_reply_send(uwsd_client_context_t *cl, uwsd_ws_opcode_t opcode, const void *data, size_t datalen)
{
	return ws_downstream_tx(cl, opcode, true, data, datalen);
}

__hidden void __attribute__((format (printf, 3, 0)))
uwsd_ws_connection_close(uwsd_client_context_t *cl, uint16_t code, const char *message, ...)
{
	va_list ap;
	char *s, *nl;
	int len;

	va_start(ap, message);
	len = xvasprintf(&s, message, ap);
	va_end(ap);

	free(cl->ws.error.msg);
	cl->ws.error.code = code;
	cl->ws.error.msg = s;

	if (len > 123)
		len = 123;

	if ((nl = memchr(cl->ws.error.msg, '\n', len)) != NULL)
		len = nl - cl->ws.error.msg;

	uwsd_io_reset(&cl->upstream);
	uwsd_io_printf(&cl->upstream, "%c%c%.*s", code / 256, code % 256, len, cl->ws.error.msg);

	ws_downstream_tx(cl, OPCODE_CLOSE, true,
		uwsd_io_getbuf(&cl->upstream), uwsd_io_offset(&cl->upstream));
}

__hidden void
uwsd_ws_state_xstream_recv(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	if (upstream)
		uwsd_ws_state_upstream_recv(cl, state);
	else
		uwsd_ws_state_downstream_recv(cl, state);
}

__hidden void
uwsd_ws_state_xstream_send(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	if (upstream)
		uwsd_ws_state_upstream_send(cl, state);
	else
		uwsd_ws_state_downstream_send(cl, state);
}

__hidden void
uwsd_ws_state_xstream_timeout(uwsd_client_context_t *cl, uwsd_connection_state_t state, bool upstream)
{
	if (upstream)
		uwsd_ws_connection_close(cl, STATUS_CONNECTION_CLOSING, "Upstream connection timeout");
	else
		ws_terminate(cl, STATUS_TERMINATED, "Peer connection timeout");
}
