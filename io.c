/*
 * Copyright (C) 2023 Jo-Philipp Wich <jo@mein.io>
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

#include <errno.h>
#include <stdarg.h>

#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include "client.h"
#include "http.h"
#include "log.h"
#include "io.h"

static uwsd_client_context_t *
conn_to_ctx(uwsd_connection_t *conn)
{
	if (conn->upstream)
		 return container_of(conn, uwsd_client_context_t, upstream);

	return container_of(conn, uwsd_client_context_t, downstream);
}

__hidden bool
uwsd_iov_send(uwsd_connection_t *conn, struct iovec *iov, size_t len)
{
	ssize_t wlen;
	size_t i;

	errno = 0;
	wlen = client_sendv(conn, iov, len);

	if (wlen == -1) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			errno = 0;

		return false;
	}

	for (i = 0; i < len && wlen > 0; i++) {
		if ((size_t)wlen > iov[i].iov_len) {
			wlen -= iov[i].iov_len;
			iov[i].iov_base += iov[i].iov_len;
			iov[i].iov_len = 0;
		}
		else {
			iov[i].iov_base += wlen;
			iov[i].iov_len -= wlen;
			wlen = 0;

			if (iov[i].iov_len)
				return false;
		}
	}

	return true;
}

__hidden void
_uwsd_iov_put(uwsd_client_context_t *cl, ...)
{
	va_list ap;
	size_t i;

	va_start(ap, cl);

	memset(cl->tx, 0, sizeof(cl->tx));

	for (i = 0; i < ARRAY_SIZE(cl->tx); i++) {
		cl->tx[i].iov_base = va_arg(ap, void *);

		if (!cl->tx[i].iov_base)
			break;

		cl->tx[i].iov_len = va_arg(ap, size_t);
	}

	va_end(ap);
}

__hidden bool
uwsd_iov_tx(uwsd_connection_t *conn, uwsd_connection_state_t next_state)
{
	uwsd_client_context_t *cl = conn_to_ctx(conn);

	errno = 0;

	if (!uwsd_iov_send(conn, cl->tx, ARRAY_SIZE(cl->tx))) {
		if (errno) {
			if (conn == &cl->downstream)
				client_free(cl, "downstream send error: %m");
			else if (cl->protocol == UWSD_PROTOCOL_WS)
				uwsd_ws_connection_close(cl, STATUS_INTERNAL_ERROR,
					"Error while sending data to upstream server: %m");
			else
				uwsd_http_error_send(cl, 502, "Bad Gateway",
					"Error while sending data to upstream server: %m\n");
		}
		else {
			uwsd_http_debug(cl, "Partial TX, delaying sending remainder...");
			uwsd_state_transition(cl, next_state);
		}

		return false;
	}

	return true;
}

__hidden bool
uwsd_io_recv(uwsd_connection_t *conn)
{
	uwsd_client_context_t *cl = conn_to_ctx(conn);
	ssize_t rlen;

	errno = 0;

	conn->buf.pos = conn->buf.data;
	conn->buf.end = conn->buf.pos;

	while (conn->buf.end != conn->buf.data + sizeof(conn->buf.data)) {
		rlen = client_recv(conn, conn->buf.end,
			sizeof(conn->buf.data) - (conn->buf.end - conn->buf.data));

		if (rlen == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;

			if (errno == EINTR)
				continue;

			client_free(cl, "%s recv error: %m", conn->upstream ? "upstream" : "downstream");

			return false;
		}

		if (rlen == 0)
			break;

		conn->buf.end += rlen;
	}

	return true;
}

__hidden void
uwsd_io_flush(uwsd_connection_t *conn)
{
#ifdef __linux__
	setsockopt(conn->ufd.fd, IPPROTO_TCP, TCP_NODELAY, &(int){ 1 }, sizeof(int));
	setsockopt(conn->ufd.fd, IPPROTO_TCP, TCP_NODELAY, &(int){ 0 }, sizeof(int));
#endif
}

__hidden int
uwsd_io_strcmp(uwsd_connection_t *conn, const char *str)
{
	size_t blen = uwsd_io_offset(conn);
	size_t slen = strlen(str);

	if (blen < slen)
		return -str[blen];

	if (blen > slen)
		return conn->buf.data[slen];

	return strncmp(uwsd_io_getbuf(conn), str, slen);
}

__hidden bool __attribute__((format(printf, 2, 0)))
uwsd_io_printf(uwsd_connection_t *conn, const char *fmt, ...)
{
	ssize_t rem = uwsd_io_available(conn);
	ssize_t len;
	va_list ap;

	va_start(ap, fmt);
	len = vsnprintf(uwsd_io_getpos(conn), rem, fmt, ap);
	va_end(ap);

	if (len == -1)
		return false;

	if (len >= rem) {
		conn->buf.pos += rem;

		return false;
	}

	conn->buf.pos += len;
	conn->buf.end += len;

	return true;
}
