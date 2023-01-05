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
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <sys/time.h>
#include <sys/sendfile.h>
#include <arpa/inet.h>

#include "client.h"
#include "state.h"
#include "http.h"
#include "ws.h"
#include "ssl.h"
#include "log.h"
#include "script.h"

static LIST_HEAD(clients);

__hidden void
client_create(int fd, uwsd_listen_t *listen, struct sockaddr *peeraddr, size_t alen)
{
	uwsd_client_context_t *cl = alloc_obj(uwsd_client_context_t);

	cl->listener = listen;

	cl->rxbuf.pos = cl->rxbuf.data;
	cl->rxbuf.end = cl->rxbuf.pos;

	cl->txbuf.pos = cl->txbuf.data;
	cl->txbuf.end = cl->txbuf.pos;

	cl->upstream.upstream = true;

	cl->downstream.ufd.fd = fd;
	cl->upstream.ufd.fd = -1;

	memcpy(&cl->sa.unspec, peeraddr, alen);

	INIT_LIST_HEAD(&cl->ws.txq);

	list_add_tail(&cl->list, &clients);

	uwsd_log_debug(cl, "connected");

	if (listen->ssl && !uwsd_ssl_init(cl))
		return;

	uwsd_state_init(cl, STATE_CONN_ACCEPT);
}

__hidden void
client_free(uwsd_client_context_t *cl, const char *reason, ...)
{
	ws_txbuf_t *e, *tmp;

#ifndef NDEBUG
	char *msg = NULL;
	va_list ap;

	if (reason) {
		va_start(ap, reason);
		vasprintf(&msg, reason, ap);
		va_end(ap);
	}

	uwsd_log_debug(cl, "destroying context: %s", msg ? msg : "unspecified reason");
	free(msg);
#endif

	uwsd_script_close(cl);

	uloop_timeout_cancel(&cl->upstream.utm);
	uloop_fd_delete(&cl->upstream.ufd);

	if (cl->upstream.ufd.fd != -1)
		close(cl->upstream.ufd.fd);

	uloop_timeout_cancel(&cl->downstream.utm);
	uloop_fd_delete(&cl->downstream.ufd);

	if (cl->downstream.ufd.fd != -1)
		close(cl->downstream.ufd.fd);

	if (cl->downstream.ssl)
		uwsd_ssl_free(cl);

	list_for_each_entry_safe(e, tmp, &cl->ws.txq, list)
		free(e);

	while (cl->http_num_headers > 0)
		free(cl->http_headers[--cl->http_num_headers].name);

	free(cl->http_headers);
	free(cl->request_uri);

	free(cl->ws.error.msg);

	list_del(&cl->list);
	free(cl);
}

__hidden void
client_free_all(void)
{
	uwsd_client_context_t *cl, *tmp;

	list_for_each_entry_safe(cl, tmp, &clients, list) {
		if (cl->protocol == UWSD_PROTOCOL_WS) {
			uwsd_ws_connection_close(cl,
				cl->ws.error.code ? cl->ws.error.code : STATUS_GOING_AWAY,
				cl->ws.error.msg ? cl->ws.error.msg : "Server shutting down");
		}
		else {
			client_free(cl, "server shutdown");
		}
	}
}

__hidden bool
client_accept(uwsd_client_context_t *cl)
{
	if (cl->downstream.ssl)
		return uwsd_ssl_accept(cl);

	return true;
}

__hidden ssize_t
client_recv(uwsd_connection_t *conn, void *data, size_t len)
{
	if (conn->ssl)
		return uwsd_ssl_recv(conn, data, len);

	return read(conn->ufd.fd, data, len);
}

__hidden ssize_t
client_send(uwsd_connection_t *conn, const void *data, size_t len)
{
	if (conn->ssl)
		return uwsd_ssl_send(conn, data, len);

	return write(conn->ufd.fd, data, len);
}

__hidden ssize_t
client_sendv(uwsd_connection_t *conn, struct iovec *iov, size_t len)
{
	if (conn->ssl)
		return uwsd_ssl_sendv(conn, iov, len);

	return writev(conn->ufd.fd, iov, len);
}

__hidden ssize_t
client_sendfile(uwsd_connection_t *conn, int in_fd, off_t *offset, size_t count)
{
	if (conn->ssl) {
		errno = ENOSYS;

		return -1;
	}

	return sendfile(conn->ufd.fd, in_fd, offset, count);
}
