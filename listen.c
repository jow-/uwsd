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
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <libubox/usock.h>
#include <libubox/utils.h>

#include "listen.h"
#include "client.h"
#include "config.h"
#include "log.h"


#ifndef HAVE_ACCEPT4
#include <fcntl.h>

enum {
	SOCK_NONBLOCK = (1 << 0),
	SOCK_CLOEXEC  = (1 << 1)
};

static int
accept4(int sockfd, struct sockaddr *addr, socklen_t *addrlen, int flags)
{
	int fd = accept(sockfd, addr, addrlen);

	if (fd == -1)
		return -1;

	if (flags & SOCK_NONBLOCK)
		fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

	if (flags & SOCK_CLOEXEC)
		fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);

	return fd;
}

#endif

static void
listen_block(uwsd_listen_t *listen)
{
	if (listen->blocked)
		return;

	uloop_fd_delete(&listen->ufd);
	listen->blocked = true;

	uwsd_log_warn(NULL, "connection limit reached on %s:%hu, pausing accepts",
		listen->hostname, listen->port);
}

__hidden void
uwsd_listen_update_accept(uwsd_listen_t *listen)
{
	if (!listen || listen->ufd.fd == -1)
		return;

	if (listen->blocked && client_accept_allowed(listen, NULL, 0)) {
		uloop_fd_add(&listen->ufd, ULOOP_READ);
		listen->blocked = false;
	}
}

static void
accept_cb(struct uloop_fd *ufd, unsigned int events)
{
	uwsd_listen_t *listen = container_of(ufd, uwsd_listen_t, ufd);
	socklen_t alen = sizeof(struct sockaddr_in6);
	struct sockaddr_in6 sa = { 0 };
	int fd;

	/* At the global limit, leave pending connections in the kernel backlog
	 * and stop accepting until a client slot is released. */
	if (!client_accept_allowed(listen, NULL, 0)) {
		listen_block(listen);

		return;
	}

	fd = accept4(ufd->fd, (struct sockaddr *)&sa, &alen, SOCK_NONBLOCK|SOCK_CLOEXEC);

	if (fd == -1) {
		uwsd_log_err(NULL, "accept failed: %m");

		return;
	}

	client_create(fd, listen, (struct sockaddr *)&sa, alen);

	if (!client_accept_allowed(listen, NULL, 0))
		listen_block(listen);
}

#define LISTEN_RETRY_INTERVAL 1000
#define LISTEN_RETRY_MAX      30

static void
listen_retry_cb(struct uloop_timeout *t)
{
	uwsd_listen_t *listen = container_of(t, uwsd_listen_t, retry);

	listen->ufd.fd = usock(
		USOCK_SERVER | USOCK_NONBLOCK | USOCK_TCP,
		listen->hostname, usock_port(listen->port));

	if (listen->ufd.fd != -1) {
		uloop_fd_add(&listen->ufd, ULOOP_READ);
		uwsd_log_info(NULL, "Listening on %s:%hu (after %d retries)",
			listen->hostname, listen->port, listen->retry_count);

		return;
	}

	if (++listen->retry_count >= LISTEN_RETRY_MAX) {
		uwsd_log_err(NULL, "Unable to listen on %s:%hu after %d retries: %m",
			listen->hostname, listen->port, listen->retry_count);

		return;
	}

	uloop_timeout_set(&listen->retry, LISTEN_RETRY_INTERVAL);
}

__hidden bool
uwsd_listen_init(uwsd_listen_t *listen, const char *hostname, uint16_t port)
{
	listen->hostname = xstrdup((hostname && *hostname) ? hostname : "::");
	listen->port = port;
	listen->blocked = false;

	listen->ufd.cb = accept_cb;
	listen->ufd.fd = usock(
		USOCK_SERVER | USOCK_NONBLOCK | USOCK_TCP,
		listen->hostname, usock_port(listen->port));

	if (listen->ufd.fd == -1) {
		uwsd_log_info(NULL, "Unable to listen on %s:%hu: %m (retrying...)",
			listen->hostname, listen->port);

		listen->retry_count = 0;
		listen->retry.cb = listen_retry_cb;
		uloop_timeout_set(&listen->retry, LISTEN_RETRY_INTERVAL);

		return true;
	}

	uloop_fd_add(&listen->ufd, ULOOP_READ);

	return true;
}

__hidden void
uwsd_listen_free(uwsd_listen_t *listen)
{
	uloop_fd_delete(&listen->ufd);
	close(listen->ufd.fd);

	free(listen->hostname);
}
