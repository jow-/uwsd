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

#include <arpa/inet.h>

#include <libubox/usock.h>
#include <libubox/utils.h>

#include "listen.h"
#include "client.h"
#include "config.h"
#include "log.h"


static void
accept_cb(struct uloop_fd *ufd, unsigned int events)
{
	uwsd_listen_t *listen = container_of(ufd, uwsd_listen_t, ufd);
	socklen_t alen = sizeof(struct sockaddr_in6);
	struct sockaddr_in6 sa = { 0 };
	int fd;

	fd = accept(ufd->fd, &sa, &alen);

	if (fd == -1) {
		uwsd_log_err(NULL, "accept failed: %m");

		return;
	}

	client_create2(fd, listen, (struct sockaddr *)&sa, alen);
}

__hidden bool
uwsd_listen_init(uwsd_listen_t *listen, const char *hostname, uint16_t port)
{
	listen->hostname = xstrdup((hostname && *hostname) ? hostname : "::");
	listen->port = port;

	listen->ufd.cb = accept_cb;
	listen->ufd.fd = usock(
		USOCK_SERVER | USOCK_NONBLOCK | USOCK_TCP,
		listen->hostname, usock_port(listen->port));

	if (listen->ufd.fd == -1) {
		uwsd_log_err(NULL, "Unable to listen on %s:%hu: %m",
			listen->hostname, listen->port);

		return false;
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
