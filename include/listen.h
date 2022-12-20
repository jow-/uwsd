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

#ifndef UWSD_LISTEN_H
#define UWSD_LISTEN_H

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <ucode/vm.h>
#include <libubox/list.h>
#include <libubox/uloop.h>

#include "util.h"

typedef enum {
	UWSD_LISTEN_WS,
	UWSD_LISTEN_WSS,
	UWSD_LISTEN_HTTP,
	UWSD_LISTEN_HTTPS,
} uwsd_listen_type_t;

typedef enum {
	UWSD_BACKEND_SCRIPT,
	UWSD_BACKEND_FILE,
	UWSD_BACKEND_UNIX,
	UWSD_BACKEND_TCP,
	UWSD_BACKEND_UDP,
} uwsd_backend_type_t;

typedef struct uwsd_backend {
	uwsd_backend_type_t type;
	char *addr, *port, *wsproto;
	bool binary;
	struct {
		uc_vm_t vm;
		uc_value_t *onConnect, *onData, *onClose;
		uc_value_t *onRequest, *onBody;
	} script;
} uwsd_backend_t;

typedef struct {
	struct list_head list;
	struct uloop_fd ufd;
	char *addr, *port;
} uwsd_socket_t;

typedef struct {
	struct list_head list;
	uwsd_listen_type_t type;
	char *prefix;
	union {
		struct sockaddr unspec;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} addr;
	uwsd_socket_t *socket;
	uwsd_backend_t backend;
} uwsd_endpoint_t;

__hidden uwsd_endpoint_t *uwsd_endpoint_create(const char *);
__hidden uwsd_endpoint_t *uwsd_endpoint_lookup(struct uloop_fd *, bool, const char *);

__hidden bool uwsd_has_ssl_endpoints(void);

#endif /* UWSD_LISTEN_H */
