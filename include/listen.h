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
#include "ssl.h"


typedef enum {
	UWSD_PROTOCOL_HTTP,
	UWSD_PROTOCOL_WS,
} uwsd_protocol_t;

typedef enum {
	UWSD_ACTION_FILE,
	UWSD_ACTION_DIRECTORY,
	UWSD_ACTION_SCRIPT,
	UWSD_ACTION_BACKEND,
	UWSD_ACTION_TCP_PROXY,
	UWSD_ACTION_UDP_PROXY,
	UWSD_ACTION_UNIX_PROXY,
} uwsd_action_type_t;

typedef struct uwsd_action {
	struct list_head list;
	uwsd_action_type_t type;
	union {
		struct {
			char *path;
			char *content_type;
		} file;
		struct
		{
			char *path;
			char *content_type;
			char **index_filenames;
			bool directory_listing;
		} directory;
		struct {
			struct uloop_timeout timeout;
			struct uloop_process proc;
			struct uloop_fd out, err;
			struct sockaddr_un sun;
			char *path;
			char **env;
		} script;
		struct {
			int connect_timeout, transfer_timeout, idle_timeout;
			char *hostname;
			uint16_t port;
			bool binary;
			char *subprotocol;
		} proxy;
		struct uwsd_action *action;
	} data;
} uwsd_action_t;

typedef enum {
	UWSD_MATCH_PROTOCOL,
	UWSD_MATCH_HOSTNAME,
	UWSD_MATCH_PATH,
} uwsd_match_type_t;

typedef struct {
	struct list_head list;
	struct list_head matches;
	struct list_head auth;
	uwsd_match_type_t type;
	uwsd_action_t *default_action;
	union {
		uwsd_protocol_t protocol;
		char *value;
	} data;
} uwsd_match_t;

typedef struct {
	struct list_head list;
	char *name;
	uwsd_action_t *default_action;
} uwsd_backend_t;

typedef struct {
	struct list_head list;
	char *hostname;
	uint16_t port;
	struct uloop_fd ufd;
	struct list_head matches;
	struct list_head auth;
	int request_timeout, transfer_timeout, idle_timeout;
	uwsd_action_t *default_action;
	uwsd_ssl_t *ssl;
} uwsd_listen_t;


__hidden bool uwsd_listen_init(uwsd_listen_t *, const char *, uint16_t);
__hidden void uwsd_listen_free(uwsd_listen_t *);

#endif /* UWSD_LISTEN_H */
