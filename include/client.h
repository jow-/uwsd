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

#ifndef UWSD_CLIENT_H
#define UWSD_CLIENT_H

#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <libubox/list.h>
#include <libubox/uloop.h>

#include "listen.h"
#include "state.h"
#include "util.h"
#include "http.h"
#include "ws.h"


typedef struct uwsd_connection {
	bool upstream;
	void *ssl;
	struct uloop_fd ufd;
	struct uloop_timeout utm;
} uwsd_connection_t;

typedef struct uwsd_client_context {
	struct list_head list;
	uwsd_listen_t *listener;
	uwsd_action_t *action;
	struct list_head *auths;
	char *prefix;
	uwsd_protocol_t protocol;
	union {
		struct sockaddr unspec;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} sa_local;
	union {
		struct sockaddr unspec;
		struct sockaddr_in in;
		struct sockaddr_in6 in6;
	} sa_peer;
	struct {
		uint8_t data[16384];
		uint8_t *pos, *end, *sent;
	} rxbuf;
	struct {
		uint8_t data[10 + 16384];
		uint8_t *pos, *end;
	} txbuf;
	uwsd_connection_state_t state;
	uwsd_http_method_t request_method;
	size_t request_length;
	char *request_uri;
	uint16_t http_version, http_status;
	size_t http_num_headers;
	uwsd_http_header_t *http_headers;
	uwsd_connection_t downstream;
	uwsd_connection_t upstream;
	struct {
		uwsd_http_state_t state;
		ssize_t chunk_len;
	} http;
	struct {
		uwsd_ws_state_t state;
		union {
			ws_frame_header_t header;
			uint16_t u16;
			uint64_t u64;
			uint8_t mask[4];
			char data[125];
		} buf;
		struct {
			uint16_t code;
			char *msg;
		} error;
		size_t buflen, fragments;
		ws_frame_header_t header;
		uint64_t len;
		uint8_t mask[4];
		struct list_head txq;
		size_t txqlen;
	} ws;
} uwsd_client_context_t;

__hidden void client_create(int, uwsd_listen_t *, struct sockaddr *, size_t);
__hidden void client_free(uwsd_client_context_t *, const char *, ...);
__hidden void client_free_all(void);

__hidden bool client_accept(uwsd_client_context_t *);
__hidden ssize_t client_pending(uwsd_connection_t *);
__hidden ssize_t client_recv(uwsd_connection_t *, void *, size_t);
__hidden ssize_t client_send(uwsd_connection_t *, const void *, size_t);
__hidden ssize_t client_sendv(uwsd_connection_t *, struct iovec *, size_t);
__hidden ssize_t client_sendfile(uwsd_connection_t *, int, off_t *, size_t);

#endif /* UWSD_CLIENT_H */
