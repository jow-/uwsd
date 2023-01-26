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

#ifndef UWSD_STATE_H
#define UWSD_STATE_H

#include <stdbool.h>
#include <stdint.h>

#include "util.h"


typedef struct uwsd_client_context uwsd_client_context_t;

#define CONN_STATE_LIST			\
	STATE(ACCEPT),				\
	STATE(IDLE),				\
	STATE(REQUEST),				\
	STATE(RESPONSE),			\
	STATE(UPSTREAM_CONNECT),	\
	STATE(UPSTREAM_SEND),		\
	STATE(UPSTREAM_RECV),		\
	STATE(DOWNSTREAM_SEND),		\
	STATE(DOWNSTREAM_RECV),		\
	STATE(WS_IDLE),				\
	STATE(WS_UPSTREAM_CONNECT),	\
	STATE(WS_UPSTREAM_SEND),	\
	STATE(WS_DOWNSTREAM_SEND),	\
	STATE(WS_DOWNSTREAM_RECV)

typedef enum uwsd_connection_state {
#define STATE(name) STATE_CONN_##name
	CONN_STATE_LIST
#undef STATE
} uwsd_connection_state_t;

enum {
	CHANNEL_DOWNSTREAM = (1 << 0),
	CHANNEL_UPSTREAM   = (1 << 1)
};

enum {
	EVENT_READABLE = (1 << 0),
	EVENT_WRITABLE = (1 << 1)
};

typedef enum {
	TIMEOUT_NONE,

	TIMEOUT_DOWNSTREAM_REQUEST,
	TIMEOUT_DOWNSTREAM_TRANSFER,
	TIMEOUT_DOWNSTREAM_IDLE,

	TIMEOUT_UPSTREAM_CONNECT,
	TIMEOUT_UPSTREAM_TRANSFER,

	TIMEOUT_XSTREAM_IDLE
} uwsd_timeout_kind_t;

typedef struct {
	uint8_t channels;
	uint8_t events;
	void (*io_cb)(uwsd_client_context_t *, uwsd_connection_state_t, bool);
	uwsd_timeout_kind_t timeout;
	void (*timeout_cb)(uwsd_client_context_t *, uwsd_connection_state_t, bool);
} uwsd_state_entry_t;

__hidden void uwsd_state_init(uwsd_client_context_t *, uwsd_connection_state_t);
__hidden void uwsd_state_transition(uwsd_client_context_t *, uwsd_connection_state_t);

#endif /* UWSD_STATE_H */
