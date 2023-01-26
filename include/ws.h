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

#ifndef UWSD_WS_H
#define UWSD_WS_H

#include <stdint.h>
#include <sys/uio.h>
#include <libubox/utils.h>

#include "util.h"

#define WS_STATE_LIST	\
	STATE(HEADER),		\
	STATE(EXT_LEN16),	\
	STATE(EXT_LEN64),	\
	STATE(MASK_KEY),	\
	STATE(PAYLOAD),		\
	STATE(COMPLETE)

typedef enum {
#define STATE(name) STATE_WS_##name
	WS_STATE_LIST
#undef STATE
} uwsd_ws_state_t;

typedef enum {
	OPCODE_CONTINUATION,
	OPCODE_TEXT,
	OPCODE_BINARY,
	OPCODE_RESERVED_3,
	OPCODE_RESERVED_4,
	OPCODE_RESERVED_5,
	OPCODE_RESERVED_6,
	OPCODE_RESERVED_7,
	OPCODE_CLOSE,
	OPCODE_PING,
	OPCODE_PONG,
	OPCODE_RESERVED_11,
	OPCODE_RESERVED_12,
	OPCODE_RESERVED_13,
	OPCODE_RESERVED_14,
	OPCODE_RESERVED_15
} uwsd_ws_opcode_t;

typedef enum {
	STATUS_CONNECTION_CLOSING = 1000,
	STATUS_GOING_AWAY         = 1001,
	STATUS_PROTOCOL_ERROR     = 1002,
	STATUS_NOT_ACCEPTABLE     = 1003,
	STATUS_RESERVED_1004      = 1004,
	STATUS_NO_STATUSCODE      = 1005,
	STATUS_TERMINATED         = 1006,
	STATUS_BAD_ENCODING       = 1007,
	STATUS_POLICY_VIOLATION   = 1008,
	STATUS_MESSAGE_TOO_BIG    = 1009,
	STATUS_EXTENSION_EXPECTED = 1010,
	STATUS_INTERNAL_ERROR     = 1011,
	STATUS_TLS_ERROR          = 1015
} uwsd_ws_status_t;

typedef struct __attribute__((packed)) {
	uint8_t opcode:4;
	uint8_t rsv3:1;
	uint8_t rsv2:1;
	uint8_t rsv1:1;
	uint8_t fin:1;

	uint8_t len:7;
	uint8_t mask:1;
} ws_frame_header_t;

typedef struct uwsd_client_context uwsd_client_context_t;

__hidden bool uwsd_ws_reply_send(uwsd_client_context_t *, uwsd_ws_opcode_t, const void *, size_t);
__hidden bool uwsd_ws_connection_accept(uwsd_client_context_t *);
__hidden void uwsd_ws_connection_close(uwsd_client_context_t *, uint16_t, const char *, ...);

__hidden void uwsd_ws_state_upstream_connected(uwsd_client_context_t *, uwsd_connection_state_t, bool);
__hidden void uwsd_ws_state_upstream_send(uwsd_client_context_t *, uwsd_connection_state_t, bool);
__hidden void uwsd_ws_state_upstream_recv(uwsd_client_context_t *, uwsd_connection_state_t, bool);
__hidden void uwsd_ws_state_upstream_timeout(uwsd_client_context_t *, uwsd_connection_state_t, bool);

__hidden void uwsd_ws_state_downstream_send(uwsd_client_context_t *, uwsd_connection_state_t, bool);
__hidden void uwsd_ws_state_downstream_recv(uwsd_client_context_t *, uwsd_connection_state_t, bool);
__hidden void uwsd_ws_state_downstream_timeout(uwsd_client_context_t *, uwsd_connection_state_t, bool);

__hidden void uwsd_ws_state_xstream_recv(uwsd_client_context_t *, uwsd_connection_state_t, bool);
__hidden void uwsd_ws_state_xstream_timeout(uwsd_client_context_t *, uwsd_connection_state_t, bool);

#endif /* UWSD_WS_H */
