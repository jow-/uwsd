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

#ifndef UWSD_HTTP_H
#define UWSD_HTTP_H

#include <stdint.h>
#include <stdbool.h>

#include "util.h"

#define HTTP_STATE_LIST			\
	STATE(REQUEST_METHOD),		\
	STATE(REQUEST_URI),			\
	STATE(REQUEST_VERSION),		\
	STATE(REQUESTLINE_LF),		\
								\
	STATE(STATUS_VERSION),		\
	STATE(STATUS_CODE),			\
	STATE(STATUS_MESSAGE),		\
	STATE(STATUSLINE_LF),		\
								\
	STATE(HEADERLINE),			\
	STATE(HEADERLINE_LF),		\
								\
	STATE(BODY_KNOWN_LENGTH),	\
	STATE(BODY_UNTIL_EOF),		\
								\
	STATE(CHUNK_HEADER),		\
	STATE(CHUNK_HEADER_EXT),	\
	STATE(CHUNK_HEADER_LF),		\
	STATE(CHUNK_DATA),			\
	STATE(CHUNK_DATA_CR),		\
	STATE(CHUNK_DATA_LF),		\
	STATE(CHUNK_TRAILER),		\
	STATE(CHUNK_TRAILLINE),		\
	STATE(CHUNK_TRAILLINE_LF),	\
	STATE(CHUNK_TRAILER_LF),	\
	STATE(CHUNK_DONE),			\
								\
	STATE(REQUEST_DONE),		\
	STATE(BODY_CLOSE)

typedef enum {
	HTTP_WANT_CLOSE   = (1 << 0),
	HTTP_SEND_PLAIN   = (1 << 1),
	HTTP_SEND_CHUNKED = (1 << 2),
	HTTP_SEND_COPY    = (1 << 3),
	HTTP_SEND_FILE    = (1 << 4),
} uwsd_http_flag_t;

typedef enum {
	HTTP_GET,
	HTTP_POST,
	HTTP_PUT,
	HTTP_HEAD,
	HTTP_OPTIONS,
	HTTP_DELETE,
	HTTP_TRACE,
	HTTP_CONNECT
} uwsd_http_method_t;

typedef struct {
	char *name;
	char *value;
} uwsd_http_header_t;

typedef enum {
#define STATE(name) STATE_HTTP_##name
	HTTP_STATE_LIST
#undef STATE
} uwsd_http_state_t;

typedef struct uwsd_client_context uwsd_client_context_t;
typedef enum uwsd_connection_state uwsd_connection_state_t;

#define UWSD_HTTP_REPLY_EMPTY	"\127"
#define UWSD_HTTP_REPLY_EOH		NULL

__attribute__((__format__ (__printf__, 6, 0)))
__hidden size_t uwsd_http_reply_buffer_varg(char *, size_t, double, uint16_t, const char *, const char *, va_list);

__attribute__((__format__ (__printf__, 4, 0)))
__hidden size_t uwsd_http_reply(uwsd_client_context_t *, uint16_t, const char *, const char *, ...);

static inline size_t
uwsd_http_reply_buffer(void *buf, size_t buflen, double http_version,
                       uint16_t code, const char *reason, const char *fmt, ...)
{
	va_list ap;
	size_t len;

	va_start(ap, fmt);
	len = uwsd_http_reply_buffer_varg((char *)buf, buflen, http_version, code, reason, fmt ? fmt : "\127", ap);
	va_end(ap);

	return len;
}

#define uwsd_http_error_send(cl, code, reason, msg, ...)				\
	do {																\
		uwsd_http_reply(cl, code, reason, msg,							\
			##__VA_ARGS__,												\
			"Connection", "close", UWSD_HTTP_REPLY_EOH);				\
																		\
		if (uwsd_http_reply_send(cl, true))								\
			client_free(cl, "%hu (%s)", code, reason ? reason : "-");	\
	} while(0)

#define uwsd_http_error_return(cl, ...)									\
	do {																\
		uwsd_http_error_send(cl, __VA_ARGS__);							\
																		\
		return false;													\
	} while (0)

__hidden char *uwsd_http_header_lookup(uwsd_client_context_t *, const char *);
__hidden bool uwsd_http_header_contains(uwsd_client_context_t *, const char *, const char *);

__hidden bool uwsd_http_reply_send(uwsd_client_context_t *, bool);

__hidden void uwsd_http_state_idle_timeout(uwsd_client_context_t *, uwsd_connection_state_t, bool);

__hidden void uwsd_http_state_accept(uwsd_client_context_t *, uwsd_connection_state_t, bool);

__hidden void uwsd_http_state_request_recv(uwsd_client_context_t *, uwsd_connection_state_t, bool);
__hidden void uwsd_http_state_request_timeout(uwsd_client_context_t *, uwsd_connection_state_t, bool);

__hidden void uwsd_http_state_response_send(uwsd_client_context_t *, uwsd_connection_state_t, bool);
__hidden void uwsd_http_state_response_timeout(uwsd_client_context_t *, uwsd_connection_state_t, bool);

__hidden void uwsd_http_state_upstream_connected(uwsd_client_context_t *, uwsd_connection_state_t, bool);
__hidden void uwsd_http_state_upstream_handshake(uwsd_client_context_t *, uwsd_connection_state_t, bool);
__hidden void uwsd_http_state_upstream_send(uwsd_client_context_t *, uwsd_connection_state_t, bool);
__hidden void uwsd_http_state_upstream_recv(uwsd_client_context_t *, uwsd_connection_state_t, bool);
__hidden void uwsd_http_state_upstream_timeout(uwsd_client_context_t *, uwsd_connection_state_t, bool);

__hidden void uwsd_http_state_downstream_send(uwsd_client_context_t *, uwsd_connection_state_t, bool);
__hidden void uwsd_http_state_downstream_recv(uwsd_client_context_t *, uwsd_connection_state_t, bool);
__hidden void uwsd_http_state_downstream_timeout(uwsd_client_context_t *, uwsd_connection_state_t, bool);

#endif /* UWSD_HTTP_H */
