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

#ifndef UWSD_LOG_H
#define UWSD_LOG_H

#include "util.h"
#include "client.h"


typedef enum {
	UWSD_PRIO_DBG,
	UWSD_PRIO_INFO,
	UWSD_PRIO_WARN,
	UWSD_PRIO_ERR
} uwsd_log_priority_t;

typedef enum {
	UWSD_LOG_GLOBAL,
	UWSD_LOG_HTTP,
	UWSD_LOG_WS,
	UWSD_LOG_SSL,
	UWSD_LOG_SCRIPT,
} uwsd_log_channel_t;

extern uwsd_log_priority_t uwsd_logging_priority;
extern unsigned int uwsd_logging_channels;

struct uwsd_client_context;

__hidden __attribute__((format(printf, 4, 0))) void
uwsd_log(uwsd_log_priority_t, uwsd_log_channel_t, struct uwsd_client_context *, const char *, ...);


#ifdef NDEBUG
# define uwsd_log_debug(...)
# define uwsd_http_debug(...)
# define uwsd_ws_debug(...)
# define uwsd_ssl_debug(...)
#else
# define uwsd_log_debug(...) uwsd_log(UWSD_PRIO_DBG, UWSD_LOG_GLOBAL, __VA_ARGS__)
# define uwsd_http_debug(...) uwsd_log(UWSD_PRIO_DBG, UWSD_LOG_HTTP, __VA_ARGS__)
# define uwsd_ws_debug(...) uwsd_log(UWSD_PRIO_DBG, UWSD_LOG_WS, __VA_ARGS__)
# define uwsd_ssl_debug(...) uwsd_log(UWSD_PRIO_DBG, UWSD_LOG_SSL, __VA_ARGS__)
#endif

#define uwsd_log_info(...) uwsd_log(UWSD_PRIO_INFO, UWSD_LOG_GLOBAL, __VA_ARGS__)
#define uwsd_log_warn(...) uwsd_log(UWSD_PRIO_WARN, UWSD_LOG_GLOBAL, __VA_ARGS__)
#define uwsd_log_err(...) uwsd_log(UWSD_PRIO_ERR, UWSD_LOG_GLOBAL, __VA_ARGS__)

#define uwsd_http_info(...) uwsd_log(UWSD_PRIO_INFO, UWSD_LOG_HTTP, __VA_ARGS__)
#define uwsd_http_warn(...) uwsd_log(UWSD_PRIO_WARN, UWSD_LOG_HTTP, __VA_ARGS__)
#define uwsd_http_err(...) uwsd_log(UWSD_PRIO_ERR, UWSD_LOG_HTTP, __VA_ARGS__)

#define uwsd_ws_info(...) uwsd_log(UWSD_PRIO_INFO, UWSD_LOG_WS, __VA_ARGS__)
#define uwsd_ws_warn(...) uwsd_log(UWSD_PRIO_WARN, UWSD_LOG_WS, __VA_ARGS__)
#define uwsd_ws_err(...) uwsd_log(UWSD_PRIO_ERR, UWSD_LOG_WS, __VA_ARGS__)

#define uwsd_ssl_info(...) uwsd_log(UWSD_PRIO_INFO, UWSD_LOG_SSL, __VA_ARGS__)
#define uwsd_ssl_warn(...) uwsd_log(UWSD_PRIO_WARN, UWSD_LOG_SSL, __VA_ARGS__)
#define uwsd_ssl_err(...) uwsd_log(UWSD_PRIO_ERR, UWSD_LOG_SSL, __VA_ARGS__)

#endif /* UWSD_LOG_H */
