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

#include <libubox/uloop.h>

#include "state.h"
#include "http.h"
#include "ws.h"
#include "client.h"

#define DOWNSTREAM_IDLE_TIMEOUT_MS 60000
#define DOWNSTREAM_HEAD_TIMEOUT_MS 1000
#define DOWNSTREAM_XFER_TIMEOUT_MS 10000

#define UPSTREAM_CONNECT_TIMEOUT_MS 10000
#define UPSTREAM_XFER_TIMEOUT_MS 10000

static const uwsd_state_entry_t states[] = {
	[STATE_CONN_ACCEPT] = {
		.channels   = CHANNEL_DOWNSTREAM,
		.events     = EVENT_READABLE,
		.io_cb      = uwsd_http_state_accept,
		.timeout    = DOWNSTREAM_HEAD_TIMEOUT_MS,
		.timeout_cb = uwsd_http_state_request_timeout
	},

	[STATE_CONN_IDLE] = {
		.channels   = CHANNEL_DOWNSTREAM,
		.events     = EVENT_READABLE,
		.io_cb      = uwsd_http_state_request_header,
		.timeout    = DOWNSTREAM_IDLE_TIMEOUT_MS,
		.timeout_cb = uwsd_http_state_idle_timeout
	},

	[STATE_CONN_REQUEST] = {
		.channels   = CHANNEL_DOWNSTREAM,
		.events     = EVENT_READABLE,
		.io_cb      = uwsd_http_state_request_header,
		.timeout    = DOWNSTREAM_HEAD_TIMEOUT_MS,
		.timeout_cb = uwsd_http_state_request_timeout
	},

	[STATE_CONN_ERROR_ASYNC] = {
		.channels   = CHANNEL_DOWNSTREAM,
		.events     = EVENT_WRITABLE,
		.io_cb      = uwsd_http_state_response_send,
		.timeout    = DOWNSTREAM_XFER_TIMEOUT_MS,
		.timeout_cb = uwsd_http_state_response_timeout
	},
	[STATE_CONN_REPLY_ASYNC] = {
		.channels   = CHANNEL_DOWNSTREAM,
		.events     = EVENT_WRITABLE,
		.io_cb      = uwsd_http_state_response_send,
		.timeout    = DOWNSTREAM_XFER_TIMEOUT_MS,
		.timeout_cb = uwsd_http_state_response_timeout
	},
	[STATE_CONN_REPLY_FILECOPY] = {
		.channels   = CHANNEL_DOWNSTREAM,
		.events     = EVENT_WRITABLE,
		.io_cb      = uwsd_http_state_response_send,
		.timeout    = DOWNSTREAM_XFER_TIMEOUT_MS,
		.timeout_cb = uwsd_http_state_response_timeout
	},
	[STATE_CONN_REPLY_SENDFILE] = {
		.channels   = CHANNEL_DOWNSTREAM,
		.events     = EVENT_WRITABLE,
		.io_cb      = uwsd_http_state_response_sendfile,
		.timeout    = DOWNSTREAM_XFER_TIMEOUT_MS,
		.timeout_cb = uwsd_http_state_response_timeout
	},

	[STATE_CONN_UPSTREAM_CONNECT] = {
		.channels   = CHANNEL_UPSTREAM,
		.events     = EVENT_WRITABLE,
		.io_cb      = uwsd_http_state_upstream_connected,
		.timeout    = UPSTREAM_CONNECT_TIMEOUT_MS,
		.timeout_cb = uwsd_http_state_upstream_timeout
	},

	[STATE_CONN_UPSTREAM_SEND] = {
		.channels   = CHANNEL_UPSTREAM,
		.events     = EVENT_WRITABLE,
		.io_cb      = uwsd_http_state_upstream_send,
		.timeout    = UPSTREAM_XFER_TIMEOUT_MS,
		.timeout_cb = uwsd_http_state_upstream_timeout
	},
	[STATE_CONN_UPSTREAM_RECV] = {
		.channels   = CHANNEL_UPSTREAM,
		.events     = EVENT_READABLE,
		.io_cb      = uwsd_http_state_upstream_recv,
		.timeout    = UPSTREAM_XFER_TIMEOUT_MS,
		.timeout_cb = uwsd_http_state_upstream_timeout
	},

	[STATE_CONN_DOWNSTREAM_SEND] = {
		.channels   = CHANNEL_DOWNSTREAM,
		.events     = EVENT_WRITABLE,
		.io_cb      = uwsd_http_state_downstream_send,
		.timeout    = UPSTREAM_XFER_TIMEOUT_MS,
		.timeout_cb = uwsd_http_state_downstream_timeout
	},
	[STATE_CONN_DOWNSTREAM_RECV] = {
		.channels   = CHANNEL_DOWNSTREAM,
		.events     = EVENT_READABLE,
		.io_cb      = uwsd_http_state_downstream_recv,
		.timeout    = UPSTREAM_XFER_TIMEOUT_MS,
		.timeout_cb = uwsd_http_state_downstream_timeout
	},

	[STATE_CONN_WS_IDLE] = {
		.channels   = CHANNEL_UPSTREAM|CHANNEL_DOWNSTREAM,
		.events     = EVENT_READABLE,
		.io_cb      = uwsd_ws_state_xstream_recv,
		.timeout    = UPSTREAM_XFER_TIMEOUT_MS,
		.timeout_cb = uwsd_ws_state_xstream_timeout
	},

	[STATE_CONN_WS_UPSTREAM_CONNECT] = {
		.channels   = CHANNEL_UPSTREAM,
		.events     = EVENT_WRITABLE,
		.io_cb      = uwsd_ws_state_upstream_connected,
		.timeout    = UPSTREAM_CONNECT_TIMEOUT_MS,
		.timeout_cb = uwsd_ws_state_upstream_timeout
	},

	[STATE_CONN_WS_UPSTREAM_SEND] = {
		.channels   = CHANNEL_UPSTREAM,
		.events     = EVENT_WRITABLE,
		.io_cb      = uwsd_ws_state_upstream_send,
		.timeout    = UPSTREAM_XFER_TIMEOUT_MS,
		.timeout_cb = uwsd_ws_state_upstream_timeout
	},

	[STATE_CONN_WS_DOWNSTREAM_SEND] = {
		.channels   = CHANNEL_DOWNSTREAM,
		.events     = EVENT_WRITABLE,
		.io_cb      = uwsd_ws_state_downstream_send,
		.timeout    = UPSTREAM_XFER_TIMEOUT_MS,
		.timeout_cb = uwsd_ws_state_downstream_timeout
	},
	[STATE_CONN_WS_DOWNSTREAM_RECV] = {
		.channels   = CHANNEL_DOWNSTREAM,
		.events     = EVENT_READABLE,
		.io_cb      = uwsd_ws_state_downstream_recv,
		.timeout    = UPSTREAM_XFER_TIMEOUT_MS,
		.timeout_cb = uwsd_ws_state_downstream_timeout
	}
};

static const char *
state_name(uwsd_connection_state_t state)
{
#ifndef NDEBUG
# define STATE(name)	#name
	const char *statenames[] = {
		CONN_STATE_LIST
	};

	return statenames[state];
# undef STATE
#else
	return NULL;
#endif
}

static void
upstream_ufd_cb(struct uloop_fd *ufd, unsigned int events)
{
	uwsd_client_context_t *cl = container_of(ufd, uwsd_client_context_t, upstream.ufd);

	states[cl->state].io_cb(cl, cl->state, true);
}

static void
upstream_utm_cb(struct uloop_timeout *utm)
{
	uwsd_client_context_t *cl = container_of(utm, uwsd_client_context_t, upstream.utm);

	states[cl->state].timeout_cb(cl, cl->state, true);
}

static void
downstream_ufd_cb(struct uloop_fd *ufd, unsigned int events)
{
	uwsd_client_context_t *cl = container_of(ufd, uwsd_client_context_t, downstream.ufd);

	states[cl->state].io_cb(cl, cl->state, false);
}

static void
downstream_utm_cb(struct uloop_timeout *utm)
{
	uwsd_client_context_t *cl = container_of(utm, uwsd_client_context_t, downstream.utm);

	states[cl->state].timeout_cb(cl, cl->state, false);
}

__hidden void
uwsd_state_init(uwsd_client_context_t *cl, uwsd_connection_state_t state)
{
	cl->upstream.ufd.cb = upstream_ufd_cb;
	cl->upstream.utm.cb = upstream_utm_cb;
	cl->downstream.ufd.cb = downstream_ufd_cb;
	cl->downstream.utm.cb = downstream_utm_cb;

	uwsd_state_transition(cl, state);
}

__hidden void
uwsd_state_transition(uwsd_client_context_t *cl, uwsd_connection_state_t state)
{
	const uwsd_state_entry_t *se = &states[state];
	unsigned int events =
		((se->events & EVENT_WRITABLE) ? ULOOP_WRITE : 0) |
		((se->events & EVENT_READABLE) ? ULOOP_READ : 0);

	if (1) client_debug(cl, "IO state %s -> %s [Td: %lldms] [Tu: %lldms]",
		state_name(cl->state), state_name(state),
		uloop_timeout_remaining64(&cl->downstream.utm),
		uloop_timeout_remaining64(&cl->upstream.utm)
	);

	cl->state = state;

	if (se->channels & CHANNEL_UPSTREAM) {
		uloop_fd_add(&cl->upstream.ufd, events);

		if (se->timeout > -1)
			uloop_timeout_set(&cl->upstream.utm, se->timeout);
		else
			uloop_timeout_cancel(&cl->upstream.utm);
	}
	else {
		uloop_fd_delete(&cl->upstream.ufd);
		uloop_timeout_cancel(&cl->upstream.utm);
	}

	if (se->channels & CHANNEL_DOWNSTREAM) {
		uloop_fd_add(&cl->downstream.ufd, events);

		if (se->timeout > -1)
			uloop_timeout_set(&cl->downstream.utm, se->timeout);
		else
			uloop_timeout_cancel(&cl->downstream.utm);
	}
	else {
		uloop_fd_delete(&cl->downstream.ufd);
		uloop_timeout_cancel(&cl->downstream.utm);
	}
}
