/*
 * Copyright (C) 2023 Jo-Philipp Wich <jo@mein.io>
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

#ifndef UWSD_IO_H
#define UWSD_IO_H

#include <stdint.h>
#include <stdbool.h>

#include <sys/uio.h>

#include "util.h"

#define uwsd_iov_put(cl, ...) _uwsd_iov_put(cl, ##__VA_ARGS__, NULL)

__hidden bool uwsd_iov_send(uwsd_connection_t *, struct iovec *, size_t);
__hidden void _uwsd_iov_put(uwsd_client_context_t *, ...);
__hidden bool uwsd_iov_tx(uwsd_connection_t *, uwsd_connection_state_t);

__hidden bool uwsd_io_recv(uwsd_connection_t *);
__hidden int uwsd_io_strcmp(uwsd_connection_t *, const char *);
__hidden void uwsd_io_flush(uwsd_connection_t *);

__attribute__((format(printf, 2, 0)))
__hidden bool uwsd_io_printf(uwsd_connection_t *conn, const char *, ...);

static inline void
uwsd_io_reset(uwsd_connection_t *conn)
{
	conn->buf.pos = conn->buf.data;
	conn->buf.end = conn->buf.pos;
}

static inline size_t
uwsd_io_offset(uwsd_connection_t *conn)
{
	return conn->buf.pos - conn->buf.data;
}

static inline size_t
uwsd_io_pending(uwsd_connection_t *conn)
{
	return conn->buf.end - conn->buf.pos;
}

static inline size_t
uwsd_io_available(uwsd_connection_t *conn)
{
	return sizeof(conn->buf.data) - uwsd_io_offset(conn);
}

static inline bool
uwsd_io_full(uwsd_connection_t *conn)
{
	return conn->buf.end == conn->buf.data + sizeof(conn->buf.data);
}

static inline bool
uwsd_io_eof(uwsd_connection_t *conn)
{
	return conn->ufd.eof;
}

static inline bool
uwsd_io_readahead(uwsd_connection_t *conn)
{
	return (uwsd_io_pending(conn) || uwsd_io_recv(conn));
}

static inline char *
uwsd_io_getbuf(uwsd_connection_t *conn)
{
	return (char *)conn->buf.data;
}

static inline char *
uwsd_io_getpos(uwsd_connection_t *conn)
{
	return (char *)conn->buf.pos;
}

static inline bool
uwsd_io_putchar(uwsd_connection_t *conn, char c)
{
	if (conn->buf.pos == conn->buf.data + sizeof(conn->buf.data))
		return false;

	*conn->buf.pos++ = (uint8_t)c;

	return true;
}

static inline int
uwsd_io_getc(uwsd_connection_t *conn)
{
	if (conn->buf.pos == conn->buf.end)
		return EOF;

	return (unsigned char)*conn->buf.pos++;
}

static inline int
uwsd_io_nextc(uwsd_connection_t *conn)
{
	if (conn->buf.pos + 1 == conn->buf.end)
		return EOF;

	return (unsigned char)*++conn->buf.pos;
}

static inline bool
uwsd_io_ungetc(uwsd_connection_t *conn)
{
	if (conn->buf.pos == conn->buf.data)
		return false;

	conn->buf.pos--;

	return true;
}

static inline void
uwsd_io_consume(uwsd_connection_t *conn, size_t len)
{
	conn->buf.pos += size_t_min(len, uwsd_io_pending(conn));
}

static inline char *
uwsd_io_strdup(uwsd_connection_t *conn)
{
	return strndup((char *)conn->buf.data, uwsd_io_offset(conn));
}

#endif /* UWSD_IO_H */
