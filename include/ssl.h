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

#ifndef UWSD_SSL_H
#define UWSD_SSL_H

#include <sys/uio.h>

#include <openssl/ssl.h>


typedef struct uwsd_client_context uwsd_client_context_t;
typedef struct uwsd_connection uwsd_connection_t;

typedef struct {
	bool verify_peer;
	char *private_key, *certificate, *certificate_directory, *ciphers;
	struct {
		SSL_CTX **entries;
		size_t count;
	} contexts;
} uwsd_ssl_t;

__hidden bool uwsd_ssl_ctx_init(uwsd_ssl_t *);
__hidden void uwsd_ssl_ctx_free(uwsd_ssl_t *);

__hidden bool uwsd_ssl_init(uwsd_client_context_t *);
__hidden void uwsd_ssl_free(uwsd_client_context_t *);
__hidden bool uwsd_ssl_accept(uwsd_client_context_t *);

__hidden ssize_t uwsd_ssl_pending(uwsd_connection_t *);
__hidden ssize_t uwsd_ssl_recv(uwsd_connection_t *, void *, size_t);
__hidden ssize_t uwsd_ssl_send(uwsd_connection_t *, const void *, size_t);
__hidden ssize_t uwsd_ssl_sendv(uwsd_connection_t *, struct iovec *, size_t);
__hidden ssize_t uwsd_ssl_close(uwsd_connection_t *);

__hidden const char *uwsd_ssl_cipher_name(uwsd_connection_t *);
__hidden const char *uwsd_ssl_peer_subject_name(uwsd_connection_t *);
__hidden const char *uwsd_ssl_peer_issuer_name(uwsd_connection_t *);

#endif /* UWSD_SSL_H */
