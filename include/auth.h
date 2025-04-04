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

#ifndef UWSD_AUTH_H
#define UWSD_AUTH_H

#include <stdbool.h>

#include "util.h"


struct uwsd_client_context;

typedef enum {
	UWSD_AUTH_BASIC,
	UWSD_AUTH_MTLS,
} uwsd_auth_type_t;

typedef struct {
	struct list_head list;
	uwsd_auth_type_t type;
	union {
		struct {
			char *realm;
			char *username;
			char *password;
			bool lookup_shadow;
		} basic;
		struct {
			char *require_issuer;
			char *require_subject;
		} mtls;
	} data;
} uwsd_auth_t;


__hidden bool auth_check(struct uwsd_client_context *);

#endif /* UWSD_AUTH_H */
