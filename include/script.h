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

#ifndef UWSD_SCRIPT_H
#define UWSD_SCRIPT_H

#include <stdbool.h>

#include "util.h"
#include "listen.h"

struct uwsd_client_context;

__hidden int uwsd_script_worker_main(const char *, const char *);

__hidden bool uwsd_script_init(uwsd_action_t *, const char *);
__hidden bool uwsd_script_connect(struct uwsd_client_context *, const char *);
__hidden bool uwsd_script_send(struct uwsd_client_context *, const void *, size_t);
__hidden void uwsd_script_close(struct uwsd_client_context *);
__hidden void uwsd_script_free(uwsd_action_t *);

__hidden bool uwsd_script_request(struct uwsd_client_context *);
__hidden bool uwsd_script_bodydata(struct uwsd_client_context *, const void *, size_t);

#endif /* UWSD_SCRIPT_H */
