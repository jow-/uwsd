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

#ifndef UWSD_FILE_H
#define UWSD_FILE_H

#include <stdbool.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "util.h"
#include "client.h"

__hidden const char *uwsd_file_mime_lookup(const char *);
__hidden const char *uwsd_file_mktag(struct stat *);
__hidden time_t uwsd_file_date2unix(const char *);
__hidden char *uwsd_file_unix2date(time_t);

__hidden bool uwsd_file_if_match(uwsd_client_context_t *, struct stat *);
__hidden bool uwsd_file_if_modified_since(uwsd_client_context_t *, struct stat *);
__hidden bool uwsd_file_if_none_match(uwsd_client_context_t *, struct stat *);
__hidden bool uwsd_file_if_range(uwsd_client_context_t *, struct stat *);
__hidden bool uwsd_file_if_unmodified_since(uwsd_client_context_t *, struct stat *);

#endif /* UWSD_FILE_H */
