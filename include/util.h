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

#ifndef UWSD_UTIL_H
#define UWSD_UTIL_H

#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/uio.h>
#include <sys/types.h>

#ifndef __hidden
#define __hidden __attribute__((visibility("hidden")))
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))
#endif

#ifndef ALIGN
#define ALIGN(x) (((x) + sizeof(size_t) - 1) & -sizeof(size_t))
#endif

__hidden __attribute__((noreturn)) void fatal(const char *);

#define alloc_obj(type) (type *)xalloc(sizeof(type))

__hidden size_t memspn_common(const void *, size_t, const char *, size_t, bool);
#define memspn(s, n, set) memspn_common(s, n, set, sizeof(set) - 1, false)
#define memcspn(s, n, set) memspn_common(s, n, set, sizeof(set) - 1, true)

__hidden int strspncmp(const char *, const char *, const char *);
__hidden int strspncasecmp(const char *, const char *, const char *);

__hidden char *urldecode(const char *);
__hidden char *pathexpand(const char *, const char *);
__hidden size_t pathmatch(const char *, const char *);

static inline size_t
size_t_min(size_t a, size_t b)
{
	return (a < b) ? a : b;
}

static inline ssize_t
ssize_t_min(ssize_t a, ssize_t b)
{
	return (a < b) ? a : b;
}

__hidden __attribute__((format(printf, 1, 0))) void sys_perror(const char *, ...);

#endif /* UWSD_UTIL_H */
