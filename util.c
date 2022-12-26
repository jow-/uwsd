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
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>

#include "util.h"

__hidden __attribute__((noreturn)) void
fatal(const char *msg)
{
	if (errno)
		fprintf(stderr, "%s: %s\n", msg, strerror(errno));
	else
		fprintf(stderr, "%s\n", msg);

	exit(1);
}

__hidden size_t
memspn_common(const void *s, size_t n, const char *set, size_t m, bool invert)
{
	uint64_t mask[(1 << CHAR_BIT) / (sizeof(uint64_t) * CHAR_BIT)] = { 0 };
	const uint8_t *u8 = s;

	#define mask_off(n) mask[((unsigned char)(n) / (sizeof(mask[0]) * CHAR_BIT))]
	#define mask_bit(n) (1ULL << ((unsigned char)(n) % (sizeof(mask[0]) * CHAR_BIT)))

	/* NB: Nudge clang & gcc to unroll the mask initialization loop below.
	 *     Since we only invoke _memspn() with constant set string literals,
	 *     the loop below should be optimized into constant load opcodes for
	 *     mask[0] .. mask[3].
	 */
	#ifdef __clang__
	#pragma unroll 255
	#elif __GNUC__
	#pragma GCC unroll 255
	#endif
	for (; m > 0; m--, set++)
		mask_off(*set) |= mask_bit(*set);

	for (m = 0; m < n; m++)
		if (!(mask_off(u8[m]) & mask_bit(u8[m])) == !invert)
			break;

	#undef mask_off
	#undef mask_bit

	return m;
}

__hidden int
strspncmp(const char *start, const char *end, const char *cmp)
{
	while (start < end) {
		if (*start != *cmp)
			return *(unsigned char *)start - *(unsigned char *)cmp;

		start++;
		cmp++;
	}

	if (*cmp)
		return 0 - *(unsigned char *)cmp;

	return 0;
}

__hidden int
strspncasecmp(const char *start, const char *end, const char *cmp)
{
	while (start < end) {
		if ((*start|32) != (*cmp|32))
			return *(unsigned char *)start - *(unsigned char *)cmp;

		start++;
		cmp++;
	}

	if (*cmp)
		return 0 - *(unsigned char *)cmp;

	return 0;
}

__hidden char *
urldecode(const char *str)
{
	char *s, *p, *r;

	p = strdup(str);

	if (!p) {
		errno = ENOMEM;

		return NULL;
	}

#define hex(x) \
	(((x) <= '9') ? ((x) - '0') : \
		(((x) <= 'F') ? ((x) - 'A' + 10) : \
			((x) - 'a' + 10)))

	for (s = r = p; *p; p++) {
		if (*p == '%' && isxdigit(p[1]) && isxdigit(p[2])) {
			*r++ = hex(p[1]) * 16 + hex(p[2]);
			p += 2;
		}
		else {
			*r++ = *p;
		}
	}
#undef hex

	*r = 0;

	return s;
}

__hidden char *
pathexpand(const char *path, const char *base)
{
	char buf[PATH_MAX] = { 0 }, *s, *p = NULL, *r;

	if (*path != '/') {
		if (base && *base == '/') {
			if (asprintf(&p, "%s/%s", base, path) == -1)
				return NULL;
		}
		else if (base) {
			if (!getcwd(buf, sizeof(buf)))
				return NULL;

			if (asprintf(&p, "%s/%s/%s", buf, base, path) == -1)
				return NULL;
		}
		else {
			if (!getcwd(buf, sizeof(buf)))
				return NULL;

			if (asprintf(&p, "%s/%s", buf, path) == -1)
				return NULL;
		}
	}
	else {
		p = strdup(path);
	}

	if (!p) {
		errno = ENOMEM;

		return NULL;
	}

	for (s = r = p; *p; p++) {
		if (*p == '/') {
			/* skip repeating slashes */
			while (p[1] == '/')
				p++;

			/* skip /./ */
			if (p[1] == '.' && (p[2] == '/' || p[2] == '\0')) {
				p += 1;
				continue;
			}

			/* handle /../ */
			if (p[1] == '.' && p[2] == '.' && (p[3] == '/' || p[3] == '\0')) {
				p += 2;

				for (r -= (r > s); r >= s && *r != '/'; r--)
					;

				continue;
			}

			if (p[1])
				*r++ = '/';
		}
		else {
			*r++ = *p;
		}
	}

	if (r == s)
		*r++ = '/';

	*r = 0;

	return s;
}

__hidden size_t
pathmatch(const char *prefix, const char *path)
{
	size_t prefixlen = strlen(prefix);
	size_t pathlen = strlen(path);

	if (*prefix == '/' && prefixlen == 1)
		return 1;

	while (prefixlen > 0 && prefix[prefixlen-1] == '/')
		prefixlen--;

	if (pathlen < prefixlen)
		return 0;

	if (path[prefixlen] != '/' && path[prefixlen] != '?' && path[prefixlen] != 0)
		return 0;

	if (strncmp(prefix, path, prefixlen))
		return 0;

	return prefixlen;
}

__hidden __attribute__((format(printf, 1, 0))) void
sys_perror(const char *fmt, ...)
{
	int err = errno;
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, ": %s\n", strerror(err));
}
