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

#ifndef UWSD_MIMETYPES_H
#define UWSD_MIMETYPES_H

typedef struct {
	const char *extn;
	const char *mime;
} uwsd_mimetype_t;

static const uwsd_mimetype_t uwsd_mime_types[] = {
	{ "txt",     "text/plain" },
	{ "js",      "text/javascript" },
	{ "css",     "text/css" },
	{ "htm",     "text/html" },
	{ "html",    "text/html" },

	{ "bmp",     "image/bmp" },
	{ "gif",     "image/gif" },
	{ "png",     "image/png" },
	{ "jpg",     "image/jpeg" },
	{ "jpeg",    "image/jpeg" },
	{ "svg",     "image/svg+xml" },

	{ "json",    "application/json" },
	{ "xml",     "application/xml" },
	{ "xsl",     "application/xml" },

	{ "pac",      "application/x-ns-proxy-autoconfig" },
	{ "wpad.dat", "application/x-ns-proxy-autoconfig" },
	{ "appcache", "text/cache-manifest" },
	{ "manifest", "text/cache-manifest" },

	{ NULL, NULL }
};

#endif /* UWSD_MIMETYPES_H */
