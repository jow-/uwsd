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
#include <string.h>
#include <inttypes.h>
#include <time.h>

#include <sys/stat.h>

#include "file.h"
#include "http.h"
#include "mimetypes.h"

__hidden const char *
uwsd_file_mime_lookup(const char *path)
{
	size_t elen, plen = strlen(path);
	const uwsd_mimetype_t *m;

	for (m = uwsd_mime_types; m->extn; m++) {
		elen = strlen(m->extn);

		if (plen < elen)
			continue;

		if (strncasecmp(path + plen - elen, m->extn, elen))
			continue;

		if (plen > elen && path[plen - elen - 1] != '/' && path[plen - elen - 1] != '.')
			continue;

		return m->mime;
	}

	return "application/octet-stream";
}

__hidden const char *
uwsd_file_mktag(struct stat *s)
{
	static char buf[sizeof("\"ffffffffffffffff-ffffffffffffffff-ffffffffffffffff\"")];

	snprintf(buf, sizeof(buf), "\"%" PRIx64 "-%" PRIx64 "-%" PRIx64 "\"",
	         s->st_ino, s->st_size, (uint64_t)s->st_mtime);

	return buf;
}

__hidden time_t
uwsd_file_date2unix(const char *date)
{
	struct tm t;

	memset(&t, 0, sizeof(t));

	if (strptime(date, "%a, %d %b %Y %H:%M:%S %Z", &t) != NULL)
		return timegm(&t);

	return 0;
}

__hidden char *
uwsd_file_unix2date(time_t ts)
{
	static char buf[sizeof("Sun, 31 Dec 9999 23:59:59 GMT")];
	struct tm *t = gmtime(&ts);

	strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S GMT", t);

	return buf;
}

__hidden bool
uwsd_file_if_match(uwsd_client_context_t *cl, struct stat *s)
{
	if (!uwsd_http_header_lookup(cl, "If-Match") ||
	    uwsd_http_header_contains(cl, "If-Match", "*") ||
	    uwsd_http_header_contains(cl, "If-Match", uwsd_file_mktag(s)))
		return true;

	uwsd_http_reply_start(cl, 412, "Precondition Failed");
	uwsd_http_reply_finish(cl, NULL);

	return false;
}

__hidden bool
uwsd_file_if_modified_since(uwsd_client_context_t *cl, struct stat *s)
{
	char *hdr = uwsd_http_header_lookup(cl, "If-Modified-Since");

	if (!hdr)
		return true;

	if (uwsd_file_date2unix(hdr) >= s->st_mtime) {
		uwsd_http_reply_start(cl, 304, "Not Modified");
		uwsd_http_reply_header(cl, "ETag", uwsd_file_mktag(s));
		uwsd_http_reply_header(cl, "Last-Modified", uwsd_file_unix2date(s->st_mtime));
		uwsd_http_reply_finish(cl, NULL);

		return false;
	}

	return true;
}

__hidden bool
uwsd_file_if_none_match(uwsd_client_context_t *cl, struct stat *s)
{
	const char *tag = uwsd_file_mktag(s);

	if (uwsd_http_header_contains(cl, "If-None-Match", "*") ||
	    uwsd_http_header_contains(cl, "If-None-Match", tag)) {
		if (cl->request_method == HTTP_GET || cl->request_method == HTTP_HEAD) {
			uwsd_http_reply_start(cl, 304, "Not Modified");
			uwsd_http_reply_header(cl, "ETag", tag);
			uwsd_http_reply_header(cl, "Last-Modified", uwsd_file_unix2date(s->st_mtime));
			uwsd_http_reply_finish(cl, NULL);
		}
		else {
			uwsd_http_reply_start(cl, 412, "Precondition Failed");
			uwsd_http_reply_finish(cl, NULL);
		}

		return false;
	}

	return true;
}

__hidden bool
uwsd_file_if_range(uwsd_client_context_t *cl, struct stat *s)
{
	char *hdr = uwsd_http_header_lookup(cl, "If-Range");

	if (hdr) {
		uwsd_http_reply_start(cl, 412, "Precondition Failed");
		uwsd_http_reply_finish(cl, NULL);

		return false;
	}

	return true;
}

__hidden bool
uwsd_file_if_unmodified_since(uwsd_client_context_t *cl, struct stat *s)
{
	char *hdr = uwsd_http_header_lookup(cl, "If-Unmodified-Since");

	if (hdr && uwsd_file_date2unix(hdr) <= s->st_mtime) {
		uwsd_http_reply_start(cl, 412, "Precondition Failed");
		uwsd_http_reply_finish(cl, NULL);

		return false;
	}

	return true;
}
