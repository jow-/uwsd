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
#include <fcntl.h>

#include <sys/stat.h>

#ifdef HAVE_MEMFD_CREATE
#include <sys/mman.h>
#endif

#include "file.h"
#include "http.h"
#include "mimetypes.h"
#include "config.h"

__hidden const char *
uwsd_file_mime_lookup(const char *path)
{
	size_t elen, plen = strlen(path);
	const uwsd_mimetype_t *m;
	char **e;

	for (e = config->mimetypes; e && *e; e++) {
		elen = strcspn(*e, "=");

		if (plen < elen)
			continue;

		if (plen > elen && path[plen - elen - 1] != '/' && path[plen - elen - 1] != '.')
			continue;

		if (strncasecmp(path + plen - elen, *e, elen))
			continue;

		return *e + elen + 1;
	}

	for (m = uwsd_mime_types; m->extn; m++) {
		elen = strlen(m->extn);

		if (plen < elen)
			continue;

		if (plen > elen && path[plen - elen - 1] != '/' && path[plen - elen - 1] != '.')
			continue;

		if (strncasecmp(path + plen - elen, m->extn, elen))
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

	uwsd_http_reply(cl, 412, "Precondition Failed",
		UWSD_HTTP_REPLY_EMPTY,
		UWSD_HTTP_REPLY_EOH);

	return false;
}

__hidden bool
uwsd_file_if_modified_since(uwsd_client_context_t *cl, struct stat *s)
{
	char *hdr = uwsd_http_header_lookup(cl, "If-Modified-Since");

	if (!hdr)
		return true;

	if (uwsd_file_date2unix(hdr) >= s->st_mtime) {
		uwsd_http_reply(cl, 304, "Not Modified",
			UWSD_HTTP_REPLY_EMPTY,
			"ETag", uwsd_file_mktag(s),
			"Last-Modified", uwsd_file_unix2date(s->st_mtime),
			UWSD_HTTP_REPLY_EOH);

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
			uwsd_http_reply(cl, 304, "Not Modified",
				UWSD_HTTP_REPLY_EMPTY,
				"ETag", tag,
				"Last-Modified", uwsd_file_unix2date(s->st_mtime),
				UWSD_HTTP_REPLY_EOH);
		}
		else {
		uwsd_http_reply(cl, 412, "Precondition Failed",
			UWSD_HTTP_REPLY_EMPTY,
			UWSD_HTTP_REPLY_EOH);
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
		uwsd_http_reply(cl, 412, "Precondition Failed",
			UWSD_HTTP_REPLY_EMPTY,
			UWSD_HTTP_REPLY_EOH);

		return false;
	}

	return true;
}

__hidden bool
uwsd_file_if_unmodified_since(uwsd_client_context_t *cl, struct stat *s)
{
	char *hdr = uwsd_http_header_lookup(cl, "If-Unmodified-Since");

	if (hdr && uwsd_file_date2unix(hdr) <= s->st_mtime) {
		uwsd_http_reply(cl, 412, "Precondition Failed",
			UWSD_HTTP_REPLY_EMPTY,
			UWSD_HTTP_REPLY_EOH);

		return false;
	}

	return true;
}


static int
dirent_cmp(const struct dirent **a, const struct dirent **b)
{
	bool dir_a = !!((*a)->d_type & DT_DIR);
	bool dir_b = !!((*b)->d_type & DT_DIR);

	/* directories first */
	if (dir_a != dir_b)
		return dir_b - dir_a;

	return alphasort(a, b);
}

static char *
filetype_lookup(const char *path)
{
	const char *mime, *p;
	static char buf[32];

	mime = uwsd_file_mime_lookup(path);
	p = strchr(mime, '/');

	if (!strcmp(mime, "application/octet-stream"))
		return "unknown type";

	if (!strspncmp(mime, p, "application"))
		return "binary file";

	snprintf(buf, sizeof(buf), "%.*s file", (int)(p - mime), mime);

	return buf;
}

static void
print_entry(FILE *tmp, struct dirent *e,
            const char *physpath, const char *urlpath)
{
	const char *type = "directory";
	unsigned int mode = S_IROTH;
	struct stat s;
	char *p;

	if (!strcmp(e->d_name, "."))
		return;

	p = pathexpand(e->d_name, physpath);

	if (!p)
		return;

	if (!stat(p, &s)) {
		if (S_ISDIR(s.st_mode))
			mode |= S_IXOTH;
		else
			type = filetype_lookup(p);
	}
	else {
		s.st_mode = 0;
	}

	free(p);

	if ((s.st_mode & mode) != mode)
		return;

	p = htmlescape(e->d_name);

	if (!p)
		return;

	fprintf(tmp,
		"<li><strong><a href='%s/%s%s'>%s</a>%s"
		"</strong><br /><small>modified: %s"
		"<br />%s - %.02f kbyte<br />"
		"<br /></small></li>\n",
		urlpath, p, (mode & S_IXOTH) ? "/" : "",
		p, (mode & S_IXOTH) ? "/" : "",
		uwsd_file_unix2date(s.st_mtime),
		type, s.st_size / 1024.0);

	free(p);
}

static void
list_entries(FILE *tmp, struct dirent **files, int count,
             const char *physpath, const char *urlpath)
{
	int i;

	if (!strcmp(urlpath, "/"))
		urlpath = "";

	for (i = 0; i < count; i++) {
		print_entry(tmp, files[i], physpath, urlpath);
		free(files[i]);
	}
}

__hidden bool
uwsd_file_directory_list(uwsd_client_context_t *cl, const char *physpath, const char *urlpath)
{
	const char *type = cl->action->data.directory.content_type;
	char szbuf[sizeof("18446744073709551615")];
	struct dirent **files = NULL;
	int fd = -1, count;
	char *title;
	FILE *tmp;

#ifdef HAVE_MEMFD_CREATE
	if (fd == -1)
		fd = memfd_create("uwsd-directory-listing", 0);
#endif

#ifdef HAVE_O_TMPFILE
	if (fd == -1)
		fd = open("/tmp", O_TMPFILE|O_RDWR, 0600);
#endif

	tmp = (fd > -1) ? fdopen(fd, "r+") : tmpfile();

	if (!tmp)
		return false;

	title = htmlescape(urlpath);

	if (!title)
		return false;

	fprintf(tmp,
		"<html><head><title>Index of %1$s/</title></head>"
		"<body><h1>Index of %1$s/</h1><hr /><ol>\n",
		strcmp(title, "/") ? title : "");

	count = scandir(physpath, &files, NULL, dirent_cmp);

	list_entries(tmp, files, count, physpath, title);

	free(title);
	free(files);

	fprintf(tmp, "</ol><hr /></body></html>");

	cl->upstream.ufd.fd = dup(fileno(tmp));

	if (cl->upstream.ufd.fd == -1) {
		fclose(tmp);

		return false;
	}

	snprintf(szbuf, sizeof(szbuf), "%lu", ftell(tmp));

	fflush(tmp);
	fclose(tmp);

	lseek(cl->upstream.ufd.fd, 0, SEEK_SET);

	uwsd_http_reply(cl, 200, "OK", UWSD_HTTP_REPLY_EMPTY,
		"Content-Type", type ? type : "text/html; charset=utf-8",
		"Content-Length", szbuf,
		"Connection", uwsd_http_header_contains(cl, "Connection", "close") ? "close" : NULL,
		UWSD_HTTP_REPLY_EOH);

	uwsd_state_transition(cl, STATE_CONN_REPLY_SENDFILE);

	return true;
}
