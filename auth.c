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

#include <string.h>
#include <shadow.h>
#include <crypt.h>
#include <fnmatch.h>

#include <libubox/list.h>

#include "auth.h"
#include "http.h"
#include "ssl.h"
#include "log.h"

static char *
auth_www_authenticate_hdr(const char *realm)
{
	const char *p;
	size_t len;
	char *s;

	for (p = realm, len = 0; *p; p++, len++)
		if (*p == '"')
			len++;

	s = xalloc(sizeof("Basic realm=\"\"") + len);
	len = sprintf(s, "Basic realm=\"");

	for (p = realm; *p; p++) {
		if (*p == '"')
			s[len++] = '\\';

		s[len++] = *p;
	}

	s[len] = '"';

	return s;
}

static bool
auth_check_credentials(uwsd_client_context_t *cl, uwsd_auth_t *auth,
                       const char *username, const char *password)
{
	struct spwd *sp;
	char *hash;

	if (strcmp(auth->data.basic.username, username)) {
		uwsd_http_warn(cl, "Authentication failure: wrong username '%s'", username);

		return false;
	}

	if (auth->data.basic.lookup_shadow) {
		sp = getspnam(username);

		if (!sp) {
			uwsd_http_warn(cl, "Authentication failure: unknown shadow user '%s'", username);

			return false;
		}

		hash = crypt(password, sp->sp_pwdp);

		if (strcmp(hash, sp->sp_pwdp)) {
			uwsd_http_warn(cl, "Authentication failure: invalid password for user '%s'", username);

			return false;
		}
	}
	else {
		if (strcmp(auth->data.basic.password, password)) {
			uwsd_http_warn(cl, "Authentication failure: invalid password for user '%s'", username);

			return false;
		}
	}

	return true;
}

static bool
check_basic(uwsd_auth_t *auth, uwsd_client_context_t *cl)
{
	char *hdr, *dec = NULL;
	size_t len;

	hdr = uwsd_http_header_lookup(cl, "Authorization");

	if (!hdr)
		goto fail;

	dec = hdr + strcspn(hdr, " \t\r\n");

	if (dec == hdr || strspncasecmp(hdr, dec, "Basic"))
		goto fail;

	hdr = dec + strspn(dec, " \t\r\n");
	len = B64_DECODE_LEN(strlen(hdr));
	dec = xalloc(len);

	if (b64_decode(hdr, dec, len) == -1)
		goto fail;

	hdr = strchr(dec, ':');

	if (!hdr)
		goto fail;

	*hdr++ = 0;

	if (!auth_check_credentials(cl, auth, dec, hdr))
		goto fail;

	free(dec);

	return true;

fail:
	hdr = auth_www_authenticate_hdr(auth->data.basic.realm);

	uwsd_http_reply(cl, 401, "Unauthorized",
		"Login required\n",
		"WWW-Authenticate", hdr,
		UWSD_HTTP_REPLY_EOH);

	uwsd_http_reply_send(cl, HTTP_WANT_CLOSE);

	free(dec);
	free(hdr);

	return false;
}

static bool
check_mtls(uwsd_auth_t *auth, uwsd_client_context_t *cl)
{
	const char *p;

	if (auth->data.mtls.require_subject) {
		p = uwsd_ssl_peer_subject_name(&cl->downstream);

		if (!p || fnmatch(auth->data.mtls.require_subject, p, FNM_NOESCAPE) == FNM_NOMATCH) {
			uwsd_ssl_warn(cl,
				"Authentication failure: peer subject CN '%s' not matching '%s'",
				p, auth->data.mtls.require_subject);

			goto fail;
		}
	}

	if (auth->data.mtls.require_issuer) {
		p = uwsd_ssl_peer_issuer_name(&cl->downstream);

		if (!p || fnmatch(auth->data.mtls.require_issuer, p, FNM_NOESCAPE) == FNM_NOMATCH) {
			uwsd_ssl_warn(cl,
				"Authentication failure: peer issuer '%s' not matching '%s'",
				p, auth->data.mtls.require_issuer);

			goto fail;
		}
	}

	return true;

fail:
	uwsd_http_reply(cl, 403, "Forbidden",
		"Peer certificate refused\n",
		UWSD_HTTP_REPLY_EOH);

	uwsd_http_reply_send(cl, HTTP_WANT_CLOSE);

	return false;
}

__hidden bool
auth_check(uwsd_client_context_t *cl)
{
	uwsd_auth_t *auth;

	if (cl->auths) {
		list_for_each_entry(auth, cl->auths, list) {
			switch (auth->type) {
			case UWSD_AUTH_BASIC:
				if (!check_basic(auth, cl))
					return false;

				break;

			case UWSD_AUTH_MTLS:
				if (!check_mtls(auth, cl))
					return false;

				break;
			}
		}
	}

	return true;
}
