/*
 * Copyright (C) 2023 Jo-Philipp Wich <jo@mein.io>
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

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fnmatch.h>
#include <stdarg.h>
#include <dirent.h>
#include <limits.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/error.h>
#include <mbedtls/oid.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net_sockets.h>

#include <libubox/list.h>

#include "client.h"
#include "ssl.h"
#include "config.h"
#include "auth.h"
#include "log.h"


typedef struct {
	mbedtls_ssl_config conf;
	mbedtls_pk_context key;
	mbedtls_x509_crt certs;
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_context cache;
#endif
	int *ciphers;
} ssl_ctx_t;


static mbedtls_x509_crt ca_certs = { 0 };
static bool ca_certs_initialized = false;


static char *
ssl_error(int err)
{
	static char buf[256];

	memset(buf, 0, sizeof(buf));
	mbedtls_strerror(err, buf, sizeof(buf));

	return buf;
}

static void __attribute__((format(printf, 3, 0)))
ssl_perror(uwsd_client_context_t *cl, int err, const char *fmt, ...)
{
	char buf[256];
	va_list ap;
	int len;

	va_start(ap, fmt);
	len = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (err)
		snprintf(buf + len, sizeof(buf) - len, ": %s (-0x%04x)", ssl_error(err), -err);

	uwsd_ssl_err(cl, "%s", buf);
}

static ssl_ctx_t *
ssl_lookup_context_by_hostname(uwsd_client_context_t *cl, const char *hostname);

static const char *
ssl_get_subject_name(const mbedtls_x509_crt *crt)
{
	const mbedtls_x509_name *name;
	static char buf[65];

	for (name = &crt->subject; name != NULL; name = name->next) {
		if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid) == 0) {
			snprintf(buf, sizeof(buf), "%.*s", (int)name->val.len, name->val.p);

			return buf;
		}
	}

	return NULL;
}

static const char *
ssl_get_issuer_name(const mbedtls_x509_crt *crt)
{
	const mbedtls_x509_name *name;
	static char buf[65];

	for (name = &crt->issuer; name != NULL; name = name->next) {
		if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid) == 0) {
			snprintf(buf, sizeof(buf), "%.*s", (int)name->val.len, name->val.p);

			return buf;
		}
	}

	return NULL;
}

/* SNI callbacks */
static int
servername_cb(void *arg, mbedtls_ssl_context *ssl, const unsigned char *name, size_t namelen)
{
	const char *hostname = (char *)name;
	uwsd_client_context_t *cl = arg;
	ssl_ctx_t *tls_ctx;

	if (hostname && strlen(hostname) == namelen) {
		tls_ctx = ssl_lookup_context_by_hostname(cl, hostname);

		uwsd_ssl_debug(cl, "SNI: selecting cert '%s' by '%s' for server name '%s'",
			ssl_get_subject_name(&tls_ctx->certs),
			ssl_get_issuer_name(&tls_ctx->certs),
			hostname);

		if (tls_ctx->certs.next)
			mbedtls_ssl_set_hs_ca_chain(ssl, tls_ctx->certs.next, NULL);

		return mbedtls_ssl_set_hs_own_cert(ssl, &tls_ctx->certs, &tls_ctx->key);
	}

	return -1;
}

static int
ssl_gather_entropy(void *ctx, unsigned char *out, size_t len)
{
	int fd;

	fd = open("/dev/urandom", O_RDONLY);

	if (fd == -1)
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;

	if (read(fd, out, len) < 0) {
		close(fd);

		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
	}

	close(fd);

	return 0;
}

static bool
ssl_parse_protocols(ssl_ctx_t *tls_ctx, char *const *protocols)
{
	bool has_1_2 = false, has_1_3 = false;

	while (*protocols) {
		if (!strcmp(*protocols, "TLSv1.2")) {
			has_1_2 = true;
		}
		else if (!strcmp(*protocols, "TLSv1.3")) {
			has_1_3 = true;
		}
		else {
			uwsd_ssl_err(NULL, "Unrecognized SSL protocol '%s'", *protocols);

			return false;
		}

		protocols++;
	}

	if (!has_1_2 && !has_1_3) {
		uwsd_ssl_err(NULL, "No usable SSL protocol provided");

		return false;
	}

#if MBEDTLS_VERSION_NUMBER >= 0x03020000
	mbedtls_ssl_conf_min_tls_version(&tls_ctx->conf,
		has_1_2 ? MBEDTLS_SSL_VERSION_TLS1_2 : MBEDTLS_SSL_VERSION_TLS1_3);

	mbedtls_ssl_conf_max_tls_version(&tls_ctx->conf,
		has_1_3 ? MBEDTLS_SSL_VERSION_TLS1_3 : MBEDTLS_SSL_VERSION_TLS1_2);
#else
	mbedtls_ssl_conf_min_version(&tls_ctx->conf,
		MBEDTLS_SSL_MAJOR_VERSION_3,
		has_1_2 ? MBEDTLS_SSL_MINOR_VERSION_3 : MBEDTLS_SSL_MINOR_VERSION_4);

	mbedtls_ssl_conf_max_version(&tls_ctx->conf,
		MBEDTLS_SSL_MAJOR_VERSION_3,
		has_1_3 ? MBEDTLS_SSL_MINOR_VERSION_4 : MBEDTLS_SSL_MINOR_VERSION_3);
#endif

	return true;
}

static bool
ssl_parse_cipherlist(ssl_ctx_t *tls_ctx, const char *ciphers)
{
	char *cipherlist = xstrdup(ciphers);
	int id, len = 0;
	char *p, *q;

	for (p = strtok(cipherlist, ",: \t\n"); p; p = strtok(NULL, ",: \r\n")) {
		for (q = p; *q; q++) {
			if (*q >= 'a' && *q <= 'z')
				*q &= ~32;
			else if (*q == '_')
				*q = '-';
		}

		id = mbedtls_ssl_get_ciphersuite_id(p);

		if (id > 0) {
			tls_ctx->ciphers = xrealloc(tls_ctx->ciphers, (len + 2) * sizeof(int));
			tls_ctx->ciphers[len++] = id;
			tls_ctx->ciphers[len] = 0;
		}
		else {
			uwsd_ssl_err(NULL, "Unrecognized cipher name '%s'", p);

			free(tls_ctx->ciphers);
			free(cipherlist);

			tls_ctx->ciphers = NULL;

			return false;
		}
	}

	free(cipherlist);

	mbedtls_ssl_conf_ciphersuites(&tls_ctx->conf, tls_ctx->ciphers);

	return true;
}

static void
ssl_free_context(ssl_ctx_t *tls_ctx)
{
#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_free(&tls_ctx->cache);
#endif

	mbedtls_pk_free(&tls_ctx->key);
	mbedtls_x509_crt_free(&tls_ctx->certs);
	mbedtls_ssl_config_free(&tls_ctx->conf);

	free(tls_ctx);
}

static void
ssl_load_ca_certificates(const char *directory)
{
	char path[PATH_MAX];
	struct dirent *e;
	struct stat s;
	char *ext;
	DIR *dp;
	int err;

	if (ca_certs_initialized)
		return;

	mbedtls_x509_crt_init(&ca_certs);

	dp = opendir(directory);

	if (!dp)
		return sys_perror("Unable to open certificate directory '%s'", directory);

	while ((e = readdir(dp)) != NULL) {
		ext = strrchr(e->d_name, '.');

		if (!ext || strcmp(ext, ".crt"))
			continue;

		snprintf(path, sizeof(path), "%s/%s", directory, e->d_name);

		if (stat(path, &s)) {
			sys_perror("Unable to stat '%s'", path);
			continue;
		}

		if (!S_ISREG(s.st_mode))
			continue;

		err = mbedtls_x509_crt_parse_file(&ca_certs, path);

		if (err) {
			ssl_perror(NULL, err, "Unable to parse X.509 certificate '%s'", path);
			continue;
		}
	}

	closedir(dp);

	ca_certs_initialized = true;
}

static ssl_ctx_t *
ssl_create_context(bool server, char *const *protocols, const char *ciphers)
{
	ssl_ctx_t *tls_ctx = NULL;

	tls_ctx = calloc(1, sizeof(*tls_ctx));

	if (!tls_ctx) {
		uwsd_ssl_err(NULL, "Unable to allocate TLS context");

		return NULL;
	}

	mbedtls_pk_init(&tls_ctx->key);
	mbedtls_x509_crt_init(&tls_ctx->certs);

#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_cache_init(&tls_ctx->cache);
	mbedtls_ssl_cache_set_timeout(&tls_ctx->cache, 30 * 60);
	mbedtls_ssl_cache_set_max_entries(&tls_ctx->cache, 5);
#endif

	mbedtls_ssl_config_init(&tls_ctx->conf);
	mbedtls_ssl_config_defaults(&tls_ctx->conf,
		server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
		MBEDTLS_SSL_TRANSPORT_STREAM,
	    MBEDTLS_SSL_PRESET_DEFAULT);

	mbedtls_ssl_conf_rng(&tls_ctx->conf, ssl_gather_entropy, NULL);

	if (server) {
		mbedtls_ssl_conf_authmode(&tls_ctx->conf, MBEDTLS_SSL_VERIFY_NONE);
	}
	else {
		ssl_load_ca_certificates("/etc/ssl/certs");
		mbedtls_ssl_conf_ca_chain(&tls_ctx->conf, &ca_certs, NULL);
		mbedtls_ssl_conf_authmode(&tls_ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	}

	if (protocols && !ssl_parse_protocols(tls_ctx, protocols)) {
		ssl_free_context(tls_ctx);

		return NULL;
	}

	if (ciphers && !ssl_parse_cipherlist(tls_ctx, ciphers)) {
		ssl_free_context(tls_ctx);

		return NULL;
	}

#if defined(MBEDTLS_SSL_CACHE_C)
	mbedtls_ssl_conf_session_cache(&tls_ctx->conf, &tls_ctx->cache,
		mbedtls_ssl_cache_get, mbedtls_ssl_cache_set);
#endif

	return tls_ctx;
}

static bool
ssl_match_cn(const mbedtls_x509_buf *name, const char *cn, size_t cnlen)
{
	const char *p, *cmp;
	size_t cmplen;

	cmp = (char *)name->p;
	cmplen = name->len;

	/* wildcard match */
	if (cmplen > 2 && !memcmp(cmp, "*.", 2)) {
		p = strchr(cn, '.');

		if (!p || p == cn)
			return false;

		cn = ++p;
		cnlen -= (p - cn);

		cmp += 2;
		cmplen -= 2;
	}

	return (cnlen == cmplen && !strncasecmp(cn, cmp, cmplen));
}

static bool
ssl_match_context(ssl_ctx_t *ssl_ctx, const struct sockaddr *sa, const char *hostname)
{
	struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)sa;
	struct sockaddr_in *s4 = (struct sockaddr_in *)sa;
	const mbedtls_x509_crt *crt = &ssl_ctx->certs;
	const mbedtls_x509_sequence *san;
	const mbedtls_x509_name *name;
	size_t namelen;

	if (sa) {
		if (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
			for (san = &crt->subject_alt_names; san; san = san->next) {
				if ((san->buf.tag & MBEDTLS_ASN1_TAG_VALUE_MASK) != MBEDTLS_X509_SAN_IP_ADDRESS)
					continue;

				if ((san->buf.len == 4 && sa->sa_family == AF_INET &&
				     !memcmp(san->buf.p, &s4->sin_addr, 4)) ||
				    (san->buf.len == 16 && sa->sa_family == AF_INET6 &&
				     !memcmp(san->buf.p, &s6->sin6_addr, 16)))
				    return true;
			}
		}
	}

	if (hostname) {
		namelen = strlen(hostname);

		if (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
			for (san = &crt->subject_alt_names; san; san = san->next) {
				if ((san->buf.tag & MBEDTLS_ASN1_TAG_VALUE_MASK) != MBEDTLS_X509_SAN_DNS_NAME)
					continue;

				if (ssl_match_cn(&san->buf, hostname, namelen))
					return true;
			}
		}

		for (name = &crt->subject; name; name = name->next)
			if (MBEDTLS_OID_CMP(MBEDTLS_OID_AT_CN, &name->oid) == 0)
				return ssl_match_cn(&name->val, hostname, namelen);
	}

	return false;
}

static ssl_ctx_t *
ssl_lookup_context_by_hostname(uwsd_client_context_t *cl, const char *hostname)
{
	uwsd_ssl_t *ctx = cl->listener->ssl;
	size_t i;

	if (ctx->contexts.count > 1) {
		for (i = 0; i < ctx->contexts.count; i++)
			if (ssl_match_context(ctx->contexts.entries[i], NULL, hostname))
				return ctx->contexts.entries[i];

		uwsd_ssl_debug(NULL, "No matching certificate for hostname '%s' - using first one\n", hostname);
	}

	return ctx->contexts.entries[0];
}

static ssl_ctx_t *
ssl_lookup_context_by_sockaddr(uwsd_client_context_t *cl, const struct sockaddr *sa)
{
	uwsd_ssl_t *ctx = cl->listener->ssl;
	size_t i;

	if (ctx->contexts.count > 1)
		for (i = 0; i < ctx->contexts.count; i++)
			if (ssl_match_context(ctx->contexts.entries[i], sa, NULL))
				return ctx->contexts.entries[i];

	return ctx->contexts.entries[0];
}

static bool
ssl_load_pem_files(ssl_ctx_t *ssl_ctx, const char *pkey_path,
                                       char *const *cert_paths)
{
	size_t i;
	int err;

	err = mbedtls_pk_parse_keyfile(&ssl_ctx->key, pkey_path, NULL);

	if (err) {
		ssl_perror(NULL, err, "Unable to load private key from PEM file '%s'", pkey_path);
		ssl_free_context(ssl_ctx);

		return false;
	}

	for (i = 0; cert_paths[i]; i++) {
		err = mbedtls_x509_crt_parse_file(&ssl_ctx->certs, cert_paths[i]);

		if (err) {
			ssl_perror(NULL, err, "Unable to load certificates from from PEM file '%s'", cert_paths[i]);
			ssl_free_context(ssl_ctx);

			return false;
		}
	}

	mbedtls_ssl_conf_ca_chain(&ssl_ctx->conf, ssl_ctx->certs.next, NULL);

	err = mbedtls_ssl_conf_own_cert(&ssl_ctx->conf, &ssl_ctx->certs, &ssl_ctx->key);

	if (err) {
		ssl_perror(NULL, err, "Unable to use certificate '%s' with key file '%s'", cert_paths[0], pkey_path);
		ssl_free_context(ssl_ctx);

		return false;
	}

	return true;
}

static bool
ssl_create_context_from_pem(uwsd_ssl_t *ctx, const char *pkey_path,
                                             char *const *cert_paths)
{
	ssl_ctx_t *ssl_ctx = ssl_create_context(true, ctx->protocols, ctx->ciphers);

	if (!ssl_ctx)
		return false;

	if (!ssl_load_pem_files(ssl_ctx, pkey_path, cert_paths))
		return false;

	uwsd_ssl_info(NULL, "loading certificate '%s' by '%s' from '%s'",
		ssl_get_subject_name(&ssl_ctx->certs),
		ssl_get_issuer_name(&ssl_ctx->certs),
		cert_paths[0]);

	ctx->contexts.entries = xrealloc(ctx->contexts.entries,
		sizeof(*ctx->contexts.entries) * (ctx->contexts.count + 1));

	ctx->contexts.entries[ctx->contexts.count++] = ssl_ctx;

	return true;
}

static bool
ssl_load_certificates(uwsd_ssl_t *ctx, const char *directory)
{
	char path[PATH_MAX];
	struct dirent *e;
	struct stat s;
	DIR *dp;

	dp = opendir(directory);

	if (!dp) {
		sys_perror("Unable to open certificate directory '%s'", directory);

		return false;
	}

	while ((e = readdir(dp)) != NULL) {
		snprintf(path, sizeof(path), "%s/%s", directory, e->d_name);

		if (stat(path, &s)) {
			sys_perror("Unable to stat '%s'", path);
			continue;
		}

		if (!S_ISREG(s.st_mode))
			continue;

		ssl_create_context_from_pem(ctx, path, (char *const []){ path, NULL });
	}

	closedir(dp);

	return (ctx->contexts.count > 0);
}

__hidden bool
uwsd_ssl_ctx_init(uwsd_ssl_t *ctx)
{
	if (ctx->certificate_directory)
		ssl_load_certificates(ctx, ctx->certificate_directory);

	if (!!ctx->private_key ^ !!ctx->certificates) {
		uwsd_ssl_err(NULL, "Require both 'private-key' and 'certificate' properties");

		return false;
	}

	if (ctx->private_key && ctx->certificates) {
		if (!ssl_create_context_from_pem(ctx, ctx->private_key, ctx->certificates))
			return false;
	}

	if (!ctx->contexts.count) {
		uwsd_ssl_err(NULL, "No certificates loaded, unable to continue");

		return false;
	}

	return true;
}

__hidden void
uwsd_ssl_ctx_free(uwsd_ssl_t *ctx)
{
	while (ctx->contexts.count > 0)
		ssl_free_context(ctx->contexts.entries[--ctx->contexts.count]);

	free(ctx->contexts.entries);
}

__hidden bool
uwsd_ssl_client_ctx_init(uwsd_ssl_client_t *ctx)
{
	ssl_ctx_t *ssl_ctx = ssl_create_context(false, ctx->protocols, ctx->ciphers);
	int err;

	if (!ssl_ctx)
		return false;

	if (!!ctx->private_key ^ !!ctx->certificates) {
		uwsd_ssl_err(NULL, "Require both 'private-key' and 'certificate' properties");

		return false;
	}

	if (ctx->private_key && ctx->certificates) {
		if (!ssl_load_pem_files(ssl_ctx, ctx->private_key, ctx->certificates))
			return false;

		mbedtls_ssl_conf_ca_chain(&ssl_ctx->conf, ssl_ctx->certs.next, NULL);

		err = mbedtls_ssl_conf_own_cert(&ssl_ctx->conf, &ssl_ctx->certs, &ssl_ctx->key);

		if (err) {
			ssl_perror(NULL, err, "Unable to use certificate '%s' with key file '%s'", ctx->certificates[0], ctx->private_key);
			ssl_free_context(ssl_ctx);

			return false;
		}
	}

	ctx->context = ssl_ctx;

	return true;
}

__hidden void
uwsd_ssl_client_ctx_free(uwsd_ssl_client_t *ctx)
{
	if (ctx->context)
		ssl_free_context(ctx->context);

	ctx->context = NULL;
}

static int
ssl_lowlevel_send(void *ctx, const unsigned char *buf, size_t len)
{
	uwsd_connection_t *conn = ctx;
	ssize_t rv;

	rv = send(conn->ufd.fd, buf, len, 0);

	if (rv == -1) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return MBEDTLS_ERR_SSL_WANT_WRITE;

		if (errno == EPIPE || errno == ECONNRESET)
			return MBEDTLS_ERR_NET_CONN_RESET;

		return MBEDTLS_ERR_NET_SEND_FAILED;
	}

	return rv;
}

static int
ssl_lowlevel_recv(void *ctx, unsigned char *buf, size_t len)
{
	uwsd_connection_t *conn = ctx;
	ssize_t rv;

	rv = recv(conn->ufd.fd, buf, len, 0);

	if (rv == -1) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			return MBEDTLS_ERR_SSL_WANT_READ;

		if (errno == EPIPE || errno == ECONNRESET)
			return MBEDTLS_ERR_NET_CONN_RESET;

		return MBEDTLS_ERR_NET_RECV_FAILED;
	}

	return rv;
}

__hidden bool
uwsd_ssl_init(uwsd_client_context_t *cl)
{
	mbedtls_ssl_context *ssl = NULL;
	ssl_ctx_t *tls_ctx;
	int err;

	tls_ctx = ssl_lookup_context_by_sockaddr(cl, &cl->sa_peer.unspec);

#ifndef NDEBUG
	char buf[INET6_ADDRSTRLEN];

	uwsd_ssl_debug(cl, "selecting cert '%s' by '%s' for IP address '%s'",
		ssl_get_subject_name(&tls_ctx->certs),
		ssl_get_issuer_name(&tls_ctx->certs),
		inet_ntop(cl->sa_peer.unspec.sa_family, &cl->sa_peer.in6.sin6_addr, buf, sizeof(buf)));
#endif

	mbedtls_ssl_conf_sni(&tls_ctx->conf, servername_cb, cl);

	ssl = calloc(1, sizeof(*ssl));

	if (!ssl) {
		client_free(cl, "Unable to initialize TLS context: Out of memory");

		return false;
	}

	mbedtls_ssl_init(ssl);

	err = mbedtls_ssl_setup(ssl, &tls_ctx->conf);

	if (err) {
		client_free(cl, "Unable to setup TLS context: %s", ssl_error(err));

		mbedtls_ssl_free(ssl);
		free(ssl);

		return false;
	}

	mbedtls_ssl_set_bio(ssl, &cl->downstream,
		ssl_lowlevel_send, ssl_lowlevel_recv, NULL);

	switch (cl->listener->ssl->verify_peer) {
	case UWSD_VERIFY_PEER_DISABLED:
		mbedtls_ssl_set_hs_authmode(ssl, MBEDTLS_SSL_VERIFY_NONE);
		break;

	case UWSD_VERIFY_PEER_OPTIONAL:
		uwsd_ssl_debug(cl, "peer verification optional");
		mbedtls_ssl_set_hs_authmode(ssl, MBEDTLS_SSL_VERIFY_OPTIONAL);
		break;

	case UWSD_VERIFY_PEER_REQUIRED:
		uwsd_ssl_debug(cl, "peer verification required");
		mbedtls_ssl_set_hs_authmode(ssl, MBEDTLS_SSL_VERIFY_REQUIRED);
		break;
	}

	cl->downstream.ssl = ssl;

	return true;
}

__hidden void
uwsd_ssl_free(uwsd_client_context_t *cl)
{
	mbedtls_ssl_context *ssl = cl->downstream.ssl;

	mbedtls_ssl_free(ssl);
	free(ssl);

	cl->downstream.ssl = NULL;
}

static bool
ssl_handshake(uwsd_client_context_t *cl, mbedtls_ssl_context *ssl)
{
	int err;

	errno = 0;
	err = mbedtls_ssl_handshake(ssl);

	switch (err) {
	case 0:
		return true;

	case MBEDTLS_ERR_SSL_WANT_READ:
		errno = ENODATA;

		return false;

	case MBEDTLS_ERR_SSL_WANT_WRITE:
		errno = EAGAIN;

		return false;

	default:
		errno = EINVAL;
		ssl_perror(cl, err, "Handshake failed");

		/* NB: calling mbedtls_ssl_handshake_step() here to flush pending alerts/output,
		 *     but not sure if this is the most appropriate way */
		mbedtls_ssl_handshake_step(ssl);

		mbedtls_ssl_session_reset(ssl);

		return false;
	}
}

__hidden bool
uwsd_ssl_accept(uwsd_client_context_t *cl)
{
	return ssl_handshake(cl, cl->downstream.ssl);
}

__hidden bool
uwsd_ssl_client_init(uwsd_client_context_t *cl)
{
	uwsd_ssl_client_t *ctx = cl->action->data.proxy.ssl;
	mbedtls_ssl_context *ssl = NULL;
	ssl_ctx_t *tls_ctx;
	int err;

	tls_ctx = ctx->context;
	ssl = calloc(1, sizeof(*ssl));

	if (!ssl) {
		client_free(cl, "Unable to initialize TLS context: Out of memory");

		return false;
	}

	mbedtls_ssl_init(ssl);

	err = mbedtls_ssl_setup(ssl, &tls_ctx->conf);

	if (err) {
		client_free(cl, "Unable to setup TLS context: %s", ssl_error(err));

		mbedtls_ssl_free(ssl);
		free(ssl);

		return false;
	}

	mbedtls_ssl_set_bio(ssl, &cl->upstream,
		ssl_lowlevel_send, ssl_lowlevel_recv, NULL);

	cl->upstream.ssl = ssl;

	return true;
}

__hidden void
uwsd_ssl_client_free(uwsd_client_context_t *cl)
{
	mbedtls_ssl_context *ssl = cl->upstream.ssl;

	mbedtls_ssl_free(ssl);
	free(ssl);

	cl->upstream.ssl = NULL;
}

static bool
ssl_connect_verify_result(uwsd_client_context_t *cl, uint32_t flags)
{
	char buf[512], *p;

	if (flags == 0)
		return true;

	mbedtls_x509_crt_verify_info(buf, sizeof(buf), " ", flags);

	for (p = buf; *p; p++)
		if (*p == '\n')
			*p = p[1] ? ',' : '\0';

	uwsd_ssl_warn(cl, "Upstream handshake:%s", buf);

	return false;
}

__hidden bool
uwsd_ssl_client_connect(uwsd_client_context_t *cl)
{
	uwsd_ssl_client_t *ctx;
	uint32_t res;

	if (!ssl_handshake(cl, cl->upstream.ssl))
		return false;

	res = mbedtls_ssl_get_verify_result(cl->upstream.ssl);
	ctx = cl->action ? cl->action->data.proxy.ssl : NULL;

	switch (ctx ? ctx->verify_server : UWSD_VERIFY_SERVER_STRICT) {
	case UWSD_VERIFY_SERVER_STRICT:
		return ssl_connect_verify_result(cl, res);

	case UWSD_VERIFY_SERVER_LOOSE:
		return ssl_connect_verify_result(cl, res & ~(
			MBEDTLS_X509_BADCERT_EXPIRED |
			MBEDTLS_X509_BADCERT_FUTURE |
			MBEDTLS_X509_BADCERT_NOT_TRUSTED |
			MBEDTLS_X509_BADCRL_EXPIRED |
			MBEDTLS_X509_BADCRL_FUTURE |
			MBEDTLS_X509_BADCRL_NOT_TRUSTED
		));

	default:
		return true;
	}
}

__hidden ssize_t
uwsd_ssl_pending(uwsd_connection_t *conn)
{
	mbedtls_ssl_context *ssl = conn->ssl;

	return mbedtls_ssl_get_bytes_avail(ssl);
}

__hidden ssize_t
uwsd_ssl_recv(uwsd_connection_t *conn, void *data, size_t len)
{
	mbedtls_ssl_context *ssl = conn->ssl;
	int err;

	errno = 0;
	err = mbedtls_ssl_read(ssl, data, len);

	if (err >= 0)
		return err;

	switch (err) {
	case MBEDTLS_ERR_SSL_WANT_READ:
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		errno = EAGAIN;

		return -1;

	case MBEDTLS_ERR_SSL_CLIENT_RECONNECT:
		errno = ECONNRESET;

		return -1;

	default:
		errno = EINVAL;

		return -1;
	}
}

__hidden ssize_t
uwsd_ssl_sendv(uwsd_connection_t *conn, struct iovec *iov, size_t len)
{
	mbedtls_ssl_context *ssl = conn->ssl;
	ssize_t total = 0;
	size_t i;
	int err;

	errno = 0;

	for (i = 0; i < len; i++) {
		if (iov[i].iov_len == 0)
			continue;

		err = mbedtls_ssl_write(ssl, iov[i].iov_base, iov[i].iov_len);

		if (err >= 0)
			total += err;

		switch (err) {
		case MBEDTLS_ERR_SSL_WANT_READ:
		case MBEDTLS_ERR_SSL_WANT_WRITE:
			if (total)
				return total;

			errno = EAGAIN;

			return -1;

		default:
			if (total)
				return total;

			errno = EINVAL;

			return -1;
		}
	}

	return total;
}

__hidden ssize_t
uwsd_ssl_close(uwsd_connection_t *conn)
{
	mbedtls_ssl_context *ssl = conn->ssl;

	return mbedtls_ssl_close_notify(ssl);
}

__hidden const char *
uwsd_ssl_cipher_name(uwsd_connection_t *conn)
{
	mbedtls_ssl_context *ssl = conn->ssl;

	return mbedtls_ssl_get_ciphersuite(ssl);
}

__hidden const char *
uwsd_ssl_peer_subject_name(uwsd_connection_t *conn)
{
	mbedtls_ssl_context *ssl = conn->ssl;
	const mbedtls_x509_crt *peer_cert;

	if (!ssl)
		return NULL;

	peer_cert = mbedtls_ssl_get_peer_cert(ssl);

	if (!peer_cert)
		return NULL;

	return ssl_get_subject_name(peer_cert);
}

__hidden const char *
uwsd_ssl_peer_issuer_name(uwsd_connection_t *conn)
{
	mbedtls_ssl_context *ssl = conn->ssl;
	const mbedtls_x509_crt *peer_cert;

	if (!ssl)
		return NULL;

	peer_cert = mbedtls_ssl_get_peer_cert(ssl);

	if (!peer_cert)
		return NULL;

	return ssl_get_issuer_name(peer_cert);
}
