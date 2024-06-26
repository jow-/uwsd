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

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <libubox/list.h>

#include "client.h"
#include "ssl.h"
#include "config.h"
#include "auth.h"
#include "log.h"


static bool ssl_initialized = false;


static int
password_cb(char *buf, int size, int rwflag, void *u)
{
	return -1;
}

static char *
ssl_error(void)
{
	return (char *)ERR_error_string(ERR_get_error(), NULL);
}

#define ssl_perror(fmt, ...) uwsd_ssl_err(NULL, fmt ": %s", ##__VA_ARGS__, ssl_error())

static SSL_CTX *
ssl_lookup_context_by_hostname(uwsd_client_context_t *cl, const char *hostname);

static const char *
ssl_get_subject_cn(X509_NAME *subj);

/* SNI callback */
static int
servername_cb(SSL *ssl, int *al, void *arg)
{
	const char *hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	uwsd_client_context_t *cl = arg;
	SSL_CTX *tls_ctx;

	if (hostname) {
		tls_ctx = ssl_lookup_context_by_hostname(cl, hostname);

#ifndef NDEBUG
		X509_NAME *n = X509_get_subject_name(SSL_CTX_get0_certificate(tls_ctx));
		X509_NAME *i = X509_get_issuer_name(SSL_CTX_get0_certificate(tls_ctx));
		uwsd_client_context_t *cl = arg;

		uwsd_ssl_debug(cl, "SNI: selecting cert '%s' by '%s' for server name '%s'",
			n ? ssl_get_subject_cn(n) : NULL,
			i ? ssl_get_subject_cn(i) : NULL,
			hostname);
#endif

		SSL_set_SSL_CTX(ssl, tls_ctx);
	}

	return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *
ssl_create_context(char *const *protocols, const char *ciphers)
{
	SSL_CTX *tls_ctx = NULL;
	long options;

	if (!ssl_initialized) {
		SSL_load_error_strings();
		SSL_library_init();

		ssl_initialized = true;
	}

	tls_ctx = SSL_CTX_new(TLS_method());

	if (!tls_ctx) {
		ssl_perror("Unable to allocate TLS context");

		return NULL;
	}

	SSL_CTX_set_default_verify_paths(tls_ctx);
	SSL_CTX_set_session_cache_mode(tls_ctx, SSL_SESS_CACHE_CLIENT);
	SSL_CTX_set_session_id_context(tls_ctx, (const unsigned char *)"1", 1);

	if (protocols) {
		options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
		          SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
		          SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_3;

		while (*protocols) {
			if (!strcmp(*protocols, "SSLv2")) {
				options &= ~SSL_OP_NO_SSLv2;
			}
			else if (!strcmp(*protocols, "SSLv3")) {
				options &= ~SSL_OP_NO_SSLv3;
			}
			else if (!strcmp(*protocols, "TLSv1")) {
				options &= ~SSL_OP_NO_TLSv1;
			}
			else if (!strcmp(*protocols, "TLSv1.1")) {
				options &= ~SSL_OP_NO_TLSv1_1;
			}
			else if (!strcmp(*protocols, "TLSv1.2")) {
				options &= ~SSL_OP_NO_TLSv1_2;
			}
			else if (!strcmp(*protocols, "TLSv1.3")) {
				options &= ~SSL_OP_NO_TLSv1_3;
			}
			else {
				uwsd_ssl_err(NULL, "Unrecognized SSL protocol '%s'", *protocols);
				SSL_CTX_free(tls_ctx);

				return NULL;
			}

			protocols++;
		}
	}
	else {
		options = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
	}

	SSL_CTX_set_options(tls_ctx, options);

	if (ciphers && !SSL_CTX_set_cipher_list(tls_ctx, ciphers)) {
		ssl_perror("Unable to configure cipher list '%s'", ciphers);
		SSL_CTX_free(tls_ctx);

		return NULL;
	}

	return tls_ctx;
}

static const char *
ssl_get_subject_cn(X509_NAME *subj)
{
	X509_NAME_ENTRY *e;
	ASN1_STRING *s;
	const char *p;
	int pos;

	pos = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);

	if (pos < 0)
		return NULL;

	e = X509_NAME_get_entry(subj, pos);
	s = X509_NAME_ENTRY_get_data(e);
	p = (char *)ASN1_STRING_get0_data(s);

	if ((size_t)ASN1_STRING_length(s) != strlen(p))
		return NULL;

	return p;
}

static bool
ssl_match_context(SSL_CTX *ssl_ctx, const struct sockaddr *sa, const char *hostname)
{
	struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)sa;
	struct sockaddr_in *s4 = (struct sockaddr_in *)sa;
	X509 *cert;

	cert = SSL_CTX_get0_certificate(ssl_ctx);

	if (sa) {
		if (sa->sa_family == AF_INET6) {
			if (IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr))
				return (X509_check_ip(cert, &s6->sin6_addr.s6_addr[12], 4, 0) == 1);

			return (X509_check_ip(cert, s6->sin6_addr.s6_addr, 16, 0) == 1);
		}

		return (X509_check_ip(cert, (unsigned char *)&s4->sin_addr, 4, 0) == 1);
	}

	if (hostname) {
		return (
			X509_check_host(cert, hostname, strlen(hostname),
				X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS|X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS,
				NULL
			) == 1
		);
	}

	return false;
}

static SSL_CTX *
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

static SSL_CTX *
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
ssl_load_pem_privkey(SSL_CTX *ssl_ctx, FILE *fp, const char *path)
{
	EVP_PKEY *pkey = NULL;

	rewind(fp);

	pkey = PEM_read_PrivateKey(fp, NULL, password_cb, NULL);

	if (!pkey) {
		ssl_perror("Unable to read private key from PEM file '%s'", path);

		return false;
	}

	if (!SSL_CTX_use_PrivateKey(ssl_ctx, pkey)) {
		ssl_perror("Unable to use private key from PEM file '%s'", path);
		EVP_PKEY_free(pkey);

		return false;
	}

	return true;
}

static bool
ssl_load_pem_certificate_chain(SSL_CTX *ssl_ctx, FILE *fp, const char *path)
{
	X509_STORE *store;
	X509 *other;

	store = SSL_CTX_get_cert_store(ssl_ctx);

	while ((other = PEM_read_X509(fp, NULL, password_cb, NULL)) != NULL) {
		if (SSL_CTX_add0_chain_cert(ssl_ctx, other)) {
			X509_STORE_add_cert(store, other);
		}
		else {
			ssl_perror("Unable to use additional CA certificate from PEM file '%s'", path);
			X509_free(other);
		}
	}

	return true;
}

static bool
ssl_load_pem_certificate(SSL_CTX *ssl_ctx, FILE *fp, const char *path)
{
	X509 *cert;

	rewind(fp);

	cert = PEM_read_X509_AUX(fp, NULL, password_cb, NULL);

	if (!cert) {
		ssl_perror("Unable to read certificate from PEM file '%s'", path);

		return false;
	}

	if (!SSL_CTX_use_certificate(ssl_ctx, cert)) {
		ssl_perror("Unable to use certificate from PEM file '%s'", path);
		X509_free(cert);

		return false;
	}

	return ssl_load_pem_certificate_chain(ssl_ctx, fp, path);
}

static bool
ssl_load_pem_files(SSL_CTX *ssl_ctx, FILE *pkey_fp, const char *pkey_path,
                                     FILE *cert_fp, const char *cert_path,
                                     char *const *extra_certs)
{
	FILE *extra_fp;

	if (!ssl_load_pem_privkey(ssl_ctx, pkey_fp, pkey_path) ||
	    !ssl_load_pem_certificate(ssl_ctx, cert_fp, cert_path)) {

		SSL_CTX_free(ssl_ctx);

		return false;
	}

	while (*extra_certs) {
		extra_fp = fopen(*extra_certs, "r");

		if (!extra_fp) {
			uwsd_ssl_err(NULL, "Unable to open certificate chain file '%s': %m", *extra_certs);
			SSL_CTX_free(ssl_ctx);

			return false;
		}

		ssl_load_pem_certificate_chain(ssl_ctx, extra_fp, *extra_certs);
		fclose(extra_fp);

		extra_certs++;
	}

	return true;
}

static bool
ssl_create_context_from_pem(uwsd_ssl_t *ctx, FILE *pkey_fp, const char *pkey_path,
                                             FILE *cert_fp, const char *cert_path,
                                             char *const *extra_certs)
{
	SSL_CTX *ssl_ctx = ssl_create_context(ctx->protocols, ctx->ciphers);
	X509_NAME *n, *i;

	if (!ssl_ctx)
		return false;

	if (!ssl_load_pem_files(ssl_ctx, pkey_fp, pkey_path,
	                                 cert_fp, cert_path, extra_certs))
		return false;

	n = X509_get_subject_name(SSL_CTX_get0_certificate(ssl_ctx));
	i = X509_get_issuer_name(SSL_CTX_get0_certificate(ssl_ctx));

	uwsd_ssl_info(NULL, "loading certificate '%s' by '%s' from '%s'",
		n ? ssl_get_subject_cn(n) : NULL,
		i ? ssl_get_subject_cn(i) : NULL,
		cert_path);

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
	FILE *fp;
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

		fp = fopen(path, "r");

		if (!fp) {
			sys_perror("Unable to open '%s'", path);
			continue;
		}

		ssl_create_context_from_pem(ctx, fp, path, fp, path, NULL);

		fclose(fp);
	}

	closedir(dp);

	return (ctx->contexts.count > 0);
}

#ifndef HAVE_SSL_GET0_PEER_CERTIFICATE
static X509 *
SSL_get0_peer_certificate(const SSL *ssl)
{
	X509 *cert;

	cert = SSL_get_peer_certificate(ssl);

	X509_free(cert);

	return cert;
}
#endif

static int
ssl_verify_loose_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	int err;

	if (preverify_ok == 1)
		return 1;

	err = X509_STORE_CTX_get_error(x509_ctx);

	switch (err) {
	case X509_V_OK:
	case X509_V_ERR_CERT_NOT_YET_VALID:
	case X509_V_ERR_CERT_HAS_EXPIRED:
	case X509_V_ERR_CRL_NOT_YET_VALID:
	case X509_V_ERR_CRL_HAS_EXPIRED:
	case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
	case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
	case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
	case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
	case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
	case X509_V_ERR_CERT_UNTRUSTED:
		return 1;

	default:
		return 0;
	}
}

__hidden bool
uwsd_ssl_ctx_init(uwsd_ssl_t *ctx)
{
	FILE *pkey_fp, *cert_fp;

	if (ctx->certificate_directory)
		ssl_load_certificates(ctx, ctx->certificate_directory);

	if (!!ctx->private_key ^ !!ctx->certificates) {
		uwsd_ssl_err(NULL, "Require both 'private-key' and 'certificate' properties");

		return false;
	}

	if (ctx->private_key && ctx->certificates) {
		pkey_fp = fopen(ctx->private_key, "r");

		if (!pkey_fp) {
			uwsd_ssl_err(NULL, "Unable to open private key file '%s': %m", ctx->private_key);

			return false;
		}

		cert_fp = fopen(ctx->certificates[0], "r");

		if (!cert_fp) {
			uwsd_ssl_err(NULL, "Unable to open certificate file '%s': %m", ctx->certificates[0]);
			fclose(pkey_fp);

			return false;
		}

		ssl_create_context_from_pem(ctx, pkey_fp, ctx->private_key,
		                                 cert_fp, ctx->certificates[0],
		                                 ctx->certificates + 1);

		fclose(pkey_fp);
		fclose(cert_fp);
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
		SSL_CTX_free(ctx->contexts.entries[--ctx->contexts.count]);

	free(ctx->contexts.entries);
}

__hidden bool
uwsd_ssl_client_ctx_init(uwsd_ssl_client_t *ctx)
{
	SSL_CTX *ssl_ctx = ssl_create_context(ctx->protocols, ctx->ciphers);
	FILE *pkey_fp, *cert_fp;
	bool success;

	if (!ssl_ctx)
		return false;

	if (!!ctx->private_key ^ !!ctx->certificates) {
		uwsd_ssl_err(NULL, "Require both 'private-key' and 'certificate' properties");

		return false;
	}

	if (ctx->private_key && ctx->certificates) {
		pkey_fp = fopen(ctx->private_key, "r");

		if (!pkey_fp) {
			uwsd_ssl_err(NULL, "Unable to open private key file '%s': %m", ctx->private_key);

			return false;
		}

		cert_fp = fopen(ctx->certificates[0], "r");

		if (!cert_fp) {
			uwsd_ssl_err(NULL, "Unable to open certificate file '%s': %m", ctx->certificates[0]);
			fclose(pkey_fp);

			return false;
		}

		success = ssl_load_pem_files(ssl_ctx, pkey_fp, ctx->private_key,
		                                      cert_fp, ctx->certificates[0],
		                                      ctx->certificates + 1);

		fclose(pkey_fp);
		fclose(cert_fp);

		if (!success)
			return false;
	}

	switch (ctx->verify_server) {
	case UWSD_VERIFY_SERVER_STRICT:
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
		break;

	case UWSD_VERIFY_SERVER_LOOSE:
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, ssl_verify_loose_cb);
		break;

	case UWSD_VERIFY_SERVER_SKIP:
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
		break;
	}

	ctx->context = ssl_ctx;

	return true;
}

__hidden void
uwsd_ssl_client_ctx_free(uwsd_ssl_client_t *ctx)
{
	SSL_CTX_free(ctx->context);

	ctx->context = NULL;
}

__hidden bool
uwsd_ssl_init(uwsd_client_context_t *cl)
{
	SSL_CTX *tls_ctx;
	SSL *ssl = NULL;

	tls_ctx = ssl_lookup_context_by_sockaddr(cl, &cl->sa_peer.unspec);

#ifndef NDEBUG
	X509_NAME *n = X509_get_subject_name(SSL_CTX_get0_certificate(tls_ctx));
	X509_NAME *i = X509_get_issuer_name(SSL_CTX_get0_certificate(tls_ctx));
	char buf[INET6_ADDRSTRLEN];

	uwsd_ssl_debug(cl, "selecting cert '%s' by '%s' for IP address '%s'",
		n ? ssl_get_subject_cn(n) : NULL,
		i ? ssl_get_subject_cn(i) : NULL,
		inet_ntop(cl->sa_peer.unspec.sa_family, &cl->sa_peer.in6.sin6_addr, buf, sizeof(buf)));
#endif

	SSL_CTX_set_tlsext_servername_callback(tls_ctx, servername_cb);
	SSL_CTX_set_tlsext_servername_arg(tls_ctx, cl);

	ssl = SSL_new(tls_ctx);

	if (!ssl)
		goto err;

	SSL_set_fd(ssl, cl->downstream.ufd.fd);

	switch (cl->listener->ssl->verify_peer) {
	case UWSD_VERIFY_PEER_DISABLED:
		SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);
		break;

	case UWSD_VERIFY_PEER_OPTIONAL:
		uwsd_ssl_debug(cl, "peer verification optional");
		SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);
		break;

	case UWSD_VERIFY_PEER_REQUIRED:
		uwsd_ssl_debug(cl, "peer verification required");
		SSL_set_verify(ssl, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
		break;
	}

	cl->downstream.ssl = ssl;

	return true;

err:
	SSL_free(ssl);

	client_free(cl, "Unable to initialize TLS context: %s", ssl_error());

	return false;
}

__hidden void
uwsd_ssl_free(uwsd_client_context_t *cl)
{
	SSL *ssl = cl->downstream.ssl;

	SSL_free(ssl);

	cl->downstream.ssl = NULL;
}

__hidden bool
uwsd_ssl_accept(uwsd_client_context_t *cl)
{
	SSL *ssl = cl->downstream.ssl;
	int err;

	errno = 0;
	err = SSL_accept(ssl);

	switch (SSL_get_error(ssl, err)) {
	case SSL_ERROR_NONE:
		return true;

	case SSL_ERROR_WANT_READ:
		errno = ENODATA;

		return false;

	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;

		return false;

	case SSL_ERROR_SYSCALL:
		if (errno == 0)
			errno = EPIPE;

		return false;

	default:
		errno = EINVAL;
		uwsd_ssl_err(cl, "SSL_accept(): %s", ssl_error());

		return false;
	}
}

__hidden bool
uwsd_ssl_client_init(uwsd_client_context_t *cl)
{
	uwsd_ssl_client_t *ctx = cl->action->data.proxy.ssl;
	SSL_CTX *tls_ctx;
	SSL *ssl = NULL;

	tls_ctx = ctx->context;

	ssl = SSL_new(tls_ctx);

	if (!ssl)
		goto err;

	SSL_set_fd(ssl, cl->upstream.ufd.fd);

	cl->upstream.ssl = ssl;

	return true;

err:
	SSL_free(ssl);

	client_free(cl, "Unable to initialize TLS context: %s", ssl_error());

	return false;
}

__hidden void
uwsd_ssl_client_free(uwsd_client_context_t *cl)
{
	SSL *ssl = cl->upstream.ssl;

	SSL_free(ssl);

	cl->upstream.ssl = NULL;
}

__hidden bool
uwsd_ssl_client_connect(uwsd_client_context_t *cl)
{
	SSL *ssl = cl->upstream.ssl;
	int err;

	errno = 0;
	err = SSL_connect(ssl);

	switch (SSL_get_error(ssl, err)) {
	case SSL_ERROR_NONE:
		return true;

	case SSL_ERROR_WANT_READ:
		errno = ENODATA;

		return false;

	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;

		return false;

	case SSL_ERROR_SYSCALL:
		if (errno == 0)
			errno = EPIPE;

		return false;

	default:
		errno = EINVAL;
		uwsd_ssl_err(cl, "SSL_connect(): %s", ssl_error());

		return false;
	}
}

__hidden ssize_t
uwsd_ssl_pending(uwsd_connection_t *conn)
{
	SSL *ssl = conn->ssl;

	return SSL_pending(ssl);
}

__hidden ssize_t
uwsd_ssl_recv(uwsd_connection_t *conn, void *data, size_t len)
{
	SSL *ssl = conn->ssl;
	int err;

	errno = 0;
	err = SSL_read(ssl, data, len);

	switch (SSL_get_error(ssl, err)) {
	case SSL_ERROR_NONE:
		return err;

	case SSL_ERROR_ZERO_RETURN:
		return 0;

	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;

		return -1;

	case SSL_ERROR_WANT_CONNECT:
	case SSL_ERROR_WANT_ACCEPT:
		errno = EINPROGRESS;

		return -1;

	case SSL_ERROR_SYSCALL:
		if (errno == 0)
			errno = EPIPE;

		return -1;

	default:
		errno = EINVAL;

		return -1;
	}
}

__hidden ssize_t
uwsd_ssl_sendv(uwsd_connection_t *conn, struct iovec *iov, size_t len)
{
	SSL *ssl = conn->ssl;
	ssize_t total = 0;
	size_t i;
	int err;

	errno = 0;

	for (i = 0; i < len; i++) {
		if (iov[i].iov_len == 0)
			continue;

		err = SSL_write(ssl, iov[i].iov_base, iov[i].iov_len);

		switch (SSL_get_error(ssl, err)) {
		case SSL_ERROR_NONE:
			//iov[i].iov_base += err;
			//iov[i].iov_len -= err;
			total += err;
			break;

		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
			if (total)
				return total;

			errno = EAGAIN;

			return -1;

		case SSL_ERROR_SYSCALL:
			if (total)
				return total;

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
	SSL *ssl = conn->ssl;

	return SSL_shutdown(ssl);
}

__hidden const char *
uwsd_ssl_cipher_name(uwsd_connection_t *conn)
{
	SSL *ssl = conn->ssl;

	return SSL_get_cipher(ssl);
}

__hidden const char *
uwsd_ssl_peer_subject_name(uwsd_connection_t *conn)
{
	SSL *ssl = conn->ssl;
	X509_NAME *peer_subj;
	X509 *peer_cert;

	if (!ssl)
		return NULL;

	peer_cert = SSL_get0_peer_certificate(ssl);

	if (!peer_cert)
		return NULL;

	peer_subj = X509_get_subject_name(peer_cert);

	if (!peer_subj)
		return NULL;

	return ssl_get_subject_cn(peer_subj);
}

__hidden const char *
uwsd_ssl_peer_issuer_name(uwsd_connection_t *conn)
{
	SSL *ssl = conn->ssl;
	X509_NAME *peer_issuer;
	X509 *peer_cert;

	if (!ssl)
		return NULL;

	peer_cert = SSL_get0_peer_certificate(ssl);

	if (!peer_cert)
		return NULL;

	peer_issuer = X509_get_issuer_name(peer_cert);

	if (!peer_issuer)
		return NULL;

	return ssl_get_subject_cn(peer_issuer);
}
