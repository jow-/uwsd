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

#include "client.h"
#include "ssl.h"


static bool ssl_initialized = false;

static SSL_CTX **certs = NULL;
static size_t num_certs = 0;


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

static void
sys_perror(const char *fmt, ...)
{
	int err = errno;
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, ": %s\n", strerror(err));
}

static void
ssl_perror(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, ": %s\n", ssl_error());
}

static SSL_CTX *
ssl_lookup_context_by_hostname(const char *hostname);

/* SNI callback */
static int
servername_cb(SSL *ssl, int *al, void *arg)
{
	const char *hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
	SSL_CTX *tls_ctx;

	if (hostname) {
		tls_ctx = ssl_lookup_context_by_hostname(hostname);

		SSL_set_SSL_CTX(ssl, tls_ctx);
	}

	return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *
ssl_create_context(void)
{
	SSL_CTX *tls_ctx = NULL;

	if (!ssl_initialized) {
		SSL_load_error_strings();
		SSL_library_init();

		ssl_initialized = true;
	}

	tls_ctx = SSL_CTX_new(TLS_method());

	if (!tls_ctx)
		goto err;

	SSL_CTX_set_options(tls_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
	SSL_CTX_set_default_verify_paths(tls_ctx);
	SSL_CTX_set_session_cache_mode(tls_ctx, SSL_SESS_CACHE_CLIENT);
	SSL_CTX_set_session_id_context(tls_ctx, (const unsigned char *)"1", 1);

#if 0
	SSL_CTX_set_cipher_list(tls_ctx, ssl_tlsciphers);
#endif

	SSL_CTX_set_tlsext_servername_callback(tls_ctx, servername_cb);

	return tls_ctx;

err:
	SSL_CTX_free(tls_ctx);

	ssl_perror("Unable to initialize TLS context");

	return NULL;
}

static bool
ssl_match_hostname(const char *certname, const char *hostname)
{
	const char *p;

	/* wildcard */
	if (strncmp(certname, "*.", 2) == 0) {
		p = strchr(hostname, '.');

		if (!p || !p[1] || p == hostname)
			return false;

		hostname = p + 1;
		certname += 2;
	}

	return (strcasecmp(certname, hostname) == 0);
}

static bool
ssl_match_context(SSL_CTX *ssl_ctx, const struct sockaddr *sa, const char *hostname)
{
	struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)sa;
	struct sockaddr_in *s4 = (struct sockaddr_in *)sa;

	STACK_OF(GENERAL_NAME) *san;
	const GENERAL_NAME *name;

	X509_NAME_ENTRY *e;
	X509_NAME *subj;
	X509 *cert;

	ASN1_STRING *s;
	const char *p;
	bool match;
	int pos;

	cert = SSL_CTX_get0_certificate(ssl_ctx);

	if (hostname) {
		/* check common name match */
		subj = X509_get_subject_name(cert);
		pos = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);

		if (pos >= 0) {
			e = X509_NAME_get_entry(subj, pos);
			s = X509_NAME_ENTRY_get_data(e);
			p = (char *)ASN1_STRING_get0_data(s);

			if ((size_t)ASN1_STRING_length(s) == strlen(p) &&
			    ssl_match_hostname(p, hostname))
				return true;
		}
	}

	/* check subject alt name matches */
	san = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

	for (pos = 0, match = false; san && !match && pos < sk_GENERAL_NAME_num(san); pos++) {
		name = sk_GENERAL_NAME_value(san, pos);

		switch (name->type) {
		case GEN_DNS:
			if (!hostname)
				continue;

			p = (char *)ASN1_STRING_get0_data(name->d.dNSName);

			if ((size_t)ASN1_STRING_length(name->d.dNSName) != strlen(p))
				continue;

			match = ssl_match_hostname(p, hostname);
			break;

		case GEN_IPADD:
			if (!sa)
				continue;

			p = (char *)name->d.ip->data;

			if (name->d.ip->length == 4) {
				if (sa->sa_family == AF_INET6 && IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr))
					match = !memcmp(p, &s6->sin6_addr.s6_addr[12], 4);
				else if (sa->sa_family == AF_INET)
					match = !memcmp(p, &s4->sin_addr, 4);
			}
			else if (name->d.ip->length == 16) {
				match = (sa->sa_family == AF_INET6 && !memcmp(p, &s6->sin6_addr, 16));
			}

			break;
		}
	}

	sk_GENERAL_NAME_pop_free(san, GENERAL_NAME_free);

	return match;
}

static SSL_CTX *
ssl_lookup_context_by_hostname(const char *hostname)
{
	size_t i;

	if (num_certs > 1) {
		for (i = 0; i < num_certs; i++)
			if (ssl_match_context(certs[i], NULL, hostname))
				return certs[i];

		fprintf(stderr, "No matching certificate for hostname '%s' - using first one\n", hostname);
	}

	return certs[0];
}

static SSL_CTX *
ssl_lookup_context_by_sockaddr(const struct sockaddr *sa)
{
	size_t i;

	if (num_certs > 1)
		for (i = 0; i < num_certs; i++)
			if (ssl_match_context(certs[i], sa, NULL))
				return certs[i];

	return certs[0];
}

__hidden bool
uwsd_ssl_load_certificates(const char *directory)
{
	char path[PATH_MAX];
	struct dirent *e;
	struct stat s;
	FILE *fp;
	DIR *dp;

	X509 *cert = NULL, *other;
	X509_STORE *store = NULL;
	SSL_CTX *ssl_ctx = NULL;
	EVP_PKEY *pkey = NULL;

	if (!ssl_initialized) {
		SSL_load_error_strings();
		SSL_library_init();

		ssl_initialized = true;
	}

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

		pkey = PEM_read_PrivateKey(fp, NULL, password_cb, NULL);

		if (!pkey) {
			ssl_perror("Unable to read private key from PEM file '%s'", path);
			goto skip;
		}

		rewind(fp);

		cert = PEM_read_X509_AUX(fp, NULL, password_cb, NULL);

		if (!cert) {
			ssl_perror("Unable to read certificate from PEM file '%s'", path);
			goto skip;
		}

		ssl_ctx = ssl_create_context();

		if (!ssl_ctx)
			goto skip;

		if (!SSL_CTX_use_certificate(ssl_ctx, cert)) {
			ssl_perror("Unable to use certificate from PEM file '%s'", path);
			goto skip;
		}

		if (!SSL_CTX_use_PrivateKey(ssl_ctx, pkey)) {
			ssl_perror("Unable to use private key from PEM file '%s'", path);
			goto skip;
		}

		store = SSL_CTX_get_cert_store(ssl_ctx);

		while ((other = PEM_read_X509(fp, NULL, password_cb, NULL)) != NULL) {
			if (SSL_CTX_add0_chain_cert(ssl_ctx, other)) {
				X509_STORE_add_cert(store, other);
			}
			else {
				ssl_perror("Unable to use additional certificate from PEM file '%s'", path);
				X509_free(other);
			}
		}

		fclose(fp);

		certs = xrealloc(certs, sizeof(*certs) * (num_certs + 1));
		certs[num_certs++] = ssl_ctx;

		continue;

skip:
		SSL_CTX_free(ssl_ctx);
		EVP_PKEY_free(pkey);
		X509_free(cert);

		fclose(fp);
	}

	closedir(dp);

	return (num_certs > 0);
}

__hidden bool
uwsd_ssl_init(uwsd_client_context_t *cl)
{
	SSL_CTX *tls_ctx;
	SSL *ssl = NULL;

	tls_ctx = ssl_lookup_context_by_sockaddr(&cl->sa.unspec);
	ssl = SSL_new(tls_ctx);

	if (!ssl)
		goto err;

	SSL_set_fd(ssl, cl->downstream.ufd.fd);

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
	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;

		return false;

	case SSL_ERROR_SYSCALL:
		if (errno == 0)
			errno = EPIPE;

		return false;

	default:
		errno = EINVAL;
		client_debug(cl, "SSL_accept(): %s", ssl_error());

		return false;
	}
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
uwsd_ssl_send(uwsd_connection_t *conn, const void *data, size_t len)
{
	SSL *ssl = conn->ssl;
	int err;

	errno = 0;

	if (len == 0)
		return 0;

	err = SSL_write(ssl, data, len);

	switch (SSL_get_error(ssl, err)) {
	case SSL_ERROR_NONE:
		return err;

	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;

		return -1;

	case SSL_ERROR_SYSCALL:
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
			errno = EAGAIN;
			break;

		case SSL_ERROR_SYSCALL:
			break;

		default:
			errno = EINVAL;
			break;
		}
	}

	return total ? total : -1;
}
