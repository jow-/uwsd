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
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <arpa/inet.h>

#include <libubox/usock.h>
#include <libubox/utils.h>

#include "listen.h"
#include "client.h"
#include "config.h"

static LIST_HEAD(uwsd_endpoints);
static LIST_HEAD(uwsd_sockets);

static uwsd_socket_t *
socket_lookup(const char *addr, size_t addrlen, const char *port, size_t portlen) {
	uwsd_socket_t *sk;

	list_for_each_entry(sk, &uwsd_sockets, list) {
		if (strlen(sk->addr) != addrlen || strlen(sk->port) != portlen)
			continue;

		if (strncmp(sk->addr, addr, addrlen) || strncmp(sk->port, port, portlen))
			continue;

		return sk;
	}

	return NULL;
}

static void *
parse_error(const char *msg)
{
	fprintf(stderr, "Invalid endpoint specification: %s\n", msg);

	return NULL;
}

static void
accept_cb(struct uloop_fd *ufd, unsigned int events)
{
	socklen_t alen = sizeof(struct sockaddr_in6);
	struct sockaddr_in6 sa = { 0 };
	uwsd_endpoint_t *ep;
	bool ssl = false;
	int fd;

	fd = accept(ufd->fd, &sa, &alen);

	if (fd == -1) {
		fprintf(stderr, "accept failed: %s\n", strerror(errno));

		return;
	}

	// FIXME: infinite loop here
	list_for_each_entry(ep, &config->endpoints, list) {
		fprintf(stderr, "ep %p\n", ep);
		//	ep
		//fprintf(stderr, "[%s:%s] ep %p / ep->socket %p / ep->socket->ufd %p / ufd %p\n",
		//	ep->socket->addr, ep->socket->port,
		//	ep, ep->socket, &ep->socket->ufd, ufd);

		if (&ep->socket->ufd != ufd)
			continue;

		if (ep->type != UWSD_LISTEN_HTTPS && ep->type != UWSD_LISTEN_WSS)
			continue;

		ssl = true;
		break;
	}

	client_create(fd, ufd, (struct sockaddr *)&sa, alen, ssl);
}

__hidden uwsd_endpoint_t *
uwsd_endpoint_lookup(struct uloop_fd *ufd, bool ws, const char *prefix)
{
	uwsd_endpoint_t *ep, *matching_ep = NULL;
	size_t len, matching_len = 0;

	list_for_each_entry(ep, &config->endpoints, list) {
		if (&ep->socket->ufd != ufd)
			continue;

		if (ws && ep->type != UWSD_LISTEN_WS && ep->type != UWSD_LISTEN_WSS)
			continue;

		if (!ws && ep->type != UWSD_LISTEN_HTTP && ep->type != UWSD_LISTEN_HTTPS)
			continue;

		len = pathmatch(ep->prefix, prefix);

		if (len > matching_len) {
			matching_len = len;
			matching_ep = ep;
		}
	}

	return matching_ep;
}

__hidden bool
uwsd_has_ssl_endpoints(void)
{
	uwsd_endpoint_t *ep;

	list_for_each_entry(ep, &config->endpoints, list)
		if (ep->type == UWSD_LISTEN_WSS || ep->type == UWSD_LISTEN_HTTPS)
			return true;

	return false;
}


__hidden bool
uwsd_endpoint_url_parse(uwsd_endpoint_t *ep, const char *spec)
{
	const char *p, *addr, *port, *prefix;
	size_t addrlen, portlen, prefixlen;
	char *_addr, *_port;
	uwsd_listen_type_t type;
	uwsd_socket_t *sk;

	p = spec + strcspn(spec, ":");

	if (!strspncmp(spec, p, "ws"))
		type = UWSD_LISTEN_WS;
	else if (!strspncmp(spec, p, "wss"))
		type = UWSD_LISTEN_WSS;
	else if (!strspncmp(spec, p, "http"))
		type = UWSD_LISTEN_HTTP;
	else if (!strspncmp(spec, p, "https"))
		type = UWSD_LISTEN_HTTPS;
	else
		return parse_error("unrecognized listen URL scheme");

	if (!strncmp(p, "://", 3))
		p += 3;
	else
		return parse_error("invalid listen URL format");

	if (*p == '[') {
		addr = p + 1;
		addrlen = strcspn(addr, "]");
		p = addr + addrlen;

		if (*p++ != ']')
			return parse_error("invalid listen URL format");
	}
	else {
		addr = p;
		addrlen = strcspn(addr, ":");
		p = addr + addrlen;
	}

	if (*p == ':') {
		port = p + 1;
		portlen = strcspn(port, "/");
		p = port + portlen;
	}
	else if (type == UWSD_LISTEN_WSS || type == UWSD_LISTEN_HTTPS) {
		port = "443";
		portlen = 3;
	}
	else {
		port = "80";
		portlen = 2;
	}

	if (*p != '/')
		return parse_error("invalid listen URL format");

	prefix = p;
	prefixlen = strcspn(prefix, " \t\n");

	for (p = prefix + prefixlen; isspace(*p); p++)
		;

	sk = socket_lookup(addr, addrlen, port, portlen);

	if (!sk) {
		sk = calloc_a(sizeof(*sk), &_addr, addrlen + 1, &_port, portlen + 1);

		if (!sk) {
			fprintf(stderr, "Unable to allocate socket structure\n");

			return false;
		}

		sk->addr = strncpy(_addr, addr, addrlen);
		sk->port = strncpy(_port, port, portlen);

		sk->ufd.cb = accept_cb;
		sk->ufd.fd = usock(USOCK_SERVER | USOCK_NONBLOCK | USOCK_TCP,
			sk->addr, sk->port);

		if (sk->ufd.fd == -1) {
			fprintf(stderr, "Unable to listen on %s:%s: %s\n",
				sk->addr, sk->port, strerror(errno));

			free(sk);

			return false;
		}

		uloop_fd_add(&sk->ufd, ULOOP_READ);
		list_add_tail(&sk->list, &uwsd_sockets);
	}

	fprintf(stderr, "ep %p / ep->socket = %p\n", ep, sk);

	ep->type = type;
	ep->socket = sk;
	xasprintf(&ep->prefix, "%.*s", (int)prefixlen, prefix);

	return true;
}

__hidden bool
uwsd_backend_url_parse(uwsd_backend_t *be, const char *spec)
{
	const char *p, *uaddr, *uport, *uproto;
	size_t uaddrlen, uportlen, uprotolen;
	uwsd_backend_type_t utype;
	bool ubinary;

	uproto = spec;
	p = uproto + strcspn(uproto, ":");

	if (!strspncmp(uproto, p, "unix"))
		utype = UWSD_BACKEND_UNIX;
	else if (!strspncmp(uproto, p, "script"))
		utype = UWSD_BACKEND_SCRIPT;
	else if (!strspncmp(uproto, p, "file"))
		utype = UWSD_BACKEND_FILE;
	else if (!strspncmp(uproto, p, "tcp"))
		utype = UWSD_BACKEND_TCP;
	else if (!strspncmp(uproto, p, "udp"))
		utype = UWSD_BACKEND_UDP;
	else
		return parse_error("invalid upstream type");

	if (*p++ != ':')
		return parse_error("invalid upstream address");

	uaddr = p;
	uaddrlen = strcspn(uaddr, ": \t\n");
	p = uaddr + uaddrlen;

	if (utype == UWSD_BACKEND_TCP || utype == UWSD_BACKEND_UDP) {
		if (*p++ != ':')
			return parse_error("missing upstream port");

		uport = p;
		uportlen = strcspn(uport, " \t\n");
		p = uport + uportlen;
	}
	else {
		uport = NULL;
		uportlen = 0;
	}

	uproto = p + strspn(p, " \t\n");

	if (uproto > p && *uproto) {
		p = uproto + strcspn(uproto, " \t\n");

		if (!strspncmp(uproto, p, "binary"))
			ubinary = true;
		else if (!strspncmp(uproto, p, "text"))
			ubinary = false;
		else
			return parse_error("protocol type must be either text or binary");

		uproto = p + strspn(p, " \t\n");

		if (uproto > p && *uproto) {
			uprotolen = strcspn(uproto, " \t\n");
		}
		else {
			uproto = NULL;
			uprotolen = 0;
		}
	}
	else {
		ubinary = false;

		uproto = NULL;
		uprotolen = 0;
	}

	be->type = utype;
	be->binary = ubinary;
	xasprintf(&be->addr, "%.*s", (int)uaddrlen, uaddr);

	if (uport)
		xasprintf(&be->port, "%.*s", (int)uportlen, uport);

	if (uproto)
		xasprintf(&be->wsproto, "%.*s", (int)uprotolen, uproto);

	if (utype == UWSD_BACKEND_SCRIPT)
		uwsd_script_init(be);

	return true;
}
