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
	int fd;

	fd = accept(ufd->fd, &sa, &alen);

	if (fd == -1) {
		fprintf(stderr, "accept failed: %s\n", strerror(errno));

		return;
	}

	client_create(fd, ufd, (struct sockaddr *)&sa, alen);
}

__hidden uwsd_endpoint_t *
uwsd_endpoint_create(const char *spec)
{
	size_t addrlen, portlen, prefixlen, uaddrlen, uportlen, uprotolen;
	const char *p, *addr, *port, *prefix, *uaddr, *uport, *uproto;
	char *_addr, *_port, *_prefix, *_uaddr, *_uport, *_uproto;
	uwsd_backend_type_t utype;
	uwsd_listen_type_t type;
	uwsd_endpoint_t *ep;
	uwsd_socket_t *sk;
	bool ubinary;

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

	uproto = p;
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

	if ((type == UWSD_LISTEN_WS || type == UWSD_LISTEN_WSS) && utype == UWSD_BACKEND_FILE)
		return parse_error("WebSocket endpoints require an script, unix, tcp or udp backend");
	else if ((type == UWSD_LISTEN_HTTP || type == UWSD_LISTEN_HTTPS) &&
	         (utype == UWSD_BACKEND_UDP || utype == UWSD_BACKEND_UNIX))
		return parse_error("HTTP endpoints require a script, file or tcp backend");

	sk = socket_lookup(addr, addrlen, port, portlen);

	if (!sk) {
		sk = calloc_a(sizeof(*sk),  &_addr, addrlen + 1, &_port, portlen + 1);

		if (!sk) {
			fprintf(stderr, "Unable to allocate socket structure\n");

			return NULL;
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

			return NULL;
		}

		uloop_fd_add(&sk->ufd, ULOOP_READ);
		list_add_tail(&sk->list, &uwsd_sockets);
	}

	ep = calloc_a(sizeof(uwsd_endpoint_t),
		&_prefix, prefixlen + 1,
		&_uaddr, uaddrlen + 1,
		&_uport, uport ? uportlen + 1 : 0,
		&_uproto, uproto ? uprotolen + 1 : 0);

	if (!ep) {
		fprintf(stderr, "Unable to allocate endpoint structure\n");

		return NULL;
	}

	ep->type = type;
	ep->prefix = strncpy(_prefix, prefix, prefixlen);
	ep->socket = sk;

	ep->backend.type = utype;
	ep->backend.binary = ubinary;
	ep->backend.addr = strncpy(_uaddr, uaddr, uaddrlen);
	ep->backend.port = uport ? strncpy(_uport, uport, uportlen) : NULL;
	ep->backend.wsproto = uproto ? strncpy(_uproto, uproto, uprotolen) : NULL;

	if (utype == UWSD_BACKEND_SCRIPT)
		uwsd_script_init(&ep->backend);

	list_add_tail(&ep->list, &uwsd_endpoints);

	return ep;
}

__hidden uwsd_endpoint_t *
uwsd_endpoint_lookup(struct uloop_fd *ufd, bool ws, const char *prefix)
{
	uwsd_endpoint_t *ep, *matching_ep = NULL;
	size_t len, matching_len = 0;

	list_for_each_entry(ep, &uwsd_endpoints, list) {
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
