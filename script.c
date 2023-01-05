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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#include <signal.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <sys/wait.h>

#include <libubox/uloop.h>
#include <ucode/compiler.h>
#include <ucode/lib.h>

#include "state.h"
#include "script.h"
#include "ws.h"
#include "client.h"
#include "listen.h"
#include "log.h"


static LIST_HEAD(requests);

typedef enum {
	UWSD_SCRIPT_DATA_PEER_ADDR,
	UWSD_SCRIPT_DATA_CONNECTION_TYPE,
	UWSD_SCRIPT_DATA_HTTP_VERSION,
	UWSD_SCRIPT_DATA_HTTP_METHOD,
	UWSD_SCRIPT_DATA_HTTP_URI,
	UWSD_SCRIPT_DATA_HTTP_HEADER,
	UWSD_SCRIPT_DATA_HTTP_DATA,
	UWSD_SCRIPT_DATA_HTTP_EOF,
	UWSD_SCRIPT_DATA_WS_INIT,
	UWSD_SCRIPT_DATA_WS_FRAGMENT,
	UWSD_SCRIPT_DATA_WS_FINAL,
	UWSD_SCRIPT_DATA_WS_EOF
} script_data_type_t;

typedef enum {
	PARSE_TYPE1,
	PARSE_TYPE2,
	PARSE_LEN1,
	PARSE_LEN2,
	PARSE_DATA
} script_request_parse_state_t;

typedef enum {
	STATE_HEAD,
	STATE_BODY,
	STATE_WS,
	STATE_EOF
} script_request_state_t;

typedef struct {
	uc_vm_t vm;
	uc_value_t *onConnect, *onData, *onClose;
	uc_value_t *onRequest, *onBody;
	struct uloop_fd ufd;
} script_context_t;

typedef struct {
	struct list_head list;
	struct uloop_fd ufd;
	script_context_t *ctx;
	script_request_state_t state;
	struct {
		script_request_parse_state_t state;
		uint16_t type;
		uint16_t len;
		uint16_t datalen;
		uint8_t data[8192];
	} buf;
	uc_value_t *req, *hdr, *conn, *data, *proto;
} script_connection_t;


static const char *http_method_names[] = {
	[HTTP_GET]     = "GET",
	[HTTP_POST]    = "POST",
	[HTTP_PUT]     = "PUT",
	[HTTP_HEAD]    = "HEAD",
	[HTTP_OPTIONS] = "OPTIONS",
	[HTTP_DELETE]  = "DELETE",
	[HTTP_TRACE]   = "TRACE",
	[HTTP_CONNECT] = "CONNECT"
};


/* -- Internal utility functions ----------------------- */

static bool script_conn_ws_handshake(script_connection_t *, const char *);
static bool script_conn_ws_data(script_connection_t *, const void *, size_t, bool);
static bool script_conn_http_request(script_connection_t *);
static bool script_conn_http_body(script_connection_t *, const void *, size_t);
static void script_conn_close(script_connection_t *, uint16_t, const char *);

static void
ucv_clear(uc_value_t **uv)
{
	ucv_put(*uv);

	*uv = NULL;
}

static bool
tlv_send(int fd, uint16_t type, uint16_t len, const void *value)
{
	struct iovec iov[3];
	ssize_t total;

	type = htons(type);
	len = htons(len);

	iov[0].iov_base = &type;
	iov[0].iov_len = sizeof(type);

	iov[1].iov_base = &len;
	iov[1].iov_len = sizeof(len);

	iov[2].iov_base = (void *)value;
	iov[2].iov_len = ntohs(len);

	total = iov[0].iov_len + iov[1].iov_len + iov[2].iov_len;

	return writev(fd, iov, 3) == total;
}

static bool
header_tlv_send(int fd, uwsd_http_header_t *hdr)
{
	size_t nlen = strlen(hdr->name);
	size_t vlen = strlen(hdr->value);
	uint16_t type = htons(UWSD_SCRIPT_DATA_HTTP_HEADER);
	uint16_t len = htons(nlen + vlen + 1);
	struct iovec iov[4];
	ssize_t total;

	iov[0].iov_base = &type;
	iov[0].iov_len = sizeof(type);

	iov[1].iov_base = &len;
	iov[1].iov_len = sizeof(len);

	iov[2].iov_base = hdr->name;
	iov[2].iov_len = nlen + 1;

	iov[3].iov_base = hdr->value;
	iov[3].iov_len = vlen;

	total = iov[0].iov_len + iov[1].iov_len + iov[2].iov_len + iov[3].iov_len;

	return writev(fd, iov, 4) == total;
}

static int
server_socket_setup(const char *sockpath)
{
	struct sockaddr_un sun = { .sun_family = AF_UNIX };
	const int one = 1;
	int sock;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);

	if (sock == -1) {
		uwsd_log_err(NULL, "Unable to spawn UNIX socket: %m");

		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
		uwsd_log_warn(NULL, "Unable to set SO_REUSEADDR: %m");

#ifdef __linux__
	strncpy(sun.sun_path + 1, sockpath, sizeof(sun.sun_path) - 1);
#else
	strncpy(sun.sun_path, sockpath, sizeof(sun.sun_path));
#endif

	if (bind(sock, &sun, sizeof(sun)) == -1) {
		uwsd_log_err(NULL, "Unable to bind to UNIX socket '%s%s': %m",
			sun.sun_path[0] ? "" : "@",
			sun.sun_path[0] ? sun.sun_path : sun.sun_path + 1);

		close(sock);

		return -1;
	}

	if (listen(sock, SOMAXCONN) == -1) {
		uwsd_log_err(NULL, "Unable to listen on UNIX socket '%s%s': %m",
			sun.sun_path[0] ? "" : "@",
			sun.sun_path[0] ? sun.sun_path : sun.sun_path + 1);

		close(sock);

		return -1;
	}

	return sock;
}

static bool
ws_frame_send(script_connection_t *conn, uwsd_ws_opcode_t opcode, const void *data, size_t len)
{
	struct iovec iov[2];
	size_t iolen = 0;

	struct __attribute__((packed)) {
		ws_frame_header_t hdr;
		union {
			uint16_t u16;
			uint64_t u64;
		} extlen;
	} hdrbuf = {
		.hdr = {
			.opcode = opcode,
			.fin = true
		}
	};

	iov[0].iov_base = &hdrbuf;
	iolen++;

	if (len > 0xffff) {
		hdrbuf.hdr.len = 127;
		hdrbuf.extlen.u64 = htobe64(len);
		iov[0].iov_len = sizeof(ws_frame_header_t) + sizeof(uint64_t);
	}
	else if (len > 0x7d) {
		hdrbuf.hdr.len = 126;
		hdrbuf.extlen.u16 = htobe16(len);
		iov[0].iov_len = sizeof(ws_frame_header_t) + sizeof(uint16_t);
	}
	else {
		hdrbuf.hdr.len = len;
		iov[0].iov_len = sizeof(ws_frame_header_t);
	}

	iov[iolen].iov_base = (void *)data;
	iov[iolen].iov_len = len;
	iolen++;

	// FIXME: fragmentation, error handling etc.
	if (writev(conn->ufd.fd, iov, iolen) == -1)
		return false;

	return true;
}

static void
ws_error_send(script_connection_t *conn, bool terminate, uint16_t code, const char *msg, ...)
{
	va_list ap;
	size_t len;

	code = htons(code);
	len = sizeof(code);
	memcpy(conn->buf.data, &code, len);

	va_start(ap, msg);
	len += vsnprintf((char *)conn->buf.data + len, 124, msg, ap);
	va_end(ap);

	ws_frame_send(conn, OPCODE_CLOSE, conn->buf.data, len);

	if (terminate)
		script_conn_close(conn, ntohs(code), (char *)conn->buf.data + 2);
}

static void
http_reply_start(script_connection_t *conn, uint16_t code, const char *reason)
{
	double http_version = ucv_double_get(ucv_object_get(conn->req, "http_version", NULL));

	//uwsd_http_info(cl, "R %03hu %s", code, reason ? reason : "-");

	conn->buf.datalen = snprintf((char *)conn->buf.data, sizeof(conn->buf.data),
		"HTTP/%.1f %hu %s\r\n", http_version, code, reason);
}

static void
http_reply_header(script_connection_t *conn, const char *name, const char *value)
{
	conn->buf.datalen += snprintf(
		(char *)conn->buf.data + conn->buf.datalen,
		sizeof(conn->buf.data) - conn->buf.datalen,
		"%s: %s\r\n", name, value);
}

static void
http_reply_finish_v(script_connection_t *conn, const char *ctype, const char *msg, va_list ap)
{
	uc_value_t *method = ucv_object_get(conn->req, "request_method", NULL);
	va_list ap1;

	if (msg && strcmp(ucv_string_get(method), "HEAD")) {
		va_copy(ap1, ap);
		conn->buf.datalen += snprintf(
			(char *)conn->buf.data + conn->buf.datalen,
			sizeof(conn->buf.data) - conn->buf.datalen,
			"Content-Type: %s\r\n"
			"Content-Length: %d\r\n\r\n",
			ctype ? ctype : "text/plain",
			vsnprintf("", 0, msg, ap1)
		);
		va_end(ap1);

		va_copy(ap1, ap);
		conn->buf.datalen += vsnprintf(
			(char *)conn->buf.data + conn->buf.datalen,
			sizeof(conn->buf.data) - conn->buf.datalen,
			msg, ap1);
		va_end(ap1);
	}
	else {
		conn->buf.datalen += snprintf(
			(char *)conn->buf.data + conn->buf.datalen,
			sizeof(conn->buf.data) - conn->buf.datalen,
			"\r\n");
	}

	send(conn->ufd.fd, conn->buf.data, conn->buf.datalen, 0);
}

static void
http_reply_finish(script_connection_t *conn, const char *ctype, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	http_reply_finish_v(conn, ctype, msg, ap);
	va_end(ap);
}

static void
http_error_send(script_connection_t *conn, bool terminate, uint16_t code, const char *reason, const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	http_reply_start(conn, code, reason);
	http_reply_header(conn, "Connection", "close");
	http_reply_finish_v(conn, "text/plain", msg, ap);
	va_end(ap);

	if (terminate)
		script_conn_close(conn, 0, NULL);
}


/* -- script host side methods ------------------------- */

static bool
script_conn_ws_handshake(script_connection_t *conn, const char *acceptkey)
{
	uc_vm_t *vm = &conn->ctx->vm;
	uc_value_t *ctx, *protocols = NULL;
	uc_resource_type_t *conn_type;
	uc_exception_type_t ex;
	char *protohdr, *p;
	size_t plen;
	void **clp;

	conn_type = ucv_resource_type_lookup(vm, "uwsd.connection");
	assert(conn_type);

	conn->conn = uc_resource_new(conn_type, conn);

	if (conn->ctx->onConnect) {
		protohdr = NULL;

		ucv_object_foreach(conn->hdr, hname, hvalue) {
			if (!strcasecmp(hname, "Sec-WebSocket-Protocol")) {
				protohdr = ucv_string_get(hvalue);
				break;
			}
		}

		if (protohdr) {
			for (p = protohdr, plen = strcspn(p, ", \t\r\n");
			     plen != 0;
			     p += plen + strspn(p + plen, ", \t\r\n"), plen = strcspn(p, ", \t\r\n")) {

				if (!protocols)
					protocols = ucv_array_new(vm);

				ucv_array_push(protocols,
					ucv_string_new_length(p, plen));
			}
		}

		uc_vm_stack_push(vm, ucv_get(conn->ctx->onConnect));
		uc_vm_stack_push(vm, ucv_get(conn->conn));
		uc_vm_stack_push(vm, protocols);

		clp = ucv_resource_dataptr(conn->conn, "uwsd.connection");
		ex = uc_vm_call(vm, false, 2);

		if (!clp || !*clp) {
			script_conn_close(conn, 0, NULL);

			return false; /* onConnect() function freed the connection */
		}

		if (ex != EXCEPTION_NONE) {
			ctx = ucv_object_get(ucv_array_get(vm->exception.stacktrace, 0), "context", NULL);

			http_error_send(conn, true, 500, "Internal Server Error",
				"Exception in onConnect(): %s\n%s",
					vm->exception.message,
					ucv_string_get(ctx));

			return false;
		}

		ucv_put(uc_vm_stack_pop(vm));

		if (!conn->proto) {
			http_error_send(conn, true, 500, "Internal Server Error",
				"The onConnect() handler did not accept the connection\n");

			return false;
		}

		if (ucv_type(conn->proto) != UC_STRING)
			ucv_clear(&conn->proto);
	}

	http_reply_start(conn, 101, "Switching Protocols");
	http_reply_header(conn, "Upgrade", "WebSocket");
	http_reply_header(conn, "Connection", "Upgrade");
	http_reply_header(conn, "Sec-WebSocket-Accept", acceptkey);

	if (conn->proto)
		http_reply_header(conn, "Sec-WebSocket-Protocol", ucv_string_get(conn->proto));

	http_reply_finish(conn, NULL, NULL);

	return true;
}

static bool
script_conn_ws_data(script_connection_t *conn, const void *data, size_t len, bool final)
{
	uc_vm_t *vm = &conn->ctx->vm;
	uc_exception_type_t ex;
	uc_value_t *ctx;

	if (!conn->ctx->onData)
		return true;

	uc_vm_stack_push(vm, ucv_get(conn->ctx->onData));
	uc_vm_stack_push(vm, ucv_get(conn->conn));
	uc_vm_stack_push(vm, ucv_string_new_length(data, len));
	uc_vm_stack_push(vm, ucv_boolean_new(final));

	ex = uc_vm_call(vm, false, 3);

	if (ex != EXCEPTION_NONE) {
		ctx = ucv_object_get(ucv_array_get(vm->exception.stacktrace, 0), "context", NULL);

		ws_error_send(conn, true, STATUS_INTERNAL_ERROR,
			"Exception in onData(): %s\n%s",
				vm->exception.message,
				ucv_string_get(ctx));

		return false;
	}

	ucv_put(uc_vm_stack_pop(vm));

	return true;
}

static void
script_conn_close(script_connection_t *conn, uint16_t code, const char *msg)
{
	uc_vm_t *vm = &conn->ctx->vm;
	void **reqptr;
	size_t nargs;

	if (conn->ctx->onClose) {
		if (vm->exception.type != EXCEPTION_NONE)
			uc_vm_exception_handler_get(vm)(vm, &vm->exception);

		uc_vm_stack_push(vm, ucv_get(conn->ctx->onClose));
		uc_vm_stack_push(vm, ucv_get(conn->conn));
		nargs = 1;

		if (code) {
			uc_vm_stack_push(vm, ucv_uint64_new(code));
			uc_vm_stack_push(vm, (msg && *msg) ? ucv_string_new(msg) : NULL);
			nargs += 2;
		}

		if (uc_vm_call(vm, false, nargs) == EXCEPTION_NONE)
			ucv_put(uc_vm_stack_pop(vm));
	}

	reqptr = ucv_resource_dataptr(conn->conn, NULL);

	if (reqptr)
		*reqptr = NULL;

	ucv_clear(&conn->req);
	ucv_clear(&conn->data);
	ucv_clear(&conn->proto);
	ucv_clear(&conn->conn);

	uloop_fd_delete(&conn->ufd);
	list_del(&conn->list);

	free(conn);
}

static bool
script_conn_http_request(script_connection_t *conn)
{
	uc_resource_type_t *conn_type;
	uc_vm_t *vm = &conn->ctx->vm;
	uc_exception_type_t ex;
	uc_value_t *ctx;

	conn_type = ucv_resource_type_lookup(vm, "uwsd.request");
	assert(conn_type);

	ucv_set_constant(conn->req, true);
	ucv_set_constant(conn->hdr, true);

	conn->conn = uc_resource_new(conn_type, conn);

	if (conn->ctx->onRequest) {
		uc_vm_stack_push(vm, ucv_get(conn->ctx->onRequest));
		uc_vm_stack_push(vm, ucv_get(conn->conn));
		uc_vm_stack_push(vm, ucv_get(ucv_object_get(conn->conn, "request_method", NULL)));
		uc_vm_stack_push(vm, ucv_get(ucv_object_get(conn->conn, "request_uri", NULL)));

		ex = uc_vm_call(vm, false, 3);

		if (ex != EXCEPTION_NONE) {
			ctx = ucv_object_get(ucv_array_get(vm->exception.stacktrace, 0), "context", NULL);

			http_error_send(conn, true, 500, "Internal Server Error",
				"Exception in onRequest(): %s\n%s",
					vm->exception.message,
					ucv_string_get(ctx));

			return false;
		}

		ucv_put(uc_vm_stack_pop(vm));
	}
	else {
		http_error_send(conn, true, 501, "Not Implemented",
			"Backend script does not implement an onRequest() handler.\n");

		return false;
	}

	return true;
}

static bool
script_conn_http_body(script_connection_t *conn, const void *data, size_t len)
{
	uc_vm_t *vm = &conn->ctx->vm;
	uc_exception_type_t ex;
	uc_value_t *ctx;

	if (!conn->ctx->onBody)
		return true;

	uc_vm_stack_push(vm, ucv_get(conn->ctx->onBody));
	uc_vm_stack_push(vm, ucv_get(conn->conn));
	uc_vm_stack_push(vm, ucv_string_new_length(data, len));

	ex = uc_vm_call(vm, false, 2);

	if (ex != EXCEPTION_NONE) {
		ctx = ucv_object_get(ucv_array_get(vm->exception.stacktrace, 0), "context", NULL);

		http_error_send(conn, true, 500, "Internal Server Error",
			"Exception in onBody(): %s\n%s",
				vm->exception.message,
				ucv_string_get(ctx));

		return false;
	}

	ucv_put(uc_vm_stack_pop(vm));

	return true;
}


/* -- ucode resource methods --------------------------- */

static uc_value_t *
uc_script_accept(uc_vm_t *vm, size_t nargs)
{
	script_connection_t **conn = uc_fn_this("uwsd.connection");
	uc_value_t *proto = uc_fn_arg(0);

	if (!conn || !*conn)
		return NULL;

	if (proto && ucv_type(proto) != UC_STRING)
		return NULL;

	(*conn)->proto = proto ? ucv_get(proto) : ucv_boolean_new(true);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_script_data(uc_vm_t *vm, size_t nargs)
{
	script_connection_t **conn = uc_fn_this("uwsd.connection");
	uc_value_t *set = uc_fn_arg(0);

	if (!conn)
		conn = uc_fn_this("uwsd.request");

	if (!conn || !*conn)
		return NULL;

	if (nargs) {
		ucv_get(set);
		ucv_put((*conn)->data);
		(*conn)->data = set;

		return ucv_get(set);
	}

	return ucv_get((*conn)->data);
}

static uc_value_t *
uc_script_send(uc_vm_t *vm, size_t nargs)
{
	script_connection_t **conn = uc_fn_this("uwsd.connection");
	uc_value_t *data = uc_fn_arg(0);

	if (!conn || !*conn)
		return NULL;

	if (ucv_type(data) != UC_STRING)
		return NULL;

	return ucv_boolean_new(ws_frame_send(*conn, OPCODE_TEXT,
		ucv_string_get(data), ucv_string_length(data)));
}

static uc_value_t *
uc_script_close(uc_vm_t *vm, size_t nargs)
{
	script_connection_t *connp, **conn = uc_fn_this("uwsd.connection");
	uc_value_t *rcode = uc_fn_arg(0);
	uc_value_t *rmsg = uc_fn_arg(1);

	if (!conn || !*conn)
		return NULL;

	if (ucv_type(rcode) != UC_INTEGER || ucv_type(rmsg) != UC_STRING)
		return NULL;

	connp = *conn;
	*conn = NULL;

	ws_error_send(connp, false, ucv_uint64_get(rcode), "%s", ucv_string_get(rmsg));

	return ucv_boolean_new(true);
}

static const uc_function_list_t conn_fns[] = {
	{ "accept",	uc_script_accept },
	{ "data",	uc_script_data },
	{ "send",	uc_script_send },
	{ "close",	uc_script_close }
};

static void
close_conn(void *ud)
{
}


static uc_value_t *
uc_script_get_common(uc_vm_t *vm, size_t nargs, const char *field)
{
	script_connection_t **conn = uc_fn_this("uwsd.request");

	if (!conn || !*conn)
		return NULL;

	return ucv_get(ucv_object_get((*conn)->conn, field, NULL));
}

static uc_value_t *
uc_script_http_version(uc_vm_t *vm, size_t nargs)
{
	return uc_script_get_common(vm, nargs, "http_version");
}

static uc_value_t *
uc_script_request_method(uc_vm_t *vm, size_t nargs)
{
	return uc_script_get_common(vm, nargs, "request_method");
}

static uc_value_t *
uc_script_request_uri(uc_vm_t *vm, size_t nargs)
{
	return uc_script_get_common(vm, nargs, "request_uri");
}

static uc_value_t *
uc_script_request_header(uc_vm_t *vm, size_t nargs)
{
	script_connection_t **conn = uc_fn_this("uwsd.request");
	uc_value_t *name = uc_fn_arg(0);

	if (!conn || !*conn)
		return NULL;

	if (name && ucv_type(name) != UC_STRING)
		return NULL;

	if (!name)
		return ucv_get((*conn)->hdr);

	ucv_object_foreach((*conn)->hdr, hname, hvalue)
		if (!strcasecmp(hname, ucv_string_get(name)))
			return ucv_get(hvalue);

	return NULL;
}

static uc_value_t *
uc_script_reply(uc_vm_t *vm, size_t nargs)
{
	script_connection_t **conn = uc_fn_this("uwsd.request");
	uc_stringbuf_t *buf = xprintbuf_new();
	uc_value_t *header = uc_fn_arg(0);
	uc_value_t *body = uc_fn_arg(1);
	ssize_t wlen, n, lenoff = 0;
	uint16_t status = 200;
	char *reason = "OK";
	uc_value_t *v;
	bool found;
	char *p;

	if (!conn || !*conn)
		return NULL;

	v = ucv_object_get(header, "Status", NULL);

	if (ucv_type(v) == UC_STRING) {
		p = ucv_string_get(v);

		if (isdigit(p[0]) && isdigit(p[1]) && isdigit(p[2]) && isspace(p[3])) {
			status = (p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0');

			for (reason = p + 3; isspace(*reason); reason++)
				;
		}
	}

	sprintbuf(buf, "HTTP/%.1f %03hu %s\r\n",
		ucv_double_get(ucv_object_get((*conn)->conn, "http_version", NULL)),
		status, reason);

	ucv_object_foreach(header, name, value) {
		if (!strcmp(name, "Status"))
			continue;

		printbuf_memappend(buf, name, strlen(name));
		printbuf_strappend(buf, ": ");
		ucv_to_stringbuf(vm, buf, value, false);
		printbuf_strappend(buf, "\r\n");
	}

	ucv_object_get(header, "Content-Type", &found);

	if (!found)
		printbuf_strappend(buf, "Content-Type: application/octet-stream\r\n");

	ucv_object_get(header, "Content-Length", &found);

	if (!found) {
		lenoff = printbuf_length(buf) + strlen("Content-Length: ");
		printbuf_strappend(buf, "Content-Length: 00000000000000000000\r\n");
	}

	printbuf_strappend(buf, "\r\n");
	n = printbuf_length(buf);

	if (body)
		ucv_to_stringbuf(vm, buf, body, false);

	if (lenoff) {
		snprintf(buf->buf + lenoff, 21, "%-20zd", printbuf_length(buf) - n);
		buf->buf[lenoff + 20] = '\r';
	}

	for (p = buf->buf, n = printbuf_length(buf); n > 0; ) {
		wlen = write((*conn)->ufd.fd, p, ssize_t_min(n, 8192));

		if (wlen == -1) {
			if (errno == EINTR)
				continue;

			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "write error: %s", strerror(errno));
			break;
		}

		p += wlen;
		n -= wlen;
	}

	close((*conn)->ufd.fd);
	printbuf_free(buf);

	*conn = NULL;

	return ucv_boolean_new(!n);
}

static const uc_function_list_t req_fns[] = {
	{ "version", uc_script_http_version },
	{ "method",  uc_script_request_method },
	{ "uri",     uc_script_request_uri },
	{ "header",  uc_script_request_header },
	{ "data",    uc_script_data },
	{ "reply",   uc_script_reply }
};

static void
close_req(void *ud)
{
}


/* -- Scripting host implementation -------------------- */

static void
handle_exception(uc_vm_t *vm, uc_exception_t *ex)
{
	uc_value_t *ctx = ucv_object_get(ucv_array_get(ex->stacktrace, 0), "context", NULL);
	const char *extype;

	switch (ex->type) {
	case EXCEPTION_SYNTAX:
		extype = "Syntax error";
		break;

	case EXCEPTION_RUNTIME:
		extype = "Runtime error";
		break;

	case EXCEPTION_TYPE:
		extype = "Type error";
		break;

	case EXCEPTION_REFERENCE:
		extype = "Reference error";
		break;

	default:
		extype = "Exception";
		break;
	}

	fprintf(stderr,
		"Exception while executing handler script: %s: %s\n%s",
		extype, ex->message, ucv_string_get(ctx));
}

static bool script_context_start(uwsd_action_t *);

static void
handle_restart(struct uloop_timeout *utm)
{
	uwsd_action_t *action = container_of(utm, uwsd_action_t, data.script.timeout);

	uwsd_log_warn(NULL, "Restarting script worker '%s'", action->data.script.path);

	if (!script_context_start(action)) {
		uwsd_log_err(NULL, "Failed to start script worker '%s', scheduling restart",
			action->data.script.path);

		uloop_timeout_set(&action->data.script.timeout, 1000);
	}
}

static void
handle_termination(struct uloop_process *proc, int exitcode)
{
	uwsd_action_t *action = container_of(proc, uwsd_action_t, data.script.proc);

	uwsd_log_err(NULL, "Script worker '%s' terminated with code %d",
		action->data.script.path, exitcode);

	action->data.script.timeout.cb = handle_restart;
	uloop_timeout_set(&action->data.script.timeout, 1000);
}

static bool
handle_tlv(script_connection_t *conn, uint16_t type, uint16_t len, uint8_t *data)
{
	struct sockaddr *sa = (struct sockaddr *)data;
	char addr[INET6_ADDRSTRLEN];
	uwsd_http_method_t method;
	uint16_t u16;
	size_t nlen;

	switch (type) {
	case UWSD_SCRIPT_DATA_PEER_ADDR:
		if (sa->sa_family == AF_INET) {
			inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, addr, sizeof(addr));

			ucv_object_add(conn->req, "peer_port",
				ucv_uint64_new(ntohs(((struct sockaddr_in *)sa)->sin_port)));
		}
		else {
			inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, addr, sizeof(addr));

			ucv_object_add(conn->req, "peer_port",
				ucv_uint64_new(ntohs(((struct sockaddr_in6 *)sa)->sin6_port)));
		}

		ucv_object_add(conn->req, "peer_address",
			ucv_string_new(addr));

		break;

	case UWSD_SCRIPT_DATA_HTTP_VERSION:
		memcpy(&u16, data, sizeof(u16));
		ucv_object_add(conn->req, "http_version",
			ucv_double_new((double)(u16 >> 8) + ((double)(u16 & 0xff) / 10.0)));

		break;

	case UWSD_SCRIPT_DATA_HTTP_METHOD:
		memcpy(&method, data, sizeof(method));
		ucv_object_add(conn->req, "request_method",
			ucv_string_new(http_method_names[method]));

		break;

	case UWSD_SCRIPT_DATA_HTTP_URI:
		ucv_object_add(conn->req, "request_uri",
			ucv_string_new_length((char *)data, len));

		break;

	case UWSD_SCRIPT_DATA_HTTP_HEADER:
		if (!conn->hdr) {
			conn->hdr = ucv_object_new(&conn->ctx->vm);
			ucv_object_add(conn->req, "request_headers", conn->hdr);
		}

		nlen = strlen((char *)data) + 1;

		ucv_object_add(conn->hdr, (char *)data,
			ucv_string_new_length((char *)data + nlen, len - nlen));

		break;

	case UWSD_SCRIPT_DATA_HTTP_DATA:
	case UWSD_SCRIPT_DATA_HTTP_EOF:
		if (conn->state == STATE_HEAD) {
			if (!script_conn_http_request(conn))
				return false;

			conn->state = STATE_BODY;
		}

		if (!script_conn_http_body(conn, data, len))
			return false;

		if (type == UWSD_SCRIPT_DATA_HTTP_EOF) {
			script_conn_close(conn, 0, NULL);

			return false;
		}

		break;

	case UWSD_SCRIPT_DATA_WS_INIT:
		if (!script_conn_ws_handshake(conn, (char *)data))
			return false;

		conn->state = STATE_WS;
		break;

	case UWSD_SCRIPT_DATA_WS_FRAGMENT:
	case UWSD_SCRIPT_DATA_WS_FINAL:
		if (!script_conn_ws_data(conn, data, len, type == UWSD_SCRIPT_DATA_WS_FINAL))
			return false;

		break;

	case UWSD_SCRIPT_DATA_WS_EOF:
		memcpy(&u16, data, 2);
		script_conn_close(conn, ntohs(u16), (char *)data + 2);

		return false;
	}

	return true;
}

static void
handle_request(struct uloop_fd *ufd, unsigned int events)
{
	script_connection_t *conn = container_of(ufd, script_connection_t, ufd);
	ssize_t rlen, i, rem;
	uint8_t buf[8192];

	while (true) {
		rlen = recv(ufd->fd, buf, sizeof(buf), 0);

		if (rlen == -1) {
			if (errno == EINTR)
				continue;

			return uwsd_log_err(NULL, "Internal receive error: %m");
		}

		break;
	}

	for (i = 0; i < rlen; ) {
		switch (conn->buf.state) {
		case PARSE_TYPE1:
			conn->buf.type = (uint16_t)buf[i++] << 8;
			conn->buf.state = PARSE_TYPE2;
			break;

		case PARSE_TYPE2:
			conn->buf.type |= (uint16_t)buf[i++];
			conn->buf.state = PARSE_LEN1;
			break;

		case PARSE_LEN1:
			conn->buf.len = (uint16_t)buf[i++] << 8;
			conn->buf.state = PARSE_LEN2;
			break;

		case PARSE_LEN2:
			conn->buf.len |= (uint16_t)buf[i++];
			assert(conn->buf.len <= sizeof(conn->buf.data));

			// complete payload already in buffer
			if (i + conn->buf.len <= rlen) {
				if (!handle_tlv(conn, conn->buf.type, conn->buf.len, buf + i))
					return;

				i += conn->buf.len;
				conn->buf.state = PARSE_TYPE1;
			}

			// otherwise entire remainder is data, buffer it and end loop
			else {
				memcpy(conn->buf.data, buf + i, rlen - i);
				conn->buf.datalen = rlen - i;
				conn->buf.state = PARSE_DATA;
				i = rlen;
			}

			break;

		case PARSE_DATA:
			rem = ssize_t_min(conn->buf.len - conn->buf.datalen, rlen - i);
			memcpy(conn->buf.data + conn->buf.datalen, buf + i, rem);
			conn->buf.datalen += rem;
			i += rem;

			if (conn->buf.datalen == conn->buf.len) {
				if (!handle_tlv(conn, conn->buf.type, conn->buf.len, conn->buf.data))
					return;

				conn->buf.state = PARSE_TYPE1;
			}

			break;
		}
	}
}

static void
handle_client(struct uloop_fd *ufd, unsigned int events)
{
	script_context_t *ctx = container_of(ufd, script_context_t, ufd);
	script_connection_t *conn;
	int fd;

	fd = accept(ufd->fd, NULL, NULL);

	if (fd == -1)
		return uwsd_log_err(NULL, "Unable to accept client connection: %m");

	conn = xalloc(sizeof(*conn));
	conn->ctx = ctx;
	conn->req = ucv_object_new(&ctx->vm);
	conn->ufd.fd = fd;
	conn->ufd.cb = handle_request;

	uloop_fd_add(&conn->ufd, ULOOP_READ | ULOOP_BLOCKING);
	list_add_tail(&conn->list, &requests);
}

static int
script_context_run(const char *sockpath, const char *scriptpath)
{
	script_context_t ctx = { 0 };
	uc_source_t *source;
	uc_program_t *prog;
	uc_value_t *result;
	char *script, *err;
	int len, rc;

	len = xasprintf(&script,
		"{%%\n"
		"import * as cb from '%s';\n"
		"return [ cb.onConnect, cb.onData, cb.onRequest, cb.onBody, cb.onClose ];\n",
		scriptpath);

	source = uc_source_new_buffer("bootstrap script", script, len);
	prog = uc_compile(NULL, source, &err);
	uc_source_put(source);

	if (!prog) {
		uwsd_log_err(NULL, "Failed to compile handler script: %s", err);

		return false;
	}

	uc_vm_init(&ctx.vm, NULL);
	uc_vm_exception_handler_set(&ctx.vm, handle_exception);
	uc_stdlib_load(uc_vm_scope_get(&ctx.vm));

	rc = uc_vm_execute(&ctx.vm, prog, &result);

	uc_program_put(prog);

	switch (rc) {
	case STATUS_OK:
		uc_type_declare(&ctx.vm, "uwsd.connection", conn_fns, close_conn);
		uc_type_declare(&ctx.vm, "uwsd.request", req_fns, close_req);

		ctx.onConnect = ucv_get(ucv_array_get(result, 0));
		ctx.onData    = ucv_get(ucv_array_get(result, 1));
		ctx.onRequest = ucv_get(ucv_array_get(result, 2));
		ctx.onBody    = ucv_get(ucv_array_get(result, 3));
		ctx.onClose   = ucv_get(ucv_array_get(result, 4));

		ucv_put(result);

		break;

	case STATUS_EXIT:
		rc = (int)ucv_uint64_get(result);
		uwsd_log_err(NULL, "Handler script exited with code %d", rc);
		ucv_put(result);

		return rc;

	default:
		return -1;
	}

	ctx.ufd.cb = handle_client;
	ctx.ufd.fd = server_socket_setup(sockpath);

	uloop_init();
	uloop_fd_add(&ctx.ufd, ULOOP_READ);
	uloop_run();

	return 0;
}

static bool
script_context_start(uwsd_action_t *action)
{
	char ibuf[32];
	pid_t pid;
	int fd;

	pid = fork();

	switch (pid) {
	case -1:
		uwsd_log_err(NULL, "Unable to fork script process '%s': %m",
			action->data.script.path);

		return false;

	case 0:
		fd = open("/dev/null", O_RDWR);

		if (fd != -1) {
			dup2(fd, 0);
			dup2(fd, 1);

			if (fd > 2)
				close(fd);
		}

		uloop_done();

		setenv("UWSD_WORKER_SOCKET",
			action->data.script.sun.sun_path + !action->data.script.sun.sun_path[0], 1);

		setenv("UWSD_WORKER_SCRIPT",
			action->data.script.path, 1);

		snprintf(ibuf, sizeof(ibuf), "%u", (unsigned int)uwsd_logging_priority);
		setenv("UWSD_LOG_PRIORITY", ibuf, 1);

		snprintf(ibuf, sizeof(ibuf), "%u", (unsigned int)uwsd_logging_channels);
		setenv("UWSD_LOG_CHANNELS", ibuf, 1);

		execl(getenv("UWSD_EXECUTABLE"), getenv("UWSD_EXECUTABLE"), NULL);

		uwsd_log_err(NULL, "Failed to execute '%s': %m", getenv("UWSD_EXECUTABLE"));
		exit(-1);
		break;

	default:
		action->data.script.proc.pid = pid;
		action->data.script.proc.cb = handle_termination;
		uloop_process_add(&action->data.script.proc);
		break;
	}

	return true;
}


/* -- External API functions---------------------------- */

__hidden bool
uwsd_script_init(uwsd_action_t *action, const char *path)
{
	struct sockaddr_un *sun = &action->data.script.sun;

	sun->sun_family = AF_UNIX;
	action->data.script.path = xstrdup(path);

#ifdef __linux__
	snprintf(sun->sun_path, sizeof(sun->sun_path), "%c/uwsd/%u/%zx",
		0,
		(unsigned int)getpid(),
		(size_t)(uintptr_t)action);
#else
	snprintf(sun->sun_path, sizeof(sun->sun_path), "/tmp/uwsd.%u.%zx.sock",
		(unsigned int)getpid(),
		(size_t)(uintptr_t)action);
#endif

	return script_context_start(action);
}


#define add_tlv(_type, _len, _data)   \
	do {                              \
		tlv[i].type = _type;          \
		tlv[i].len = _len;            \
		tlv[i].data = (void *)_data;  \
		i++;                          \
	} while(0)

__hidden bool
uwsd_script_connect(uwsd_client_context_t *cl, const char *acceptkey)
{
	struct { uint16_t type; uint16_t len; void *data; } tlv[5 + cl->http_num_headers];
	size_t i = 0, j;

	add_tlv(UWSD_SCRIPT_DATA_PEER_ADDR, sizeof(cl->sa.in6), &cl->sa.in6);
	add_tlv(UWSD_SCRIPT_DATA_HTTP_VERSION, sizeof(cl->http_version), &cl->http_version);
	add_tlv(UWSD_SCRIPT_DATA_HTTP_METHOD, sizeof(cl->request_method), &cl->request_method);
	add_tlv(UWSD_SCRIPT_DATA_HTTP_URI, strlen(cl->request_uri), cl->request_uri);

	for (j = 0; j < cl->http_num_headers; j++)
		add_tlv(UWSD_SCRIPT_DATA_HTTP_HEADER, 0, &cl->http_headers[j]);

	add_tlv(UWSD_SCRIPT_DATA_WS_INIT, strlen(acceptkey) + 1, acceptkey);

	for (j = 0; j < i; j++) {
		if (tlv[j].type == UWSD_SCRIPT_DATA_HTTP_HEADER) {
			if (!header_tlv_send(cl->upstream.ufd.fd, tlv[j].data))
				return false;
		}
		else {
			if (!tlv_send(cl->upstream.ufd.fd, tlv[j].type, tlv[j].len, tlv[j].data))
				return false;
		}
	}

	return true;
}


__hidden bool
uwsd_script_send(uwsd_client_context_t *cl, const void *data, size_t len)
{
	uint16_t type;

	assert(len <= sizeof(((script_connection_t *)NULL)->buf.data));

	cl->ws.len -= len;

	if (len > 0)
		type = cl->ws.len ? UWSD_SCRIPT_DATA_WS_FRAGMENT : UWSD_SCRIPT_DATA_WS_FINAL;
	else
		type = UWSD_SCRIPT_DATA_WS_EOF;

	return tlv_send(cl->upstream.ufd.fd, type, len, data);
}

__hidden void
uwsd_script_close(uwsd_client_context_t *cl)
{
	char statusbuf[125];
	int statuslen = 2;

	if (cl->protocol == UWSD_PROTOCOL_HTTP) {
		tlv_send(cl->upstream.ufd.fd, UWSD_SCRIPT_DATA_HTTP_EOF, 0, "");
	}
	else {
		statuslen = snprintf(statusbuf, sizeof(statusbuf), "%c%c%s",
			(cl->ws.error.code ? cl->ws.error.code : 1000) / 256,
			(cl->ws.error.code ? cl->ws.error.code : 1000) % 256,
			cl->ws.error.msg ? cl->ws.error.msg : "");

		tlv_send(cl->upstream.ufd.fd, UWSD_SCRIPT_DATA_WS_EOF, statuslen + 1, statusbuf);
	}
}

__hidden void
uwsd_script_free(uwsd_action_t *action)
{
	uloop_timeout_cancel(&action->data.script.timeout);
	uloop_process_delete(&action->data.script.proc);

	kill(action->data.script.proc.pid, SIGTERM);
	waitpid(action->data.script.proc.pid, NULL, 0);

	free(action->data.script.path);
}

__hidden bool
uwsd_script_request(uwsd_client_context_t *cl, int downstream)
{
	struct { uint16_t type; uint16_t len; void *data; } tlv[4 + cl->http_num_headers];
	size_t i = 0, j;

	add_tlv(UWSD_SCRIPT_DATA_PEER_ADDR, sizeof(cl->sa.in6), &cl->sa.in6);
	add_tlv(UWSD_SCRIPT_DATA_HTTP_VERSION, sizeof(cl->http_version), &cl->http_version);
	add_tlv(UWSD_SCRIPT_DATA_HTTP_METHOD, sizeof(cl->request_method), &cl->request_method);
	add_tlv(UWSD_SCRIPT_DATA_HTTP_URI, strlen(cl->request_uri), cl->request_uri);

	for (j = 0; j < cl->http_num_headers; j++)
		add_tlv(UWSD_SCRIPT_DATA_HTTP_HEADER, 0, &cl->http_headers[j]);

	for (j = 0; j < i; j++) {
		if (tlv[j].type == UWSD_SCRIPT_DATA_HTTP_HEADER) {
			if (!header_tlv_send(cl->upstream.ufd.fd, tlv[j].data))
				return false;
		}
		else {
			if (!tlv_send(cl->upstream.ufd.fd, tlv[j].type, tlv[j].len, tlv[j].data))
				return false;
		}
	}

	return true;
}

__hidden bool
uwsd_script_bodydata(uwsd_client_context_t *cl, const void *data, size_t len)
{
	uint16_t type = len ? UWSD_SCRIPT_DATA_HTTP_DATA : UWSD_SCRIPT_DATA_HTTP_EOF;

	assert(len <= sizeof(((script_connection_t *)NULL)->buf.data));

	return tlv_send(cl->upstream.ufd.fd, type, len, data);
}

__hidden int
uwsd_script_worker_main(const char *sockpath, const char *scriptpath)
{
	uwsd_logging_priority = atoi(getenv("UWSD_LOG_PRIORITY") ?: "0");
	uwsd_logging_channels = atoi(getenv("UWSD_LOG_CHANNELS") ?: "0");

	return script_context_run(sockpath, scriptpath);
}
