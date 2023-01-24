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
#include <ucode/util.h>

#include "state.h"
#include "script.h"
#include "ws.h"
#include "client.h"
#include "listen.h"
#include "log.h"
#include "teeny-sha1.h"


static LIST_HEAD(requests);

typedef enum {
	UWSD_SCRIPT_DATA_PEER_ADDR,
	UWSD_SCRIPT_DATA_LOCAL_ADDR,
	UWSD_SCRIPT_DATA_SSL_CIPHER,
	UWSD_SCRIPT_DATA_X509_PEER_ISSUER,
	UWSD_SCRIPT_DATA_X509_PEER_SUBJECT,
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
	uwsd_protocol_t proto;
	struct {
		script_request_parse_state_t state;
		uint16_t type;
		uint16_t len;
		uint16_t datalen;
		uint8_t data[16384];
	} buf;
	uc_value_t *req, *hdr, *conn, *data, *subproto;
	struct {
		uwsd_ws_msg_format_t format;
		union {
			uc_stringbuf_t *buffer;
			struct {
				json_tokener *tok;
				json_object *obj;
			} json;
		} data;
		size_t limit, size;
	} reassembly;
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
set_cloexec(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFD);

	if (flags == -1)
		return false;

	return (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0);
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

	if (!set_cloexec(sock))
		uwsd_log_warn(NULL, "Failed to apply FD_CLOEXEC to descriptor: %m");

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
		uwsd_log_warn(NULL, "Unable to set SO_REUSEADDR: %m");

#ifdef __linux__
	strncpy(sun.sun_path + 1, sockpath, sizeof(sun.sun_path) - 1);
#else
	strncpy(sun.sun_path, sockpath, sizeof(sun.sun_path));
#endif

	if (bind(sock, (struct sockaddr *)&sun, sizeof(sun)) == -1) {
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
http_reply_send(script_connection_t *conn, uint16_t code, const char *reason, const char *msg, ...)
{
	va_list ap;
	size_t len;

	va_start(ap, msg);
	len = uwsd_http_reply_buffer_varg((char *)conn->buf.data, sizeof(conn->buf.data),
		ucv_double_get(ucv_object_get(conn->req, "http_version", NULL)),
		code, reason, msg, ap);
	va_end(ap);

	send(conn->ufd.fd, conn->buf.data, len, 0);
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

	conn->proto = UWSD_PROTOCOL_WS;
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

			http_reply_send(conn,
				500, "Internal Server Error",
				"Exception in onConnect(): %s\n%s",
					vm->exception.message,
					ucv_string_get(ctx),
				"Connection", "close",
				UWSD_HTTP_REPLY_EOH
			);

			script_conn_close(conn, 0, NULL);

			return false;
		}

		ucv_put(uc_vm_stack_pop(vm));

		if (!conn->subproto) {
			http_reply_send(conn,
				500, "Internal Server Error",
				"The onConnect() handler did not accept the connection\n",
				"Connection", "close",
				UWSD_HTTP_REPLY_EOH
			);

			script_conn_close(conn, 0, NULL);

			return false;
		}

		if (ucv_type(conn->subproto) != UC_STRING)
			ucv_clear(&conn->subproto);
	}

	http_reply_send(conn,
		101, "Switching Protocols",
		UWSD_HTTP_REPLY_EMPTY,
		"Upgrade", "WebSocket",
		"Connection", "Upgrade",
		"Sec-WebSocket-Accept", acceptkey,
		"Sec-WebSocket-Protocol", ucv_string_get(conn->subproto),
		UWSD_HTTP_REPLY_EOH
	);

	return true;
}

static void
script_conn_reset_reassembly(script_connection_t *conn)
{
	switch (conn->reassembly.format) {
	case UWSD_WS_MSG_FORMAT_JSON:
		if (conn->reassembly.data.json.tok)
			json_tokener_free(conn->reassembly.data.json.tok);

		if (conn->reassembly.data.json.obj)
			json_object_put(conn->reassembly.data.json.obj);

		conn->reassembly.data.json.tok = NULL;
		conn->reassembly.data.json.obj = NULL;
		break;

	case UWSD_WS_MSG_FORMAT_BUFFERED:
		if (conn->reassembly.data.buffer)
			printbuf_free(conn->reassembly.data.buffer);

		conn->reassembly.data.buffer = NULL;
		break;

	default:
		break;
	}

	conn->reassembly.size = 0;
}

static bool
script_conn_ws_data(script_connection_t *conn, const void *data, size_t len, bool final)
{
	uc_vm_t *vm = &conn->ctx->vm;
	enum json_tokener_error err;
	uc_exception_type_t ex;
	json_tokener *tok;
	uc_value_t *ctx;

	if (!conn->ctx->onData)
		return true;

	if (conn->reassembly.size + len < conn->reassembly.size /* overflow */ ||
	    (conn->reassembly.limit > 0 &&
	     conn->reassembly.size + len > conn->reassembly.limit))
	{
		ws_error_send(conn, true, STATUS_MESSAGE_TOO_BIG,
			"Message exceeds limit of %zu bytes", conn->reassembly.limit);

		return false;
	}

	switch (conn->reassembly.format) {
	case UWSD_WS_MSG_FORMAT_BUFFERED:
		if (!conn->reassembly.data.buffer)
			conn->reassembly.data.buffer = ucv_stringbuf_new();

		ucv_stringbuf_addstr(conn->reassembly.data.buffer, data, len);

		conn->reassembly.size += len;

		if (!final)
			return true;

		uc_vm_stack_push(vm, ucv_get(conn->ctx->onData));
		uc_vm_stack_push(vm, ucv_get(conn->conn));
		uc_vm_stack_push(vm, ucv_stringbuf_finish(conn->reassembly.data.buffer));

		ex = uc_vm_call(vm, false, 2);

		conn->reassembly.data.buffer = NULL;

		break;

	case UWSD_WS_MSG_FORMAT_JSON:
		tok = conn->reassembly.data.json.tok;

		if (!tok) {
			tok = xjs_new_tokener();
			conn->reassembly.data.json.tok = tok;
		}

		conn->reassembly.data.json.obj = json_tokener_parse_ex(tok, data, len);

		err = json_tokener_get_error(tok);

		if (final && err == json_tokener_continue)
			err = json_tokener_error_parse_eof;
		else if (final && err == json_tokener_success && json_tokener_get_parse_end(tok) < len)
			err = json_tokener_error_parse_unexpected;

		if (err != json_tokener_success) {
			ws_error_send(conn, true, STATUS_BAD_ENCODING,
				"JSON parse error: %s", json_tokener_error_desc(err));

			return false;
		}

		conn->reassembly.size += len;

		if (!final)
			return true;

		uc_vm_stack_push(vm, ucv_get(conn->ctx->onData));
		uc_vm_stack_push(vm, ucv_get(conn->conn));
		uc_vm_stack_push(vm, ucv_from_json(vm, conn->reassembly.data.json.obj));

		ex = uc_vm_call(vm, false, 2);

		break;

	default:
		uc_vm_stack_push(vm, ucv_get(conn->ctx->onData));
		uc_vm_stack_push(vm, ucv_get(conn->conn));
		uc_vm_stack_push(vm, ucv_string_new_length(data, len));
		uc_vm_stack_push(vm, ucv_boolean_new(final));

		ex = uc_vm_call(vm, false, 3);

		break;
	}

	script_conn_reset_reassembly(conn);

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
	ucv_clear(&conn->subproto);
	ucv_clear(&conn->conn);

	uloop_fd_delete(&conn->ufd);
	list_del(&conn->list);

	close(conn->ufd.fd);

	script_conn_reset_reassembly(conn);

	free(conn);
}

static bool
script_conn_http_request(script_connection_t *conn)
{
	uc_resource_type_t *conn_type;
	uc_vm_t *vm = &conn->ctx->vm;
	uc_exception_type_t ex;
	uc_value_t *ctx;

	conn_type = ucv_resource_type_lookup(vm, "uwsd.connection");
	assert(conn_type);

	ucv_set_constant(conn->req, true);
	ucv_set_constant(conn->hdr, true);

	conn->proto = UWSD_PROTOCOL_HTTP;
	conn->conn = uc_resource_new(conn_type, conn);

	if (conn->ctx->onRequest) {
		uc_vm_stack_push(vm, ucv_get(conn->ctx->onRequest));
		uc_vm_stack_push(vm, ucv_get(conn->conn));
		uc_vm_stack_push(vm, ucv_get(ucv_object_get(conn->req, "request_method", NULL)));
		uc_vm_stack_push(vm, ucv_get(ucv_object_get(conn->req, "request_uri", NULL)));

		ex = uc_vm_call(vm, false, 3);

		if (ex != EXCEPTION_NONE) {
			ctx = ucv_object_get(ucv_array_get(vm->exception.stacktrace, 0), "context", NULL);

			http_reply_send(conn,
				500, "Internal Server Error",
				"Exception in onRequest(): %s\n%s",
					vm->exception.message,
					ucv_string_get(ctx),
				"Connection", "close",
				UWSD_HTTP_REPLY_EOH
			);

			script_conn_close(conn, 0, NULL);

			return false;
		}

		ucv_put(uc_vm_stack_pop(vm));
	}
	else {
		http_reply_send(conn,
			501, "Not Implemented",
			"Backend script does not implement an onRequest() handler.\n",
			"Connection", "close",
			UWSD_HTTP_REPLY_EOH
		);

		script_conn_close(conn, 0, NULL);

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

		http_reply_send(conn,
			500, "Internal Server Error",
			"Exception in onBody(): %s\n%s",
				vm->exception.message,
				ucv_string_get(ctx),
			"Connection", "close",
			UWSD_HTTP_REPLY_EOH
		);

		script_conn_close(conn, 0, NULL);

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

	if (!conn || !*conn || (*conn)->proto != UWSD_PROTOCOL_WS)
		return NULL;

	if (proto && ucv_type(proto) != UC_STRING)
		return NULL;

	(*conn)->subproto = proto ? ucv_get(proto) : ucv_boolean_new(true);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_script_expect(uc_vm_t *vm, size_t nargs)
{
	script_connection_t **conn = uc_fn_this("uwsd.connection");
	uc_value_t *format = uc_fn_arg(0);
	uc_value_t *limit = uc_fn_arg(1);
	uwsd_ws_msg_format_t fmt;
	size_t lim;

	if (!conn || !*conn || (*conn)->proto != UWSD_PROTOCOL_WS)
		return NULL;

	if (ucv_type(format) != UC_STRING)
		return NULL;

	if (limit && ucv_type(limit) != UC_INTEGER)
		return NULL;

	if (!strcmp(ucv_string_get(format), "raw")) {
		fmt = UWSD_WS_MSG_FORMAT_RAW;
		lim = 0;
	}
	else if (!strcmp(ucv_string_get(format), "buffered")) {
		fmt = UWSD_WS_MSG_FORMAT_BUFFERED;
		lim = ucv_int64_get(limit);
	}
	else if (!strcmp(ucv_string_get(format), "json")) {
		fmt = UWSD_WS_MSG_FORMAT_JSON;
		lim = ucv_int64_get(limit);
	}
	else {
		return NULL;
	}

	script_conn_reset_reassembly(*conn);

	(*conn)->reassembly.format = fmt;
	(*conn)->reassembly.limit = lim;

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_script_data(uc_vm_t *vm, size_t nargs)
{
	script_connection_t **conn = uc_fn_this("uwsd.connection");
	uc_value_t *set = uc_fn_arg(0);

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
	ssize_t n, wlen;
	char *p;

	if (!conn || !*conn)
		return NULL;

	if (ucv_type(data) != UC_STRING)
		return NULL;

	p = ucv_string_get(data);
	n = ucv_string_length(data);

	if ((*conn)->proto == UWSD_PROTOCOL_WS) {
		if ((*conn)->state != STATE_WS)
			return NULL;

		if (!ws_frame_send(*conn, OPCODE_TEXT, p, n))
			return ucv_boolean_new(false);
	}
	else {
		while (n) {
			wlen = write((*conn)->ufd.fd, p, ssize_t_min(n, 16384));

			if (wlen == -1) {
				if (errno == EINTR)
					continue;

				uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "write error: %m");
				break;
			}

			p += wlen;
			n -= wlen;
		}
	}

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_script_close(uc_vm_t *vm, size_t nargs)
{
	script_connection_t *connp, **conn = uc_fn_this("uwsd.connection");
	uc_value_t *rcode = uc_fn_arg(0);
	uc_value_t *rmsg = uc_fn_arg(1);

	if (!conn || !*conn || (*conn)->proto != UWSD_PROTOCOL_WS)
		return NULL;

	if (ucv_type(rcode) != UC_INTEGER || ucv_type(rmsg) != UC_STRING)
		return NULL;

	connp = *conn;
	*conn = NULL;

	ws_error_send(connp, false, ucv_uint64_get(rcode), "%s", ucv_string_get(rmsg));

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_script_get_common(uc_vm_t *vm, size_t nargs, const char *field)
{
	script_connection_t **conn = uc_fn_this("uwsd.connection");

	if (!conn || !*conn)
		return NULL;

	return ucv_get(ucv_object_get((*conn)->req, field, NULL));
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
	script_connection_t **conn = uc_fn_this("uwsd.connection");
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
uc_script_request_info(uc_vm_t *vm, size_t nargs)
{
	script_connection_t **conn = uc_fn_this("uwsd.connection");
	uc_value_t *rv, *v;
	size_t i;

	const char *fields[] = {
		"local_address", "local_port",
		"peer_address", "peer_port",
		"ssl", "ssl_cipher", "x509_peer_issuer", "x509_peer_subject"
	};

	if (!conn || !*conn)
		return NULL;

	rv = ucv_object_new(vm);

	for (i = 0; i < ARRAY_SIZE(fields); i++) {
		v = ucv_object_get((*conn)->req, fields[i], NULL);

		if (v)
			ucv_object_add(rv, fields[i], ucv_get(v));
	}

	ucv_set_constant(rv, true);

	return rv;
}

static uc_value_t *
uc_script_reply(uc_vm_t *vm, size_t nargs)
{
	script_connection_t **conn = uc_fn_this("uwsd.connection");
	uc_stringbuf_t *buf = xprintbuf_new();
	uc_value_t *header = uc_fn_arg(0);
	uc_value_t *body = uc_fn_arg(1);
	ssize_t wlen, n, lenoff = 0;
	uint16_t status = 200;
	char *reason = "OK";
	uc_value_t *v;
	bool found;
	char *p;

	if (!conn || !*conn || (*conn)->proto != UWSD_PROTOCOL_HTTP)
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
		ucv_double_get(ucv_object_get((*conn)->req, "http_version", NULL)),
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
		wlen = write((*conn)->ufd.fd, p, ssize_t_min(n, 16384));

		if (wlen == -1) {
			if (errno == EINTR)
				continue;

			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "write error: %m");
			break;
		}

		p += wlen;
		n -= wlen;
	}

	printbuf_free(buf);

	*conn = NULL;

	return ucv_boolean_new(!n);
}

static const uc_function_list_t conn_fns[] = {
	{ "version", uc_script_http_version },
	{ "method",  uc_script_request_method },
	{ "uri",     uc_script_request_uri },
	{ "header",  uc_script_request_header },
	{ "info",    uc_script_request_info },
	{ "data",    uc_script_data },

	{ "reply",   uc_script_reply },
	{ "accept",  uc_script_accept },
	{ "expect",  uc_script_expect },
	{ "send",    uc_script_send },

	{ "close",   uc_script_close }
};

static void
close_conn(void *ud)
{
}


static uc_value_t *
uc_script_connections(uc_vm_t *vm, size_t nargs)
{
	script_connection_t *conn;
	uc_value_t *rv;

	rv = ucv_array_new(vm);

	list_for_each_entry(conn, &requests, list) {
		if (conn->conn)
			ucv_array_push(rv, ucv_get(conn->conn));
	}

	return rv;
}

static uc_value_t *
uc_script_sha1digest(uc_vm_t *vm, size_t nargs)
{
	uc_value_t *data = uc_fn_arg(0);
	char *p, digest[41];
	size_t len;

	if (ucv_type(data) == UC_STRING) {
		p = NULL;
		len = ucv_string_length(data);
	}
	else if (data) {
		p = ucv_to_string(vm, data);
		len = strlen(p);
	}
	else {
		p = NULL;
		len = 0;
	}

	sha1digest(NULL, digest,
		(uint8_t *)(len ? (p ? p : ucv_string_get(data)) : ""), len);

	free(p);

	return ucv_string_new(digest);
}

static uc_resource_type_t *
uc_script_acquire_file_resource(uc_vm_t *vm)
{
	uc_resource_type_t *restype;
	uc_cfn_ptr_t requirefn;

	restype = ucv_resource_type_lookup(vm, "fs.file");

	if (!restype) {
		requirefn = uc_stdlib_function("require");

		uc_vm_stack_push(vm, ucv_string_new("fs"));
		ucv_put(requirefn(vm, 1));

		restype = ucv_resource_type_lookup(vm, "fs.file");
	}

	return restype;
}

typedef struct {
	uc_value_t *ifp, *ofp;
	pid_t pid;
} script_spawn_t;

static uc_value_t *
uc_script_spawn_stdin(uc_vm_t *vm, size_t nargs)
{
	script_spawn_t **spawn = uc_fn_this("uwsd.spawn");

	return ucv_get((*spawn)->ifp);
}

static uc_value_t *
uc_script_spawn_stdout(uc_vm_t *vm, size_t nargs)
{
	script_spawn_t **spawn = uc_fn_this("uwsd.spawn");

	return ucv_get((*spawn)->ofp);
}

static void
xclose(int fd)
{
	if (fd > 2)
		close(fd);
}

static void
close_spawn(void *ud);

static uc_value_t *
uc_script_spawn_close(uc_vm_t *vm, size_t nargs)
{
	script_spawn_t **spawn = uc_fn_this("uwsd.spawn");
	pid_t pid;
	int rc;

	if (!spawn || !*spawn)
		return NULL;

	pid = (*spawn)->pid;
	(*spawn)->pid = -1;

	close_spawn(*spawn);

	*spawn = NULL;

	if (waitpid(pid, &rc, 0) == -1) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Unable to waitpid: %m");

		return NULL;
	}

	if (WIFEXITED(rc))
		return ucv_int64_new(WEXITSTATUS(rc));

	if (WIFSIGNALED(rc))
		return ucv_int64_new(-WTERMSIG(rc));

	return ucv_int64_new(0);
}

static void
close_spawn(void *ud)
{
	script_spawn_t *spawn = ud;
	FILE **ifp, **ofp;

	if (!spawn)
		return;

	ifp = (FILE **)ucv_resource_dataptr(spawn->ifp, "fs.file");
	ofp = (FILE **)ucv_resource_dataptr(spawn->ofp, "fs.file");

	if (ifp && *ifp) {
		fclose(*ifp);
		*ifp = NULL;
	}

	if (ofp && *ofp) {
		fclose(*ofp);
		*ofp = NULL;
	}

	if (spawn->pid != -1)
		waitpid(spawn->pid, NULL, 0);

	free(spawn);
}

static const uc_function_list_t spawn_fns[] = {
	{ "stdin",	uc_script_spawn_stdin },
	{ "stdout",	uc_script_spawn_stdout },
	{ "close",	uc_script_spawn_close },
};

static void __attribute__((noreturn))
uc_script_spawn_command(uc_vm_t *vm, uc_value_t *cmd, uc_value_t *arg, uc_value_t *env)
{
	char *envp[ucv_object_length(env) + 2];
	char *argv[ucv_array_length(arg) + 1];
	uc_stringbuf_t *buf;
	uc_value_t *e;
	size_t i = 0;

	xasprintf(&envp[i++], "PATH=%s", getenv("PATH") ?: "");

	ucv_object_foreach(env, k, v) {
		if (v) {
			buf = xprintbuf_new();

			sprintbuf(buf, "%s=", k);
			ucv_to_stringbuf(vm, buf, v, false);

			envp[i++] = buf->buf;

			free(buf);
		}
	}

	envp[i] = NULL;

	switch (ucv_type(cmd)) {
	case UC_STRING:
		for (i = 0; i < ucv_array_length(arg); i++) {
			e = ucv_array_get(arg, i);

			if (ucv_type(e) == UC_STRING)
				argv[i] = ucv_string_get(e);
			else
				argv[i] = ucv_to_string(vm, e);
		}

		argv[i] = NULL;

		execvpe(ucv_string_get(cmd), argv, envp);
		exit(-1);

		break;

	case UC_CLOSURE:
	case UC_CFUNCTION:
		clearenv();

		for (i = 0; envp[i]; i++)
			putenv(envp[i]);

		uc_vm_stack_push(vm, cmd);

		for (i = 0; i < ucv_array_length(arg); i++)
			uc_vm_stack_push(vm, ucv_array_get(arg, i));

		switch (uc_vm_call(vm, false, i)) {
		case EXCEPTION_NONE:
			exit(ucv_int64_get(uc_vm_stack_pop(vm)));
			break;

		case EXCEPTION_EXIT:
			exit(vm->arg.s32);
			break;

		default:
			exit(-1);
			break;
		}

		break;

	default:
		exit(-1);
		break;
	}
}

static uc_value_t *
uc_script_spawn(uc_vm_t *vm, size_t nargs)
{
	uc_resource_type_t *filetype = uc_script_acquire_file_resource(vm);
	script_context_t *ctx = container_of(vm, script_context_t, vm);
	script_connection_t *conn, *tmp;
	uc_value_t *cmd = uc_fn_arg(0);
	uc_value_t *arg = uc_fn_arg(1);
	uc_value_t *env = uc_fn_arg(2);
	script_spawn_t *spawn;
	int pfds[2][2];
	pid_t pid;
	FILE *fp;

	if (!filetype)
		return NULL;

	if (!ucv_is_callable(cmd) && ucv_type(cmd) != UC_STRING) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Command value is neither function nor string");

		return NULL;
	}

	if (arg && ucv_type(arg) != UC_ARRAY) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Argument vector is not an array");

		return NULL;
	}

	if (env && ucv_type(env) != UC_OBJECT) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Environment value is not an object");

		return NULL;
	}

	if (pipe(pfds[0]) == -1) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Unable to spawn pipe: %m");

		return NULL;
	}

	if (pipe(pfds[1]) == -1) {
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Unable to spawn pipe: %m");

		xclose(pfds[0][0]);
		xclose(pfds[0][1]);

		return NULL;
	}

	pid = fork();

	switch (pid) {
	case -1:
		uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Unable to fork: %m");

		xclose(pfds[0][0]);
		xclose(pfds[0][1]);
		xclose(pfds[1][0]);
		xclose(pfds[1][1]);

		return NULL;

	case 0:
		dup2(pfds[0][0], 0);
		dup2(pfds[1][1], 1);

		xclose(pfds[0][0]);
		xclose(pfds[0][1]);
		xclose(pfds[1][0]);
		xclose(pfds[1][1]);

		uloop_done();

		list_for_each_entry_safe(conn, tmp, &requests, list) {
			list_del(&conn->list);
			close(conn->ufd.fd);
		}

		close(ctx->ufd.fd);

		uc_script_spawn_command(vm, cmd, arg, env);
		break;

	default:
		xclose(pfds[0][0]);
		xclose(pfds[1][1]);

		spawn = xalloc(sizeof(*spawn));
		spawn->pid = pid;

		/* setup stdin descriptor */
		fp = fdopen(pfds[0][1], "w");

		if (!fp) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Unable to fdopen(): %m");

			xclose(pfds[0][1]);
			xclose(pfds[1][0]);

			free(spawn);

			return NULL;
		}

		spawn->ifp = uc_resource_new(filetype, fp);

		/* setup stdout descriptor */
		fp = fdopen(pfds[1][0], "r");

		if (!fp) {
			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "Unable to fdopen(): %m");

			xclose(pfds[1][0]);

			ucv_put(spawn->ifp);
			free(spawn);

			return NULL;
		}

		spawn->ofp = uc_resource_new(filetype, fp);

		return uc_resource_new(ucv_resource_type_lookup(vm, "uwsd.spawn"), spawn);
	}
}

static const uc_function_list_t global_fns[] = {
	{ "connections", uc_script_connections },
	{ "sha1digest",  uc_script_sha1digest },
	{ "spawn",       uc_script_spawn },
};


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

	fprintf(stderr, "Restarting script worker '%s'\n", action->data.script.path);

	if (!script_context_start(action)) {
		fprintf(stderr, "Failed to start script worker '%s', scheduling restart\n",
			action->data.script.path);

		uloop_timeout_set(&action->data.script.timeout, 1000);
	}
}

static void
handle_termination(struct uloop_process *proc, int exitcode)
{
	uwsd_action_t *action = container_of(proc, uwsd_action_t, data.script.proc);

	fprintf(stderr, "Script worker '%s' terminated with code %d\n",
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
	case UWSD_SCRIPT_DATA_LOCAL_ADDR:
		if (sa->sa_family == AF_INET) {
			u16 = ntohs(((struct sockaddr_in *)sa)->sin_port);
			inet_ntop(AF_INET, &((struct sockaddr_in *)sa)->sin_addr, addr, sizeof(addr));
		}
		else {
			u16 = ntohs(((struct sockaddr_in6 *)sa)->sin6_port);

			if (IN6_IS_ADDR_V4MAPPED(&((struct sockaddr_in6 *)sa)->sin6_addr))
				inet_ntop(AF_INET, &((struct sockaddr_in6 *)sa)->sin6_addr.s6_addr[12], addr, sizeof(addr));
			else
				inet_ntop(AF_INET6, &((struct sockaddr_in6 *)sa)->sin6_addr, addr, sizeof(addr));
		}

		if (type == UWSD_SCRIPT_DATA_LOCAL_ADDR) {
			ucv_object_add(conn->req, "local_address", ucv_string_new(addr));
			ucv_object_add(conn->req, "local_port", ucv_uint64_new(u16));
		}
		else {
			ucv_object_add(conn->req, "peer_address", ucv_string_new(addr));
			ucv_object_add(conn->req, "peer_port", ucv_uint64_new(u16));
		}

		break;

	case UWSD_SCRIPT_DATA_SSL_CIPHER:
		ucv_object_add(conn->req, "ssl", ucv_boolean_new(true));
		ucv_object_add(conn->req, "ssl_cipher",
			ucv_string_new_length((char *)data, len));

		break;

	case UWSD_SCRIPT_DATA_X509_PEER_ISSUER:
		ucv_object_add(conn->req, "x509_peer_issuer",
			ucv_string_new_length((char *)data, len));

		break;

	case UWSD_SCRIPT_DATA_X509_PEER_SUBJECT:
		ucv_object_add(conn->req, "x509_peer_subject",
			ucv_string_new_length((char *)data, len));

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
			ucv_string_new_length((char *)data + nlen, len - nlen - 1));

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
	uint8_t buf[16384];

	while (true) {
		rlen = recv(ufd->fd, buf, sizeof(buf), 0);

		if (rlen == -1) {
			if (errno == EINTR)
				continue;

			fprintf(stderr, "Internal receive error: %m\n");

			return;
		}

		if (rlen == 0) {
			fprintf(stderr, "Backend connection closed by peer\n");
			script_conn_close(conn, 0, NULL);

			return;
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
	char *s;
	int fd;

	fd = accept(ufd->fd, NULL, NULL);

	if (fd == -1) {
		fprintf(stderr, "Unable to accept client connection: %m\n");

		return;
	}

	if (!set_cloexec(fd))
		fprintf(stderr, "Failed to apply FD_CLOEXEC to descriptor: %m\n");

	conn = xalloc(sizeof(*conn));
	conn->ctx = ctx;
	conn->req = ucv_object_new(&ctx->vm);
	conn->ufd.fd = fd;
	conn->ufd.cb = handle_request;

	if ((s = getenv("UWSD_WS_MSG_FORMAT")) != NULL)
		conn->reassembly.format = strtoul(s, NULL, 10);

	if ((s = getenv("UWSD_WS_MSG_LIMIT")) != NULL)
		conn->reassembly.limit = strtoul(s, NULL, 10);

	uloop_fd_add(&conn->ufd, ULOOP_READ | ULOOP_BLOCKING);
	list_add_tail(&conn->list, &requests);
}

static void
handle_stdio(uwsd_action_t *action, int fd, uwsd_log_priority_t prio)
{
	char buf[256] = { 0 }, *p, *nl;
	int len;

	if (read(fd, buf, sizeof(buf) - 1) <= 0)
		return;

	p = buf;
	nl = strchr(buf, '\n');

	while (true) {
		len = nl ? (size_t)(nl - p) : strlen(p);

		if (len)
			uwsd_log(prio, UWSD_LOG_SCRIPT, NULL, "[%s] %.*s",
				basename(action->data.script.path),
				len, p);

		if (!nl)
			break;

		p = nl + 1;
		nl = strchr(p, '\n');
	}
}

static void
handle_stdout(struct uloop_fd *ufd, unsigned int events)
{
	uwsd_action_t *action = container_of(ufd, uwsd_action_t, data.script.out);

	handle_stdio(action, ufd->fd, UWSD_PRIO_INFO);
}

static void
handle_stderr(struct uloop_fd *ufd, unsigned int events)
{
	uwsd_action_t *action = container_of(ufd, uwsd_action_t, data.script.err);

	handle_stdio(action, ufd->fd, UWSD_PRIO_WARN);
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
		fprintf(stderr, "Failed to compile handler script: %s\n", err);

		return false;
	}

	uc_vm_init(&ctx.vm, NULL);
	uc_vm_exception_handler_set(&ctx.vm, handle_exception);
	uc_stdlib_load(uc_vm_scope_get(&ctx.vm));

	uc_function_list_register(uc_vm_scope_get(&ctx.vm), global_fns);

	rc = uc_vm_execute(&ctx.vm, prog, &result);

	uc_program_put(prog);

	switch (rc) {
	case STATUS_OK:
		uc_type_declare(&ctx.vm, "uwsd.connection", conn_fns, close_conn);
		uc_type_declare(&ctx.vm, "uwsd.spawn", spawn_fns, close_spawn);

		ctx.onConnect = ucv_get(ucv_array_get(result, 0));
		ctx.onData    = ucv_get(ucv_array_get(result, 1));
		ctx.onRequest = ucv_get(ucv_array_get(result, 2));
		ctx.onBody    = ucv_get(ucv_array_get(result, 3));
		ctx.onClose   = ucv_get(ucv_array_get(result, 4));

		ucv_put(result);

		break;

	case STATUS_EXIT:
		rc = (int)ucv_uint64_get(result);
		fprintf(stderr, "Handler script exited with code %d\n", rc);
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
	int fd, opipe[2] = { -1, -1 }, epipe[2] = { -1, -1 };
	char ibuf[32], **e;
	pid_t pid;

	if (pipe(opipe) == -1 || pipe(epipe) == -1) {
		uwsd_log_err(NULL, "Unable to spawn pipes for script process '%s': %m",
			action->data.script.path);

		xclose(opipe[0]);
		xclose(opipe[1]);
		xclose(epipe[0]);
		xclose(epipe[1]);

		return false;
	}

	pid = fork();

	switch (pid) {
	case -1:
		uwsd_log_err(NULL, "Unable to fork script process '%s': %m",
			action->data.script.path);

		xclose(opipe[0]);
		xclose(opipe[1]);
		xclose(epipe[0]);
		xclose(epipe[1]);

		return false;

	case 0:
		fd = open("/dev/null", O_RDONLY);

		if (fd != -1) {
			dup2(fd, 0);
			xclose(fd);
		}

		dup2(opipe[1], 1);
		xclose(opipe[0]);
		xclose(opipe[1]);

		dup2(epipe[1], 2);
		xclose(epipe[0]);
		xclose(epipe[1]);

		uloop_done();

		for (e = action->data.script.env; e && *e; e++)
			putenv(*e);

		setenv("UWSD_WORKER_SOCKET",
			action->data.script.sun.sun_path + !action->data.script.sun.sun_path[0], 1);

		setenv("UWSD_WORKER_SCRIPT",
			action->data.script.path, 1);

		snprintf(ibuf, sizeof(ibuf), "%u", (unsigned int)uwsd_logging_priority);
		setenv("UWSD_LOG_PRIORITY", ibuf, 1);

		snprintf(ibuf, sizeof(ibuf), "%u", (unsigned int)uwsd_logging_channels);
		setenv("UWSD_LOG_CHANNELS", ibuf, 1);

		snprintf(ibuf, sizeof(ibuf), "%u", (unsigned int)action->data.script.msg_format);
		setenv("UWSD_WS_MSG_FORMAT", ibuf, 1);

		snprintf(ibuf, sizeof(ibuf), "%u", (unsigned int)action->data.script.msg_limit);
		setenv("UWSD_WS_MSG_LIMIT", ibuf, 1);

		execl(getenv("UWSD_EXECUTABLE"), getenv("UWSD_EXECUTABLE"), NULL);

		fprintf(stderr, "Failed to execute '%s': %m\n", getenv("UWSD_EXECUTABLE"));
		exit(-1);
		break;

	default:
		action->data.script.proc.pid = pid;
		action->data.script.proc.cb = handle_termination;
		uloop_process_add(&action->data.script.proc);

		action->data.script.out.fd = opipe[0];
		action->data.script.out.cb = handle_stdout;
		uloop_fd_add(&action->data.script.out, ULOOP_READ);

		action->data.script.err.fd = epipe[0];
		action->data.script.err.cb = handle_stderr;
		uloop_fd_add(&action->data.script.err, ULOOP_READ);

		xclose(opipe[1]);
		xclose(epipe[1]);
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


static size_t
push_tlv(struct iovec **iov, uint16_t *type, uint16_t *len, const void *data)
{
	(*iov)->iov_base = (void *)type;
	(*iov)->iov_len = sizeof(*type);
	(*iov)++;

	(*iov)->iov_base = (void *)len;
	(*iov)->iov_len = sizeof(*len);
	(*iov)++;

	(*iov)->iov_base = (void *)data;
	(*iov)->iov_len = ntohs(*len);

	return sizeof(*type) + sizeof(*len) + ((*iov)++)->iov_len;
}

#define static_tlv(_iovp, _type, _len, _data) \
	push_tlv(_iovp, &((uint16_t){ htons(_type) }), &((uint16_t){ htons(_len) }), _data)

#define single_tlv(_iov, _type, _len, _data) \
	static_tlv(&((struct iovec *){ _iov }), _type, _len, _data)

__hidden bool
uwsd_script_connect(uwsd_client_context_t *cl, const char *acceptkey)
{
	uint16_t tv[cl->http_num_headers], lv[cl->http_num_headers];
	struct iovec iov[(9 + cl->http_num_headers) * 3];
	struct iovec *iop = iov;
	ssize_t total = 0;
	const char *s;
	size_t i;

	total += static_tlv(&iop, UWSD_SCRIPT_DATA_PEER_ADDR, sizeof(cl->sa_peer.in6), &cl->sa_peer.in6);
	total += static_tlv(&iop, UWSD_SCRIPT_DATA_LOCAL_ADDR, sizeof(cl->sa_local.in6), &cl->sa_local.in6);
	total += static_tlv(&iop, UWSD_SCRIPT_DATA_HTTP_VERSION, sizeof(cl->http_version), &cl->http_version);
	total += static_tlv(&iop, UWSD_SCRIPT_DATA_HTTP_METHOD, sizeof(cl->request_method), &cl->request_method);
	total += static_tlv(&iop, UWSD_SCRIPT_DATA_HTTP_URI, strlen(cl->request_uri), cl->request_uri);

	for (i = 0; i < cl->http_num_headers; i++) {
		tv[i] = htons(UWSD_SCRIPT_DATA_HTTP_HEADER);
		lv[i] = htons(strlen(cl->http_headers[i].name) + strlen(cl->http_headers[i].value) + 2);
		total += push_tlv(&iop, &tv[i], &lv[i], cl->http_headers[i].name);
	}

	if (cl->listener->ssl) {
		s = uwsd_ssl_cipher_name(&cl->downstream);

		if (s)
			total += static_tlv(&iop, UWSD_SCRIPT_DATA_SSL_CIPHER, strlen(s), s);

		s = uwsd_ssl_peer_issuer_name(&cl->downstream);

		if (s)
			total += static_tlv(&iop, UWSD_SCRIPT_DATA_X509_PEER_ISSUER, strlen(s), s);

		s = uwsd_ssl_peer_subject_name(&cl->downstream);

		if (s)
			total += static_tlv(&iop, UWSD_SCRIPT_DATA_X509_PEER_SUBJECT, strlen(s), s);
	}

	total += static_tlv(&iop, UWSD_SCRIPT_DATA_WS_INIT, strlen(acceptkey) + 1, acceptkey);

	return (writev(cl->upstream.ufd.fd, iov, iop - iov) == total);
}


__hidden bool
uwsd_script_send(uwsd_client_context_t *cl, const void *data, size_t len)
{
	struct iovec iov[3];
	ssize_t total;
	uint16_t type;

	assert(len <= sizeof(((script_connection_t *)NULL)->buf.data));

	cl->ws.len -= len;

	if (len > 0)
		type = cl->ws.len ? UWSD_SCRIPT_DATA_WS_FRAGMENT : UWSD_SCRIPT_DATA_WS_FINAL;
	else
		type = UWSD_SCRIPT_DATA_WS_EOF;

	total = single_tlv(iov, type, len, data);

	return (writev(cl->upstream.ufd.fd, iov, ARRAY_SIZE(iov)) == total);
}

__hidden void
uwsd_script_close(uwsd_client_context_t *cl)
{
	struct iovec iov[3];
	char statusbuf[125];
	int statuslen = 2;

	if (!cl->action || cl->action->type != UWSD_ACTION_SCRIPT)
		return;

	if (cl->protocol == UWSD_PROTOCOL_HTTP) {
		single_tlv(iov, UWSD_SCRIPT_DATA_HTTP_EOF, 0, "");
	}
	else {
		statuslen = snprintf(statusbuf, sizeof(statusbuf), "%c%c%s",
			(cl->ws.error.code ? cl->ws.error.code : 1000) / 256,
			(cl->ws.error.code ? cl->ws.error.code : 1000) % 256,
			cl->ws.error.msg ? cl->ws.error.msg : "");

		single_tlv(iov, UWSD_SCRIPT_DATA_WS_EOF, statuslen + 1, statusbuf);
	}

	writev(cl->upstream.ufd.fd, iov, ARRAY_SIZE(iov));
}

__hidden void
uwsd_script_free(uwsd_action_t *action)
{
	uloop_timeout_cancel(&action->data.script.timeout);
	uloop_process_delete(&action->data.script.proc);

	kill(action->data.script.proc.pid, SIGKILL);
	waitpid(action->data.script.proc.pid, NULL, 0);

	free(action->data.script.path);
}

__hidden bool
uwsd_script_request(uwsd_client_context_t *cl, int downstream)
{
	uint16_t tv[cl->http_num_headers], lv[cl->http_num_headers];
	struct iovec iov[(7 + cl->http_num_headers) * 3];
	struct iovec *iop = iov;
	ssize_t total = 0;
	const char *s;
	size_t i;

	total += static_tlv(&iop, UWSD_SCRIPT_DATA_PEER_ADDR, sizeof(cl->sa_peer.in6), &cl->sa_peer.in6);
	total += static_tlv(&iop, UWSD_SCRIPT_DATA_LOCAL_ADDR, sizeof(cl->sa_local.in6), &cl->sa_local.in6);
	total += static_tlv(&iop, UWSD_SCRIPT_DATA_HTTP_VERSION, sizeof(cl->http_version), &cl->http_version);
	total += static_tlv(&iop, UWSD_SCRIPT_DATA_HTTP_METHOD, sizeof(cl->request_method), &cl->request_method);
	total += static_tlv(&iop, UWSD_SCRIPT_DATA_HTTP_URI, strlen(cl->request_uri), cl->request_uri);

	for (i = 0; i < cl->http_num_headers; i++) {
		tv[i] = htons(UWSD_SCRIPT_DATA_HTTP_HEADER);
		lv[i] = htons(strlen(cl->http_headers[i].name) + strlen(cl->http_headers[i].value) + 2);
		total += push_tlv(&iop, &tv[i], &lv[i], cl->http_headers[i].name);
	}

	if (cl->listener->ssl) {
		s = uwsd_ssl_peer_issuer_name(&cl->downstream);

		if (s)
			total += static_tlv(&iop, UWSD_SCRIPT_DATA_X509_PEER_ISSUER, strlen(s), s);

		s = uwsd_ssl_peer_subject_name(&cl->downstream);

		if (s)
			total += static_tlv(&iop, UWSD_SCRIPT_DATA_X509_PEER_SUBJECT, strlen(s), s);
	}

	return (writev(cl->upstream.ufd.fd, iov, iop - iov) == total);
}

__hidden bool
uwsd_script_bodydata(uwsd_client_context_t *cl, const void *data, size_t len)
{
	struct iovec iov[3];
	ssize_t total;

	assert(len <= sizeof(((script_connection_t *)NULL)->buf.data));

	total = single_tlv(iov,
		len ? UWSD_SCRIPT_DATA_HTTP_DATA : UWSD_SCRIPT_DATA_HTTP_EOF,
		len, data);

	return (writev(cl->upstream.ufd.fd, iov, ARRAY_SIZE(iov)) == total);
}

__hidden int
uwsd_script_worker_main(const char *sockpath, const char *scriptpath)
{
	uwsd_logging_priority = atoi(getenv("UWSD_LOG_PRIORITY") ?: "0");
	uwsd_logging_channels = atoi(getenv("UWSD_LOG_CHANNELS") ?: "0");

	setvbuf(stdout, NULL, _IOLBF, 0);
	setvbuf(stderr, NULL, _IOLBF, 0);

	return script_context_run(sockpath, scriptpath);
}
