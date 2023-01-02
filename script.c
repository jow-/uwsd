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
#include <errno.h>
#include <assert.h>
#include <ctype.h>

#include <libubox/uloop.h>
#include <ucode/compiler.h>
#include <ucode/lib.h>

#include "state.h"
#include "script.h"
#include "ws.h"
#include "client.h"
#include "listen.h"
#include "log.h"


static uc_value_t *
uc_script_accept(uc_vm_t *vm, size_t nargs)
{
	uwsd_client_context_t **cl = uc_fn_this("uwsd.connection");
	uc_value_t *proto = uc_fn_arg(0);

	if (!cl || !*cl)
		return NULL;

	if (proto && ucv_type(proto) != UC_STRING)
		return NULL;

	(*cl)->script.proto = proto ? ucv_get(proto) : ucv_boolean_new(true);

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_script_data(uc_vm_t *vm, size_t nargs)
{
	uwsd_client_context_t **cl = uc_fn_this("uwsd.connection");
	uc_value_t *set = uc_fn_arg(0);

	if (!cl)
		cl = uc_fn_this("uwsd.request");

	if (!cl || !*cl)
		return NULL;

	if (nargs) {
		ucv_get(set);
		ucv_put((*cl)->script.data);
		(*cl)->script.data = set;

		return ucv_get(set);
	}

	return ucv_get((*cl)->script.data);
}

static uc_value_t *
uc_script_send(uc_vm_t *vm, size_t nargs)
{
	uwsd_client_context_t **cl = uc_fn_this("uwsd.connection");
	uc_value_t *data = uc_fn_arg(0);
	int wakefd;

	if (!cl || !*cl)
		return NULL;

	if (ucv_type(data) != UC_STRING)
		return NULL;

	wakefd = (*cl)->script.fd;

	if (!uwsd_ws_reply_send(*cl, OPCODE_TEXT, ucv_string_get(data), ucv_string_length(data))) {
		write(wakefd, ".", 1);

		return ucv_boolean_new(false);
	}

	return ucv_boolean_new(true);
}

static uc_value_t *
uc_script_close(uc_vm_t *vm, size_t nargs)
{
	uwsd_client_context_t *clp, **cl = uc_fn_this("uwsd.connection");
	uc_value_t *rcode = uc_fn_arg(0);
	uc_value_t *rmsg = uc_fn_arg(1);
	const char *httpstatus;
	uint16_t httpcode;

	if (!cl || !*cl)
		return NULL;

	if (ucv_type(rcode) != UC_INTEGER || ucv_type(rmsg) != UC_STRING)
		return NULL;

	clp = *cl;
	*cl = NULL;

	if (clp->script.fd != -1) {
		uwsd_ws_connection_close(*cl, ucv_uint64_get(rcode), "%s", ucv_string_get(rmsg));
	}
	else {
		httpcode = ucv_uint64_get(rcode);

		switch (httpcode) {
		case STATUS_NOT_ACCEPTABLE:
			httpcode = 406;
			httpstatus = "Not Acceptable";
			break;

		case STATUS_MESSAGE_TOO_BIG:
			httpcode = 413;
			httpstatus = "Payload Too Large";
			break;

		default:
			httpcode = 400;
			httpstatus = "Bad Request";
			break;
		}

		uwsd_http_error_send(clp, httpcode, httpstatus,
			"Unacceptable WebSocket request:\n%hu - %s\n",
			(uint16_t)ucv_uint64_get(rcode), ucv_string_get(rmsg));
	}

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
uc_script_http_version(uc_vm_t *vm, size_t nargs)
{
	uwsd_client_context_t **cl = uc_fn_this("uwsd.request");

	if (!cl || !*cl)
		return NULL;

	return ucv_double_new(
		(double)((*cl)->http_version >> 8) +
		(10.0 / (double)((*cl)->http_version & 0xff))
	);
}

static uc_value_t *
uc_script_request_uri(uc_vm_t *vm, size_t nargs)
{
	uwsd_client_context_t **cl = uc_fn_this("uwsd.request");

	if (!cl || !*cl)
		return NULL;

	return ucv_string_new((*cl)->request_uri);
}

static uc_value_t *
uc_script_request_header(uc_vm_t *vm, size_t nargs)
{
	uwsd_client_context_t **cl = uc_fn_this("uwsd.request");
	uc_value_t *name = uc_fn_arg(0);
	uc_value_t *o;
	size_t i;

	if (!cl || !*cl)
		return NULL;

	if (name && ucv_type(name) != UC_STRING)
		return NULL;

	if (name) {
		for (i = 0; i < (*cl)->http_num_headers; i++)
			if (!strcasecmp((*cl)->http_headers[i].name, ucv_string_get(name)))
				return ucv_string_new((*cl)->http_headers[i].value);

		return NULL;
	}

	o = ucv_object_new(vm);

	for (i = 0; i < (*cl)->http_num_headers; i++)
		ucv_object_add(o, (*cl)->http_headers[i].name,
			ucv_string_new((*cl)->http_headers[i].value));

	return o;
}

static uc_value_t *
uc_script_reply(uc_vm_t *vm, size_t nargs)
{
	uwsd_client_context_t **cl = uc_fn_this("uwsd.request");
	uc_stringbuf_t *buf = xprintbuf_new();
	uc_value_t *header = uc_fn_arg(0);
	uc_value_t *body = uc_fn_arg(1);
	ssize_t wlen, n, lenoff = 0;
	uint16_t status = 200;
	char *reason = "OK";
	uc_value_t *v;
	bool found;
	char *p;

	if (!cl || !*cl)
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

	sprintbuf(buf, "HTTP/%hu.%hu %03hu %s\r\n",
		(*cl)->http_version >> 8, (*cl)->http_version & 0xff,
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
		wlen = write((*cl)->script.fd, p, n);

		if (wlen == -1) {
			if (errno == EINTR)
				continue;

			uc_vm_raise_exception(vm, EXCEPTION_RUNTIME, "write error: %s", strerror(errno));
			break;
		}

		p += wlen;
		n -= wlen;
	}

	close((*cl)->script.fd);
	printbuf_free(buf);

	*cl = NULL;

	return ucv_boolean_new(!n);
}

static const uc_function_list_t req_fns[] = {
	{ "version", uc_script_http_version },
	{ "uri",     uc_script_request_uri },
	{ "header",  uc_script_request_header },
	{ "data",    uc_script_data },
	{ "reply",   uc_script_reply }
};

static void
close_req(void *ud)
{
}

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


static void
ucv_clear(uc_value_t **uv)
{
	ucv_put(*uv);

	*uv = NULL;
}


__hidden bool
uwsd_script_init(uwsd_action_t *action, const char *path)
{
	uc_vm_t *vm = &action->data.script.vm;
	uc_source_t *source;
	uc_program_t *prog;
	uc_value_t *result;
	char *script, *err;
	int len, rc;

	len = xasprintf(&script,
		"{%%\n"
		"import * as cb from '%s';\n"
		"return [ cb.onConnect, cb.onData, cb.onRequest, cb.onBody, cb.onClose ];\n",
		path);

	source = uc_source_new_buffer("bootstrap script", script, len);
	prog = uc_compile(NULL, source, &err);
	uc_source_put(source);

	if (!prog) {
		uwsd_log_err(NULL, "Failed to compile handler script: %s", err);

		return false;
	}

	uc_vm_init(vm, NULL);
	uc_vm_exception_handler_set(vm, handle_exception);
	uc_stdlib_load(uc_vm_scope_get(vm));

	rc = uc_vm_execute(vm, prog, &result);

	uc_program_put(prog);

	switch (rc) {
	case STATUS_OK:
		uc_type_declare(vm, "uwsd.connection", conn_fns, close_conn);
		uc_type_declare(vm, "uwsd.request", req_fns, close_req);

		action->data.script.onConnect = ucv_get(ucv_array_get(result, 0));
		action->data.script.onData    = ucv_get(ucv_array_get(result, 1));
		action->data.script.onRequest = ucv_get(ucv_array_get(result, 2));
		action->data.script.onBody    = ucv_get(ucv_array_get(result, 3));
		action->data.script.onClose   = ucv_get(ucv_array_get(result, 4));

		ucv_put(result);

		break;

	case STATUS_EXIT:
		uwsd_log_err(NULL, "Handler script exited with code %d", (int)ucv_uint64_get(result));
		ucv_put(result);

		break;

	default:
		return false;
	}

	return true;
}

__hidden bool
uwsd_script_connect(uwsd_client_context_t *cl, int wakefd)
{
	uc_vm_t *vm = &cl->action->data.script.vm;
	uwsd_action_t *action = cl->action;
	uc_value_t *ctx, *protocols = NULL;
	uc_resource_type_t *conn_type;
	uc_exception_type_t ex;
	char *protohdr, *p;
	size_t plen;
	void **clp;

	conn_type = ucv_resource_type_lookup(vm, "uwsd.connection");
	assert(conn_type);

	cl->script.conn = uc_resource_new(conn_type, cl);
	cl->script.fd = -1;

	if (action->data.script.onConnect) {
		protohdr = uwsd_http_header_lookup(cl, "Sec-WebSocket-Protocol");

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

		uc_vm_stack_push(vm, ucv_get(action->data.script.onConnect));
		uc_vm_stack_push(vm, ucv_get(cl->script.conn));
		uc_vm_stack_push(vm, protocols);

		clp = ucv_resource_dataptr(cl->script.conn, "uwsd.connection");
		ex = uc_vm_call(vm, false, 2);

		if (!clp || !*clp)
			return false; /* onConnect() function freed the connection */

		if (ex != EXCEPTION_NONE) {
			ctx = ucv_object_get(ucv_array_get(vm->exception.stacktrace, 0), "context", NULL);

			uwsd_http_error_send(cl, 500, "Internal Server Error",
				"Exception in onConnect(): %s\n%s",
					vm->exception.message,
					ucv_string_get(ctx));

			return false;
		}

		ucv_put(uc_vm_stack_pop(vm));

		if (!cl->script.proto) {
			uwsd_http_error_send(cl, 500, "Internal Server Error",
				"The onConnect() handler did not accept the connection\n");

			return false;
		}

		if (ucv_type(cl->script.proto) != UC_STRING)
			ucv_clear(&cl->script.proto);
	}

	cl->script.fd = wakefd;

	return true;
}


__hidden bool
uwsd_script_send(uwsd_client_context_t *cl, const void *data, size_t len)
{
	uc_vm_t *vm = &cl->action->data.script.vm;
	uwsd_action_t *action = cl->action;
	uc_exception_type_t ex;
	uc_value_t *ctx;
	bool final;

	if (!action->data.script.onData)
		return true;

	final = (cl->script.msgoff + len == cl->ws.len);

	if (final)
		cl->script.msgoff = 0;
	else
		cl->script.msgoff += len;

	uc_vm_stack_push(vm, ucv_get(action->data.script.onData));
	uc_vm_stack_push(vm, ucv_get(cl->script.conn));
	uc_vm_stack_push(vm, ucv_string_new_length(data, len));
	uc_vm_stack_push(vm, ucv_boolean_new(final));

	ex = uc_vm_call(vm, false, 3);

	if (ex != EXCEPTION_NONE) {
		ctx = ucv_object_get(ucv_array_get(vm->exception.stacktrace, 0), "context", NULL);

		uwsd_ws_connection_close(cl, STATUS_INTERNAL_ERROR,
			"Exception in onData(): %s\n%s",
				vm->exception.message,
				ucv_string_get(ctx));

		return false;
	}

	ucv_put(uc_vm_stack_pop(vm));

	return true;
}

__hidden void
uwsd_script_close(uwsd_client_context_t *cl)
{
	uwsd_action_t *action;
	void **clptr;
	size_t nargs;
	uc_vm_t *vm;

	assert(cl);

	action = cl->action;

	if (action && action->data.script.onClose) {
		vm = &action->data.script.vm;

		if (vm->exception.type != EXCEPTION_NONE)
			uc_vm_exception_handler_get(vm)(vm, &vm->exception);

		uc_vm_stack_push(vm, ucv_get(action->data.script.onClose));
		uc_vm_stack_push(vm, ucv_get(cl->script.conn));
		nargs = 1;

		if (cl->protocol == UWSD_PROTOCOL_WS) {
			uc_vm_stack_push(vm, cl->ws.error.code ? ucv_uint64_new(cl->ws.error.code) : NULL);
			uc_vm_stack_push(vm, cl->ws.error.msg ? ucv_string_new(cl->ws.error.msg) : NULL);
			nargs += 2;
		}

		if (uc_vm_call(vm, false, nargs) == EXCEPTION_NONE)
			ucv_put(uc_vm_stack_pop(vm));
	}

	clptr = ucv_resource_dataptr(cl->script.conn, NULL);

	if (clptr)
		*clptr = NULL;

	ucv_clear(&cl->script.conn);
	ucv_clear(&cl->script.data);
	ucv_clear(&cl->script.proto);
}

__hidden void
uwsd_script_free(uwsd_action_t *action)
{
	ucv_clear(&action->data.script.onConnect);
	ucv_clear(&action->data.script.onData);
	ucv_clear(&action->data.script.onClose);

	ucv_clear(&action->data.script.onRequest);
	ucv_clear(&action->data.script.onBody);

	uc_vm_free(&action->data.script.vm);
}

__hidden bool
uwsd_script_request(uwsd_client_context_t *cl, int downstream)
{
	uc_vm_t *vm = &cl->action->data.script.vm;
	uwsd_action_t *action = cl->action;
	uc_resource_type_t *conn_type;
	uc_exception_type_t ex;
	uc_value_t *ctx;

	const char *http_method_names[] = {
		[HTTP_GET]     = "GET",
		[HTTP_POST]    = "POST",
		[HTTP_PUT]     = "PUT",
		[HTTP_HEAD]    = "HEAD",
		[HTTP_OPTIONS] = "OPTIONS",
		[HTTP_DELETE]  = "DELETE",
		[HTTP_TRACE]   = "TRACE",
		[HTTP_CONNECT] = "CONNECT"
	};

	conn_type = ucv_resource_type_lookup(vm, "uwsd.request");
	assert(conn_type);

	cl->script.conn = uc_resource_new(conn_type, cl);
	cl->script.fd = downstream;

	if (action->data.script.onRequest) {
		uc_vm_stack_push(vm, ucv_get(action->data.script.onRequest));
		uc_vm_stack_push(vm, ucv_get(cl->script.conn));
		uc_vm_stack_push(vm, ucv_string_new(http_method_names[cl->request_method]));
		uc_vm_stack_push(vm, ucv_string_new(cl->request_uri));

		ex = uc_vm_call(vm, false, 3);

		if (ex != EXCEPTION_NONE) {
			ctx = ucv_object_get(ucv_array_get(vm->exception.stacktrace, 0), "context", NULL);

			uwsd_http_error_send(cl, 500, "Internal Server Error",
				"Exception in onRequest(): %s\n%s",
					vm->exception.message,
					ucv_string_get(ctx));

			return false;
		}

		ucv_put(uc_vm_stack_pop(vm));
	}
	else {
		uwsd_http_error_send(cl, 501, "Not Implemented",
			"Backend script does not implement an onRequest() handler.\n");

		return false;
	}

	return true;
}

__hidden bool
uwsd_script_bodydata(uwsd_client_context_t *cl, const void *data, size_t len)
{
	uc_vm_t *vm = &cl->action->data.script.vm;
	uwsd_action_t *action = cl->action;
	uc_exception_type_t ex;
	uc_value_t *ctx;

	if (!action->data.script.onBody)
		return true;

	uc_vm_stack_push(vm, ucv_get(action->data.script.onBody));
	uc_vm_stack_push(vm, ucv_get(cl->script.conn));
	uc_vm_stack_push(vm, ucv_string_new_length(data, len));

	ex = uc_vm_call(vm, false, 2);

	if (ex != EXCEPTION_NONE) {
		ctx = ucv_object_get(ucv_array_get(vm->exception.stacktrace, 0), "context", NULL);

		uwsd_http_error_send(cl, 500, "Internal Server Error",
			"Exception in onBody(): %s\n%s",
				vm->exception.message,
				ucv_string_get(ctx));

		return false;
	}

	ucv_put(uc_vm_stack_pop(vm));

	return true;
}
