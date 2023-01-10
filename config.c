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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <sys/stat.h>

#include "config.h"
#include "listen.h"
#include "ssl.h"
#include "auth.h"
#include "script.h"
#include "log.h"


uwsd_config_t *config;

typedef enum {
	STRING,
	BOOLEAN,
	INTEGER,
	NESTED_SINGLE,
	NESTED_MULTIPLE,
} config_type_t;

typedef struct config_block config_block_t;
typedef struct config_prop config_prop_t;


typedef struct config_prop {
	const char *name;
	config_type_t type;
	size_t offset;
	const config_block_t *nested;
} config_prop_t;

typedef struct config_block {
	struct list_head list;
	size_t size;
	bool (*init)(void *, const char *);
	bool (*validate)(void *);
	void (*free)(void *);
	struct config_prop properties[];
} config_block_t;



#define parse_error(fmt, ...) (uwsd_log_err(NULL, fmt, ##__VA_ARGS__), false)

static void *
property_ptr(const config_prop_t *prop, void *base)
{
	return (void *)((uintptr_t)base + prop->offset);
}

#define char_ptr(prop, base) *(char **)property_ptr(prop, base)
#define bool_ptr(prop, base) *(bool *)property_ptr(prop, base)
#define int_ptr(prop, base)  *(int *)property_ptr(prop, base)
#define list_ptr(prop, base) (struct list_head *)property_ptr(prop, base)


static bool parse_backend(void *obj, const char *label);
static bool validate_backend(void *obj);
static void free_backend(void *obj);

static bool parse_listen(void *obj, const char *label);
static bool validate_listen(void *obj);
static void free_listen(void *obj);

static bool parse_protocol_match(void *obj, const char *label);
static bool parse_hostname_match(void *obj, const char *label);
static bool parse_path_match(void *obj, const char *label);
static void free_match(void *obj);

static bool parse_serve_file(void *obj, const char *label);
static bool parse_serve_directory(void *obj, const char *label);
static bool parse_run_script(void *obj, const char *label);
static bool parse_use_backend(void *obj, const char *label);
static bool parse_proxy_tcp(void *obj, const char *label);
static bool parse_proxy_udp(void *obj, const char *label);
static bool parse_proxy_unix(void *obj, const char *label);
static bool validate_action(void *obj);
static void free_action(void *obj);

static bool parse_auth_basic(void *obj, const char *label);
static bool parse_auth_mtls(void *obj, const char *label);
static bool validate_auth(void *obj);
static void free_auth(void *obj);

static bool validate_ssl(void *obj);
static void free_ssl(void *obj);

static const config_block_t ssl_spec = {
	.size = sizeof(uwsd_ssl_t),
	.validate = validate_ssl,
	.free = free_ssl,
	.properties = {
		{ "verify-peer", BOOLEAN,
			offsetof(uwsd_ssl_t, verify_peer), NULL },
		{ "private-key", STRING,
			offsetof(uwsd_ssl_t, private_key), NULL },
		{ "certificate", STRING,
			offsetof(uwsd_ssl_t, certificate), NULL },
		{ "certificate-directory", STRING,
			offsetof(uwsd_ssl_t, certificate_directory), NULL },
		{ "protocols", STRING,
			offsetof(uwsd_ssl_t, protocols), NULL },
		{ "ciphers", STRING,
			offsetof(uwsd_ssl_t, ciphers), NULL },
		{ 0 }
	}
};

#define MATCH_PROPERTIES(type)										\
	{ "match-protocol", NESTED_MULTIPLE,							\
		offsetof(type, matches), &match_protocol_spec },			\
	{ "match-hostname", NESTED_MULTIPLE,							\
		offsetof(type, matches), &match_hostname_spec },			\
	{ "match-path", NESTED_MULTIPLE,								\
		offsetof(type, matches), &match_path_spec },				\
	{ "auth-basic", NESTED_MULTIPLE,								\
		offsetof(type, auth), &auth_basic_spec },					\
	{ "auth-mtls", NESTED_MULTIPLE,									\
		offsetof(type, auth), &auth_mtls_spec }

#define ACTION_PROPERTIES(type)										\
	{ "serve-file", NESTED_SINGLE,									\
		offsetof(type, default_action), &serve_file_spec },			\
	{ "serve-directory", NESTED_SINGLE,								\
		offsetof(type, default_action), &serve_directory_spec },	\
	{ "run-script", NESTED_SINGLE,									\
		offsetof(type, default_action), &run_script_spec },			\
	{ "use-backend", NESTED_SINGLE,									\
		offsetof(type, default_action), &use_backend_spec },		\
	{ "proxy-tcp", NESTED_SINGLE,									\
		offsetof(type, default_action), &proxy_tcp_spec },			\
	{ "proxy-udp", NESTED_SINGLE,									\
		offsetof(type, default_action), &proxy_udp_spec },			\
	{ "proxy-unix", NESTED_SINGLE,									\
		offsetof(type, default_action), &proxy_unix_spec }

static const config_block_t backend_spec;

static const config_block_t match_protocol_spec;
static const config_block_t match_hostname_spec;
static const config_block_t match_path_spec;

static const config_block_t serve_file_spec;
static const config_block_t serve_directory_spec;
static const config_block_t run_script_spec;
static const config_block_t use_backend_spec;
static const config_block_t proxy_tcp_spec;
static const config_block_t proxy_udp_spec;
static const config_block_t proxy_unix_spec;

static const config_block_t auth_basic_spec;
static const config_block_t auth_mtls_spec;

static const config_block_t backend_spec = {
	.size = sizeof(uwsd_backend_t),
	.init = parse_backend,
	.validate = validate_backend,
	.free = free_backend,
	.properties = {
		ACTION_PROPERTIES(uwsd_backend_t),
		{ 0 }
	}
};

static const config_block_t match_protocol_spec = {
	.size = sizeof(uwsd_match_t),
	.init = parse_protocol_match,
	.free = free_match,
	.properties = {
		MATCH_PROPERTIES(uwsd_match_t),
		ACTION_PROPERTIES(uwsd_match_t),
		{ 0 }
	}
};

static const config_block_t match_hostname_spec = {
	.size = sizeof(uwsd_match_t),
	.init = parse_hostname_match,
	.free = free_match,
	.properties = {
		MATCH_PROPERTIES(uwsd_match_t),
		ACTION_PROPERTIES(uwsd_match_t),
		{ 0 }
	}
};

static const config_block_t match_path_spec = {
	.size = sizeof(uwsd_match_t),
	.init = parse_path_match,
	.free = free_match,
	.properties = {
		MATCH_PROPERTIES(uwsd_match_t),
		ACTION_PROPERTIES(uwsd_match_t),
		{ 0 }
	}
};

static const config_block_t serve_file_spec = {
	.size = sizeof(uwsd_action_t),
	.init = parse_serve_file,
	.validate = validate_action,
	.free = free_action,
	.properties = {
		{ 0 }
	}
};

static const config_block_t serve_directory_spec = {
	.size = sizeof(uwsd_action_t),
	.init = parse_serve_directory,
	.validate = validate_action,
	.free = free_action,
	.properties = {
		{ 0 }
	}
};

static const config_block_t run_script_spec = {
	.size = sizeof(uwsd_action_t),
	.init = parse_run_script,
	.validate = validate_action,
	.free = free_action,
	.properties = {
		{ 0 }
	}
};

static const config_block_t use_backend_spec = {
	.size = sizeof(uwsd_action_t),
	.init = parse_use_backend,
	.validate = validate_action,
	.free = free_action,
	.properties = {
		{ 0 }
	}
};

static const config_block_t proxy_tcp_spec = {
	.size = sizeof(uwsd_action_t),
	.init = parse_proxy_tcp,
	.validate = validate_action,
	.free = free_action,
	.properties = {
		{ "connect-timeout", INTEGER,
			offsetof(uwsd_action_t, data.proxy.connect_timeout), NULL },
		{ "transfer-timeout", INTEGER,
			offsetof(uwsd_action_t, data.proxy.transfer_timeout), NULL },
		{ "idle-timeout", INTEGER,
			offsetof(uwsd_action_t, data.proxy.idle_timeout), NULL },
		{ "binary", BOOLEAN,
			offsetof(uwsd_action_t, data.proxy.binary), NULL },
		{ "subprotocol", STRING,
			offsetof(uwsd_action_t, data.proxy.subprotocol), NULL },
		{ 0 }
	}
};

static const config_block_t proxy_udp_spec = {
	.size = sizeof(uwsd_action_t),
	.init = parse_proxy_udp,
	.validate = validate_action,
	.free = free_action,
	.properties = {
		{ "connect-timeout", INTEGER,
			offsetof(uwsd_action_t, data.proxy.connect_timeout), NULL },
		{ "transfer-timeout", INTEGER,
			offsetof(uwsd_action_t, data.proxy.transfer_timeout), NULL },
		{ "idle-timeout", INTEGER,
			offsetof(uwsd_action_t, data.proxy.idle_timeout), NULL },
		{ "binary", BOOLEAN,
			offsetof(uwsd_action_t, data.proxy.binary), NULL },
		{ "subprotocol", STRING,
			offsetof(uwsd_action_t, data.proxy.subprotocol), NULL },
		{ 0 }
	}
};

static const config_block_t proxy_unix_spec = {
	.size = sizeof(uwsd_action_t),
	.init = parse_proxy_unix,
	.validate = validate_action,
	.free = free_action,
	.properties = {
		{ "connect-timeout", INTEGER,
			offsetof(uwsd_action_t, data.proxy.connect_timeout), NULL },
		{ "transfer-timeout", INTEGER,
			offsetof(uwsd_action_t, data.proxy.transfer_timeout), NULL },
		{ "idle-timeout", INTEGER,
			offsetof(uwsd_action_t, data.proxy.idle_timeout), NULL },
		{ "binary", BOOLEAN,
			offsetof(uwsd_action_t, data.proxy.binary), NULL },
		{ "subprotocol", STRING,
			offsetof(uwsd_action_t, data.proxy.subprotocol), NULL },
		{ 0 }
	}
};

static const config_block_t auth_basic_spec = {
	.size = sizeof(uwsd_auth_t),
	.init = parse_auth_basic,
	.validate = validate_auth,
	.free = free_auth,
	.properties = {
		{ "username", STRING,
			offsetof(uwsd_auth_t, data.basic.username), NULL },
		{ "password", STRING,
			offsetof(uwsd_auth_t, data.basic.password), NULL },
		{ "lookup-shadow", BOOLEAN,
			offsetof(uwsd_auth_t, data.basic.lookup_shadow), NULL },
		{ 0 }
	}
};

static const config_block_t auth_mtls_spec = {
	.size = sizeof(uwsd_auth_t),
	.init = parse_auth_mtls,
	.validate = validate_auth,
	.free = free_auth,
	.properties = {
		{ "require-issuer", STRING,
			offsetof(uwsd_auth_t, data.mtls.require_issuer), NULL },
		{ "require-subject", STRING,
			offsetof(uwsd_auth_t, data.mtls.require_subject), NULL },
		{ 0 }
	}
};

static const config_block_t listen_spec = {
	.size = sizeof(uwsd_listen_t),
	.init = parse_listen,
	.validate = validate_listen,
	.free = free_listen,
	.properties = {
		{ "ssl", NESTED_SINGLE,
			offsetof(uwsd_listen_t, ssl), &ssl_spec },
		{ "request-timeout", INTEGER,
			offsetof(uwsd_listen_t, request_timeout), NULL },
		{ "transfer-timeout", INTEGER,
			offsetof(uwsd_listen_t, transfer_timeout), NULL },
		{ "idle-timeout", INTEGER,
			offsetof(uwsd_listen_t, idle_timeout), NULL },
		MATCH_PROPERTIES(uwsd_listen_t),
		ACTION_PROPERTIES(uwsd_listen_t),
		{ 0 }
	}
};

static const config_block_t toplevel_spec = {
	.size = sizeof(uwsd_config_t),
	.properties = {
		{ "backend", NESTED_MULTIPLE,
			offsetof(uwsd_config_t, backends), &backend_spec },
		{ "listen", NESTED_MULTIPLE,
			offsetof(uwsd_config_t, listeners), &listen_spec },
		{ 0 }
	}
};


static char
hex(char c)
{
	if ((c|32) >= 'a')
		return (c|32) - 'a';

	return c - '0';
}

static void
skipws(const char **input)
{
	while (**input) {
		if (**input == '#') {
			*input += strcspn(*input, "\n");
			continue;
		}
		else if (isspace(**input)) {
			*input += 1;
		}
		else {
			break;
		}
	}
}

static bool
skipchar(const char **input, char c)
{
	skipws(input);

	if (**input != c)
		return false;

	(*input)++;

	skipws(input);

	return true;
}

static void
config_free_object(const config_block_t *spec, void *base);

static void *
config_alloc_object(const config_block_t *spec, const char *label)
{
	const config_prop_t *prop;
	void *obj = NULL;

	obj = xalloc(spec->size);

	for (prop = spec->properties; prop->name; prop++)
		if (prop->type == NESTED_MULTIPLE)
			INIT_LIST_HEAD(list_ptr(prop, obj));

	if (spec->init && !spec->init(obj, label)) {
		config_free_object(spec, obj);

		return NULL;
	}

	return obj;
}

static void
config_free_object(const config_block_t *spec, void *base)
{
	const config_prop_t *prop;
	struct list_head *e, *tmp;
	char *obj;

	for (prop = spec->properties; prop->name; prop++) {
		switch (prop->type) {
		case STRING:
			free(char_ptr(prop, base));
			break;

		case NESTED_MULTIPLE:
			list_for_each_safe(e, tmp, list_ptr(prop, base)) {
				list_del(e);
				config_free_object(prop->nested, e);
			}

			break;

		case NESTED_SINGLE:
			obj = char_ptr(prop, base);

			if (obj) {
				*(void **)property_ptr(prop, base) = NULL;
				config_free_object(prop->nested, obj);
			}

			break;

		default:
			break;
		}
	}

	if (spec->free)
		spec->free(base);

	free(base);
}

static bool
config_parse_block(const char **input, const config_block_t *spec, void *base);

static bool
config_parse_value(const char **input, const config_prop_t *prop, void *base)
{
	char buf[PATH_MAX] = { 0 }, q, *e;
	size_t buflen = 0;
	const char *p;
	void *obj;
	bool esc;
	int n;

	skipws(input);

	if (**input == '"' || **input == '\'') {
		for (q = **input, p = ++(*input), esc = false; *p; p = ++(*input)) {
			if (buflen == sizeof(buf) - 1)
				return parse_error("String value too long");

			if (esc) {
				switch (*p) {
				case 'x':
					if (!isxdigit(p[1]) || !isxdigit(p[2]))
						return parse_error("Invalid escape sequence");

					buf[buflen++] = hex(p[1]) * 16 + hex(p[2]);
					p = ((*input) += 2);
					break;

				case 'a': buf[buflen++] = '\a';   break;
				case 'b': buf[buflen++] = '\b';   break;
				case 'e': buf[buflen++] = '\033'; break;
				case 'f': buf[buflen++] = '\f';   break;
				case 'n': buf[buflen++] = '\n';   break;
				case 'r': buf[buflen++] = '\r';   break;
				case 't': buf[buflen++] = '\t';   break;
				case 'v': buf[buflen++] = '\v';   break;
				default:  buf[buflen++] = *p;     break;
				}

				esc = false;
			}
			else if (*p == '\\') {
				esc = true;
			}
			else if (*p == q) {
				(*input)++;
				break;
			}
			else {
				buf[buflen++] = *p;
			}
		}
	}
	else {
		p = *input + strcspn(*input, "{;\n");

		while (p > *input && isspace(p[-1]))
			p--;

		if (p - *input >= (ssize_t)sizeof(buf))
			return parse_error("Value too long");

		buflen = p - *input;
		memcpy(buf, *input, buflen);

		*input = p;
	}

	switch (prop->type) {
	case STRING:
		if (!buflen)
			return parse_error("Expecting non-empty value");

		char_ptr(prop, base) = strdup(buf);

		break;

	case BOOLEAN:
		if (!buflen ||
		    !strcmp(buf, "true") || !strcmp(buf, "yes") ||
		    !strcmp(buf, "on") || !strcmp(buf, "enabled"))
			bool_ptr(prop, base) = true;
		else if (!strcmp(buf, "false") || !strcmp(buf, "no") ||
		    !strcmp(buf, "off") || !strcmp(buf, "disabled"))
			bool_ptr(prop, base) = false;
		else
			return parse_error("Expecting 'true', 'yes', 'on', 'enabled', 'false', 'no', 'off' or 'disabled'");

		break;

	case INTEGER:
		n = strtol(buf, &e, 0);

		if (e == buf || *e)
			return parse_error("Expecting number");

		int_ptr(prop, base) = n;

		break;

	case NESTED_SINGLE:
		if (char_ptr(prop, base))
			return parse_error("The '%s' property may only appear once within this block", prop->name);

		/* fall through */

	case NESTED_MULTIPLE:
		obj = config_alloc_object(prop->nested, buflen ? buf : NULL);

		if (!obj)
			return false;

		if (!config_parse_block(input, prop->nested, obj)) {
			config_free_object(prop->nested, obj);

			return false;
		}

		if (prop->type == NESTED_SINGLE)
			char_ptr(prop, base) = (char *)obj;
		else
			list_add_tail((struct list_head *)obj, list_ptr(prop, base));

		return true;
	}

	return skipchar(input, ';') ? true : parse_error("Expecting ';'");
}

static bool
config_parse_property(const char **input, const config_block_t *spec, void *base)
{
	const config_prop_t *prop;
	const char *p;

	skipws(input);

	p = *input + strcspn(*input, ";} \t\n");

	if (p == *input)
		return parse_error("Expecting property");

	for (prop = spec->properties; prop->name; prop++) {
		if (!strspncmp(*input, p, prop->name)) {
			*input = p;

			return config_parse_value(input, prop, base);
		}
	}

	return parse_error("Unrecognized property '%.*s'", (int)(p - *input), *input);
}

static bool
config_parse_block(const char **input, const config_block_t *spec, void *base)
{
	const char *off = *input, *p;

	if (skipchar(input, '{')) {
		while (!skipchar(input, '}'))
			if (!config_parse_property(input, spec, base))
				return false;
	}
	else if (!skipchar(input, ';')) {
		return parse_error("Expecting '{' or ';'");
	}

	if (spec->validate) {
		p = *input;
		*input = off;

		if (!spec->validate(base))
			return false;

		*input = p;
	}

	return true;
}

static void
print_error_pos(const char *input, const char *off)
{
	size_t line, byte;
	const char *p;

	for (line = 1, byte = 1, p = input; p != off; p++) {
		if (*p == '\n') {
			input = p + 1;
			byte = 1;
			line++;
		}
	}

	uwsd_log_err(NULL, "In line %zu, byte %zu.", line, byte);
	uwsd_log_err(NULL, "Near here:");
	uwsd_log_err(NULL, "  `%.*s`", (int)strcspn(input, "\n"), input);
}


static bool
parse_protocol_match(void *obj, const char *label)
{
	uwsd_match_t *match = obj;

	if (!strcasecmp(label, "http"))
		match->data.protocol = UWSD_PROTOCOL_HTTP;
	else if (!strcasecmp(label, "ws"))
		match->data.protocol = UWSD_PROTOCOL_WS;
	else
		return parse_error("Unrecognized protocol, expect either 'http' or 'ws'");

	match->type = UWSD_MATCH_PROTOCOL;

	return true;
}

static bool
parse_hostname_match(void *obj, const char *label)
{
	uwsd_match_t *match = obj;

	if (!label || !*label)
		return parse_error("Expecting hostname value for 'match-hostname' property");

	match->type = UWSD_MATCH_HOSTNAME;
	match->data.value = xstrdup(label);

	return true;
}

static bool
parse_path_match(void *obj, const char *label)
{
	uwsd_match_t *match = obj;

	if (!label || *label != '/')
		return parse_error("Expecting absolute path value for 'match-path' property");

	match->type = UWSD_MATCH_PATH;
	match->data.value = xstrdup(label);

	return true;
}

static bool
check_path(const char *path, bool directory, char **dest)
{
	struct stat s;

	if (!path || !*path)
		return parse_error("Expecting path value");

	if (stat(path, &s))
		return parse_error("Unable to stat '%s': %m", path);

	if (!directory && !S_ISREG(s.st_mode))
		return parse_error("Path '%s' exists but does not point to a regular file", path);

	if (directory && !S_ISDIR(s.st_mode))
		return parse_error("Path '%s' exists but does not point to a directory", path);

	*dest = realpath(path, NULL);

	if (!*dest)
		return parse_error("Unable to resolve absolute path of '%s': %m", path);

	return true;
}

static bool
parse_serve_file(void *obj, const char *label)
{
	uwsd_action_t *action = obj;

	action->type = UWSD_ACTION_FILE;

	return check_path(label, false, &action->data.file);
}

static bool
parse_serve_directory(void *obj, const char *label)
{
	uwsd_action_t *action = obj;

	action->type = UWSD_ACTION_DIRECTORY;

	return check_path(label, true, &action->data.directory);
}

static bool
parse_run_script(void *obj, const char *label)
{
	uwsd_action_t *action = obj;
	char *path = NULL;
	bool rv;

	action->type = UWSD_ACTION_SCRIPT;
	rv = check_path(label, false, &path) && uwsd_script_init(action, path);

	free(path);

	return rv;
}

static bool
parse_use_backend(void *obj, const char *label)
{
	uwsd_action_t *action = obj;
	uwsd_backend_t *backend;

	action->type = UWSD_ACTION_BACKEND;

	list_for_each_entry(backend, &config->backends, list)
		if (!strcmp(backend->name, label))
			action->data.action = backend->default_action;

	if (!action->data.action)
		return parse_error("Unknown backend '%s' referenced by 'use-backend' property", label);

	return true;
}

static bool
parse_hostname_port(const char *label, const char *prop, char **hostname, uint16_t *port)
{
	int labellen, n;
	const char *p;
	char *e;

	if (!label)
		return parse_error("Expecting hostname:port value for '%s' property", prop);

	if (*label == '[') {
		p = strchr(label, ']');

		if (!p)
			return parse_error("Invalid IPv6 address literal for '%s' property", prop);

		labellen = (p - label) - 1;
		label++;

		if (p[1] != ':')
			return parse_error("Missing port value for '%s' property", prop);
	}
	else {
		p = strchr(label, ':');

		if (!p)
			return parse_error("Missing port value for '%s' property", prop);

		labellen = p - label;
	}

	n = strtol(++p, &e, 10);

	if (e == p || *e || n < 0 || n > 65535)
		return parse_error("Invalid port for '%s' property", prop);

	*port = n;
	xasprintf(hostname, "%.*s", labellen, label);

	return true;
}

static bool
parse_proxy_common(void *obj, const char *label, uwsd_action_type_t type, const char *prop)
{
	uwsd_action_t *action = obj;

	action->type = type;

	/* set default timeouts */
	action->data.proxy.connect_timeout = 10000;
	action->data.proxy.transfer_timeout = 10000;
	action->data.proxy.idle_timeout = 60000;

	return parse_hostname_port(label, prop,
		&action->data.proxy.hostname,
		&action->data.proxy.port);
}

static bool
parse_proxy_tcp(void *obj, const char *label)
{
	return parse_proxy_common(obj, label, UWSD_ACTION_TCP_PROXY, "proxy-tcp");
}

static bool
parse_proxy_udp(void *obj, const char *label)
{
	return parse_proxy_common(obj, label, UWSD_ACTION_UDP_PROXY, "proxy-udp");
}

static bool
parse_proxy_unix(void *obj, const char *label)
{
	return parse_proxy_common(obj, label, UWSD_ACTION_UNIX_PROXY, "proxy-unix");
}

static bool
validate_action(void *obj)
{
	uwsd_action_t *action = obj;
	struct stat s;

	switch (action->type) {
	case UWSD_ACTION_FILE:
		if (stat(action->data.file, &s))
			return parse_error("Failed to stat '%s': %m", action->data.file);

		if (!S_ISREG(s.st_mode))
			return parse_error("Path '%s' exists but is not a regular file", action->data.file);

		break;

	case UWSD_ACTION_DIRECTORY:
		if (stat(action->data.file, &s))
			return parse_error("Failed to stat '%s': %m", action->data.directory);

		if (!S_ISDIR(s.st_mode))
			return parse_error("Path '%s' exists but is not a directory", action->data.directory);

		break;

	case UWSD_ACTION_SCRIPT:
		break;

	case UWSD_ACTION_TCP_PROXY:
	case UWSD_ACTION_UDP_PROXY:
	case UWSD_ACTION_UNIX_PROXY:
		if (action->data.proxy.connect_timeout < 1)
			return parse_error("Invalid connect-timeout");

		if (action->data.proxy.transfer_timeout < 1)
			return parse_error("Invalid transfer-timeout");

		if (action->data.proxy.idle_timeout < 1)
			return parse_error("Invalid idle-timeout");

		break;

	case UWSD_ACTION_BACKEND:
		break;
	}

	return true;
}

static void
free_action(void *obj)
{
	uwsd_action_t *action = obj;

	switch (action->type) {
	case UWSD_ACTION_FILE:       return free(action->data.file);
	case UWSD_ACTION_DIRECTORY:  return free(action->data.directory);
	case UWSD_ACTION_SCRIPT:     return uwsd_script_free(action);
	case UWSD_ACTION_TCP_PROXY:  return free(action->data.proxy.hostname);
	case UWSD_ACTION_UDP_PROXY:  return free(action->data.proxy.hostname);
	case UWSD_ACTION_UNIX_PROXY: return free(action->data.proxy.hostname);
	case UWSD_ACTION_BACKEND:    return;
	}
}

static void
free_match(void *obj)
{
	uwsd_match_t *match = obj;

	switch (match->type) {
	case UWSD_MATCH_PATH:     return free(match->data.value);
	case UWSD_MATCH_HOSTNAME: return free(match->data.value);
	default:                  break;
	}
}


static bool
parse_auth_basic(void *obj, const char *label)
{
	uwsd_auth_t *auth = obj;

	auth->type = UWSD_AUTH_BASIC;
	auth->data.basic.realm = xstrdup(label ? label : "Protected area");

	return true;
}

static bool
parse_auth_mtls(void *obj, const char *label)
{
	uwsd_auth_t *auth = obj;

	auth->type = UWSD_AUTH_MTLS;

	if (label)
		return parse_error("Value not allowed for 'auth-mtls' property");

	return true;
}

static bool
validate_auth(void *obj)
{
	uwsd_auth_t *auth = obj;

	switch (auth->type) {
	case UWSD_AUTH_BASIC:
		if (!auth->data.basic.username)
			return parse_error("Require property 'username' for 'auth-basic'");

		if (!auth->data.basic.password && !auth->data.basic.lookup_shadow)
			return parse_error("Require property 'password' or 'lookup-shadow' for 'auth-basic'");

		if (auth->data.basic.password && auth->data.basic.lookup_shadow)
			return parse_error("Properties 'password' and 'lookup-shadow' are exclusive");

		break;

	case UWSD_AUTH_MTLS:
		break;
	}

	return true;
}

static void
free_auth(void *obj)
{
	uwsd_auth_t *auth = obj;

	switch (auth->type) {
	case UWSD_AUTH_BASIC:
		free(auth->data.basic.realm);
		break;

	case UWSD_AUTH_MTLS:
		break;
	}
}


static bool
parse_backend(void *obj, const char *label)
{
	uwsd_backend_t *backend = obj;

	if (!label || !*label)
		return parse_error("Expecting name for 'backend' property");

	backend->name = xstrdup(label);

	return true;
}

static bool
validate_backend(void *obj)
{
	uwsd_backend_t *backend = obj;
	uwsd_backend_t *other;

	if (!backend->default_action)
		return parse_error("Backend declares no action directive");

	if (backend->default_action->type == UWSD_ACTION_BACKEND)
		return parse_error("The 'use-backend' property may not be used within `backend` directives");

	list_for_each_entry(other, &config->backends, list)
		if (other != backend && !strcmp(other->name, backend->name))
			return parse_error("Name '%s' already used by another backend directive", backend->name);

	return true;
}

static void
free_backend(void *obj)
{
	uwsd_backend_t *backend = obj;

	free(backend->name);
}


static bool
parse_listen(void *obj, const char *label)
{
	uwsd_listen_t *listen = obj;
	char *hostname;
	uint16_t port;
	bool rv;

	/* set default timeouts */
	listen->request_timeout = 1000;
	listen->transfer_timeout = 10000;
	listen->idle_timeout = 60000;

	if (!parse_hostname_port(label, "listen", &hostname, &port))
		return false;

	rv = uwsd_listen_init(listen, hostname, port);

	free(hostname);

	return rv;
}

static bool
validate_listen(void *obj)
{
	uwsd_listen_t *listen = obj;

	if (listen->request_timeout < 1)
		return parse_error("Invalid request-timeout");

	if (listen->transfer_timeout < 1)
		return parse_error("Invalid transfer-timeout");

	if (listen->idle_timeout < 1)
		return parse_error("Invalid idle-timeout");

	if (!listen->default_action && list_empty(&listen->matches))
		return parse_error("Listen declares neither action nor match directives");

	return true;
}

static void
free_listen(void *obj)
{
	uwsd_listen_t *listen = obj;

	uwsd_listen_free(listen);
}


static bool
validate_ssl(void *obj)
{
	uwsd_ssl_t *ssl = obj;

	return uwsd_ssl_ctx_init(ssl);
}

static void
free_ssl(void *obj)
{
	uwsd_ssl_t *ssl = obj;

	return uwsd_ssl_ctx_free(ssl);
}


__hidden bool
uwsd_config_parse(const char *file)
{
	const char *off;
	struct stat s;
	char *input;
	FILE *fp;

	if (stat(file, &s)) {
		sys_perror("Unable to stat() configuration file '%s'", file);

		return false;
	}

	fp = fopen(file, "r");

	if (!fp) {
		sys_perror("Unable to open configuration file '%s'", file);

		return false;
	}

	input = xalloc(s.st_size + 1);

	fread(input, 1, s.st_size, fp);
	fclose(fp);

	off = (const char *)input;
	config = config_alloc_object(&toplevel_spec, NULL);

	do {
		if (!config_parse_property(&off, &toplevel_spec, config)) {
			config_free_object(&toplevel_spec, config);
			print_error_pos(input, off);
			free(input);

			return false;
		}
	} while (*off != '\0');

	free(input);

	return true;
}
