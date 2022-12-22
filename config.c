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


uwsd_config_t *config;

typedef enum {
	STRING,
	BOOLEAN,
	INTEGER,
	BLOCK,
} config_type_t;

typedef struct config_block config_block_t;
typedef struct config_prop config_prop_t;


typedef struct config_prop {
	const char *name;
	config_type_t type;
	size_t offset;
	const config_block_t *nested;
	bool (*parse)(const config_prop_t *, void *, const char *);
} config_prop_t;

typedef struct config_block {
	struct list_head list;
	size_t size;
	bool (*init)(void *, const char *);
	bool (*validate)(void *);
	struct config_prop properties[];
} config_block_t;



static bool __attribute__((format(printf, 1, 0)))
parse_error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");

	return false;
}

static bool
add_certdir(const config_prop_t *spec, void *base, const char *dir)
{
	return uwsd_ssl_load_certificates(dir);
}

static bool
parse_endpoint(void *obj, const char *url)
{
	uwsd_endpoint_t *ep = obj;

	return uwsd_endpoint_url_parse(ep, url);
}

static bool
validate_endpoint(void *obj)
{
	uwsd_endpoint_t *ep = obj;
	uwsd_backend_t *be = uwsd_endpoint_backend_get(ep);

	if (!be)
		return parse_error("Endpoint has no upstream defined");

	if (!list_is_last(ep->upstream.next, &ep->upstream))
		return parse_error("Endpoint has multiple upstreams defined");

	switch (ep->type) {
	case UWSD_LISTEN_WS:
	case UWSD_LISTEN_WSS:
		if (be->type == UWSD_BACKEND_FILE)
			return parse_error("WebSocket endpoints require a script, unix, tcp or udp backend");

		break;

	case UWSD_LISTEN_HTTP:
	case UWSD_LISTEN_HTTPS:
		if (be->type == UWSD_BACKEND_UDP || be->type == UWSD_BACKEND_UNIX)
			return parse_error("HTTP endpoints require a script, file or tcp backend");

		break;
	}

	return true;
}

static bool
parse_upstream(void *obj, const char *url)
{
	uwsd_backend_t *be = obj;

	return uwsd_backend_url_parse(be, url);
}

static void *
property_ptr(const config_prop_t *prop, void *base)
{
	return (void *)((uintptr_t)base + prop->offset);
}

#define char_ptr(prop, base) *(char **)property_ptr(prop, base)
#define bool_ptr(prop, base) *(bool *)property_ptr(prop, base)
#define int_ptr(prop, base)  *(int *)property_ptr(prop, base)
#define list_ptr(prop, base) (struct list_head *)property_ptr(prop, base)


static const config_block_t upstream_spec = {
	.size = sizeof(uwsd_backend_t),
	.init = parse_upstream,
	.properties = {
		{ "binary", BOOLEAN,
			offsetof(uwsd_backend_t, binary), NULL, NULL },
		{ "idle-timeout", INTEGER,
			offsetof(uwsd_backend_t, idle_timeout), NULL, NULL },
		{ "connect-timeout", INTEGER,
			offsetof(uwsd_backend_t, connect_timeout), NULL, NULL },
		{ 0 }
	}
};

static const config_block_t endpoint_spec = {
	.size = sizeof(uwsd_endpoint_t),
	.init = parse_endpoint,
	.validate = validate_endpoint,
	.properties = {
		{ "upstream", BLOCK,
			offsetof(uwsd_endpoint_t, upstream), &upstream_spec, NULL },
		{ 0 }
	}
};

static const config_block_t toplevel_spec = {
	.size = sizeof(uwsd_config_t),
	.properties = {
		{ "certificate-directory", STRING,
			0, NULL, add_certdir },
		{ "endpoint", BLOCK,
			offsetof(uwsd_config_t, endpoints), &endpoint_spec, NULL },
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
		if (prop->type == BLOCK)
			INIT_LIST_HEAD((struct list_head *)((char *)obj + prop->offset));

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

	for (prop = spec->properties; prop->name; prop++) {
		switch (prop->type) {
		case STRING:
			free(char_ptr(prop, base));
			break;

		case BLOCK:
			list_for_each_safe(e, tmp, list_ptr(prop, base))
				config_free_object(prop->nested, e);
			break;

		default:
			break;
		}
	}

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

		while (p > *input && isspace(*p))
			p--;

		if (p - *input >= (ssize_t)sizeof(buf))
			return parse_error("Value too long");

		buflen = p - *input;
		memcpy(buf, *input, buflen);

		*input = p;
	}

	if (prop->parse) {
		if (!prop->parse(prop, base, buflen ? buf : NULL))
			return false;
	}
	else {
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

		case BLOCK:
			obj = config_alloc_object(prop->nested, buflen ? buf : NULL);

			if (!obj)
				return false;

			if (!config_parse_block(input, prop->nested, obj)) {
				config_free_object(prop->nested, obj);

				return false;
			}

			list_add_tail((struct list_head *)obj, list_ptr(prop, base));

			return true;
		}
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

	fprintf(stderr, "In line %zu, byte %zu.\n", line, byte);
	fprintf(stderr, "Near here:\n\n  `%.*s`\n\n", (int)strcspn(input, "\n"), input);
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
