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

#ifndef UWSD_CONFIG_H
#define UWSD_CONFIG_H

#include <stdbool.h>

#include <sys/un.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <ucode/vm.h>
#include <libubox/list.h>
#include <libubox/uloop.h>

#include "util.h"


typedef struct {
	char *certificate_directory;
	struct list_head listeners;
} uwsd_config_t;

extern uwsd_config_t *config;

__hidden bool uwsd_config_parse(const char *);

#endif /* UWSD_CONFIG_H */
