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

#include <stdbool.h>
#include <getopt.h>

#include "listen.h"
#include "client.h"
#include "ssl.h"
#include "config.h"
#include "log.h"


static struct option uwsd_options[] = {
	{ "config", required_argument, NULL, 0 },
	{ "log-priority", required_argument, NULL, 1 },
	{ "log-channel", required_argument, NULL, 2 },
	{ 0 }
};

static int
usage(void)
{
	fatal(
		"Usage: uwsd --config={file}\n\n"
	);

	return 1;
}

int
main(int argc, char **argv)
{
	int opt, option_index = 0;
	unsigned int channels = 0;

	uloop_init();

	while (true) {
		opt = getopt_long(argc, argv, "", uwsd_options, &option_index);

		if (opt == 0) {
			if (config)
				fatal("Option --config must be given only once");

			if (!uwsd_config_parse(optarg))
				exit(1);
		}
		else if (opt == 1) {
			if (!strcmp(optarg, "debug"))
				uwsd_logging_priority = UWSD_PRIO_DBG;
			else if (!strcmp(optarg, "info"))
				uwsd_logging_priority = UWSD_PRIO_INFO;
			else if (!strcmp(optarg, "warn"))
				uwsd_logging_priority = UWSD_PRIO_WARN;
			else if (!strcmp(optarg, "err"))
				uwsd_logging_priority = UWSD_PRIO_ERR;
			else
				fatal("Invalid log priority, expecting 'debug', 'info', 'warn' or 'err'");
		}
		else if (opt == 2) {
			if (!strcmp(optarg, "global"))
				channels |= (1 << UWSD_LOG_GLOBAL);
			else if (!strcmp(optarg, "http"))
				channels |= (1 << UWSD_LOG_HTTP);
			else if (!strcmp(optarg, "ws"))
				channels |= (1 << UWSD_LOG_WS);
			else if (!strcmp(optarg, "ssl"))
				channels |= (1 << UWSD_LOG_SSL);
			else
				fatal("Invalid log channel, expecting 'global', 'http', 'ws' or 'ssl'");
		}
		else if (opt == -1) {
			break;
		}
		else if (opt == '?') {
			return usage();
		}
	}

	if (!config && !uwsd_config_parse("/etc/uwsd/uwsd.conf"))
		exit(1);

	if (list_empty(&config->endpoints))
		fatal("No endpoints defined in configuration, aborting");

	if (channels)
		uwsd_logging_channels = channels;

	uloop_run();

	client_free_all();

	return 0;
}
