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


static struct option uwsd_options[] = {
	{ "endpoint", required_argument, NULL, 0 },
	{ "certdir",  required_argument, NULL, 1 },
	{ 0 }
};

static int
usage(void)
{
	fatal(
		"Usage: uwsd --endpoint={spec} [--endpoint={spec}...]\n\n"
		"Endpoint format:\n"
		"{ws,wss,http,https}://{host}[:{port}]/{path} \\\n"
		"	{tcp,udp,unix,script,file}:{host-or-path}[:{port}] \\\n"
		"	[{binary,text} [{protocol}]]"
	);

	return 1;
}

int
main(int argc, char **argv)
{
	bool has_endpoints = false, has_certificates = false, has_certdirs = false;
	int opt, option_index = 0;

	uloop_init();

	while (true) {
		opt = getopt_long(argc, argv, "", uwsd_options, &option_index);

		if (opt == 0) {
			has_endpoints = true;
			uwsd_endpoint_create(optarg);
		}
		else if (opt == 1) {
			has_certdirs = true;

			if (uwsd_ssl_load_certificates(optarg))
				has_certificates = true;
		}
		else if (opt == -1) {
			break;
		}
		else if (opt == '?') {
			return usage();
		}
	}

	if (!has_endpoints)
		return usage();

	if (uwsd_has_ssl_endpoints()) {
		if (!has_certdirs)
			has_certificates = uwsd_ssl_load_certificates("/etc/uwsd/certificates");

		if (!has_certificates) {
			fprintf(stderr, "SSL endpoints defined but no usable certificates loaded, aborting.\n");

			return 1;
		}
	}

	uloop_run();

	client_free_all();

	return 0;
}
