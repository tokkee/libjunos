/*
 * libJUNOS - src/junosc.c
 * Copyright (C) 2012 Sebastian 'tokkee' Harl <sh@tokkee.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * A JUNOScript client application.
 */

#if HAVE_CONFIG_H
#	include "config.h"
#endif /* HAVE_CONFIG_H */

#include "junos.h"
#include "libjunos_features.h"

#if HAVE_LIBGEN_H
#	include <libgen.h>
#else /* HAVE_LIBGEN_H */
#	define basename(path) (path)
#endif /* ! HAVE_LIBGEN_H */

#include <stdio.h>
#include <stdlib.h>

#include <unistd.h>

static void
exit_usage(char *name, int status)
{
	printf(
"Usage: %s -H <host> [<options>] <method>\n"

"\nOptions:\n"
"  -H <host>    hostname to connect to\n"
"  -u <user>    username to connect with\n"
"  -p <pass>    password to connect with\n"
"  -n           do not use .netrc for username/password lookup\n"
"\n"
"  -h           display this help and exit\n"
"  -V           display the version number and copyright\n"

"\njunosc "LIBJUNOS_VERSION_STRING LIBJUNOS_VERSION_EXTRA", "PACKAGE_URL"\n",
basename(name));
	exit(status);
} /* exit_usage */

static void
exit_version(void)
{
	printf("junosc version "LIBJUNOS_VERSION_STRING LIBJUNOS_VERSION_EXTRA", "
			"built "BUILD_DATE"\n"
			"Copyright (C) 2012 "PACKAGE_MAINTAINER"\n"

			"\nThis is free software under the terms of the BSD license, see "
			"the source for\ncopying conditions. There is NO WARRANTY; not "
			"even for MERCHANTABILITY or\nFITNESS FOR A PARTICULAR "
			"PURPOSE.\n");
	exit(0);
} /* exit_version */

int
main(int argc, char **argv)
{
	junos_netrc_t *netrc;

	int use_netrc  = 1;

	char *hostname = NULL;
	char *username = NULL;
	char *password = NULL;

	char *method   = NULL;

	junos_t *junos;
	xmlDocPtr doc;

	while (42) {
		int opt = getopt(argc, argv, "H:u:p:nhV");

		if (-1 == opt)
			break;

		switch (opt) {
			case 'H':
				hostname = optarg;
				break;
			case 'u':
				username = optarg;
				break;
			case 'p':
				password = optarg;
				break;
			case 'n':
				use_netrc = 0;
				break;

			case 'h':
				exit_usage(argv[0], 0);
				break;
			case 'V':
				exit_version();
				break;
			default:
				exit_usage(argv[0], 1);
		}
	}

	if (! hostname) {
		fprintf(stderr, "Missing hostname\n");
		exit_usage(argv[0], 1);
	}

	if (optind != argc - 1) {
		fprintf(stderr, "Missing method name\n");
		exit_usage(argv[0], 1);
	}

	method = argv[optind];
	++optind;

	if (use_netrc
			&& (netrc = junos_netrc_read(/* filename = default */ NULL))) {
		const junos_netrc_entry_t *entry;

		entry = junos_netrc_lookup(netrc, hostname);
		if (entry) {
			if ((! username) && (entry->login)) {
				dprintf("Using username '%s' from netrc\n", entry->login);
				username = entry->login;
			}

			if ((! password) && (entry->password)) {
				dprintf("Using password from netrc\n");
				password = entry->password;
			}
		}
	}

	if (! username)
		username = getlogin();

	if (! username) {
		fprintf(stderr, "Missing username\n");
		if (netrc)
			junos_netrc_free(netrc);
		exit_usage(argv[0], 1);
	}

	if (junos_init()) {
		fprintf(stderr, "FATAL: Failed to initialize libJUNOS. Aborting.\n");
		exit(1);
	}

	junos = junos_new(hostname, username, password);
	if (! junos) {
		fprintf(stderr, "FATAL: Failed to create JUNOS object!\n");
		exit(1);
	}

	if (junos_connect(junos)) {
		fprintf(stderr, "Failed to connect: %s\n", junos_get_errstr(junos));
		junos_free(junos);
		exit(1);
	}

	junos_clear_error(junos);
	doc = junos_simple_method(junos, method);
	if (doc) {
		xmlDocFormatDump(stderr, doc, /* format = */ 1);
		xmlFreeDoc(doc);
	}
	else {
		fprintf(stderr, "Method failed: %s\n", junos_get_errstr(junos));
	}

	junos_disconnect(junos);
	junos_free(junos);

	if (netrc)
		junos_netrc_free(netrc);
	return 0;
} /* main */

/* vim: set tw=78 sw=4 ts=4 noexpandtab : */

