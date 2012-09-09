/*
 * libJUNOS - src/netrc.c
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
 * Access .netrc information.
 */

#include "junos.h"

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <strings.h>

/*
 * private data structures
 */

enum {
	TOKEN_NONE = 0,
	TOKEN_MACHINE,
	TOKEN_LOGIN,
	TOKEN_PASSWORD,
	TOKEN_ACCOUNT,
	TOKEN_MACDEF,
};

struct junos_netrc {
	char *filename;

	junos_netrc_entry_t *entries;
	size_t               entries_num;
};

/*
 * private helper functions
 */

static int
netrc_add_machine(junos_netrc_t *netrc)
{
	junos_netrc_entry_t *tmp;

	tmp = realloc(netrc->entries, netrc->entries_num + 1);
	if (! tmp)
		return -1;

	netrc->entries = tmp;
	++netrc->entries_num;

	memset(netrc->entries + (netrc->entries_num - 1), 0,
			sizeof(*netrc->entries));
	return 0;
} /* netrc_add_machine */

static int
netrc_set_value(junos_netrc_t *netrc, int token, char *value)
{
	junos_netrc_entry_t *entry;
	char **target = NULL;

	if (! netrc->entries_num)
		return -1;

	entry = netrc->entries + (netrc->entries_num - 1);

	switch (token) {
		case TOKEN_NONE: /* fall thru */
		case TOKEN_MACDEF: /* fall thru */
		case TOKEN_ACCOUNT:
			break;
		case TOKEN_MACHINE:
			target = &entry->machine;
			break;
		case TOKEN_LOGIN:
			target = &entry->login;
			break;
		case TOKEN_PASSWORD:
			target = &entry->password;
			break;
	}

	if (target) {
		if (*target)
			free(*target);
		*target = strdup(value);
	}
	return 0;
} /* netrc_set_value */

static int
netrc_parse_line(char *line, junos_netrc_t *netrc, int *last_token)
{
	char *lasts_ptr = NULL;
	char *token;

	if ((*last_token == TOKEN_MACDEF) && (line[0] != '\0'))
		return 0; /* skip line */

	while ((token = strtok_r(line, " \t\r\n", &lasts_ptr))) {
		line = NULL;

		if (*last_token != TOKEN_NONE) {
			netrc_set_value(netrc, *last_token, token);
			*last_token = TOKEN_NONE;
		}
		else if (! strcasecmp(token, "machine")) {
			*last_token = TOKEN_MACHINE;
			if (netrc_add_machine(netrc))
				return -1;
		}
		else if (! strcasecmp(token, "default")) {
			*last_token = TOKEN_NONE;
			if (netrc_add_machine(netrc))
				return -1;
		}
		else if (! strcasecmp(token, "login"))
			*last_token = TOKEN_LOGIN;
		else if (! strcasecmp(token, "password"))
			*last_token = TOKEN_PASSWORD;
		else if (! strcasecmp(token, "account"))
			*last_token = TOKEN_ACCOUNT;
		else if (! strcasecmp(token, "macdef")) {
			*last_token = TOKEN_MACDEF;
			return 0;
		}
	}
	return 0;
} /* netrc_parse_line */

static int
netrc_read(FILE *fh, junos_netrc_t *netrc)
{
	char  line_buf[1024];
	char *line;

	int status;
	int last_token = TOKEN_NONE;

	while ((line = fgets(line_buf, sizeof(line_buf), fh)))
		if ((status = netrc_parse_line(line, netrc, &last_token)))
			return status;

	if (! feof(fh))
		return -1;
	return 0;
} /* netrc_read */

/*
 * public API
 */

junos_netrc_t *
junos_netrc_read(char *filename)
{
	char  buf[1024];
	FILE *fh;

	junos_netrc_t *netrc;

	if (! filename) {
		char *home_dir = getenv("HOME");
		if (! home_dir) {
			dprintf("Failed to determine home directory\n");
			return NULL;
		}

		snprintf(buf, sizeof(buf), "%s/.netrc", home_dir);
		filename = buf;
	}

	fh = fopen(filename, "r");
	if (! fh) {
		dprintf("Failed to open '%s'\n", filename);
		return NULL;
	}

	netrc = calloc(1, sizeof(*netrc));
	if (netrc)
		netrc->filename = strdup(filename);

	if ((! netrc) || (! netrc->filename)) {
		dprintf("Failed to allocate libJUNOS netrc object\n");
		fclose(fh);
		junos_netrc_free(netrc);
		return NULL;
	}

	if (netrc_read(fh, netrc)) {
		dprintf("Failed to parse .netrc\n");
		fclose(fh);
		junos_netrc_free(netrc);
		return NULL;
	}

	fclose(fh);
	return netrc;
} /* junos_netrc_read */

void
junos_netrc_free(junos_netrc_t *netrc)
{
	size_t i;

	if (! netrc)
		return;

	if (netrc->filename)
		free(netrc->filename);

	for (i = 0; i < netrc->entries_num; ++i) {
		junos_netrc_entry_t *entry = netrc->entries + i;

		if (entry->machine)
			free(entry->machine);
		if (entry->login)
			free(entry->login);
		if (entry->password)
			free(entry->password);
	}
	free(netrc->entries);
	free(netrc);
} /* junos_netrc_free */

const junos_netrc_entry_t *
junos_netrc_lookup(junos_netrc_t *netrc, char *hostname)
{
	size_t i;

	if ((! netrc) || (! hostname))
		return NULL;

	for (i = 0; i < netrc->entries_num; ++i) {
		junos_netrc_entry_t *entry = netrc->entries + i;

		if ((! entry->machine) || (! strcasecmp(hostname, entry->machine)))
			return entry;
	}
	return NULL;
} /* junos_netrc_lookup */

/* vim: set tw=78 sw=4 ts=4 noexpandtab : */

