/*
 * libJUNOS - src/junos.h
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
 * Base object used to manage the connection to a JUNOS device.
 */

#ifndef JUNOS_H
#define JUNOS_H 1

#include <stdio.h>

#include <libxml/tree.h>

#if defined(DEBUG) && (! defined(NDEBUG))
#	define dprintf(...) fprintf(stderr, "LIBJUNOS DEBUG: "__VA_ARGS__)
#else
#	define dprintf(...) /* noop */
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * data types
 */

typedef struct junos junos_t;

/* string buffer */

typedef struct junos_strbuf junos_strbuf_t;

/* netrc */

typedef struct {
	char *machine;
	char *login;
	char *password;
	/* we don't care for 'account' or 'macdef' */
} junos_netrc_entry_t;

typedef struct junos_netrc junos_netrc_t;

/* access types */

typedef struct junos_ssh_access junos_ssh_access_t;

/* error information */

enum {
	JUNOS_OK = 0,
	JUNOS_SYS_ERROR,
	JUNOS_GAI_ERROR,
	JUNOS_XML_ERROR,
	JUNOS_ACCESS_ERROR
};

typedef struct {
	int  type;
	int  error;
	char errmsg[1024];
} junos_error_t;

#define JUNOS_NO_ERROR { JUNOS_OK, 0, "" }

/*
 * JUNOS object
 */

int
junos_init(void);

junos_t *
junos_new(char *hostname, char *username, char *password);

char *
junos_get_hostname(junos_t *junos);
char *
junos_get_username(junos_t *junos);
char *
junos_get_password(junos_t *junos);

int
junos_connect(junos_t *junos);

xmlDocPtr
junos_simple_method(junos_t *junos, const char *name);

int
junos_disconnect(junos_t *junos);

void
junos_free(junos_t *junos);

/*
 * string buffer
 */

junos_strbuf_t *
junos_strbuf_new(size_t size);

void
junos_strbuf_free(junos_strbuf_t *strbuf);

ssize_t
junos_strbuf_sprintf(junos_strbuf_t *strbuf, const char *fmt, ...);

ssize_t
junos_strbuf_vsprintf(junos_strbuf_t *strbuf, const char *fmt, va_list ap);

char *
junos_strbuf_string(junos_strbuf_t *strbuf);

size_t
junos_strbuf_len(junos_strbuf_t *strbuf);

/*
 * netrc
 */

junos_netrc_t *
junos_netrc_read(char *filename);

void
junos_netrc_free(junos_netrc_t *netrc);

const junos_netrc_entry_t *
junos_netrc_lookup(junos_netrc_t *netrc, char *hostname);

/*
 * error handling
 */

const char *
junos_get_errstr(junos_t *junos);

int
junos_set_error(junos_t *junos, int type, int error,
		char *msg_prefix, ...);
int
junos_set_verror(junos_t *junos, int type, int error,
		char *msg_prefix, va_list ap);

int
junos_set_ssh_error(junos_error_t *err, junos_ssh_access_t *ssh,
		char *msg_prefix, ...);
int
junos_set_ssh_verror(junos_error_t *err, junos_ssh_access_t *ssh,
		char *msg_prefix, va_list ap);

void
junos_clear_error(junos_t *junos);

/*
 * SSH
 */

junos_ssh_access_t *
junos_ssh_new(junos_t *junos);

int
junos_ssh_connect(junos_ssh_access_t *ssh);

ssize_t
junos_ssh_recv(junos_ssh_access_t *ssh, char *buf, size_t buf_len);

ssize_t
junos_ssh_send(junos_ssh_access_t *ssh, char *buf, size_t buf_len);

int
junos_ssh_disconnect(junos_ssh_access_t *ssh);

int
junos_ssh_free(junos_ssh_access_t *ssh);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ! JUNOS_H */

/* vim: set tw=78 sw=4 ts=4 noexpandtab : */

