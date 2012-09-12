/*
 * libJUNOS - src/junos.c
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

#include "junos.h"

#include "libjunos_features.h"

#include <errno.h>

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <libssh2.h>

#include <libxml/tree.h>
#include <libxml/parser.h>

#ifndef LIBXML_PUSH_ENABLED
#	error "libxml has not been compiled with push parser support"
#endif

/*
 * private data structures
 */

struct junos {
	char *hostname;
	char *username;
	char *password;

	void *access;

	xmlParserCtxtPtr xml_ctx;

	junos_error_t err;
};

/*
 * private helper functions
 */

static int
meth_append_arg(junos_strbuf_t *body, junos_strbuf_t *attrs,
		int arg_type, va_list *ap)
{
	char *name = va_arg(*ap, char *);
	ssize_t status;

	if (! name) {
		errno = EINVAL;
		return -1;
	}

	switch (arg_type) {
		case JUNOS_ARG_TOGGLE: /* fall thru */
		case JUNOS_ARG_TOGGLE_NO:
			{
				int value = va_arg(*ap, int);
				if (value)
					status = junos_strbuf_sprintf(body,
							"    <%s/>\n", name);
				else if (arg_type == JUNOS_ARG_TOGGLE_NO)
					status = junos_strbuf_sprintf(body,
							"    <no-%s/>\n", name);
			}
			break;
		case JUNOS_ARG_STRING:
			{
				char *value = va_arg(*ap, char *);
				status = junos_strbuf_sprintf(body,
						"    <%s>%s</%s>\n", name,
						value ? value : "", name);
			}
			break;
		case JUNOS_ARG_INTEGER:
			{
				int value = va_arg(*ap, int);
				status = junos_strbuf_sprintf(body,
						"    <%s>%i</%s>\n",
						name, value, name);
			}
			break;
		case JUNOS_ARG_DOUBLE:
			{
				double value = va_arg(*ap, double);
				status = junos_strbuf_sprintf(body,
						"    <%s>%lf</%s>\n",
						name, value, name);
			}
			break;
		case JUNOS_ARG_DOM:
			{
				status = junos_strbuf_sprintf(body,
						"    %s\n", name);
			}
			break;
		case JUNOS_ATTR_STRING:
			{
				char *value = va_arg(*ap, char *);
				status = junos_strbuf_sprintf(attrs,
						" %s=\"%s\"",
						name, value ? value : "");
			}
			break;
		case JUNOS_ATTR_INTEGER:
			{
				int value = va_arg(*ap, int);
				status = junos_strbuf_sprintf(attrs,
						" %s=\"%s\"", name, value);
			}
			break;
		case JUNOS_ATTR_DOUBLE:
			{
				double value = va_arg(*ap, double);
				status = junos_strbuf_sprintf(attrs,
						" %s=\"%s\"", name, value);
			}
			break;
		default:
			errno = EINVAL;
			return -1;
			break;
	}
	if (status < 0)
		return -1;
	return 0;
} /* meth_append_arg */

static ssize_t
read_lines(junos_t *junos, char *buf, size_t buf_len)
{
	ssize_t count = 0;

	while (42) {
		ssize_t status;

		/* junos_ssh_recv requires at least two bytes */
		if (buf_len - 2 < (size_t)count) {
			dprintf("Receive buffer too small\n");
			break;
		}

		status = junos_ssh_recv(junos->access,
				buf + count, buf_len - (size_t)count);
		if (status < 0) {
			count = -1;
			break;
		}

		if (! status)
			if (count)
				break;
			/* else: retry */

		count += status;

		if (buf[count - 1] == '\n')
			break;
	}
	return count;
} /* read_line */

/*
 * public API
 */

int
junos_init(void)
{
	int status;

	status = libssh2_init(/* flags = */ 0);
	if (status < 0) {
		dprintf("Failed to initialize libssh2 (status %d)\n", status);
		return status;
	}

	LIBXML_TEST_VERSION;
	return 0;
} /* junos_init */

junos_t *
junos_new(char *hostname, char *username, char *password)
{
	junos_t *junos;

	if ((! hostname) || (! username))
		return NULL;

	junos = calloc(1, sizeof(*junos));
	if (! junos)
		return NULL;

	junos->hostname = strdup(hostname);
	junos->username = strdup(username);
	if (password)
		junos->password = strdup(password);

	if ((! junos->hostname) || (! junos->username)
			|| (password && (! junos->password))) {
		junos_free(junos);
		return NULL;
	}

	junos->access  = NULL;
	junos->xml_ctx = NULL;

	junos_clear_error(junos);
	return junos;
} /* junos_new */

char *
junos_get_hostname(junos_t *junos)
{
	if (! junos)
		return NULL;
	return junos->hostname;
} /* junos_get_hostname */

char *
junos_get_username(junos_t *junos)
{
	if (! junos)
		return NULL;
	return junos->username;
} /* junos_get_username */

char *
junos_get_password(junos_t *junos)
{
	if (! junos)
		return NULL;
	return junos->password;
} /* junos_get_password */

void
junos_free(junos_t *junos)
{
	if (! junos)
		return;

	junos_disconnect(junos);

	if (junos->hostname)
		free(junos->hostname);
	if (junos->username)
		free(junos->username);
	if (junos->password)
		free(junos->password);

	free(junos);
} /* junos_free */

int
junos_connect(junos_t *junos)
{
	char recv_buf[4096];
	ssize_t count = 0;
	ssize_t status;

	char *tmp;

	char js_handshake[] = "<?xml version=\"1.0\" encoding=\"us-ascii\"?>"
		"<junoscript version=\"1.0\" os=\"libJUNOS\">";

	if (! junos)
		return -1;

	junos->access = junos_ssh_new(junos);
	if (! junos->access)
		return -1;

	if (junos_ssh_connect(junos->access))
		return -1;

	while (42) {
		status = read_lines(junos, recv_buf + count,
				sizeof(recv_buf) - (size_t)count);
		if (status < 0)
			break;

		count += status;

		if ((tmp = strstr(recv_buf, "<?xml"))
				&& strstr(tmp, "<junoscript"))
			break;
	}

	dprintf("Header: %s", recv_buf);

	/* don't send the trailing null byte */
	status = junos_ssh_send(junos->access,
			js_handshake, sizeof(js_handshake) - 1);
	if (status != (ssize_t)sizeof(js_handshake) - 1) {
		dprintf("Failed to send JUNOScript handshake (status %d)\n",
				(int)status);
		return -1;
	}

	read_lines(junos, recv_buf, sizeof(recv_buf));
	dprintf(" ->  %s", recv_buf);
	return 0;
} /* junos_connect */

int
junos_disconnect(junos_t *junos)
{
	if (! junos)
		return -1;

	if (junos->access)
		junos_ssh_free(junos->access);
	junos->access = NULL;

	return 0;
} /* junos_disconnect */

xmlDocPtr
junos_invoke_method(junos_t *junos, const char *name, ...)
{
	junos_strbuf_t *method_buf;
	junos_strbuf_t *body_buf;
	junos_strbuf_t *attr_buf;

	char  *method_string;
	size_t method_len;
	char  *body_string;
	char  *attr_string;

	char recv_buf[4096];
	ssize_t status;

	int xml_status;
	xmlDocPtr doc;

	va_list ap;
	int arg_type;

	if ((! junos) || (! name)) {
		junos_set_error(junos, JUNOS_SYS_ERROR, EINVAL,
				"junos_invoke_method() requires the "
				"'junos' and 'name' arguments");
		return NULL;
	}

	if (! junos->access) {
		junos_set_error(junos, JUNOS_SYS_ERROR, EINVAL,
				"Please call junos_connect() before invoking a method");
		return NULL;
	}

	errno = 0;
	method_buf = junos_strbuf_new(1024);
	body_buf   = junos_strbuf_new(1024);
	attr_buf   = junos_strbuf_new(1024);

#define BUF_FREE() \
	do { \
		junos_strbuf_free(method_buf); \
		method_buf    = NULL; \
		method_string = NULL; \
		method_len    = 0;    \
		junos_strbuf_free(body_buf); \
		body_buf      = NULL; \
		body_string   = NULL; \
		junos_strbuf_free(attr_buf); \
		attr_buf      = NULL; \
		attr_string   = NULL; \
	} while (0)

	if ((! method_buf) || (! body_buf) || (! attr_buf)) {
		junos_set_error(junos, JUNOS_SYS_ERROR, errno,
				"Failed to allocate string buffers");
		BUF_FREE();
		return NULL;
	}

	va_start(ap, name);
	while ((arg_type = va_arg(ap, int)) != JUNOS_NO_ARGS) {
		if (meth_append_arg(body_buf, attr_buf, arg_type, &ap)) {
			BUF_FREE();
			junos_set_error(junos, JUNOS_SYS_ERROR, errno,
					"Failed to append argument (type %d) to method '%s'",
					arg_type, name);
			return NULL;
		}
	}
	va_end(ap);

	body_string = junos_strbuf_string(body_buf);
	attr_string = junos_strbuf_string(attr_buf);

	if (body_string[0])
		junos_strbuf_sprintf(method_buf,
				"<rpc>\n"
				"  <%s%s>\n%s"
				"  </%s>\n"
				"</rpc>",
				name, attr_string, body_string, name);
	else
		junos_strbuf_sprintf(method_buf,
				"<rpc>\n"
				"  <%s%s/>\n"
				"</rpc>",
				name, attr_string);

	method_string = junos_strbuf_string(method_buf);
	method_len    = junos_strbuf_len(method_buf);

	dprintf(" -> %s\n", method_string);
	status = junos_ssh_send(junos->access, method_string, method_len);

	if (status != (ssize_t)method_len) {
		dprintf("Failed to send method '%s' (status %d)\n",
				method_string, (int)status);
		BUF_FREE();
		return NULL;
	}

	BUF_FREE();

	errno = 0;
	junos->xml_ctx = xmlCreatePushParserCtxt(/* sax = */ NULL,
			/* user_data = */ NULL,
			/* chunk = */ NULL, /* size = */ 0,
			/* filename = */ NULL);
	if (! junos->xml_ctx) {
		junos_set_error(junos, JUNOS_SYS_ERROR, errno,
				"Failed to create XML parser context");
		return NULL;
	}

	while (42) {
		status = read_lines(junos, recv_buf, sizeof(recv_buf));
		if (status < 0)
			break;

		dprintf(" ->  %s", recv_buf);

		xml_status = xmlParseChunk(junos->xml_ctx, recv_buf, (int)status,
				/* terminate = */ 0);
		if (xml_status) {
			junos_set_error(junos, JUNOS_XML_ERROR, xml_status,
					"XML parsing failed");
			break;
		}

		if (strstr(recv_buf, "</rpc-reply>"))
			break;
	}

	/* finish parser */
	xmlParseChunk(junos->xml_ctx, "", 0, /* terminate = */ 1);

	doc = junos->xml_ctx->myDoc;
	if (xml_status || (! junos->xml_ctx->wellFormed)) {
		if ((! xml_status) && (! status))
			junos_set_error(junos, JUNOS_XML_ERROR, -1,
					"XML validation failed");
		if (status >= 0)
			status = -1;
	}

	xmlFreeParserCtxt(junos->xml_ctx);
	junos->xml_ctx = NULL;

	if (status < 0) {
		xmlFreeDoc(doc);
		return NULL;
	}

	return doc;
} /* junos_invoke_method */

/* error handling */

const char *
junos_get_errstr(junos_t *junos)
{
	if (! junos)
		return NULL;
	return junos->err.errmsg;
} /* junos_get_errstr */

void
junos_clear_error(junos_t *junos)
{
	junos_error_t no_error = JUNOS_NO_ERROR;

	if (! junos)
		return;

	junos->err = no_error;
} /* junos_clear_error */

int
junos_set_error(junos_t *junos, int type, int error,
		char *msg_prefix, ...)
{
	va_list ap;
	int status;

	va_start(ap, msg_prefix);
	status = junos_set_verror(junos, type, error, msg_prefix, ap);
	va_end(ap);

	return status;
} /* junos_set_error */

int
junos_set_verror(junos_t *junos, int type, int error,
		char *msg_prefix, va_list ap)
{
	junos_error_t *err;

	char errbuf[1024];
	const char *err_msg;

	char prefix[1024];

	int status = 0;

	if (! junos)
		return -1;

	err = &junos->err;

	err->type  = type;
	err->error = error;

	vsnprintf(prefix, sizeof(prefix), msg_prefix, ap);
	prefix[sizeof(prefix) - 1] = '\0';

	switch (type) {
		case JUNOS_OK:
			snprintf(err->errmsg, sizeof(err->errmsg),
					"i%s: success", prefix);
			break;
		case JUNOS_SYS_ERROR:
			{
				int failed = 0;

#if STRERROR_R_CHAR_P
				errbuf[0] = '\0';
				err_msg = strerror_r(error, errbuf, sizeof(errbuf));
				if (! err_msg)
					err_msg = errbuf;
				if (! err_msg[0])
					failed = 1;
#else /* STRERROR_R_CHAR_P */
				failed = strerror_r(error, errbuf, sizeof(errbuf));
				err_msg = errbuf;
#endif /* STRERROR_R_CHAR_P */

				if (failed)
					snprintf(err->errmsg, sizeof(err->errmsg),
							"%s: system error #%i", prefix, error);
				else
					snprintf(err->errmsg, sizeof(err->errmsg),
							"%s: %s", prefix, err_msg);
			}
			break;
		case JUNOS_GAI_ERROR:
			if (error == EAI_SYSTEM)
				return junos_set_error(junos, JUNOS_SYS_ERROR, error,
						"%s: network address translation failed", prefix);

			err_msg = gai_strerror(error);
			if (err_msg)
				snprintf(err->errmsg, sizeof(err->errmsg),
						"%s: %s", prefix, err_msg);
			else
				snprintf(err->errmsg, sizeof(err->errmsg),
						"%s: network address translation error #%i",
						prefix, error);
			break;
		case JUNOS_XML_ERROR:
			{
				xmlErrorPtr xml_err;

				if (! junos->xml_ctx) /* don't touch any error information */
					return 0;

				xml_err = xmlCtxtGetLastError(junos->xml_ctx);
				if (! xml_err)
					return 0;

				err->error = xml_err->code;
				snprintf(err->errmsg, sizeof(err->errmsg),
						"%s: %s", prefix, xml_err->message);
			}
			break;
		case JUNOS_ACCESS_ERROR:
			status = junos_set_ssh_error(err, junos->access,
					"%s", prefix);
			break;
		default:
			return -1;
			break;
	}

	err->errmsg[sizeof(err->errmsg) - 1] = '\0';
	dprintf("ERROR: %s\n", err->errmsg);

	return status;
} /* junos_set_verror */

/* features */

unsigned int
libjunos_version(void)
{
	return LIBJUNOS_VERSION;
} /* libjunos_version */

const char *
libjunos_version_string(void)
{
	return LIBJUNOS_VERSION_STRING;
} /* libjunos_version_string */

const char *
libjunos_version_extra(void)
{
	return LIBJUNOS_VERSION_EXTRA;
} /* libjunos_version_extra */

/* vim: set tw=78 sw=4 ts=4 noexpandtab : */

