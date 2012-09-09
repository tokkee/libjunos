/*
 * libJUNOS - src/access_ssh.c
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
 * SSH access backend for the JUNOS object.
 */

#include "junos.h"

#include <errno.h>

#include <libssh2.h>

#include <sys/socket.h>
#include <netdb.h>

#include <stdlib.h>
#include <unistd.h>

/*
 * private data structures
 */

struct junos_ssh_access {
	junos_t *junos;

	char *hostname;
	char *username;
	char *password;

	struct addrinfo ai;
	int sock_fd;

	LIBSSH2_SESSION *session;
	LIBSSH2_CHANNEL *channel;

	char *banner;
};

/*
 * private helper functions
 */

static void
ssh_set_error(junos_ssh_access_t *ssh, int type, int error,
		char *msg_prefix, ...)
{
	va_list ap;

	if (! ssh)
		return;

	va_start(ap, msg_prefix);
	junos_set_verror(ssh->junos, type, error, msg_prefix, ap);
	va_end(ap);
} /* ssh_set_error */

static int
ssh_select(junos_ssh_access_t *ssh)
{
	int direction;

	fd_set fd;
	fd_set *read_fds  = NULL;
	fd_set *write_fds = NULL;

	struct timeval timeout;

	timeout.tv_sec  = 10;
	timeout.tv_usec = 0;

	FD_ZERO(&fd);
	FD_SET(ssh->sock_fd, &fd);

	direction = libssh2_session_block_directions(ssh->session);

	if (direction & LIBSSH2_SESSION_BLOCK_INBOUND)
		read_fds = &fd;

	if (direction & LIBSSH2_SESSION_BLOCK_OUTBOUND)
		write_fds = &fd;

	return select(ssh->sock_fd + 1, read_fds, write_fds,
			/* error_fds = */ NULL, &timeout);
} /* ssh_select */

static int
ssh_connect(junos_ssh_access_t *ssh)
{
	int status;

	struct addrinfo *ai;
	struct addrinfo *ai_ptr;
	struct addrinfo  ai_hints;

	int have_error = 0;

	memset(&ai_hints, 0, sizeof(ai_hints));
	ai_hints.ai_flags    = 0;
	ai_hints.ai_family   = AF_UNSPEC;
	ai_hints.ai_socktype = SOCK_STREAM;
	ai_hints.ai_protocol = IPPROTO_TCP;

	status = getaddrinfo(ssh->hostname, /* servname = */ "22",
			&ai_hints, &ai);
	if (status) {
		ssh_set_error(ssh, JUNOS_GAI_ERROR, status,
				"Failed to resolve hostname '%s'", ssh->hostname);
		return -1;
	}

	for (ai_ptr = ai; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
		ssh->sock_fd = socket(ai_ptr->ai_family, ai_ptr->ai_socktype,
				ai_ptr->ai_protocol);
		if (ssh->sock_fd < 0) {
			ssh_set_error(ssh, JUNOS_SYS_ERROR, errno,
					"Failed to open socket");
			have_error = 1;
			continue;
		}

		status = connect(ssh->sock_fd, (struct sockaddr *)ai_ptr->ai_addr,
				ai_ptr->ai_addrlen);
		if (status) {
			ssh_set_error(ssh, JUNOS_SYS_ERROR, errno,
					"Failed to connect to host '%s'", ssh->hostname);
			shutdown(ssh->sock_fd, SHUT_RDWR);
			close(ssh->sock_fd);
			ssh->sock_fd = -1;
			have_error = 1;
			continue;
		}

		/* succeeded to connect */
		ssh->ai = *ai_ptr;
		break;
	}

	if (ai_ptr && have_error)
		junos_clear_error(ssh->junos);
	else if (! ai_ptr) /* use error set above */
		return -1;

	freeaddrinfo(ai);
	return 0;
} /* ssh_connect */

static int
ssh_authenticate_password(junos_ssh_access_t *ssh)
{
	int status;

	while ((status = libssh2_userauth_password_ex(ssh->session,
					ssh->username, (unsigned int)strlen(ssh->username),
					ssh->password, (unsigned int)strlen(ssh->password),
					/* passwd_change_cb = */ NULL)) == LIBSSH2_ERROR_EAGAIN)
		/* retry */;

	if (status) {
		ssh_set_error(ssh, JUNOS_ACCESS_ERROR, status,
				"Password authentication failed for user '%s'",
				ssh->username);
		return -1;
	}
	return 0;
} /* ssh_authenticate_password */

static int
ssh_authenticate_pubkey(junos_ssh_access_t *ssh)
{
	int status;

	char  ssh_pub_key[256];
	char  ssh_priv_key[256];

	char *home_dir;

	home_dir = getenv("HOME");
	if (! home_dir) {
		ssh_set_error(ssh, JUNOS_SYS_ERROR, errno,
				"Failed to determine home directory");
		return -1;
	}

	snprintf(ssh_pub_key, sizeof(ssh_pub_key) - 1,
			"%s/.ssh/id_rsa.pub", home_dir);
	ssh_pub_key[sizeof(ssh_pub_key) - 1] = '\0';
	snprintf(ssh_priv_key, sizeof(ssh_priv_key) - 1,
			"%s/.ssh/id_rsa", home_dir);
	ssh_priv_key[sizeof(ssh_priv_key) - 1] = '\0';

	while ((status = libssh2_userauth_publickey_fromfile_ex(ssh->session,
					ssh->username, (unsigned int)strlen(ssh->username),
					ssh_pub_key, ssh_priv_key,
					/* passphrase = */ "")) == LIBSSH2_ERROR_EAGAIN)
		/* retry */;

	if (status) {
		ssh_set_error(ssh, JUNOS_ACCESS_ERROR, status,
				"Public key authentication failed for user '%s'",
				ssh->username);
		return -1;
	}
	return 0;
} /* ssh_authenticate_pubkey */

static int
ssh_authenticate(junos_ssh_access_t *ssh)
{
	if (ssh->password && strlen(ssh->password))
		return ssh_authenticate_password(ssh);
	else
		return ssh_authenticate_pubkey(ssh);
	return -1;
} /* ssh_authenticate */

static void
ssh_access_disconnect(junos_ssh_access_t *ssh, char *msg)
{
	int status;

	if (! ssh)
		return;

	if (! msg)
		msg = "SSH session terminated";

	if (ssh->channel) {
		while ((status = libssh2_channel_close(ssh->channel)) == LIBSSH2_ERROR_EAGAIN)
			ssh_select(ssh);

		libssh2_channel_free(ssh->channel);
		ssh->channel = NULL;
	}

	if (ssh->session) {
		libssh2_session_disconnect(ssh->session, msg);
		libssh2_session_free(ssh->session);
		ssh->session = NULL;
	}

	if (ssh->sock_fd >= 0) {
		shutdown(ssh->sock_fd, SHUT_RDWR);
		close(ssh->sock_fd);
		ssh->sock_fd = -1;
	}

	if (ssh->banner)
		free(ssh->banner);
	ssh->banner = NULL;
} /* ssh_access_disconnect */

static void
ssh_access_free(junos_ssh_access_t *ssh, char *msg)
{
	ssh_access_disconnect(ssh, msg);

	if (ssh->hostname)
		free(ssh->hostname);
	if (ssh->username)
		free(ssh->username);
	if (ssh->password)
		free(ssh->password);
	ssh->hostname = ssh->username = ssh->password = NULL;

	free(ssh);
} /* ssh_access_free */

/*
 * public API
 */

junos_ssh_access_t *
junos_ssh_new(junos_t *junos)
{
	junos_ssh_access_t *ssh;

	if (! junos) {
		dprintf("SSH: Missing JUNOS object\n");
		return NULL;
	}

	ssh = calloc(1, sizeof(*ssh));
	if (! ssh) {
		junos_set_error(junos, JUNOS_SYS_ERROR, errno,
				"Failed to allocate a new JUNOS SSH object");
		return NULL;
	}

	ssh->junos = junos;

	ssh->hostname = junos_get_hostname(junos);
	if (ssh->hostname)
		ssh->hostname = strdup(ssh->hostname);
	ssh->username = junos_get_username(junos);
	if (ssh->username)
		ssh->username = strdup(ssh->username);
	ssh->password = junos_get_password(junos);
	if (ssh->password)
		ssh->password = strdup(ssh->password);

	if ((! ssh->hostname) || (! ssh->username)) {
		ssh_set_error(ssh, JUNOS_SYS_ERROR, errno,
				"Failed to duplicate hostname/username strings");
		ssh_access_free(ssh, "Internal error: strdup failed");
		return NULL;
	}

	ssh->sock_fd = -1;

	ssh->session = NULL;
	ssh->channel = NULL;

	ssh->banner  = NULL;

	return ssh;
} /* junos_ssh_new */

int
junos_ssh_connect(junos_ssh_access_t *ssh)
{
	int status;
	const char *ssh_banner;

	if (! ssh)
		return -1;

	if (ssh_connect(ssh)) {
		ssh_access_disconnect(ssh, "Failed to connect to host");
		return -1;
	}

	ssh->session = libssh2_session_init();
	if (! ssh->session) {
		ssh_set_error(ssh, JUNOS_ACCESS_ERROR,
				libssh2_session_last_error(ssh->session, NULL, NULL, 0),
				"Failed to create libssh2 session object");
		ssh_access_disconnect(ssh, "Failed to create libssh2 session object");
		return -1;
	}

	/* do non-blocking I/O */
	libssh2_session_set_blocking(ssh->session, 0);

	while ((status = libssh2_session_handshake(ssh->session,
					ssh->sock_fd)) == LIBSSH2_ERROR_EAGAIN)
		/* retry */;

	if (status) {
		ssh_set_error(ssh, JUNOS_ACCESS_ERROR, status,
				"Failed to establish libssh2 session");
		ssh_access_disconnect(ssh, "Failed to establish libssh2 session");
		return -1;
	}

	/* XXX: verify host key */

	if (ssh_authenticate(ssh)) {
		ssh_access_disconnect(ssh, "Authentication failed");
		return -1;
	}

	while ((! (ssh->channel = libssh2_channel_open_session(ssh->session)))
			&& (libssh2_session_last_error(ssh->session,
					NULL, NULL, 0) == LIBSSH2_ERROR_EAGAIN))
		ssh_select(ssh);

	if (! ssh->channel) {
		ssh_set_error(ssh, JUNOS_ACCESS_ERROR,
				libssh2_session_last_error(ssh->session, NULL, NULL, 0),
				"Failed to open libssh2 session");
		ssh_access_disconnect(ssh, "Failed to open libssh2 session");
		return -1;
	}

	ssh_banner = libssh2_session_banner_get(ssh->session);
	if (ssh_banner) {
		dprintf("SSH: Successfully connected to host '%s': %s\n",
				ssh->hostname, ssh_banner);
		ssh->banner = strdup(ssh_banner);
	}

	while ((status = libssh2_channel_exec(ssh->channel,
					"junoscript")) == LIBSSH2_ERROR_EAGAIN)
		ssh_select(ssh);

	if (status) {
		ssh_set_error(ssh, JUNOS_ACCESS_ERROR, status,
				"Failed to start 'junoscript'");
		ssh_access_disconnect(ssh, "Failed to start 'junoscript'");
		return -1;
	}

	return 0;
} /* junos_ssh_connect */

int
junos_ssh_disconnect(junos_ssh_access_t *ssh)
{
	ssh_access_disconnect(ssh, NULL);
	return 0;
} /* junos_ssh_disconnect */

int
junos_ssh_free(junos_ssh_access_t *ssh)
{
	ssh_access_disconnect(ssh, NULL);
	ssh_access_free(ssh, NULL);
	return 0;
} /* junos_ssh_free */

ssize_t
junos_ssh_recv(junos_ssh_access_t *ssh, char *buf, size_t buf_len)
{
	ssize_t status;
	ssize_t count = 0;

	if ((! ssh) || (! buf)) {
		ssh_set_error(ssh, JUNOS_SYS_ERROR, EINVAL,
				"junos_ssh_recv() requires the 'ssh' and 'buf' arguments");
		return -1;
	}

	if (buf_len <= 1) {
		ssh_set_error(ssh, JUNOS_SYS_ERROR, EINVAL,
				"junos_ssh_recv() requires buffer >= 2 bytes");
		return -1;
	}

	while (42) {
		if ((size_t)count >= buf_len - 1)
			break;

		status = libssh2_channel_read(ssh->channel,
				buf + count, buf_len - (size_t)count - 1);

		if (! status)
			break;
		else if (status == LIBSSH2_ERROR_EAGAIN) {
			if (! count) {
				ssh_select(ssh);
				continue;
			}
			break;
		}
		else if (status < 0) {
			ssh_set_error(ssh, JUNOS_ACCESS_ERROR, (int)status,
					"Failed to read from remote host");
			if (! count)
				count = -1;
			break;
		}

		count += status;
	}

	if (count >= 0)
		buf[count] = '\0';

	return count;
} /* junos_ssh_recv */

ssize_t
junos_ssh_send(junos_ssh_access_t *ssh, char *buf, size_t buf_len)
{
	ssize_t status;
	ssize_t count = 0;

	if ((! ssh) || (! buf)) {
		ssh_set_error(ssh, JUNOS_SYS_ERROR, EINVAL,
				"junos_ssh_send() requires the 'ssh' and 'buf' arguments");
		return -1;
	}

	while (42) {
		if ((size_t)count >= buf_len)
			break;

		status = libssh2_channel_write(ssh->channel,
				buf + count, buf_len - (size_t)count);

		if (status == LIBSSH2_ERROR_EAGAIN)
			continue;
		else if (status < 0) {
			ssh_set_error(ssh, JUNOS_ACCESS_ERROR, (int)status,
					"Failed to write to remote host");
			if (! count)
				count = -1;
			break;
		}

		count += status;
	}

	return count;
} /* junos_ssh_send */

int
junos_set_ssh_error(junos_error_t *err, junos_ssh_access_t *ssh,
		char *msg_prefix, ...)
{
	va_list ap;
	int status;

	va_start(ap, msg_prefix);
	status = junos_set_ssh_verror(err, ssh, msg_prefix, ap);
	va_end(ap);

	return status;
} /* junos_set_ssh_error */

int
junos_set_ssh_verror(junos_error_t *err, junos_ssh_access_t *ssh,
		char *msg_prefix, va_list ap)
{
	char *err_msg = NULL;

	char prefix[1024];

	vsnprintf(prefix, sizeof(prefix), msg_prefix, ap);
	prefix[sizeof(prefix) - 1] = '\0';

	if (! ssh->session) {
		err->type  = JUNOS_ACCESS_ERROR;
		err->error = -1;
		snprintf(err->errmsg, sizeof(err->errmsg),
				"%s: SSH session not initialized", prefix);
		return 0;
	}

	err->type  = JUNOS_ACCESS_ERROR;
	err->error = libssh2_session_last_error(ssh->session, &err_msg,
			/* errmsg_len = */ NULL, /* want_buf = */ 0);

	if (! err->error) {
		junos_clear_error(ssh->junos);
		return 0;
	}

	snprintf(err->errmsg, sizeof(err->errmsg), "%s: %s", prefix, err_msg);
	return 0;
} /* ssh_set_verror */

/* error handling */

/* vim: set tw=78 sw=4 ts=4 noexpandtab : */

