/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-rpc-tls.c - TLS functionality (PSK and mTLS) to protect communication

   Copyright (C) 2013, NORDUnet A/S

   pkcs11-proxy is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   pkcs11-proxy is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the Gnome Library General Public License along with this
   library; see the file COPYING.LIB.  If not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

   Author: Fredrik Thulin <fredrik@thulin.net>
*/

#include "config.h"

#include "gck-rpc-private.h"
#include "gck-rpc-tls.h"

#include <sys/param.h>
#include <assert.h>

/* for file I/O */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <arpa/inet.h>

#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

/* TLS pre-shared key */
static char tls_psk_identity[1024] = { 0, };
static char tls_psk_key_filename[MAXPATHLEN] = { 0, };

static char *
_tls_trim_whitespace(char *str)
{
	char *end;

	while (*str && isspace((unsigned char)*str))
		str++;
	if (*str == '\0')
		return str;
	end = str + strlen(str) - 1;
	while (end > str && isspace((unsigned char)*end))
		end--;
	*(end + 1) = '\0';
	return str;
}

int
gck_rpc_tls_set_peer_host(GckRpcTlsState *state, const char *host)
{
	unsigned char buf[sizeof(struct in6_addr)];

	if (!state || !host || !host[0])
		return 0;

	snprintf(state->peer_host, sizeof(state->peer_host), "%s", host);
	state->peer_host_set = 1;
	state->peer_host_is_ip = 0;

	if (inet_pton(AF_INET, host, buf) == 1 || inet_pton(AF_INET6, host, buf) == 1)
		state->peer_host_is_ip = 1;

	return 1;
}
/* -----------------------------------------------------------------------------
 * LOGGING and DEBUGGING
 */
#ifndef DEBUG_OUTPUT
#define DEBUG_OUTPUT 0
#endif
#if DEBUG_OUTPUT
#define debug(x) gck_rpc_debug x
#else
#define debug(x)
#endif
#define warning(x) gck_rpc_warn x


/* -----------------------------------------------------------------------------
 * TLS-PSK (pre-shared key) functionality
 */

/* Utility function to decode a single hex char.
 *
 * Returns value as integer, or -1 on invalid hex char (not 0-9, a-f or A-F).
 */
static int
_tls_psk_to_hex(char val)
{
	if (val >= '0' && val <= '9')
		return val - '0';
	if (val >= 'a' && val <= 'f')
		return val - 'a' + 10;
	if (val >= 'A' && val <= 'F')
		return val - 'A' + 10;
	return -1;
}

/* Hex decode the key from an entry in the TLS-PSK key file. Entrys are of the form
 *
 *   identity:hex-key\n
 *
 * Logging debug/error messages here is a bit problematic since the key is sensitive
 * and should not be logged to syslog for example. This code avoids logging the key
 * part and only logs identity.
 *
 * Returns 0 on failure, number of bytes in hex-decoded key on success.
 */
static int
_tls_psk_decode_key(const char *identity, const char *hexkey, unsigned char *psk, unsigned int max_psk_len)
{
	int psk_len, i;

	/* check that length of the key is even */
	if ((strlen(hexkey) % 2) != 0) {
		warning(("un-even length TLS-PSK key"));
		return 0;
	}

	memset(psk, 0, max_psk_len);
	psk_len = 0;

	while (*hexkey && (psk_len < max_psk_len)) {
		/* decode first half of byte, check for errors */
		if ((i = _tls_psk_to_hex(*hexkey)) < 0) {
			warning(("bad TLS-PSK '%.100s' hex char at position %i (%c)",
				 identity, psk_len + 1, *hexkey));
			return 0;
		}
		*psk = i << 4;
		hexkey++;

		/* decode second half of byte, check for errors */
		if ((i = _tls_psk_to_hex(*hexkey)) < 0) {
			warning(("bad TLS-PSK '%.100s' hex char at position %i (%c)",
				 identity, psk_len + 1, *hexkey));
			return 0;
		}
		*psk |= i;
		hexkey++;

		psk_len++;
		psk++;
	}

	if (*hexkey)
		warning(("too long TLS-PSK '%.100s' key (max %i)", identity, max_psk_len));

	return psk_len;
}

/*
 * Callbacks invoked by OpenSSL PSK initialization.
 */

/* Server side TLS-PSK initialization callback. Given an identity (chosen by the client),
 * locate a pre-shared key and put it in psk.
 *
 * Returns the number of bytes put in psk, or 0 on failure.
 */
static unsigned int
_tls_psk_server_cb(SSL *ssl, const char *identity,
		   unsigned char *psk, unsigned int max_psk_len)
{
	char line[1024];
	char *hexkey;
	int fd;
	unsigned int psk_len;

	debug(("Initializing TLS-PSK with keyfile '%.100s', identity '%.100s'",
	       tls_psk_key_filename, identity));

	if ((fd = open(tls_psk_key_filename, O_RDONLY | O_CLOEXEC)) < 0) {
		gck_rpc_warn("can't open TLS-PSK keyfile '%.100s' for reading : %s",
			     tls_psk_key_filename, strerror(errno));
		return 0;
	}

	/* Format of PSK file is that of GnuTLS psktool.
	 *
	 * 1. A comment line starts with a '#'
	 * 2. The form of a line is <username>:<hex_password>
	 */
	psk_len = 0;
	while (gck_rpc_fgets(line, sizeof(line), fd)) {
		/* Strip trailing CR/LF */
		for (hexkey = line; *hexkey != '\0'; hexkey++) {
			if (*hexkey == '\r' || *hexkey == '\n')
				*hexkey = '\0';
		}
		/* Skip comment lines */
		if (line[0] == '#')
			continue;
		/* Split line to get identity and key */
		hexkey = strchr(line, ':');
		if (hexkey == NULL)
			continue;
		*hexkey = '\0';
		hexkey++;
		if (!strcmp(line, identity)) {
			psk_len = _tls_psk_decode_key(line, hexkey, psk, max_psk_len);
			if (psk_len)
				debug(("Loaded TLS-PSK '%.100s' from keyfile '%.100s'",
				       line, tls_psk_key_filename));
			else
				warning(("Failed loading TLS-PSK '%.100s' from keyfile '%.100s'",
					 line, tls_psk_key_filename));
			break;
		}
	}

	close(fd);
	return psk_len;
}

/* Client side TLS-PSK initialization callback. Indicate to OpenSSL what identity to
 * use for this connection, and locate the PSK for that identity.
 *
 * Returns the number of bytes put in psk, or 0 on failure.
 */
static unsigned int
_tls_psk_client_cb(SSL *ssl, const char *hint,
		   char *identity, unsigned int max_identity_len,
		   unsigned char *psk, unsigned int max_psk_len)
{
	snprintf(identity, max_identity_len, "%s", tls_psk_identity);
	return _tls_psk_server_cb(ssl, identity, psk, max_psk_len);
}

static int
_tls_init_ctx_common(GckRpcTlsCtx *tls_ctx, enum gck_rpc_tls_caller caller,
		     enum gck_rpc_tls_mode mode, int restrict_tls12)
{
	if (tls_ctx->initialized == 1) {
		warning(("TLS context already initialized"));
		return 0;
	}

	assert(caller == GCK_RPC_TLS_CLIENT || caller == GCK_RPC_TLS_SERVER);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	tls_ctx->libctx = OSSL_LIB_CTX_new();
	if (tls_ctx->libctx == NULL) {
		gck_rpc_warn("failed to create OpenSSL library context");
		return 0;
	}
	tls_ctx->ssl_ctx = SSL_CTX_new_ex(tls_ctx->libctx, NULL, TLS_method());
#else
	/* Global OpenSSL initialization (legacy) */
	SSL_load_error_strings();
	SSL_library_init();
	OpenSSL_add_ssl_algorithms();
	tls_ctx->ssl_ctx = SSL_CTX_new(TLS_method());
#endif

	if (tls_ctx->ssl_ctx == NULL) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
		OSSL_LIB_CTX_free(tls_ctx->libctx);
		tls_ctx->libctx = NULL;
#endif
		gck_rpc_warn("can't initialize SSL_CTX");
		return 0;
	}

	/* Set minimal version to TLS 1.2 */
	if (!SSL_CTX_set_min_proto_version(tls_ctx->ssl_ctx, TLS1_2_VERSION)) {
		gck_rpc_warn("cannot set minimal protocol version to TLS 1.2");
		gck_rpc_close_tls_ctx(tls_ctx);
		return 0;
	}

	if (restrict_tls12) {
		/* TLS-PSK only supports TLS 1.2 in this implementation */
		if (!SSL_CTX_set_max_proto_version(tls_ctx->ssl_ctx, TLS1_2_VERSION)) {
			gck_rpc_warn("cannot set maximal protocol version to TLS 1.2");
			gck_rpc_close_tls_ctx(tls_ctx);
			return 0;
		}
	}

	SSL_CTX_set_options(tls_ctx->ssl_ctx, SSL_OP_NO_COMPRESSION);
	tls_ctx->type = caller;
	tls_ctx->mode = mode;

	return 1;
}

static int
_tls_load_crl(SSL_CTX *ctx, const char *crl_file)
{
	X509_STORE *store;
	X509_LOOKUP *lookup;

	store = SSL_CTX_get_cert_store(ctx);
	if (!store)
		return 0;

	lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
	if (!lookup)
		return 0;

	if (X509_load_crl_file(lookup, crl_file, X509_FILETYPE_PEM) != 1)
		return 0;

	X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
	return 1;
}

/* Initialize OpenSSL and create an SSL CTX for TLS-PSK. Should be called just once.
 *
 * Returns 0 on failure and 1 on success.
 */
int
gck_rpc_init_tls_psk(GckRpcTlsCtx *tls_ctx, const char *key_filename,
		     const char *identity, enum gck_rpc_tls_caller caller)
{
	char *tls_psk_ciphers = PKCS11PROXY_TLS_PSK_CIPHERS;
	int fd;
	size_t i;

	if (!_tls_init_ctx_common(tls_ctx, caller, GCK_RPC_TLS_MODE_PSK, 1))
		return 0;

	/* Set up callback for TLS-PSK initialization */
	if (caller == GCK_RPC_TLS_CLIENT)
		SSL_CTX_set_psk_client_callback(tls_ctx->ssl_ctx, _tls_psk_client_cb);
	else
		SSL_CTX_set_psk_server_callback(tls_ctx->ssl_ctx, _tls_psk_server_cb);

	if (!SSL_CTX_set_cipher_list(tls_ctx->ssl_ctx, tls_psk_ciphers)) {
		gck_rpc_warn("unable to set TLS-PSK ciphers");
		gck_rpc_close_tls_ctx(tls_ctx);
		return 0;
	}

	snprintf(tls_psk_key_filename, sizeof(tls_psk_key_filename), "%s", key_filename);

	if (caller == GCK_RPC_TLS_CLIENT && !identity) {
		/* Parse the psk file just to find the identity, and use the first line */
		if ((fd = open(tls_psk_key_filename, O_RDONLY | O_CLOEXEC)) < 0) {
			gck_rpc_warn("can't open TLS-PSK keyfile '%.100s' for reading : %s",
				     tls_psk_key_filename, strerror(errno));
			gck_rpc_close_tls_ctx(tls_ctx);
			return 0;
		}

		while (gck_rpc_fgets(tls_psk_identity, sizeof(tls_psk_identity), fd)) {
			char *line = tls_psk_identity;
			char *hexkey;

			/* Strip trailing CR/LF */
			for (i = 0; line[i] != '\0'; i++) {
				if (line[i] == '\r' || line[i] == '\n') {
					line[i] = '\0';
					break;
				}
			}

			line = _tls_trim_whitespace(line);
			if (line[0] == '\0' || line[0] == '#')
				continue;

			hexkey = strchr(line, ':');
			if (!hexkey)
				continue;

			*hexkey = '\0';
			line = _tls_trim_whitespace(line);
			if (line[0] == '\0')
				continue;

			snprintf(tls_psk_identity, sizeof(tls_psk_identity), "%s", line);
			break;
		}
		close(fd);
	} else if (identity) {
		snprintf(tls_psk_identity, sizeof(tls_psk_identity), "%s", identity);
	}

	tls_ctx->initialized = 1;
	debug(("Initialized TLS-PSK %s", caller == GCK_RPC_TLS_CLIENT ? "client" : "server"));
	return 1;
}

/* Initialize OpenSSL and create an SSL CTX for certificate-based TLS (mTLS).
 *
 * Returns 0 on failure and 1 on success.
 */
int
gck_rpc_init_tls_cert(GckRpcTlsCtx *tls_ctx, const char *cert_file,
		      const char *key_file, const char *ca_file,
		      const char *ca_path, const char *crl_file,
		      bool verify_peer, enum gck_rpc_tls_caller caller)
{
	int verify_mode = SSL_VERIFY_NONE;

	if (!cert_file || !key_file) {
		gck_rpc_warn("certificate file and key file are required for TLS cert mode");
		return 0;
	}

	if (!_tls_init_ctx_common(tls_ctx, caller, GCK_RPC_TLS_MODE_CERT, 0))
		return 0;

	if (SSL_CTX_use_certificate_chain_file(tls_ctx->ssl_ctx, cert_file) != 1) {
		gck_rpc_warn("failed loading TLS certificate chain");
		gck_rpc_close_tls_ctx(tls_ctx);
		return 0;
	}

	if (SSL_CTX_use_PrivateKey_file(tls_ctx->ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
		gck_rpc_warn("failed loading TLS private key");
		gck_rpc_close_tls_ctx(tls_ctx);
		return 0;
	}

	if (SSL_CTX_check_private_key(tls_ctx->ssl_ctx) != 1) {
		gck_rpc_warn("TLS private key does not match the certificate");
		gck_rpc_close_tls_ctx(tls_ctx);
		return 0;
	}

	if (verify_peer) {
		if (ca_file || ca_path) {
			if (SSL_CTX_load_verify_locations(tls_ctx->ssl_ctx, ca_file, ca_path) != 1) {
				gck_rpc_warn("failed loading TLS CA bundle");
				gck_rpc_close_tls_ctx(tls_ctx);
				return 0;
			}
		} else if (SSL_CTX_set_default_verify_paths(tls_ctx->ssl_ctx) != 1) {
			gck_rpc_warn("failed loading default TLS CA paths");
			gck_rpc_close_tls_ctx(tls_ctx);
			return 0;
		}

		if (crl_file && crl_file[0]) {
			if (!_tls_load_crl(tls_ctx->ssl_ctx, crl_file)) {
				gck_rpc_warn("failed loading TLS CRL");
				gck_rpc_close_tls_ctx(tls_ctx);
				return 0;
			}
		}

		if (caller == GCK_RPC_TLS_SERVER)
			verify_mode = SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
		else
			verify_mode = SSL_VERIFY_PEER;
	}

	SSL_CTX_set_verify(tls_ctx->ssl_ctx, verify_mode, NULL);

	tls_ctx->initialized = 1;
	debug(("Initialized TLS-CERT %s", caller == GCK_RPC_TLS_CLIENT ? "client" : "server"));
	return 1;
}

/* Set up SSL for a new socket. Call this after accept() or connect().
 *
 * When a socket has been created, call gck_rpc_start_tls() with the TLS state
 * initialized using gck_rpc_init_tls_*() and the new socket.
 */
int
gck_rpc_start_tls(GckRpcTlsState *state, int sock)
{
	char buf[1024];
	int res;

	state->ssl = SSL_new(state->ctx->ssl_ctx);
	if (! state->ssl) {
		warning(("can't initialize SSL"));
		return 0;
	}

	/* wrap the TCP socket with a BIO */
	state->bio = BIO_new_socket(sock, BIO_NOCLOSE);
	if (! state->bio) {
		warning(("can't initialize SSL BIO"));
		return 0;
	}

	SSL_set_bio(state->ssl, state->bio, state->bio);

	if (state->ctx->type == GCK_RPC_TLS_CLIENT &&
	    state->ctx->mode == GCK_RPC_TLS_MODE_CERT &&
	    state->peer_host_set) {
		X509_VERIFY_PARAM *param = SSL_get0_param(state->ssl);

		if (!param) {
			warning(("can't get X509 verify params"));
			return 0;
		}

		if (state->peer_host_is_ip) {
			if (!X509_VERIFY_PARAM_set1_ip_asc(param, state->peer_host)) {
				warning(("failed to set TLS peer IP for verification"));
				return 0;
			}
		} else {
			if (!SSL_set_tlsext_host_name(state->ssl, state->peer_host)) {
				warning(("failed to set TLS SNI"));
				return 0;
			}
			if (!X509_VERIFY_PARAM_set1_host(param, state->peer_host, 0)) {
				warning(("failed to set TLS peer host for verification"));
				return 0;
			}
		}
	}

	/* Set up callback for TLS initialization */
	if (state->ctx->type == GCK_RPC_TLS_CLIENT)
		res = SSL_connect(state->ssl);
	else
		res = SSL_accept(state->ssl);

	if (res <= 0) {
		warning(("can't start TLS : %i/%i (%s perhaps)",
			 res, SSL_get_error(state->ssl, res), strerror(errno)));
		ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
		warning(("SSL ERR: %s", buf));
		return 0;
	}

	return 1;
}

/* Un-initialize everything SSL context related structs. Call this on application shut down.
 */
void
gck_rpc_close_tls_ctx(GckRpcTlsCtx *tls_ctx)
{
	if (tls_ctx->ssl_ctx) {
		SSL_CTX_free(tls_ctx->ssl_ctx);
		tls_ctx->ssl_ctx = NULL;
	}
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (tls_ctx->libctx) {
		OSSL_LIB_CTX_free(tls_ctx->libctx);
		tls_ctx->libctx = NULL;
	}
#endif
	tls_ctx->initialized = 0;
}

/* Un-initialize SSL.
 */
void
gck_rpc_close_tls_state(GckRpcTlsState *tls_state)
{
	if (tls_state->ssl) {
		SSL_free(tls_state->ssl);
		tls_state->ssl = NULL;
	}
}

/* Un-initialize all SSL.
 */
void
gck_rpc_close_tls_all(GckRpcTlsState *tls_state)
{
	if (tls_state->ctx)
		gck_rpc_close_tls_ctx(tls_state->ctx);
	gck_rpc_close_tls_state(tls_state);
}

/* Send data using SSL.
 */
int
gck_rpc_tls_write_all(GckRpcTlsState *state, void *data, unsigned int len)
{
	int ret, ssl_err;
	char buf[1024];

	ret = SSL_write(state->ssl, data, len);
	if (ret > 0)
		return ret;

	ssl_err = SSL_get_error(state->ssl, ret);
	switch (ssl_err) {
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		break;
	case SSL_ERROR_ZERO_RETURN:
		warning(("SSL_write: connection closed"));
		break;
	case SSL_ERROR_SYSCALL:
		if (ret == 0) {
			warning(("SSL_write: syscall EOF"));
		} else {
			if (errno == EPIPE || errno == ECONNRESET)
				break;
			perror("SSL_write: syscall error");
		}
		break;
	default:
		/* Print all queued OpenSSL errors */
		while ((ssl_err = ERR_get_error())) {
			ERR_error_string_n(ssl_err, buf, sizeof(buf));
			warning(("SSL_write error: %s", buf));
		}
		break;
	}

	return -1;
}

/* Read data using SSL.
 */
int
gck_rpc_tls_read_all(GckRpcTlsState *state, void *data, unsigned int len)
{
	int ret, ssl_err;
	char buf[1024];

	ret = SSL_read(state->ssl, data, len);
	if (ret > 0)
		return ret;

	ssl_err = SSL_get_error(state->ssl, ret);
	switch (ssl_err) {
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		break;
	case SSL_ERROR_ZERO_RETURN:
		warning(("SSL_read: connection closed"));
		break;
	case SSL_ERROR_SYSCALL:
		if (ret == 0) {
			warning(("SSL_read: syscall EOF"));
		} else {
			perror("SSL_read: syscall error");
		}
		break;
	default:
		/* Print all queued OpenSSL errors */
		while ((ssl_err = ERR_get_error())) {
			ERR_error_string_n(ssl_err, buf, sizeof(buf));
			warning(("SSL_read error: %s", buf));
		}
		break;
	}

	return -1;
}
