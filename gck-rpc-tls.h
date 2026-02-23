/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
#ifndef GCKRPC_TLS_H_
#define GCKRPC_TLS_H_

#include <stdbool.h>
#include <netdb.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#if OPENSSL_VERSION_NUMBER < 0x10000000
# error "OpenSSL version >= 1.0.0 required"
#endif

enum gck_rpc_tls_caller {
	GCK_RPC_TLS_CLIENT,
	GCK_RPC_TLS_SERVER
};

enum gck_rpc_tls_mode {
	GCK_RPC_TLS_MODE_PSK,
	GCK_RPC_TLS_MODE_CERT
};

typedef struct {
	SSL_CTX *ssl_ctx;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	OSSL_LIB_CTX *libctx;
#endif
	int initialized;
	enum gck_rpc_tls_caller type;
	enum gck_rpc_tls_mode mode;
} GckRpcTlsCtx;

typedef struct {
	GckRpcTlsCtx *ctx;
	BIO *bio;
	SSL *ssl;
	char peer_host[NI_MAXHOST];
	int peer_host_set;
	int peer_host_is_ip;
} GckRpcTlsState;

int gck_rpc_init_tls_psk(GckRpcTlsCtx *tls_ctx, const char *key_filename,
			 const char *identity, enum gck_rpc_tls_caller caller);
int gck_rpc_init_tls_cert(GckRpcTlsCtx *tls_ctx, const char *cert_file,
			  const char *key_file, const char *ca_file,
			  const char *ca_path, const char *crl_file,
			  bool verify_peer, enum gck_rpc_tls_caller caller);

int gck_rpc_start_tls(GckRpcTlsState *state, int sock);
int gck_rpc_tls_set_peer_host(GckRpcTlsState *state, const char *host);

int gck_rpc_tls_write_all(GckRpcTlsState *state, void *data, unsigned int len);
int gck_rpc_tls_read_all(GckRpcTlsState *state, void *data, unsigned int len);

void gck_rpc_close_tls_ctx(GckRpcTlsCtx *tls_ctx);
void gck_rpc_close_tls_state(GckRpcTlsState *state);
void gck_rpc_close_tls_all(GckRpcTlsState *state);

#endif /* GCKRPC_TLS_H_ */
