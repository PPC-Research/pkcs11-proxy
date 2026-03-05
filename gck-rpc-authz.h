/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
#ifndef GCK_RPC_AUTHZ_H
#define GCK_RPC_AUTHZ_H

#include <stddef.h>

#include "pkcs11/pkcs11.h"
#include "gck-rpc-tls.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	GCK_RPC_AUTHZ_MODE_DISABLED = 0,
	GCK_RPC_AUTHZ_MODE_ENFORCE,
	GCK_RPC_AUTHZ_MODE_AUDIT
} GckRpcAuthzMode;

typedef struct {
	char *fingerprint;
	char *subject;
	char *subject_cn;
	char **san_dns;
	size_t san_dns_count;
	char **san_uri;
	size_t san_uri_count;
	char **san_ip;
	size_t san_ip_count;
	int verified;
} GckRpcAuthzClient;

typedef struct {
	GckRpcAuthzClient *client;
	int matched;
	int deny_all;
	int deny_all_peer;
	int allow_all;
	int tokens_unrestricted;
	int objects_unrestricted;
	int audit_would_deny;
	unsigned char allowed_calls[256];
	char **tokens;
	size_t tokens_count;
	char **objects;
	size_t objects_count;
} GckRpcAuthzClientCtx;

typedef struct {
	int has_slot;
	CK_SLOT_ID slot_id;
	int has_session;
	CK_SESSION_HANDLE session;
	int has_object;
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE_PTR template;
	CK_ULONG template_count;
} GckRpcAuthzRequest;

int gck_rpc_authz_init(void);
void gck_rpc_authz_shutdown(void);
void gck_rpc_authz_set_module(CK_FUNCTION_LIST_PTR module);

int gck_rpc_authz_is_enabled(void);
GckRpcAuthzMode gck_rpc_authz_mode(void);

extern const char *gck_rpc_authz_diag_version;

void gck_rpc_authz_client_ctx_init(GckRpcAuthzClientCtx *ctx, GckRpcTlsState *tls);
void gck_rpc_authz_client_ctx_free(GckRpcAuthzClientCtx *ctx);

CK_RV gck_rpc_authz_check_basic(GckRpcAuthzClientCtx *ctx, int call_id);
CK_RV gck_rpc_authz_check_scoped(GckRpcAuthzClientCtx *ctx, int call_id, const GckRpcAuthzRequest *req);

#ifdef __cplusplus
}
#endif

#endif /* GCK_RPC_AUTHZ_H */
