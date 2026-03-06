#ifndef AUTHZ_POLICY_PARSER_H
#define AUTHZ_POLICY_PARSER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char **pkcs11_functions;
	size_t pkcs11_functions_count;
	char **tokens;
	size_t tokens_count;
	char **objects;
	size_t objects_count;
} AuthzParsedAllow;

typedef struct {
	char *id_type;
	char *id;
	AuthzParsedAllow allow;
} AuthzParsedClient;

typedef struct {
	int version;
	int default_allow_set;
	int default_allow; /* 1 allow, 0 deny */
	AuthzParsedClient *clients;
	size_t clients_count;
} AuthzParsedPolicy;

int authz_policy_parse_file(const char *path, AuthzParsedPolicy *out_policy, char *err, size_t err_len);
void authz_policy_free(AuthzParsedPolicy *policy);

#ifdef __cplusplus
}
#endif

#endif /* AUTHZ_POLICY_PARSER_H */
