#include "authz-policy-parser.h"

#include <stdio.h>
#include <string.h>

static void print_policy(const AuthzParsedPolicy *p)
{
	size_t i;
	size_t j;
	printf("version=%d\n", p->version);
	if (p->default_allow_set)
		printf("default=%s\n", p->default_allow ? "allow" : "deny");
	printf("clients=%zu\n", p->clients_count);
	for (i = 0; i < p->clients_count; i++) {
		const AuthzParsedClient *c = &p->clients[i];
		printf("client[%zu].id_type=%s\n", i, c->id_type ? c->id_type : "");
		printf("client[%zu].id=%s\n", i, c->id ? c->id : "");
		printf("client[%zu].allow.pkcs11_functions=%zu\n", i, c->allow.pkcs11_functions_count);
		for (j = 0; j < c->allow.pkcs11_functions_count; j++)
			printf("  fn=%s\n", c->allow.pkcs11_functions[j]);
		printf("client[%zu].allow.tokens=%zu\n", i, c->allow.tokens_count);
		for (j = 0; j < c->allow.tokens_count; j++)
			printf("  token=%s\n", c->allow.tokens[j]);
		printf("client[%zu].allow.objects=%zu\n", i, c->allow.objects_count);
		for (j = 0; j < c->allow.objects_count; j++)
			printf("  object=%s\n", c->allow.objects[j]);
	}
}

int main(int argc, char *argv[])
{
	AuthzParsedPolicy policy;
	char err[256];
	const char *path = "";
	if (argc < 2) {
		fprintf(stderr, "usage: %s /path/to/authz.json\n", argv[0]);
		return 2;
	}
	path = argv[1];
	memset(err, 0, sizeof(err));
	if (!authz_policy_parse_file(path, &policy, err, sizeof(err))) {
		fprintf(stderr, "parse failed: %s\n", err[0] ? err : "unknown");
		return 1;
	}
	print_policy(&policy);
	authz_policy_free(&policy);
	return 0;
}
