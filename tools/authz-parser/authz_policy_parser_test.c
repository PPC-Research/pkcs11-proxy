#include "authz-policy-parser.h"

#include <stdio.h>
#include <string.h>

static int expect_str(const char *label, const char *got, const char *expected)
{
	if (!got || strcmp(got, expected) != 0) {
		fprintf(stderr, "%s mismatch: got='%s' expected='%s'\n", label, got ? got : "(null)", expected);
		return 0;
	}
	return 1;
}

int main(int argc, char *argv[])
{
	AuthzParsedPolicy policy;
	char err[256];
	int ok = 1;
	const char *path = "../../mtls-demo/authz.json";

	if (argc > 1)
		path = argv[1];

	memset(err, 0, sizeof(err));
	if (!authz_policy_parse_file(path, &policy, err, sizeof(err))) {
		fprintf(stderr, "parse failed: %s\n", err[0] ? err : "unknown");
		return 1;
	}

	ok &= (policy.version == 1);
	if (!ok) fprintf(stderr, "version mismatch\n");
	ok &= (policy.default_allow_set == 1);
	ok &= (policy.default_allow == 0);
	ok &= (policy.clients_count == 1);
	if (policy.clients_count >= 1) {
		AuthzParsedClient *c = &policy.clients[0];
		ok &= expect_str("id_type", c->id_type, "cert_fingerprint_sha256");
		ok &= (c->allow.pkcs11_functions_count > 0);
		ok &= (c->allow.tokens_count == 1);
		ok &= (c->allow.objects_count == 1);
		if (c->allow.tokens_count == 1)
			ok &= expect_str("token", c->allow.tokens[0], "ProxyTestToken");
		if (c->allow.objects_count == 1)
			ok &= expect_str("object", c->allow.objects[0], "ProxyTestExistingECKey");
	}

	authz_policy_free(&policy);
	return ok ? 0 : 1;
}
