#include "authz-policy-parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int expect_str(const char *label, const char *got, const char *expected)
{
	if (!got || strcmp(got, expected) != 0) {
		fprintf(stderr, "%s mismatch: got='%s' expected='%s'\n", label, got ? got : "(null)", expected);
		return 0;
	}
	return 1;
}

static int write_policy_file(const char *path, const char *json)
{
	FILE *fp = fopen(path, "w");
	if (!fp)
		return 0;
	if (fputs(json, fp) == EOF) {
		fclose(fp);
		return 0;
	}
	return fclose(fp) == 0;
}

static int check_multi_client_policy(void)
{
	static const char json[] =
		"{\"version\":1,\"default\":\"deny\",\"clients\":["
		"{\"id_type\":\"subject_cn\",\"id\":\"clientA\","
		"\"allow\":{\"pkcs11_functions\":[\"C_GetSlotList\"],\"tokens\":[\"TokenA\"]}},"
		"{\"id_type\":\"subject_cn\",\"id\":\"clientB\","
		"\"allow\":{\"pkcs11_functions\":[\"C_Sign\"],\"tokens\":[\"TokenB\"],\"objects\":[\"KeyB\"]}}"
		"]}";
	char path[] = "/tmp/authz-policy-parser-test-XXXXXX";
	AuthzParsedPolicy policy;
	char err[256];
	int fd;
	int ok = 1;

	fd = mkstemp(path);
	if (fd < 0) {
		fprintf(stderr, "mkstemp failed\n");
		return 0;
	}
	close(fd);
	if (!write_policy_file(path, json)) {
		fprintf(stderr, "failed to write multi-client policy\n");
		unlink(path);
		return 0;
	}

	memset(err, 0, sizeof(err));
	if (!authz_policy_parse_file(path, &policy, err, sizeof(err))) {
		fprintf(stderr, "multi-client parse failed: %s\n", err[0] ? err : "unknown");
		unlink(path);
		return 0;
	}

	ok &= (policy.clients_count == 2);
	if (!ok)
		fprintf(stderr, "multi-client count mismatch: got=%zu expected=2\n", policy.clients_count);
	if (policy.clients_count >= 2) {
		ok &= expect_str("client[0].id", policy.clients[0].id, "clientA");
		ok &= expect_str("client[1].id", policy.clients[1].id, "clientB");
		ok &= (policy.clients[1].allow.tokens_count == 1);
		ok &= (policy.clients[1].allow.objects_count == 1);
		if (policy.clients[1].allow.tokens_count == 1)
			ok &= expect_str("client[1].token", policy.clients[1].allow.tokens[0], "TokenB");
		if (policy.clients[1].allow.objects_count == 1)
			ok &= expect_str("client[1].object", policy.clients[1].allow.objects[0], "KeyB");
	}

	authz_policy_free(&policy);
	unlink(path);
	return ok;
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
	ok &= check_multi_client_policy();
	return ok ? 0 : 1;
}
