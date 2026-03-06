/* -*- Mode: C; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* gck-rpc-authz.c - mTLS client authorization policy */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include "config.h"

#include "gck-rpc-authz.h"
#include "authz-policy-parser.h"
#include "gck-rpc-private.h"

#include "jsmn.h"

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>

#ifndef CKR_FUNCTION_NOT_PERMITTED
#define CKR_FUNCTION_NOT_PERMITTED CKR_GENERAL_ERROR
#endif

#define AUTHZ_MAX_CALLS 256

typedef struct {
	char *id_type;
	char *id;
	unsigned char allowed_calls[AUTHZ_MAX_CALLS];
	char **tokens;
	size_t tokens_count;
	char **objects;
	size_t objects_count;
	int tokens_unrestricted;
	int objects_unrestricted;
} AuthzRule;

typedef struct {
	int version;
	int default_allow;
	int default_allow_set;
	AuthzRule *rules;
	size_t rules_count;
} AuthzPolicy;

typedef struct {
	AuthzPolicy *policy;
	GckRpcAuthzMode mode;
	int default_allow;
	int log_debug;
	CK_FUNCTION_LIST_PTR module;
} AuthzState;

static AuthzState authz_state;
const char *gck_rpc_authz_diag_version = "authz-diag-v3";

static void authz_policy_free_internal(AuthzPolicy *policy);
static char *authz_normalize_fingerprint(const char *input);
static int authz_add_string(char ***list, size_t *count, const char *value);
static void authz_rule_set_call(AuthzRule *rule, const char *name);
static int authz_add_rule(AuthzPolicy *policy, const AuthzRule *rule);

static const char *authz_getenv(const char *name)
{
	const char *value = secure_getenv(name);
	return value && value[0] ? value : NULL;
}

static void authz_free_string_list(char **list, size_t count)
{
	size_t i;
	if (!list)
		return;
	for (i = 0; i < count; i++)
		free(list[i]);
	free(list);
}

static void authz_policy_free_internal(AuthzPolicy *policy)
{
	size_t i;
	if (!policy)
		return;
	for (i = 0; i < policy->rules_count; i++) {
		AuthzRule *rule = &policy->rules[i];
		free(rule->id_type);
		free(rule->id);
		authz_free_string_list(rule->tokens, rule->tokens_count);
		authz_free_string_list(rule->objects, rule->objects_count);
	}
	free(policy->rules);
	free(policy);
}

static char *authz_read_file(const char *path, size_t *out_len)
{
	FILE *fp;
	char *buf;
	long len;

	fp = fopen(path, "rb");
	if (!fp) {
		gck_rpc_warn("AUTHZ: failed to open policy file '%s': %s", path, strerror(errno));
		return NULL;
	}

	if (fseek(fp, 0, SEEK_END) != 0) {
		gck_rpc_warn("AUTHZ: failed to seek policy file '%s': %s", path, strerror(errno));
		fclose(fp);
		return NULL;
	}
	len = ftell(fp);
	if (len < 0 || len > INT_MAX) {
		gck_rpc_warn("AUTHZ: invalid policy file length for '%s'", path);
		fclose(fp);
		return NULL;
	}
	if (fseek(fp, 0, SEEK_SET) != 0) {
		gck_rpc_warn("AUTHZ: failed to rewind policy file '%s': %s", path, strerror(errno));
		fclose(fp);
		return NULL;
	}

	buf = calloc(1, (size_t)len + 1);
	if (!buf) {
		gck_rpc_warn("AUTHZ: failed to allocate policy buffer for '%s'", path);
		fclose(fp);
		return NULL;
	}

	if (fread(buf, 1, (size_t)len, fp) != (size_t)len) {
		gck_rpc_warn("AUTHZ: failed to read policy file '%s': %s", path, strerror(errno));
		free(buf);
		fclose(fp);
		return NULL;
	}
	fclose(fp);

	if (out_len)
		*out_len = (size_t)len;
	return buf;
}

static void authz_strip_bom(char *buf, size_t *len)
{
	if (!buf || !len || *len < 3)
		return;
	if ((unsigned char)buf[0] == 0xEF &&
	    (unsigned char)buf[1] == 0xBB &&
	    (unsigned char)buf[2] == 0xBF) {
		memmove(buf, buf + 3, *len - 2);
		*len -= 3;
		buf[*len] = '\0';
	}
}

static void authz_strip_trailing_nuls(char *buf, size_t *len)
{
	while (buf && len && *len > 0 && buf[*len - 1] == '\0')
		(*len)--;
	if (buf && len)
		buf[*len] = '\0';
}

static void authz_sanitize_control_chars(char *buf, size_t len)
{
	size_t i;
	for (i = 0; buf && i < len; i++) {
		unsigned char c = (unsigned char)buf[i];
		if (c < 0x20 && c != '\n' && c != '\r' && c != '\t')
			buf[i] = ' ';
		else if (c >= 0x80)
			buf[i] = ' ';
	}
}

static void authz_log_json_snippet(const char *label, const char *buf, size_t len)
{
	size_t i;
	size_t max_bytes = len < 256 ? len : 256;
	char snippet[1100];
	char hex_prefix[3 * 64 + 1];
	char hex_suffix[3 * 64 + 1];
	size_t sn = 0;

	if (!buf)
		return;

	gck_rpc_warn("AUTHZ: policy %s length=%zu", label, len);

	for (i = 0; i < max_bytes && sn + 5 < sizeof(snippet); i++) {
		unsigned char c = (unsigned char)buf[i];
		if (c == '\n') {
			sn += (size_t)snprintf(snippet + sn, sizeof(snippet) - sn, "\\n");
		} else if (c == '\r') {
			sn += (size_t)snprintf(snippet + sn, sizeof(snippet) - sn, "\\r");
		} else if (c == '\t') {
			sn += (size_t)snprintf(snippet + sn, sizeof(snippet) - sn, "\\t");
		} else if (c < 0x20 || c >= 0x7f) {
			sn += (size_t)snprintf(snippet + sn, sizeof(snippet) - sn, "\\x%02x", c);
		} else {
			sn += (size_t)snprintf(snippet + sn, sizeof(snippet) - sn, "%c", c);
		}
	}
	snippet[sn] = '\0';
	gck_rpc_warn("AUTHZ: policy %s prefix=%s", label, snippet);

	hex_prefix[0] = '\0';
	hex_suffix[0] = '\0';
	if (len > 0) {
		size_t hp = 0;
		size_t hs = 0;
		size_t prefix_len = len < 64 ? len : 64;
		size_t suffix_len = len < 64 ? len : 64;
		const unsigned char *u = (const unsigned char *)buf;
		for (i = 0; i < prefix_len && hp + 4 < sizeof(hex_prefix); i++)
			hp += (size_t)snprintf(hex_prefix + hp, sizeof(hex_prefix) - hp, "%02x ", u[i]);
		if (len > suffix_len) {
			const unsigned char *s = u + (len - suffix_len);
			for (i = 0; i < suffix_len && hs + 4 < sizeof(hex_suffix); i++)
				hs += (size_t)snprintf(hex_suffix + hs, sizeof(hex_suffix) - hs, "%02x ", s[i]);
		} else {
			memcpy(hex_suffix, hex_prefix, sizeof(hex_suffix) - 1);
			hex_suffix[sizeof(hex_suffix) - 1] = '\0';
		}
		gck_rpc_warn("AUTHZ: policy %s hex_prefix=%s", label, hex_prefix);
		if (len > 64)
			gck_rpc_warn("AUTHZ: policy %s hex_suffix=%s", label, hex_suffix);
	}
}

static char *authz_extract_json_object(const char *buf, size_t *len)
{
	const char *start;
	const char *end;
	size_t new_len;
	char *out;

	if (!buf || !len || *len == 0)
		return NULL;

	start = strchr(buf, '{');
	end = strrchr(buf, '}');
	if (!start || !end || end <= start)
		return NULL;

	new_len = (size_t)(end - start + 1);
	out = calloc(1, new_len + 1);
	if (!out)
		return NULL;
	memcpy(out, start, new_len);
	out[new_len] = '\0';
	*len = new_len;
	return out;
}

static const char *authz_skip_ws_range(const char *p, const char *end)
{
	while (p < end && isspace((unsigned char)*p))
		p++;
	return p;
}

static const char *authz_parse_string_literal(const char *p, const char *end, char **out)
{
	size_t cap = 32;
	size_t len = 0;
	char *buf;

	if (p >= end || *p != '"')
		return NULL;
	p++;

	buf = calloc(1, cap);
	if (!buf)
		return NULL;

	while (p < end) {
		char c = *p++;
		if (c == '"') {
			buf[len] = '\0';
			*out = buf;
			return p;
		}
		if (c == '\\' && p < end) {
			char esc = *p++;
			switch (esc) {
			case '"': c = '"'; break;
			case '\\': c = '\\'; break;
			case '/': c = '/'; break;
			case 'b': c = '\b'; break;
			case 'f': c = '\f'; break;
			case 'n': c = '\n'; break;
			case 'r': c = '\r'; break;
			case 't': c = '\t'; break;
			case 'u':
				/* Skip \uXXXX */
				if (p + 3 < end)
					p += 4;
				c = '?';
				break;
			default:
				c = esc;
				break;
			}
		}
		if (len + 2 > cap) {
			cap *= 2;
			char *tmp = realloc(buf, cap);
			if (!tmp) {
				free(buf);
				return NULL;
			}
			buf = tmp;
		}
		buf[len++] = c;
	}

	free(buf);
	return NULL;
}

static const char *authz_find_key_in_range(const char *start, const char *end, const char *key)
{
	const char *p = start;
	while (p < end) {
		p = authz_skip_ws_range(p, end);
		if (p >= end)
			return NULL;
		if (*p == '"') {
			char *name = NULL;
			const char *after = authz_parse_string_literal(p, end, &name);
			if (!after) {
				free(name);
				return NULL;
			}
			after = authz_skip_ws_range(after, end);
			if (after < end && *after == ':') {
				after++;
				if (name && strcmp(name, key) == 0) {
					free(name);
					return authz_skip_ws_range(after, end);
				}
			}
			free(name);
			p = after;
		} else {
			p++;
		}
	}
	return NULL;
}

static const char *authz_parse_string_array_literal(const char *p, const char *end,
						    char ***out, size_t *out_count)
{
	if (p >= end || *p != '[')
		return NULL;
	p++;
	p = authz_skip_ws_range(p, end);
	while (p < end && *p != ']') {
		char *val = NULL;
		if (*p == '"') {
			const char *next = authz_parse_string_literal(p, end, &val);
			if (!next) {
				free(val);
				return NULL;
			}
			authz_add_string(out, out_count, val);
			free(val);
			p = authz_skip_ws_range(next, end);
			if (p < end && *p == ',') {
				p++;
				p = authz_skip_ws_range(p, end);
			}
		} else {
			p++;
		}
	}
	if (p < end && *p == ']')
		return p + 1;
	return NULL;
}

static int authz_parse_allow_fallback(const char *start, const char *end, AuthzRule *rule)
{
	const char *p;
	p = authz_find_key_in_range(start, end, "pkcs11_functions");
	if (p && *p == '[') {
		char **fns = NULL;
		size_t fn_count = 0;
		const char *after = authz_parse_string_array_literal(p, end, &fns, &fn_count);
		size_t i;
		for (i = 0; i < fn_count; i++)
			authz_rule_set_call(rule, fns[i]);
		authz_free_string_list(fns, fn_count);
		p = after;
	}
	p = authz_find_key_in_range(start, end, "tokens");
	if (p && *p == '[') {
		authz_parse_string_array_literal(p, end, &rule->tokens, &rule->tokens_count);
		if (rule->tokens_count > 0)
			rule->tokens_unrestricted = 0;
	}
	p = authz_find_key_in_range(start, end, "objects");
	if (p && *p == '[') {
		authz_parse_string_array_literal(p, end, &rule->objects, &rule->objects_count);
		if (rule->objects_count > 0)
			rule->objects_unrestricted = 0;
	}
	return 1;
}

static int authz_parse_client_object_fallback(const char *start, const char *end, AuthzPolicy *policy)
{
	AuthzRule rule;
	const char *p;
	memset(&rule, 0, sizeof(rule));
	rule.tokens_unrestricted = 1;
	rule.objects_unrestricted = 1;

	p = authz_find_key_in_range(start, end, "id_type");
	if (p && *p == '"')
		authz_parse_string_literal(p, end, &rule.id_type);

	p = authz_find_key_in_range(start, end, "id");
	if (p && *p == '"')
		authz_parse_string_literal(p, end, &rule.id);

	p = authz_find_key_in_range(start, end, "allow");
	if (p && *p == '{') {
		const char *allow_start = p;
		int depth = 0;
		int in_string = 0;
		for (p = allow_start; p < end; p++) {
			char c = *p;
			if (c == '"' && (p == allow_start || p[-1] != '\\'))
				in_string = !in_string;
			if (!in_string) {
				if (c == '{') depth++;
				else if (c == '}') {
					depth--;
					if (depth == 0) {
						authz_parse_allow_fallback(allow_start, p + 1, &rule);
						break;
					}
				}
			}
		}
	}

	if (rule.id_type && rule.id) {
		if (strcmp(rule.id_type, "cert_fingerprint_sha256") == 0) {
			char *normalized = authz_normalize_fingerprint(rule.id);
			free(rule.id);
			rule.id = normalized;
		}
		authz_add_rule(policy, &rule);
		return 1;
	}

	free(rule.id_type);
	free(rule.id);
	authz_free_string_list(rule.tokens, rule.tokens_count);
	authz_free_string_list(rule.objects, rule.objects_count);
	return 0;
}

static AuthzPolicy *authz_policy_load_fallback(const char *json, size_t len)
{
	AuthzPolicy *policy;
	const char *end = json + len;
	const char *p;

	policy = calloc(1, sizeof(AuthzPolicy));
	if (!policy)
		return NULL;

	p = authz_find_key_in_range(json, end, "version");
	if (p) {
		p = authz_skip_ws_range(p, end);
		if (p < end && isdigit((unsigned char)*p))
			policy->version = (int)strtol(p, NULL, 10);
	}
	p = authz_find_key_in_range(json, end, "default");
	if (p && *p == '"') {
		char *def = NULL;
		authz_parse_string_literal(p, end, &def);
		if (def) {
			if (strcasecmp(def, "allow") == 0) {
				policy->default_allow = 1;
				policy->default_allow_set = 1;
			} else if (strcasecmp(def, "deny") == 0) {
				policy->default_allow = 0;
				policy->default_allow_set = 1;
			}
			free(def);
		}
	}
	p = authz_find_key_in_range(json, end, "clients");
	if (p && *p == '[') {
		int depth = 0;
		int in_string = 0;
		const char *obj_start = NULL;
		for (; p < end; p++) {
			char c = *p;
			if (c == '"' && (p == json || p[-1] != '\\'))
				in_string = !in_string;
			if (in_string)
				continue;
			if (c == '{') {
				if (depth == 0)
					obj_start = p;
				depth++;
			} else if (c == '}') {
				depth--;
				if (depth == 0 && obj_start) {
					authz_parse_client_object_fallback(obj_start, p + 1, policy);
					obj_start = NULL;
				}
			}
		}
	}

	return policy;
}

static const char *authz_jsmn_error(int code)
{
	switch (code) {
	case JSMN_ERROR_INVAL:
		return "invalid JSON";
	case JSMN_ERROR_NOMEM:
		return "not enough tokens";
	case JSMN_ERROR_PART:
		return "incomplete JSON";
	default:
		return "unknown";
	}
}

static int authz_token_eq(const char *json, const jsmntok_t *tok, const char *str)
{
	size_t len = (size_t)(tok->end - tok->start);
	return tok->type == JSMN_STRING && strlen(str) == len &&
		strncmp(json + tok->start, str, len) == 0;
}

static char *authz_token_strdup(const char *json, const jsmntok_t *tok)
{
	size_t len;
	char *out;
	if (tok->type != JSMN_STRING)
		return NULL;
	len = (size_t)(tok->end - tok->start);
	out = calloc(1, len + 1);
	if (!out)
		return NULL;
	memcpy(out, json + tok->start, len);
	out[len] = '\0';
	return out;
}

static int authz_token_to_int(const char *json, const jsmntok_t *tok, int *value)
{
	char *tmp;
	char *endptr;
	long v;
	if (tok->start < 0 || tok->end < 0 || tok->end < tok->start)
		return 0;
	tmp = calloc(1, (size_t)(tok->end - tok->start) + 1);
	if (!tmp)
		return 0;
	memcpy(tmp, json + tok->start, (size_t)(tok->end - tok->start));
	tmp[tok->end - tok->start] = '\0';
	v = strtol(tmp, &endptr, 10);
	free(tmp);
	if (!endptr || *endptr != '\0')
		return 0;
	*value = (int)v;
	return 1;
}

static int authz_skip_token(const jsmntok_t *tokens, int index)
{
	int i;
	int count = 1;
	int idx = index + 1;

	switch (tokens[index].type) {
	case JSMN_OBJECT:
		for (i = 0; i < tokens[index].size; i++) {
			int skipped = authz_skip_token(tokens, idx);
			count += skipped;
			idx += skipped;
			skipped = authz_skip_token(tokens, idx);
			count += skipped;
			idx += skipped;
		}
		break;
	case JSMN_ARRAY:
		for (i = 0; i < tokens[index].size; i++) {
			int skipped = authz_skip_token(tokens, idx);
			count += skipped;
			idx += skipped;
		}
		break;
	default:
		break;
	}
	return count;
}

static char *authz_normalize_fingerprint(const char *input)
{
	size_t len;
	size_t i;
	char *out;
	char *p;
	if (!input)
		return NULL;
	len = strlen(input);
	out = calloc(1, len + 1);
	if (!out)
		return NULL;
	p = out;
	for (i = 0; i < len; i++) {
		char c = input[i];
		if (c == ':' || c == ' ' || c == '\t' || c == '\n' || c == '\r')
			continue;
		*p++ = (char)tolower((unsigned char)c);
	}
	*p = '\0';
	return out;
}

static int authz_add_string(char ***list, size_t *count, const char *value)
{
	char **tmp;
	char *copy;

	if (!value)
		return 0;
	copy = strdup(value);
	if (!copy)
		return 0;
	tmp = realloc(*list, sizeof(char *) * (*count + 1));
	if (!tmp) {
		free(copy);
		return 0;
	}
	tmp[*count] = copy;
	*list = tmp;
	*count += 1;
	return 1;
}

static void authz_rule_set_call(AuthzRule *rule, const char *name)
{
	int i;
	if (!name)
		return;
	for (i = 0; i < GCK_RPC_CALL_MAX; i++) {
		if (gck_rpc_calls[i].name && strcmp(gck_rpc_calls[i].name, name) == 0) {
			rule->allowed_calls[i] = 1;
			return;
		}
	}
	gck_rpc_warn("AUTHZ: unknown pkcs11_functions entry '%s'", name);
}

static int authz_parse_string_array(const char *json, const jsmntok_t *tokens,
		int index, char ***out, size_t *out_count)
{
	int i;
	int idx;
	const jsmntok_t *arr;

	arr = &tokens[index];
	if (arr->type != JSMN_ARRAY)
		return 0;
	idx = index + 1;
	for (i = 0; i < arr->size; i++) {
		const jsmntok_t *tok = &tokens[idx];
		char *val = authz_token_strdup(json, tok);
		if (val) {
			authz_add_string(out, out_count, val);
			free(val);
		}
		idx += authz_skip_token(tokens, idx);
	}
	return 1;
}

static int authz_parse_allow(const char *json, const jsmntok_t *tokens, int index, AuthzRule *rule)
{
	int i;
	int idx;
	const jsmntok_t *obj = &tokens[index];

	if (obj->type != JSMN_OBJECT)
		return 0;

	rule->tokens_unrestricted = 1;
	rule->objects_unrestricted = 1;

	idx = index + 1;
	for (i = 0; i < obj->size; i++) {
		const jsmntok_t *key = &tokens[idx];
		const jsmntok_t *val = &tokens[idx + 1];

		if (authz_token_eq(json, key, "pkcs11_functions") && val->type == JSMN_ARRAY) {
			int j;
			int arr_idx = idx + 2;
			for (j = 0; j < val->size; j++) {
				char *fn = authz_token_strdup(json, &tokens[arr_idx]);
				if (fn) {
					authz_rule_set_call(rule, fn);
					free(fn);
				}
				arr_idx += authz_skip_token(tokens, arr_idx);
			}
		} else if (authz_token_eq(json, key, "tokens") && val->type == JSMN_ARRAY) {
			authz_parse_string_array(json, tokens, idx + 1, &rule->tokens, &rule->tokens_count);
			if (rule->tokens_count > 0)
				rule->tokens_unrestricted = 0;
		} else if (authz_token_eq(json, key, "objects") && val->type == JSMN_ARRAY) {
			authz_parse_string_array(json, tokens, idx + 1, &rule->objects, &rule->objects_count);
			if (rule->objects_count > 0)
				rule->objects_unrestricted = 0;
		}

		idx += 1 + authz_skip_token(tokens, idx + 1);
	}

	return 1;
}

static int authz_add_rule(AuthzPolicy *policy, const AuthzRule *rule)
{
	AuthzRule *tmp;

	tmp = realloc(policy->rules, sizeof(AuthzRule) * (policy->rules_count + 1));
	if (!tmp)
		return 0;
	policy->rules = tmp;
	policy->rules[policy->rules_count] = *rule;
	policy->rules_count++;
	return 1;
}

static int authz_parse_clients(const char *json, const jsmntok_t *tokens, int index, AuthzPolicy *policy)
{
	int i;
	int idx;
	const jsmntok_t *arr = &tokens[index];

	if (arr->type != JSMN_ARRAY)
		return 0;

	idx = index + 1;
	for (i = 0; i < arr->size; i++) {
		AuthzRule rule;
		int j;
		int obj_index = idx;
		const jsmntok_t *obj = &tokens[obj_index];
		int obj_idx;
		memset(&rule, 0, sizeof(rule));
		rule.tokens_unrestricted = 1;
		rule.objects_unrestricted = 1;

		if (obj->type != JSMN_OBJECT) {
			idx += authz_skip_token(tokens, idx);
			continue;
		}

		obj_idx = obj_index + 1;
		for (j = 0; j < obj->size; j++) {
			const jsmntok_t *key = &tokens[obj_idx];
			const jsmntok_t *val = &tokens[obj_idx + 1];

			if (authz_token_eq(json, key, "id_type")) {
				rule.id_type = authz_token_strdup(json, val);
			} else if (authz_token_eq(json, key, "id")) {
				rule.id = authz_token_strdup(json, val);
			} else if (authz_token_eq(json, key, "allow")) {
				authz_parse_allow(json, tokens, obj_idx + 1, &rule);
			}

			obj_idx += 1 + authz_skip_token(tokens, obj_idx + 1);
		}

		if (rule.id_type && rule.id) {
			if (strcmp(rule.id_type, "cert_fingerprint_sha256") == 0) {
				char *normalized = authz_normalize_fingerprint(rule.id);
				free(rule.id);
				rule.id = normalized;
			} else if (strcmp(rule.id_type, "subject_cn") != 0 &&
				   strcmp(rule.id_type, "san_uri") != 0) {
				gck_rpc_warn("AUTHZ: unknown id_type '%s'", rule.id_type);
				free(rule.id_type);
				free(rule.id);
				authz_free_string_list(rule.tokens, rule.tokens_count);
				authz_free_string_list(rule.objects, rule.objects_count);
				idx += authz_skip_token(tokens, idx);
				continue;
			}
			authz_add_rule(policy, &rule);
		} else {
			free(rule.id_type);
			free(rule.id);
			authz_free_string_list(rule.tokens, rule.tokens_count);
			authz_free_string_list(rule.objects, rule.objects_count);
		}

		idx += authz_skip_token(tokens, idx);
	}
	return 1;
}

static AuthzPolicy *authz_policy_load(const char *path)
{
	AuthzPolicy *policy;
	char *json;
	char *json_sanitized = NULL;
	size_t len;
	jsmn_parser parser;
	jsmntok_t *tokens;
	int tok_count;
	int i;
	int idx;

	json = authz_read_file(path, &len);
	if (!json)
		return NULL;

	jsmn_init(&parser);
	tok_count = jsmn_parse(&parser, json, len, NULL, 0);
	if (tok_count < 0) {
		gck_rpc_warn("AUTHZ: failed to parse policy JSON (%s) on raw buffer", authz_jsmn_error(tok_count));
		authz_log_json_snippet("raw", json, len);

		authz_strip_bom(json, &len);
		authz_strip_trailing_nuls(json, &len);
		authz_sanitize_control_chars(json, len);

		jsmn_init(&parser);
		tok_count = jsmn_parse(&parser, json, len, NULL, 0);
		if (tok_count < 0) {
			gck_rpc_warn("AUTHZ: failed to parse policy JSON (%s) after sanitize", authz_jsmn_error(tok_count));
			authz_log_json_snippet("sanitized", json, len);

			json_sanitized = authz_extract_json_object(json, &len);
			if (!json_sanitized) {
				AuthzPolicy *fallback = authz_policy_load_fallback(json, len);
				free(json);
				return fallback;
			}
			free(json);
			json = json_sanitized;
			jsmn_init(&parser);
			tok_count = jsmn_parse(&parser, json, len, NULL, 0);
			if (tok_count < 0) {
				gck_rpc_warn("AUTHZ: failed to parse policy JSON (%s) after extract", authz_jsmn_error(tok_count));
				authz_log_json_snippet("extracted", json, len);
				AuthzPolicy *fallback = authz_policy_load_fallback(json, len);
				free(json);
				return fallback;
			}
		}
	}

	gck_rpc_warn("AUTHZ: first-pass token count=%d len=%zu", tok_count, len);

	tokens = calloc((size_t)tok_count + 1, sizeof(jsmntok_t));
	if (!tokens) {
		free(json);
		return NULL;
	}

	jsmn_init(&parser);
	tok_count = jsmn_parse(&parser, json, len, tokens, (unsigned int)tok_count + 1);
	if (tok_count < 0) {
		gck_rpc_warn("AUTHZ: failed to parse policy JSON (%s) on token pass (count=%d len=%zu)",
			     authz_jsmn_error(tok_count), tok_count, len);
		authz_log_json_snippet("token-pass", json, len);

		free(tokens);
		tokens = calloc((size_t)len + 256, sizeof(jsmntok_t));
		if (!tokens) {
			free(json);
			return NULL;
		}
		jsmn_init(&parser);
		tok_count = jsmn_parse(&parser, json, len, tokens, (unsigned int)len + 256);
		if (tok_count < 0) {
			gck_rpc_warn("AUTHZ: failed to parse policy JSON (%s) on oversized token pass", authz_jsmn_error(tok_count));
			authz_log_json_snippet("oversized-pass", json, len);
			free(tokens);
			free(json);
			return NULL;
		}
	}

	policy = calloc(1, sizeof(AuthzPolicy));
	if (!policy) {
		free(tokens);
		free(json);
		return NULL;
	}

	if (tokens[0].type != JSMN_OBJECT) {
		gck_rpc_warn("AUTHZ: policy root is not a JSON object");
		authz_policy_free_internal(policy);
		free(tokens);
		free(json);
		return NULL;
	}

	idx = 1;
	for (i = 0; i < tokens[0].size; i++) {
		const jsmntok_t *key = &tokens[idx];
		const jsmntok_t *val = &tokens[idx + 1];

		if (authz_token_eq(json, key, "version")) {
			int v;
			if (authz_token_to_int(json, val, &v))
				policy->version = v;
		} else if (authz_token_eq(json, key, "default")) {
			char *def = authz_token_strdup(json, val);
			if (def) {
				if (strcasecmp(def, "allow") == 0) {
					policy->default_allow = 1;
					policy->default_allow_set = 1;
				} else if (strcasecmp(def, "deny") == 0) {
					policy->default_allow = 0;
					policy->default_allow_set = 1;
				}
				free(def);
			}
		} else if (authz_token_eq(json, key, "clients")) {
			authz_parse_clients(json, tokens, idx + 1, policy);
		}

		idx += 1 + authz_skip_token(tokens, idx + 1);
	}

	free(tokens);
	free(json);
	return policy;
}

static AuthzPolicy *authz_policy_load_parsed(const char *path)
{
	AuthzPolicy *policy;
	AuthzParsedPolicy parsed;
	char err[256];
	size_t i;

	memset(&parsed, 0, sizeof(parsed));
	memset(err, 0, sizeof(err));
	if (!authz_policy_parse_file(path, &parsed, err, sizeof(err))) {
		gck_rpc_warn("AUTHZ: failed to parse policy JSON (%s)", err[0] ? err : "unknown");
		return NULL;
	}

	policy = calloc(1, sizeof(AuthzPolicy));
	if (!policy) {
		authz_policy_free(&parsed);
		return NULL;
	}
	policy->version = parsed.version;
	if (parsed.default_allow_set) {
		policy->default_allow = parsed.default_allow;
		policy->default_allow_set = 1;
	}

	for (i = 0; i < parsed.clients_count; i++) {
		AuthzRule rule;
		AuthzParsedClient *pc = &parsed.clients[i];
		size_t j;
		memset(&rule, 0, sizeof(rule));
		rule.tokens_unrestricted = 1;
		rule.objects_unrestricted = 1;

		if (pc->id_type)
			rule.id_type = strdup(pc->id_type);
		if (pc->id)
			rule.id = strdup(pc->id);

		for (j = 0; j < pc->allow.pkcs11_functions_count; j++)
			authz_rule_set_call(&rule, pc->allow.pkcs11_functions[j]);
		for (j = 0; j < pc->allow.tokens_count; j++)
			authz_add_string(&rule.tokens, &rule.tokens_count, pc->allow.tokens[j]);
		for (j = 0; j < pc->allow.objects_count; j++)
			authz_add_string(&rule.objects, &rule.objects_count, pc->allow.objects[j]);

		if (rule.tokens_count > 0)
			rule.tokens_unrestricted = 0;
		if (rule.objects_count > 0)
			rule.objects_unrestricted = 0;

		if (rule.id_type && rule.id) {
			if (strcmp(rule.id_type, "cert_fingerprint_sha256") == 0) {
				char *normalized = authz_normalize_fingerprint(rule.id);
				free(rule.id);
				rule.id = normalized;
			} else if (strcmp(rule.id_type, "subject_cn") != 0 &&
				   strcmp(rule.id_type, "san_uri") != 0) {
				gck_rpc_warn("AUTHZ: unknown id_type '%s'", rule.id_type);
				free(rule.id_type);
				free(rule.id);
				authz_free_string_list(rule.tokens, rule.tokens_count);
				authz_free_string_list(rule.objects, rule.objects_count);
				continue;
			}
			authz_add_rule(policy, &rule);
		} else {
			free(rule.id_type);
			free(rule.id);
			authz_free_string_list(rule.tokens, rule.tokens_count);
			authz_free_string_list(rule.objects, rule.objects_count);
		}
	}

	authz_policy_free(&parsed);
	return policy;
}

static int authz_list_match(char **patterns, size_t count, const char *value)
{
	size_t i;
	if (!patterns || !value)
		return 0;
	for (i = 0; i < count; i++) {
		if (fnmatch(patterns[i], value, 0) == 0)
			return 1;
	}
	return 0;
}

static int authz_client_match_rule(const GckRpcAuthzClient *client, const AuthzRule *rule)
{
	if (!client || !rule || !rule->id_type || !rule->id)
		return 0;

	if (strcmp(rule->id_type, "cert_fingerprint_sha256") == 0) {
		if (!client->fingerprint)
			return 0;
		return strcmp(client->fingerprint, rule->id) == 0;
	} else if (strcmp(rule->id_type, "subject_cn") == 0) {
		if (!client->subject_cn)
			return 0;
		return fnmatch(rule->id, client->subject_cn, 0) == 0;
	} else if (strcmp(rule->id_type, "san_uri") == 0) {
		size_t i;
		for (i = 0; i < client->san_uri_count; i++) {
			if (fnmatch(rule->id, client->san_uri[i], 0) == 0)
				return 1;
		}
		return 0;
	}

	return 0;
}

static void authz_copy_allowed_calls(unsigned char *dest, const unsigned char *src)
{
	int i;
	for (i = 0; i < AUTHZ_MAX_CALLS; i++) {
		if (src[i])
			dest[i] = 1;
	}
}

static int authz_append_list(char ***dest, size_t *dest_count, char **src, size_t src_count)
{
	size_t i;
	for (i = 0; i < src_count; i++) {
		if (!authz_add_string(dest, dest_count, src[i]))
			return 0;
	}
	return 1;
}

static char *authz_token_label_from_session(CK_SESSION_HANDLE session)
{
	CK_SESSION_INFO info;
	CK_TOKEN_INFO token;
	CK_RV rv;
	char label[33];
	int i;

	if (!authz_state.module)
		return NULL;
	rv = authz_state.module->C_GetSessionInfo(session, &info);
	if (rv != CKR_OK)
		return NULL;
	rv = authz_state.module->C_GetTokenInfo(info.slotID, &token);
	if (rv != CKR_OK)
		return NULL;

	memcpy(label, token.label, 32);
	label[32] = '\0';
	for (i = 31; i >= 0; i--) {
		if (label[i] == ' ' || label[i] == '\0')
			label[i] = '\0';
		else
			break;
	}
	return strdup(label);
}

static char *authz_token_label_from_slot(CK_SLOT_ID slot_id)
{
	CK_TOKEN_INFO token;
	CK_RV rv;
	char label[33];
	int i;

	if (!authz_state.module)
		return NULL;
	rv = authz_state.module->C_GetTokenInfo(slot_id, &token);
	if (rv != CKR_OK)
		return NULL;
	memcpy(label, token.label, 32);
	label[32] = '\0';
	for (i = 31; i >= 0; i--) {
		if (label[i] == ' ' || label[i] == '\0')
			label[i] = '\0';
		else
			break;
	}
	return strdup(label);
}

static char *authz_label_from_template(CK_ATTRIBUTE_PTR template, CK_ULONG count)
{
	CK_ULONG i;
	for (i = 0; i < count; i++) {
		CK_ATTRIBUTE_PTR attr = &template[i];
		if (attr->type == CKA_LABEL && attr->pValue && attr->ulValueLen > 0) {
			char *label = calloc(1, attr->ulValueLen + 1);
			if (!label)
				return NULL;
			memcpy(label, attr->pValue, attr->ulValueLen);
			label[attr->ulValueLen] = '\0';
			return label;
		}
	}
	return NULL;
}

static char *authz_label_from_object(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE object)
{
	CK_ATTRIBUTE attr;
	CK_RV rv;
	char *label;

	if (!authz_state.module)
		return NULL;

	attr.type = CKA_LABEL;
	attr.pValue = NULL;
	attr.ulValueLen = 0;
	rv = authz_state.module->C_GetAttributeValue(session, object, &attr, 1);
	if (rv != CKR_OK || attr.ulValueLen == CK_UNAVAILABLE_INFORMATION || attr.ulValueLen == 0)
		return NULL;

	label = calloc(1, attr.ulValueLen + 1);
	if (!label)
		return NULL;
	attr.pValue = label;
	rv = authz_state.module->C_GetAttributeValue(session, object, &attr, 1);
	if (rv != CKR_OK) {
		free(label);
		return NULL;
	}
	label[attr.ulValueLen] = '\0';
	return label;
}

static void authz_log_decision(const char *prefix, const GckRpcAuthzClient *client,
		const char *function, const char *token, const char *object, const char *reason)
{
	const char *fingerprint = client && client->fingerprint ? client->fingerprint : "-";
	const char *subject = client && client->subject ? client->subject : "-";
	const char *token_label = token ? token : "-";
	const char *object_label = object ? object : "-";
	const char *fn = function ? function : "-";
	const char *why = reason ? reason : "-";

	gck_rpc_log("%s fingerprint=%s subject=\"%s\" function=%s token=%s object=%s reason=%s",
			prefix, fingerprint, subject, fn, token_label, object_label, why);
	if (authz_state.log_debug) {
		fprintf(stderr, "%s fingerprint=%s subject=\"%s\" function=%s token=%s object=%s reason=%s\n",
			prefix, fingerprint, subject, fn, token_label, object_label, why);
		fflush(stderr);
	}
}

static int authz_function_allowed(GckRpcAuthzClientCtx *ctx, int call_id)
{
	if (!ctx)
		return 1;
	if (ctx->deny_all)
		return 0;
	if (ctx->allow_all)
		return 1;
	if (!ctx->matched)
		return authz_state.default_allow;
	if (call_id >= 0 && call_id < AUTHZ_MAX_CALLS)
		return ctx->allowed_calls[call_id] ? 1 : 0;
	return 0;
}

int gck_rpc_authz_is_enabled(void)
{
	return authz_state.mode != GCK_RPC_AUTHZ_MODE_DISABLED;
}

GckRpcAuthzMode gck_rpc_authz_mode(void)
{
	return authz_state.mode;
}

void gck_rpc_authz_set_module(CK_FUNCTION_LIST_PTR module)
{
	authz_state.module = module;
}

int gck_rpc_authz_init(void)
{
	const char *mode = authz_getenv("PKCS11_PROXY_AUTHZ_MODE");
	const char *policy_path = authz_getenv("PKCS11_PROXY_AUTHZ_FILE");
	const char *default_action = authz_getenv("PKCS11_PROXY_AUTHZ_DEFAULT");
	const char *log_level = authz_getenv("PKCS11_PROXY_AUTHZ_LOG_LEVEL");
	int default_set = 0;

	memset(&authz_state, 0, sizeof(authz_state));
	authz_state.mode = GCK_RPC_AUTHZ_MODE_DISABLED;
	authz_state.default_allow = 0;

	if (mode) {
		if (strcasecmp(mode, "enforce") == 0)
			authz_state.mode = GCK_RPC_AUTHZ_MODE_ENFORCE;
		else if (strcasecmp(mode, "audit") == 0)
			authz_state.mode = GCK_RPC_AUTHZ_MODE_AUDIT;
		else if (strcasecmp(mode, "disabled") == 0)
			authz_state.mode = GCK_RPC_AUTHZ_MODE_DISABLED;
		else
			gck_rpc_warn("AUTHZ: unknown PKCS11_PROXY_AUTHZ_MODE '%s'", mode);
	}

	if (default_action) {
		if (strcasecmp(default_action, "allow") == 0)
			authz_state.default_allow = 1;
		else if (strcasecmp(default_action, "deny") == 0)
			authz_state.default_allow = 0;
		else
			gck_rpc_warn("AUTHZ: unknown PKCS11_PROXY_AUTHZ_DEFAULT '%s'", default_action);
		default_set = 1;
	}

	if (log_level && strcasecmp(log_level, "debug") == 0)
		authz_state.log_debug = 1;

	if (authz_state.mode == GCK_RPC_AUTHZ_MODE_DISABLED)
		return 1;

	gck_rpc_warn("AUTHZ: mode=%d file=%s", authz_state.mode, policy_path ? policy_path : "(null)");

	if (!policy_path) {
		gck_rpc_warn("AUTHZ: PKCS11_PROXY_AUTHZ_FILE not set; default policy applies");
		return 1;
	}

	authz_state.policy = authz_policy_load_parsed(policy_path);
	if (!authz_state.policy) {
		gck_rpc_warn("AUTHZ: failed to load policy file '%s'", policy_path);
		return 1;
	}

	if (authz_state.policy->version != 0 && authz_state.policy->version != 1)
		gck_rpc_warn("AUTHZ: unexpected policy version %d", authz_state.policy->version);
	if (!default_set && authz_state.policy->default_allow_set)
		authz_state.default_allow = authz_state.policy->default_allow;

	return 1;
}

void gck_rpc_authz_shutdown(void)
{
	if (authz_state.policy)
		authz_policy_free_internal(authz_state.policy);
	memset(&authz_state, 0, sizeof(authz_state));
}

static void authz_client_free(GckRpcAuthzClient *client)
{
	if (!client)
		return;
	free(client->fingerprint);
	free(client->subject);
	free(client->subject_cn);
	authz_free_string_list(client->san_dns, client->san_dns_count);
	authz_free_string_list(client->san_uri, client->san_uri_count);
	authz_free_string_list(client->san_ip, client->san_ip_count);
	free(client);
}

static char *authz_x509_name_to_string(X509_NAME *name)
{
	BIO *bio;
	char *data = NULL;
	long len;
	char *out;

	if (!name)
		return NULL;
	bio = BIO_new(BIO_s_mem());
	if (!bio)
		return NULL;
	if (X509_NAME_print_ex(bio, name, 0, XN_FLAG_RFC2253) < 0) {
		BIO_free(bio);
		return NULL;
	}
	len = BIO_get_mem_data(bio, &data);
	if (len <= 0) {
		BIO_free(bio);
		return NULL;
	}
	out = calloc(1, (size_t)len + 1);
	if (out) {
		memcpy(out, data, (size_t)len);
		out[len] = '\0';
	}
	BIO_free(bio);
	return out;
}

static int authz_add_san_ip(GckRpcAuthzClient *client, const unsigned char *data, int len)
{
	char buf[INET6_ADDRSTRLEN];
	const char *res;

	if (len == 4)
		res = inet_ntop(AF_INET, data, buf, sizeof(buf));
	else if (len == 16)
		res = inet_ntop(AF_INET6, data, buf, sizeof(buf));
	else
		return 0;
	if (!res)
		return 0;
	return authz_add_string(&client->san_ip, &client->san_ip_count, buf);
}

static GckRpcAuthzClient *authz_client_from_cert(X509 *cert, int verified)
{
	GckRpcAuthzClient *client;
	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int md_len = 0;
	int cn_len;
	char cn_buf[256];
	GENERAL_NAMES *san_names;
	int i;

	client = calloc(1, sizeof(GckRpcAuthzClient));
	if (!client)
		return NULL;
	client->verified = verified;

	if (X509_digest(cert, EVP_sha256(), md, &md_len) == 1 && md_len > 0) {
		char *fp = calloc(1, md_len * 2 + 1);
		unsigned int j;
		if (fp) {
			for (j = 0; j < md_len; j++)
				sprintf(fp + j * 2, "%02x", md[j]);
			client->fingerprint = fp;
		}
	}

	client->subject = authz_x509_name_to_string(X509_get_subject_name(cert));

	cn_len = X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, cn_buf, sizeof(cn_buf));
	if (cn_len > 0) {
		cn_buf[sizeof(cn_buf) - 1] = '\0';
		client->subject_cn = strdup(cn_buf);
	}

	san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
	if (san_names) {
		int count = sk_GENERAL_NAME_num(san_names);
		for (i = 0; i < count; i++) {
			GENERAL_NAME *name = sk_GENERAL_NAME_value(san_names, i);
			if (!name)
				continue;
			if (name->type == GEN_DNS) {
				ASN1_IA5STRING *dns = name->d.dNSName;
				if (dns && dns->data)
					authz_add_string(&client->san_dns, &client->san_dns_count, (char *)dns->data);
			} else if (name->type == GEN_URI) {
				ASN1_IA5STRING *uri = name->d.uniformResourceIdentifier;
				if (uri && uri->data)
					authz_add_string(&client->san_uri, &client->san_uri_count, (char *)uri->data);
			} else if (name->type == GEN_IPADD) {
				ASN1_OCTET_STRING *ip = name->d.iPAddress;
				if (ip && ip->data)
					authz_add_san_ip(client, ip->data, ip->length);
			}
		}
		GENERAL_NAMES_free(san_names);
	}

	return client;
}

void gck_rpc_authz_client_ctx_init(GckRpcAuthzClientCtx *ctx, GckRpcTlsState *tls)
{
	size_t i;
	if (!ctx)
		return;
	memset(ctx, 0, sizeof(*ctx));

	if (authz_state.mode == GCK_RPC_AUTHZ_MODE_DISABLED)
		return;

	if (!tls || !tls->ssl) {
		if (authz_state.mode == GCK_RPC_AUTHZ_MODE_ENFORCE) {
			ctx->deny_all = 1;
			ctx->deny_all_peer = 1;
		}
		return;
	}

	{
		long verify_result = SSL_get_verify_result(tls->ssl);
		int verified = (verify_result == X509_V_OK);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
		X509 *peer = SSL_get1_peer_certificate(tls->ssl);
#else
		X509 *peer = SSL_get_peer_certificate(tls->ssl);
#endif
		if (peer) {
			ctx->client = authz_client_from_cert(peer, verified);
			X509_free(peer);
		}
		if (authz_state.mode == GCK_RPC_AUTHZ_MODE_ENFORCE && !verified) {
			ctx->deny_all = 1;
			ctx->deny_all_peer = 1;
		}
	}

	if (!authz_state.policy || !ctx->client)
		return;

	for (i = 0; i < authz_state.policy->rules_count; i++) {
		AuthzRule *rule = &authz_state.policy->rules[i];
		if (!authz_client_match_rule(ctx->client, rule))
			continue;
		ctx->matched = 1;
		authz_copy_allowed_calls(ctx->allowed_calls, rule->allowed_calls);
		if (rule->tokens_unrestricted)
			ctx->tokens_unrestricted = 1;
		else
			authz_append_list(&ctx->tokens, &ctx->tokens_count, rule->tokens, rule->tokens_count);
		if (rule->objects_unrestricted)
			ctx->objects_unrestricted = 1;
		else
			authz_append_list(&ctx->objects, &ctx->objects_count, rule->objects, rule->objects_count);
	}

	if (!ctx->matched) {
		ctx->allow_all = authz_state.default_allow ? 1 : 0;
	}
}

void gck_rpc_authz_client_ctx_free(GckRpcAuthzClientCtx *ctx)
{
	if (!ctx)
		return;
	authz_client_free(ctx->client);
	authz_free_string_list(ctx->tokens, ctx->tokens_count);
	authz_free_string_list(ctx->objects, ctx->objects_count);
	memset(ctx, 0, sizeof(*ctx));
}

CK_RV gck_rpc_authz_check_basic(GckRpcAuthzClientCtx *ctx, int call_id)
{
	const char *fn_name = NULL;
	int allowed;

	if (authz_state.mode == GCK_RPC_AUTHZ_MODE_DISABLED)
		return CKR_OK;
	if (!ctx)
		return CKR_OK;
	ctx->audit_would_deny = 0;

	if (call_id >= 0 && call_id < GCK_RPC_CALL_MAX)
		fn_name = gck_rpc_calls[call_id].name;

	if (ctx->deny_all) {
		const char *reason = ctx->deny_all_peer ? "peer_not_verified" : "deny_all";
		if (authz_state.mode == GCK_RPC_AUTHZ_MODE_AUDIT) {
			ctx->audit_would_deny = 1;
			authz_log_decision("AUTHZ AUDIT", ctx->client, fn_name, NULL, NULL, reason);
			return CKR_OK;
		}
		authz_log_decision("AUTHZ DENY", ctx->client, fn_name, NULL, NULL, reason);
		return CKR_FUNCTION_NOT_PERMITTED;
	}

	allowed = authz_function_allowed(ctx, call_id);
	if (allowed)
		return CKR_OK;

	if (authz_state.mode == GCK_RPC_AUTHZ_MODE_AUDIT) {
		ctx->audit_would_deny = 1;
		authz_log_decision("AUTHZ AUDIT", ctx->client, fn_name, NULL, NULL, "function_not_allowed");
		return CKR_OK;
	}

	authz_log_decision("AUTHZ DENY", ctx->client, fn_name, NULL, NULL, "function_not_allowed");
	return CKR_FUNCTION_NOT_PERMITTED;
}

CK_RV gck_rpc_authz_check_scoped(GckRpcAuthzClientCtx *ctx, int call_id, const GckRpcAuthzRequest *req)
{
	CK_RV rv = CKR_OK;
	char *token_label = NULL;
	char *object_label = NULL;
	const char *fn_name = NULL;
	int deny = 0;

	if (authz_state.mode == GCK_RPC_AUTHZ_MODE_DISABLED)
		return CKR_OK;
	if (!ctx || !ctx->matched)
		return CKR_OK;
	if (ctx->audit_would_deny)
		return CKR_OK;

	if (call_id >= 0 && call_id < GCK_RPC_CALL_MAX)
		fn_name = gck_rpc_calls[call_id].name;

	if (!ctx->tokens_unrestricted) {
		if (req && req->has_slot)
			token_label = authz_token_label_from_slot(req->slot_id);
		else if (req && req->has_session)
			token_label = authz_token_label_from_session(req->session);

		if (token_label && !authz_list_match(ctx->tokens, ctx->tokens_count, token_label))
			deny = 1;
	}

	if (!deny && !ctx->objects_unrestricted) {
		if (req && req->template && req->template_count > 0)
			object_label = authz_label_from_template(req->template, req->template_count);

		if (!object_label && req && req->has_object && req->has_session)
			object_label = authz_label_from_object(req->session, req->object);

		if (object_label && !authz_list_match(ctx->objects, ctx->objects_count, object_label))
			deny = 1;
	}

	if (!deny)
		goto cleanup;

	if (authz_state.mode == GCK_RPC_AUTHZ_MODE_AUDIT) {
		authz_log_decision("AUTHZ AUDIT", ctx->client, fn_name, token_label, object_label, "scope_not_allowed");
		rv = CKR_OK;
		goto cleanup;
	}

	authz_log_decision("AUTHZ DENY", ctx->client, fn_name, token_label, object_label, "scope_not_allowed");
	rv = CKR_FUNCTION_NOT_PERMITTED;

cleanup:
	free(token_label);
	free(object_label);
	return rv;
}
