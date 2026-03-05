#include "authz-policy-parser.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "jsmn.h"

static void free_string_list(char **list, size_t count);
static int add_string(char ***list, size_t *count, const char *value);

static void set_err(char *err, size_t err_len, const char *msg)
{
	if (err && err_len > 0) {
		snprintf(err, err_len, "%s", msg);
	}
}

static char *read_file(const char *path, size_t *out_len, char *err, size_t err_len)
{
	FILE *fp;
	long len;
	char *buf;

	fp = fopen(path, "rb");
	if (!fp) {
		char tmp[256];
		snprintf(tmp, sizeof(tmp), "open failed: %s", strerror(errno));
		set_err(err, err_len, tmp);
		return NULL;
	}
	if (fseek(fp, 0, SEEK_END) != 0) {
		set_err(err, err_len, "fseek failed");
		fclose(fp);
		return NULL;
	}
	len = ftell(fp);
	if (len < 0) {
		set_err(err, err_len, "ftell failed");
		fclose(fp);
		return NULL;
	}
	if (fseek(fp, 0, SEEK_SET) != 0) {
		set_err(err, err_len, "fseek rewind failed");
		fclose(fp);
		return NULL;
	}
	buf = calloc(1, (size_t)len + 1);
	if (!buf) {
		set_err(err, err_len, "calloc failed");
		fclose(fp);
		return NULL;
	}
	if (fread(buf, 1, (size_t)len, fp) != (size_t)len) {
		set_err(err, err_len, "fread failed");
		free(buf);
		fclose(fp);
		return NULL;
	}
	fclose(fp);
	if (out_len)
		*out_len = (size_t)len;
	return buf;
}

static void strip_bom(char *buf, size_t *len)
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

static void strip_trailing_nuls(char *buf, size_t *len)
{
	while (buf && len && *len > 0 && buf[*len - 1] == '\0')
		(*len)--;
	if (buf && len)
		buf[*len] = '\0';
}

static void sanitize_control_chars(char *buf, size_t len)
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

static const char *skip_ws_range(const char *p, const char *end)
{
	while (p < end && isspace((unsigned char)*p))
		p++;
	return p;
}

static const char *parse_string_literal(const char *p, const char *end, char **out)
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

static const char *find_key_in_range(const char *start, const char *end, const char *key)
{
	const char *p = start;
	while (p < end) {
		p = skip_ws_range(p, end);
		if (p >= end)
			return NULL;
		if (*p == '"') {
			char *name = NULL;
			const char *after = parse_string_literal(p, end, &name);
			if (!after) {
				free(name);
				return NULL;
			}
			after = skip_ws_range(after, end);
			if (after < end && *after == ':') {
				after++;
				if (name && strcmp(name, key) == 0) {
					free(name);
					return skip_ws_range(after, end);
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

static const char *parse_string_array_literal(const char *p, const char *end,
					      char ***out, size_t *out_count)
{
	if (p >= end || *p != '[')
		return NULL;
	p++;
	p = skip_ws_range(p, end);
	while (p < end && *p != ']') {
		char *val = NULL;
		if (*p == '"') {
			const char *next = parse_string_literal(p, end, &val);
			if (!next) {
				free(val);
				return NULL;
			}
			add_string(out, out_count, val);
			free(val);
			p = skip_ws_range(next, end);
			if (p < end && *p == ',') {
				p++;
				p = skip_ws_range(p, end);
			}
		} else {
			p++;
		}
	}
	if (p < end && *p == ']')
		return p + 1;
	return NULL;
}

static int parse_allow_fallback(const char *start, const char *end, AuthzParsedAllow *allow)
{
	const char *p;
	p = find_key_in_range(start, end, "pkcs11_functions");
	if (p && *p == '[') {
		parse_string_array_literal(p, end, &allow->pkcs11_functions, &allow->pkcs11_functions_count);
	}
	p = find_key_in_range(start, end, "tokens");
	if (p && *p == '[') {
		parse_string_array_literal(p, end, &allow->tokens, &allow->tokens_count);
	}
	p = find_key_in_range(start, end, "objects");
	if (p && *p == '[') {
		parse_string_array_literal(p, end, &allow->objects, &allow->objects_count);
	}
	return 1;
}

static int parse_client_object_fallback(const char *start, const char *end, AuthzParsedPolicy *policy)
{
	AuthzParsedClient client;
	const char *p;
	memset(&client, 0, sizeof(client));

	p = find_key_in_range(start, end, "id_type");
	if (p && *p == '"')
		parse_string_literal(p, end, &client.id_type);

	p = find_key_in_range(start, end, "id");
	if (p && *p == '"')
		parse_string_literal(p, end, &client.id);

	p = find_key_in_range(start, end, "allow");
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
						parse_allow_fallback(allow_start, p + 1, &client.allow);
						break;
					}
				}
			}
		}
	}

	if (client.id_type && client.id) {
		AuthzParsedClient *tmp = realloc(policy->clients, sizeof(AuthzParsedClient) * (policy->clients_count + 1));
		if (tmp) {
			policy->clients = tmp;
			policy->clients[policy->clients_count] = client;
			policy->clients_count++;
			return 1;
		}
	}

	free(client.id_type);
	free(client.id);
	free_string_list(client.allow.pkcs11_functions, client.allow.pkcs11_functions_count);
	free_string_list(client.allow.tokens, client.allow.tokens_count);
	free_string_list(client.allow.objects, client.allow.objects_count);
	return 0;
}

static int policy_parse_fallback(const char *json, size_t len, AuthzParsedPolicy *policy)
{
	const char *end = json + len;
	const char *p;

	p = find_key_in_range(json, end, "version");
	if (p) {
		p = skip_ws_range(p, end);
		if (p < end && isdigit((unsigned char)*p))
			policy->version = (int)strtol(p, NULL, 10);
	}
	p = find_key_in_range(json, end, "default");
	if (p && *p == '"') {
		char *def = NULL;
		parse_string_literal(p, end, &def);
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
	p = find_key_in_range(json, end, "clients");
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
					parse_client_object_fallback(obj_start, p + 1, policy);
					obj_start = NULL;
				}
			}
		}
	}
	return policy->clients_count > 0;
}

static int token_eq(const char *json, const jsmntok_t *tok, const char *str)
{
	size_t len = (size_t)(tok->end - tok->start);
	return tok->type == JSMN_STRING && strlen(str) == len &&
		strncmp(json + tok->start, str, len) == 0;
}

static char *token_strdup(const char *json, const jsmntok_t *tok)
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

static int token_to_int(const char *json, const jsmntok_t *tok, int *value)
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
	v = strtol(tmp, &endptr, 10);
	free(tmp);
	if (endptr == tmp)
		return 0;
	*value = (int)v;
	return 1;
}

static int skip_token(const jsmntok_t *tokens, int index)
{
	int i;
	int skipped = 1;
	if (tokens[index].type == JSMN_OBJECT || tokens[index].type == JSMN_ARRAY) {
		for (i = 0; i < tokens[index].size; i++) {
			int child = index + skipped;
			skipped += skip_token(tokens, child);
			if (tokens[index].type == JSMN_OBJECT)
				i++;
		}
	}
	return skipped;
}

static void free_string_list(char **list, size_t count)
{
	size_t i;
	if (!list)
		return;
	for (i = 0; i < count; i++)
		free(list[i]);
	free(list);
}

static int add_string(char ***list, size_t *count, const char *value)
{
	char **tmp;
	char *dup;
	dup = strdup(value);
	if (!dup)
		return 0;
	tmp = realloc(*list, sizeof(char *) * (*count + 1));
	if (!tmp) {
		free(dup);
		return 0;
	}
	*list = tmp;
	(*list)[*count] = dup;
	(*count)++;
	return 1;
}

static int parse_string_array(const char *json, const jsmntok_t *tokens, int index,
				 char ***out, size_t *out_count)
{
	const jsmntok_t *arr = &tokens[index];
	int i;
	int idx;
	if (arr->type != JSMN_ARRAY)
		return 0;
	idx = index + 1;
	for (i = 0; i < arr->size; i++) {
		const jsmntok_t *tok = &tokens[idx];
		char *val = token_strdup(json, tok);
		if (val) {
			add_string(out, out_count, val);
			free(val);
		}
		idx += skip_token(tokens, idx);
	}
	return 1;
}

static int parse_allow(const char *json, const jsmntok_t *tokens, int index, AuthzParsedAllow *allow)
{
	const jsmntok_t *obj = &tokens[index];
	int i;
	int idx;
	if (obj->type != JSMN_OBJECT)
		return 0;
	idx = index + 1;
	for (i = 0; i < obj->size; i++) {
		const jsmntok_t *key = &tokens[idx];
		const jsmntok_t *val = &tokens[idx + 1];
		if (token_eq(json, key, "pkcs11_functions") && val->type == JSMN_ARRAY) {
			parse_string_array(json, tokens, idx + 1, &allow->pkcs11_functions, &allow->pkcs11_functions_count);
		} else if (token_eq(json, key, "tokens") && val->type == JSMN_ARRAY) {
			parse_string_array(json, tokens, idx + 1, &allow->tokens, &allow->tokens_count);
		} else if (token_eq(json, key, "objects") && val->type == JSMN_ARRAY) {
			parse_string_array(json, tokens, idx + 1, &allow->objects, &allow->objects_count);
		}
		idx += 1 + skip_token(tokens, idx + 1);
	}
	return 1;
}

static int parse_clients(const char *json, const jsmntok_t *tokens, int index, AuthzParsedPolicy *policy)
{
	const jsmntok_t *arr = &tokens[index];
	int i;
	int idx;
	if (arr->type != JSMN_ARRAY)
		return 0;
	idx = index + 1;
	for (i = 0; i < arr->size; i++) {
		AuthzParsedClient client;
		int j;
		const jsmntok_t *obj = &tokens[idx];
		int obj_idx;
		memset(&client, 0, sizeof(client));
		if (obj->type != JSMN_OBJECT) {
			idx += skip_token(tokens, idx);
			continue;
		}
		obj_idx = idx + 1;
		for (j = 0; j < obj->size; j++) {
			const jsmntok_t *key = &tokens[obj_idx];
			const jsmntok_t *val = &tokens[obj_idx + 1];
			if (token_eq(json, key, "id_type")) {
				client.id_type = token_strdup(json, val);
			} else if (token_eq(json, key, "id")) {
				client.id = token_strdup(json, val);
			} else if (token_eq(json, key, "allow")) {
				parse_allow(json, tokens, obj_idx + 1, &client.allow);
			}
			obj_idx += 1 + skip_token(tokens, obj_idx + 1);
		}
		if (client.id_type && client.id) {
			AuthzParsedClient *tmp = realloc(policy->clients, sizeof(AuthzParsedClient) * (policy->clients_count + 1));
			if (tmp) {
				policy->clients = tmp;
				policy->clients[policy->clients_count] = client;
				policy->clients_count++;
			} else {
				free(client.id_type);
				free(client.id);
				free_string_list(client.allow.pkcs11_functions, client.allow.pkcs11_functions_count);
				free_string_list(client.allow.tokens, client.allow.tokens_count);
				free_string_list(client.allow.objects, client.allow.objects_count);
			}
		} else {
			free(client.id_type);
			free(client.id);
			free_string_list(client.allow.pkcs11_functions, client.allow.pkcs11_functions_count);
			free_string_list(client.allow.tokens, client.allow.tokens_count);
			free_string_list(client.allow.objects, client.allow.objects_count);
		}
		idx += skip_token(tokens, idx);
	}
	return 1;
}

int authz_policy_parse_file(const char *path, AuthzParsedPolicy *out_policy, char *err, size_t err_len)
{
	char *json;
	size_t len;
	jsmn_parser parser;
	jsmntok_t *tokens;
	int tok_count;
	int i;
	int idx;

	if (!out_policy) {
		set_err(err, err_len, "out_policy is null");
		return 0;
	}
	memset(out_policy, 0, sizeof(*out_policy));

	json = read_file(path, &len, err, err_len);
	if (!json)
		return 0;

	strip_bom(json, &len);
	strip_trailing_nuls(json, &len);
	sanitize_control_chars(json, len);

	jsmn_init(&parser);
	tok_count = jsmn_parse(&parser, json, len, NULL, 0);
	if (tok_count < 0) {
		if (policy_parse_fallback(json, len, out_policy)) {
			free(json);
			return 1;
		}
		set_err(err, err_len, "json parse failed");
		free(json);
		return 0;
	}

	tokens = calloc((size_t)tok_count + 1, sizeof(jsmntok_t));
	if (!tokens) {
		set_err(err, err_len, "calloc tokens failed");
		free(json);
		return 0;
	}

	jsmn_init(&parser);
	tok_count = jsmn_parse(&parser, json, len, tokens, (unsigned int)tok_count + 1);
	if (tok_count < 0) {
		free(tokens);
		tokens = calloc((size_t)len + 256, sizeof(jsmntok_t));
		if (!tokens) {
			set_err(err, err_len, "calloc tokens failed");
			free(json);
			return 0;
		}
		jsmn_init(&parser);
		tok_count = jsmn_parse(&parser, json, len, tokens, (unsigned int)len + 256);
		if (tok_count < 0) {
			free(tokens);
			if (policy_parse_fallback(json, len, out_policy)) {
				free(json);
				return 1;
			}
			set_err(err, err_len, "json parse failed (tokens)");
			free(json);
			return 0;
		}
	}

	if (tokens[0].type != JSMN_OBJECT) {
		set_err(err, err_len, "root is not object");
		free(tokens);
		free(json);
		return 0;
	}

	idx = 1;
	for (i = 0; i < tokens[0].size; i++) {
		const jsmntok_t *key = &tokens[idx];
		const jsmntok_t *val = &tokens[idx + 1];
		if (token_eq(json, key, "version")) {
			int v;
			if (token_to_int(json, val, &v))
				out_policy->version = v;
		} else if (token_eq(json, key, "default")) {
			char *def = token_strdup(json, val);
			if (def) {
				if (strcasecmp(def, "allow") == 0) {
					out_policy->default_allow = 1;
					out_policy->default_allow_set = 1;
				} else if (strcasecmp(def, "deny") == 0) {
					out_policy->default_allow = 0;
					out_policy->default_allow_set = 1;
				}
				free(def);
			}
		} else if (token_eq(json, key, "clients")) {
			parse_clients(json, tokens, idx + 1, out_policy);
		}
		idx += 1 + skip_token(tokens, idx + 1);
	}

	free(tokens);
	free(json);
	return 1;
}

void authz_policy_free(AuthzParsedPolicy *policy)
{
	size_t i;
	if (!policy)
		return;
	for (i = 0; i < policy->clients_count; i++) {
		AuthzParsedClient *client = &policy->clients[i];
		free(client->id_type);
		free(client->id);
		free_string_list(client->allow.pkcs11_functions, client->allow.pkcs11_functions_count);
		free_string_list(client->allow.tokens, client->allow.tokens_count);
		free_string_list(client->allow.objects, client->allow.objects_count);
	}
	free(policy->clients);
	memset(policy, 0, sizeof(*policy));
}
