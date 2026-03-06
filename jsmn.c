/*
 * MIT License
 *
 * Copyright (c) 2010 Serge A. Zaitsev
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "jsmn.h"

#include <stdlib.h>
#include <string.h>

/**
 * Allocates a fresh unused token from the token pool.
 */
static jsmntok_t *jsmn_alloc_token(jsmn_parser *parser,
		jsmntok_t *tokens, unsigned int num_tokens)
{
	jsmntok_t *tok;
	if (parser->toknext >= num_tokens) {
		return NULL;
	}
	tok = &tokens[parser->toknext++];
	tok->start = tok->end = -1;
	tok->size = 0;
#ifdef JSMN_PARENT_LINKS
	tok->parent = -1;
#endif
	return tok;
}

/**
 * Fills token type and boundaries.
 */
static void jsmn_fill_token(jsmntok_t *token, jsmntype_t type,
		int start, int end)
{
	token->type = type;
	token->start = start;
	token->end = end;
	token->size = 0;
}

/**
 * Fills next available token with JSON primitive.
 */
static int jsmn_parse_primitive(jsmn_parser *parser, const char *js,
		size_t len, jsmntok_t *tokens, unsigned int num_tokens)
{
	jsmntok_t *token;
	int start;

	start = parser->pos;

	for (; parser->pos < len; parser->pos++) {
		switch (js[parser->pos]) {
		case '\t' : case '\r' : case '\n' : case ' ':
		case ','  : case ']'  : case '}':
			goto found;
		default:
			if (js[parser->pos] < 32 || js[parser->pos] >= 127) {
				parser->pos = start;
				return JSMN_ERROR_INVAL;
			}
		}
	}
found:
	if (tokens == NULL) {
		parser->pos--;
		return 0;
	}
	token = jsmn_alloc_token(parser, tokens, num_tokens);
	if (token == NULL) {
		parser->pos = start;
		return JSMN_ERROR_NOMEM;
	}
	jsmn_fill_token(token, JSMN_PRIMITIVE, start, parser->pos);
#ifdef JSMN_PARENT_LINKS
	token->parent = parser->toksuper;
#endif
	parser->pos--;
	return 0;
}

/**
 * Fills next token with JSON string.
 */
static int jsmn_parse_string(jsmn_parser *parser, const char *js,
		size_t len, jsmntok_t *tokens, unsigned int num_tokens)
{
	jsmntok_t *token;
	int start = parser->pos;

	parser->pos++;

	for (; parser->pos < len; parser->pos++) {
		char c = js[parser->pos];

		/* Quote: end of string */
		if (c == '"') {
			if (tokens == NULL) {
				return 0;
			}
			token = jsmn_alloc_token(parser, tokens, num_tokens);
			if (token == NULL) {
				parser->pos = start;
				return JSMN_ERROR_NOMEM;
			}
			jsmn_fill_token(token, JSMN_STRING, start + 1, parser->pos);
#ifdef JSMN_PARENT_LINKS
			token->parent = parser->toksuper;
#endif
			return 0;
		}

		/* Backslash: Quoted symbol expected */
		if (c == '\\') {
			parser->pos++;
			switch (js[parser->pos]) {
			case '"': case '/' : case '\\' : case 'b' : case 'f' :
			case 'r' : case 'n' : case 't' :
				break;
			case 'u':
				/* TODO */
				break;
			default:
				parser->pos = start;
				return JSMN_ERROR_INVAL;
			}
		}
	}
	parser->pos = start;
	return JSMN_ERROR_PART;
}

/**
 * Initialize JSON parser.
 */
void jsmn_init(jsmn_parser *parser)
{
	parser->pos = 0;
	parser->toknext = 0;
	parser->toksuper = -1;
}

/**
 * Parse JSON string and fill tokens.
 */
int jsmn_parse(jsmn_parser *parser, const char *js, size_t len,
		jsmntok_t *tokens, unsigned int num_tokens)
{
	int r;
	int i;
	jsmntok_t *token;
	int count = parser->toknext;

	for (; parser->pos < len; parser->pos++) {
		char c = js[parser->pos];
		switch (c) {
		case '{': case '[':
			count++;
			if (tokens == NULL) {
				break;
			}
			token = jsmn_alloc_token(parser, tokens, num_tokens);
			if (token == NULL)
				return JSMN_ERROR_NOMEM;
			if (parser->toksuper != -1) {
				tokens[parser->toksuper].size++;
#ifdef JSMN_PARENT_LINKS
				token->parent = parser->toksuper;
#endif
			}
			token->type = (c == '{' ? JSMN_OBJECT : JSMN_ARRAY);
			token->start = parser->pos;
			parser->toksuper = parser->toknext - 1;
			break;
		case '}': case ']':
			if (tokens == NULL)
				break;
			{
				jsmntype_t type = (c == '}' ? JSMN_OBJECT : JSMN_ARRAY);
				for (i = parser->toknext - 1; i >= 0; i--) {
					token = &tokens[i];
					if (token->start != -1 && token->end == -1) {
						if (token->type != type) {
							return JSMN_ERROR_INVAL;
						}
						token->end = parser->pos + 1;
						parser->toksuper = -1;
#ifdef JSMN_PARENT_LINKS
						parser->toksuper = token->parent;
#else
						for (i = i - 1; i >= 0; i--) {
							if (tokens[i].start != -1 && tokens[i].end == -1) {
								parser->toksuper = i;
								break;
							}
						}
#endif
						break;
					}
				}
				if (i == -1) return JSMN_ERROR_INVAL;
			}
			break;
		case '"':
			r = jsmn_parse_string(parser, js, len, tokens, num_tokens);
			if (r < 0) return r;
			count++;
			if (parser->toksuper != -1 && tokens != NULL)
				tokens[parser->toksuper].size++;
			break;
		case '\t' : case '\r' : case '\n' : case ' ':
			break;
		case ':':
			parser->toksuper = parser->toknext - 1;
			break;
		case ',':
			if (tokens != NULL && parser->toksuper != -1 &&
				tokens[parser->toksuper].type != JSMN_ARRAY &&
				tokens[parser->toksuper].type != JSMN_OBJECT) {
#ifdef JSMN_PARENT_LINKS
				parser->toksuper = tokens[parser->toksuper].parent;
#endif
			}
			break;
		default:
			r = jsmn_parse_primitive(parser, js, len, tokens, num_tokens);
			if (r < 0) return r;
			count++;
			if (parser->toksuper != -1 && tokens != NULL)
				tokens[parser->toksuper].size++;
			break;
		}
	}

	for (i = parser->toknext - 1; i >= 0; i--) {
		if (tokens[i].start != -1 && tokens[i].end == -1) {
			return JSMN_ERROR_PART;
		}
	}

	return count;
}
