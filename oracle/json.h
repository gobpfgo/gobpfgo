// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

#ifndef ORACLE_JSON_H
#define ORACLE_JSON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define JSON_MAX_DEPTH 32

struct json {
	FILE *out;
	int depth;
	bool first[JSON_MAX_DEPTH + 1];
	bool compact[JSON_MAX_DEPTH + 1];
};

void json_init(struct json *j, FILE *out);
void json_obj_begin(struct json *j, const char *key);
void json_obj_begin_compact(struct json *j, const char *key);
void json_obj_end(struct json *j);
void json_arr_begin(struct json *j, const char *key);
void json_arr_end(struct json *j);
void json_str(struct json *j, const char *key, const char *value);
void json_bool(struct json *j, const char *key, bool value);
void json_u32(struct json *j, const char *key, uint32_t value);
void json_s32(struct json *j, const char *key, int32_t value);
void json_u64(struct json *j, const char *key, uint64_t value);
void json_hex(struct json *j, const char *key, const uint8_t *data, size_t len);

#endif
