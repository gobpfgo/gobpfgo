// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "json.h"

#include <stdlib.h>
#include <string.h>

static void json_indent(struct json *j) {
	int i;

	for (i = 0; i < j->depth; i++)
		fputs("  ", j->out);
}

static void json_quote(FILE *out, const char *value) {
	const unsigned char *p = (const unsigned char *)(value ? value : "");

	fputc('"', out);
	for (; *p; p++) {
		switch (*p) {
		case '"':
		case '\\':
			fputc('\\', out);
			fputc(*p, out);
			break;
		case '\n':
			fputs("\\n", out);
			break;
		default:
			fputc(*p, out);
			break;
		}
	}
	fputc('"', out);
}

static void json_begin(struct json *j, const char *key) {
	if (j->depth > 0) {
		if (j->compact[j->depth]) {
			if (!j->first[j->depth])
				fputs(", ", j->out);
		} else {
			fputs(j->first[j->depth] ? "\n" : ",\n", j->out);
			json_indent(j);
		}
		j->first[j->depth] = false;
	}

	if (key) {
		json_quote(j->out, key);
		fputs(": ", j->out);
	}
}

static void json_push(struct json *j) {
	if (j->depth >= JSON_MAX_DEPTH) {
		fprintf(stderr, "json: nesting too deep\n");
		exit(1);
	}

	j->depth++;
	j->first[j->depth]   = true;
	j->compact[j->depth] = false;
}

void json_init(struct json *j, FILE *out) {
	memset(j, 0, sizeof(*j));
	j->out      = out;
	j->first[0] = true;
}

void json_obj_begin(struct json *j, const char *key) {
	json_begin(j, key);
	fputc('{', j->out);
	json_push(j);
}

void json_obj_begin_compact(struct json *j, const char *key) {
	json_begin(j, key);
	fputc('{', j->out);
	json_push(j);
	j->compact[j->depth] = true;
}

void json_obj_end(struct json *j) {
	bool compact = j->compact[j->depth];

	j->depth--;
	if (compact) {
		fputc('}', j->out);
		return;
	}

	fputc('\n', j->out);
	json_indent(j);
	fputc('}', j->out);
}

void json_arr_begin(struct json *j, const char *key) {
	json_begin(j, key);
	fputc('[', j->out);
	json_push(j);
}

void json_arr_begin_compact(struct json *j, const char *key) {
	json_begin(j, key);
	fputc('[', j->out);
	json_push(j);
	j->compact[j->depth] = true;
}

void json_arr_end(struct json *j) {
	bool compact = j->compact[j->depth];

	j->depth--;
	if (compact) {
		fputc(']', j->out);
		return;
	}

	fputc('\n', j->out);
	json_indent(j);
	fputc(']', j->out);
}

void json_str(struct json *j, const char *key, const char *value) {
	json_begin(j, key);
	json_quote(j->out, value);
}

void json_bool(struct json *j, const char *key, bool value) {
	json_begin(j, key);
	fputs(value ? "true" : "false", j->out);
}

void json_u32(struct json *j, const char *key, uint32_t value) {
	json_begin(j, key);
	fprintf(j->out, "%u", value);
}

void json_s32(struct json *j, const char *key, int32_t value) {
	json_begin(j, key);
	fprintf(j->out, "%d", value);
}

void json_u64(struct json *j, const char *key, uint64_t value) {
	json_begin(j, key);
	fprintf(j->out, "%llu", (unsigned long long)value);
}

void json_s64(struct json *j, const char *key, int64_t value) {
	json_begin(j, key);
	fprintf(j->out, "%lld", (long long)value);
}

void json_hex(struct json *j, const char *key, const uint8_t *data, size_t len) {
	size_t i;

	json_begin(j, key);
	fputc('"', j->out);
	for (i = 0; i < len; i++)
		fprintf(j->out, "%02x", data[i]);
	fputc('"', j->out);
}
