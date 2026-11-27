// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#ifndef ORACLE_H
#define ORACLE_H

#include "json.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ORACLE_LIBBPF_COMMIT "4f05fb027a08a8a66d03916cf6a68a91e2c720ea"
#define ORACLE_ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define ORACLE_OFFSETOFEND(type, field) (offsetof(type, field) + sizeof(((type *)0)->field))

struct oracle_meta {
	const char *case_name;
	bool commit;
	bool version;
};

struct oracle_field {
	const char *name;
	size_t offset;
	size_t size;
};

int oracle_layout(void);
int oracle_attr(void);
int oracle_open(const char *path);
int oracle_load(const char *path);
int oracle_attach(const char *path);
int oracle_dump(const char *path);
int oracle_dump_decl(const char *path);
int oracle_dump_decl_strip(const char *path);
int oracle_ringbuf(const char *path);
int oracle_perfbuf(const char *path);
int oracle_probe(void);
int oracle_linker(const char *const *paths, int count);
int oracle_dedup(const char *const *paths, int count);
int oracle_core(const char *path);
int oracle_core_reloc(const char *path, const char *target_path);
int oracle_linfo(void);
int oracle_zip(void);
int oracle_usdt(const char *path);
int oracle_kconfig(const char *path);

void oracle_meta(struct json *j, const struct oracle_meta *meta);
void oracle_field_block(struct json *j, const char *name, const struct oracle_field *fields, size_t count, size_t size);
const char *oracle_basename(const char *path);

#endif
