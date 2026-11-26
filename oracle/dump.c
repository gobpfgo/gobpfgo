// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include "btf.h"
#include "libbpf.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void dump_printf(void *ctx, const char *fmt, va_list args) {
	(void)ctx;
	vprintf(fmt, args);
}

int oracle_dump(const char *path) {
	struct btf *btf;
	struct btf_dump *dump;
	long err;

	btf = btf__parse_elf(path, NULL);
	err = libbpf_get_error(btf);
	if (err) {
		fprintf(stderr, "parse %s: %s\n", path, strerror((int)-err));
		return 1;
	}

	dump = btf_dump__new(btf, dump_printf, NULL, NULL);
	err  = libbpf_get_error(dump);
	if (err) {
		fprintf(stderr, "btf_dump__new: %s\n", strerror((int)-err));
		btf__free(btf);
		return 1;
	}

	for (__u32 id = 1; id < btf__type_cnt(btf); id++) {
		if (btf_dump__dump_type(dump, id)) {
			fprintf(stderr, "btf_dump__dump_type %u failed\n", id);
			btf_dump__free(dump);
			btf__free(btf);
			return 1;
		}
	}

	btf_dump__free(dump);
	btf__free(btf);
	return 0;
}

static int dump_decl_common(const char *path, bool strip_mods) {
	LIBBPF_OPTS(btf_dump_emit_type_decl_opts, opts, .field_name = "field", .strip_mods = strip_mods);
	struct btf *btf;
	struct btf_dump *dump;
	long err;

	btf = btf__parse_elf(path, NULL);
	err = libbpf_get_error(btf);
	if (err) {
		fprintf(stderr, "parse %s: %s\n", path, strerror((int)-err));
		return 1;
	}

	dump = btf_dump__new(btf, dump_printf, NULL, NULL);
	err  = libbpf_get_error(dump);
	if (err) {
		fprintf(stderr, "btf_dump__new: %s\n", strerror((int)-err));
		btf__free(btf);
		return 1;
	}

	for (__u32 id = 1; id < btf__type_cnt(btf); id++) {
		switch (btf_kind(btf__type_by_id(btf, id))) {
		case BTF_KIND_VAR:
		case BTF_KIND_DATASEC:
		case BTF_KIND_FUNC:
		case BTF_KIND_DECL_TAG:
			continue;
		}
		if (btf_dump__emit_type_decl(dump, id, &opts)) {
			fprintf(stderr, "btf_dump__emit_type_decl %u failed\n", id);
			btf_dump__free(dump);
			btf__free(btf);
			return 1;
		}
		printf(";\n");
	}

	btf_dump__free(dump);
	btf__free(btf);
	return 0;
}

int oracle_dump_decl(const char *path) {
	return dump_decl_common(path, false);
}

int oracle_dump_decl_strip(const char *path) {
	return dump_decl_common(path, true);
}
