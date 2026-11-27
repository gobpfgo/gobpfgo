// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include "libbpf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * The base config sets every CONFIG_ extern of kconfig_types.bpf.o, so libbpf
 * never falls back to the system config and the results do not depend on the
 * host. It has no final newline. A case puts its lines in front of it, and
 * the first value an extern sees wins.
 */
static const char kconfig_base[] =
	"CONFIG_GOBPFGO_BOOL=y\n"
	"CONFIG_GOBPFGO_CHAR=m\n"
	"CONFIG_GOBPFGO_U8=200\n"
	"CONFIG_GOBPFGO_S16=-2\n"
	"CONFIG_GOBPFGO_S32=-100\n"
	"CONFIG_GOBPFGO_U32=0xdeadbeef\n"
	"CONFIG_GOBPFGO_S64=-1\n"
	"CONFIG_GOBPFGO_U64=0x0123456789abcdef\n"
	"CONFIG_GOBPFGO_TRISTATE=m\n"
	"CONFIG_GOBPFGO_STR=\"abc\"\n"
	"CONFIG_GOBPFGO_STRONG=7";

struct kconfig_case {
	const char *name;
	const char *kconfig;
};

static const struct kconfig_case kconfig_cases[] = {
	{"base", ""},
	{"blank-lines", "\n\n"},
	{"comment", "# CONFIG_GOBPFGO_U32 is not set\n"},
	{"other-prefix", "GOBPFGO_U32=5\n"},
	{"unknown-name", "CONFIG_GOBPFGO_OTHER=1\n"},
	{"unknown-bad-value", "CONFIG_GOBPFGO_OTHER=\"x\n"},
	{"first-wins", "CONFIG_GOBPFGO_U32=1\nCONFIG_GOBPFGO_U32=2\n"},
	{"no-separator", "CONFIG_GOBPFGO_U32\n"},
	{"no-value", "CONFIG_GOBPFGO_U32=\n"},
	{"no-value-unknown", "CONFIG_GOBPFGO_OTHER=\n"},
	{"bool-n", "CONFIG_GOBPFGO_BOOL=n\n"},
	{"bool-yes", "CONFIG_GOBPFGO_BOOL=yes\n"},
	{"bool-m", "CONFIG_GOBPFGO_BOOL=m\n"},
	{"bool-1", "CONFIG_GOBPFGO_BOOL=1\n"},
	{"bool-str", "CONFIG_GOBPFGO_BOOL=\"y\"\n"},
	{"char-y", "CONFIG_GOBPFGO_CHAR=y\n"},
	{"char-num", "CONFIG_GOBPFGO_CHAR=65\n"},
	{"char-min", "CONFIG_GOBPFGO_CHAR=-128\n"},
	{"char-range", "CONFIG_GOBPFGO_CHAR=128\n"},
	{"char-str", "CONFIG_GOBPFGO_CHAR=\"a\"\n"},
	{"u8-max", "CONFIG_GOBPFGO_U8=255\n"},
	{"u8-range", "CONFIG_GOBPFGO_U8=256\n"},
	{"u8-negative", "CONFIG_GOBPFGO_U8=-1\n"},
	{"u8-tri", "CONFIG_GOBPFGO_U8=n\n"},
	{"s16-max", "CONFIG_GOBPFGO_S16=32767\n"},
	{"s16-min", "CONFIG_GOBPFGO_S16=-32768\n"},
	{"s16-range", "CONFIG_GOBPFGO_S16=32768\n"},
	{"s16-octal", "CONFIG_GOBPFGO_S16=0777\n"},
	{"s16-bad-octal", "CONFIG_GOBPFGO_S16=08\n"},
	{"s32-min", "CONFIG_GOBPFGO_S32=-2147483648\n"},
	{"s32-range", "CONFIG_GOBPFGO_S32=2147483648\n"},
	{"s32-tri", "CONFIG_GOBPFGO_S32=y\n"},
	{"u32-max", "CONFIG_GOBPFGO_U32=4294967295\n"},
	{"u32-range", "CONFIG_GOBPFGO_U32=4294967296\n"},
	{"u32-hex-upper", "CONFIG_GOBPFGO_U32=0XAbC\n"},
	{"u32-space", "CONFIG_GOBPFGO_U32= \t42\n"},
	{"u32-plus", "CONFIG_GOBPFGO_U32=+42\n"},
	{"u32-trailing-space", "CONFIG_GOBPFGO_U32=42 \n"},
	{"u32-crlf", "CONFIG_GOBPFGO_U32=42\r\n"},
	{"u32-0x", "CONFIG_GOBPFGO_U32=0x\n"},
	{"u32-word", "CONFIG_GOBPFGO_U32=abc\n"},
	{"u32-sign-only", "CONFIG_GOBPFGO_U32=-\n"},
	{"s64-min", "CONFIG_GOBPFGO_S64=-9223372036854775808\n"},
	{"u64-max", "CONFIG_GOBPFGO_U64=18446744073709551615\n"},
	{"u64-overflow", "CONFIG_GOBPFGO_U64=18446744073709551616\n"},
	{"u64-negative-overflow", "CONFIG_GOBPFGO_U64=-18446744073709551616\n"},
	{"u64-negative-hex", "CONFIG_GOBPFGO_U64=-0x10\n"},
	{"tristate-y", "CONFIG_GOBPFGO_TRISTATE=y\n"},
	{"tristate-n", "CONFIG_GOBPFGO_TRISTATE=n\n"},
	{"tristate-num", "CONFIG_GOBPFGO_TRISTATE=1\n"},
	{"tristate-str", "CONFIG_GOBPFGO_TRISTATE=\"y\"\n"},
	{"str", "CONFIG_GOBPFGO_STR=\"hello\"\n"},
	{"str-empty", "CONFIG_GOBPFGO_STR=\"\"\n"},
	{"str-fits", "CONFIG_GOBPFGO_STR=\"0123456\"\n"},
	{"str-truncated", "CONFIG_GOBPFGO_STR=\"0123456789\"\n"},
	{"str-inner-quote", "CONFIG_GOBPFGO_STR=\"a\"b\"\n"},
	{"str-unterminated", "CONFIG_GOBPFGO_STR=\"abc\n"},
	{"str-quote-only", "CONFIG_GOBPFGO_STR=\"\n"},
	{"str-tri", "CONFIG_GOBPFGO_STR=y\n"},
	{"str-num", "CONFIG_GOBPFGO_STR=1\n"},
	{"strong", "CONFIG_GOBPFGO_STRONG=-1\n"},
};

/*
 * kconfig_resolve opens the object with kconfig as the extra config and runs
 * libbpf's load with a generated loader, which resolves the externs without
 * creating anything in the kernel. It prints the load errno and the .kconfig
 * map value as libbpf left it, also after a failure.
 */
static int kconfig_resolve(struct json *j, const char *path, const char *kconfig) {
	LIBBPF_OPTS(bpf_object_open_opts, opts, .kconfig = kconfig);
	LIBBPF_OPTS(gen_loader_opts, gen);
	const struct bpf_map *map;
	struct bpf_object *obj;
	size_t size = 0;
	void *value;
	int err;

	obj = bpf_object__open_file(path, &opts);
	if (!obj) {
		fprintf(stderr, "open %s failed\n", path);
		return 1;
	}

	err = bpf_object__gen_loader(obj, &gen);
	if (!err)
		err = bpf_object__load(obj);
	json_s32(j, "errno", err);

	map   = bpf_object__find_map_by_name(obj, ".kconfig");
	value = map ? bpf_map__initial_value(map, &size) : NULL;
	json_hex(j, "value", value, value ? size : 0);

	bpf_object__close(obj);
	return 0;
}

int oracle_kconfig(const char *path) {
	struct oracle_meta meta = {.case_name = "kconfig", .commit = true};
	libbpf_print_fn_t old_print;
	struct json j;
	char *kconfig;
	size_t i;
	int err = 0;

	old_print = libbpf_set_print(NULL);

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);
	json_str(&j, "object", oracle_basename(path));
	json_str(&j, "base", kconfig_base);

	json_arr_begin(&j, "cases");
	for (i = 0; i < ORACLE_ARRAY_SIZE(kconfig_cases) && !err; i++) {
		const struct kconfig_case *c = &kconfig_cases[i];

		kconfig = malloc(strlen(c->kconfig) + sizeof(kconfig_base));
		if (!kconfig) {
			perror("malloc");
			err = 1;
			break;
		}
		strcpy(kconfig, c->kconfig);
		strcat(kconfig, kconfig_base);

		json_obj_begin_compact(&j, NULL);
		json_str(&j, "name", c->name);
		json_str(&j, "kconfig", c->kconfig);
		err = kconfig_resolve(&j, path, kconfig);
		json_obj_end(&j);
		free(kconfig);
	}
	json_arr_end(&j);

	json_obj_end(&j);
	fputc('\n', stdout);

	libbpf_set_print(old_print);
	return err;
}
