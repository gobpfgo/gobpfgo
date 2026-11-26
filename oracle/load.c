// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include "libbpf.h"
#include "bpf.h"

#include <linux/bpf.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void copy_name(char *dst, const char *src) {
	memcpy(dst, src, BPF_OBJ_NAME_LEN - 1);
	dst[BPF_OBJ_NAME_LEN - 1] = '\0';
}

static void map_json(struct json *j, struct bpf_map *map) {
	struct bpf_map_info info = {};
	char name[BPF_OBJ_NAME_LEN];
	__u32 len = sizeof(info);

	if (bpf_obj_get_info_by_fd(bpf_map__fd(map), &info, &len) != 0) {
		fprintf(stderr, "map info %s: %s\n", bpf_map__name(map), strerror(errno));
		exit(1);
	}
	copy_name(name, info.name);

	json_obj_begin_compact(j, NULL);
	json_str(j, "name", name);
	json_u32(j, "type", info.type);
	json_u32(j, "id", info.id);
	json_u32(j, "key_size", info.key_size);
	json_u32(j, "value_size", info.value_size);
	json_u32(j, "max_entries", info.max_entries);
	json_u32(j, "map_flags", info.map_flags);
	json_u32(j, "btf_key_type_id", info.btf_key_type_id);
	json_u32(j, "btf_value_type_id", info.btf_value_type_id);
	json_obj_end(j);
}

static void program_json(struct json *j, struct bpf_program *prog) {
	struct bpf_prog_info info = {};
	char name[BPF_OBJ_NAME_LEN];
	__u32 len = sizeof(info);

	if (bpf_obj_get_info_by_fd(bpf_program__fd(prog), &info, &len) != 0) {
		fprintf(stderr, "prog info %s: %s\n", bpf_program__name(prog), strerror(errno));
		exit(1);
	}
	copy_name(name, info.name);

	json_obj_begin_compact(j, NULL);
	json_str(j, "name", name);
	json_u32(j, "type", info.type);
	json_u32(j, "id", info.id);
	json_str(j, "section", bpf_program__section_name(prog));
	json_u64(j, "insn_cnt", bpf_program__insn_cnt(prog));
	json_u32(j, "xlated_insn_cnt", info.xlated_prog_len / 8);
	json_u32(j, "jited_prog_len", info.jited_prog_len);
	json_obj_end(j);
}

int oracle_load(const char *path) {
	struct oracle_meta meta = {.case_name = "load", .version = true};
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_map *map;
	struct json j;
	long err;
	int ret;

	obj = bpf_object__open_file(path, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "open %s: %s\n", path, strerror((int)-err));
		return 1;
	}

	ret = bpf_object__load(obj);
	if (ret) {
		fprintf(stderr, "load %s: %s\n", path, strerror(-ret));
		bpf_object__close(obj);
		return 1;
	}

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);

	json_str(&j, "object_name", bpf_object__name(obj));

	json_arr_begin(&j, "maps");
	for (map = bpf_object__next_map(obj, NULL); map; map = bpf_object__next_map(obj, map))
		map_json(&j, map);
	json_arr_end(&j);

	json_arr_begin(&j, "programs");
	for (prog = bpf_object__next_program(obj, NULL); prog; prog = bpf_object__next_program(obj, prog))
		program_json(&j, prog);
	json_arr_end(&j);

	json_obj_end(&j);
	fputc('\n', stdout);

	bpf_object__close(obj);
	return 0;
}
