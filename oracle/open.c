// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include "btf.h"
#include "libbpf.h"

#include <linux/bpf.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void map_json(struct json *j, const struct bpf_map *map) {
	json_obj_begin_compact(j, NULL);
	json_str(j, "name", bpf_map__name(map));
	json_u32(j, "type", (uint32_t)bpf_map__type(map));
	json_u32(j, "key_size", bpf_map__key_size(map));
	json_u32(j, "value_size", bpf_map__value_size(map));
	json_u32(j, "max_entries", bpf_map__max_entries(map));
	json_u32(j, "map_flags", bpf_map__map_flags(map));
	json_u32(j, "btf_key_type_id", bpf_map__btf_key_type_id(map));
	json_u32(j, "btf_value_type_id", bpf_map__btf_value_type_id(map));
	json_str(j, "pin_path", bpf_map__pin_path(map));
	json_obj_end(j);
}

static void program_json(struct json *j, const struct bpf_program *prog) {
	json_obj_begin_compact(j, NULL);
	json_str(j, "name", bpf_program__name(prog));
	json_u32(j, "type", (uint32_t)bpf_program__type(prog));
	json_u32(j, "expected_attach_type", (uint32_t)bpf_program__expected_attach_type(prog));
	json_str(j, "section", bpf_program__section_name(prog));
	json_u64(j, "insn_cnt", bpf_program__insn_cnt(prog));
	json_obj_end(j);
}

/*
 * kconfig_json prints the .kconfig DATASEC after open: its size and, in BTF
 * order, each variable's name, offset, size and linkage. Objects without
 * .kconfig externs print nothing.
 */
static void kconfig_json(struct json *j, const struct bpf_object *obj) {
	const struct btf_var_secinfo *vsi;
	const struct btf_type *sec, *var;
	struct btf *btf = bpf_object__btf(obj);
	__u32 i;
	int id;

	if (!btf)
		return;

	id = btf__find_by_name_kind(btf, ".kconfig", BTF_KIND_DATASEC);
	if (id < 0)
		return;

	sec = btf__type_by_id(btf, id);
	json_obj_begin(j, "kconfig");
	json_u32(j, "size", sec->size);
	json_arr_begin(j, "vars");
	for (i = 0, vsi = btf_var_secinfos(sec); i < btf_vlen(sec); i++, vsi++) {
		var = btf__type_by_id(btf, vsi->type);
		json_obj_begin_compact(j, NULL);
		json_str(j, "name", btf__name_by_offset(btf, var->name_off));
		json_u32(j, "offset", vsi->offset);
		json_u32(j, "size", vsi->size);
		json_u32(j, "linkage", btf_var(var)->linkage);
		json_obj_end(j);
	}
	json_arr_end(j);
	json_obj_end(j);
}

/*
 * ksyms_btf_json prints the object BTF after open, as hex, for an object with
 * a .ksyms DATASEC. Open turns that DATASEC into integer slots, gives the
 * functions global linkage and adds a dummy_ksym variable for them, so the
 * bytes show the whole rewrite. Other objects print nothing.
 */
static void ksyms_btf_json(struct json *j, const struct bpf_object *obj) {
	struct btf *btf = bpf_object__btf(obj);
	const void *raw;
	__u32 size;

	if (!btf || btf__find_by_name_kind(btf, ".ksyms", BTF_KIND_DATASEC) < 0)
		return;

	raw = btf__raw_data(btf, &size);
	if (raw)
		json_hex(j, "ksyms_btf", raw, size);
}

int oracle_open(const char *path) {
	struct oracle_meta meta = {.case_name = "open", .version = true};
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_map *map;
	struct json j;
	long err;

	obj = bpf_object__open_file(path, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "open %s: %s\n", path, strerror((int)-err));
		return 1;
	}

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);

	json_str(&j, "object", oracle_basename(path));
	json_str(&j, "object_name", bpf_object__name(obj));

	json_arr_begin(&j, "maps");
	for (map = bpf_object__next_map(obj, NULL); map; map = bpf_object__next_map(obj, map))
		map_json(&j, map);
	json_arr_end(&j);

	json_arr_begin(&j, "programs");
	for (prog = bpf_object__next_program(obj, NULL); prog; prog = bpf_object__next_program(obj, prog))
		program_json(&j, prog);
	json_arr_end(&j);

	kconfig_json(&j, obj);
	ksyms_btf_json(&j, obj);

	json_obj_end(&j);
	fputc('\n', stdout);

	bpf_object__close(obj);
	return 0;
}
