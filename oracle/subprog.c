// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include "btf.h"
#include "libbpf.h"

#include <linux/bpf.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SUBPROG_LINKED_NAME "linked.bpf.o"

/* func_info_json prints the function records libbpf prepared for the program:
 * the instruction index and the BTF type ID of each.
 */
static void func_info_json(struct json *j, const struct bpf_program *prog) {
	const struct bpf_func_info *info = bpf_program__func_info(prog);
	__u32 cnt                        = bpf_program__func_info_cnt(prog);
	__u32 i;

	json_arr_begin(j, "func_info");
	for (i = 0; info && i < cnt; i++) {
		json_obj_begin_compact(j, NULL);
		json_u32(j, "insn_off", info[i].insn_off);
		json_u32(j, "type_id", info[i].type_id);
		json_obj_end(j);
	}
	json_arr_end(j);
}

/* line_info_json prints the line records libbpf prepared for the program. */
static void line_info_json(struct json *j, const struct bpf_program *prog) {
	const struct bpf_line_info *info = bpf_program__line_info(prog);
	__u32 cnt                        = bpf_program__line_info_cnt(prog);
	__u32 i;

	json_arr_begin(j, "line_info");
	for (i = 0; info && i < cnt; i++) {
		json_obj_begin_compact(j, NULL);
		json_u32(j, "insn_off", info[i].insn_off);
		json_u32(j, "file_name_off", info[i].file_name_off);
		json_u32(j, "line_off", info[i].line_off);
		json_u32(j, "line_col", info[i].line_col);
		json_obj_end(j);
	}
	json_arr_end(j);
}

/* program_json prints a main program's final instructions, with the
 * subprograms it calls appended, and its function and line records.
 */
static void program_json(struct json *j, const struct bpf_program *prog) {
	size_t cnt = bpf_program__insn_cnt(prog);

	json_obj_begin(j, NULL);
	json_str(j, "name", bpf_program__name(prog));
	json_str(j, "section", bpf_program__section_name(prog));
	json_u64(j, "insn_cnt", cnt);
	json_hex(j, "insns", (const uint8_t *)bpf_program__insns(prog), cnt * sizeof(struct bpf_insn));
	func_info_json(j, prog);
	line_info_json(j, prog);
	json_obj_end(j);
}

/* btf_json prints the object BTF after the load, as hex. The generated loader
 * assumes the latest kernel, so the load marks hidden subprograms static but
 * never rewrites arg:ctx arguments.
 */
static void btf_json(struct json *j, const struct bpf_object *obj) {
	struct btf *btf = bpf_object__btf(obj);
	const void *raw;
	__u32 size;

	if (!btf)
		return;

	raw = btf__raw_data(btf, &size);
	if (raw)
		json_hex(j, "btf", raw, size);
}

/* subprog_report loads the object through a generated loader, which runs
 * libbpf's relocation without creating anything in the kernel, and prints the
 * load errno, the BTF after the load, the map names in map index order and
 * every main program.
 */
static int subprog_report(struct json *j, const char *path) {
	LIBBPF_OPTS(gen_loader_opts, gen);
	struct bpf_program *prog;
	struct bpf_map *map;
	struct bpf_object *obj;
	int err;

	obj = bpf_object__open_file(path, NULL);
	if (!obj) {
		fprintf(stderr, "open %s failed\n", path);
		return 1;
	}

	err = bpf_object__gen_loader(obj, &gen);
	if (!err)
		err = bpf_object__load(obj);
	json_s32(j, "errno", err);
	btf_json(j, obj);

	json_arr_begin(j, "maps");
	for (map = bpf_object__next_map(obj, NULL); map; map = bpf_object__next_map(obj, map))
		json_str(j, NULL, bpf_map__name(map));
	json_arr_end(j);

	json_arr_begin(j, "programs");
	for (prog = bpf_object__next_program(obj, NULL); prog; prog = bpf_object__next_program(obj, prog))
		program_json(j, prog);
	json_arr_end(j);

	bpf_object__close(obj);
	return 0;
}

/* oracle_subprog reports one object, or the object libbpf's linker builds
 * from several, linked in order into a temporary file.
 */
int oracle_subprog(const char *const *paths, int count) {
	struct oracle_meta meta = {.case_name = "subprog", .commit = true};
	char dir[]              = "/tmp/gobpfgo-subprog-XXXXXX";
	char linked[PATH_MAX]   = "";
	const char *path        = paths[0];
	libbpf_print_fn_t old_print;
	struct json j;
	int ret = 1;
	int i;

	if (count > 1) {
		if (!mkdtemp(dir)) {
			perror("mkdtemp");
			return 1;
		}

		snprintf(linked, sizeof(linked), "%s/%s", dir, SUBPROG_LINKED_NAME);
		if (oracle_link_objects(paths, count, linked) != 0)
			goto out;
		path = linked;
	}

	old_print = libbpf_set_print(NULL);

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);
	json_arr_begin(&j, "objects");
	for (i = 0; i < count; i++)
		json_str(&j, NULL, oracle_basename(paths[i]));
	json_arr_end(&j);
	ret = subprog_report(&j, path);
	json_obj_end(&j);
	fputc('\n', stdout);

	libbpf_set_print(old_print);

out:
	if (count > 1) {
		unlink(linked);
		rmdir(dir);
	}
	return ret;
}
