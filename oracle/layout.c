// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include <linux/bpf.h>

#include <stddef.h>
#include <stdint.h>

#define F(name) {#name, offsetof(union bpf_attr, name), sizeof(((union bpf_attr *)0)->name)}
#define FMAP(name) {#name, offsetof(struct bpf_map_info, name), sizeof(((struct bpf_map_info *)0)->name)}
#define FPROG(name) {#name, offsetof(struct bpf_prog_info, name), sizeof(((struct bpf_prog_info *)0)->name)}

int oracle_layout(void) {
	static const struct oracle_field map_create_fields[] = {
		F(map_type),
		F(key_size),
		F(value_size),
		F(max_entries),
		F(map_flags),
		F(inner_map_fd),
		F(numa_node),
		F(map_name),
		F(map_ifindex),
		F(btf_fd),
		F(btf_key_type_id),
		F(btf_value_type_id),
		F(btf_vmlinux_value_type_id),
		F(map_extra),
		F(value_type_btf_obj_fd),
		F(map_token_fd),
		F(excl_prog_hash),
		F(excl_prog_hash_size),
	};
	static const struct oracle_field btf_load_fields[] = {
		F(btf),
		F(btf_log_buf),
		F(btf_size),
		F(btf_log_size),
		F(btf_log_level),
		F(btf_log_true_size),
		F(btf_flags),
		F(btf_token_fd),
	};
	static const struct oracle_field prog_load_fields[] = {
		F(prog_type),
		F(insn_cnt),
		F(insns),
		F(license),
		F(log_level),
		F(log_size),
		F(log_buf),
		F(prog_flags),
		F(prog_name),
		F(expected_attach_type),
		F(prog_btf_fd),
	};
	static const struct oracle_field map_elem_fields[] = {
		F(map_fd),
		F(key),
		F(value),
		F(flags),
	};
	static const struct oracle_field obj_info_fields[] = {
		{"bpf_fd", offsetof(union bpf_attr, info), 4},
		{"info_len", offsetof(union bpf_attr, info) + 4, 4},
		{"info", offsetof(union bpf_attr, info) + 8, 8},
	};
	static const struct oracle_field map_info_fields[] = {
		FMAP(type),
		FMAP(id),
		FMAP(key_size),
		FMAP(value_size),
		FMAP(max_entries),
		FMAP(map_flags),
		FMAP(name),
		FMAP(btf_key_type_id),
		FMAP(btf_value_type_id),
	};
	static const struct oracle_field prog_info_fields[] = {
		FPROG(type),
		FPROG(id),
		FPROG(jited_prog_len),
		FPROG(xlated_prog_len),
		FPROG(name),
	};
	struct oracle_meta meta = {.commit = true};
	struct json j;

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);

	oracle_field_block(&j, "map_create", map_create_fields, ORACLE_ARRAY_SIZE(map_create_fields), ORACLE_OFFSETOFEND(union bpf_attr, excl_prog_hash_size));
	oracle_field_block(&j, "btf_load", btf_load_fields, ORACLE_ARRAY_SIZE(btf_load_fields), ORACLE_OFFSETOFEND(union bpf_attr, btf_token_fd));
	oracle_field_block(&j, "prog_load", prog_load_fields, ORACLE_ARRAY_SIZE(prog_load_fields), ORACLE_OFFSETOFEND(union bpf_attr, keyring_id));
	oracle_field_block(&j, "map_elem", map_elem_fields, ORACLE_ARRAY_SIZE(map_elem_fields), ORACLE_OFFSETOFEND(union bpf_attr, flags));
	oracle_field_block(&j, "obj_info", obj_info_fields, ORACLE_ARRAY_SIZE(obj_info_fields), ORACLE_OFFSETOFEND(union bpf_attr, info));
	oracle_field_block(&j, "map_info", map_info_fields, ORACLE_ARRAY_SIZE(map_info_fields), sizeof(struct bpf_map_info));
	oracle_field_block(&j, "prog_info", prog_info_fields, ORACLE_ARRAY_SIZE(prog_info_fields), sizeof(struct bpf_prog_info));

	json_obj_end(&j);
	fputc('\n', stdout);
	return 0;
}
