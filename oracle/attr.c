// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include <linux/bpf.h>

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void copy_name(char *dst, const char *src, size_t size) {
	size_t i;

	if (size == 0)
		return;

	size--;
	for (i = 0; i < size && src[i]; i++)
		dst[i] = src[i];
	dst[i] = '\0';
}

int oracle_attr(void) {
	const char *name        = "gobpfgo-test";
	const size_t attr_size  = ORACLE_OFFSETOFEND(union bpf_attr, excl_prog_hash_size);
	struct oracle_meta meta = {.case_name = "map_create"};
	union bpf_attr attr;
	struct json j;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	copy_name(attr.map_name, name, sizeof(attr.map_name));
	attr.key_size    = 4;
	attr.value_size  = 8;
	attr.max_entries = 16;

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);

	json_obj_begin(&j, "input");
	json_u32(&j, "map_type", attr.map_type);
	json_str(&j, "name", name);
	json_u32(&j, "key_size", attr.key_size);
	json_u32(&j, "value_size", attr.value_size);
	json_u32(&j, "max_entries", attr.max_entries);
	json_u32(&j, "map_flags", attr.map_flags);
	json_u32(&j, "btf_fd", attr.btf_fd);
	json_u32(&j, "btf_key_type_id", attr.btf_key_type_id);
	json_u32(&j, "btf_value_type_id", attr.btf_value_type_id);
	json_u32(&j, "btf_vmlinux_value_type_id", attr.btf_vmlinux_value_type_id);
	json_u32(&j, "inner_map_fd", attr.inner_map_fd);
	json_u64(&j, "map_extra", attr.map_extra);
	json_u32(&j, "numa_node", attr.numa_node);
	json_u32(&j, "map_ifindex", attr.map_ifindex);
	json_s32(&j, "value_type_btf_obj_fd", attr.value_type_btf_obj_fd);
	json_s32(&j, "token_fd", attr.map_token_fd);
	json_u32(&j, "excl_prog_hash_size", attr.excl_prog_hash_size);
	json_obj_end(&j);

	json_u64(&j, "size", attr_size);
	json_hex(&j, "hex", (const uint8_t *)&attr, attr_size);
	json_obj_end(&j);
	fputc('\n', stdout);
	return 0;
}
