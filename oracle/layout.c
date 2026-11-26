// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include <linux/bpf.h>
#include <linux/perf_event.h>

#include <stddef.h>
#include <stdint.h>

#define F(name) {#name, offsetof(union bpf_attr, name), sizeof(((union bpf_attr *)0)->name)}
#define FC(name) {#name, offsetof(union bpf_attr, link_create.name), sizeof(((union bpf_attr *)0)->link_create.name)}
#define FU(name) {#name, offsetof(union bpf_attr, link_update.name), sizeof(((union bpf_attr *)0)->link_update.name)}
#define FR(name) {#name, offsetof(union bpf_attr, raw_tracepoint.name), sizeof(((union bpf_attr *)0)->raw_tracepoint.name)}
#define FMAP(name) {#name, offsetof(struct bpf_map_info, name), sizeof(((struct bpf_map_info *)0)->name)}
#define FPROG(name) {#name, offsetof(struct bpf_prog_info, name), sizeof(((struct bpf_prog_info *)0)->name)}
#define FPAGE(name) {#name, offsetof(struct perf_event_mmap_page, name), sizeof(((struct perf_event_mmap_page *)0)->name)}
#define FHDR(name) {#name, offsetof(struct perf_event_header, name), sizeof(((struct perf_event_header *)0)->name)}

struct perf_sample_raw_layout {
	struct perf_event_header header;
	__u32 size;
};

struct perf_sample_lost_layout {
	struct perf_event_header header;
	__u64 id;
	__u64 lost;
	__u64 sample_id;
};

#define FSAMPLE(name) {#name, offsetof(struct perf_sample_raw_layout, name), sizeof(((struct perf_sample_raw_layout *)0)->name)}
#define FLOST(name) {#name, offsetof(struct perf_sample_lost_layout, name), sizeof(((struct perf_sample_lost_layout *)0)->name)}

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
		F(kern_version),
		F(prog_flags),
		F(prog_name),
		F(prog_ifindex),
		F(expected_attach_type),
		F(prog_btf_fd),
		F(func_info_rec_size),
		F(func_info),
		F(func_info_cnt),
		F(line_info_rec_size),
		F(line_info),
		F(line_info_cnt),
		F(attach_btf_id),
		F(attach_btf_obj_fd),
	};
	static const struct oracle_field link_create_fields[] = {
		FC(prog_fd),
		FC(target_fd),
		FC(attach_type),
		FC(flags),
		FC(target_btf_id),
		FC(perf_event.bpf_cookie),
		FC(kprobe_multi.flags),
		FC(kprobe_multi.cnt),
		FC(kprobe_multi.syms),
		FC(kprobe_multi.addrs),
		FC(kprobe_multi.cookies),
		FC(tracing.target_btf_id),
		FC(tracing.cookie),
		FC(uprobe_multi.path),
		FC(uprobe_multi.offsets),
		FC(uprobe_multi.ref_ctr_offsets),
		FC(uprobe_multi.cookies),
		FC(uprobe_multi.cnt),
		FC(uprobe_multi.flags),
		FC(uprobe_multi.pid),
	};
	static const struct oracle_field link_update_fields[] = {
		FU(link_fd),
		FU(new_prog_fd),
		FU(flags),
		FU(old_prog_fd),
	};
	static const struct oracle_field raw_tracepoint_fields[] = {
		FR(name),
		FR(prog_fd),
		FR(cookie),
	};
	static const struct oracle_field map_elem_fields[] = {
		F(map_fd),
		F(key),
		F(value),
		F(flags),
	};
	static const struct oracle_field obj_pin_fields[] = {
		F(pathname),
		F(bpf_fd),
		F(file_flags),
		F(path_fd),
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
		FPROG(nr_jited_ksyms),
		FPROG(nr_jited_func_lens),
		FPROG(jited_ksyms),
		FPROG(jited_func_lens),
		FPROG(nr_line_info),
		FPROG(line_info),
		FPROG(jited_line_info),
		FPROG(nr_jited_line_info),
		FPROG(line_info_rec_size),
		FPROG(jited_line_info_rec_size),
	};
	static const struct oracle_field perf_event_fields[] = {
		FPAGE(data_head),
		FPAGE(data_tail),
	};
	static const struct oracle_field perf_event_header_fields[] = {
		FHDR(type),
		FHDR(misc),
		FHDR(size),
	};
	static const struct oracle_field perf_sample_fields[] = {
		FSAMPLE(size),
	};
	static const struct oracle_field perf_lost_fields[] = {
		FLOST(id),
		FLOST(lost),
		FLOST(sample_id),
	};
	struct oracle_meta meta = {.commit = true};
	struct json j;

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);

	oracle_field_block(&j, "map_create", map_create_fields, ORACLE_ARRAY_SIZE(map_create_fields), ORACLE_OFFSETOFEND(union bpf_attr, excl_prog_hash_size));
	oracle_field_block(&j, "btf_load", btf_load_fields, ORACLE_ARRAY_SIZE(btf_load_fields), ORACLE_OFFSETOFEND(union bpf_attr, btf_token_fd));
	oracle_field_block(&j, "prog_load", prog_load_fields, ORACLE_ARRAY_SIZE(prog_load_fields), ORACLE_OFFSETOFEND(union bpf_attr, keyring_id));
	oracle_field_block(&j, "link_create", link_create_fields, ORACLE_ARRAY_SIZE(link_create_fields), ORACLE_OFFSETOFEND(union bpf_attr, link_create));
	oracle_field_block(&j, "link_update", link_update_fields, ORACLE_ARRAY_SIZE(link_update_fields), ORACLE_OFFSETOFEND(union bpf_attr, link_update));
	oracle_field_block(&j, "raw_tracepoint", raw_tracepoint_fields, ORACLE_ARRAY_SIZE(raw_tracepoint_fields), ORACLE_OFFSETOFEND(union bpf_attr, raw_tracepoint));
	oracle_field_block(&j, "map_elem", map_elem_fields, ORACLE_ARRAY_SIZE(map_elem_fields), ORACLE_OFFSETOFEND(union bpf_attr, flags));
	oracle_field_block(&j, "obj_pin", obj_pin_fields, ORACLE_ARRAY_SIZE(obj_pin_fields), ORACLE_OFFSETOFEND(union bpf_attr, path_fd));
	oracle_field_block(&j, "obj_info", obj_info_fields, ORACLE_ARRAY_SIZE(obj_info_fields), ORACLE_OFFSETOFEND(union bpf_attr, info));
	oracle_field_block(&j, "map_info", map_info_fields, ORACLE_ARRAY_SIZE(map_info_fields), sizeof(struct bpf_map_info));
	oracle_field_block(&j, "prog_info", prog_info_fields, ORACLE_ARRAY_SIZE(prog_info_fields), sizeof(struct bpf_prog_info));
	oracle_field_block(&j, "perf_event", perf_event_fields, ORACLE_ARRAY_SIZE(perf_event_fields), ORACLE_OFFSETOFEND(struct perf_event_mmap_page, data_tail));
	oracle_field_block(&j, "perf_event_header", perf_event_header_fields, ORACLE_ARRAY_SIZE(perf_event_header_fields), sizeof(struct perf_event_header));
	oracle_field_block(&j, "perf_sample", perf_sample_fields, ORACLE_ARRAY_SIZE(perf_sample_fields), sizeof(struct perf_sample_raw_layout));
	oracle_field_block(&j, "perf_lost", perf_lost_fields, ORACLE_ARRAY_SIZE(perf_lost_fields), sizeof(struct perf_sample_lost_layout));

	json_obj_end(&j);
	fputc('\n', stdout);
	return 0;
}
