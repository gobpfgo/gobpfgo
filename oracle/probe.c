// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include "libbpf.h"

#include <linux/bpf.h>

#include <stdio.h>

struct prog_case {
	const char *name;
	enum bpf_prog_type type;
};

struct map_case {
	const char *name;
	enum bpf_map_type type;
};

struct helper_case {
	const char *prog_name;
	enum bpf_prog_type prog_type;
	const char *helper_name;
	enum bpf_func_id helper_id;
};

static const struct prog_case prog_cases[] = {
	{"unspec", BPF_PROG_TYPE_UNSPEC},
	{"socket_filter", BPF_PROG_TYPE_SOCKET_FILTER},
	{"kprobe", BPF_PROG_TYPE_KPROBE},
	{"tracepoint", BPF_PROG_TYPE_TRACEPOINT},
	{"xdp", BPF_PROG_TYPE_XDP},
	{"perf_event", BPF_PROG_TYPE_PERF_EVENT},
	{"raw_tracepoint", BPF_PROG_TYPE_RAW_TRACEPOINT},
	{"cgroup_sock_addr", BPF_PROG_TYPE_CGROUP_SOCK_ADDR},
	{"tracing", BPF_PROG_TYPE_TRACING},
	{"struct_ops", BPF_PROG_TYPE_STRUCT_OPS},
	{"ext", BPF_PROG_TYPE_EXT},
	{"lsm", BPF_PROG_TYPE_LSM},
	{"syscall", BPF_PROG_TYPE_SYSCALL},
	{"netfilter", BPF_PROG_TYPE_NETFILTER},
};

static const struct map_case map_cases[] = {
	{"unspec", BPF_MAP_TYPE_UNSPEC},
	{"hash", BPF_MAP_TYPE_HASH},
	{"array", BPF_MAP_TYPE_ARRAY},
	{"prog_array", BPF_MAP_TYPE_PROG_ARRAY},
	{"perf_event_array", BPF_MAP_TYPE_PERF_EVENT_ARRAY},
	{"stack_trace", BPF_MAP_TYPE_STACK_TRACE},
	{"lpm_trie", BPF_MAP_TYPE_LPM_TRIE},
	{"array_of_maps", BPF_MAP_TYPE_ARRAY_OF_MAPS},
	{"hash_of_maps", BPF_MAP_TYPE_HASH_OF_MAPS},
	{"cgroup_storage", BPF_MAP_TYPE_CGROUP_STORAGE},
	{"queue", BPF_MAP_TYPE_QUEUE},
	{"sk_storage", BPF_MAP_TYPE_SK_STORAGE},
	{"struct_ops", BPF_MAP_TYPE_STRUCT_OPS},
	{"ringbuf", BPF_MAP_TYPE_RINGBUF},
	{"inode_storage", BPF_MAP_TYPE_INODE_STORAGE},
	{"task_storage", BPF_MAP_TYPE_TASK_STORAGE},
	{"bloom_filter", BPF_MAP_TYPE_BLOOM_FILTER},
	{"user_ringbuf", BPF_MAP_TYPE_USER_RINGBUF},
	{"cgrp_storage", BPF_MAP_TYPE_CGRP_STORAGE},
	{"arena", BPF_MAP_TYPE_ARENA},
	{"insn_array", BPF_MAP_TYPE_INSN_ARRAY},
	{"rhash", BPF_MAP_TYPE_RHASH},
};

static const struct helper_case helper_cases[] = {
	{"socket_filter", BPF_PROG_TYPE_SOCKET_FILTER, "map_lookup_elem", BPF_FUNC_map_lookup_elem},
	{"socket_filter", BPF_PROG_TYPE_SOCKET_FILTER, "ktime_get_ns", BPF_FUNC_ktime_get_ns},
	{"socket_filter", BPF_PROG_TYPE_SOCKET_FILTER, "perf_event_output", BPF_FUNC_perf_event_output},
	{"kprobe", BPF_PROG_TYPE_KPROBE, "probe_read", BPF_FUNC_probe_read},
	{"kprobe", BPF_PROG_TYPE_KPROBE, "get_current_pid_tgid", BPF_FUNC_get_current_pid_tgid},
	{"kprobe", BPF_PROG_TYPE_KPROBE, "get_attach_cookie", BPF_FUNC_get_attach_cookie},
	{"xdp", BPF_PROG_TYPE_XDP, "redirect", BPF_FUNC_redirect},
	{"tracepoint", BPF_PROG_TYPE_TRACEPOINT, "trace_printk", BPF_FUNC_trace_printk},
};

int oracle_probe(void) {
	struct oracle_meta meta = {.case_name = "probe", .version = true};
	struct json j;
	size_t i;

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);
	json_s32(&j, "possible_cpus", libbpf_num_possible_cpus());

	json_arr_begin(&j, "prog_types");
	for (i = 0; i < ORACLE_ARRAY_SIZE(prog_cases); i++) {
		json_obj_begin_compact(&j, NULL);
		json_str(&j, "name", prog_cases[i].name);
		json_u32(&j, "id", (__u32)prog_cases[i].type);
		json_s32(&j, "result", libbpf_probe_bpf_prog_type(prog_cases[i].type, NULL));
		json_obj_end(&j);
	}
	json_arr_end(&j);

	json_arr_begin(&j, "map_types");
	for (i = 0; i < ORACLE_ARRAY_SIZE(map_cases); i++) {
		json_obj_begin_compact(&j, NULL);
		json_str(&j, "name", map_cases[i].name);
		json_u32(&j, "id", (__u32)map_cases[i].type);
		json_s32(&j, "result", libbpf_probe_bpf_map_type(map_cases[i].type, NULL));
		json_obj_end(&j);
	}
	json_arr_end(&j);

	json_arr_begin(&j, "helpers");
	for (i = 0; i < ORACLE_ARRAY_SIZE(helper_cases); i++) {
		json_obj_begin_compact(&j, NULL);
		json_str(&j, "prog_type", helper_cases[i].prog_name);
		json_u32(&j, "prog_type_id", (__u32)helper_cases[i].prog_type);
		json_str(&j, "helper", helper_cases[i].helper_name);
		json_u32(&j, "helper_id", (__u32)helper_cases[i].helper_id);
		json_s32(&j, "result", libbpf_probe_bpf_helper(helper_cases[i].prog_type, helper_cases[i].helper_id, NULL));
		json_obj_end(&j);
	}
	json_arr_end(&j);

	json_obj_end(&j);
	fputc('\n', stdout);
	return 0;
}
