// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>

enum core_enum {
	CORE_FIRST  = 1,
	CORE_SECOND = 2,
};

struct core_sample {
	int first;
	int second;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct core_sample);
} values SEC(".maps");

SEC("kprobe/do_sys_openat2")
int handle_core(void *ctx) {
	__u32 key                  = 0;
	struct core_sample *sample = bpf_map_lookup_elem(&values, &key);

	if (!sample)
		return 0;
	if (!bpf_core_type_exists(struct core_sample))
		return 0;
	if (bpf_core_type_size(struct core_sample) != sizeof(struct core_sample))
		return 0;
	if (bpf_core_type_id_local(struct core_sample) == 0)
		return 0;
	if (bpf_core_type_id_kernel(struct core_sample) == 0)
		return 0;
	return __builtin_preserve_access_index(sample->second) + bpf_core_enum_value(enum core_enum, CORE_SECOND);
}

char LICENSE[] SEC("license") = "GPL";
