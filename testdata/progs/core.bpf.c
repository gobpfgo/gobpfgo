// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

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
	return __builtin_preserve_access_index(sample->second);
}

char LICENSE[] SEC("license") = "GPL";
