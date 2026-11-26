// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} counts SEC(".maps");

SEC("kprobe/do_sys_openat2")
int handle_open(void *ctx) {
	__u32 key    = 0;
	__u64 *value = bpf_map_lookup_elem(&counts, &key);

	if (value)
		__sync_fetch_and_add(value, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
