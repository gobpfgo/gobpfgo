// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} counts_a SEC(".maps");

/* Weak: link_b.bpf.c holds the strong definition that wins the link. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} shared_counts SEC(".maps") __weak;

static __always_inline void count(void *map) {
	__u32 key    = 0;
	__u64 *value = bpf_map_lookup_elem(map, &key);

	if (value)
		__sync_fetch_and_add(value, 1);
}

SEC("kprobe/do_sys_openat2")
int handle_a(void *ctx) {
	count(&counts_a);
	count(&shared_counts);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
