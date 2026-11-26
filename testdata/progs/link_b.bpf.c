// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* Strong: replaces the weak definition in link_a.bpf.c. handle_b uses it
 * first, so clang places it first in .maps and the linked .maps keeps its
 * variables in offset order.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} shared_counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} counts_b SEC(".maps");

static __always_inline void count(void *map) {
	__u32 key    = 0;
	__u64 *value = bpf_map_lookup_elem(map, &key);

	if (value)
		__sync_fetch_and_add(value, 1);
}

SEC("kprobe/do_sys_open")
int handle_b(void *ctx) {
	count(&shared_counts);
	count(&counts_b);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
