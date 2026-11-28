// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

struct bpf_iter_meta;
struct bpf_map;

// The context of the bpf_map iterator. The kernel wraps both members in an
// anonymous union, so CO-RE relocates the member offsets against vmlinux.
struct bpf_iter__bpf_map {
	struct bpf_iter_meta *meta;
	struct bpf_map *map;
} __attribute__((preserve_access_index));

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} maps_seen SEC(".maps");

SEC("iter/bpf_map")
int dump_bpf_map(struct bpf_iter__bpf_map *ctx) {
	__u32 key = 0;
	__u64 *value;

	if (!ctx->map)
		return 0;

	value = bpf_map_lookup_elem(&maps_seen, &key);
	if (value)
		__sync_fetch_and_add(value, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
