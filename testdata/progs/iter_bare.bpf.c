// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

struct bpf_iter_meta;
struct bpf_map;

// The context of the bpf_map iterator, as in iter.bpf.c.
struct bpf_iter__bpf_map {
	struct bpf_iter_meta *meta;
	struct bpf_map *map;
} __attribute__((preserve_access_index));

// An iterator whose section names no target. The loader takes the iterator
// from BpfProgramSetAttachTarget; the tests name bpf_map.
SEC("iter")
int dump_bare(struct bpf_iter__bpf_map *ctx) {
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
