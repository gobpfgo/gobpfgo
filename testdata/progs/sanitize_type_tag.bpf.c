// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* clang emits a BTF_KIND_TYPE_TAG named user between the pointer and the
 * int it points to. A kernel without type tags rejects that BTF, so the
 * loader passes it a copy in which the tag is an unnamed CONST.
 */
#define __tag_user __attribute__((btf_type_tag("user")))

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} tagged_ptrs SEC(".maps");

int __tag_user *tagged_uptr;

SEC("kprobe/do_sys_openat2")
int handle_type_tag(void *ctx) {
	__u32 key    = 0;
	__u64 *value = bpf_map_lookup_elem(&tagged_ptrs, &key);

	if (value)
		*value = (__u64)tagged_uptr;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
