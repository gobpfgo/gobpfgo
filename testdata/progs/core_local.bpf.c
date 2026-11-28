// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>

// No kernel has this struct, so every field relocation below finds no
// target. The local access is still computed: field_exists and the signedness
// of val resolve, the latter to a poisoned instruction the type check keeps
// out of reach, while the signedness of an array element cannot be computed
// and fails the load before any program reaches the kernel.
struct gobpfgo_local_missing {
	int val;
	int arr[4];
};

__u64 results[3];

// bpf_core_read.h has no macro for the field signedness relocation.
#define field_signed(field) __builtin_preserve_field_info(field, BPF_FIELD_SIGNED)

SEC("kprobe/do_sys_openat2")
int handle_core_local(void *ctx) {
	struct gobpfgo_local_missing *p = ctx;

	results[0] = bpf_core_field_exists(p->val);
	if (!bpf_core_type_exists(struct gobpfgo_local_missing))
		return 0;
	results[1] = field_signed(p->val);
	results[2] = field_signed(p->arr[1]);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
