// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* .data: starts above zero, so the extern increment in link_extern_a.bpf.c
 * is visible on top of the initial value.
 */
__u64 ext_counter = 100;

/* A global function in .text: the kernel verifies it on its own, and its
 * scalar arguments and return value keep it valid on 5.10.
 */
__noinline __u64 ext_add(__u64 value, __u64 delta) {
	return value + delta;
}

char LICENSE[] SEC("license") = "GPL";
