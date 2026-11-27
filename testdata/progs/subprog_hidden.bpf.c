// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* A global subprogram with hidden visibility. The loader marks its BTF FUNC
 * static, so the verifier checks it in its caller's context and knows the
 * argument points at the caller's stack. Checked as a global function, the
 * pointer could be NULL and the load would fail.
 */
__hidden __noinline int subprog_hidden(__u64 *value) {
	return *value + 1;
}

/* A global subprogram with default visibility. Its BTF FUNC stays global. */
__noinline int subprog_visible(__u32 value) {
	return value * 2;
}

/* A main program with hidden visibility. It is not a subprogram, so its BTF
 * FUNC stays global.
 */
__hidden SEC("kprobe/do_sys_openat2") int handle_hidden(void *ctx) {
	__u64 value = 1;

	return subprog_hidden(&value) + subprog_visible(2);
}

char LICENSE[] SEC("license") = "GPL";
