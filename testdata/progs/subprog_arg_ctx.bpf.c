// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* A global subprogram whose second argument is the program context, tagged
 * __arg_ctx. The verifier checks a global function on its own, so it reads
 * the context only if it knows the argument is one: a kernel with native
 * __arg_ctx support reads the tag, and on older kernels the loader rewrites
 * the argument type to the kprobe context struct.
 */
__noinline int subprog_arg_ctx(__u64 delta, void *ctx __arg_ctx) {
	return *(__u64 *)ctx + delta != 0;
}

SEC("kprobe/do_sys_openat2")
int handle_arg_ctx(void *ctx) {
	return subprog_arg_ctx(1, ctx);
}

/* A second program that calls the same subprogram. Each main program gets
 * its own rewritten copy of the subprogram's BTF.
 */
SEC("kprobe/do_sys_openat2")
int handle_arg_ctx_shared(void *ctx) {
	return subprog_arg_ctx(2, ctx);
}

char LICENSE[] SEC("license") = "GPL";
