// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

#define __exception_cb(name) __attribute__((btf_decl_tag("exception_callback:" #name)))

/* An exception callback that its program also calls directly. The direct
 * call appends it first, so the tag must not append it again. The verifier
 * rejects a direct call to the exception callback, so the object is opened
 * and relocated, never loaded.
 */
__noinline int on_throw_direct(__u64 cookie) {
	return cookie != 0;
}

SEC("fentry/do_sys_openat2")
__exception_cb(on_throw_direct) int handle_direct(void *ctx) {
	return on_throw_direct(0);
}

char LICENSE[] SEC("license") = "GPL";
