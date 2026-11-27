// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* Weak externs in the .extern BTF DATASEC. link_extern_b.bpf.c defines
 * ext_counter, which turns the weak extern into its strong definition;
 * nothing defines ext_missing or ext_missing_add, so they stay undefined weak
 * symbols in the linked object.
 */
extern __u64 ext_counter SEC(".extern") __weak;
extern __u64 ext_missing SEC(".extern") __weak;
extern __u64 ext_missing_add(__u64 value, __u64 delta) SEC(".extern") __weak;

/* .bss: what the program read, for the test to check. */
__u64 weak_seen;

SEC("kprobe/do_sys_openat2")
int handle_weak(void *ctx) {
	__sync_fetch_and_add(&ext_counter, 1);
	weak_seen = ext_missing_add(ext_missing, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
