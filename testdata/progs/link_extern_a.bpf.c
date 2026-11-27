// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* Both externs are defined in link_extern_b.bpf.c. The section attribute puts
 * the variable and the function in the .extern BTF DATASEC, and the static
 * linker resolves both to the definitions there.
 */
extern __u64 ext_counter SEC(".extern");
extern __u64 ext_add(__u64 value, __u64 delta) SEC(".extern");

/* .bss: what the program got back from ext_add, for the test to check. */
__u64 ext_seen;

SEC("kprobe/do_sys_openat2")
int handle_extern(void *ctx) {
	__sync_fetch_and_add(&ext_counter, 1);
	ext_seen = ext_add(0x1200, 0x34);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
