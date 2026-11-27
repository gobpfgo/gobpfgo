// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* Typeless .ksyms externs, which the loader resolves through /proc/kallsyms
 * and patches in as 64-bit constants. bpf_prog_active is a per-CPU
 * variable, so its value is the per-CPU offset kallsyms lists.
 */
extern const void bpf_prog_active __ksym;
extern const void init_task __ksym;

/* .bss: the addresses the program saw, in declaration order. */
__u64 ksym_addrs[2];

SEC("kprobe/do_sys_openat2")
int handle_ksyms_addr(void *ctx) {
	ksym_addrs[0] = (__u64)&bpf_prog_active;
	ksym_addrs[1] = (__u64)&init_task;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
