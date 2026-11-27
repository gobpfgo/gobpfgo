// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

// .percpu: every CPU starts with these values. The 32-bit variable comes last,
// so the section is 12 bytes and each CPU's value is padded to 16.
__u64 percpu_counter SEC(".percpu") = 100;
__u32 percpu_last SEC(".percpu")    = 0x5eed;

// .percpu.custom: a second per-CPU section, named by its whole section name.
__u32 percpu_custom SEC(".percpu.custom") = 0xc0ffee;

// .bss: the thread whose opens the program counts, written by the test after
// load. Zero counts none, so other threads never touch the per-CPU values.
__u32 target_tid;

SEC("kprobe/do_sys_openat2")
int handle_percpu(void *ctx) {
	__u32 tid = (__u32)bpf_get_current_pid_tgid();

	if (target_tid == 0 || tid != target_tid)
		return 0;

	percpu_counter = percpu_counter + 1;
	percpu_last    = tid;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
