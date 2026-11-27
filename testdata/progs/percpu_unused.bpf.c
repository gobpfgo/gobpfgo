// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

// .percpu: per-CPU values that no program reads or writes, so the object
// loads even when the kernel has no global per-CPU data to create them.
__u64 unused_counter SEC(".percpu") = 7;
__u32 unused_last SEC(".percpu")    = 0xfeed;

// .bss: the only variable the program uses.
__u64 opens;

SEC("kprobe/do_sys_openat2")
int handle_percpu_unused(void *ctx) {
	opens = opens + 1;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
