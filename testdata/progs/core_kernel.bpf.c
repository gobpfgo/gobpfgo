// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

struct pt_regs {
	unsigned long sp;
};

SEC("kprobe/do_sys_openat2")
int handle_regs(void *ctx) {
	struct pt_regs *regs = ctx;

	return __builtin_preserve_access_index(regs->sp) != 0;
}

char LICENSE[] SEC("license") = "GPL";
