// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

// Replaces xdp_pass of xdp.bpf.o. The kernel replaces only a function whose
// arguments are scalars or pointers to the program's context type, so the
// argument is struct xdp_md *, not void *.
SEC("freplace/xdp_pass")
int replace_xdp(struct xdp_md *ctx) {
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
