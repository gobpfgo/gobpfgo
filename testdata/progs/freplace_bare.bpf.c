// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

// A freplace program whose section names no function. The loader takes the
// target program and function from BpfProgramSetAttachTarget; the tests
// point it at xdp_pass of xdp.bpf.o, so the argument is struct xdp_md *.
SEC("freplace")
int replace_bare(struct xdp_md *ctx) {
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
