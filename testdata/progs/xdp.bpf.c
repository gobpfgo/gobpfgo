// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
