// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

// BPF_FLOW_DISSECTOR_CONTINUE hands every packet back to the kernel's own
// dissector on Linux 6.1 and newer, so attaching the program to a network
// namespace does not change how its packets are dissected.
SEC("flow_dissector")
int dissect(struct __sk_buff *skb) {
	return BPF_FLOW_DISSECTOR_CONTINUE;
}

char LICENSE[] SEC("license") = "GPL";
