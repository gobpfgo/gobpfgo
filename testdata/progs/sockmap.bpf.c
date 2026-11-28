// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

SEC("sk_msg")
int msg_pass(struct sk_msg_md *msg) {
	return SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";
