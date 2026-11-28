// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

// Every program lets the packet through, so attaching them to a cgroup does
// not change its traffic. cgroup/skb has no attach type of its own and loads
// as an ingress program, which gives the tests a second ingress program.

SEC("cgroup_skb/ingress")
int cgroup_ingress(struct __sk_buff *skb) {
	return 1;
}

SEC("cgroup_skb/egress")
int cgroup_egress(struct __sk_buff *skb) {
	return 1;
}

SEC("cgroup/skb")
int cgroup_skb(struct __sk_buff *skb) {
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
