// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>

struct module_sample {
	int value;
};

SEC("kprobe/do_sys_openat2")
int handle_module(void *ctx) {
	return bpf_core_type_exists(struct module_sample);
}

char LICENSE[] SEC("license") = "GPL";
