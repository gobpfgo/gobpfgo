// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>

struct missing_sample {
	int value;
};

SEC("kprobe/do_sys_openat2")
int handle_missing(void *ctx) {
	if (!bpf_core_type_exists(struct missing_sample))
		return 0;
	return bpf_core_type_size(struct missing_sample) + __builtin_preserve_access_index(((struct missing_sample *)ctx)->value);
}

char LICENSE[] SEC("license") = "GPL";
