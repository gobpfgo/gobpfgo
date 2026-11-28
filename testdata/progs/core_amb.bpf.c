// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>

// A local type with a field that both of its candidates in
// core_cands_target.c have, at different offsets, so neither relocation can
// pick one. core_amb_single.c has one candidate. The program is relocated
// against those target BTFs and never loaded.
struct cc_amb {
	int y;
};

__u64 results[2];

SEC("kprobe/do_sys_openat2")
int handle_amb(void *ctx) {
	struct cc_amb *amb = ctx;

	results[0] = bpf_core_field_exists(amb->y);
	results[1] = bpf_core_field_offset(amb->y);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
