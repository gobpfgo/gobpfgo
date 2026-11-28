// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>

// Local types with two candidates each in core_cands_target.c. The first
// relocation of each type keeps only the candidate it matched, which decides
// the second one. The program is relocated against that target BTF and never
// loaded.

// Only cc_nar has a; both candidates have b, at different offsets. With
// cc_nar alone, the offset of b is not ambiguous.
struct cc_nar {
	int a;
	int b;
};

// Only cc_pick has a and only cc_pick___v2 has b. With cc_pick alone, b does
// not exist.
struct cc_pick {
	int a;
	int b;
};

__u64 results[2];

SEC("kprobe/do_sys_openat2")
int handle_cands(void *ctx) {
	struct cc_nar *nar   = ctx;
	struct cc_pick *pick = ctx;

	if (bpf_core_field_exists(nar->a))
		results[0] = bpf_core_field_offset(nar->b);
	if (bpf_core_field_exists(pick->a))
		results[1] = bpf_core_field_exists(pick->b);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
