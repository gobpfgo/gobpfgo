// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* A float and a double make clang emit a BTF_KIND_FLOAT of 4 bytes and one
 * of 8. A kernel without FLOAT rejects them, so the loader passes it a copy
 * in which each is an anonymous empty STRUCT of the same size.
 */
struct sanitize_sample {
	float ratio;
	double scale;
};

// .data: the initial values give both fields nonzero bits.
struct sanitize_sample float_sample = {
	.ratio = 1.5f,
	.scale = 2.5,
};

// .bss: the raw bits the program copies out of the fields. BPF has no
// floating point instructions, so the program never does float arithmetic.
__u32 ratio_bits;
__u64 scale_bits;

SEC("kprobe/do_sys_openat2")
int handle_float(void *ctx) {
	__builtin_memcpy(&ratio_bits, &float_sample.ratio, sizeof(ratio_bits));
	__builtin_memcpy(&scale_bits, &float_sample.scale, sizeof(scale_bits));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
