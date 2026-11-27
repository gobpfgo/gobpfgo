// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* A value above 32 bits makes clang emit a BTF_KIND_ENUM64 of 8 bytes. A
 * kernel without ENUM64 rejects it, so the loader passes it a copy in which
 * the enum is a UNION of one-byte placeholder INTs.
 */
enum sanitize_wide {
	WIDE_LOW  = 1,
	WIDE_HIGH = 0x100000000ULL,
};

/* A negative value makes clang emit a signed BTF_KIND_ENUM, with the kind
 * flag set, which the same kernels reject; the copy clears the flag.
 */
enum sanitize_signed {
	SIGNED_NEG = -1,
	SIGNED_POS = 1,
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__type(key, enum sanitize_signed);
	__type(value, enum sanitize_wide);
} wide_values SEC(".maps");

SEC("kprobe/do_sys_openat2")
int handle_enum64(void *ctx) {
	enum sanitize_signed key = SIGNED_NEG;
	enum sanitize_wide value = WIDE_HIGH;

	bpf_map_update_elem(&wide_values, &key, &value, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
