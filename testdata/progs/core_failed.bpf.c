// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* A struct no kernel has, read without a bpf_core_field_exists guard. The
 * CO-RE relocation finds no target, the loader poisons the read, the verifier
 * reaches it and rejects the program, and the log fixup names the relocation.
 */
struct gobpfgo_missing {
	int pad;
	int field;
} __attribute__((preserve_access_index));

SEC("kprobe/do_sys_openat2")
int handle_core_failed(void *ctx) {
	struct gobpfgo_missing *missing = ctx;

	return missing->field;
}

char LICENSE[] SEC("license") = "GPL";
