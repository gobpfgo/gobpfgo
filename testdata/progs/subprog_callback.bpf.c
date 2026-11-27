// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* Slot 0 counts the callback's calls and slot 1 the global subprogram's. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} callback_counts SEC(".maps");

/* A global subprogram placed first in .text, so the callback does not start
 * at offset 0.
 */
__noinline int callback_count(__u32 slot) {
	__u64 *value = bpf_map_lookup_elem(&callback_counts, &slot);

	if (value)
		__sync_fetch_and_add(value, 1);

	return 0;
}

/* A static callback. Its address is an ld_imm64 relocated against the .text
 * section symbol, with the function offset in the instruction immediate.
 */
static int callback_step(__u32 index, void *ctx) {
	__u32 key    = 0;
	__u64 *value = bpf_map_lookup_elem(&callback_counts, &key);

	if (value)
		__sync_fetch_and_add(value, 1);

	return 0;
}

/* bpf_loop calls the callback four times. It needs Linux 5.17. */
SEC("kprobe/do_sys_openat2")
int handle_callback(void *ctx) {
	bpf_loop(4, callback_step, NULL, 0);
	return callback_count(1);
}

char LICENSE[] SEC("license") = "GPL";
