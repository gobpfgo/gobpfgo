// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} text_counts_a SEC(".maps");

/* A static subprogram in .text: both objects have one named bump, so the
 * linked .text holds two local functions and the calls into the second one
 * are moved by the size of the first.
 */
static __noinline int bump(void) {
	__u32 key    = 0;
	__u64 *value = bpf_map_lookup_elem(&text_counts_a, &key);

	if (value)
		__sync_fetch_and_add(value, 1);

	return 0;
}

SEC("kprobe/do_sys_openat2")
int handle_text_a(void *ctx) {
	return bump();
}

char LICENSE[] SEC("license") = "GPL";
