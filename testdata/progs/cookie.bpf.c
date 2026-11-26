// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} cookies SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_cookie(void *ctx) {
	__u32 key    = 0;
	__u64 *value = bpf_map_lookup_elem(&cookies, &key);

	if (value)
		*value = bpf_get_attach_cookie(ctx);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
