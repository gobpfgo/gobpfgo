// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

// target_tid holds the thread the test opens from; counts counts the program
// runs on that thread. Returning 0 from the entry run asks for the return
// run too, so one open on the thread counts two.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} target_tid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} counts SEC(".maps");

SEC("kprobe.session/do_sys_openat2")
int handle_session(void *ctx) {
	__u32 key   = 0;
	__u32 tid   = (__u32)bpf_get_current_pid_tgid();
	__u32 *want = bpf_map_lookup_elem(&target_tid, &key);
	__u64 *value;

	if (!want || *want != tid)
		return 0;

	value = bpf_map_lookup_elem(&counts, &key);
	if (value)
		__sync_fetch_and_add(value, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
