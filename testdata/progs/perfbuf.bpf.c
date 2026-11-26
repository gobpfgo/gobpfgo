// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 128);
} events SEC(".maps");

SEC("kprobe/do_sys_openat2")
int handle_perfbuf(void *ctx) {
	__u32 value = 0x12345678;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &value, sizeof(value));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
