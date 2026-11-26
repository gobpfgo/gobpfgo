// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events2 SEC(".maps");

SEC("kprobe/do_sys_openat2")
int handle_ringbuf(void *ctx) {
	__u32 value = 0x12345678;

	bpf_ringbuf_output(&events, &value, sizeof(value), 0);
	bpf_ringbuf_output(&events2, &value, sizeof(value), 0);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
