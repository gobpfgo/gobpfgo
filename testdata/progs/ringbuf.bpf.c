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

#define TASK_COMM_LEN 16

// The command name whose opens produce records, NUL-padded, or empty for
// every process. The tests set it to their own, so other processes add no
// records. A name, unlike a PID, is the same in every PID namespace.
char target_comm[TASK_COMM_LEN] SEC(".data") = {};

SEC("kprobe/do_sys_openat2")
int handle_ringbuf(void *ctx) {
	char comm[TASK_COMM_LEN];
	__u32 value = 0x12345678;

	if (target_comm[0]) {
		if (bpf_get_current_comm(comm, sizeof(comm)))
			return 0;
		if (__builtin_memcmp(comm, target_comm, sizeof(comm)))
			return 0;
	}

	bpf_ringbuf_output(&events, &value, sizeof(value), 0);
	bpf_ringbuf_output(&events2, &value, sizeof(value), 0);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
