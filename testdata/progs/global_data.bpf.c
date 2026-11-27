// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

// .data: the magic proves the initial section bytes reached the map, and the
// counter starts above zero so a missing initial value is visible.
__u64 data_magic   = 0xfeedfacecafebeefULL;
__u64 data_counter = 100;

// A static variable is referenced through the .data section symbol, with its
// offset in the instruction immediate instead of in a symbol value.
static volatile __u64 data_static = 7;

// .rodata: read-only for the program and frozen for user space after load.
const volatile __u32 rodata_pad   = 0x11111111;
const volatile __u64 rodata_value = 0x0123456789abcdefULL;

// .bss: zero-initialized; the program counts calls and copies the read-only
// value so the test can check what the program saw.
__u64 bss_counter;
__u64 bss_seen;

SEC("kprobe/do_sys_openat2")
int handle_global(void *ctx) {
	__sync_fetch_and_add(&data_counter, 1);
	__sync_fetch_and_add(&bss_counter, 1);
	data_static = data_static + 1;
	bss_seen    = rodata_value;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
