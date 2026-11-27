// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

// CONFIG_TEST comes from the kconfig string the test passes at open, so the
// system config is never read. LINUX_KERNEL_VERSION is a virtual extern the
// loader fills from the running kernel.
extern int CONFIG_TEST __kconfig;
extern unsigned int LINUX_KERNEL_VERSION __kconfig;

// Weak LINUX_ externs the loader does not know default to zero. The 8-byte one
// sorts first by alignment and the 1-byte one last, after the 4-byte externs.
extern __u64 LINUX_GOBPFGO_UNKNOWN __kconfig __weak;
extern _Bool LINUX_GOBPFGO_FLAG __kconfig __weak;

// values[i] holds what the program read from the i-th extern above.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} values SEC(".maps");

static __always_inline void store(__u32 key, __u64 value) {
	__u64 *slot = bpf_map_lookup_elem(&values, &key);

	if (slot)
		*slot = value;
}

SEC("kprobe/do_sys_openat2")
int handle_kconfig(void *ctx) {
	store(0, CONFIG_TEST);
	store(1, LINUX_KERNEL_VERSION);
	store(2, LINUX_GOBPFGO_UNKNOWN);
	store(3, LINUX_GOBPFGO_FLAG);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
