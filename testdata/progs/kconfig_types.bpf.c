// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

// One .kconfig extern per kconfig value type, for the value parser. The
// layout sorts them by alignment, then size, then name; the 1-byte externs
// come before the 8-byte string. The object is only opened and resolved,
// never loaded into a kernel.
extern _Bool CONFIG_GOBPFGO_BOOL __kconfig __weak;
extern char CONFIG_GOBPFGO_CHAR __kconfig __weak;
extern unsigned char CONFIG_GOBPFGO_U8 __kconfig __weak;
extern short CONFIG_GOBPFGO_S16 __kconfig __weak;
extern int CONFIG_GOBPFGO_S32 __kconfig __weak;
extern unsigned int CONFIG_GOBPFGO_U32 __kconfig __weak;
extern long long CONFIG_GOBPFGO_S64 __kconfig __weak;
extern unsigned long long CONFIG_GOBPFGO_U64 __kconfig __weak;
extern enum libbpf_tristate CONFIG_GOBPFGO_TRISTATE __kconfig __weak;
extern char CONFIG_GOBPFGO_STR[8] __kconfig __weak;

// A strong CONFIG_ extern must get a value, and a weak unknown LINUX_ extern
// defaults to zero.
extern int CONFIG_GOBPFGO_STRONG __kconfig;
extern int LINUX_GOBPFGO_UNKNOWN __kconfig __weak;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 12);
	__type(key, __u32);
	__type(value, __u64);
} values SEC(".maps");

static __always_inline void store(__u32 key, __u64 value) {
	__u64 *slot = bpf_map_lookup_elem(&values, &key);

	if (slot)
		*slot = value;
}

SEC("kprobe/do_sys_openat2")
int handle_kconfig_types(void *ctx) {
	store(0, CONFIG_GOBPFGO_BOOL);
	store(1, CONFIG_GOBPFGO_CHAR);
	store(2, CONFIG_GOBPFGO_U8);
	store(3, CONFIG_GOBPFGO_S16);
	store(4, CONFIG_GOBPFGO_S32);
	store(5, CONFIG_GOBPFGO_U32);
	store(6, CONFIG_GOBPFGO_S64);
	store(7, CONFIG_GOBPFGO_U64);
	store(8, CONFIG_GOBPFGO_TRISTATE);
	store(9, CONFIG_GOBPFGO_STR[1]);
	store(10, CONFIG_GOBPFGO_STRONG);
	store(11, LINUX_GOBPFGO_UNKNOWN);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
