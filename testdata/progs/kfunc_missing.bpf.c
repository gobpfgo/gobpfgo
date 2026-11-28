// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* A weak kernel function no kernel has, called without a bpf_ksym_exists
 * guard. The loader poisons the call, the verifier reaches it and rejects
 * the program, and the log fixup names the kernel function.
 */
extern void gobpfgo_missing_kfunc(void) __ksym __weak;

/* A map and a .data variable the program does not use. The load creates both
 * maps before the program fails, then closes them.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} kfunc_counts SEC(".maps");

__u64 kfunc_calls = 1;

SEC("kprobe/do_sys_openat2")
int handle_kfunc_missing(void *ctx) {
	gobpfgo_missing_kfunc();
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
