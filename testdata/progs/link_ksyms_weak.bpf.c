// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* Weak .ksyms externs. The kernel has none of the gobpfgo_ ones, so they
 * resolve to zero: a typed variable, a typeless variable and a kernel
 * function, whose call the loader poisons and the verifier never reaches.
 * bpf_prog_active exists and takes its kallsyms address.
 */
extern const int gobpfgo_missing_var __ksym __weak;
extern const void gobpfgo_missing_sym __ksym __weak;
extern void gobpfgo_missing_kfunc(void) __ksym __weak;
extern const void bpf_prog_active __ksym __weak;

/* .bss: whether the typed variable exists, the typeless variable's address,
 * whether the kernel function exists and bpf_prog_active's address.
 */
__u64 ksym_weak[4];

SEC("kprobe/do_sys_openat2")
int handle_ksyms_weak(void *ctx) {
	ksym_weak[0] = bpf_ksym_exists(&gobpfgo_missing_var);
	ksym_weak[1] = (__u64)&gobpfgo_missing_sym;
	ksym_weak[2] = bpf_ksym_exists(gobpfgo_missing_kfunc);

	if (bpf_ksym_exists(gobpfgo_missing_kfunc))
		gobpfgo_missing_kfunc();

	ksym_weak[3] = (__u64)&bpf_prog_active;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
