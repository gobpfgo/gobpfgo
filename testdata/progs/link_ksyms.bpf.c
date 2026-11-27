// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* .ksyms externs, which the loader resolves against the kernel BTF: a typed
 * per-CPU variable and two kernel functions. The static linker passes them
 * through undefined. The object is opened, never loaded.
 */
extern const int bpf_prog_active __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

/* .bss: the bpf_prog_active value the program saw. */
int ksym_active;

SEC("kprobe/do_sys_openat2")
int handle_ksyms(void *ctx) {
	const int *active = bpf_this_cpu_ptr(&bpf_prog_active);

	bpf_rcu_read_lock();
	ksym_active = *active;
	bpf_rcu_read_unlock();

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
