// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* Slot 0 counts handle_subprog's calls through the static subprogram, slot 1
 * its direct calls to the global one and slot 2 handle_subprog_shared's calls.
 * Each call adds a different delta, so a wrong argument shows in the value.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} subprog_counts SEC(".maps");

/* The static subprogram that updates the map. The other .text functions call
 * it without a relocation, because it is static and in the same section.
 */
static __noinline int subprog_count(__u32 slot, __u64 delta) {
	__u64 *value = bpf_map_lookup_elem(&subprog_counts, &slot);

	if (value)
		__sync_fetch_and_add(value, delta);

	return 0;
}

/* A global subprogram. The verifier checks it on its own, with only its
 * scalar arguments known. Calls to it are relocated against its symbol.
 */
__noinline int subprog_add(__u32 slot, __u64 delta) {
	return subprog_count(slot, delta);
}

/* A static subprogram called from a main program. That call is relocated
 * against the .text section symbol.
 */
static __noinline int subprog_bump(__u32 slot) {
	return subprog_count(slot, 1);
}

SEC("kprobe/do_sys_openat2")
int handle_subprog(void *ctx) {
	subprog_bump(0);
	subprog_add(1, 2);
	return 0;
}

/* A second main program in the same section that shares the global
 * subprogram, so the subprograms are appended in a different order.
 */
SEC("kprobe/do_sys_openat2")
int handle_subprog_shared(void *ctx) {
	return subprog_add(2, 3);
}

char LICENSE[] SEC("license") = "GPL";
