// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* What each function adds to its argument, so the marks show which functions
 * a program called.
 */
#define CALLX_FIRST_MARK 0x1111
#define CALLX_SECOND_MARK 0x2222
#define CALLX_THIRD_MARK 0x4444
#define CALLX_GLOBAL_MARK 0x8888

typedef __u64 (*callx_fn)(__u64 base);

/* Slot 0 is handle_callx_one's result, slot 1 handle_callx_two's and slot 2
 * handle_callx_plain's.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} callx_marks SEC(".maps");

/* Static .text subprograms that no function calls directly. The function
 * tables are the only way to reach them, so a program gets them appended only
 * because it has callx.
 */
static __noinline __u64 callx_first(__u64 base) {
	return base + CALLX_FIRST_MARK;
}

static __noinline __u64 callx_third(__u64 base) {
	return base + CALLX_THIRD_MARK;
}

/* A global .text function. callx cannot call it, so the load does not append
 * it and a program's copy of the table holds 0 in its slot.
 */
__noinline __u64 callx_global(__u64 base) {
	return base + CALLX_GLOBAL_MARK;
}

/* Plain read-only data in the same section as the first table. */
const volatile __u64 callx_bias = 0x100;

/* The first two tables are in two read-only sections and list callx_first
 * and callx_second in opposite orders. Each program appends them in its
 * table's order, so the same function sits at a different offset in each
 * program. The third table is loaded only by callx_second. volatile keeps
 * clang from turning the indirect calls into direct ones.
 */
static __noinline __u64 callx_second(__u64 base);

static const volatile callx_fn callx_table_one[]                        = {callx_first, callx_second, callx_global};
static const volatile callx_fn callx_table_two[] SEC(".rodata.two")     = {callx_second, callx_first};
static const volatile callx_fn callx_table_three[] SEC(".rodata.three") = {callx_third};

/* Calls callx_third through the third table. A program appends callx_second
 * for its own table, and the table load that callx_second brings appends
 * callx_third.
 */
static __noinline __u64 callx_second(__u64 base) {
	return callx_table_three[0](base) + CALLX_SECOND_MARK;
}

/* record writes mark into slot of callx_marks. */
static __always_inline void record(__u32 slot, __u64 mark) {
	bpf_map_update_elem(&callx_marks, &slot, &mark, BPF_ANY);
}

/* A static subprogram that calls through the first table. The program that
 * calls it has callx only in this appended subprogram, and the table load is
 * one of this subprogram's relocations.
 */
static __noinline __u64 callx_dispatch(__u64 base) {
	return callx_table_one[0](base);
}

/* Calls callx_first through the first table, from callx_dispatch. */
SEC("kprobe/do_sys_openat2")
int handle_callx_one(void *ctx) {
	record(0, callx_dispatch(0));
	return 0;
}

/* Calls callx_second through the second table, which calls callx_third
 * through the third.
 */
SEC("kprobe/do_sys_openat2")
int handle_callx_two(void *ctx) {
	record(1, callx_table_two[0](0));
	return 0;
}

/* Reads .rodata, which holds the first table, without callx. It loads the
 * object's own .rodata map and gets no function appended.
 */
SEC("kprobe/do_sys_openat2")
int handle_callx_plain(void *ctx) {
	record(2, callx_bias);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
