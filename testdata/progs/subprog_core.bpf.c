// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

// CO-RE relocations inside .text subprograms, resolved against
// core_target.bpf.o: there second moves from offset 4 to 8, struct
// core_sample grows from 8 to 12 bytes and the enum values become 10 and 20,
// so every relocation changes its instruction.

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>

enum core_enum {
	CORE_FIRST  = 1,
	CORE_SECOND = 2,
};

struct core_sample {
	int first;
	int second;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct core_sample);
} values SEC(".maps");

/* The bpf_loop callback: a static subprogram with a type size relocation. */
static int subprog_core_step(__u32 index, void *ctx) {
	return bpf_core_type_size(struct core_sample) != sizeof(struct core_sample);
}

/* A static subprogram with a map load, the callback's address load, a call
 * to the global subprogram, and a field offset and an enum value relocation.
 */
__noinline int subprog_core_enum(void);

static __noinline int subprog_core_read(__u32 key) {
	struct core_sample *sample = bpf_map_lookup_elem(&values, &key);

	if (!sample)
		return 0;
	bpf_loop(1, subprog_core_step, NULL, 0);
	return __builtin_preserve_access_index(sample->second) + bpf_core_enum_value(enum core_enum, CORE_SECOND) + subprog_core_enum();
}

/* A global subprogram with an enum value relocation. */
__noinline int subprog_core_enum(void) {
	return bpf_core_enum_value(enum core_enum, CORE_FIRST);
}

/* The main program has a relocation of its own. */
SEC("kprobe/do_sys_openat2")
int handle_subprog_core(void *ctx) {
	return subprog_core_read(0) + bpf_core_type_size(struct core_sample);
}

char LICENSE[] SEC("license") = "GPL";
