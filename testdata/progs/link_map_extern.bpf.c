// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* An extern map. Clang puts it in a .maps DATASEC but emits no .maps ELF
 * section, so the static linker gives it an ephemeral .maps section.
 * link_map_def.bpf.o defines the map with the same definition; linked after
 * this object, its .maps section turns the ephemeral one into an ELF section.
 */
extern struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} map_extern_counts SEC(".maps");

SEC("kprobe/do_sys_openat2")
int handle_map_extern(void *ctx) {
	__u32 key    = 0;
	__u64 *value = bpf_map_lookup_elem(&map_extern_counts, &key);

	if (value)
		__sync_fetch_and_add(value, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
