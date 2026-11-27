// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

// USDT attach fixture. handle_loop reads the arguments of gobpfgo:loop in
// usdt_loop_target with libbpf's usdt.bpf.h and records them per call site.

// usdt.bpf.h needs struct pt_regs for PT_REGS_IP and bool for its spec
// struct; there is no vmlinux.h to provide them.
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <stdbool.h>

// usdt.bpf.h defines bpf_usdt_arg, bpf_usdt_arg_cnt and bpf_usdt_cookie as
// weak hidden global functions, which clang emits as BPF subprograms. The Go
// loader does not load subprograms yet, so the fixture makes them static
// always-inline functions: an empty __weak, set before bpf_helpers.h defines
// it, and a __hidden redefined after. The code and the maps are unchanged;
// the maps become strong definitions.
#define __weak
#include <bpf_helpers.h>
#undef __hidden
#define __hidden static __always_inline
#include <usdt.bpf.h>

// The four probe arguments, the argument count, the USDT cookie and the
// number of hits of one call site.
struct loop_record {
	long args[4];
	long arg_cnt;
	long cookie;
	long hits;
};

// records[site] holds the last hit of the call site the first argument names:
// 1 or 2.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, struct loop_record);
} records SEC(".maps");

SEC("usdt")
int BPF_USDT(handle_loop, long site, long round, long slot, long neg) {
	struct loop_record *rec;
	__u32 key;

	if (site != 1 && site != 2)
		return 0;

	key = site;
	rec = bpf_map_lookup_elem(&records, &key);
	if (!rec)
		return 0;

	rec->args[0] = site;
	rec->args[1] = round;
	rec->args[2] = slot;
	rec->args[3] = neg;
	rec->arg_cnt = bpf_usdt_arg_cnt(ctx);
	rec->cookie  = bpf_usdt_cookie(ctx);
	__sync_fetch_and_add(&rec->hits, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
