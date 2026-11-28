// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: include/uapi/linux/bpf.h
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: enum bpf_map_type, enum bpf_prog_type, enum bpf_attach_type, BPF_F_CPU, BPF_F_ALL_CPUS, BPF_F_BEFORE, BPF_F_AFTER, BPF_F_ID, BPF_F_PREORDER, BPF_F_LINK

package libbpf

// BpfMapType is a map type from enum bpf_map_type.
type BpfMapType uint32

// Map types from enum bpf_map_type.
const (
	BPF_MAP_TYPE_UNSPEC                BpfMapType = 0
	BPF_MAP_TYPE_HASH                  BpfMapType = 1
	BPF_MAP_TYPE_ARRAY                 BpfMapType = 2
	BPF_MAP_TYPE_PROG_ARRAY            BpfMapType = 3
	BPF_MAP_TYPE_PERF_EVENT_ARRAY      BpfMapType = 4
	BPF_MAP_TYPE_PERCPU_HASH           BpfMapType = 5
	BPF_MAP_TYPE_PERCPU_ARRAY          BpfMapType = 6
	BPF_MAP_TYPE_STACK_TRACE           BpfMapType = 7
	BPF_MAP_TYPE_CGROUP_ARRAY          BpfMapType = 8
	BPF_MAP_TYPE_LRU_HASH              BpfMapType = 9
	BPF_MAP_TYPE_LRU_PERCPU_HASH       BpfMapType = 10
	BPF_MAP_TYPE_LPM_TRIE              BpfMapType = 11
	BPF_MAP_TYPE_ARRAY_OF_MAPS         BpfMapType = 12
	BPF_MAP_TYPE_HASH_OF_MAPS          BpfMapType = 13
	BPF_MAP_TYPE_DEVMAP                BpfMapType = 14
	BPF_MAP_TYPE_SOCKMAP               BpfMapType = 15
	BPF_MAP_TYPE_CPUMAP                BpfMapType = 16
	BPF_MAP_TYPE_XSKMAP                BpfMapType = 17
	BPF_MAP_TYPE_SOCKHASH              BpfMapType = 18
	BPF_MAP_TYPE_CGROUP_STORAGE        BpfMapType = 19
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY   BpfMapType = 20
	BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE BpfMapType = 21
	BPF_MAP_TYPE_QUEUE                 BpfMapType = 22
	BPF_MAP_TYPE_STACK                 BpfMapType = 23
	BPF_MAP_TYPE_SK_STORAGE            BpfMapType = 24
	BPF_MAP_TYPE_DEVMAP_HASH           BpfMapType = 25
	BPF_MAP_TYPE_STRUCT_OPS            BpfMapType = 26
	BPF_MAP_TYPE_RINGBUF               BpfMapType = 27
	BPF_MAP_TYPE_INODE_STORAGE         BpfMapType = 28
	BPF_MAP_TYPE_TASK_STORAGE          BpfMapType = 29
	BPF_MAP_TYPE_BLOOM_FILTER          BpfMapType = 30
	BPF_MAP_TYPE_USER_RINGBUF          BpfMapType = 31
	BPF_MAP_TYPE_CGRP_STORAGE          BpfMapType = 32
	BPF_MAP_TYPE_ARENA                 BpfMapType = 33
	BPF_MAP_TYPE_INSN_ARRAY            BpfMapType = 34
	BPF_MAP_TYPE_RHASH                 BpfMapType = 35
)

// BpfProgType is a program type from enum bpf_prog_type.
type BpfProgType uint32

// Program types from enum bpf_prog_type.
const (
	BPF_PROG_TYPE_UNSPEC                  BpfProgType = 0
	BPF_PROG_TYPE_SOCKET_FILTER           BpfProgType = 1
	BPF_PROG_TYPE_KPROBE                  BpfProgType = 2
	BPF_PROG_TYPE_SCHED_CLS               BpfProgType = 3
	BPF_PROG_TYPE_SCHED_ACT               BpfProgType = 4
	BPF_PROG_TYPE_TRACEPOINT              BpfProgType = 5
	BPF_PROG_TYPE_XDP                     BpfProgType = 6
	BPF_PROG_TYPE_PERF_EVENT              BpfProgType = 7
	BPF_PROG_TYPE_CGROUP_SKB              BpfProgType = 8
	BPF_PROG_TYPE_CGROUP_SOCK             BpfProgType = 9
	BPF_PROG_TYPE_LWT_IN                  BpfProgType = 10
	BPF_PROG_TYPE_LWT_OUT                 BpfProgType = 11
	BPF_PROG_TYPE_LWT_XMIT                BpfProgType = 12
	BPF_PROG_TYPE_SOCK_OPS                BpfProgType = 13
	BPF_PROG_TYPE_SK_SKB                  BpfProgType = 14
	BPF_PROG_TYPE_CGROUP_DEVICE           BpfProgType = 15
	BPF_PROG_TYPE_SK_MSG                  BpfProgType = 16
	BPF_PROG_TYPE_RAW_TRACEPOINT          BpfProgType = 17
	BPF_PROG_TYPE_CGROUP_SOCK_ADDR        BpfProgType = 18
	BPF_PROG_TYPE_LWT_SEG6LOCAL           BpfProgType = 19
	BPF_PROG_TYPE_LIRC_MODE2              BpfProgType = 20
	BPF_PROG_TYPE_SK_REUSEPORT            BpfProgType = 21
	BPF_PROG_TYPE_FLOW_DISSECTOR          BpfProgType = 22
	BPF_PROG_TYPE_CGROUP_SYSCTL           BpfProgType = 23
	BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE BpfProgType = 24
	BPF_PROG_TYPE_CGROUP_SOCKOPT          BpfProgType = 25
	BPF_PROG_TYPE_TRACING                 BpfProgType = 26
	BPF_PROG_TYPE_STRUCT_OPS              BpfProgType = 27
	BPF_PROG_TYPE_EXT                     BpfProgType = 28
	BPF_PROG_TYPE_LSM                     BpfProgType = 29
	BPF_PROG_TYPE_SK_LOOKUP               BpfProgType = 30
	BPF_PROG_TYPE_SYSCALL                 BpfProgType = 31
	BPF_PROG_TYPE_NETFILTER               BpfProgType = 32
)

// BpfAttachType is an attach type from enum bpf_attach_type.
type BpfAttachType uint32

// Attach types used by the SEC table and by link creation. The values match
// linux/bpf.h.
//
// BPF_ATTACH_TYPE_UNSPEC is the zero value a section without an attach type
// reports; the kernel's enum names 0 BPF_CGROUP_INET_INGRESS.
const (
	BPF_ATTACH_TYPE_UNSPEC   BpfAttachType = 0
	BPF_CGROUP_INET_INGRESS  BpfAttachType = 0
	BPF_CGROUP_INET_EGRESS   BpfAttachType = 1
	BPF_SK_MSG_VERDICT       BpfAttachType = 7
	BPF_CGROUP_INET4_CONNECT BpfAttachType = 10
	BPF_LIRC_MODE2           BpfAttachType = 16
	BPF_FLOW_DISSECTOR       BpfAttachType = 17
	BPF_CGROUP_GETSOCKOPT    BpfAttachType = 21
	BPF_TRACE_RAW_TP         BpfAttachType = 23
	BPF_TRACE_FENTRY         BpfAttachType = 24
	BPF_TRACE_FEXIT          BpfAttachType = 25
	BPF_MODIFY_RETURN        BpfAttachType = 26
	BPF_LSM_MAC              BpfAttachType = 27
	BPF_TRACE_ITER           BpfAttachType = 28
	BPF_SK_LOOKUP            BpfAttachType = 36
	BPF_XDP                  BpfAttachType = 37
	BPF_PERF_EVENT           BpfAttachType = 41
	BPF_TRACE_KPROBE_MULTI   BpfAttachType = 42
	BPF_NETFILTER            BpfAttachType = 45
	BPF_TRACE_UPROBE_MULTI   BpfAttachType = 48
	BPF_TRACE_KPROBE_SESSION BpfAttachType = 56
	BPF_TRACE_UPROBE_SESSION BpfAttachType = 57
)

// Link attach flags for BpfCgroupOpts.Flags. BPF_F_BEFORE and BPF_F_AFTER
// place the new program before or after the relative program or link, or
// first or last without one; BPF_F_LINK makes the relative object a link;
// BPF_F_PREORDER runs the program before the programs of descendant cgroups.
// BPF_F_ID marks the relative object as an id; the attach sets it itself
// when RelativeID is used.
const (
	BPF_F_BEFORE   uint32 = 1 << 3
	BPF_F_AFTER    uint32 = 1 << 4
	BPF_F_ID       uint32 = 1 << 5
	BPF_F_PREORDER uint32 = 1 << 6
	BPF_F_LINK     uint32 = 1 << 13
)

// BpfFuncID is a helper id from enum bpf_func_id.
type BpfFuncID uint32

// Helper ids used by the probe tests and the feature matrix.
const (
	BPF_FUNC_map_lookup_elem      BpfFuncID = 1
	BPF_FUNC_probe_read           BpfFuncID = 4
	BPF_FUNC_ktime_get_ns         BpfFuncID = 5
	BPF_FUNC_trace_printk         BpfFuncID = 6
	BPF_FUNC_get_current_pid_tgid BpfFuncID = 14
	BPF_FUNC_redirect             BpfFuncID = 23
	BPF_FUNC_perf_event_output    BpfFuncID = 25
	BPF_FUNC_get_func_ip          BpfFuncID = 173
	BPF_FUNC_get_attach_cookie    BpfFuncID = 174
)

// BPF_F_SLEEPABLE marks a sleepable program when passed in prog_flags.
const BPF_F_SLEEPABLE uint32 = 1 << 4

// BPF_F_UPROBE_MULTI_RETURN makes a uprobe multi link call the program when
// the probed functions return.
const BPF_F_UPROBE_MULTI_RETURN uint32 = 1 << 0

// Map element update flags: BPF_ANY creates or replaces the element,
// BPF_NOEXIST only creates it and BPF_EXIST only replaces it.
const (
	BPF_ANY     uint64 = 0
	BPF_NOEXIST uint64 = 1
	BPF_EXIST   uint64 = 2
)

// Per-CPU map element flags. BPF_F_CPU reads or writes the value of the CPU
// whose number is in the upper 32 bits of the flags, and BPF_F_ALL_CPUS writes
// one value to every CPU; with either flag the element value is a single
// value instead of one per possible CPU. Kernels without them reject the
// flags with EINVAL.
const (
	BPF_F_CPU      uint64 = 8
	BPF_F_ALL_CPUS uint64 = 16
)
