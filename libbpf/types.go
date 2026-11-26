// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: include/uapi/linux/bpf.h
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: enum bpf_map_type, enum bpf_prog_type, enum bpf_attach_type

package libbpf

// BpfMapType is a map type from enum bpf_map_type.
type BpfMapType uint32

// BPF_MAP_TYPE_ARRAY is the array map type. The kernel allocates a fixed-size
// array of max_entries values and indexes it by key.
const BPF_MAP_TYPE_ARRAY BpfMapType = 2

// BpfProgType is a program type from enum bpf_prog_type.
type BpfProgType uint32

// Program types used by the SEC table. The values match linux/bpf.h.
const (
	BPF_PROG_TYPE_UNSPEC         BpfProgType = 0
	BPF_PROG_TYPE_SOCKET_FILTER  BpfProgType = 1
	BPF_PROG_TYPE_KPROBE         BpfProgType = 2
	BPF_PROG_TYPE_SCHED_CLS      BpfProgType = 3
	BPF_PROG_TYPE_TRACEPOINT     BpfProgType = 5
	BPF_PROG_TYPE_XDP            BpfProgType = 6
	BPF_PROG_TYPE_RAW_TRACEPOINT BpfProgType = 17
)

// BpfAttachType is an attach type from enum bpf_attach_type.
type BpfAttachType uint32

// BPF_ATTACH_TYPE_UNSPEC is the unspecified attach type.
const BPF_ATTACH_TYPE_UNSPEC BpfAttachType = 0
