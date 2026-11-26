// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

package libbpf

// BpfMapType mirrors enum bpf_map_type.
type BpfMapType uint32

// BPF_MAP_TYPE_ARRAY is the array map type from linux/bpf.h.
const BPF_MAP_TYPE_ARRAY BpfMapType = 2

// BpfProgType mirrors enum bpf_prog_type.
type BpfProgType uint32

// Program types from linux/bpf.h used by the SEC table.
const (
	BPF_PROG_TYPE_UNSPEC         BpfProgType = 0
	BPF_PROG_TYPE_SOCKET_FILTER  BpfProgType = 1
	BPF_PROG_TYPE_KPROBE         BpfProgType = 2
	BPF_PROG_TYPE_SCHED_CLS      BpfProgType = 3
	BPF_PROG_TYPE_TRACEPOINT     BpfProgType = 5
	BPF_PROG_TYPE_XDP            BpfProgType = 6
	BPF_PROG_TYPE_RAW_TRACEPOINT BpfProgType = 17
)

// BpfAttachType mirrors enum bpf_attach_type.
type BpfAttachType uint32

// BPF_ATTACH_TYPE_UNSPEC is the unspecified attach type.
const BPF_ATTACH_TYPE_UNSPEC BpfAttachType = 0
