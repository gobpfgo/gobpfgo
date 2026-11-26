// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

package libbpf

// BpfMapType mirrors enum bpf_map_type.
type BpfMapType uint32

// BPF_MAP_TYPE_ARRAY is the array map type from linux/bpf.h.
const BPF_MAP_TYPE_ARRAY BpfMapType = 2
