// SPDX-License-Identifier: LGPL-2.1-only
// Ported from libbpf src/libbpf.c at 4f05fb0.

package libbpf

import "strings"

type secDef struct {
	prefix     string
	progType   BpfProgType
	attachType BpfAttachType
}

// secDefs is the subset of libbpf's SEC table needed by the current slices.
// It grows with the object loader.
var secDefs = []secDef{
	{"kprobe/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC},
	{"kretprobe/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC},
	{"tracepoint/", BPF_PROG_TYPE_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC},
	{"raw_tracepoint/", BPF_PROG_TYPE_RAW_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC},
	{"xdp", BPF_PROG_TYPE_XDP, BPF_ATTACH_TYPE_UNSPEC},
	{"tc", BPF_PROG_TYPE_SCHED_CLS, BPF_ATTACH_TYPE_UNSPEC},
}

func secDefFor(section string) (BpfProgType, BpfAttachType, bool) {
	for _, d := range secDefs {
		if strings.HasPrefix(section, d.prefix) {
			return d.progType, d.attachType, true
		}
	}
	return 0, 0, false
}
