// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: libbpf_sec_def

package libbpf

import "strings"

// secDef is one entry of the section-definition table. A section name matches
// when it starts with prefix; attachBTF marks sections whose target is a
// function name in the kernel BTF, in which case attachTarget holds the text
// after the prefix.
type secDef struct {
	prefix     string
	progType   BpfProgType
	attachType BpfAttachType
	progFlags  uint32
	attachBTF  bool
}

// secDefs is the subset of libbpf's SEC table needed by the current slices.
// It grows with the object loader. Namespaced prefixes come first so a bare
// section such as "uprobe" does not shadow "uprobe/...".
var secDefs = []secDef{
	{"kprobe.multi/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_KPROBE_MULTI, 0, false},
	{"kretprobe.multi/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_KPROBE_MULTI, 0, false},
	{"kprobe/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, false},
	{"kretprobe/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, false},
	{"uprobe.multi.s/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, BPF_F_SLEEPABLE, false},
	{"uprobe.multi/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, 0, false},
	{"uretprobe.multi.s/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, BPF_F_SLEEPABLE, false},
	{"uretprobe.multi/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, 0, false},
	{"uprobe.session.s/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_SESSION, BPF_F_SLEEPABLE, false},
	{"uprobe.session/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_SESSION, 0, false},
	{"uprobe/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, false},
	{"uretprobe/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, false},
	{"uprobe.s/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, BPF_F_SLEEPABLE, false},
	{"uretprobe.s/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, BPF_F_SLEEPABLE, false},
	{"tracepoint.s/", BPF_PROG_TYPE_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, BPF_F_SLEEPABLE, false},
	{"tracepoint/", BPF_PROG_TYPE_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, 0, false},
	{"tp.s/", BPF_PROG_TYPE_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, BPF_F_SLEEPABLE, false},
	{"tp/", BPF_PROG_TYPE_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, 0, false},
	{"raw_tracepoint.w/", BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE, BPF_ATTACH_TYPE_UNSPEC, 0, false},
	{"raw_tp.w/", BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE, BPF_ATTACH_TYPE_UNSPEC, 0, false},
	{"raw_tracepoint.s/", BPF_PROG_TYPE_RAW_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, BPF_F_SLEEPABLE, false},
	{"raw_tp.s/", BPF_PROG_TYPE_RAW_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, BPF_F_SLEEPABLE, false},
	{"raw_tracepoint/", BPF_PROG_TYPE_RAW_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, 0, false},
	{"raw_tp/", BPF_PROG_TYPE_RAW_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, 0, false},
	{"tp_btf.s/", BPF_PROG_TYPE_TRACING, BPF_TRACE_RAW_TP, BPF_F_SLEEPABLE, true},
	{"tp_btf/", BPF_PROG_TYPE_TRACING, BPF_TRACE_RAW_TP, 0, true},
	{"fentry.s/", BPF_PROG_TYPE_TRACING, BPF_TRACE_FENTRY, BPF_F_SLEEPABLE, true},
	{"fentry/", BPF_PROG_TYPE_TRACING, BPF_TRACE_FENTRY, 0, true},
	{"fexit.s/", BPF_PROG_TYPE_TRACING, BPF_TRACE_FEXIT, BPF_F_SLEEPABLE, true},
	{"fexit/", BPF_PROG_TYPE_TRACING, BPF_TRACE_FEXIT, 0, true},
	{"fmod_ret.s/", BPF_PROG_TYPE_TRACING, BPF_MODIFY_RETURN, BPF_F_SLEEPABLE, true},
	{"fmod_ret/", BPF_PROG_TYPE_TRACING, BPF_MODIFY_RETURN, 0, true},
	{"lsm.s/", BPF_PROG_TYPE_LSM, BPF_LSM_MAC, BPF_F_SLEEPABLE, true},
	{"lsm/", BPF_PROG_TYPE_LSM, BPF_LSM_MAC, 0, true},
	{"uprobe.multi.s", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, BPF_F_SLEEPABLE, false},
	{"uprobe.multi", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, 0, false},
	{"uretprobe.multi.s", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, BPF_F_SLEEPABLE, false},
	{"uretprobe.multi", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, 0, false},
	{"uprobe.session.s", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_SESSION, BPF_F_SLEEPABLE, false},
	{"uprobe.session", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_SESSION, 0, false},
	{"uprobe", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, false},
	{"uretprobe", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, false},
	{"kprobe", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, false},
	{"kretprobe", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, false},
	{"xdp", BPF_PROG_TYPE_XDP, BPF_ATTACH_TYPE_UNSPEC, 0, false},
	{"tc", BPF_PROG_TYPE_SCHED_CLS, BPF_ATTACH_TYPE_UNSPEC, 0, false},
}

func secDefFor(section string) (secDef, bool) {
	for _, d := range secDefs {
		if strings.HasPrefix(section, d.prefix) {
			return d, true
		}
	}
	return secDef{}, false
}
