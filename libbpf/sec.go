// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: libbpf_sec_def

package libbpf

import "strings"

// secFlags are the loader flags of a section definition.
type secFlags uint32

const (
	// secAttachBTF marks sections whose target is a function name in the
	// kernel BTF; the program's attach target is the text after the prefix.
	// The bare iter sections name none, so BpfProgramSetAttachTarget must.
	secAttachBTF secFlags = 1 << iota
	// secUSDT marks USDT sections. Their programs are loaded with the
	// uprobe multi expected attach type when the kernel has that link, so
	// BpfProgramAttachUsdt can attach every call site through one link.
	secUSDT
	// secAttachProg marks sections whose target is a function of another
	// BPF program, freplace. The program's attach target is the text after
	// the prefix; the load looks it up in the BTF of the program
	// BpfProgramSetAttachTarget names, never in the kernel BTF. The bare
	// freplace section names no function, so BpfProgramSetAttachTarget
	// must. libbpf marks freplace SEC_ATTACH_BTF and tells it apart by
	// program type.
	secAttachProg
)

// secDef is one entry of the section-definition table. A section name matches
// when it starts with prefix.
type secDef struct {
	prefix     string
	progType   BpfProgType
	attachType BpfAttachType
	progFlags  uint32
	flags      secFlags
}

// secDefs is the subset of libbpf's SEC table needed by the current slices.
// It grows with the object loader. Namespaced prefixes come first so a bare
// section such as "uprobe" does not shadow "uprobe/...".
var secDefs = []secDef{
	{"kprobe.multi/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_KPROBE_MULTI, 0, 0},
	{"kretprobe.multi/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_KPROBE_MULTI, 0, 0},
	{"kprobe.session/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_KPROBE_SESSION, 0, 0},
	{"kprobe/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
	{"kretprobe/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
	{"uprobe.multi.s/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, BPF_F_SLEEPABLE, 0},
	{"uprobe.multi/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, 0, 0},
	{"uretprobe.multi.s/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, BPF_F_SLEEPABLE, 0},
	{"uretprobe.multi/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, 0, 0},
	{"uprobe.session.s/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_SESSION, BPF_F_SLEEPABLE, 0},
	{"uprobe.session/", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_SESSION, 0, 0},
	{"usdt.s/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, BPF_F_SLEEPABLE, secUSDT},
	{"usdt/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, secUSDT},
	{"uprobe/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
	{"uretprobe/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
	{"uprobe.s/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, BPF_F_SLEEPABLE, 0},
	{"uretprobe.s/", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, BPF_F_SLEEPABLE, 0},
	{"tracepoint.s/", BPF_PROG_TYPE_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, BPF_F_SLEEPABLE, 0},
	{"tracepoint/", BPF_PROG_TYPE_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
	{"tp.s/", BPF_PROG_TYPE_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, BPF_F_SLEEPABLE, 0},
	{"tp/", BPF_PROG_TYPE_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
	{"raw_tracepoint.w/", BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
	{"raw_tp.w/", BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
	{"raw_tracepoint.s/", BPF_PROG_TYPE_RAW_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, BPF_F_SLEEPABLE, 0},
	{"raw_tp.s/", BPF_PROG_TYPE_RAW_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, BPF_F_SLEEPABLE, 0},
	{"raw_tracepoint/", BPF_PROG_TYPE_RAW_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
	{"raw_tp/", BPF_PROG_TYPE_RAW_TRACEPOINT, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
	{"tp_btf.s/", BPF_PROG_TYPE_TRACING, BPF_TRACE_RAW_TP, BPF_F_SLEEPABLE, secAttachBTF},
	{"tp_btf/", BPF_PROG_TYPE_TRACING, BPF_TRACE_RAW_TP, 0, secAttachBTF},
	{"fentry.s/", BPF_PROG_TYPE_TRACING, BPF_TRACE_FENTRY, BPF_F_SLEEPABLE, secAttachBTF},
	{"fentry/", BPF_PROG_TYPE_TRACING, BPF_TRACE_FENTRY, 0, secAttachBTF},
	{"fexit.s/", BPF_PROG_TYPE_TRACING, BPF_TRACE_FEXIT, BPF_F_SLEEPABLE, secAttachBTF},
	{"fexit/", BPF_PROG_TYPE_TRACING, BPF_TRACE_FEXIT, 0, secAttachBTF},
	{"fmod_ret.s/", BPF_PROG_TYPE_TRACING, BPF_MODIFY_RETURN, BPF_F_SLEEPABLE, secAttachBTF},
	{"fmod_ret/", BPF_PROG_TYPE_TRACING, BPF_MODIFY_RETURN, 0, secAttachBTF},
	{"lsm.s/", BPF_PROG_TYPE_LSM, BPF_LSM_MAC, BPF_F_SLEEPABLE, secAttachBTF},
	{"lsm/", BPF_PROG_TYPE_LSM, BPF_LSM_MAC, 0, secAttachBTF},
	{"iter.s/", BPF_PROG_TYPE_TRACING, BPF_TRACE_ITER, BPF_F_SLEEPABLE, secAttachBTF},
	{"iter/", BPF_PROG_TYPE_TRACING, BPF_TRACE_ITER, 0, secAttachBTF},
	{"freplace/", BPF_PROG_TYPE_EXT, BPF_ATTACH_TYPE_UNSPEC, 0, secAttachProg},
	{"uprobe.multi.s", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, BPF_F_SLEEPABLE, 0},
	{"uprobe.multi", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, 0, 0},
	{"uretprobe.multi.s", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, BPF_F_SLEEPABLE, 0},
	{"uretprobe.multi", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, 0, 0},
	{"uprobe.session.s", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_SESSION, BPF_F_SLEEPABLE, 0},
	{"uprobe.session", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_SESSION, 0, 0},
	{"usdt.s", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, BPF_F_SLEEPABLE, secUSDT},
	{"usdt", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, secUSDT},
	{"uprobe", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
	{"uretprobe", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
	{"kprobe.session", BPF_PROG_TYPE_KPROBE, BPF_TRACE_KPROBE_SESSION, 0, 0},
	{"iter.s", BPF_PROG_TYPE_TRACING, BPF_TRACE_ITER, BPF_F_SLEEPABLE, secAttachBTF},
	{"iter", BPF_PROG_TYPE_TRACING, BPF_TRACE_ITER, 0, secAttachBTF},
	{"freplace", BPF_PROG_TYPE_EXT, BPF_ATTACH_TYPE_UNSPEC, 0, secAttachProg},
	{"kprobe", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
	{"kretprobe", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
	{"xdp", BPF_PROG_TYPE_XDP, BPF_XDP, 0, 0},
	{"tc", BPF_PROG_TYPE_SCHED_CLS, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
	{"sk_msg", BPF_PROG_TYPE_SK_MSG, BPF_SK_MSG_VERDICT, 0, 0},
	{"flow_dissector", BPF_PROG_TYPE_FLOW_DISSECTOR, BPF_FLOW_DISSECTOR, 0, 0},
	{"cgroup_skb/ingress", BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_INGRESS, 0, 0},
	{"cgroup_skb/egress", BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_EGRESS, 0, 0},
	{"cgroup/skb", BPF_PROG_TYPE_CGROUP_SKB, BPF_ATTACH_TYPE_UNSPEC, 0, 0},
}

func secDefFor(section string) (secDef, bool) {
	for _, d := range secDefs {
		if strings.HasPrefix(section, d.prefix) {
			return d, true
		}
	}
	return secDef{}, false
}
