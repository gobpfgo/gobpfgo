// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import "testing"

func TestSecDefUprobeMulti(t *testing.T) {
	tests := []struct {
		section    string
		progType   BpfProgType
		attachType BpfAttachType
		flags      uint32
		ok         bool
	}{
		{"uprobe.multi", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, 0, true},
		{"uprobe.multi/path:func", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, 0, true},
		{"uprobe.multi.s", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, BPF_F_SLEEPABLE, true},
		{"uretprobe.multi", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_MULTI, 0, true},
		{"uprobe.session", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_SESSION, 0, true},
		{"uprobe.session.s/path", BPF_PROG_TYPE_KPROBE, BPF_TRACE_UPROBE_SESSION, BPF_F_SLEEPABLE, true},
		{"uprobe/path:func", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, true},
		{"uprobe", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC, 0, true},
		{"not-a-section", 0, 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.section, func(t *testing.T) {
			def, ok := secDefFor(tt.section)
			if ok != tt.ok {
				t.Fatalf("secDefFor(%q) ok = %v, want %v", tt.section, ok, tt.ok)
			}
			if !ok {
				return
			}
			if def.progType != tt.progType || def.attachType != tt.attachType || def.progFlags != tt.flags {
				t.Fatalf("secDefFor(%q) = %+v, want type %v attach %v flags %#x",
					tt.section, def, tt.progType, tt.attachType, tt.flags)
			}
		})
	}
}
