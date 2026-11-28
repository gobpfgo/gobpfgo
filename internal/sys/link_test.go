// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package sys

import (
	"bytes"
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSetUprobeMulti checks that each uprobe multi pointer field points at a
// kept buffer holding the NUL-terminated path or the native-endian array.
func TestSetUprobeMulti(t *testing.T) {
	um := &LinkUprobeMulti{
		Path:          "/usr/bin/true",
		Offsets:       []uint64{0x1000, 0x2000},
		RefCtrOffsets: []uint64{0x30, 0x40},
		Cookies:       []uint64{7, 8},
		Flags:         1,
		PID:           4242,
	}
	attr := &LinkCreateAttr{ProgFD: 3, AttachType: 48}

	keeps, err := setUprobeMulti(attr, um)
	if err != nil {
		t.Fatalf("setUprobeMulti: %v", err)
	}

	if attr.UprobeMultiCnt != 2 || attr.UprobeMultiFlags != 1 || attr.UprobeMultiPID != 4242 {
		t.Fatalf("cnt/flags/pid = %d/%d/%d, want 2/1/4242", attr.UprobeMultiCnt, attr.UprobeMultiFlags, attr.UprobeMultiPID)
	}
	checkKeptBuffer(t, keeps, "path", attr.UprobeMultiPath, []byte("/usr/bin/true\x00"))
	checkKeptBuffer(t, keeps, "offsets", attr.UprobeMultiOffsets, u64Bytes(um.Offsets))
	checkKeptBuffer(t, keeps, "ref_ctr_offsets", attr.UprobeMultiRefCtrOffsets, u64Bytes(um.RefCtrOffsets))
	checkKeptBuffer(t, keeps, "cookies", attr.UprobeMultiCookies, u64Bytes(um.Cookies))
}

// TestSetUprobeMultiOptionalArrays checks that absent reference counter
// offsets and cookies leave their pointers NULL.
func TestSetUprobeMultiOptionalArrays(t *testing.T) {
	attr := &LinkCreateAttr{}
	keeps, err := setUprobeMulti(attr, &LinkUprobeMulti{Path: "/bin/sh", Offsets: []uint64{0x10}})
	if err != nil {
		t.Fatalf("setUprobeMulti: %v", err)
	}
	if len(keeps) != 2 {
		t.Fatalf("kept %d buffers, want the path and the offsets", len(keeps))
	}
	if attr.UprobeMultiRefCtrOffsets != 0 || attr.UprobeMultiCookies != 0 {
		t.Fatalf("ref_ctr_offsets/cookies = %#x/%#x, want NULL", attr.UprobeMultiRefCtrOffsets, attr.UprobeMultiCookies)
	}
}

func TestSetUprobeMultiInvalid(t *testing.T) {
	valid := func() *LinkUprobeMulti {
		return &LinkUprobeMulti{Path: "/bin/sh", Offsets: []uint64{0x10, 0x20}}
	}
	tests := []struct {
		name string
		attr *LinkCreateAttr
		um   *LinkUprobeMulti
	}{
		{"nil attr", nil, valid()},
		{"nil arrays", &LinkCreateAttr{}, nil},
		{"empty path", &LinkCreateAttr{}, &LinkUprobeMulti{Offsets: []uint64{0x10}}},
		{"path with NUL", &LinkCreateAttr{}, &LinkUprobeMulti{Path: "/bin\x00/sh", Offsets: []uint64{0x10}}},
		{"no offsets", &LinkCreateAttr{}, &LinkUprobeMulti{Path: "/bin/sh"}},
		{"short ref_ctr_offsets", &LinkCreateAttr{}, &LinkUprobeMulti{Path: "/bin/sh", Offsets: []uint64{0x10, 0x20}, RefCtrOffsets: []uint64{0x30}}},
		{"long cookies", &LinkCreateAttr{}, &LinkUprobeMulti{Path: "/bin/sh", Offsets: []uint64{0x10}, Cookies: []uint64{1, 2}}},
		{"target btf id set", &LinkCreateAttr{TargetBTFID: 1}, valid()},
		{"perf event cookie set", &LinkCreateAttr{PerfEventCookie: 1}, valid()},
		{"tracing cookie set", &LinkCreateAttr{TracingCookie: 1}, valid()},
		{"kprobe multi set", &LinkCreateAttr{KprobeMultiCnt: 1}, valid()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := setUprobeMulti(tt.attr, tt.um); !errors.Is(err, unix.EINVAL) {
				t.Fatalf("setUprobeMulti = %v, want EINVAL", err)
			}
		})
	}
}

// TestLinkCreateUnionAttrBytes marshals one attribute per union member, plus
// attach types without a member, and requires each field at the offset and
// size libbpf's headers report, with every other byte zero. Fields of a
// member the attach type does not select must not be written, a target BTF
// id is written alone, and a cgroup relative id adds BPF_F_ID to the flags.
func TestLinkCreateUnionAttrBytes(t *testing.T) {
	f := loadLayoutFixture(t)

	stray := LinkCreateAttr{
		PerfEventCookie:        0x1111,
		TracingCookie:          0x2222,
		CgroupRelativeFD:       0x3333,
		CgroupExpectedRevision: 0x4444,
	}
	tests := []struct {
		name   string
		attr   LinkCreateAttr
		values map[string]uint64
	}{
		{
			name: "cgroup relative fd",
			attr: LinkCreateAttr{ProgFD: 7, TargetFD: 9, AttachType: BPF_CGROUP_INET_INGRESS, Flags: 1 << 3,
				CgroupRelativeFD: 11, CgroupExpectedRevision: 0x0123456789abcdef},
			values: map[string]uint64{"prog_fd": 7, "target_fd": 9, "attach_type": BPF_CGROUP_INET_INGRESS, "flags": 1 << 3,
				"cgroup.relative_fd": 11, "cgroup.expected_revision": 0x0123456789abcdef},
		},
		{
			name: "cgroup relative id",
			attr: LinkCreateAttr{ProgFD: 7, TargetFD: 9, AttachType: BPF_CGROUP_INET_EGRESS, Flags: 1 << 4,
				CgroupRelativeID: 42, CgroupExpectedRevision: 5},
			values: map[string]uint64{"prog_fd": 7, "target_fd": 9, "attach_type": BPF_CGROUP_INET_EGRESS, "flags": 1<<4 | BPF_F_ID,
				"cgroup.relative_id": 42, "cgroup.expected_revision": 5},
		},
		{
			name:   "lsm cgroup",
			attr:   LinkCreateAttr{ProgFD: 7, AttachType: BPF_LSM_CGROUP, CgroupRelativeFD: 12},
			values: map[string]uint64{"prog_fd": 7, "attach_type": BPF_LSM_CGROUP, "cgroup.relative_fd": 12},
		},
		{
			name:   "iterator",
			attr:   LinkCreateAttr{ProgFD: 7, AttachType: BPF_TRACE_ITER, IterInfo: 0x5555555555555555, IterInfoLen: 8},
			values: map[string]uint64{"prog_fd": 7, "attach_type": BPF_TRACE_ITER, "iter_info": 0x5555555555555555, "iter_info_len": 8},
		},
		{
			name: "kprobe session",
			attr: LinkCreateAttr{ProgFD: 7, AttachType: BPF_TRACE_KPROBE_SESSION, KprobeMultiCnt: 2,
				KprobeMultiSyms: 0x6666666666666666, KprobeMultiCookies: 0x7777777777777777},
			values: map[string]uint64{"prog_fd": 7, "attach_type": BPF_TRACE_KPROBE_SESSION, "kprobe_multi.flags": 0, "kprobe_multi.cnt": 2,
				"kprobe_multi.syms": 0x6666666666666666, "kprobe_multi.addrs": 0, "kprobe_multi.cookies": 0x7777777777777777},
		},
		{
			name: "kprobe multi return",
			attr: LinkCreateAttr{ProgFD: 7, AttachType: BPF_TRACE_KPROBE_MULTI, KprobeMultiFlags: 1, KprobeMultiCnt: 1,
				KprobeMultiAddrs: 0x8888888888888888},
			values: map[string]uint64{"prog_fd": 7, "attach_type": BPF_TRACE_KPROBE_MULTI, "kprobe_multi.flags": 1, "kprobe_multi.cnt": 1,
				"kprobe_multi.addrs": 0x8888888888888888},
		},
		{
			name:   "perf event",
			attr:   LinkCreateAttr{ProgFD: 7, TargetFD: 8, AttachType: BPF_PERF_EVENT, PerfEventCookie: 0x9999},
			values: map[string]uint64{"prog_fd": 7, "target_fd": 8, "attach_type": BPF_PERF_EVENT, "perf_event.bpf_cookie": 0x9999},
		},
		{
			name:   "tracing",
			attr:   LinkCreateAttr{ProgFD: 7, AttachType: BPF_TRACE_FENTRY, TracingCookie: 0xaaaa},
			values: map[string]uint64{"prog_fd": 7, "attach_type": BPF_TRACE_FENTRY, "tracing.target_btf_id": 0, "tracing.cookie": 0xaaaa},
		},
		{
			name:   "target btf id",
			attr:   LinkCreateAttr{ProgFD: 7, AttachType: BPF_CGROUP_INET_INGRESS, TargetBTFID: 77, CgroupRelativeID: 3},
			values: map[string]uint64{"prog_fd": 7, "attach_type": BPF_CGROUP_INET_INGRESS, "target_btf_id": 77},
		},
		{
			name:   "xdp",
			attr:   withLinkTarget(stray, 7, 1, linkCreateAttachXDP),
			values: map[string]uint64{"prog_fd": 7, "target_ifindex": 1, "attach_type": linkCreateAttachXDP},
		},
		{
			name:   "flow dissector",
			attr:   withLinkTarget(stray, 7, 5, linkCreateAttachFlowDissector),
			values: map[string]uint64{"prog_fd": 7, "target_fd": 5, "attach_type": linkCreateAttachFlowDissector},
		},
		{
			name:   "sk_msg",
			attr:   withLinkTarget(stray, 7, 6, linkCreateAttachSkMsgVerdict),
			values: map[string]uint64{"prog_fd": 7, "target_fd": 6, "attach_type": linkCreateAttachSkMsgVerdict},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := fixtureBytes(t, f.LinkCreate, tt.values)
			if got := tt.attr.Marshal(); !bytes.Equal(got, want) {
				t.Fatalf("link_create bytes:\n got %x\nwant %x", got, want)
			}
		})
	}
}

// Attach types without a union member, used by the attribute tests.
const (
	linkCreateAttachSkMsgVerdict  = 7
	linkCreateAttachFlowDissector = 17
	linkCreateAttachXDP           = 37
)

// withLinkTarget returns attr with the program, target and attach type set.
func withLinkTarget(attr LinkCreateAttr, progFD, targetFD, attachType uint32) LinkCreateAttr {
	attr.ProgFD = progFD
	attr.TargetFD = targetFD
	attr.AttachType = attachType
	return attr
}

// TestLinkCreateMarshalKeepsFlags checks that the BPF_F_ID a cgroup relative
// id adds goes only into the marshaled bytes.
func TestLinkCreateMarshalKeepsFlags(t *testing.T) {
	attr := &LinkCreateAttr{AttachType: BPF_CGROUP_INET_INGRESS, Flags: 1 << 3, CgroupRelativeID: 42}
	_ = attr.Marshal()
	if attr.Flags != 1<<3 {
		t.Fatalf("Flags after Marshal = %#x, want %#x", attr.Flags, 1<<3)
	}
}

func TestLinkCreateAttrValidate(t *testing.T) {
	tests := []struct {
		name string
		attr LinkCreateAttr
		want error
	}{
		{"iterator", LinkCreateAttr{AttachType: BPF_TRACE_ITER, IterInfo: 1, IterInfoLen: 8}, nil},
		{"iterator info on another type", LinkCreateAttr{AttachType: BPF_TRACE_FENTRY, IterInfoLen: 8}, unix.EINVAL},
		{"iterator info and target btf id", LinkCreateAttr{AttachType: BPF_TRACE_ITER, IterInfoLen: 8, TargetBTFID: 1}, unix.EINVAL},
		{"iterator info and union field", LinkCreateAttr{AttachType: BPF_TRACE_ITER, IterInfoLen: 8, TracingCookie: 1}, unix.EINVAL},
		{"target btf id", LinkCreateAttr{AttachType: BPF_TRACE_FENTRY, TargetBTFID: 1}, nil},
		{"target btf id and union field", LinkCreateAttr{AttachType: BPF_TRACE_FENTRY, TargetBTFID: 1, TracingCookie: 1}, unix.EINVAL},
		{"cgroup relative fd", LinkCreateAttr{AttachType: BPF_CGROUP_INET_EGRESS, CgroupRelativeFD: 3, CgroupExpectedRevision: 2}, nil},
		{"cgroup relative id", LinkCreateAttr{AttachType: BPF_CGROUP_INET_EGRESS, CgroupRelativeID: 3}, nil},
		{"cgroup relative fd and id", LinkCreateAttr{AttachType: BPF_CGROUP_INET_EGRESS, CgroupRelativeFD: 3, CgroupRelativeID: 4}, unix.EINVAL},
		{"cgroup ignores another member", LinkCreateAttr{AttachType: BPF_CGROUP_INET_EGRESS, TracingCookie: 1}, nil},
		{"xdp", LinkCreateAttr{AttachType: linkCreateAttachXDP, TargetFD: 1, Flags: 2}, nil},
		{"xdp with cgroup revision", LinkCreateAttr{AttachType: linkCreateAttachXDP, CgroupExpectedRevision: 1}, unix.EINVAL},
		{"sk_msg with relative fd", LinkCreateAttr{AttachType: linkCreateAttachSkMsgVerdict, CgroupRelativeFD: 1}, unix.EINVAL},
		{"kprobe session", LinkCreateAttr{AttachType: BPF_TRACE_KPROBE_SESSION, KprobeMultiCnt: 1}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.attr.validate(); !errors.Is(err, tt.want) {
				t.Fatalf("validate = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestLinkCreateRejectsBeforeSyscall checks that LinkCreate returns the
// validation error without calling bpf(), which would fail with EBADF for
// the invalid descriptors or EPERM without privileges.
func TestLinkCreateRejectsBeforeSyscall(t *testing.T) {
	attr := &LinkCreateAttr{ProgFD: ^uint32(0), TargetFD: ^uint32(0), AttachType: BPF_CGROUP_INET_INGRESS,
		CgroupRelativeFD: 3, CgroupRelativeID: 4}
	if _, err := LinkCreate(attr, nil); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("LinkCreate = %v, want EINVAL", err)
	}
}

// checkKeptBuffer finds the kept buffer whose address is ptr and compares its
// contents with want.
func checkKeptBuffer(t *testing.T, keeps [][]byte, name string, ptr uint64, want []byte) {
	t.Helper()

	if ptr == 0 {
		t.Fatalf("%s pointer is NULL", name)
	}
	for _, buf := range keeps {
		if uint64(addr(buf)) != ptr {
			continue
		}
		if !bytes.Equal(buf, want) {
			t.Fatalf("%s buffer = %x, want %x", name, buf, want)
		}
		return
	}
	t.Fatalf("%s pointer %#x is not a kept buffer", name, ptr)
}
