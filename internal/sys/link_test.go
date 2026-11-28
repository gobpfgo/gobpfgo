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
	attr := &LinkCreateAttr{AttachType: BPF_TRACE_UPROBE_MULTI}
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
	uprobe := func(attr LinkCreateAttr) *LinkCreateAttr {
		attr.AttachType = BPF_TRACE_UPROBE_MULTI
		return &attr
	}
	tests := []struct {
		name string
		attr *LinkCreateAttr
		um   *LinkUprobeMulti
	}{
		{"nil attr", nil, valid()},
		{"nil arrays", uprobe(LinkCreateAttr{}), nil},
		{"zero attach type", &LinkCreateAttr{}, valid()},
		{"cgroup attach type", &LinkCreateAttr{AttachType: BPF_CGROUP_INET_EGRESS}, valid()},
		{"kprobe multi attach type", &LinkCreateAttr{AttachType: BPF_TRACE_KPROBE_MULTI}, valid()},
		{"empty path", uprobe(LinkCreateAttr{}), &LinkUprobeMulti{Offsets: []uint64{0x10}}},
		{"path with NUL", uprobe(LinkCreateAttr{}), &LinkUprobeMulti{Path: "/bin\x00/sh", Offsets: []uint64{0x10}}},
		{"no offsets", uprobe(LinkCreateAttr{}), &LinkUprobeMulti{Path: "/bin/sh"}},
		{"short ref_ctr_offsets", uprobe(LinkCreateAttr{}), &LinkUprobeMulti{Path: "/bin/sh", Offsets: []uint64{0x10, 0x20}, RefCtrOffsets: []uint64{0x30}}},
		{"long cookies", uprobe(LinkCreateAttr{}), &LinkUprobeMulti{Path: "/bin/sh", Offsets: []uint64{0x10}, Cookies: []uint64{1, 2}}},
		{"target btf id set", uprobe(LinkCreateAttr{TargetBTFID: 1}), valid()},
		{"perf event cookie set", uprobe(LinkCreateAttr{PerfEventCookie: 1}), valid()},
		{"tracing cookie set", uprobe(LinkCreateAttr{TracingCookie: 1}), valid()},
		{"kprobe multi set", uprobe(LinkCreateAttr{KprobeMultiCnt: 1}), valid()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := setUprobeMulti(tt.attr, tt.um); !errors.Is(err, unix.EINVAL) {
				t.Fatalf("setUprobeMulti = %v, want EINVAL", err)
			}
		})
	}
}

// TestLinkCreateArraysNeedAttachType checks that LinkCreate with kprobe multi
// arrays and LinkCreateUprobeMulti refuse an attach type that does not select
// the member the arrays belong to, before they fill the arrays. Attach type 0
// is BPF_CGROUP_INET_INGRESS: Marshal would write the cgroup member and drop
// the arrays. The invalid program descriptor makes bpf() fail with EBADF, or
// EPERM without privileges, if the check is missing.
func TestLinkCreateArraysNeedAttachType(t *testing.T) {
	km := &LinkKprobeMulti{Syms: []string{"do_sys_openat2"}, Cookies: []uint64{1}}
	for _, attachType := range []uint32{0, BPF_CGROUP_INET_EGRESS, BPF_PERF_EVENT, BPF_TRACE_FENTRY,
		BPF_TRACE_UPROBE_MULTI, BPF_TRACE_UPROBE_SESSION, linkCreateAttachXDP} {
		attr := &LinkCreateAttr{ProgFD: ^uint32(0), AttachType: attachType}
		if _, err := LinkCreate(attr, km); !errors.Is(err, unix.EINVAL) {
			t.Errorf("LinkCreate kprobe multi with attach type %d = %v, want EINVAL", attachType, err)
		}
		if attr.memberSet(linkMemberKprobeMulti) {
			t.Errorf("attach type %d: kprobe multi fields filled: %+v", attachType, *attr)
		}
	}

	um := &LinkUprobeMulti{Path: "/bin/sh", Offsets: []uint64{0x10}, Cookies: []uint64{1}}
	for _, attachType := range []uint32{0, BPF_CGROUP_INET_EGRESS, BPF_PERF_EVENT, BPF_TRACE_FENTRY,
		BPF_TRACE_KPROBE_MULTI, BPF_TRACE_KPROBE_SESSION, linkCreateAttachXDP} {
		attr := &LinkCreateAttr{ProgFD: ^uint32(0), AttachType: attachType}
		if _, err := LinkCreateUprobeMulti(attr, um); !errors.Is(err, unix.EINVAL) {
			t.Errorf("LinkCreateUprobeMulti with attach type %d = %v, want EINVAL", attachType, err)
		}
		if attr.memberSet(linkMemberUprobeMulti) {
			t.Errorf("attach type %d: uprobe multi fields filled: %+v", attachType, *attr)
		}
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

// TestLinkCreateAttrValidate checks the input rules of validate: the attach
// type, or a nonzero target BTF id, selects one union member, and a field of
// any other member is EINVAL.
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
		{"iterator with tracing cookie", LinkCreateAttr{AttachType: BPF_TRACE_ITER, TracingCookie: 1}, unix.EINVAL},
		{"target btf id", LinkCreateAttr{AttachType: BPF_TRACE_FENTRY, TargetBTFID: 1}, nil},
		{"target btf id with attach type 0", LinkCreateAttr{AttachType: 0, TargetBTFID: 1}, nil},
		{"target btf id and union field", LinkCreateAttr{AttachType: BPF_TRACE_FENTRY, TargetBTFID: 1, TracingCookie: 1}, unix.EINVAL},
		{"target btf id and cgroup field", LinkCreateAttr{AttachType: BPF_CGROUP_INET_INGRESS, TargetBTFID: 1, CgroupRelativeFD: 3}, unix.EINVAL},

		{"cgroup relative fd", LinkCreateAttr{AttachType: BPF_CGROUP_INET_EGRESS, CgroupRelativeFD: 3, CgroupExpectedRevision: 2}, nil},
		{"cgroup relative id", LinkCreateAttr{AttachType: BPF_CGROUP_INET_EGRESS, CgroupRelativeID: 3}, nil},
		{"cgroup relative fd and id", LinkCreateAttr{AttachType: BPF_CGROUP_INET_EGRESS, CgroupRelativeFD: 3, CgroupRelativeID: 4}, unix.EINVAL},
		{"struct_ops revision", LinkCreateAttr{AttachType: BPF_STRUCT_OPS, CgroupExpectedRevision: 1}, nil},
		{"cgroup with perf event cookie", LinkCreateAttr{AttachType: BPF_CGROUP_INET_EGRESS, PerfEventCookie: 1}, unix.EINVAL},
		{"cgroup with kprobe multi count", LinkCreateAttr{AttachType: BPF_CGROUP_INET_EGRESS, KprobeMultiCnt: 1}, unix.EINVAL},
		{"cgroup with kprobe multi symbols", LinkCreateAttr{AttachType: BPF_CGROUP_INET_INGRESS, KprobeMultiSyms: 1}, unix.EINVAL},
		{"cgroup with tracing cookie", LinkCreateAttr{AttachType: BPF_CGROUP_INET_EGRESS, TracingCookie: 1}, unix.EINVAL},
		{"cgroup with uprobe multi path", LinkCreateAttr{AttachType: BPF_CGROUP_INET_INGRESS, UprobeMultiPath: 1}, unix.EINVAL},
		{"cgroup with uprobe multi pid", LinkCreateAttr{AttachType: BPF_CGROUP_SOCK_OPS, UprobeMultiPID: 1}, unix.EINVAL},
		{"cgroup with iterator info", LinkCreateAttr{AttachType: BPF_CGROUP_INET_EGRESS, IterInfo: 1}, unix.EINVAL},
		{"cgroup with iterator info length", LinkCreateAttr{AttachType: BPF_CGROUP_INET_EGRESS, IterInfoLen: 8}, unix.EINVAL},
		{"lsm cgroup with tracing cookie", LinkCreateAttr{AttachType: BPF_LSM_CGROUP, CgroupRelativeFD: 3, TracingCookie: 1}, unix.EINVAL},

		{"tracing cookie", LinkCreateAttr{AttachType: BPF_TRACE_FENTRY, TracingCookie: 1}, nil},
		{"lsm cookie", LinkCreateAttr{AttachType: BPF_LSM_MAC, TracingCookie: 1}, nil},
		{"tracing with cgroup relative fd", LinkCreateAttr{AttachType: BPF_TRACE_FENTRY, CgroupRelativeFD: 1}, unix.EINVAL},
		{"tracing with cgroup revision", LinkCreateAttr{AttachType: BPF_TRACE_FEXIT, TracingCookie: 1, CgroupExpectedRevision: 1}, unix.EINVAL},
		{"tracing with perf event cookie", LinkCreateAttr{AttachType: BPF_TRACE_RAW_TP, PerfEventCookie: 1}, unix.EINVAL},
		{"tracing with kprobe multi count", LinkCreateAttr{AttachType: BPF_MODIFY_RETURN, KprobeMultiCnt: 1}, unix.EINVAL},
		{"tracing with uprobe multi count", LinkCreateAttr{AttachType: BPF_LSM_MAC, UprobeMultiCnt: 1}, unix.EINVAL},

		{"perf event cookie", LinkCreateAttr{AttachType: BPF_PERF_EVENT, TargetFD: 9, PerfEventCookie: 1}, nil},
		{"perf event with tracing cookie", LinkCreateAttr{AttachType: BPF_PERF_EVENT, TracingCookie: 1}, unix.EINVAL},
		{"kprobe session", LinkCreateAttr{AttachType: BPF_TRACE_KPROBE_SESSION, KprobeMultiCnt: 1}, nil},
		{"kprobe multi", LinkCreateAttr{AttachType: BPF_TRACE_KPROBE_MULTI, KprobeMultiFlags: 1, KprobeMultiCnt: 2,
			KprobeMultiSyms: 1, KprobeMultiCookies: 2}, nil},
		{"kprobe multi with uprobe multi path", LinkCreateAttr{AttachType: BPF_TRACE_KPROBE_MULTI, KprobeMultiCnt: 1, UprobeMultiPath: 1}, unix.EINVAL},
		{"uprobe session", LinkCreateAttr{AttachType: BPF_TRACE_UPROBE_SESSION, UprobeMultiPath: 1, UprobeMultiOffsets: 2,
			UprobeMultiCnt: 1, UprobeMultiPID: 3}, nil},
		{"uprobe multi with kprobe multi count", LinkCreateAttr{AttachType: BPF_TRACE_UPROBE_MULTI, UprobeMultiCnt: 1, KprobeMultiCnt: 1}, unix.EINVAL},
		{"uprobe multi with cgroup revision", LinkCreateAttr{AttachType: BPF_TRACE_UPROBE_MULTI, UprobeMultiCnt: 1, CgroupExpectedRevision: 1}, unix.EINVAL},

		{"xdp", LinkCreateAttr{AttachType: linkCreateAttachXDP, TargetFD: 1, Flags: 2}, nil},
		{"xdp with cgroup revision", LinkCreateAttr{AttachType: linkCreateAttachXDP, CgroupExpectedRevision: 1}, unix.EINVAL},
		{"xdp with iterator info", LinkCreateAttr{AttachType: linkCreateAttachXDP, IterInfo: 1}, unix.EINVAL},
		{"sk_msg with relative fd", LinkCreateAttr{AttachType: linkCreateAttachSkMsgVerdict, CgroupRelativeFD: 1}, unix.EINVAL},
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
// the invalid descriptors or EPERM without privileges. The uprobe multi
// fields on attach type 0 are the arrays Marshal would drop for the cgroup
// member.
func TestLinkCreateRejectsBeforeSyscall(t *testing.T) {
	tests := map[string]*LinkCreateAttr{
		"nil attr":                             nil,
		"cgroup relative fd and id":            {AttachType: BPF_CGROUP_INET_INGRESS, CgroupRelativeFD: 3, CgroupRelativeID: 4},
		"cgroup with tracing cookie":           {AttachType: BPF_CGROUP_INET_INGRESS, TracingCookie: 1},
		"uprobe multi fields on attach type 0": {UprobeMultiPath: 1, UprobeMultiOffsets: 2, UprobeMultiCnt: 1},
	}
	for name, attr := range tests {
		t.Run(name, func(t *testing.T) {
			if attr != nil {
				attr.ProgFD, attr.TargetFD = ^uint32(0), ^uint32(0)
			}
			if _, err := LinkCreate(attr, nil); !errors.Is(err, unix.EINVAL) {
				t.Fatalf("LinkCreate = %v, want EINVAL", err)
			}
		})
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
