// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// fakeLoadedFD is a program descriptor no process has open. A test that
// expects an attach to fail before bpf() uses it, so a call that reached the
// kernel would fail with EBADF, or EPERM without privileges, not EINVAL.
const fakeLoadedFD = 1 << 30

func TestSecDefAttachFD(t *testing.T) {
	tests := []struct {
		section    string
		progType   BpfProgType
		attachType BpfAttachType
	}{
		{"cgroup_skb/ingress", BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_INGRESS},
		{"cgroup_skb/egress", BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_EGRESS},
		{"cgroup/skb", BPF_PROG_TYPE_CGROUP_SKB, BPF_ATTACH_TYPE_UNSPEC},
		{"flow_dissector", BPF_PROG_TYPE_FLOW_DISSECTOR, BPF_FLOW_DISSECTOR},
		{"sk_msg", BPF_PROG_TYPE_SK_MSG, BPF_SK_MSG_VERDICT},
		{"xdp", BPF_PROG_TYPE_XDP, BPF_XDP},
		{"kprobe.session/do_sys_openat2", BPF_PROG_TYPE_KPROBE, BPF_TRACE_KPROBE_SESSION},
		{"kprobe.session", BPF_PROG_TYPE_KPROBE, BPF_TRACE_KPROBE_SESSION},
		{"kprobe.multi/do_sys_openat2", BPF_PROG_TYPE_KPROBE, BPF_TRACE_KPROBE_MULTI},
		{"kprobe/do_sys_openat2", BPF_PROG_TYPE_KPROBE, BPF_ATTACH_TYPE_UNSPEC},
	}
	for _, tt := range tests {
		t.Run(tt.section, func(t *testing.T) {
			def, ok := secDefFor(tt.section)
			if !ok {
				t.Fatalf("secDefFor(%q) found no definition", tt.section)
			}
			if def.progType != tt.progType || def.attachType != tt.attachType || def.progFlags != 0 {
				t.Fatalf("secDefFor(%q) = %+v, want type %v attach %v and no flags",
					tt.section, def, tt.progType, tt.attachType)
			}
		})
	}
}

// TestOpenAttachFDObjects opens each fixture of the slice and checks that its
// programs take the type and expected attach type of their section.
func TestOpenAttachFDObjects(t *testing.T) {
	type progWant struct {
		name       string
		progType   BpfProgType
		attachType BpfAttachType
	}
	tests := []struct {
		object string
		progs  []progWant
	}{
		{"cgroup.bpf.o", []progWant{
			{"cgroup_ingress", BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_INGRESS},
			{"cgroup_egress", BPF_PROG_TYPE_CGROUP_SKB, BPF_CGROUP_INET_EGRESS},
			{"cgroup_skb", BPF_PROG_TYPE_CGROUP_SKB, BPF_ATTACH_TYPE_UNSPEC},
		}},
		{"netns.bpf.o", []progWant{{"dissect", BPF_PROG_TYPE_FLOW_DISSECTOR, BPF_FLOW_DISSECTOR}}},
		{"xdp.bpf.o", []progWant{{"xdp_pass", BPF_PROG_TYPE_XDP, BPF_XDP}}},
		{"sockmap.bpf.o", []progWant{{"msg_pass", BPF_PROG_TYPE_SK_MSG, BPF_SK_MSG_VERDICT}}},
		{"kprobe_session.bpf.o", []progWant{{"handle_session", BPF_PROG_TYPE_KPROBE, BPF_TRACE_KPROBE_SESSION}}},
	}
	for _, tt := range tests {
		t.Run(tt.object, func(t *testing.T) {
			obj, err := BpfObjectOpenFile(progsDir+"/"+tt.object, nil)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer BpfObjectClose(obj)

			for _, want := range tt.progs {
				prog := BpfObjectFindProgramByName(obj, want.name)
				if prog == nil {
					t.Fatalf("program %s not found", want.name)
				}
				if got := BpfProgramTypeOf(prog); got != want.progType {
					t.Errorf("%s type = %v, want %v", want.name, got, want.progType)
				}
				if got := BpfProgramExpectedAttachType(prog); got != want.attachType {
					t.Errorf("%s expected attach type = %v, want %v", want.name, got, want.attachType)
				}
			}
		})
	}
}

// attachFDCall is one public attach function of the slice, called with
// arguments that are valid apart from the program.
type attachFDCall struct {
	op     string
	attach func(*BpfProgram) (*BpfLink, error)
}

func attachFDCalls() []attachFDCall {
	return []attachFDCall{
		{"bpf_program__attach_cgroup", func(p *BpfProgram) (*BpfLink, error) { return BpfProgramAttachCgroup(p, 0) }},
		{"bpf_program__attach_cgroup_opts", func(p *BpfProgram) (*BpfLink, error) {
			return BpfProgramAttachCgroupOpts(p, 0, &BpfCgroupOpts{RelativeFD: 3})
		}},
		{"bpf_program__attach_netns", func(p *BpfProgram) (*BpfLink, error) { return BpfProgramAttachNetns(p, 0) }},
		{"bpf_program__attach_xdp", func(p *BpfProgram) (*BpfLink, error) { return BpfProgramAttachXDP(p, 1) }},
		{"bpf_program__attach_sockmap", func(p *BpfProgram) (*BpfLink, error) { return BpfProgramAttachSockmap(p, 0) }},
	}
}

// TestBpfProgramAttachFDUnloaded checks that each attach rejects a nil or
// unloaded program with EINVAL and its own operation name.
func TestBpfProgramAttachFDUnloaded(t *testing.T) {
	for _, c := range attachFDCalls() {
		for name, prog := range map[string]*BpfProgram{"nil": nil, "unloaded": {fd: -1}} {
			t.Run(c.op+"/"+name, func(t *testing.T) {
				link, err := c.attach(prog)
				checkAttachError(t, link, err, c.op, unix.EINVAL)
			})
		}
	}
}

// TestBpfProgramAttachCgroupOptsRelative checks that setting both relative
// fields fails with EINVAL before the link is created.
func TestBpfProgramAttachCgroupOptsRelative(t *testing.T) {
	prog := &BpfProgram{fd: fakeLoadedFD, expectedAttachType: BPF_CGROUP_INET_INGRESS}
	link, err := BpfProgramAttachCgroupOpts(prog, 0, &BpfCgroupOpts{RelativeFD: 3, RelativeID: 4})
	checkAttachError(t, link, err, "bpf_program__attach_cgroup_opts", unix.EINVAL)
}

// TestBpfProgramAttachCgroupOptsWrongType checks that cgroup placement on a
// program whose expected attach type is not a cgroup hook fails with EINVAL
// before the link is created, while plain flags are passed to the kernel.
func TestBpfProgramAttachCgroupOptsWrongType(t *testing.T) {
	prog := &BpfProgram{fd: fakeLoadedFD, expectedAttachType: BPF_XDP}
	for name, opts := range map[string]*BpfCgroupOpts{
		"relative fd": {RelativeFD: 3},
		"relative id": {RelativeID: 3},
		"revision":    {ExpectedRevision: 1},
	} {
		t.Run(name, func(t *testing.T) {
			link, err := BpfProgramAttachCgroupOpts(prog, 0, opts)
			checkAttachError(t, link, err, "bpf_program__attach_cgroup_opts", unix.EINVAL)
		})
	}

	link, err := BpfProgramAttachCgroupOpts(prog, 0, &BpfCgroupOpts{Flags: BPF_F_BEFORE})
	if link != nil || errors.Is(err, unix.EINVAL) {
		t.Fatalf("flags only = %v, %v; want a kernel error other than EINVAL", link, err)
	}
}

// TestAttachFDAttr checks the link attribute each attach builds: the
// program's descriptor and expected attach type, the target descriptor or
// interface index, and for cgroup options the flags and cgroup fields. The
// byte layout of these fields is tested in internal/sys.
func TestAttachFDAttr(t *testing.T) {
	tests := []struct {
		name       string
		attachType BpfAttachType
		target     int
		opts       *BpfCgroupOpts
		want       sys.LinkCreateAttr
	}{
		{name: "cgroup", attachType: BPF_CGROUP_INET_EGRESS, target: 9,
			want: sys.LinkCreateAttr{ProgFD: 5, TargetFD: 9, AttachType: sys.BPF_CGROUP_INET_EGRESS}},
		{name: "cgroup relative fd", attachType: BPF_CGROUP_INET_INGRESS, target: 9,
			opts: &BpfCgroupOpts{Flags: BPF_F_BEFORE | BPF_F_LINK, RelativeFD: 11, ExpectedRevision: 7},
			want: sys.LinkCreateAttr{ProgFD: 5, TargetFD: 9, AttachType: sys.BPF_CGROUP_INET_INGRESS,
				Flags: BPF_F_BEFORE | BPF_F_LINK, CgroupRelativeFD: 11, CgroupExpectedRevision: 7}},
		{name: "cgroup relative id", attachType: BPF_CGROUP_INET_INGRESS, target: 9,
			opts: &BpfCgroupOpts{Flags: BPF_F_AFTER, RelativeID: 42},
			want: sys.LinkCreateAttr{ProgFD: 5, TargetFD: 9, AttachType: sys.BPF_CGROUP_INET_INGRESS,
				Flags: BPF_F_AFTER, CgroupRelativeID: 42}},
		{name: "netns", attachType: BPF_FLOW_DISSECTOR, target: 4,
			want: sys.LinkCreateAttr{ProgFD: 5, TargetFD: 4, AttachType: uint32(BPF_FLOW_DISSECTOR)}},
		{name: "xdp", attachType: BPF_XDP, target: 1,
			want: sys.LinkCreateAttr{ProgFD: 5, TargetFD: 1, AttachType: uint32(BPF_XDP)}},
		{name: "sockmap", attachType: BPF_SK_MSG_VERDICT, target: 6,
			want: sys.LinkCreateAttr{ProgFD: 5, TargetFD: 6, AttachType: uint32(BPF_SK_MSG_VERDICT)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prog := &BpfProgram{fd: 5, expectedAttachType: tt.attachType}
			opts, err := cgroupOptsAttr(tt.opts)
			if err != nil {
				t.Fatalf("cgroupOptsAttr: %v", err)
			}
			var before sys.LinkCreateAttr
			if opts != nil {
				before = *opts
			}

			if got := attachFDAttr(prog, tt.target, opts); *got != tt.want {
				t.Fatalf("attribute = %+v, want %+v", *got, tt.want)
			}
			if opts != nil && *opts != before {
				t.Fatalf("attachFDAttr modified its input: %+v, was %+v", *opts, before)
			}
		})
	}
}

// TestKprobeMultiLink checks the attach type and return flag of a kprobe
// multi link and the option errors, including Retprobe with Session.
func TestKprobeMultiLink(t *testing.T) {
	syms := []string{"do_sys_openat2"}
	tests := []struct {
		name       string
		opts       *BpfKprobeMultiOpts
		attachType uint32
		flags      uint32
		err        error
	}{
		{"multi", &BpfKprobeMultiOpts{Symbols: syms}, sys.BPF_TRACE_KPROBE_MULTI, 0, nil},
		{"retprobe", &BpfKprobeMultiOpts{Symbols: syms, Retprobe: true}, sys.BPF_TRACE_KPROBE_MULTI, BPF_F_KPROBE_MULTI_RETURN, nil},
		{"session", &BpfKprobeMultiOpts{Addrs: []uint64{0xffff}, Session: true}, sys.BPF_TRACE_KPROBE_SESSION, 0, nil},
		{"retprobe and session", &BpfKprobeMultiOpts{Symbols: syms, Retprobe: true, Session: true}, 0, 0, unix.EINVAL},
		{"nil options", nil, 0, 0, unix.EINVAL},
		{"no locations", &BpfKprobeMultiOpts{Session: true}, 0, 0, unix.EINVAL},
		{"symbols and addresses", &BpfKprobeMultiOpts{Symbols: syms, Addrs: []uint64{1}}, 0, 0, unix.EINVAL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr, km, err := kprobeMultiLink(&BpfProgram{fd: 5}, tt.opts)
			if !errors.Is(err, tt.err) {
				t.Fatalf("kprobeMultiLink error = %v, want %v", err, tt.err)
			}
			if err != nil {
				return
			}
			want := sys.LinkCreateAttr{ProgFD: 5, AttachType: tt.attachType}
			if *attr != want || km.Flags != tt.flags {
				t.Fatalf("attribute %+v and flags %#x, want %+v and %#x", *attr, km.Flags, want, tt.flags)
			}
			if len(km.Syms) != len(tt.opts.Symbols) || len(km.Addrs) != len(tt.opts.Addrs) {
				t.Fatalf("arrays %v/%v, want %v/%v", km.Syms, km.Addrs, tt.opts.Symbols, tt.opts.Addrs)
			}
		})
	}
}

// TestBpfProgramAttachKprobeMultiSessionRetprobe checks that the public call
// rejects Retprobe with Session before the link is created.
func TestBpfProgramAttachKprobeMultiSessionRetprobe(t *testing.T) {
	prog := &BpfProgram{fd: fakeLoadedFD, expectedAttachType: BPF_TRACE_KPROBE_SESSION}
	link, err := BpfProgramAttachKprobeMulti(prog, &BpfKprobeMultiOpts{
		Symbols:  []string{"do_sys_openat2"},
		Retprobe: true,
		Session:  true,
	})
	checkAttachError(t, link, err, "bpf_program__attach_kprobe_multi", unix.EINVAL)
}

// TestBpfProgramAttachBareKprobeSession checks that the automatic attach of
// the bare kprobe.session section, which names no function, returns
// EOPNOTSUPP and no link before bpf(), as libbpf's bpf_program__attach does
// when attach_kprobe_session returns no link.
func TestBpfProgramAttachBareKprobeSession(t *testing.T) {
	prog := &BpfProgram{fd: fakeLoadedFD, sectionName: "kprobe.session", expectedAttachType: BPF_TRACE_KPROBE_SESSION}
	link, err := BpfProgramAttach(prog)
	checkAttachError(t, link, err, "bpf_program__attach", unix.EOPNOTSUPP)
}

// TestAttachTypeValuesMatchKernel compares the attach type values of this
// package and of internal/sys with the running kernel's enum bpf_attach_type.
// A name the kernel does not know is skipped; the test skips when the kernel
// BTF cannot be read.
func TestAttachTypeValuesMatchKernel(t *testing.T) {
	values := kernelEnumValues(t, "bpf_attach_type")

	for name, want := range attachTypeValues() {
		got, ok := values[name]
		if !ok {
			continue
		}
		if uint32(got) != want {
			t.Errorf("%s = %d, kernel has %d", name, want, got)
		}
	}
}

// attachTypeValues returns every attach type constant of this package and of
// internal/sys, by enum name. Where both define a name, the values must
// agree.
func attachTypeValues() map[string]uint32 {
	return map[string]uint32{
		"BPF_CGROUP_INET_INGRESS":      uint32(BPF_CGROUP_INET_INGRESS),
		"BPF_CGROUP_INET_EGRESS":       uint32(BPF_CGROUP_INET_EGRESS),
		"BPF_CGROUP_INET_SOCK_CREATE":  sys.BPF_CGROUP_INET_SOCK_CREATE,
		"BPF_CGROUP_SOCK_OPS":          sys.BPF_CGROUP_SOCK_OPS,
		"BPF_CGROUP_DEVICE":            sys.BPF_CGROUP_DEVICE,
		"BPF_SK_MSG_VERDICT":           uint32(BPF_SK_MSG_VERDICT),
		"BPF_CGROUP_INET4_BIND":        sys.BPF_CGROUP_INET4_BIND,
		"BPF_CGROUP_INET6_BIND":        sys.BPF_CGROUP_INET6_BIND,
		"BPF_CGROUP_INET4_CONNECT":     uint32(BPF_CGROUP_INET4_CONNECT),
		"BPF_CGROUP_INET6_CONNECT":     sys.BPF_CGROUP_INET6_CONNECT,
		"BPF_CGROUP_INET4_POST_BIND":   sys.BPF_CGROUP_INET4_POST_BIND,
		"BPF_CGROUP_INET6_POST_BIND":   sys.BPF_CGROUP_INET6_POST_BIND,
		"BPF_CGROUP_UDP4_SENDMSG":      sys.BPF_CGROUP_UDP4_SENDMSG,
		"BPF_CGROUP_UDP6_SENDMSG":      sys.BPF_CGROUP_UDP6_SENDMSG,
		"BPF_LIRC_MODE2":               uint32(BPF_LIRC_MODE2),
		"BPF_FLOW_DISSECTOR":           uint32(BPF_FLOW_DISSECTOR),
		"BPF_CGROUP_SYSCTL":            sys.BPF_CGROUP_SYSCTL,
		"BPF_CGROUP_UDP4_RECVMSG":      sys.BPF_CGROUP_UDP4_RECVMSG,
		"BPF_CGROUP_UDP6_RECVMSG":      sys.BPF_CGROUP_UDP6_RECVMSG,
		"BPF_CGROUP_GETSOCKOPT":        uint32(BPF_CGROUP_GETSOCKOPT),
		"BPF_CGROUP_SETSOCKOPT":        sys.BPF_CGROUP_SETSOCKOPT,
		"BPF_TRACE_RAW_TP":             uint32(BPF_TRACE_RAW_TP),
		"BPF_TRACE_FENTRY":             uint32(BPF_TRACE_FENTRY),
		"BPF_TRACE_FEXIT":              uint32(BPF_TRACE_FEXIT),
		"BPF_MODIFY_RETURN":            uint32(BPF_MODIFY_RETURN),
		"BPF_LSM_MAC":                  uint32(BPF_LSM_MAC),
		"BPF_TRACE_ITER":               uint32(BPF_TRACE_ITER),
		"BPF_CGROUP_INET4_GETPEERNAME": sys.BPF_CGROUP_INET4_GETPEERNAME,
		"BPF_CGROUP_INET6_GETPEERNAME": sys.BPF_CGROUP_INET6_GETPEERNAME,
		"BPF_CGROUP_INET4_GETSOCKNAME": sys.BPF_CGROUP_INET4_GETSOCKNAME,
		"BPF_CGROUP_INET6_GETSOCKNAME": sys.BPF_CGROUP_INET6_GETSOCKNAME,
		"BPF_CGROUP_INET_SOCK_RELEASE": sys.BPF_CGROUP_INET_SOCK_RELEASE,
		"BPF_SK_LOOKUP":                uint32(BPF_SK_LOOKUP),
		"BPF_XDP":                      uint32(BPF_XDP),
		"BPF_PERF_EVENT":               uint32(BPF_PERF_EVENT),
		"BPF_TRACE_KPROBE_MULTI":       uint32(BPF_TRACE_KPROBE_MULTI),
		"BPF_LSM_CGROUP":               sys.BPF_LSM_CGROUP,
		"BPF_STRUCT_OPS":               sys.BPF_STRUCT_OPS,
		"BPF_NETFILTER":                uint32(BPF_NETFILTER),
		"BPF_TRACE_UPROBE_MULTI":       uint32(BPF_TRACE_UPROBE_MULTI),
		"BPF_CGROUP_UNIX_CONNECT":      sys.BPF_CGROUP_UNIX_CONNECT,
		"BPF_CGROUP_UNIX_SENDMSG":      sys.BPF_CGROUP_UNIX_SENDMSG,
		"BPF_CGROUP_UNIX_RECVMSG":      sys.BPF_CGROUP_UNIX_RECVMSG,
		"BPF_CGROUP_UNIX_GETPEERNAME":  sys.BPF_CGROUP_UNIX_GETPEERNAME,
		"BPF_CGROUP_UNIX_GETSOCKNAME":  sys.BPF_CGROUP_UNIX_GETSOCKNAME,
		"BPF_TRACE_KPROBE_SESSION":     uint32(BPF_TRACE_KPROBE_SESSION),
		"BPF_TRACE_UPROBE_SESSION":     uint32(BPF_TRACE_UPROBE_SESSION),
		"BPF_TRACE_FSESSION":           sys.BPF_TRACE_FSESSION,
	}
}

// TestAttachTypeValuesAgree checks the attach types both this package and
// internal/sys define.
func TestAttachTypeValuesAgree(t *testing.T) {
	pairs := []struct {
		name string
		core BpfAttachType
		sys  uint32
	}{
		{"BPF_CGROUP_INET_INGRESS", BPF_CGROUP_INET_INGRESS, sys.BPF_CGROUP_INET_INGRESS},
		{"BPF_CGROUP_INET_EGRESS", BPF_CGROUP_INET_EGRESS, sys.BPF_CGROUP_INET_EGRESS},
		{"BPF_CGROUP_INET4_CONNECT", BPF_CGROUP_INET4_CONNECT, sys.BPF_CGROUP_INET4_CONNECT},
		{"BPF_CGROUP_GETSOCKOPT", BPF_CGROUP_GETSOCKOPT, sys.BPF_CGROUP_GETSOCKOPT},
		{"BPF_TRACE_RAW_TP", BPF_TRACE_RAW_TP, sys.BPF_TRACE_RAW_TP},
		{"BPF_TRACE_FENTRY", BPF_TRACE_FENTRY, sys.BPF_TRACE_FENTRY},
		{"BPF_TRACE_FEXIT", BPF_TRACE_FEXIT, sys.BPF_TRACE_FEXIT},
		{"BPF_MODIFY_RETURN", BPF_MODIFY_RETURN, sys.BPF_MODIFY_RETURN},
		{"BPF_LSM_MAC", BPF_LSM_MAC, sys.BPF_LSM_MAC},
		{"BPF_TRACE_ITER", BPF_TRACE_ITER, sys.BPF_TRACE_ITER},
		{"BPF_PERF_EVENT", BPF_PERF_EVENT, sys.BPF_PERF_EVENT},
		{"BPF_TRACE_KPROBE_MULTI", BPF_TRACE_KPROBE_MULTI, sys.BPF_TRACE_KPROBE_MULTI},
		{"BPF_TRACE_UPROBE_MULTI", BPF_TRACE_UPROBE_MULTI, sys.BPF_TRACE_UPROBE_MULTI},
		{"BPF_TRACE_KPROBE_SESSION", BPF_TRACE_KPROBE_SESSION, sys.BPF_TRACE_KPROBE_SESSION},
		{"BPF_TRACE_UPROBE_SESSION", BPF_TRACE_UPROBE_SESSION, sys.BPF_TRACE_UPROBE_SESSION},
	}
	for _, p := range pairs {
		if uint32(p.core) != p.sys {
			t.Errorf("%s: libbpf %d, internal/sys %d", p.name, p.core, p.sys)
		}
	}
	if BPF_F_ID != sys.BPF_F_ID {
		t.Errorf("BPF_F_ID: libbpf %#x, internal/sys %#x", BPF_F_ID, sys.BPF_F_ID)
	}
}

// checkAttachError requires a failed attach: no link and an *Error with op
// and errno.
func checkAttachError(t *testing.T, link *BpfLink, err error, op string, errno unix.Errno) {
	t.Helper()

	if link != nil {
		BpfLinkDestroy(link)
		t.Fatalf("attach returned a link, want %v", errno)
	}
	var e *Error
	if !errors.As(err, &e) || e.Op != op || e.Errno != errno {
		t.Fatalf("attach error = %#v, want op %s and %v", err, op, errno)
	}
}

// kernelEnumValues returns the values of the running kernel's BTF enum name
// by value name, and skips the test when the kernel BTF cannot be read.
func kernelEnumValues(t *testing.T, name string) map[string]int32 {
	t.Helper()

	kernel, err := vmlinuxBTF()
	if err != nil {
		t.Skipf("kernel BTF: %v", err)
	}
	enum := kernel.Find(name, btf.KindEnum)
	if enum == nil {
		t.Fatalf("kernel BTF has no enum %s", name)
	}
	values := make(map[string]int32, len(enum.Enums))
	for _, e := range enum.Enums {
		values[e.Name] = e.Value
	}
	return values
}
