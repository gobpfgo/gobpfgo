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

// TestSecDefIterFreplace checks the iterator and freplace section
// definitions: an iterator is a tracing program with BPF_TRACE_ITER whose
// target is a kernel BTF function, iter.s is its sleepable form, and a
// freplace program is BPF_PROG_TYPE_EXT with attach type 0 whose target is a
// function of another BPF program.
func TestSecDefIterFreplace(t *testing.T) {
	tests := []struct {
		section    string
		progType   BpfProgType
		attachType BpfAttachType
		progFlags  uint32
		flags      secFlags
	}{
		{"iter/bpf_map", BPF_PROG_TYPE_TRACING, BPF_TRACE_ITER, 0, secAttachBTF},
		{"iter.s/bpf_map", BPF_PROG_TYPE_TRACING, BPF_TRACE_ITER, BPF_F_SLEEPABLE, secAttachBTF},
		{"freplace/xdp_pass", BPF_PROG_TYPE_EXT, BPF_ATTACH_TYPE_UNSPEC, 0, secAttachProg},
	}
	for _, tt := range tests {
		t.Run(tt.section, func(t *testing.T) {
			def, ok := secDefFor(tt.section)
			if !ok {
				t.Fatalf("secDefFor(%q) found no definition", tt.section)
			}
			if def.progType != tt.progType || def.attachType != tt.attachType || def.progFlags != tt.progFlags || def.flags != tt.flags {
				t.Fatalf("secDefFor(%q) = %+v, want type %v attach %v prog flags %#x flags %#x",
					tt.section, def, tt.progType, tt.attachType, tt.progFlags, tt.flags)
			}
		})
	}
}

// TestOpenIterFreplaceObjects opens iter.bpf.o and freplace.bpf.o and
// checks that their programs take the type, attach type and attach target of
// their section: the iterator's target is resolved in the kernel BTF, the
// freplace program's in the BTF of a program.
func TestOpenIterFreplaceObjects(t *testing.T) {
	tests := []struct {
		object, name string
		progType     BpfProgType
		attachType   BpfAttachType
		attachBTF    bool
		attachProg   bool
		target       string
	}{
		{"iter.bpf.o", "dump_bpf_map", BPF_PROG_TYPE_TRACING, BPF_TRACE_ITER, true, false, "bpf_map"},
		{"freplace.bpf.o", "replace_xdp", BPF_PROG_TYPE_EXT, BPF_ATTACH_TYPE_UNSPEC, false, true, "xdp_pass"},
	}
	for _, tt := range tests {
		t.Run(tt.object, func(t *testing.T) {
			obj := openProg(t, tt.object)
			prog := BpfObjectFindProgramByName(obj, tt.name)
			if prog == nil {
				t.Fatalf("program %s not found", tt.name)
			}
			if prog.progType != tt.progType || prog.expectedAttachType != tt.attachType {
				t.Errorf("type %v attach %v, want %v and %v", prog.progType, prog.expectedAttachType, tt.progType, tt.attachType)
			}
			if prog.attachBTF != tt.attachBTF || prog.attachProg != tt.attachProg || prog.attachTarget != tt.target {
				t.Errorf("attach BTF %v, program %v, target %q; want %v, %v, %q",
					prog.attachBTF, prog.attachProg, prog.attachTarget, tt.attachBTF, tt.attachProg, tt.target)
			}
			if prog.attachBTFID != 0 || prog.attachProgFD != 0 {
				t.Errorf("attach BTF id %d and program fd %d after open, want 0", prog.attachBTFID, prog.attachProgFD)
			}
		})
	}
}

// TestAttachBTFPrefix checks the kernel BTF name and kind of each attach
// target, as libbpf's btf_get_kernel_prefix_kind gives them: an iterator
// target is the FUNC bpf_iter_<target>, the kind the kernel's iterator
// registration and its verifier require.
func TestAttachBTFPrefix(t *testing.T) {
	tests := []struct {
		attachType BpfAttachType
		target     string
		name       string
		kind       btf.Kind
	}{
		{BPF_TRACE_RAW_TP, "sys_enter", "btf_trace_sys_enter", btf.KindTypedef},
		{BPF_LSM_MAC, "file_open", "bpf_lsm_file_open", btf.KindFunc},
		{BPF_TRACE_ITER, "bpf_map", "bpf_iter_bpf_map", btf.KindFunc},
		{BPF_TRACE_FENTRY, "do_sys_openat2", "do_sys_openat2", btf.KindFunc},
		{BPF_TRACE_FEXIT, "do_sys_openat2", "do_sys_openat2", btf.KindFunc},
		{BPF_MODIFY_RETURN, "do_sys_openat2", "do_sys_openat2", btf.KindFunc},
	}
	for _, tt := range tests {
		name, kind := attachBTFPrefix(tt.attachType, tt.target)
		if name != tt.name || kind != tt.kind {
			t.Errorf("attachBTFPrefix(%v, %q) = %q %v, want %q %v", tt.attachType, tt.target, name, kind, tt.name, tt.kind)
		}
	}
}

// TestResolveAttachBTFIDIter resolves the iter/bpf_map target to the kernel's
// bpf_iter_bpf_map FUNC. It skips when the kernel BTF cannot be read and
// when it has no bpf_map iterator.
func TestResolveAttachBTFIDIter(t *testing.T) {
	kernel, err := vmlinuxBTF()
	if err != nil {
		t.Skipf("kernel BTF: %v", err)
	}
	fn := kernel.Find("bpf_iter_bpf_map", btf.KindFunc)
	if fn == nil {
		t.Skip("kernel BTF has no bpf_iter_bpf_map")
	}

	prog := openIterProgram(t)
	if err := resolveAttachBTFID(prog); err != nil {
		t.Fatalf("resolveAttachBTFID: %v", err)
	}
	if prog.attachBTFID != fn.ID || prog.attachBTFObjFD != 0 || prog.attachProgFD != 0 {
		t.Fatalf("attach BTF id %d, object fd %d, program fd %d; want %d, 0, 0",
			prog.attachBTFID, prog.attachBTFObjFD, prog.attachProgFD, fn.ID)
	}
}

// TestResolveAttachBTFIDFreplaceNoTarget checks that a freplace program
// without an attach program descriptor fails the load with EINVAL before
// any lookup, as libbpf_find_attach_btf_id does, and that an id set before
// the load is kept.
func TestResolveAttachBTFIDFreplaceNoTarget(t *testing.T) {
	prog := openFreplaceProgram(t)
	err := resolveAttachBTFID(prog)
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("resolveAttachBTFID without a target = %v, want EINVAL", err)
	}
	if prog.attachBTFID != 0 {
		t.Fatalf("attach BTF id = %d after a failed resolve, want 0", prog.attachBTFID)
	}

	prog.attachBTFID = 42
	if err := resolveAttachBTFID(prog); err != nil || prog.attachBTFID != 42 {
		t.Fatalf("resolveAttachBTFID with id 42 set = %v, id %d; want nil and 42", err, prog.attachBTFID)
	}
}

// TestResolveAttachBTFIDFreplaceBadTarget checks that a freplace program
// whose attach program descriptor is not open fails with the kernel's errno
// from the program info, EBADFD, or EPERM where unprivileged bpf() is
// refused, not EINVAL.
func TestResolveAttachBTFIDFreplaceBadTarget(t *testing.T) {
	prog := openFreplaceProgram(t)
	prog.attachProgFD = fakeLoadedFD
	err := resolveAttachBTFID(prog)
	if !errors.Is(err, unix.EBADFD) && !errors.Is(err, unix.EPERM) {
		t.Fatalf("resolveAttachBTFID with a closed target = %v, want EBADFD or EPERM", err)
	}
}

// TestProgLoadAttrAttachProgFD checks that the load passes the attach
// program descriptor and BTF id of a freplace program, and no BTF object
// descriptor.
func TestProgLoadAttrAttachProgFD(t *testing.T) {
	p := &BpfProgram{name: "replace_xdp", progType: BPF_PROG_TYPE_EXT, attachBTFID: 7, attachProgFD: 9}
	attr := progLoadAttr(&BpfObject{btfFD: 3}, &progCode{prog: p, insns: make([]byte, 2*bpfInsnLength)})
	if attr.ProgType != uint32(BPF_PROG_TYPE_EXT) || attr.ExpectedAttachType != 0 || attr.AttachBtfID != 7 ||
		attr.AttachProgFD != 9 || attr.AttachBtfObjFD != 0 {
		t.Fatalf("attr = %+v, want type EXT, attach type 0, BTF id 7, program fd 9 and no object fd", *attr)
	}
}

// TestBpfProgramSetAttachTarget checks the input rules and the stored state
// of BpfProgramSetAttachTarget that need no kernel: a nil program, a
// negative descriptor, neither argument, and a loaded or closed object are
// EINVAL; a descriptor alone is kept for the load; a descriptor that is not
// open fails the lookup with the kernel's errno, EBADFD, or EPERM where
// unprivileged bpf() is refused, and changes nothing.
func TestBpfProgramSetAttachTarget(t *testing.T) {
	const op = "bpf_program__set_attach_target"

	refused := map[string]struct {
		prog *BpfProgram
		fd   int
		name string
	}{
		"nil program":         {nil, 3, "xdp_pass"},
		"negative descriptor": {&BpfProgram{}, -1, "xdp_pass"},
		"neither":             {&BpfProgram{}, 0, ""},
		"loaded object":       {&BpfProgram{obj: &BpfObject{loaded: true}}, 3, ""},
		"closed object":       {&BpfProgram{obj: &BpfObject{closed: true}}, 3, ""},
	}
	for name, c := range refused {
		t.Run(name, func(t *testing.T) {
			checkSetAttachTargetError(t, BpfProgramSetAttachTarget(c.prog, c.fd, c.name), op, unix.EINVAL)
		})
	}

	t.Run("descriptor only", func(t *testing.T) {
		prog := openFreplaceProgram(t)
		if err := BpfProgramSetAttachTarget(prog, fakeLoadedFD, ""); err != nil {
			t.Fatalf("set attach target: %v", err)
		}
		if prog.attachProgFD != fakeLoadedFD || prog.attachBTFID != 0 {
			t.Fatalf("program fd %d, BTF id %d; want %d and 0", prog.attachProgFD, prog.attachBTFID, fakeLoadedFD)
		}
	})

	t.Run("closed descriptor and function", func(t *testing.T) {
		prog := openFreplaceProgram(t)
		err := BpfProgramSetAttachTarget(prog, fakeLoadedFD, "xdp_pass")
		var e *Error
		if !errors.As(err, &e) || e.Op != op || e.Errno != unix.EBADFD && e.Errno != unix.EPERM {
			t.Fatalf("set attach target = %#v, want op %s and EBADFD or EPERM", err, op)
		}
		if prog.attachProgFD != 0 || prog.attachBTFID != 0 {
			t.Fatalf("program fd %d, BTF id %d after a failed lookup, want 0 and 0", prog.attachProgFD, prog.attachBTFID)
		}
	})
}

// TestBpfProgramSetAttachTargetKernel sets the target of iter/bpf_map to a
// kernel function by name, which looks up bpf_iter_<name> in the vmlinux
// BTF with the iterator prefix: bpf_map resolves and a missing iterator is
// ENOENT. It skips when the kernel BTF cannot be read and when it has no
// bpf_map iterator.
func TestBpfProgramSetAttachTargetKernel(t *testing.T) {
	kernel, err := vmlinuxBTF()
	if err != nil {
		t.Skipf("kernel BTF: %v", err)
	}
	fn := kernel.Find("bpf_iter_bpf_map", btf.KindFunc)
	if fn == nil {
		t.Skip("kernel BTF has no bpf_iter_bpf_map")
	}

	prog := openIterProgram(t)
	if err := BpfProgramSetAttachTarget(prog, 0, "bpf_map"); err != nil {
		t.Fatalf("set attach target bpf_map: %v", err)
	}
	if prog.attachBTFID != fn.ID || prog.attachProgFD != 0 {
		t.Fatalf("BTF id %d, program fd %d; want %d and 0", prog.attachBTFID, prog.attachProgFD, fn.ID)
	}

	err = BpfProgramSetAttachTarget(prog, 0, "gobpfgo_no_such_iterator")
	checkSetAttachTargetError(t, err, "bpf_program__set_attach_target", unix.ENOENT)
	if prog.attachBTFID != fn.ID {
		t.Fatalf("BTF id %d after a failed lookup, want the earlier %d", prog.attachBTFID, fn.ID)
	}
}

// TestIterAttr checks the link attribute of an iterator: the program, no
// target descriptor and BPF_TRACE_ITER. internal/sys tests that
// sys.LinkCreateIter points it at the link info.
func TestIterAttr(t *testing.T) {
	want := sys.LinkCreateAttr{ProgFD: 5, AttachType: sys.BPF_TRACE_ITER}
	if got := iterAttr(&BpfProgram{fd: 5, expectedAttachType: BPF_TRACE_ITER}); *got != want {
		t.Fatalf("attribute = %+v, want %+v", *got, want)
	}
}

// TestBpfProgramAttachIterInvalid checks that the iterator attach rejects a
// nil or unloaded program and a non-nil empty LinkInfo with EINVAL before
// bpf(), and that LinkInfo bytes reach the kernel, which refuses the
// descriptor no process has open with an error other than EINVAL.
func TestBpfProgramAttachIterInvalid(t *testing.T) {
	const op = "bpf_program__attach_iter"
	loaded := &BpfProgram{fd: fakeLoadedFD, expectedAttachType: BPF_TRACE_ITER}

	refused := map[string]struct {
		prog *BpfProgram
		opts *BpfIterOpts
	}{
		"nil program":      {nil, nil},
		"unloaded":         {&BpfProgram{fd: -1}, nil},
		"empty link info":  {loaded, &BpfIterOpts{LinkInfo: []byte{}}},
		"unloaded no info": {&BpfProgram{fd: -1}, &BpfIterOpts{LinkInfo: []byte{1, 0, 0, 0}}},
	}
	for name, c := range refused {
		t.Run(name, func(t *testing.T) {
			link, err := BpfProgramAttachIter(c.prog, c.opts)
			checkAttachError(t, link, err, op, unix.EINVAL)
		})
	}

	link, err := BpfProgramAttachIter(loaded, &BpfIterOpts{LinkInfo: []byte{1, 0, 0, 0}})
	if link != nil || err == nil || errors.Is(err, unix.EINVAL) {
		t.Fatalf("link info on a closed descriptor = %v, %v; want a kernel error other than EINVAL", link, err)
	}
}

// TestFreplaceAttr checks the link attribute of a freplace attach with a
// target: the program, the target descriptor, the program's attach type, 0,
// and the target BTF id, which takes no other union field. internal/sys
// tests the bytes and the union rules.
func TestFreplaceAttr(t *testing.T) {
	prog := &BpfProgram{fd: 5, progType: BPF_PROG_TYPE_EXT}
	base := &sys.LinkCreateAttr{TargetBTFID: 77}
	want := sys.LinkCreateAttr{ProgFD: 5, TargetFD: 9, AttachType: 0, TargetBTFID: 77}
	if got := attachFDAttr(prog, 9, base); *got != want {
		t.Fatalf("attribute = %+v, want %+v", *got, want)
	}
}

// TestBpfProgramAttachFreplaceInputs checks the input rules of the freplace
// attach, which fail with EINVAL before any system call: a nil program, a
// target descriptor without a function name, a function name without a
// target descriptor, and a program that is not BPF_PROG_TYPE_EXT, with or
// without a target. An unloaded freplace program without a target fails
// with EINVAL too, reported as the freplace attach.
func TestBpfProgramAttachFreplaceInputs(t *testing.T) {
	const op = "bpf_program__attach_freplace"
	ext := &BpfProgram{fd: fakeLoadedFD, progType: BPF_PROG_TYPE_EXT}
	kprobe := &BpfProgram{fd: fakeLoadedFD, progType: BPF_PROG_TYPE_KPROBE}

	tests := map[string]struct {
		prog   *BpfProgram
		target int
		name   string
	}{
		"nil program":              {nil, fakeLoadedFD, "xdp_pass"},
		"target without name":      {ext, fakeLoadedFD, ""},
		"name without target":      {ext, 0, "xdp_pass"},
		"not ext with target":      {kprobe, fakeLoadedFD, "xdp_pass"},
		"not ext without target":   {kprobe, 0, ""},
		"unloaded without target":  {&BpfProgram{fd: -1, progType: BPF_PROG_TYPE_EXT}, 0, ""},
		"tracing program as ext":   {&BpfProgram{fd: fakeLoadedFD, progType: BPF_PROG_TYPE_TRACING}, fakeLoadedFD, "xdp_pass"},
		"negative target, no name": {ext, -1, ""},
	}
	for name, c := range tests {
		t.Run(name, func(t *testing.T) {
			link, err := BpfProgramAttachFreplace(c.prog, c.target, c.name)
			checkAttachError(t, link, err, op, unix.EINVAL)
		})
	}
}

// TestBpfProgramAttachFreplaceBadTarget checks that a target descriptor no
// process has open fails the target lookup with the kernel's errno, EBADFD,
// or EPERM where unprivileged bpf() is refused, reported as the freplace
// attach.
func TestBpfProgramAttachFreplaceBadTarget(t *testing.T) {
	prog := &BpfProgram{fd: fakeLoadedFD, progType: BPF_PROG_TYPE_EXT}
	link, err := BpfProgramAttachFreplace(prog, fakeLoadedFD, "xdp_pass")
	if link != nil {
		BpfLinkDestroy(link)
		t.Fatal("attach returned a link")
	}
	var e *Error
	if !errors.As(err, &e) || e.Op != "bpf_program__attach_freplace" || e.Errno != unix.EBADFD && e.Errno != unix.EPERM {
		t.Fatalf("attach error = %#v, want op bpf_program__attach_freplace and EBADFD or EPERM", err)
	}
}

// TestBpfProgramAttachIterFreplaceSection checks that the automatic attach
// dispatches iter to the iterator attach and freplace to the tracing
// attach, as libbpf's attach_iter and attach_trace do: with a descriptor no
// process has open, each fails in the kernel under its own operation name
// instead of returning EOPNOTSUPP.
func TestBpfProgramAttachIterFreplaceSection(t *testing.T) {
	tests := []struct {
		section string
		prog    BpfProgram
		op      string
	}{
		{"iter/bpf_map", BpfProgram{progType: BPF_PROG_TYPE_TRACING, expectedAttachType: BPF_TRACE_ITER}, "bpf_program__attach_iter"},
		{"iter.s/bpf_map", BpfProgram{progType: BPF_PROG_TYPE_TRACING, expectedAttachType: BPF_TRACE_ITER}, "bpf_program__attach_iter"},
		{"freplace/xdp_pass", BpfProgram{progType: BPF_PROG_TYPE_EXT}, "bpf_program__attach_trace"},
	}
	for _, tt := range tests {
		t.Run(tt.section, func(t *testing.T) {
			prog := tt.prog
			prog.fd = fakeLoadedFD
			prog.sectionName = tt.section
			link, err := BpfProgramAttach(&prog)
			if link != nil {
				BpfLinkDestroy(link)
				t.Fatal("attach returned a link")
			}
			var e *Error
			if !errors.As(err, &e) || e.Op != tt.op || e.Errno == unix.EOPNOTSUPP {
				t.Fatalf("attach error = %#v, want op %s and a kernel error", err, tt.op)
			}
		})
	}
}

// openIterProgram returns the iter/bpf_map program of iter.bpf.o, opened
// until the test ends.
func openIterProgram(t *testing.T) *BpfProgram {
	t.Helper()
	return findProgram(t, openProg(t, "iter.bpf.o"), "dump_bpf_map")
}

// openFreplaceProgram returns the freplace/xdp_pass program of
// freplace.bpf.o, opened until the test ends.
func openFreplaceProgram(t *testing.T) *BpfProgram {
	t.Helper()
	return findProgram(t, openProg(t, "freplace.bpf.o"), "replace_xdp")
}

// checkSetAttachTargetError requires err to be an *Error with op and errno.
func checkSetAttachTargetError(t *testing.T, err error, op string, errno unix.Errno) {
	t.Helper()

	var e *Error
	if !errors.As(err, &e) || e.Op != op || e.Errno != errno {
		t.Fatalf("error = %#v, want op %s and %v", err, op, errno)
	}
}
