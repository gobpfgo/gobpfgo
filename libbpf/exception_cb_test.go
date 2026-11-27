// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

const (
	exceptionCbObject       = "../testdata/progs/exception_cb.bpf.o"
	exceptionCbDirectObject = "../testdata/progs/exception_cb_direct.bpf.o"
)

// The cookie handle_throw throws and the slots of exc_state, as
// exception_cb.bpf.c defines them.
const (
	excThrowCookie = 0x6578630042
	excTargetTgid  = 0
	excCookie      = 1
	excCalls       = 2
	excOpens       = 3
)

// Type IDs of the synthetic exception callback objects: the FUNC_PROTO all
// functions share, the main programs handle and other, the global function
// on_throw and a static function no program has.
const (
	excCbProtoID   = 2
	excCbHandleID  = 3
	excCbOnThrowID = 4
	excCbOtherID   = 5
	excCbStaticID  = 6
)

// Section indexes of the synthetic objects: .text and the main programs'
// section.
const (
	excCbTextShndx = 2
	excCbProgShndx = 3
)

// excCbStrings is the string table of the synthetic objects, and excCbOff
// each string's offset.
var excCbStrings, excCbOff = btfStrTab("u64", "cookie", "handle", "on_throw", "other", "static_fn",
	exceptionCbTag+"on_throw", exceptionCbTag, exceptionCbTag+"missing", exceptionCbTag+"other",
	"exception_cb:on_throw")

// excCbTypes returns the types of a synthetic object followed by tags.
func excCbTypes(tags ...btf.Type) []btf.Type {
	fn := func(name string, linkage uint32) btf.Type {
		return btf.Type{NameOff: excCbOff[name], Kind: btf.KindFunc, Vlen: linkage, SizeOrType: excCbProtoID}
	}
	types := []btf.Type{
		{Kind: btf.KindVoid},
		{NameOff: excCbOff["u64"], Kind: btf.KindInt, SizeOrType: 8, Int: &btf.Int{Encoding: 64}},
		{Kind: btf.KindFuncProto, SizeOrType: 1, Params: []btf.Param{{NameOff: excCbOff["cookie"], Type: 1}}},
		fn("handle", btf.FuncGlobal),
		fn("on_throw", btf.FuncGlobal),
		fn("other", btf.FuncGlobal),
		fn("static_fn", btf.FuncStatic),
	}
	return append(types, tags...)
}

// excCbTag returns the decl tag name on component comp of type ref; comp -1
// is the whole type.
func excCbTag(name string, ref uint32, comp int32) btf.Type {
	return btf.Type{NameOff: excCbOff[name], Kind: btf.KindDeclTag, SizeOrType: ref, DeclTag: &btf.DeclTag{ComponentIdx: comp}}
}

// excCbFunc describes a .text function named on_throw in a synthetic
// object: global or static, and hidden when global.
type excCbFunc struct {
	global, hidden bool
}

// excCbObject returns a synthetic object with the BTF types, a .text
// function for each of subs, in order, and the main programs handle and
// other, in that order, after them.
func excCbObject(t *testing.T, types []btf.Type, subs []excCbFunc) *BpfObject {
	t.Helper()

	obj := &BpfObject{btf: newTestSpec(t, types, excCbStrings), textShndx: excCbTextShndx}
	for i, f := range subs {
		obj.programs = append(obj.programs, &BpfProgram{
			name:           "on_throw",
			secIdx:         excCbTextShndx,
			secInsnOff:     i,
			symGlobal:      f.global,
			markBtfStatic:  f.global && f.hidden,
			exceptionCbIdx: -1,
		})
	}
	for _, name := range []string{"handle", "other"} {
		obj.programs = append(obj.programs, &BpfProgram{
			name:           name,
			secIdx:         excCbProgShndx,
			symGlobal:      true,
			exceptionCbIdx: -1,
		})
	}
	return obj
}

// excCbGlobal is a synthetic object's usual .text: one global on_throw.
var excCbGlobal = []excCbFunc{{global: true}}

// TestAssignExceptionCb assigns handle's exception callback in synthetic
// objects. A valid tag names the first .text on_throw. A tag on another
// program, on a component, or with another prefix is skipped. A tag on a
// static FUNC or a FUNC_PROTO is EINVAL even when no program has that
// function, and so is an empty value or a static or hidden callback. A
// missing callback, or one that is a main program, is ENOENT. With two
// .text functions of the name the first wins when it is global, and is
// EINVAL when it is static. A second tag on handle clears the callback and
// ends the walk, so neither its value nor a later bad tag is checked.
// Without BTF or decl tag support nothing is assigned, and an index left by
// an earlier load is cleared.
func TestAssignExceptionCb(t *testing.T) {
	onThrow := excCbTag(exceptionCbTag+"on_throw", excCbHandleID, -1)
	tests := []struct {
		name    string
		tags    []btf.Type
		subs    []excCbFunc
		noBTF   bool
		declTag func() bool
		stale   bool
		want    int
		errno   syscall.Errno
	}{
		{name: "valid tag", tags: []btf.Type{onThrow}, want: 0},
		{name: "tag on another program", tags: []btf.Type{excCbTag(exceptionCbTag+"on_throw", excCbOtherID, -1)}, want: -1},
		{name: "tag on a component", tags: []btf.Type{excCbTag(exceptionCbTag+"on_throw", excCbHandleID, 0)}, want: -1},
		{name: "other prefix", tags: []btf.Type{excCbTag("exception_cb:on_throw", excCbHandleID, -1)}, want: -1},
		{name: "tag on a static FUNC", tags: []btf.Type{excCbTag(exceptionCbTag+"on_throw", excCbStaticID, -1)}, errno: unix.EINVAL},
		{name: "tag on a FUNC_PROTO", tags: []btf.Type{excCbTag(exceptionCbTag+"on_throw", excCbProtoID, -1)}, errno: unix.EINVAL},
		{name: "empty value", tags: []btf.Type{excCbTag(exceptionCbTag, excCbHandleID, -1)}, errno: unix.EINVAL},
		{name: "missing callback", tags: []btf.Type{excCbTag(exceptionCbTag+"missing", excCbHandleID, -1)}, errno: unix.ENOENT},
		{name: "callback is a main program", tags: []btf.Type{excCbTag(exceptionCbTag+"other", excCbHandleID, -1)}, errno: unix.ENOENT},
		{name: "static callback", tags: []btf.Type{onThrow}, subs: []excCbFunc{{}}, errno: unix.EINVAL},
		{name: "hidden callback", tags: []btf.Type{onThrow}, subs: []excCbFunc{{global: true, hidden: true}}, errno: unix.EINVAL},
		{name: "duplicate names, global first", tags: []btf.Type{onThrow}, subs: []excCbFunc{{global: true}, {}}, want: 0},
		{name: "duplicate names, static first", tags: []btf.Type{onThrow}, subs: []excCbFunc{{}, {global: true}}, errno: unix.EINVAL},
		{name: "two tags on the program", tags: []btf.Type{onThrow, excCbTag(exceptionCbTag+"missing", excCbHandleID, -1)}, want: -1},
		{name: "walk ends at the second tag", tags: []btf.Type{
			onThrow, onThrow, excCbTag(exceptionCbTag+"on_throw", excCbStaticID, -1),
		}, want: -1},
		{name: "no BTF", tags: []btf.Type{onThrow}, noBTF: true, want: -1},
		{name: "no decl tag support", tags: []btf.Type{excCbTag(exceptionCbTag+"on_throw", excCbStaticID, -1)}, declTag: declTagMissing, want: -1},
		{name: "stale index", stale: true, want: -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subs, declTag := tt.subs, tt.declTag
			if subs == nil {
				subs = excCbGlobal
			}
			if declTag == nil {
				declTag = declTagSupported
			}
			obj := excCbObject(t, excCbTypes(tt.tags...), subs)
			if tt.noBTF {
				obj.btf = nil
			}
			handle := findFunction(t, obj, "handle")
			if tt.stale {
				handle.exceptionCbIdx = 0
			}

			err := assignExceptionCb(obj, handle, declTag)
			if got := errnoOf(err); got != tt.errno {
				t.Fatalf("assignExceptionCb = %v, want errno %d", err, tt.errno)
			}
			if err != nil {
				checkExceptionCbError(t, err, "handle")
				return
			}
			if handle.exceptionCbIdx != tt.want {
				t.Fatalf("exception callback index = %d, want %d", handle.exceptionCbIdx, tt.want)
			}
		})
	}
}

// checkExceptionCbError checks that err is a relocation error that names
// the program.
func checkExceptionCbError(t *testing.T, err error, prog string) {
	t.Helper()

	var e *Error
	if !errors.As(err, &e) || e.Op != "bpf_object__relocate" || !strings.Contains(e.Log, "prog '"+prog+"'") {
		t.Fatalf("error = %#v, want a bpf_object__relocate error for prog '%s'", err, prog)
	}
}

// TestExceptionCbRelocateObject relocates synthetic objects through
// relocateObject: a valid tag appends on_throw to handle only, and a bad
// tag fails the relocation with its own errno.
func TestExceptionCbRelocateObject(t *testing.T) {
	tests := []struct {
		name  string
		tag   string
		subs  []excCbFunc
		errno syscall.Errno
	}{
		{name: "valid tag", tag: "on_throw", subs: excCbGlobal},
		{name: "static callback", tag: "on_throw", subs: []excCbFunc{{}}, errno: unix.EINVAL},
		{name: "missing callback", tag: "missing", subs: excCbGlobal, errno: unix.ENOENT},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := excCbObject(t, excCbTypes(excCbTag(exceptionCbTag+tt.tag, excCbHandleID, -1)), tt.subs)

			codes, err := relocateObject(obj, nil, nil, argCtxTagSupported, declTagSupported)
			if got := errnoOf(err); got != tt.errno {
				t.Fatalf("relocateObject = %v, want errno %d", err, tt.errno)
			}
			if err != nil {
				checkExceptionCbError(t, err, "handle")
				return
			}
			onThrow := obj.programs[0]
			for _, code := range codes {
				_, appended := code.subInsnOff[onThrow]
				if want := code.prog.name == "handle"; appended != want {
					t.Errorf("%s: on_throw appended %v, want %v", code.prog.name, appended, want)
				}
			}
		})
	}
}

// TestExceptionCbRelocate relocates exception_cb.bpf.o. handle_throw gets
// its exception callback on_throw appended after its own code, then the
// static exc_record that on_throw calls, each with its function record.
// handle_count has no tag: it gets only exc_record, which it calls.
func TestExceptionCbRelocate(t *testing.T) {
	obj := openSubprogObject(t, "exception_cb.bpf.o")
	codes := relocateObjectCode(t, obj)

	throw := codes["handle_throw"]
	starts := checkSubprogParts(t, obj, throw, []string{"handle_throw", "on_throw", "exc_record"})
	onThrow := findFunction(t, obj, "on_throw")
	if got := throw.prog.exceptionCbIdx; got < 0 || obj.programs[got] != onThrow {
		t.Fatalf("handle_throw exception callback index = %d, want on_throw", got)
	}
	checkFuncInfoStarts(t, obj, throw, starts, "on_throw", "exc_record")

	count := codes["handle_count"]
	starts = checkSubprogParts(t, obj, count, []string{"handle_count", "exc_record"})
	if got := count.prog.exceptionCbIdx; got != -1 {
		t.Fatalf("handle_count exception callback index = %d, want -1", got)
	}
	checkFuncInfoStarts(t, obj, count, starts, "exc_record")
}

// checkFuncInfoStarts checks that code has one function record per part,
// the main program's first, and that each named part's record starts where
// the part does and names its BTF FUNC.
func checkFuncInfoStarts(t *testing.T, obj *BpfObject, code *progCode, starts map[string]int, names ...string) {
	t.Helper()

	recs := decodeFuncInfo(code.funcInfo)
	if len(recs) != len(names)+1 || recs[0].InsnOff != 0 {
		t.Fatalf("%s: function records %+v, want %d starting at 0", code.prog.name, recs, len(names)+1)
	}
	for i, name := range names {
		fn := obj.btf.Find(name, btf.KindFunc)
		if fn == nil {
			t.Fatalf("no BTF FUNC %s", name)
		}
		if rec := recs[i+1]; int(rec.InsnOff) != starts[name] || rec.TypeID != fn.ID {
			t.Errorf("%s: record %d = %+v, want %s at %d with type %d", code.prog.name, i+1, rec, name, starts[name], fn.ID)
		}
	}
}

// TestExceptionCbDirectCall relocates exception_cb_direct.bpf.o, whose
// program calls its exception callback directly. The call appends the
// callback, and the tag assigns it but does not append it again.
func TestExceptionCbDirectCall(t *testing.T) {
	obj := openSubprogObject(t, "exception_cb_direct.bpf.o")
	codes := relocateObjectCode(t, obj)

	code := codes["handle_direct"]
	starts := checkSubprogParts(t, obj, code, []string{"handle_direct", "on_throw_direct"})
	if got := code.prog.exceptionCbIdx; got < 0 || obj.programs[got] != findFunction(t, obj, "on_throw_direct") {
		t.Fatalf("handle_direct exception callback index = %d, want on_throw_direct", got)
	}
	checkFuncInfoStarts(t, obj, code, starts, "on_throw_direct")
}

// TestExceptionCbNoDeclTag relocates exception_cb.bpf.o as for a kernel
// without BTF_KIND_DECL_TAG: no callback is assigned or appended, so
// handle_throw keeps only its own code.
func TestExceptionCbNoDeclTag(t *testing.T) {
	obj := openSubprogObject(t, "exception_cb.bpf.o")

	codes, err := relocateObject(obj, objectExt(t, obj), nil, argCtxTagSupported, declTagMissing)
	if err != nil {
		t.Fatalf("relocateObject: %v", err)
	}
	for _, code := range codes {
		if code.prog.name != "handle_throw" {
			continue
		}
		checkSubprogParts(t, obj, code, []string{"handle_throw"})
		if got := code.prog.exceptionCbIdx; got != -1 {
			t.Fatalf("exception callback index = %d, want -1", got)
		}
		return
	}
	t.Fatal("no code for handle_throw")
}

// TestExceptionCbLoad loads exception_cb.bpf.o and checks that
// handle_throw's final code holds on_throw and exc_record after its own
// instructions and that the kernel jited all three functions. It then
// writes this process's ID to exc_state, attaches handle_throw and
// handle_count to do_sys_openat2 and opens a file. handle_throw throws for
// this process only, so on_throw must record the thrown cookie, and the
// open must still complete, which handle_count counts on exit.
//
// It needs root or CAP_BPF and skips otherwise. bpf_throw needs Linux 6.7:
// on a kernel whose BTF lacks it, as on 5.10, the load must fail with
// EINVAL on the unresolved kfunc and the test skips.
func TestExceptionCbLoad(t *testing.T) {
	kernel := requireKernelBTF(t)
	obj, err := BpfObjectOpenFile(exceptionCbObject, nil)
	if err != nil {
		t.Fatalf("open %s: %v", exceptionCbObject, err)
	}
	defer BpfObjectClose(obj)

	err = BpfObjectLoad(obj)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("bpf() not permitted: %v", err)
	}
	if findByNameKind(kernel, 1, "bpf_throw", btf.KindFunc) == 0 {
		skipWithoutBpfThrow(t, err)
	}
	if err != nil {
		t.Fatalf("load %s: %v", exceptionCbObject, err)
	}

	throw := BpfObjectFindProgramByName(obj, "handle_throw")
	checkFinalParts(t, obj, throw, "on_throw", "exc_record")
	info, err := BpfProgramInfo(throw)
	if err != nil {
		t.Fatalf("BpfProgramInfo(handle_throw): %v", err)
	}
	if info.NrJitedKsyms != 0 && info.NrJitedKsyms != 3 {
		t.Errorf("kernel jited %d functions of handle_throw, want 3", info.NrJitedKsyms)
	}

	setExcTarget(t, obj, uint64(os.Getpid()))
	for _, name := range []string{"handle_throw", "handle_count"} {
		link, err := BpfProgramAttachTrace(BpfObjectFindProgramByName(obj, name))
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		defer BpfLinkDestroy(link)
	}
	triggerOpen(t)

	if got := mapSlot(t, obj, "exc_state", excCookie); got != excThrowCookie {
		t.Errorf("recorded cookie = %#x, want %#x", got, uint64(excThrowCookie))
	}
	if got := mapSlot(t, obj, "exc_state", excCalls); got == 0 {
		t.Error("the exception callback did not run")
	}
	if got := mapSlot(t, obj, "exc_state", excOpens); got == 0 {
		t.Error("no open completed after the throw")
	}
}

// skipWithoutBpfThrow checks that loading exception_cb.bpf.o on a kernel
// whose BTF has no bpf_throw failed with EINVAL on that kfunc, and skips the
// test.
func skipWithoutBpfThrow(t *testing.T, err error) {
	t.Helper()

	if !errors.Is(err, unix.EINVAL) || !strings.Contains(err.Error(), "'bpf_throw'") {
		t.Fatalf("load without bpf_throw = %v, want EINVAL on the bpf_throw extern", err)
	}
	t.Skipf("kernel BTF has no bpf_throw, which needs Linux 6.7: %v", err)
}

// checkFinalParts checks that prog's final code, after a load, is its own
// instructions followed by a copy of each named function, in order.
func checkFinalParts(t *testing.T, obj *BpfObject, prog *BpfProgram, names ...string) {
	t.Helper()

	insns := BpfProgramInsns(prog)
	off := prog.secInsnCnt
	for _, name := range names {
		p := findFunction(t, obj, name)
		if (off+p.secInsnCnt)*bpfInsnLength > len(insns) {
			t.Fatalf("%s: final code has %d instructions, too few for %s at %d", prog.name, len(insns)/bpfInsnLength, name, off)
		}
		for i := 0; i < p.secInsnCnt; i++ {
			got := decodeBpfInsn(insns[(off+i)*bpfInsnLength:])
			orig := decodeBpfInsn(p.insns[i*bpfInsnLength:])
			if got.Code != orig.Code || got.Dst != orig.Dst || got.Off != orig.Off {
				t.Fatalf("%s: %s insn %d = %+v, want a copy of %+v", prog.name, name, i, got, orig)
			}
		}
		off += p.secInsnCnt
	}
	if off*bpfInsnLength != len(insns) {
		t.Fatalf("%s: final code has %d instructions, want %d", prog.name, len(insns)/bpfInsnLength, off)
	}
}

// setExcTarget writes tgid to exc_state, the process the programs act for.
func setExcTarget(t *testing.T, obj *BpfObject, tgid uint64) {
	t.Helper()

	m := BpfObjectFindMapByName(obj, "exc_state")
	if m == nil {
		t.Fatal("map exc_state not found")
	}
	key := binary.NativeEndian.AppendUint32(nil, excTargetTgid)
	value := binary.NativeEndian.AppendUint64(nil, tgid)
	if err := sys.MapUpdateElem(BpfMapFD(m), key, value, 0); err != nil {
		t.Fatalf("set exc_state target: %v", err)
	}
}
