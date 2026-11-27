// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_prog_assign_exc_cb, bpf_object__relocate

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"fmt"
	"strings"
	"syscall"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

// exceptionCbTag starts the decl tag that names a main program's exception
// callback, the global .text function the verifier runs when the program
// throws with bpf_throw. The rest of the tag is the function's name.
const exceptionCbTag = "exception_callback:"

// exceptionCbError returns the relocation error of a bad exception callback
// tag.
func exceptionCbError(errno syscall.Errno, format string, args ...any) error {
	return &Error{Op: "bpf_object__relocate", Errno: errno, Log: fmt.Sprintf(format, args...)}
}

// appendExceptionCb assigns the main program of code its exception callback,
// as assignExceptionCb describes, and appends the callback to code if code
// does not hold it yet. The callback is relocated like any appended
// subprogram: its function and line records and its relocations follow it,
// and the subprograms it calls are appended after it. It runs after
// relocateCalls, so the callback comes after the subprograms the program
// calls and the functions its callx tables point to. A program that also
// calls its callback directly already holds it, and the verifier rejects
// that call.
//
// The kernel finds the callback through the tag in the uploaded BTF and the
// callback's function record; the program load passes nothing else.
func (r *relocator) appendExceptionCb(code *progCode, declTag func() bool) error {
	prog := code.prog
	if err := assignExceptionCb(r.obj, prog, declTag); err != nil {
		return err
	}
	if prog.exceptionCbIdx < 0 {
		return nil
	}

	cb := r.obj.programs[prog.exceptionCbIdx]
	if _, ok := code.subInsnOff[cb]; ok {
		return nil
	}
	r.appendSubprogCode(code, cb)
	if err := r.relocCode(code, cb); err != nil {
		return &Error{
			Op:    "bpf_object__relocate",
			Errno: unix.EINVAL,
			Log:   fmt.Sprintf("prog '%s': failed to append exception callback '%s': %v", prog.name, cb.name, err),
		}
	}
	return nil
}

// assignExceptionCb sets prog.exceptionCbIdx to the index in obj.programs of
// the exception callback that an exception_callback: decl tag on prog's BTF
// FUNC names, or to -1 when there is none.
//
// Nothing is assigned when the object has no BTF or declTag reports that
// the kernel lacks BTF_KIND_DECL_TAG, because that kernel never sees the
// tag. Otherwise every exception_callback: tag on a whole type, component
// -1, is checked in BTF order. Its type must be a global FUNC, whichever
// program the FUNC is, or the error is EINVAL. A tag on another program's
// FUNC is skipped. A second tag on prog's FUNC clears the callback and ends
// the walk, leaving the verifier to reject the program. The rest of the tag
// must not be empty, EINVAL, and must name a .text subprogram, as
// findExceptionCb describes.
func assignExceptionCb(obj *BpfObject, prog *BpfProgram, declTag func() bool) error {
	prog.exceptionCbIdx = -1
	if obj.btf == nil || !declTag() {
		return nil
	}

	spec := obj.btf
	for id := 1; id < len(spec.Types); id++ {
		tag := &spec.Types[id]
		if tag.Kind != btf.KindDeclTag || tag.DeclTag == nil || tag.DeclTag.ComponentIdx != -1 {
			continue
		}
		if !strings.HasPrefix(tag.Name, exceptionCbTag) {
			continue
		}

		fn, err := spec.TypeByID(tag.SizeOrType)
		if err != nil || fn.Kind != btf.KindFunc || fn.Vlen != btf.FuncGlobal {
			return exceptionCbError(unix.EINVAL,
				"prog '%s': exception_callback:<value> decl tag not applied to the main program: tag [%d] '%s' is on type [%d], not a global FUNC",
				prog.name, id, tag.Name, tag.SizeOrType)
		}
		if fn.Name != prog.name {
			continue
		}
		if prog.exceptionCbIdx >= 0 {
			prog.exceptionCbIdx = -1
			break
		}

		name := strings.TrimPrefix(tag.Name, exceptionCbTag)
		if name == "" {
			return exceptionCbError(unix.EINVAL,
				"prog '%s': exception_callback:<value> decl tag contains empty value", prog.name)
		}
		idx, err := findExceptionCb(obj, prog, name)
		if err != nil {
			return err
		}
		prog.exceptionCbIdx = idx
	}
	return nil
}

// findExceptionCb returns the index in obj.programs of the .text subprogram
// named name, the exception callback of prog. The first subprogram with the
// name, in program order, is the callback, and a later one with the same
// name is ignored. It must be a global or weak function without hidden or
// internal visibility, because the verifier expects a global function and
// markBtfStatic would make a hidden one static, or the error is EINVAL.
// Without a subprogram of that name the error is ENOENT.
func findExceptionCb(obj *BpfObject, prog *BpfProgram, name string) (int, error) {
	for i, sub := range obj.programs {
		if !progIsSubprog(obj, sub) || sub.name != name {
			continue
		}
		if !sub.symGlobal || sub.markBtfStatic {
			return -1, exceptionCbError(unix.EINVAL,
				"prog '%s': exception callback %s must be a global non-hidden function", prog.name, sub.name)
		}
		// libbpf checks for a second subprogram with the name next,
		// but its walk stops at the first one, so that check never
		// fails and is left out.
		return i, nil
	}
	return -1, exceptionCbError(unix.ENOENT, "prog '%s': cannot find exception callback '%s'", prog.name, name)
}
