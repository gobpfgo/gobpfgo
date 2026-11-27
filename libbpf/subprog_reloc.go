// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__relocate, bpf_object__relocate_calls, bpf_object__reloc_code, bpf_object__append_subprog_code, append_subprog_relos, find_prog_insn_relo, cmp_relocs, bpf_object__sort_relos, reloc_prog_func_and_line_info, insn_is_subprog_call, is_call_insn, insn_is_pseudo_func

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"cmp"
	"fmt"
	"slices"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

// Source register values of a call to a subprogram and of an ld_imm64 that
// loads a subprogram address.
const (
	bpfPseudoCall = 1
	bpfPseudoFunc = 4
)

// progCode is a main program as BPF_PROG_LOAD receives it: the program's own
// instructions followed by every subprogram it calls, directly or through
// another subprogram, each appended once. relocs are the relocations of every
// part at their byte offset in insns, and funcInfo and lineInfo the
// .BTF.ext records with instruction indexes into insns. subInsnOff is the
// instruction index where each part starts; the program itself starts at 0.
// hasCallx is set when the code has an indirect call; it then also holds
// every static function the read-only data it loads points to, and loads
// its own copies of those maps.
type progCode struct {
	prog       *BpfProgram
	insns      []byte
	relocs     []progReloc
	funcInfo   []byte
	lineInfo   []byte
	subInsnOff map[*BpfProgram]int
	hasCallx   bool
}

// relocator holds every program's input to the call relocation: a copy of
// its instructions after CO-RE, with the subprogram address loads marked, and
// its relocations in instruction order with offsets in that copy. A
// subprogram is copied from here into each main program that calls it.
type relocator struct {
	obj    *BpfObject
	ext    *btf.ExtSpec
	insns  map[*BpfProgram][]byte
	relocs map[*BpfProgram][]progReloc
}

// relocateObject relocates the programs of obj for loading and returns the
// code of each main program, in program order. CO-RE runs first, on every
// program and subprogram, then the calls build each main program's code
// with its function and line records, and its exception callback is
// appended when declTag reports that the kernel reads decl tags. Last, each
// main program's records of global functions with arg:ctx arguments are
// fixed up, which adds types to the object BTF, unless argCtxTag reports
// that the kernel reads the tag. relocateObjectData patches the map, global
// data and extern loads once the maps exist. The program instructions are
// not changed; each step works on copies. ext may be nil, and kernels is
// empty when there is no CO-RE relocation. A bad exception callback tag
// returns EINVAL or ENOENT, as assignExceptionCb describes.
func relocateObject(obj *BpfObject, ext *btf.ExtSpec, kernels []*btf.Spec, argCtxTag, declTag func() bool) ([]*progCode, error) {
	r := &relocator{
		obj:    obj,
		ext:    ext,
		insns:  make(map[*BpfProgram][]byte, len(obj.programs)),
		relocs: make(map[*BpfProgram][]progReloc, len(obj.programs)),
	}
	for _, p := range obj.programs {
		if err := r.prepare(p, kernels); err != nil {
			return nil, err
		}
	}

	var codes []*progCode
	for _, p := range obj.programs {
		if progIsSubprog(obj, p) {
			continue
		}
		code, err := r.relocateCalls(p)
		if err != nil {
			return nil, &Error{
				Op:    "bpf_object__relocate",
				Errno: unix.EINVAL,
				Log:   fmt.Sprintf("prog '%s': failed to relocate calls: %v", p.name, err),
			}
		}
		if err := r.appendExceptionCb(code, declTag); err != nil {
			return nil, err
		}
		codes = append(codes, code)
	}

	for _, code := range codes {
		if err := fixupFuncInfo(obj, ext, code, argCtxTag); err != nil {
			return nil, &Error{
				Op:    "bpf_object__relocate",
				Errno: unix.EINVAL,
				Log:   fmt.Sprintf("prog '%s': failed to perform .BTF.ext fix ups: %v", code.prog.name, err),
			}
		}
	}
	return codes, nil
}

// relocateObjectData patches the map, global data and extern loads in the
// code of every main program. The maps must have their descriptors. newMap
// creates the copies of the read-only data maps with function pointers that
// the programs with callx load. The error keeps the errno of a failed copy
// and is EINVAL otherwise.
func relocateObjectData(codes []*progCode, newMap funcPtrMapCreator) error {
	for _, code := range codes {
		if err := relocateData(code, newMap); err != nil {
			return &Error{Op: "bpf_prog_load", Errno: errnoFromError(err), Log: err.Error()}
		}
	}
	return nil
}

// prepare copies p's instructions, applies its CO-RE relocations, records its
// ELF relocations and marks its subprogram address loads with
// BPF_PSEUDO_FUNC, so the call relocation can tell them from other ld_imm64
// instructions.
func (r *relocator) prepare(p *BpfProgram, kernels []*btf.Spec) error {
	insns := slices.Clone(p.insns)
	if len(kernels) > 0 {
		if err := relocateCore(p, insns, r.ext, r.obj.btf, kernels); err != nil {
			return &Error{Op: "bpf_object__relocate_core", Errno: unix.EINVAL, Log: err.Error()}
		}
	}

	relocs, err := recordRelocs(r.obj, p, p.insns)
	if err != nil {
		return &Error{Op: "bpf_prog_load", Errno: unix.EINVAL, Log: err.Error()}
	}
	for _, rel := range relocs {
		if rel.kind == relocSubprogAddr {
			insns[rel.insnOff+1] = insns[rel.insnOff+1]&0x0f | bpfPseudoFunc<<4
		}
	}

	r.insns[p] = insns
	r.relocs[p] = relocs
	return nil
}

// recordRelocs resolves every ELF relocation of p against insns and returns
// them sorted by instruction.
func recordRelocs(obj *BpfObject, p *BpfProgram, insns []byte) ([]progReloc, error) {
	relocs := make([]progReloc, 0, len(p.relocs))
	for _, rel := range p.relocs {
		r, err := recordReloc(obj, p, rel, insns)
		if err != nil {
			return nil, err
		}
		relocs = append(relocs, r)
	}
	slices.SortStableFunc(relocs, func(a, b progReloc) int {
		return cmp.Compare(a.insnOff, b.insnOff)
	})
	return relocs, nil
}

// relocateCalls builds the code of the main program prog: its own
// instructions with every subprogram it reaches appended, and every call and
// subprogram address load rewritten to the appended copy. Each main program
// appends its subprograms in the order it reaches them, so a subprogram can
// sit at a different offset in each. When the code has callx, the static
// functions its read-only data points to are appended last, as
// appendFuncPtrs describes.
func (r *relocator) relocateCalls(prog *BpfProgram) (*progCode, error) {
	code := &progCode{
		prog:       prog,
		insns:      slices.Clone(r.insns[prog]),
		relocs:     slices.Clone(r.relocs[prog]),
		subInsnOff: map[*BpfProgram]int{prog: 0},
	}
	if err := r.relocCode(code, prog); err != nil {
		return nil, err
	}
	if err := r.appendFuncPtrs(code); err != nil {
		return nil, err
	}
	return code, nil
}

// relocCode adds prog's function and line records to code and rewrites the
// calls and subprogram address loads in prog's copy; a kernel function call
// is left to relocateData. A subprogram that code
// does not hold yet is appended and relocated first, recursively, so every
// subprogram is appended once and every call gets the offset of that copy.
func (r *relocator) relocCode(code *progCode, prog *BpfProgram) error {
	if err := r.relocFuncAndLineInfo(code, prog); err != nil {
		return err
	}

	base := code.subInsnOff[prog]
	for insnIdx := 0; insnIdx < prog.secInsnCnt; insnIdx++ {
		off := (base + insnIdx) * bpfInsnLength
		insn := decodeBpfInsn(code.insns[off:])
		if !insnIsSubprogCall(insn) && !insnIsPseudoFunc(insn) {
			continue
		}

		reloc := findProgInsnReloc(r.relocs[prog], insnIdx)
		if reloc != nil && reloc.kind == relocExternCall {
			// A kernel function call is patched with the data
			// relocations.
			continue
		}
		target, err := subprogTarget(prog, insnIdx, insn, reloc)
		if err != nil {
			return err
		}
		subprog := findProgBySecInsn(r.obj.programs, r.obj.textShndx, target)
		if subprog == nil {
			return fmt.Errorf("prog '%s': no .text section found yet sub-program call exists", prog.name)
		}
		if _, ok := code.subInsnOff[subprog]; !ok {
			r.appendSubprogCode(code, subprog)
			if err := r.relocCode(code, subprog); err != nil {
				return err
			}
		}

		insn.Imm = int32(code.subInsnOff[subprog] - (base + insnIdx) - 1)
		encodeBpfInsn(code.insns[off:], insn)
	}
	return nil
}

// subprogTarget returns the .text instruction index that the call or address
// load at prog's instruction insnIdx refers to. reloc is the instruction's
// relocation, or nil.
func subprogTarget(prog *BpfProgram, insnIdx int, insn bpfInsn, reloc *progReloc) (int, error) {
	switch {
	case reloc != nil && reloc.kind == relocCall:
		// A global function's call has immediate -1; a static function's
		// call is relocated against the section symbol and its immediate
		// points at the function.
		return int(reloc.symOff)/bpfInsnLength + int(insn.Imm) + 1, nil
	case reloc != nil && reloc.kind == relocSubprogAddr:
		// The symbol value plus the immediate is the byte offset of the
		// function in .text.
		return (int(reloc.symOff) + int(insn.Imm)) / bpfInsnLength, nil
	case reloc != nil:
		return 0, fmt.Errorf("prog '%s': unexpected relo for insn #%d, type %d", prog.name, insnIdx, reloc.kind)
	case insnIsPseudoFunc(insn):
		// Clang relocates every subprogram address load, even within one
		// section.
		return 0, fmt.Errorf("prog '%s': missing subprog addr relo for insn #%d", prog.name, insnIdx)
	default:
		// A call to a static function in the same section has no
		// relocation; the immediate is relative to the call's position
		// in the section.
		return prog.secInsnOff + insnIdx + int(insn.Imm) + 1, nil
	}
}

// appendSubprogCode appends subprog's copy and its relocations to code and
// records where the copy starts.
func (r *relocator) appendSubprogCode(code *progCode, subprog *BpfProgram) {
	subInsnOff := len(code.insns) / bpfInsnLength
	code.subInsnOff[subprog] = subInsnOff
	code.insns = append(code.insns, r.insns[subprog]...)

	for _, rel := range r.relocs[subprog] {
		rel.insnOff += subInsnOff * bpfInsnLength
		code.relocs = append(code.relocs, rel)
	}
}

// relocFuncAndLineInfo appends prog's function and line records to code, at
// prog's offset in code. When the main program has no records of a kind, that
// kind is left out for every part. Once the main program has records, a
// subprogram without them is an error, because the kernel needs a function
// record for every subprogram.
func (r *relocator) relocFuncAndLineInfo(code *progCode, prog *BpfProgram) error {
	if r.ext == nil {
		return nil
	}
	isMain := code.prog == prog
	subInsnOff := code.subInsnOff[prog]

	if isMain || code.funcInfo != nil {
		recs := programFuncInfo(r.ext, prog, subInsnOff)
		if recs == nil && code.funcInfo != nil {
			return fmt.Errorf("prog '%s': missing .BTF.ext function info", prog.name)
		}
		code.funcInfo = append(code.funcInfo, recs...)
	}

	if isMain || code.lineInfo != nil {
		recs := programLineInfo(r.ext, prog, subInsnOff)
		if recs == nil && code.lineInfo != nil {
			return fmt.Errorf("prog '%s': missing .BTF.ext line info", prog.name)
		}
		code.lineInfo = append(code.lineInfo, recs...)
	}
	return nil
}

// findProgInsnReloc returns the relocation of instruction insnIdx in relocs,
// which are sorted by instruction, or nil.
func findProgInsnReloc(relocs []progReloc, insnIdx int) *progReloc {
	i, found := slices.BinarySearchFunc(relocs, insnIdx*bpfInsnLength, func(r progReloc, off int) int {
		return cmp.Compare(r.insnOff, off)
	})
	if !found {
		return nil
	}
	return &relocs[i]
}

// isCallInsn reports whether insn is a call, to a helper or a subprogram.
func isCallInsn(insn bpfInsn) bool {
	return insn.Code == bpfJMP|bpfCall
}

// insnIsSubprogCall reports whether insn calls a subprogram.
func insnIsSubprogCall(insn bpfInsn) bool {
	return insn.Code == bpfJMP|bpfCall|bpfSourceK && insn.Src == bpfPseudoCall && insn.Dst == 0 && insn.Off == 0
}

// insnIsPseudoFunc reports whether insn is an ld_imm64 that loads a
// subprogram address.
func insnIsPseudoFunc(insn bpfInsn) bool {
	return insn.Code == bpfLD|bpfImm|bpfSizeDW && insn.Src == bpfPseudoFunc
}
