// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__sanitize_and_load_btf, btf_needs_sanitization, bpf_object__sanitize_btf, bpf_program_fixup_func_info, need_func_arg_type_fixup, clone_func_btf_info, global_ctx_map

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"slices"

	"github.com/gobpfgo/gobpfgo/internal/btf"
)

// argCtxTag is the decl tag that marks a global function argument as the
// program context.
const argCtxTag = "arg:ctx"

// globalCtxMap names the context struct of each program type that has one.
// A global function argument must point to that struct for the verifier to
// treat it as the program context.
var globalCtxMap = []struct {
	progType BpfProgType
	ctxName  string
}{
	{BPF_PROG_TYPE_CGROUP_DEVICE, "bpf_cgroup_dev_ctx"},
	{BPF_PROG_TYPE_CGROUP_SKB, "__sk_buff"},
	{BPF_PROG_TYPE_CGROUP_SOCK, "bpf_sock"},
	{BPF_PROG_TYPE_CGROUP_SOCK_ADDR, "bpf_sock_addr"},
	{BPF_PROG_TYPE_CGROUP_SOCKOPT, "bpf_sockopt"},
	{BPF_PROG_TYPE_CGROUP_SYSCTL, "bpf_sysctl"},
	{BPF_PROG_TYPE_FLOW_DISSECTOR, "__sk_buff"},
	{BPF_PROG_TYPE_KPROBE, "bpf_user_pt_regs_t"},
	{BPF_PROG_TYPE_LWT_IN, "__sk_buff"},
	{BPF_PROG_TYPE_LWT_OUT, "__sk_buff"},
	{BPF_PROG_TYPE_LWT_SEG6LOCAL, "__sk_buff"},
	{BPF_PROG_TYPE_LWT_XMIT, "__sk_buff"},
	{BPF_PROG_TYPE_NETFILTER, "bpf_nf_ctx"},
	{BPF_PROG_TYPE_PERF_EVENT, "bpf_perf_event_data"},
	{BPF_PROG_TYPE_RAW_TRACEPOINT, "bpf_raw_tracepoint_args"},
	{BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE, "bpf_raw_tracepoint_args"},
	{BPF_PROG_TYPE_SCHED_ACT, "__sk_buff"},
	{BPF_PROG_TYPE_SCHED_CLS, "__sk_buff"},
	{BPF_PROG_TYPE_SK_LOOKUP, "bpf_sk_lookup"},
	{BPF_PROG_TYPE_SK_MSG, "sk_msg_md"},
	{BPF_PROG_TYPE_SK_REUSEPORT, "sk_reuseport_md"},
	{BPF_PROG_TYPE_SK_SKB, "__sk_buff"},
	{BPF_PROG_TYPE_SOCK_OPS, "bpf_sock_ops"},
	{BPF_PROG_TYPE_SOCKET_FILTER, "__sk_buff"},
	{BPF_PROG_TYPE_XDP, "xdp_md"},
}

// progCtxName returns the context struct name of progType, or "" for a type
// without a named context struct.
func progCtxName(progType BpfProgType) string {
	for _, e := range globalCtxMap {
		if e.progType == progType {
			return e.ctxName
		}
	}
	return ""
}

// userPtRegsStruct is the struct behind the kernel's bpf_user_pt_regs_t
// typedef on the host architecture, which a perf_event program's register
// argument points to.
func userPtRegsStruct() string {
	if runtime.GOARCH == "arm64" {
		return "user_pt_regs"
	}
	return "pt_regs"
}

// markBtfStatic gives static linkage to the BTF FUNC of every .text
// subprogram whose symbol is global or weak with hidden or internal
// visibility, so the verifier checks it in each caller's context as it does
// a static function. For each such subprogram, the first global FUNC with
// its name changes. Main programs keep their linkage.
func markBtfStatic(obj *BpfObject) error {
	spec := obj.btf
	for _, p := range obj.programs {
		if !p.markBtfStatic || !progIsSubprog(obj, p) {
			continue
		}
		for id := 1; id < len(spec.Types); id++ {
			t := &spec.Types[id]
			if t.Kind != btf.KindFunc || t.Vlen != btf.FuncGlobal || t.Name != p.name {
				continue
			}
			if err := spec.SetFuncLinkage(uint32(id), btf.FuncStatic); err != nil {
				return err
			}
			break
		}
	}
	return nil
}

// btfNeedsSanitization reports whether the kernel with the BTF features
// kern lacks one that the load's BTF sanitizer rewrites.
func btfNeedsSanitization(kern btf.KernelFeatures) bool {
	return !kern.Func || !kern.Datasec || !kern.GlobalFunc || !kern.Float ||
		!kern.DeclTag || !kern.TypeTag || !kern.Enum64 || !kern.QmarkDatasec ||
		!kern.Layout
}

// sanitizeBTF returns the BTF blob that the load passes to BPF_BTF_LOAD.
// When kern lacks a feature that btfNeedsSanitization checks, it is a copy
// of spec's blob with the types, names and header fields that need the
// feature rewritten, as btf.Spec.Sanitize describes, in which every type
// keeps its ID; otherwise it is spec's blob itself. A kernel without the
// layout section, any before Linux 7.1, always gets the copy, as with
// libbpf. Either way the blob carries the fixups already applied to spec,
// and spec keeps its original types:
// BpfObjectBTF returns the object BTF unsanitized, and the descriptor of
// the loaded blob is the object's BTF descriptor.
func sanitizeBTF(spec *btf.Spec, kern btf.KernelFeatures) ([]byte, error) {
	if !btfNeedsSanitization(kern) {
		return spec.Raw(), nil
	}
	return spec.Sanitize(kern)
}

// argCtxFixup is the state of fixupFuncInfo for one main program: its
// function records, the FUNC IDs they held before the fixup, and the pointer
// to the context struct once it exists.
type argCtxFixup struct {
	spec     *btf.Spec
	prog     *BpfProgram
	ctxName  string
	funcInfo []byte
	origIDs  []uint32
	ptrID    uint32
}

// fixupFuncInfo rewrites the BTF of global functions whose arguments carry
// the arg:ctx decl tag, for a kernel that does not read the tag. For each
// tag on a global FUNC that one of code's function records names, when the
// argument type is not one the verifier already takes as the context, it
// clones the FUNC and its FUNC_PROTO, points the record at the clone, adds a
// copy of the tag for the clone and makes the clone's argument a pointer to
// the program type's context struct. The struct and the pointer are added
// once for code. The original types stay, for the other main programs.
//
// Nothing changes without function records, when argCtxTag reports kernel
// support, or for a program type without a named context struct. The types
// are added to the object BTF, which the load passes to the kernel.
func fixupFuncInfo(obj *BpfObject, ext *btf.ExtSpec, code *progCode, argCtxTag func() bool) error {
	if ext == nil || len(code.funcInfo) == 0 {
		return nil
	}
	if argCtxTag() {
		return nil
	}
	ctxName := progCtxName(code.prog.progType)
	if ctxName == "" {
		return nil
	}

	f := &argCtxFixup{
		spec:     obj.btf,
		prog:     code.prog,
		ctxName:  ctxName,
		funcInfo: code.funcInfo,
	}
	for rec := 0; rec < f.recCnt(); rec++ {
		f.origIDs = append(f.origIDs, f.recTypeID(rec))
	}

	// The types the fixup adds are not visited.
	for id, n := uint32(1), uint32(len(f.spec.Types)); id < n; id++ {
		if err := f.fixTag(id); err != nil {
			return err
		}
	}
	return nil
}

// fixTag fixes up the argument that the type id tags, if id is an arg:ctx
// decl tag on a global function the main program calls and the argument
// needs it. A tag on anything else is skipped.
func (f *argCtxFixup) fixTag(id uint32) error {
	tag := &f.spec.Types[id]
	if tag.Kind != btf.KindDeclTag || tag.Name != argCtxTag || tag.DeclTag == nil {
		return nil
	}
	origFnID, argIdx := tag.SizeOrType, tag.DeclTag.ComponentIdx

	fn, err := f.spec.TypeByID(origFnID)
	if err != nil || fn.Kind != btf.KindFunc || fn.Vlen != btf.FuncGlobal {
		return nil
	}
	proto, err := f.spec.TypeByID(fn.SizeOrType)
	if err != nil || proto.Kind != btf.KindFuncProto {
		return nil
	}
	rec := slices.Index(f.origIDs, origFnID)
	if rec < 0 {
		return nil
	}
	if argIdx < 0 || int(argIdx) >= len(proto.Params) {
		return nil
	}
	if !needFuncArgTypeFixup(f.spec, f.prog.progType, proto.Params[argIdx].Type, f.ctxName) {
		return nil
	}

	// A function with several tagged arguments is cloned once.
	if f.recTypeID(rec) == origFnID {
		fnID, err := cloneFuncBtfInfo(f.spec, origFnID, f.prog)
		if err != nil {
			return err
		}
		f.setRecTypeID(rec, fnID)
	}
	if err := f.addCtxPtr(); err != nil {
		return err
	}

	fnID := f.recTypeID(rec)
	if _, err := f.spec.AddDeclTag(argCtxTag, fnID, argIdx); err != nil {
		return err
	}
	clone, err := f.spec.TypeByID(fnID)
	if err != nil {
		return err
	}
	return f.spec.SetParamType(clone.SizeOrType, int(argIdx), f.ptrID)
}

// addCtxPtr adds the context struct, empty, and a pointer to it, the first
// time the main program needs them. Every global function the program calls
// shares them, because they all take the program type's context.
func (f *argCtxFixup) addCtxPtr() error {
	if f.ptrID != 0 {
		return nil
	}
	structID, err := f.spec.AddStruct(f.ctxName, 0)
	if err != nil {
		return err
	}
	f.ptrID, err = f.spec.AddPtr(structID)
	return err
}

// recCnt returns the number of function records.
func (f *argCtxFixup) recCnt() int {
	return len(f.funcInfo) / btf.FuncInfoMinSize
}

// recTypeID returns the FUNC ID of function record rec.
func (f *argCtxFixup) recTypeID(rec int) uint32 {
	return binary.NativeEndian.Uint32(f.funcInfo[rec*btf.FuncInfoMinSize+bpfFuncInfoOffTypeID:])
}

// setRecTypeID writes the FUNC ID of function record rec.
func (f *argCtxFixup) setRecTypeID(rec int, typeID uint32) {
	binary.NativeEndian.PutUint32(f.funcInfo[rec*btf.FuncInfoMinSize+bpfFuncInfoOffTypeID:], typeID)
}

// needFuncArgTypeFixup reports whether the argument type argTypeID of a
// global function must become a pointer to ctxName, the context struct of
// progType, for the verifier to take it as the context. A void pointer
// needs it. A pointer to ctxName does not. A kprobe's struct pt_regs
// pointer, a perf_event's pointer to the architecture's register struct and
// a raw tracepoint's 64-bit integer pointer need it. Any other type is left
// alone; libbpf only warns that it is not a context pointer.
func needFuncArgTypeFixup(spec *btf.Spec, progType BpfProgType, argTypeID uint32, ctxName string) bool {
	t, _ := skipModsAndTypedefs(spec, argTypeID)
	if t == nil || t.Kind != btf.KindPtr {
		return false
	}

	// The bpf_user_pt_regs_t typedef is the canonical kprobe and perf_event
	// context. As in libbpf, t is the pointer here, not what it points
	// to, so the check does not match and a pointer to the typedef is
	// judged by the struct behind it below.
	for isBtfMod(t) {
		if t, _ = spec.TypeByID(t.SizeOrType); t == nil {
			return false
		}
	}
	if t.Kind == btf.KindTypedef && (progType == BPF_PROG_TYPE_KPROBE || progType == BPF_PROG_TYPE_PERF_EVENT) &&
		t.Name == "bpf_user_pt_regs_t" {
		return false
	}

	t, _ = skipModsAndTypedefs(spec, t.SizeOrType)
	if t == nil {
		return false
	}
	if t.Kind == btf.KindVoid {
		return true
	}
	isStruct := t.Kind == btf.KindStruct
	if isStruct && t.Name == ctxName {
		return false
	}

	switch progType {
	case BPF_PROG_TYPE_KPROBE:
		return isStruct && t.Name == "pt_regs"
	case BPF_PROG_TYPE_PERF_EVENT:
		return isStruct && t.Name == userPtRegsStruct()
	case BPF_PROG_TYPE_RAW_TRACEPOINT, BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE:
		return t.Kind == btf.KindInt && t.SizeOrType == 8
	}
	return false
}

// isBtfMod reports whether t is a type modifier: volatile, const, restrict
// or a type tag.
func isBtfMod(t *btf.Type) bool {
	switch t.Kind {
	case btf.KindVolatile, btf.KindConst, btf.KindRestrict, btf.KindTypeTag:
		return true
	}
	return false
}

// cloneFuncBtfInfo appends a copy of the FUNC origFnID and of its
// FUNC_PROTO, with the same name, linkage, return type and parameter names
// and types, and returns the new FUNC's ID. The caller has checked that
// origFnID is a FUNC of a FUNC_PROTO. The parameters are added unnamed and
// the FUNC under the main program's name, then renamed to the original
// strings, so the string table grows exactly as in libbpf.
func cloneFuncBtfInfo(spec *btf.Spec, origFnID uint32, prog *BpfProgram) (uint32, error) {
	fn, err := spec.TypeByID(origFnID)
	if err != nil {
		return 0, err
	}
	fnNameOff, linkage, origProtoID := fn.NameOff, fn.Vlen, fn.SizeOrType
	proto, err := spec.TypeByID(origProtoID)
	if err != nil {
		return 0, err
	}
	retTypeID, params := proto.SizeOrType, slices.Clone(proto.Params)

	protoID, err := spec.AddFuncProto(retTypeID)
	if err != nil {
		return 0, fmt.Errorf("clone FUNC_PROTO %d: %w", origProtoID, err)
	}
	for i, p := range params {
		if err := spec.AddFuncParam("", p.Type); err != nil {
			return 0, err
		}
		if err := spec.SetParamNameOff(protoID, i, p.NameOff); err != nil {
			return 0, err
		}
	}

	fnID, err := spec.AddFunc(prog.name, linkage, protoID)
	if err != nil {
		return 0, fmt.Errorf("clone FUNC %d: %w", origFnID, err)
	}
	if err := spec.SetNameOff(fnID, fnNameOff); err != nil {
		return 0, err
	}
	return fnID, nil
}
