// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

package btf

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestAddFuncTypes builds a FUNC_PROTO with two parameters, a FUNC, a STRUCT,
// a PTR and a DECL_TAG on a parsed spec, then renames the FUNC and retypes a
// parameter. Names reuse the existing strings and only new ones are
// appended; the rebuilt blob parses back to the same types.
func TestAddFuncTypes(t *testing.T) {
	spec := buildSpec(t, []Type{
		{Kind: KindVoid},
		{NameOff: 1, Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 1<<24 | 32}},
	}, "\x00int\x00ctx\x00orig\x00")
	strs := string(spec.Strings)

	protoID, err := spec.AddFuncProto(1)
	mustSucceed(t, "AddFuncProto", err)
	mustSucceed(t, "AddFuncParam(x)", spec.AddFuncParam("x", 1))
	mustSucceed(t, "AddFuncParam(ctx)", spec.AddFuncParam("ctx", 0))
	fnID, err := spec.AddFunc("main", FuncGlobal, protoID)
	mustSucceed(t, "AddFunc", err)
	structID, err := spec.AddStruct("bpf_user_pt_regs_t", 0)
	mustSucceed(t, "AddStruct", err)
	ptrID, err := spec.AddPtr(structID)
	mustSucceed(t, "AddPtr", err)
	tagID, err := spec.AddDeclTag("arg:ctx", fnID, 1)
	mustSucceed(t, "AddDeclTag", err)
	mustSucceed(t, "SetNameOff", spec.SetNameOff(fnID, 9))
	mustSucceed(t, "SetParamType", spec.SetParamType(protoID, 1, ptrID))

	if ids := [...]uint32{protoID, fnID, structID, ptrID, tagID}; ids != [...]uint32{2, 3, 4, 5, 6} {
		t.Fatalf("type IDs = %v, want 2 to 6", ids)
	}
	if want := strs + "x\x00main\x00bpf_user_pt_regs_t\x00arg:ctx\x00"; string(spec.Strings) != want {
		t.Fatalf("strings = %q, want %q", spec.Strings, want)
	}

	reparsed, err := Parse(spec.Raw(), binary.LittleEndian)
	mustSucceed(t, "Parse", err)
	for _, s := range []*Spec{spec, reparsed} {
		checkAddedTypes(t, s)
	}
}

// checkAddedTypes checks the types TestAddFuncTypes added to s.
func checkAddedTypes(t *testing.T, s *Spec) {
	t.Helper()

	proto, fn, st, ptr, tag := s.Types[2], s.Types[3], s.Types[4], s.Types[5], s.Types[6]
	if proto.Kind != KindFuncProto || proto.SizeOrType != 1 || len(proto.Params) != 2 ||
		proto.Params[0] != (Param{NameOff: 14, Name: "x", Type: 1}) ||
		proto.Params[1] != (Param{NameOff: 5, Name: "ctx", Type: 5}) {
		t.Errorf("FUNC_PROTO = %+v", proto)
	}
	if fn.Kind != KindFunc || fn.Name != "orig" || fn.Vlen != FuncGlobal || fn.SizeOrType != 2 {
		t.Errorf("FUNC = %+v", fn)
	}
	if st.Kind != KindStruct || st.Name != "bpf_user_pt_regs_t" || st.SizeOrType != 0 || len(st.Members) != 0 {
		t.Errorf("STRUCT = %+v", st)
	}
	if ptr.Kind != KindPtr || ptr.NameOff != 0 || ptr.SizeOrType != 4 {
		t.Errorf("PTR = %+v", ptr)
	}
	if tag.Kind != KindDeclTag || tag.Name != "arg:ctx" || tag.SizeOrType != 3 || tag.DeclTag.ComponentIdx != 1 {
		t.Errorf("DECL_TAG = %+v", tag)
	}
}

// TestAddFuncTypesErrors checks the arguments the builders reject: a
// parameter without a FUNC_PROTO before it, an empty or unknown-linkage
// FUNC, a DECL_TAG without a value or below component -1, an out-of-range
// type ID, a bad name offset and a split spec.
func TestAddFuncTypesErrors(t *testing.T) {
	spec := buildSpec(t, []Type{
		{Kind: KindVoid},
		{NameOff: 1, Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 32}},
	}, "\x00int\x00")
	raw := bytes.Clone(spec.Raw())

	_, errFunc := spec.AddFunc("", FuncGlobal, 0)
	_, errLinkage := spec.AddFunc("f", 3, 0)
	_, errTagValue := spec.AddDeclTag("", 1, 0)
	_, errTagIdx := spec.AddDeclTag("t", 1, -2)
	_, errPtr := spec.AddPtr(maxNrTypes + 1)
	_, errProto := spec.AddFuncProto(maxNrTypes + 1)
	for name, err := range map[string]error{
		"AddFuncParam without FUNC_PROTO": spec.AddFuncParam("x", 1),
		"AddFunc without a name":          errFunc,
		"AddFunc with linkage 3":          errLinkage,
		"AddDeclTag without a value":      errTagValue,
		"AddDeclTag on component -2":      errTagIdx,
		"AddPtr past the last type ID":    errPtr,
		"AddFuncProto past the last ID":   errProto,
		"SetNameOff past the strings":     spec.SetNameOff(1, 100),
		"SetParamType on an INT":          spec.SetParamType(1, 0, 1),
	} {
		if err == nil {
			t.Errorf("%s succeeded", name)
		}
	}
	if !bytes.Equal(spec.Raw(), raw) {
		t.Error("a rejected call changed the blob")
	}

	split := &Spec{base: spec}
	if _, err := split.AddStruct("s", 0); err == nil {
		t.Error("AddStruct on split BTF succeeded")
	}
}

func mustSucceed(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}
