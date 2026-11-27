// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/btf.c
// libbpf-source: src/strset.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: btf__add_var, btf__add_str, strset__add_str, strset__new, btf__add_ptr, btf__add_struct, btf__add_func, btf__add_func_proto, btf__add_func_param, btf__add_decl_tag, btf_add_ref_kind, btf_add_composite, btf_add_decl_tag, validate_type_id

package btf

import (
	"bytes"
	"fmt"
)

// AddVar appends a VAR type named name with linkage and type typeID, and
// returns its ID. The name reuses the first string of the table equal to
// it, or is appended to the table. The blob is rebuilt, so Raw returns the
// header, the types and then the strings.
//
// An empty name, a linkage other than VarStatic, VarGlobalAllocated or
// VarGlobalExtern, or a split spec is an error.
func (s *Spec) AddVar(name string, linkage, typeID uint32) (uint32, error) {
	if err := s.checkModifiable(); err != nil {
		return 0, err
	}
	if name == "" {
		return 0, fmt.Errorf("btf: VAR without a name")
	}
	if linkage != VarStatic && linkage != VarGlobalAllocated && linkage != VarGlobalExtern {
		return 0, fmt.Errorf("btf: VAR %s: invalid linkage %d", name, linkage)
	}

	return s.addType(Type{
		NameOff:    s.addString(name),
		Name:       name,
		Kind:       KindVar,
		SizeOrType: typeID,
		Var:        &Var{Linkage: linkage},
	})
}

// AddPtr appends a PTR type to refID and returns its ID. An out-of-range
// type ID or a split spec is an error.
func (s *Spec) AddPtr(refID uint32) (uint32, error) {
	return s.addRefKind(KindPtr, "", refID)
}

// AddStruct appends a STRUCT type named name, of size bytes and without
// members, and returns its ID. An empty name makes an anonymous struct. The
// name reuses a string of the table like AddVar. A split spec is an error.
func (s *Spec) AddStruct(name string, size uint32) (uint32, error) {
	if err := s.checkModifiable(); err != nil {
		return 0, err
	}
	var nameOff uint32
	if name != "" {
		nameOff = s.addString(name)
	}
	return s.addType(Type{NameOff: nameOff, Name: name, Kind: KindStruct, SizeOrType: size})
}

// AddFuncProto appends a FUNC_PROTO type returning retID, without
// parameters, and returns its ID. AddFuncParam adds the parameters. An
// out-of-range type ID or a split spec is an error.
func (s *Spec) AddFuncProto(retID uint32) (uint32, error) {
	if err := s.checkModifiable(); err != nil {
		return 0, err
	}
	if err := validateTypeID(retID); err != nil {
		return 0, err
	}
	return s.addType(Type{Kind: KindFuncProto, SizeOrType: retID})
}

// AddFuncParam appends a parameter named name of type typeID to the last
// type, which must be a FUNC_PROTO. An empty name makes an unnamed
// parameter. An out-of-range type ID or a split spec is an error.
func (s *Spec) AddFuncParam(name string, typeID uint32) error {
	if err := validateTypeID(typeID); err != nil {
		return err
	}
	if len(s.Types) < 2 || s.Types[len(s.Types)-1].Kind != KindFuncProto {
		return fmt.Errorf("btf: last type is not a FUNC_PROTO")
	}
	if err := s.checkModifiable(); err != nil {
		return err
	}

	var nameOff uint32
	if name != "" {
		nameOff = s.addString(name)
	}
	proto := &s.Types[len(s.Types)-1]
	proto.Params = append(proto.Params, Param{NameOff: nameOff, Name: name, Type: typeID})
	return s.encode()
}

// AddFunc appends a FUNC type named name with linkage and prototype protoID,
// and returns its ID. An empty name, a linkage other than FuncStatic,
// FuncGlobal or FuncExtern, an out-of-range type ID or a split spec is an
// error.
func (s *Spec) AddFunc(name string, linkage, protoID uint32) (uint32, error) {
	if name == "" {
		return 0, fmt.Errorf("btf: FUNC without a name")
	}
	if linkage != FuncStatic && linkage != FuncGlobal && linkage != FuncExtern {
		return 0, fmt.Errorf("btf: FUNC %s: invalid linkage %d", name, linkage)
	}
	id, err := s.addRefKind(KindFunc, name, protoID)
	if err != nil {
		return 0, err
	}
	if err := s.SetFuncLinkage(id, linkage); err != nil {
		return 0, err
	}
	return id, nil
}

// AddDeclTag appends a DECL_TAG type with value, tagging refID, and returns
// its ID. componentIdx is the member or parameter the tag applies to, or -1
// for refID itself. An empty value, a componentIdx below -1, an out-of-range
// type ID or a split spec is an error.
func (s *Spec) AddDeclTag(value string, refID uint32, componentIdx int32) (uint32, error) {
	if value == "" || componentIdx < -1 {
		return 0, fmt.Errorf("btf: invalid DECL_TAG %q on component %d", value, componentIdx)
	}
	if err := validateTypeID(refID); err != nil {
		return 0, err
	}
	if err := s.checkModifiable(); err != nil {
		return 0, err
	}
	return s.addType(Type{
		NameOff:    s.addString(value),
		Name:       value,
		Kind:       KindDeclTag,
		SizeOrType: refID,
		DeclTag:    &DeclTag{ComponentIdx: componentIdx},
	})
}

// addRefKind appends a type of kind that refers to refID, with an optional
// name, and returns its ID.
func (s *Spec) addRefKind(kind Kind, name string, refID uint32) (uint32, error) {
	if err := validateTypeID(refID); err != nil {
		return 0, err
	}
	if err := s.checkModifiable(); err != nil {
		return 0, err
	}
	var nameOff uint32
	if name != "" {
		nameOff = s.addString(name)
	}
	return s.addType(Type{NameOff: nameOff, Name: name, Kind: kind, SizeOrType: refID})
}

// addType appends t with the next type ID, rebuilds the blob and returns the
// ID.
func (s *Spec) addType(t Type) (uint32, error) {
	t.ID = uint32(len(s.Types))
	s.Types = append(s.Types, t)
	if err := s.encode(); err != nil {
		return 0, err
	}
	return t.ID, nil
}

// checkModifiable rejects adding types to a split spec, whose types and
// strings continue a base spec's.
func (s *Spec) checkModifiable() error {
	if s.base != nil || s.mergedSplit {
		return fmt.Errorf("btf: cannot add a type to split BTF")
	}
	return nil
}

// validateTypeID rejects a type ID past the largest one BTF can hold.
func validateTypeID(id uint32) error {
	if id > maxNrTypes {
		return fmt.Errorf("btf: type id %d out of range", id)
	}
	return nil
}

// addString returns the offset of str in the string table. The first string
// that starts after a NUL and equals str is reused; otherwise str is appended
// with its NUL.
func (s *Spec) addString(str string) uint32 {
	if off, ok := findString(s.Strings, str); ok {
		return off
	}
	off := uint32(len(s.Strings))
	strs := make([]byte, 0, len(s.Strings)+len(str)+1)
	strs = append(append(append(strs, s.Strings...), str...), 0)
	s.Strings = strs
	return off
}

// findString returns the offset of the first string of the table strs, at
// its start or right after a NUL, that equals str, and whether there is one.
func findString(strs []byte, str string) (uint32, bool) {
	for off := 0; off < len(strs); {
		end := bytes.IndexByte(strs[off:], 0)
		if end < 0 {
			break
		}
		if string(strs[off:off+end]) == str {
			return uint32(off), true
		}
		off += end + 1
	}
	return 0, false
}

// SetVarType writes typeID into the type field of the VAR type id, in both
// the raw blob and the parsed type. It returns an error when id is not a VAR.
func (s *Spec) SetVarType(id, typeID uint32) error {
	t, err := s.TypeByID(id)
	if err != nil {
		return err
	}
	if t.Kind != KindVar {
		return fmt.Errorf("btf: type %d is %v, not a VAR", id, t.Kind)
	}
	if err := s.patchWord(t, 8, typeID); err != nil {
		return err
	}
	t.SizeOrType = typeID
	return nil
}

// SetFuncLinkage writes linkage, the vlen of a FUNC's info word, into the
// FUNC type id, in both the raw blob and the parsed type. It returns an
// error when id is not a FUNC.
func (s *Spec) SetFuncLinkage(id, linkage uint32) error {
	t, err := s.TypeByID(id)
	if err != nil {
		return err
	}
	if t.Kind != KindFunc {
		return fmt.Errorf("btf: type %d is %v, not a FUNC", id, t.Kind)
	}
	info := t.Info&^0xffff | linkage&0xffff
	if err := s.patchWord(t, 4, info); err != nil {
		return err
	}
	t.Info = info
	t.Vlen = linkage & 0xffff
	return nil
}

// SetParamNameOff writes nameOff into the name of parameter j of the
// FUNC_PROTO type id, in both the raw blob and the parsed type. It returns an
// error when id is not a FUNC_PROTO, j is not one of its parameters or
// nameOff is not a string of the table.
func (s *Spec) SetParamNameOff(id uint32, j int, nameOff uint32) error {
	t, err := s.TypeByID(id)
	if err != nil {
		return err
	}
	if t.Kind != KindFuncProto {
		return fmt.Errorf("btf: type %d is %v, not a FUNC_PROTO", id, t.Kind)
	}
	if j < 0 || j >= len(t.Params) {
		return fmt.Errorf("btf: func_proto %d: parameter %d out of range", id, j)
	}
	name, err := s.String(nameOff)
	if err != nil {
		return err
	}
	if err := s.patchWord(t, 12+j*8, nameOff); err != nil {
		return err
	}
	t.Params[j].NameOff = nameOff
	t.Params[j].Name = name
	return nil
}

// SetParamType writes typeID into the type of parameter j of the FUNC_PROTO
// type id, in both the raw blob and the parsed type. It returns an error when
// id is not a FUNC_PROTO or j is not one of its parameters.
func (s *Spec) SetParamType(id uint32, j int, typeID uint32) error {
	t, err := s.TypeByID(id)
	if err != nil {
		return err
	}
	if t.Kind != KindFuncProto {
		return fmt.Errorf("btf: type %d is %v, not a FUNC_PROTO", id, t.Kind)
	}
	if j < 0 || j >= len(t.Params) {
		return fmt.Errorf("btf: func_proto %d: parameter %d out of range", id, j)
	}
	if err := s.patchWord(t, 12+j*8+4, typeID); err != nil {
		return err
	}
	t.Params[j].Type = typeID
	return nil
}

// SetNameOff writes nameOff into the name of type id, in both the raw blob
// and the parsed type. It returns an error when nameOff is not a string of
// the table.
func (s *Spec) SetNameOff(id, nameOff uint32) error {
	t, err := s.TypeByID(id)
	if err != nil {
		return err
	}
	name, err := s.String(nameOff)
	if err != nil {
		return err
	}
	if err := s.patchWord(t, 0, nameOff); err != nil {
		return err
	}
	t.NameOff = nameOff
	t.Name = name
	return nil
}

// SetDatasecVar writes vsi into member j of the DATASEC type id, in both the
// raw blob and the parsed type. It returns an error when id is not a DATASEC
// or j is not one of its members.
func (s *Spec) SetDatasecVar(id uint32, j int, vsi VarSecInfo) error {
	t, err := s.datasec(id)
	if err != nil {
		return err
	}
	if j < 0 || j >= len(t.DataSec) {
		return fmt.Errorf("btf: datasec %s: member %d out of range", t.Name, j)
	}
	off := 12 + j*12
	for i, word := range []uint32{vsi.Type, vsi.Offset, vsi.Size} {
		if err := s.patchWord(t, off+4*i, word); err != nil {
			return err
		}
	}
	t.DataSec[j] = vsi
	return nil
}

// patchWord writes word at byte off of t's record in the raw blob.
func (s *Spec) patchWord(t *Type, off int, word uint32) error {
	return s.putRecordWord(s.raw, t, off, word)
}

// putRecordWord writes word at byte off of t's record in raw, which is the
// spec's blob or a copy of it with the same layout.
func (s *Spec) putRecordWord(raw []byte, t *Type, off int, word uint32) error {
	if s.base != nil || raw == nil {
		return fmt.Errorf("btf: type %d has no raw record", t.ID)
	}
	pos := s.typeStart + int(t.rawOff) + off
	if pos < 0 || pos+4 > len(raw) {
		return fmt.Errorf("btf: type %d: field at %d out of bounds", t.ID, off)
	}
	s.ByteOrder.PutUint32(raw[pos:], word)
	return nil
}
