// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

package btf

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

// declTagSpec returns a spec with decl tags on a struct member, a function
// parameter and a variable, one of them with the kind flag, between and
// after other types.
func declTagSpec(t *testing.T) *Spec {
	t.Helper()

	return buildSpec(t, []Type{
		{Kind: KindVoid},
		{NameOff: 1, Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 1<<24 | 32}},
		{NameOff: 5, Kind: KindStruct, SizeOrType: 4, Members: []Member{{NameOff: 7, Type: 1}}},
		{NameOff: 9, Kind: KindVar, SizeOrType: 1, Var: &Var{Linkage: VarStatic}},
		{Kind: KindFuncProto, SizeOrType: 1, Params: []Param{{NameOff: 11, Type: 1}}},
		{NameOff: 13, Kind: KindFunc, SizeOrType: 4, Vlen: FuncGlobal},
		{NameOff: 15, Kind: KindDeclTag, SizeOrType: 2, DeclTag: &DeclTag{ComponentIdx: 0}},
		{NameOff: 19, Kind: KindDeclTag, SizeOrType: 5, DeclTag: &DeclTag{ComponentIdx: 0}},
		{NameOff: 15, Kind: KindDeclTag, KindFlag: true, SizeOrType: 3, DeclTag: &DeclTag{ComponentIdx: -1}},
		{Kind: KindPtr, SizeOrType: 2},
	}, "\x00int\x00s\x00x\x00v\x00a\x00f\x00tag\x00arg:ctx\x00")
}

// TestSanitizeDeclTags sanitizes a spec with three decl tags. The copy has
// the blob's length, header and string table; each tag is now an unflagged
// INT of size 1 with encoding word 8 under the tag's name and type ID, and
// every other type parses back unchanged. The spec keeps its decl tags and
// its blob.
func TestSanitizeDeclTags(t *testing.T) {
	spec := declTagSpec(t)
	orig := bytes.Clone(spec.Raw())

	raw, err := spec.SanitizeDeclTags()
	mustSucceed(t, "SanitizeDeclTags", err)
	if !bytes.Equal(spec.Raw(), orig) {
		t.Fatal("SanitizeDeclTags changed the spec's blob")
	}
	for _, id := range []int{6, 7, 8} {
		if spec.Types[id].Kind != KindDeclTag {
			t.Fatalf("spec type %d is %v after SanitizeDeclTags, want its DECL_TAG", id, spec.Types[id].Kind)
		}
	}
	if len(raw) != len(orig) || &raw[0] == &orig[0] {
		t.Fatalf("copy has %d bytes at %p, want %d bytes in a new buffer", len(raw), &raw[0], len(orig))
	}
	if hdr := spec.Header.HdrLen; !bytes.Equal(raw[:hdr], orig[:hdr]) {
		t.Error("header changed")
	}

	sanitized, err := Parse(raw, binary.LittleEndian)
	mustSucceed(t, "Parse", err)
	if !bytes.Equal(sanitized.Strings, spec.Strings) {
		t.Errorf("strings = %q, want %q", sanitized.Strings, spec.Strings)
	}
	if len(sanitized.Types) != len(spec.Types) {
		t.Fatalf("%d types, want %d", len(sanitized.Types), len(spec.Types))
	}
	for id := range spec.Types {
		checkSanitizedType(t, &spec.Types[id], &sanitized.Types[id])
	}
}

// checkSanitizedType checks the type got that sanitizing want's blob made:
// an INT in place of a decl tag, and want itself otherwise.
func checkSanitizedType(t *testing.T, want, got *Type) {
	t.Helper()

	if want.Kind != KindDeclTag {
		if !reflect.DeepEqual(got, want) {
			t.Errorf("type %d = %+v, want it unchanged as %+v", want.ID, got, want)
		}
		return
	}
	if want.DeclTag == nil {
		t.Fatalf("type %d: decl tag without payload", want.ID)
	}
	if got.ID != want.ID || got.Kind != KindInt || got.KindFlag || got.Vlen != 0 {
		t.Errorf("type %d = %v kind flag %v vlen %d, want an INT %d without kind flag or vlen", got.ID, got.Kind, got.KindFlag, got.Vlen, want.ID)
	}
	if got.SizeOrType != 1 || got.Int == nil || got.Int.Encoding != 8 {
		t.Errorf("type %d: size %d, int %+v, want size 1 and encoding word 8", got.ID, got.SizeOrType, got.Int)
	}
	if got.NameOff != want.NameOff || got.Name != want.Name {
		t.Errorf("type %d named %q at %d, want the tag's %q at %d", got.ID, got.Name, got.NameOff, want.Name, want.NameOff)
	}
}

// TestSanitizeDeclTagsNone sanitizes a spec without decl tags, which comes
// back as an equal copy, and a split spec, which is an error.
func TestSanitizeDeclTagsNone(t *testing.T) {
	spec := buildSpec(t, []Type{
		{Kind: KindVoid},
		{NameOff: 1, Kind: KindInt, SizeOrType: 4, Int: &Int{Encoding: 32}},
	}, "\x00int\x00")

	raw, err := spec.SanitizeDeclTags()
	mustSucceed(t, "SanitizeDeclTags", err)
	if !bytes.Equal(raw, spec.Raw()) || &raw[0] == &spec.Raw()[0] {
		t.Error("blob without decl tags did not come back as an equal copy")
	}

	split := &Spec{base: spec}
	if _, err := split.SanitizeDeclTags(); err == nil {
		t.Error("SanitizeDeclTags on split BTF succeeded")
	}
}
