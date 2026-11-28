// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

const (
	sanitizeTypeTagObject = "sanitize_type_tag.bpf.o"
	sanitizeEnum64Object  = "sanitize_enum64.bpf.o"
	sanitizeFloatObject   = "sanitize_float.bpf.o"
)

// parseProbeBTF parses the BTF blob of a feature probe and checks its
// layout: a 32-byte header, typeLen bytes of types right after it and then
// exactly the string table strs.
func parseProbeBTF(t *testing.T, raw []byte, typeLen uint32, strs string) *btf.Spec {
	t.Helper()

	spec, err := btf.Parse(raw, binary.NativeEndian)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := btf.Header{
		Magic:   0xeb9f,
		Version: 1,
		HdrLen:  rawBTFHdrLen,
		TypeLen: typeLen,
		StrOff:  typeLen,
		StrLen:  uint32(len(strs)),
	}
	if spec.Header != want {
		t.Errorf("header = %+v, want %+v", spec.Header, want)
	}
	if len(raw) != rawBTFHdrLen+int(typeLen)+len(strs) || string(spec.Strings) != strs {
		t.Errorf("%d bytes with strings %q, want %d bytes with %q", len(raw), spec.Strings, rawBTFHdrLen+int(typeLen)+len(strs), strs)
	}
	return spec
}

// checkSignedInt32 checks that type id of spec is a signed 32-bit INT.
func checkSignedInt32(t *testing.T, spec *btf.Spec, id uint32) {
	t.Helper()

	if enc := spec.Types[id].Int; enc == nil || enc.Encoding != 1<<24|32 {
		t.Errorf("INT %d encoding = %+v, want signed 32 bits", id, enc)
	}
}

// TestBtfTypeTagProbeBTF parses the BTF the type tag probe loads: a signed
// 32-bit int, a type tag named tag on it and a pointer to the tag.
func TestBtfTypeTagProbeBTF(t *testing.T) {
	spec := parseProbeBTF(t, typeTagBTF(), 40, "\x00tag\x00")
	checkArgCtxTypes(t, spec, 1, []argCtxType{
		{btf.KindInt, "", 4, 0}, {btf.KindTypeTag, "tag", 1, 0}, {btf.KindPtr, "", 2, 0},
	})
	checkSignedInt32(t, spec, 1)
	if spec.Types[2].KindFlag {
		t.Error("TYPE_TAG has the kind flag")
	}
}

// TestBtfEnum64ProbeBTF parses the BTF the enum64 probe loads: one
// unsigned ENUM64 named enum64, of 8 bytes and without values.
func TestBtfEnum64ProbeBTF(t *testing.T) {
	spec := parseProbeBTF(t, enum64BTF(), 12, "\x00enum64\x00")
	checkArgCtxTypes(t, spec, 1, []argCtxType{{btf.KindEnum64, "enum64", 8, 0}})
	if e := spec.Types[1]; e.KindFlag || e.Vlen != 0 {
		t.Errorf("ENUM64 kind flag %v, vlen %d; want neither", e.KindFlag, e.Vlen)
	}
}

// TestBtfQmarkDatasecProbeBTF parses the BTF the '?' DATASEC probe loads: a
// signed 32-bit int, a static variable x of it, and a 4-byte DATASEC named
// ?.data that holds x at offset 0.
func TestBtfQmarkDatasecProbeBTF(t *testing.T) {
	spec := parseProbeBTF(t, qmarkDatasecBTF(), 56, "\x00x\x00?.data\x00")
	checkArgCtxTypes(t, spec, 1, []argCtxType{
		{btf.KindInt, "", 4, 0}, {btf.KindVar, "x", 1, 0}, {btf.KindDatasec, "?.data", 4, 0},
	})
	checkSignedInt32(t, spec, 1)
	if v := spec.Types[2].Var; v == nil || v.Linkage != btf.VarStatic {
		t.Errorf("VAR = %+v, want static linkage", v)
	}
	if ds := spec.Types[3].DataSec; !slices.Equal(ds, []btf.VarSecInfo{{Type: 2, Offset: 0, Size: 4}}) {
		t.Errorf("DATASEC variables = %+v, want x at offset 0 of size 4", ds)
	}
}

// TestBtfFloatProbeBTF parses the BTF the float probe loads: one FLOAT
// named float, of 4 bytes.
func TestBtfFloatProbeBTF(t *testing.T) {
	spec := parseProbeBTF(t, floatBTF(), 12, "\x00float\x00")
	checkArgCtxTypes(t, spec, 1, []argCtxType{{btf.KindFloat, "float", 4, 0}})
	if f := spec.Types[1]; f.KindFlag || f.Vlen != 0 {
		t.Errorf("FLOAT kind flag %v, vlen %d; want neither", f.KindFlag, f.Vlen)
	}
}

// TestBtfNeedsSanitization checks that the load sanitizes the BTF for a
// kernel that lacks any one of the nine BTF features, and passes the object
// BTF itself to a kernel that has them all.
func TestBtfNeedsSanitization(t *testing.T) {
	if btfNeedsSanitization(allBTFFeatures) {
		t.Error("a kernel with every BTF feature needs sanitization")
	}
	for _, tt := range []struct {
		name  string
		clear func(*btf.KernelFeatures)
	}{
		{"decl tag", func(k *btf.KernelFeatures) { k.DeclTag = false }},
		{"type tag", func(k *btf.KernelFeatures) { k.TypeTag = false }},
		{"enum64", func(k *btf.KernelFeatures) { k.Enum64 = false }},
		{"qmark datasec", func(k *btf.KernelFeatures) { k.QmarkDatasec = false }},
		{"float", func(k *btf.KernelFeatures) { k.Float = false }},
		{"func", func(k *btf.KernelFeatures) { k.Func = false }},
		{"datasec", func(k *btf.KernelFeatures) { k.Datasec = false }},
		{"global func", func(k *btf.KernelFeatures) { k.GlobalFunc = false }},
		{"layout", func(k *btf.KernelFeatures) { k.Layout = false }},
	} {
		kern := allBTFFeatures
		tt.clear(&kern)
		if !btfNeedsSanitization(kern) {
			t.Errorf("a kernel without %s needs no sanitization", tt.name)
		}
	}

	obj := openSubprogObject(t, sanitizeTypeTagObject)
	raw, err := sanitizeBTF(obj.btf, allBTFFeatures)
	if err != nil || len(raw) == 0 || &raw[0] != &obj.btf.Raw()[0] {
		t.Errorf("BTF for a kernel with every feature is not the object BTF itself: %v", err)
	}
}

// sanitizeObjectBTF opens the fixture name, sanitizes its BTF for a kernel
// without DECL_TAG, TYPE_TAG, ENUM64, '?' DATASEC names and FLOAT, but with
// FUNC, DATASEC, global functions and the layout section, and returns the
// object BTF and the copy, both parsed from their blobs. The object BTF
// must keep its bytes.
func sanitizeObjectBTF(t *testing.T, name string) (orig, sanitized *btf.Spec) {
	t.Helper()

	obj := openSubprogObject(t, name)
	opened := bytes.Clone(obj.btf.Raw())
	raw, err := sanitizeBTF(obj.btf, btf.KernelFeatures{Func: true, Datasec: true, GlobalFunc: true, Layout: true})
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if !bytes.Equal(obj.btf.Raw(), opened) {
		t.Fatal("sanitizing changed the object BTF")
	}
	if orig, err = btf.Parse(opened, obj.elf.ByteOrder); err != nil {
		t.Fatalf("parse the object BTF: %v", err)
	}
	if sanitized, err = btf.Parse(raw, obj.elf.ByteOrder); err != nil {
		t.Fatalf("parse the sanitized BTF: %v", err)
	}
	return orig, sanitized
}

// findType returns the type of kind named name in spec.
func findType(t *testing.T, spec *btf.Spec, name string, kind btf.Kind) *btf.Type {
	t.Helper()

	typ := spec.Find(name, kind)
	if typ == nil {
		t.Fatalf("no %v %s in the object BTF", kind, name)
	}
	return typ
}

// checkTypesKept checks that every type of orig but those in changed has
// the same ID and record in sanitized.
func checkTypesKept(t *testing.T, orig, sanitized *btf.Spec, changed ...uint32) {
	t.Helper()

	for id := range orig.Types {
		if slices.Contains(changed, uint32(id)) {
			continue
		}
		if want, got := &orig.Types[id], &sanitized.Types[id]; !reflect.DeepEqual(got, want) {
			t.Errorf("type %d = %+v, want it unchanged as %+v", id, got, want)
		}
	}
}

// TestSanitizeTypeTagObject sanitizes the BTF of sanitize_type_tag.bpf.o,
// where clang puts a TYPE_TAG named user between the global pointer and
// int. The copy has an unnamed CONST of int under the tag's ID, the same
// string table, and every other type as compiled.
func TestSanitizeTypeTagObject(t *testing.T) {
	orig, sanitized := sanitizeObjectBTF(t, sanitizeTypeTagObject)
	tag := findType(t, orig, "user", btf.KindTypeTag)
	ptr := orig.Types[findType(t, orig, "tagged_uptr", btf.KindVar).SizeOrType]
	if ptr.Kind != btf.KindPtr || ptr.SizeOrType != tag.ID {
		t.Fatalf("tagged_uptr has type %v to %d, want a pointer to the type tag %d", ptr.Kind, ptr.SizeOrType, tag.ID)
	}

	if len(sanitized.Types) != len(orig.Types) || !bytes.Equal(sanitized.Strings, orig.Strings) {
		t.Fatalf("copy has %d types and %d string bytes, want %d and %d", len(sanitized.Types), len(sanitized.Strings), len(orig.Types), len(orig.Strings))
	}
	got := sanitized.Types[tag.ID]
	if got.Kind != btf.KindConst || got.KindFlag || got.NameOff != 0 || got.SizeOrType != tag.SizeOrType {
		t.Errorf("type tag %d is now %v named at %d of type %d, want an unnamed CONST of %d", tag.ID, got.Kind, got.NameOff, got.SizeOrType, tag.SizeOrType)
	}
	checkTypesKept(t, orig, sanitized, tag.ID)
}

// TestSanitizeEnum64Object sanitizes the BTF of sanitize_enum64.bpf.o. clang
// emits enum sanitize_wide, with a value above 32 bits, as an unsigned
// ENUM64 of 8 bytes, and enum sanitize_signed, with a negative value, as an
// ENUM with the kind flag. In the copy the ENUM64 is a UNION of 8 bytes
// whose members keep the value names, at offset 0, of the
// enum64_placeholder INT added after the last type, the ENUM has no kind
// flag, and every other type keeps its ID and record.
func TestSanitizeEnum64Object(t *testing.T) {
	orig, sanitized := sanitizeObjectBTF(t, sanitizeEnum64Object)
	wide := findType(t, orig, "sanitize_wide", btf.KindEnum64)
	signed := findType(t, orig, "sanitize_signed", btf.KindEnum)
	if wide.KindFlag || wide.SizeOrType != 8 || len(wide.Enum64s) != 2 || wide.Enum64s[1].Value != 1<<32 {
		t.Fatalf("sanitize_wide = %+v, want an unsigned 8-byte ENUM64 with 1<<32", wide)
	}
	if !signed.KindFlag {
		t.Fatalf("sanitize_signed = %+v, want the signed kind flag", signed)
	}

	placeholderID := uint32(len(orig.Types))
	if len(sanitized.Types) != len(orig.Types)+1 {
		t.Fatalf("copy has %d types, want %d", len(sanitized.Types), len(orig.Types)+1)
	}
	if want := append(bytes.Clone(orig.Strings), "enum64_placeholder\x00"...); !bytes.Equal(sanitized.Strings, want) {
		t.Errorf("copy strings end with %q, want enum64_placeholder appended", sanitized.Strings[len(orig.Strings):])
	}
	placeholder := sanitized.Types[placeholderID]
	if placeholder.Kind != btf.KindInt || placeholder.Name != "enum64_placeholder" || placeholder.SizeOrType != 1 || placeholder.Int == nil || placeholder.Int.Encoding != 8 {
		t.Errorf("type %d = %+v, want the one-byte enum64_placeholder INT", placeholderID, placeholder)
	}

	union := sanitized.Types[wide.ID]
	wantMembers := []btf.Member{
		{NameOff: wide.Enum64s[0].NameOff, Name: "WIDE_LOW", Type: placeholderID},
		{NameOff: wide.Enum64s[1].NameOff, Name: "WIDE_HIGH", Type: placeholderID},
	}
	if union.Kind != btf.KindUnion || union.KindFlag || union.Name != "sanitize_wide" || union.SizeOrType != 8 || !slices.Equal(union.Members, wantMembers) {
		t.Errorf("sanitize_wide is now %+v, want an 8-byte UNION of %+v", union, wantMembers)
	}
	enum := sanitized.Types[signed.ID]
	if enum.Kind != btf.KindEnum || enum.KindFlag || enum.Vlen != signed.Vlen || !slices.Equal(enum.Enums, signed.Enums) {
		t.Errorf("sanitize_signed is now %+v, want %+v without the kind flag", enum, signed)
	}
	checkTypesKept(t, orig, sanitized, wide.ID, signed.ID)
}

// TestSanitizeFloatObject sanitizes the BTF of sanitize_float.bpf.o, where
// clang emits the members of struct sanitize_sample as a FLOAT named float
// of 4 bytes and one named double of 8. In the copy each is an unnamed
// STRUCT of the same size without members, under the same ID; the string
// table and every other type, including the struct that refers to them, are
// as compiled.
func TestSanitizeFloatObject(t *testing.T) {
	orig, sanitized := sanitizeObjectBTF(t, sanitizeFloatObject)
	sample := findType(t, orig, "sanitize_sample", btf.KindStruct)
	floats := []*btf.Type{findType(t, orig, "float", btf.KindFloat), findType(t, orig, "double", btf.KindFloat)}
	if len(sample.Members) != 2 || sample.Members[0].Type != floats[0].ID || sample.Members[1].Type != floats[1].ID {
		t.Fatalf("sanitize_sample members = %+v, want ratio of float %d and scale of double %d", sample.Members, floats[0].ID, floats[1].ID)
	}

	if len(sanitized.Types) != len(orig.Types) || !bytes.Equal(sanitized.Strings, orig.Strings) {
		t.Fatalf("copy has %d types and %d string bytes, want %d and %d", len(sanitized.Types), len(sanitized.Strings), len(orig.Types), len(orig.Strings))
	}
	for i, size := range []uint32{4, 8} {
		f := floats[i]
		if f.SizeOrType != size {
			t.Fatalf("%s has %d bytes, want %d", f.Name, f.SizeOrType, size)
		}
		got := sanitized.Types[f.ID]
		if got.Kind != btf.KindStruct || got.KindFlag || got.NameOff != 0 || got.SizeOrType != size || len(got.Members) != 0 {
			t.Errorf("%s %d is now %v named at %d of %d bytes with %d members, want an unnamed empty STRUCT of %d bytes", f.Name, f.ID, got.Kind, got.NameOff, got.SizeOrType, len(got.Members), size)
		}
	}
	checkTypesKept(t, orig, sanitized, floats[0].ID, floats[1].ID)
}

// TestSanitizeTypeTagLoad loads sanitize_type_tag.bpf.o, whose global
// pointer carries a TYPE_TAG. It needs root or CAP_BPF and skips otherwise.
func TestSanitizeTypeTagLoad(t *testing.T) {
	testSanitizeLoad(t, sanitizeTypeTagObject, "user", btf.KindTypeTag,
		func(k btf.KernelFeatures) bool { return k.TypeTag })
}

// TestSanitizeEnum64Load loads sanitize_enum64.bpf.o, whose map key is a
// signed ENUM and whose value is an ENUM64. It needs root or CAP_BPF and
// skips otherwise.
func TestSanitizeEnum64Load(t *testing.T) {
	testSanitizeLoad(t, sanitizeEnum64Object, "sanitize_wide", btf.KindEnum64,
		func(k btf.KernelFeatures) bool { return k.Enum64 })
}

// TestSanitizeFloatLoad loads sanitize_float.bpf.o, whose .data struct has
// a float and a double member. It needs root or CAP_BPF and skips
// otherwise.
func TestSanitizeFloatLoad(t *testing.T) {
	testSanitizeLoad(t, sanitizeFloatObject, "float", btf.KindFloat,
		func(k btf.KernelFeatures) bool { return k.Float })
}

// testSanitizeLoad loads the fixture name and logs the kernel release and
// the nine BTF feature probes. The load must succeed, and the object BTF
// must keep its bytes and the type of kind named typeName. On a kernel with
// every feature the uploaded BTF is the object BTF itself. On one without
// the fixture's feature, which supported reads from the probes, the
// uploaded copy has no type of that kind and the kernel rejects the object
// BTF as compiled, so the load passed with the sanitized copy only.
func testSanitizeLoad(t *testing.T, name, typeName string, kind btf.Kind, supported func(btf.KernelFeatures) bool) {
	obj, err := BpfObjectOpenFile(filepath.Join(progsDir, name), nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer BpfObjectClose(obj)
	opened := bytes.Clone(obj.btf.Raw())

	err = BpfObjectLoad(obj)
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("bpf() not permitted: %v", err)
	}
	kern := kernelBTFFeatures()
	logBTFFeatures(t, kern)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	checkSubprogDescriptors(t, obj)

	spec, err := BpfObjectBTF(obj).btfSpec()
	if err != nil {
		t.Fatalf("object BTF: %v", err)
	}
	if !bytes.Equal(spec.Raw(), opened) {
		t.Error("load changed the object BTF")
	}
	findType(t, spec, typeName, kind)

	uploaded, err := sanitizeBTF(spec, kern)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if !btfNeedsSanitization(kern) {
		if !bytes.Equal(uploaded, spec.Raw()) {
			t.Error("the kernel has every BTF feature, but the uploaded BTF is not the object BTF")
		}
		return
	}
	if supported(kern) {
		return
	}
	sanitized, err := btf.Parse(uploaded, obj.elf.ByteOrder)
	if err != nil {
		t.Fatalf("parse the uploaded BTF: %v", err)
	}
	if n := countKind(sanitized, kind); n != 0 {
		t.Errorf("uploaded BTF has %d %v types", n, kind)
	}
	fd, err := sys.BtfLoad(spec.Raw(), nil, 0)
	if err == nil {
		unix.Close(fd)
		t.Fatalf("the kernel lacks %v but accepted the object BTF as compiled", kind)
	}
	t.Logf("object BTF as compiled rejected: %v", err)
}
