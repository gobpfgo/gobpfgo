// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

package btf

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"syscall"
	"testing"
)

// dedupFixture is testdata/oracle/dedup.json: libbpf's dedup of the .BTF and
// .BTF.ext of fixture objects, and of synthetic BTF built from scratch.
type dedupFixture struct {
	Objects []struct {
		Object string `json:"object"`
		Errno  int    `json:"errno"`
		BTF    string `json:"btf"`
		BTFExt string `json:"btf_ext"`
	} `json:"objects"`
	Cases []struct {
		Name   string `json:"name"`
		Input  string `json:"input"`
		Errno  int    `json:"errno"`
		Output string `json:"output"`
	} `json:"cases"`
}

func loadDedupFixture(t *testing.T) dedupFixture {
	t.Helper()

	data, err := os.ReadFile("../../testdata/oracle/dedup.json")
	if err != nil {
		t.Fatalf("read dedup fixture: %v", err)
	}
	var f dedupFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse dedup fixture: %v", err)
	}
	return f
}

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return b
}

// TestDedupOracleObjects dedups the parsed .BTF of each fixture object with
// its .BTF.ext and compares both sections, byte for byte, with libbpf's. The
// string table is rebuilt in reference order here.
func TestDedupOracleObjects(t *testing.T) {
	for _, want := range loadDedupFixture(t).Objects {
		t.Run(want.Object, func(t *testing.T) {
			spec, obj := parseObjectBTF(t, want.Object)
			ext := bytes.Clone(obj.BTFExt)

			if _, err := spec.Dedup(&DedupOpts{Ext: ext}); err != nil {
				t.Fatalf("Dedup: %v", err)
			}
			if got := hex.EncodeToString(spec.Raw()); got != want.BTF {
				t.Fatalf(".BTF = %s\nwant %s", got, want.BTF)
			}
			if got := hex.EncodeToString(ext); got != want.BTFExt {
				t.Fatalf(".BTF.ext = %s\nwant %s", got, want.BTFExt)
			}
		})
	}
}

// TestDedupOracleCases dedups the synthetic BTF that libbpf built from
// scratch, wrapped with NewSpec so its string table is kept, and compares
// the blob or the errno with libbpf's.
func TestDedupOracleCases(t *testing.T) {
	for _, want := range loadDedupFixture(t).Cases {
		t.Run(want.Name, func(t *testing.T) {
			in, err := Parse(decodeHex(t, want.Input), binary.LittleEndian)
			if err != nil {
				t.Fatalf("Parse input: %v", err)
			}
			spec, err := NewSpec(binary.LittleEndian, in.Types, in.Strings)
			if err != nil {
				t.Fatalf("NewSpec: %v", err)
			}
			if got := hex.EncodeToString(spec.Raw()); got != want.Input {
				t.Fatalf("NewSpec blob = %s\nwant %s", got, want.Input)
			}

			_, err = spec.Dedup(nil)
			if want.Errno != 0 {
				if !errors.Is(err, syscall.Errno(want.Errno)) {
					t.Fatalf("Dedup = %v, want errno %d", err, want.Errno)
				}
				return
			}
			if err != nil {
				t.Fatalf("Dedup: %v", err)
			}
			if got := hex.EncodeToString(spec.Raw()); got != want.Output {
				t.Fatalf("output = %s\nwant %s", got, want.Output)
			}
		})
	}
}

// specBuilder collects types and interns their names in first-use order,
// like a BTF built from scratch.
type specBuilder struct {
	types []Type
	strs  *strSet
}

func newSpecBuilder() *specBuilder {
	return &specBuilder{types: []Type{{Kind: KindVoid}}, strs: newStrSet()}
}

// add appends t with its name offsets set and returns its ID.
func (b *specBuilder) add(t Type) uint32 {
	t.ID = uint32(len(b.types))
	t.NameOff = b.strs.add(t.Name)
	for i := range t.Members {
		t.Members[i].NameOff = b.strs.add(t.Members[i].Name)
	}
	for i := range t.Enums {
		t.Enums[i].NameOff = b.strs.add(t.Enums[i].Name)
	}
	for i := range t.Enum64s {
		t.Enum64s[i].NameOff = b.strs.add(t.Enum64s[i].Name)
	}
	for i := range t.Params {
		t.Params[i].NameOff = b.strs.add(t.Params[i].Name)
	}
	b.types = append(b.types, t)
	return t.ID
}

// spec wraps the types with NewSpec.
func (b *specBuilder) spec(t *testing.T) *Spec {
	t.Helper()

	s, err := NewSpec(binary.LittleEndian, b.types, b.strs.data)
	if err != nil {
		t.Fatalf("NewSpec: %v", err)
	}
	return s
}

func intType(name string, size uint32, enc uint32) Type {
	return Type{Kind: KindInt, Name: name, SizeOrType: size, Int: &Int{Encoding: enc<<24 | size*8}}
}

func refType(kind Kind, name string, to uint32) Type {
	return Type{Kind: kind, Name: name, SizeOrType: to}
}

func fwdType(name string, union bool) Type {
	return Type{Kind: KindFwd, Name: name, KindFlag: union}
}

func structType(kind Kind, name string, size uint32, members ...Member) Type {
	return Type{Kind: kind, Name: name, SizeOrType: size, Members: members}
}

func enumType(name string, values ...Enum) Type {
	return Type{Kind: KindEnum, Name: name, SizeOrType: 4, Enums: values}
}

func arrayType(elem, index, n uint32) Type {
	return Type{Kind: KindArray, Array: &Array{Type: elem, IndexType: index, Nelems: n}}
}

func protoType(ret uint32, params ...Param) Type {
	return Type{Kind: KindFuncProto, SizeOrType: ret, Params: params}
}

func funcType(name string, proto uint32) Type {
	return Type{Kind: KindFunc, Name: name, Vlen: 1, SizeOrType: proto}
}

func dedupSpec(t *testing.T, s *Spec, opts *DedupOpts) []uint32 {
	t.Helper()

	remap, err := s.Dedup(opts)
	if err != nil {
		t.Fatalf("Dedup: %v", err)
	}
	return remap
}

func checkRemap(t *testing.T, got, want []uint32) {
	t.Helper()

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("remap = %v, want %v", got, want)
	}
}

// extSection is one section block of buildExt: a name offset and records of
// 32-bit words.
type extSection struct {
	nameOff uint32
	recs    [][]uint32
}

// buildExt encodes a little-endian .BTF.ext with function, line and CO-RE
// subsections of 8-, 16- and 16-byte records.
func buildExt(funcs, lines, cores []extSection) []byte {
	le := binary.LittleEndian
	sub := func(recSize uint32, secs []extSection) []byte {
		if len(secs) == 0 {
			return nil
		}
		b := le.AppendUint32(nil, recSize)
		for _, s := range secs {
			b = le.AppendUint32(b, s.nameOff)
			b = le.AppendUint32(b, uint32(len(s.recs)))
			for _, rec := range s.recs {
				for _, w := range rec {
					b = le.AppendUint32(b, w)
				}
			}
		}
		return b
	}
	f, l, c := sub(8, funcs), sub(16, lines), sub(16, cores)

	b := le.AppendUint16(nil, extMagic)
	b = append(b, 1, 0)
	for _, w := range []int{extHeaderSize, 0, len(f), len(f), len(l), len(f) + len(l), len(c)} {
		b = le.AppendUint32(b, uint32(w))
	}
	return append(append(append(b, f...), l...), c...)
}

// encodeParsed writes types and strings with a 24-byte header, as a compiler
// does, and parses them back, so Dedup rebuilds the string table.
func encodeParsed(t *testing.T, types []Type, strs []byte) *Spec {
	t.Helper()

	le := binary.LittleEndian
	var typeData []byte
	for i := 1; i < len(types); i++ {
		typeData = AppendType(typeData, &types[i], le)
	}
	raw := le.AppendUint16(nil, 0xeb9f)
	raw = append(raw, 1, 0)
	for _, w := range []int{minHdrLen, 0, len(typeData), len(typeData), len(strs)} {
		raw = le.AppendUint32(raw, uint32(w))
	}
	spec, err := Parse(append(append(raw, typeData...), strs...), le)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return spec
}

// TestDedupStrings rebuilds a parsed string table: the two "int" copies
// become one, so the INTs that named them merge, the unused string goes away,
// and the .BTF.ext section names, file name and line follow the types'
// strings in reference order.
func TestDedupStrings(t *testing.T) {
	strs := []byte("\x00int\x00unused\x00int\x00sec\x00file\x00line\x00")
	const intA, intB, sec, file, line = 1, 12, 16, 20, 25
	types := []Type{
		{Kind: KindVoid},
		{Kind: KindInt, NameOff: intA, SizeOrType: 4, Int: &Int{Encoding: 32}},
		{Kind: KindInt, NameOff: intB, SizeOrType: 4, Int: &Int{Encoding: 32}},
	}
	spec := encodeParsed(t, types, strs)
	ext := buildExt(
		[]extSection{{sec, [][]uint32{{0, 2}}}},
		[]extSection{{sec, [][]uint32{{0, file, line, 7}}}},
		nil)

	checkRemap(t, dedupSpec(t, spec, &DedupOpts{Ext: ext}), []uint32{0, 1, 1})

	if got, want := string(spec.Strings), "\x00int\x00sec\x00file\x00line\x00"; got != want {
		t.Fatalf("strings = %q, want %q", got, want)
	}
	want := buildExt(
		[]extSection{{5, [][]uint32{{0, 1}}}},
		[]extSection{{5, [][]uint32{{0, 9, 14, 7}}}},
		nil)
	if !bytes.Equal(ext, want) {
		t.Fatalf(".BTF.ext = %x\nwant %x", ext, want)
	}
	if spec.Header.StrLen != uint32(len(spec.Strings)) || len(spec.Types) != 2 {
		t.Fatalf("header %+v with %d types", spec.Header, len(spec.Types))
	}
}

// TestDedupKeepsBuiltStrings keeps the string table of a NewSpec spec, even
// the names of the types that merge away.
func TestDedupKeepsBuiltStrings(t *testing.T) {
	b := newSpecBuilder()
	b.add(intType("int", 4, 1))
	b.add(intType("int", 4, 1))
	b.add(intType("gone", 4, 0))
	b.add(intType("gone", 4, 0))
	spec := b.spec(t)
	before := bytes.Clone(spec.Strings)

	checkRemap(t, dedupSpec(t, spec, nil), []uint32{0, 1, 1, 2, 2})
	if !bytes.Equal(spec.Strings, before) {
		t.Fatalf("strings = %q, want %q", spec.Strings, before)
	}
}

// TestDedupPrimitives merges equal INTs and FLOATs, keeps an INT of another
// encoding, and resolves enum forward declarations to the full enum, before
// or after it, including an ENUM declaration of an ENUM64.
func TestDedupPrimitives(t *testing.T) {
	enum64 := Type{Kind: KindEnum64, Name: "e64", SizeOrType: 8, Enum64s: []Enum64{{Name: "B", Value: 1 << 40}}}
	b := newSpecBuilder()
	b.add(intType("int", 4, 1))                                // 1
	b.add(intType("int", 4, 1))                                // 2 -> 1
	b.add(intType("int", 4, 0))                                // 3
	b.add(Type{Kind: KindFloat, Name: "float", SizeOrType: 4}) // 4
	b.add(Type{Kind: KindFloat, Name: "float", SizeOrType: 4}) // 5 -> 4
	b.add(enumType("e"))                                       // 6, forward -> 7
	b.add(enumType("e", Enum{Name: "A", Value: 1}))            // 7
	b.add(enumType("e"))                                       // 8 -> 7
	b.add(enumType("e64"))                                     // 9 -> 10
	b.add(enum64)                                              // 10

	remap := dedupSpec(t, b.spec(t), nil)
	checkRemap(t, remap, []uint32{0, 1, 1, 2, 3, 3, 4, 4, 4, 5, 5})
}

// TestDedupStructs merges two copies of a self-referencing struct, two
// unions and two bitfield structs, and keeps a struct whose member name
// differs.
func TestDedupStructs(t *testing.T) {
	b := newSpecBuilder()
	for n := 0; n < 2; n++ {
		i := b.add(intType("int", 4, 1))
		s := b.add(structType(KindStruct, "s", 16,
			Member{Name: "next", Type: uint32(len(b.types)) + 1},
			Member{Name: "x", Type: i, Offset: 64}))
		b.add(refType(KindPtr, "", s))
		b.add(structType(KindUnion, "u", 4, Member{Name: "a", Type: i}, Member{Name: "b", Type: i}))
		bits := structType(KindStruct, "bits", 4,
			Member{Name: "lo", Type: i, BitfieldSize: 3},
			Member{Name: "hi", Type: i, Offset: 3, BitfieldSize: 5})
		bits.KindFlag = true
		b.add(bits)
	}
	b.add(structType(KindStruct, "s", 16, Member{Name: "next", Type: 3}, Member{Name: "y", Type: 1, Offset: 64}))

	spec := b.spec(t)
	remap := dedupSpec(t, spec, nil)
	checkRemap(t, remap, []uint32{0, 1, 2, 3, 4, 5, 1, 2, 3, 4, 5, 6})
	if next := spec.Types[2].Members[0].Type; next != 3 || spec.Types[3].SizeOrType != 2 {
		t.Fatalf("struct s points to %d, pointer to %d; want 3 and 2", next, spec.Types[3].SizeOrType)
	}
}

// TestDedupForwardDecls resolves a struct forward declaration that a type
// graph comparison links to its struct, although another struct shares its
// name, and one that only its unique name links, and leaves one whose name
// two structs share and a union declaration of a struct name.
func TestDedupForwardDecls(t *testing.T) {
	b := newSpecBuilder()
	// struct A { struct B *p; } with B declared, then with B defined.
	fwdB := b.add(fwdType("B", false))                                                // 1
	b.add(structType(KindStruct, "A", 8, Member{Name: "p", Type: 3}))                 // 2
	b.add(refType(KindPtr, "", fwdB))                                                 // 3
	i := b.add(intType("int", 4, 1))                                                  // 4
	structB := b.add(structType(KindStruct, "B", 4, Member{Name: "x", Type: i}))      // 5
	b.add(structType(KindStruct, "A", 8, Member{Name: "p", Type: 7}))                 // 6 -> 2
	b.add(refType(KindPtr, "", structB))                                              // 7 -> 3
	unique := b.add(fwdType("unique", false))                                         // 8 -> 9
	b.add(structType(KindStruct, "unique", 4, Member{Name: "u", Type: i}))            // 9
	twice := b.add(fwdType("twice", false))                                           // 10
	b.add(structType(KindStruct, "twice", 4, Member{Name: "u", Type: i}))             // 11
	b.add(structType(KindStruct, "twice", 8, Member{Name: "v", Type: i, Offset: 32})) // 12
	kind := b.add(fwdType("kind", true))                                              // 13
	b.add(structType(KindStruct, "kind", 4, Member{Name: "u", Type: i}))              // 14
	b.add(refType(KindPtr, "", unique))                                               // 15
	b.add(refType(KindPtr, "", twice))                                                // 16
	b.add(refType(KindPtr, "", kind))                                                 // 17
	b.add(structType(KindStruct, "B", 4, Member{Name: "y", Type: i}))                 // 18

	spec := b.spec(t)
	remap := dedupSpec(t, spec, nil)
	checkRemap(t, remap, []uint32{0, 4, 1, 2, 3, 4, 1, 2, 5, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14})
	if p := spec.Types[2]; p.Kind != KindPtr || p.SizeOrType != 4 {
		t.Fatalf("struct A's pointer = %v to %d, want a pointer to struct B (4)", p.Kind, p.SizeOrType)
	}
}

// TestDedupRemap checks the returned map against the rewritten references of
// reference types, variables and data sections, and that the new blob parses
// back to the same types and works with the Set methods.
func TestDedupRemap(t *testing.T) {
	b := newSpecBuilder()
	for n := 0; n < 2; n++ {
		i := b.add(intType("int", 4, 1))
		td := b.add(refType(KindTypedef, "t", i))
		c := b.add(refType(KindConst, "", td))
		p := b.add(refType(KindPtr, "", c))
		proto := b.add(protoType(i, Param{Name: "a", Type: p}))
		b.add(funcType("f", proto))
		b.add(arrayType(td, i, 4))
	}
	v1 := b.add(Type{Kind: KindVar, Name: "v", SizeOrType: 7, Var: &Var{Linkage: VarGlobalAllocated}})
	v2 := b.add(Type{Kind: KindVar, Name: "v", SizeOrType: 14, Var: &Var{Linkage: VarGlobalAllocated}})
	b.add(Type{Kind: KindDatasec, Name: ".data", DataSec: []VarSecInfo{{Type: v1, Size: 16}, {Type: v2, Offset: 16, Size: 16}}})

	spec := b.spec(t)
	remap := dedupSpec(t, spec, nil)
	checkRemap(t, remap, []uint32{0, 1, 2, 3, 4, 5, 6, 7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10})

	// Both variables stay, and both now name the first array.
	if spec.Types[8].SizeOrType != 7 || spec.Types[9].SizeOrType != 7 {
		t.Fatalf("variables point to %d and %d, want 7", spec.Types[8].SizeOrType, spec.Types[9].SizeOrType)
	}
	if ds := spec.Types[10].DataSec; ds[0].Type != 8 || ds[1].Type != 9 {
		t.Fatalf("data section variables = %+v", ds)
	}

	again, err := Parse(spec.Raw(), binary.LittleEndian)
	if err != nil {
		t.Fatalf("Parse deduplicated blob: %v", err)
	}
	if len(again.Types) != len(spec.Types) {
		t.Fatalf("reparsed %d types, want %d", len(again.Types), len(spec.Types))
	}
	if err := spec.SetDatasecSize(10, 32); err != nil {
		t.Fatalf("SetDatasecSize: %v", err)
	}
	if again, _ = Parse(spec.Raw(), binary.LittleEndian); again.Types[10].SizeOrType != 32 {
		t.Fatalf("data section size = %d after SetDatasecSize, want 32", again.Types[10].SizeOrType)
	}
}

// TestDedupExtRemap rewrites the function and CO-RE record type IDs of a
// .BTF.ext to the merged types and leaves its string offsets alone when the
// string table is kept.
func TestDedupExtRemap(t *testing.T) {
	b := newSpecBuilder()
	for n := 0; n < 2; n++ {
		i := b.add(intType("int", 4, 1))
		proto := b.add(protoType(i))
		b.add(funcType("f", proto))
		b.add(structType(KindStruct, "s", 4, Member{Name: "x", Type: i}))
	}
	sec, access := b.strs.add("kprobe/f"), b.strs.add("0:0")
	ext := buildExt(
		[]extSection{{sec, [][]uint32{{0, 3}, {8, 7}}}},
		[]extSection{{sec, [][]uint32{{0, sec, access, 1}}}},
		[]extSection{{sec, [][]uint32{{0, 8, access, 0}, {8, 4, access, 0}}}})

	remap := dedupSpec(t, b.spec(t), &DedupOpts{Ext: ext})
	checkRemap(t, remap, []uint32{0, 1, 2, 3, 4, 1, 2, 3, 4})

	want := buildExt(
		[]extSection{{sec, [][]uint32{{0, 3}, {8, 3}}}},
		[]extSection{{sec, [][]uint32{{0, sec, access, 1}}}},
		[]extSection{{sec, [][]uint32{{0, 4, access, 0}, {8, 4, access, 0}}}})
	if !bytes.Equal(ext, want) {
		t.Fatalf(".BTF.ext = %x\nwant %x", ext, want)
	}
}

// TestDedupTableOrder checks the candidate order of the signature table: a
// new candidate goes first, and growing the table reverses each hash's
// candidates.
func TestDedupTableOrder(t *testing.T) {
	var tb dedupTable
	tb.add(7, 1) // grows to 4 buckets
	tb.add(7, 2)
	if got := tb.candidates(7); !reflect.DeepEqual(got, []uint32{2, 1}) {
		t.Fatalf("candidates = %v, want [2 1]", got)
	}
	tb.add(8, 3)
	tb.add(9, 4) // grows to 8 buckets
	if got := tb.candidates(7); !reflect.DeepEqual(got, []uint32{1, 2}) {
		t.Fatalf("candidates after growing = %v, want [1 2]", got)
	}
	tb.add(7, 5)
	if got := tb.candidates(7); !reflect.DeepEqual(got, []uint32{5, 1, 2}) || tb.capacity != 8 {
		t.Fatalf("candidates = %v with %d buckets, want [5 1 2] with 8", got, tb.capacity)
	}
}

func TestDedupErrors(t *testing.T) {
	tests := []struct {
		name  string
		build func(b *specBuilder)
		errno syscall.Errno
	}{
		{"reference cycle", func(b *specBuilder) {
			b.add(refType(KindPtr, "", 2))
			b.add(refType(KindConst, "", 1))
		}, syscall.ELOOP},
		{"type id out of range", func(b *specBuilder) {
			b.add(refType(KindPtr, "", 9))
		}, syscall.EINVAL},
		{"missing payload", func(b *specBuilder) {
			b.add(Type{Kind: KindArray})
		}, syscall.EINVAL},
		{"unknown kind", func(b *specBuilder) {
			b.add(Type{Kind: 25})
		}, syscall.EINVAL},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := newSpecBuilder()
			tt.build(b)
			if _, err := b.spec(t).Dedup(nil); !errors.Is(err, tt.errno) {
				t.Fatalf("Dedup = %v, want %v", err, tt.errno)
			}
		})
	}
}

// TestDedupBadExt rejects a .BTF.ext with a type ID out of range or a
// truncated subsection before it changes the spec or the section.
func TestDedupBadExt(t *testing.T) {
	b := newSpecBuilder()
	b.add(intType("int", 4, 1))
	b.add(intType("int", 4, 1))
	sec := b.strs.add("sec")

	outOfRange := buildExt([]extSection{{sec, [][]uint32{{0, 9}}}}, nil, nil)
	truncated := buildExt([]extSection{{sec, [][]uint32{{0, 2}}}}, nil, nil)
	truncated = truncated[:len(truncated)-4]

	for name, ext := range map[string][]byte{"out of range": outOfRange, "truncated": truncated} {
		t.Run(name, func(t *testing.T) {
			spec := b.spec(t)
			raw, before := bytes.Clone(spec.Raw()), bytes.Clone(ext)
			if _, err := spec.Dedup(&DedupOpts{Ext: ext}); !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("Dedup = %v, want EINVAL", err)
			}
			if !bytes.Equal(spec.Raw(), raw) || !bytes.Equal(ext, before) || len(spec.Types) != 3 {
				t.Fatal("a rejected Dedup changed the spec or the .BTF.ext")
			}
		})
	}
}

// TestDedupMergedSplit rejects a spec merged from split BTF, whose type
// names come from two string tables.
func TestDedupMergedSplit(t *testing.T) {
	base, _ := parseObjectBTF(t, "kprobe.bpf.o")
	module, _ := parseObjectBTF(t, "kprobe.bpf.o")
	merged, err := MergeSplit(base, module)
	if err != nil {
		t.Fatalf("MergeSplit: %v", err)
	}
	if _, err := merged.Dedup(nil); !errors.Is(err, syscall.EOPNOTSUPP) {
		t.Fatalf("Dedup = %v, want EOPNOTSUPP", err)
	}
}

// TestDedupLayoutHeader rejects a header that declares a layout section,
// which the encoder cannot carry over.
func TestDedupLayoutHeader(t *testing.T) {
	b := newSpecBuilder()
	b.add(intType("int", 4, 1))
	raw := bytes.Clone(b.spec(t).Raw())
	binary.LittleEndian.PutUint32(raw[28:], 4)

	spec, err := Parse(raw, binary.LittleEndian)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := spec.Dedup(nil); !errors.Is(err, syscall.EOPNOTSUPP) {
		t.Fatalf("Dedup = %v, want EOPNOTSUPP", err)
	}
}
