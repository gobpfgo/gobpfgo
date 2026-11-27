// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/linker.c
// libbpf-source: src/btf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: linker_append_btf, add_btf_ext_rec, linker_append_btf_ext, complete_extern_btf_info, finalize_btf, emit_elf_data_sec, emit_btf_ext_data, finalize_btf_ext, btf__new_empty, btf__add_str, btf__add_type, btf__add_datasec, btf__add_datasec_var_info

package libbpf

import (
	"debug/elf"
	"encoding/binary"
	"maps"
	"slices"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	objelf "github.com/gobpfgo/gobpfgo/internal/elf"
	"golang.org/x/sys/unix"
)

// .BTF.ext layout written by the linker. btfExtHdrLen is
// sizeof(struct btf_ext_header).
const (
	btfMagic      = 0xeb9f
	btfVersion    = 1
	btfExtHdrLen  = 32
	btfFuncGlobal = 1
)

// linkerBTF is the output BTF before dedup. spec holds the types in output ID
// order with their names resolved; every name offset points into strs, which
// keeps one copy of each string in the order it was first added.
type linkerBTF struct {
	spec    *btf.Spec
	strs    []byte
	strOffs map[string]uint32
}

func newLinkerBTF() *linkerBTF {
	return &linkerBTF{
		spec:    &btf.Spec{ByteOrder: binary.LittleEndian, Types: []btf.Type{{Kind: btf.KindVoid}}},
		strs:    []byte{0},
		strOffs: map[string]uint32{"": 0},
	}
}

// clone copies the type list and the string table, so types and strings can
// be added to the copy. The existing types are shared and must not change.
func (b *linkerBTF) clone() *linkerBTF {
	spec := *b.spec
	spec.Types = slices.Clone(b.spec.Types)
	return &linkerBTF{spec: &spec, strs: slices.Clone(b.strs), strOffs: maps.Clone(b.strOffs)}
}

func (b *linkerBTF) typeCnt() int {
	return len(b.spec.Types)
}

// addStr returns the offset of s in the string table, adding it if needed.
func (b *linkerBTF) addStr(s string) uint32 {
	if off, ok := b.strOffs[s]; ok {
		return off
	}
	off := uint32(len(b.strs))
	b.strs = append(append(b.strs, s...), 0)
	b.strOffs[s] = off
	return off
}

// addType appends a copy of t with its names moved to the output string
// table and returns its ID. Its type IDs still refer to t's BTF; the caller
// remaps them.
func (b *linkerBTF) addType(t *btf.Type) uint32 {
	c := t.Clone()
	c.ID = uint32(len(b.spec.Types))
	c.NameOff = b.addStr(c.Name)
	for i := range c.Members {
		c.Members[i].NameOff = b.addStr(c.Members[i].Name)
	}
	for i := range c.Enums {
		c.Enums[i].NameOff = b.addStr(c.Enums[i].Name)
	}
	for i := range c.Enum64s {
		c.Enum64s[i].NameOff = b.addStr(c.Enum64s[i].Name)
	}
	for i := range c.Params {
		c.Params[i].NameOff = b.addStr(c.Params[i].Name)
	}
	b.spec.Types = append(b.spec.Types, c)
	return c.ID
}

// addDatasec appends a DATASEC named name with the given size and variables.
func (b *linkerBTF) addDatasec(name string, size uint64, vars []btf.VarSecInfo) {
	b.spec.Types = append(b.spec.Types, btf.Type{
		ID:         uint32(len(b.spec.Types)),
		NameOff:    b.addStr(name),
		Name:       name,
		Kind:       btf.KindDatasec,
		SizeOrType: uint32(size),
		DataSec:    slices.Clone(vars),
	})
}

// completeExternInfo marks the output VAR or FUNC dstID as a definition after
// the input definition srcID resolved an extern or replaced a weak
// definition: a VAR becomes allocated, and a FUNC becomes global and takes
// the parameter names of srcID's prototype, which an extern prototype lacks.
// The output keeps both prototypes; dedup merges them once the names agree.
func (b *linkerBTF) completeExternInfo(dstID uint32, src *btf.Spec, srcID uint32) error {
	dst, err := b.spec.TypeByID(dstID)
	if err != nil {
		return linkerErrorf(unix.EINVAL, "%v", err)
	}
	if dst.Kind == btf.KindVar {
		if dst.Var != nil {
			dst.Var.Linkage = btf.VarGlobalAllocated
		}
		return nil
	}

	dst.Vlen = btfFuncGlobal
	dst.KindFlag = false
	srcFunc, err := src.TypeByID(srcID)
	if err != nil {
		return linkerErrorf(unix.EINVAL, "%v", err)
	}
	srcProto, err1 := src.TypeByID(srcFunc.SizeOrType)
	dstProto, err2 := b.spec.TypeByID(dst.SizeOrType)
	if err1 != nil || err2 != nil {
		return linkerErrorf(unix.EINVAL, "missing function prototype for type #%d", dstID)
	}

	for i := range dstProto.Params {
		if i >= len(srcProto.Params) || srcProto.Params[i].NameOff == 0 {
			continue
		}
		dstProto.Params[i].Name = srcProto.Params[i].Name
		dstProto.Params[i].NameOff = b.addStr(srcProto.Params[i].Name)
	}
	return nil
}

// appendBTF concatenates the input types, except DATASECs, to the output BTF
// and remaps their type IDs. A global VAR or FUNC is added once, by the first
// object that defines it; later objects reuse it, and a VAR or FUNC without a
// global symbol, such as one in a deduplicated license section, is dropped.
// The DATASEC variables are then merged into their output sections.
func (out *linkerOutput) appendBTF(in *linkerInput) error {
	if in.btf == nil {
		return nil
	}

	startID := out.btf.typeCnt()
	in.btfTypeMap = make([]uint32, len(in.btf.Types)+1)
	for i := 1; i < len(in.btf.Types); i++ {
		out.appendBTFType(in, i)
	}
	if err := out.remapBTFTypes(in, startID); err != nil {
		return err
	}

	for gi := range out.globSyms {
		g := &out.globSyms[gi]
		if g.underlyingBtfID >= 0 {
			continue
		}
		g.underlyingBtfID = int64(in.btfTypeMap[-g.underlyingBtfID])
		out.btf.spec.Types[g.btfID].SizeOrType = uint32(g.underlyingBtfID)
	}

	for i := 1; i < len(in.secs); i++ {
		if err := out.appendDatasec(in, i); err != nil {
			return err
		}
	}
	return nil
}

// appendBTFType adds input type i and records its output ID.
func (out *linkerOutput) appendBTFType(in *linkerInput, i int) {
	t := &in.btf.Types[i]
	if t.Kind == btf.KindDatasec {
		return
	}

	var g *linkerGlobSym
	if btfIsNonStatic(t) {
		g = out.findGlobSym(t.Name)
		if g == nil {
			return
		}
		if g.underlyingBtfID == 0 {
			g.underlyingBtfID = -int64(t.SizeOrType)
		}
		if g.btfID != 0 {
			in.btfTypeMap[i] = g.btfID
			return
		}
	}

	id := out.btf.addType(t)
	in.btfTypeMap[i] = id
	if g != nil {
		g.btfID = id
		g.underlyingBtfID = -int64(t.SizeOrType)
	}
}

// remapBTFTypes rewrites the type IDs of the types added from in, starting at
// output ID startID. Void stays void; any other ID without a mapping is an
// error.
func (out *linkerOutput) remapBTFTypes(in *linkerInput, startID int) error {
	for id := startID; id < out.btf.typeCnt(); id++ {
		err := out.btf.spec.Types[id].VisitTypeIDs(func(typeID *uint32) error {
			newID := in.btfTypeMap[*typeID]
			if newID == 0 && *typeID != 0 {
				return linkerErrorf(unix.EINVAL, "failed to find new ID mapping for original BTF type ID %d", *typeID)
			}
			*typeID = newID
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// appendDatasec merges the DATASEC of input section i into its output
// section: each variable moves by the section's output offset. A global that
// is already in the section keeps one entry, which follows the winning
// definition's offset and size. The .extern DATASEC has no input section, so
// its externs reach the output only through the section of the definition
// that resolves them; like libbpf, an unresolved extern is left in no
// DATASEC.
func (out *linkerOutput) appendDatasec(in *linkerInput, i int) error {
	src := &in.secs[i]
	if src.btfTypeID == 0 || src.skipped {
		return nil
	}
	dst := out.sec(src.dst)
	dst.hasBTF = true

	for _, sv := range in.btf.Types[src.btfTypeID].DataSec {
		newID := in.btfTypeMap[sv.Type]
		t := &out.btf.spec.Types[newID]

		var g *linkerGlobSym
		if btfIsNonStatic(t) {
			if g = out.findGlobSym(t.Name); g == nil {
				return linkerErrorf(unix.EINVAL, "global '%s' has no symbol", t.Name)
			}
			if g.secID != src.dst {
				return linkerErrorf(unix.EINVAL, "global '%s': section mismatch %d vs %d", t.Name, g.secID, src.dst)
			}
		}

		if g != nil && g.varIdx >= 0 {
			if t.Kind == btf.KindFunc {
				continue
			}
			if err := out.updateDatasecVar(dst, g); err != nil {
				return err
			}
			continue
		}

		dst.vars = append(dst.vars, btf.VarSecInfo{Type: newID, Size: sv.Size, Offset: uint32(src.dstOff) + sv.Offset})
		if g != nil {
			g.varIdx = len(dst.vars) - 1
		}
	}
	return nil
}

// updateDatasecVar points the DATASEC entry of g at the size of its current
// type and, once g is defined, at its symbol value. An extern keeps the
// offset it was added with.
func (out *linkerOutput) updateDatasecVar(dst *linkerSec, g *linkerGlobSym) error {
	v := &dst.vars[g.varIdx]
	if !g.isExtern {
		v.Offset = uint32(out.sym(g.symIdx).Value)
	}
	size, err := out.btf.spec.SizeOf(uint32(g.underlyingBtfID))
	if err != nil {
		return linkerErrorf(unix.EINVAL, "global '%s': failed to resolve size of underlying type: %v", g.name, err)
	}
	v.Size = size
	return nil
}

// appendBTFExt adds the function, line and CO-RE records of in to their
// output sections. Instruction offsets move with the section, type IDs are
// remapped and strings move to the output string table.
func (out *linkerOutput) appendBTFExt(in *linkerInput) error {
	if in.btfExt == nil {
		return nil
	}

	kinds := []struct {
		blocks []btf.ExtRecords
		recs   func(*linkerSec) *linkerExtRecs
		fix    func(rec []byte)
	}{
		{in.btfExt.FuncInfo, func(s *linkerSec) *linkerExtRecs { return &s.funcInfo }, func(rec []byte) {
			out.remapExtType(in, rec, extRecTypeID)
		}},
		{in.btfExt.LineInfo, func(s *linkerSec) *linkerExtRecs { return &s.lineInfo }, func(rec []byte) {
			out.moveExtString(in, rec, extRecFileName)
			out.moveExtString(in, rec, extRecLine)
		}},
		{in.btfExt.CoreRelo, func(s *linkerSec) *linkerExtRecs { return &s.coreRelo }, func(rec []byte) {
			out.remapExtType(in, rec, extRecTypeID)
			out.moveExtString(in, rec, extRecAccessStr)
		}},
	}

	for _, kind := range kinds {
		for _, block := range kind.blocks {
			if err := out.appendExtBlock(in, block, kind.recs, kind.fix); err != nil {
				return err
			}
		}
	}
	return nil
}

// appendExtBlock copies the records of one .BTF.ext block to the output
// section it describes and fixes each copy. Records of a section that has no
// output section, such as an ignored one, are dropped, as libbpf does.
func (out *linkerOutput) appendExtBlock(in *linkerInput, block btf.ExtRecords, recsOf func(*linkerSec) *linkerExtRecs, fix func(rec []byte)) error {
	srcIdx := in.findSecByName(block.Section)
	if srcIdx == 0 {
		return linkerErrorf(unix.EINVAL, "can't find section '%s' referenced from .BTF.ext", block.Section)
	}
	src := &in.secs[srcIdx]
	if src.dst == 0 {
		return nil
	}
	recs := recsOf(out.sec(src.dst))

	if recs.recSize == 0 {
		recs.recSize = block.RecSize
	}
	if recs.recSize != block.RecSize {
		return linkerErrorf(unix.EINVAL, "incompatible .BTF.ext record sizes for section '%s'", block.Section)
	}

	le := binary.LittleEndian
	for off := 0; off+block.RecSize <= len(block.Records); off += block.RecSize {
		start := len(recs.records)
		recs.records = append(recs.records, block.Records[off:off+block.RecSize]...)
		rec := recs.records[start:]
		le.PutUint32(rec, le.Uint32(rec)+uint32(src.dstOff))
		fix(rec)
	}
	return nil
}

func (out *linkerOutput) remapExtType(in *linkerInput, rec []byte, off int) {
	le := binary.LittleEndian
	le.PutUint32(rec[off:], in.btfTypeMap[le.Uint32(rec[off:])])
}

// moveExtString re-adds the input string at rec[off] to the output string
// table. The sanity check already resolved every offset.
func (out *linkerOutput) moveExtString(in *linkerInput, rec []byte, off int) {
	le := binary.LittleEndian
	s, _ := in.btf.String(le.Uint32(rec[off:]))
	le.PutUint32(rec[off:], out.btf.addStr(s))
}

// finalizeBTF returns the .BTF and .BTF.ext sections, 8-byte aligned, or none
// when no input had BTF types. It works on a copy of the output BTF: it adds
// one DATASEC per output section that had one, in section order, and the
// .BTF.ext section names, then deduplicates the types, which rewrites the
// type IDs of the .BTF.ext records. The string table is kept as built.
func (out *linkerOutput) finalizeBTF() ([]objelf.OutputSection, error) {
	if out.btf.typeCnt() == 1 {
		return nil, nil
	}

	b := out.btf.clone()
	for _, s := range out.secs {
		if s.hasBTF {
			b.addDatasec(s.name, s.size, s.vars)
		}
	}

	ext, err := out.finalizeBTFExt(b)
	if err != nil {
		return nil, err
	}

	spec, err := btf.NewSpec(binary.LittleEndian, b.spec.Types, b.strs)
	if err != nil {
		return nil, linkerErrorf(unix.EINVAL, "%v", err)
	}
	if _, err := spec.Dedup(&btf.DedupOpts{Ext: ext}); err != nil {
		return nil, linkerErrorf(errnoFromError(err), "BTF dedup failed: %v", err)
	}

	secs := []objelf.OutputSection{{Name: btfSecName, Type: elf.SHT_PROGBITS, Addralign: 8, Data: spec.Raw()}}
	if ext != nil {
		secs = append(secs, objelf.OutputSection{Name: btfExtSecName, Type: elf.SHT_PROGBITS, Addralign: 8, Data: ext})
	}
	return secs, nil
}

// finalizeBTFExt builds the .BTF.ext section from the records of every output
// section, or returns nil when there are none. Each kind of record has one
// size across all sections.
func (out *linkerOutput) finalizeBTFExt(b *linkerBTF) ([]byte, error) {
	kinds := []struct {
		name string
		recs func(*linkerSec) *linkerExtRecs
	}{
		{"func_info", func(s *linkerSec) *linkerExtRecs { return &s.funcInfo }},
		{"line_info", func(s *linkerSec) *linkerExtRecs { return &s.lineInfo }},
		{"core_relo_info", func(s *linkerSec) *linkerExtRecs { return &s.coreRelo }},
	}

	var subsections [3][]byte
	empty := true
	for k, kind := range kinds {
		recSize, err := out.extRecSize(kind.name, kind.recs)
		if err != nil {
			return nil, err
		}
		if recSize != 0 {
			subsections[k] = out.extSubsection(b, recSize, kind.recs)
			empty = false
		}
	}
	if empty {
		return nil, nil
	}

	le := binary.LittleEndian
	funcs, lines, cores := len(subsections[0]), len(subsections[1]), len(subsections[2])
	data := make([]byte, 0, btfExtHdrLen+funcs+lines+cores)
	data = le.AppendUint16(data, btfMagic)
	data = append(data, btfVersion, 0)
	data = le.AppendUint32(data, btfExtHdrLen)
	data = le.AppendUint32(data, 0)
	data = le.AppendUint32(data, uint32(funcs))
	data = le.AppendUint32(data, uint32(funcs))
	data = le.AppendUint32(data, uint32(lines))
	data = le.AppendUint32(data, uint32(funcs+lines))
	data = le.AppendUint32(data, uint32(cores))
	for _, sub := range subsections {
		data = append(data, sub...)
	}
	return data, nil
}

// extRecSize returns the record size of one kind of .BTF.ext record across
// the output sections, 0 when there are none, or an error when two sections
// disagree.
func (out *linkerOutput) extRecSize(name string, recsOf func(*linkerSec) *linkerExtRecs) (int, error) {
	recSize := 0
	for _, s := range out.secs {
		recs := recsOf(s)
		if recs.count() == 0 {
			continue
		}
		if recSize == 0 {
			recSize = recs.recSize
		}
		if recSize != recs.recSize {
			return 0, linkerErrorf(unix.EINVAL, "mismatch in %s record size %d != %d", name, recSize, recs.recSize)
		}
	}
	return recSize, nil
}

// extSubsection encodes one .BTF.ext subsection: the record size, then for
// each output section with records its name offset, record count and
// records.
func (out *linkerOutput) extSubsection(b *linkerBTF, recSize int, recsOf func(*linkerSec) *linkerExtRecs) []byte {
	le := binary.LittleEndian
	data := le.AppendUint32(nil, uint32(recSize))
	for _, s := range out.secs {
		recs := recsOf(s)
		if recs.count() == 0 {
			continue
		}
		data = le.AppendUint32(data, b.addStr(s.name))
		data = le.AppendUint32(data, uint32(recs.count()))
		data = append(data, recs.records...)
	}
	return data
}
