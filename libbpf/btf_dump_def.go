// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/btf_dump.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: btf_dump_emit_struct_fwd, btf_dump_emit_struct_def, btf_dump_emit_enum_fwd, btf_dump_emit_enum_def, btf_dump_emit_fwd_def, btf_dump_emit_typedef_def, btf_dump_emit_bit_padding, btf_dump_emit_decl_tag, btf_dump_emit_decl_tags, btf_is_struct_packed

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"strings"

	"github.com/gobpfgo/gobpfgo/internal/btf"
)

// maxDumpIndent is the number of tabs in the C library's fixed prefix.
const maxDumpIndent = 13

func pfx(level int) string {
	if level <= 0 {
		return ""
	}
	if level > maxDumpIndent {
		level = maxDumpIndent
	}
	return strings.Repeat("\t", level)
}

func roundup(value, align int) int {
	if align <= 0 {
		return value
	}
	return (value + align - 1) / align * align
}

func (d *BtfDump) emitStructFwd(id uint32, t *btf.Type) {
	kind := "struct"
	if t.Kind == btf.KindUnion {
		kind = "union"
	}
	separator := ""
	if t.NameOff != 0 {
		separator = " "
	}
	d.print("%s%s%s", kind, separator, d.typeName(id))
}

func (d *BtfDump) emitDeclTag(t *btf.Type) {
	if t.KindFlag {
		d.print(" __attribute__((%s))", t.Name)
		return
	}
	d.print(" __attribute__((btf_decl_tag(\"%s\")))", t.Name)
}

// emitDeclTags emits the declaration tags of id whose component index is
// compIdx. The tag list is sorted by target and tag id at resize time.
func (d *BtfDump) emitDeclTags(id uint32, compIdx int) {
	for _, tag := range d.declTags {
		if tag.targetID < id {
			continue
		}
		if tag.targetID > id {
			return
		}
		t := &d.btf.Types[tag.tagID]
		if t.DeclTag != nil && int(t.DeclTag.ComponentIdx) == compIdx {
			d.emitDeclTag(t)
		}
	}
}

// structPacked reports whether the struct or union layout is not naturally
// aligned, which requires the packed attribute.
func (d *BtfDump) structPacked(id uint32, t *btf.Type) bool {
	maxAlign := 1
	for _, member := range t.Members {
		align, err := d.btf.AlignOf(member.Type)
		if err != nil || align <= 0 {
			align = 1
		}
		if member.BitfieldSize == 0 && member.Offset%uint32(8*align) != 0 {
			return true
		}
		if align > maxAlign {
			maxAlign = align
		}
	}
	return t.SizeOrType%uint32(maxAlign) != 0
}

// emitBitPadding fills the gap between curOff and nextOff with explicit
// bitfield padding, choosing the largest naturally aligned type that fits.
func (d *BtfDump) emitBitPadding(curOff, nextOff, nextAlign int, inBitfield bool, level int) {
	pads := []struct {
		name string
		bits int
	}{
		{"long", d.ptrSz * 8},
		{"int", 32},
		{"short", 16},
		{"char", 8},
	}
	if curOff >= nextOff {
		return
	}
	if nextAlign <= 0 {
		nextAlign = 1
	}

	var padType string
	padBits := 0
	newOff := 0
	for _, pad := range pads {
		padType = pad.name
		padBits = pad.bits
		newOff = roundup(curOff, padBits)
		if newOff <= nextOff {
			break
		}
	}

	if newOff > curOff && newOff <= nextOff {
		if inBitfield ||
			(newOff == nextOff && roundup(curOff, nextAlign*8) != newOff) ||
			(newOff != nextOff && nextOff-newOff <= newOff-curOff) {
			bits := 0
			if inBitfield {
				bits = newOff - curOff
			}
			d.print("\n%s%s: %d;", pfx(level), padType, bits)
		}
		curOff = newOff
	}

	for curOff != nextOff {
		bits := nextOff - curOff
		if bits > padBits {
			bits = padBits
		}
		if bits == padBits {
			d.print("\n%s%s: %d;", pfx(level), padType, padBits)
			curOff += bits
			continue
		}
		for i := len(pads) - 1; i >= 0; i-- {
			padType = pads[i].name
			padBits = pads[i].bits
			if padBits < bits {
				continue
			}
			d.print("\n%s%s: %d;", pfx(level), padType, bits)
			curOff += bits
			break
		}
	}
}

func (d *BtfDump) emitStructDef(id uint32, t *btf.Type, level int) {
	isStruct := t.Kind == btf.KindStruct
	kind := "struct"
	if !isStruct {
		kind = "union"
	}
	align, err := d.btf.AlignOf(id)
	if err != nil || align <= 0 {
		align = 1
	}
	packed := isStruct && d.structPacked(id, t)

	separator := ""
	if t.NameOff != 0 {
		separator = " "
	}
	d.print("%s%s%s {", kind, separator, d.typeName(id))

	offset := 0
	prevBitfield := false
	for i, member := range t.Members {
		bitSize := int(member.BitfieldSize)
		memberOff := int(member.Offset)
		memberAlign := 1
		if !packed {
			if a, err := d.btf.AlignOf(member.Type); err == nil && a > 0 {
				memberAlign = a
			}
		}
		inBitfield := prevBitfield && bitSize != 0

		d.emitBitPadding(offset, memberOff, memberAlign, inBitfield, level+1)
		d.print("\n%s", pfx(level+1))
		d.emitTypeDecl(member.Type, member.Name, level+1)

		if bitSize != 0 {
			d.print(": %d", bitSize)
			offset = memberOff + bitSize
			prevBitfield = true
		} else {
			size := 0
			if resolved, err := d.btf.SizeOf(member.Type); err == nil {
				size = int(resolved)
			}
			offset = memberOff + size*8
			prevBitfield = false
		}
		d.emitDeclTags(id, i)
		d.print(";")
	}

	if isStruct {
		d.emitBitPadding(offset, int(t.SizeOrType)*8, align, false, level+1)
	}
	if len(t.Members) != 0 || t.SizeOrType != 0 {
		d.print("\n%s}", pfx(level))
	} else {
		d.print("}")
	}
	if packed {
		d.print(" __attribute__((packed))")
	}
	d.emitDeclTags(id, -1)
}

func (d *BtfDump) emitEnumFwd(id uint32) {
	d.print("enum %s", d.typeName(id))
}

func (d *BtfDump) emitEnum32Val(t *btf.Type, level int) {
	signed := t.KindFlag
	for _, value := range t.Enums {
		dups := d.nameDups(d.identNames, value.Name)
		if dups > 1 {
			if signed {
				d.print("\n%s%s___%d = %d,", pfx(level+1), value.Name, dups, value.Value)
			} else {
				d.print("\n%s%s___%d = %d,", pfx(level+1), value.Name, dups, uint32(value.Value))
			}
			continue
		}
		if signed {
			d.print("\n%s%s = %d,", pfx(level+1), value.Name, value.Value)
		} else {
			d.print("\n%s%s = %d,", pfx(level+1), value.Name, uint32(value.Value))
		}
	}
}

func (d *BtfDump) emitEnum64Val(t *btf.Type, level int) {
	signed := t.KindFlag
	for _, value := range t.Enum64s {
		dups := d.nameDups(d.identNames, value.Name)
		if dups > 1 {
			if signed {
				d.print("\n%s%s___%d = %dLL,", pfx(level+1), value.Name, dups, int64(value.Value))
			} else {
				d.print("\n%s%s___%d = %dULL,", pfx(level+1), value.Name, dups, value.Value)
			}
			continue
		}
		if signed {
			d.print("\n%s%s = %dLL,", pfx(level+1), value.Name, int64(value.Value))
		} else {
			d.print("\n%s%s = %dULL,", pfx(level+1), value.Name, value.Value)
		}
	}
}

func (d *BtfDump) emitEnumDef(id uint32, t *btf.Type, level int) {
	separator := ""
	if t.NameOff != 0 {
		separator = " "
	}
	d.print("enum%s%s", separator, d.typeName(id))
	if len(t.Enums) == 0 && len(t.Enum64s) == 0 {
		return
	}

	d.print(" {")
	if t.Kind == btf.KindEnum {
		d.emitEnum32Val(t, level)
	} else {
		d.emitEnum64Val(t, level)
	}
	d.print("\n%s}", pfx(level))

	if t.SizeOrType == 1 {
		d.print(" __attribute__((mode(byte)))")
	} else if t.SizeOrType == 8 && d.ptrSz == 8 {
		needsWordMode := true
		if t.Kind == btf.KindEnum64 {
			needsWordMode = true
			for _, value := range t.Enum64s {
				if value.Value>>32 != 0 {
					needsWordMode = false
					break
				}
			}
		}
		if needsWordMode {
			d.print(" __attribute__((mode(word)))")
		}
	}
}

func (d *BtfDump) emitFwdDef(id uint32, t *btf.Type) {
	kind := "struct"
	if t.KindFlag {
		kind = "union"
	}
	d.print("%s %s", kind, d.typeName(id))
}

func (d *BtfDump) emitTypedefDef(id uint32, t *btf.Type, level int) {
	name := d.identName(id)
	if t.SizeOrType == 0 && name == "__gnuc_va_list" {
		d.print("typedef __builtin_va_list __gnuc_va_list")
		return
	}
	d.print("typedef ")
	d.emitTypeDecl(t.SizeOrType, name, level)
	d.emitDeclTags(id, -1)
}
