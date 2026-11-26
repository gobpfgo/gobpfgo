// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/btf.c
// libbpf-source: src/libbpf_internal.h
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: btf_ext_header, btf_ext_info_sec, bpf_func_info, bpf_line_info, bpf_core_relo

package btf

import (
	"encoding/binary"
	"fmt"
)

// extMagic is the .BTF.ext magic from the UAPI.
const extMagic = 0xeb9f

// extHeaderSize is sizeof(struct btf_ext_header).
const extHeaderSize = 32

// ExtSpec holds the function, line and CO-RE relocation records of a
// .BTF.ext section.
type ExtSpec struct {
	FuncInfos []FuncInfoSection
	LineInfos []LineInfoSection
	CoreRelos []CoreReloSection
}

// FuncInfoSection groups the function records of one program section.
type FuncInfoSection struct {
	Section string
	Records []FuncInfo
}

// FuncInfo is one struct bpf_func_info record.
type FuncInfo struct {
	InsnOff uint32
	TypeID  uint32
}

// LineInfoSection groups the line records of one program section.
type LineInfoSection struct {
	Section string
	Records []LineInfo
}

// LineInfo is one struct bpf_line_info record. InsnOff is the byte offset of
// the instruction from the start of the section, as Clang emits it;
// FileNameOff and LineOff are string offsets into the object BTF.
type LineInfo struct {
	InsnOff     uint32
	FileNameOff uint32
	LineOff     uint32
	LineCol     uint32
}

// CoreReloSection groups the CO-RE records of one program section.
type CoreReloSection struct {
	Section string
	Relos   []CoreRelo
}

// CoreRelo is one struct bpf_core_relo record.
type CoreRelo struct {
	InsnOff      uint32
	TypeID       uint32
	AccessStrOff uint32
	Kind         CoreReloKind
}

// extRecordSection is one decoded section block of a .BTF.ext subsection.
type extRecordSection struct {
	name    string
	recSize int
	records []byte
}

// ParseExt parses the .BTF.ext data against the matching BTF spec and decodes
// the function, line and CO-RE subsections.
//
// The header offsets are relative to hdr_len, as the UAPI defines. The
// section names and access strings are resolved through spec, so spec must be
// the .BTF blob from the same object.
func ParseExt(data []byte, spec *Spec, order binary.ByteOrder) (*ExtSpec, error) {
	hdrLen, err := extHeaderLen(data, spec, order)
	if err != nil {
		return nil, err
	}

	funcSections, err := parseExtRecords(data, spec, order, hdrLen, extFuncInfoField, FuncInfoMinSize, "func")
	if err != nil {
		return nil, err
	}
	lineSections, err := parseExtRecords(data, spec, order, hdrLen, extLineInfoField, LineInfoMinSize, "line")
	if err != nil {
		return nil, err
	}
	coreSections, err := parseExtRecords(data, spec, order, hdrLen, extCoreReloField, CoreReloMinSize, "core")
	if err != nil {
		return nil, err
	}

	var ext ExtSpec
	for _, section := range funcSections {
		ext.FuncInfos = append(ext.FuncInfos, FuncInfoSection{Section: section.name, Records: decodeFuncInfos(order, section)})
	}
	for _, section := range lineSections {
		ext.LineInfos = append(ext.LineInfos, LineInfoSection{Section: section.name, Records: decodeLineInfos(order, section)})
	}
	for _, section := range coreSections {
		ext.CoreRelos = append(ext.CoreRelos, CoreReloSection{Section: section.name, Relos: decodeCoreRelos(order, section)})
	}

	return &ext, nil
}

// Minimum record sizes of the .BTF.ext subsections: struct bpf_func_info,
// struct bpf_line_info and struct bpf_core_relo. A record may be larger.
const (
	FuncInfoMinSize = 8
	LineInfoMinSize = 16
	CoreReloMinSize = 16
)

// Offsets of the offset and length pairs of each subsection in the .BTF.ext
// header.
const (
	extFuncInfoField = 8
	extLineInfoField = 16
	extCoreReloField = 24
)

// ExtRecords is one section block of a .BTF.ext subsection: the program
// section it describes, the record size and the raw records.
type ExtRecords struct {
	Section string
	RecSize int
	Records []byte
}

// ExtRaw holds the function, line and CO-RE records of a .BTF.ext section
// without decoding them, one block per program section in file order.
type ExtRaw struct {
	FuncInfo []ExtRecords
	LineInfo []ExtRecords
	CoreRelo []ExtRecords
}

// ParseExtRaw validates the .BTF.ext header and splits the function, line and
// CO-RE subsections into raw record blocks. Section names are resolved
// through spec, which must be the .BTF blob from the same object; the records
// themselves are not checked.
func ParseExtRaw(data []byte, spec *Spec, order binary.ByteOrder) (*ExtRaw, error) {
	hdrLen, err := extHeaderLen(data, spec, order)
	if err != nil {
		return nil, err
	}

	var raw ExtRaw
	subsections := []struct {
		field, minRec int
		what          string
		out           *[]ExtRecords
	}{
		{extFuncInfoField, FuncInfoMinSize, "func", &raw.FuncInfo},
		{extLineInfoField, LineInfoMinSize, "line", &raw.LineInfo},
		{extCoreReloField, CoreReloMinSize, "core", &raw.CoreRelo},
	}
	for _, sub := range subsections {
		sections, err := parseExtRecords(data, spec, order, hdrLen, sub.field, sub.minRec, sub.what)
		if err != nil {
			return nil, err
		}
		for _, s := range sections {
			*sub.out = append(*sub.out, ExtRecords{Section: s.name, RecSize: s.recSize, Records: s.records})
		}
	}
	return &raw, nil
}

// extHeaderLen validates the .BTF.ext magic, version and header length and
// returns the header length.
func extHeaderLen(data []byte, spec *Spec, order binary.ByteOrder) (int, error) {
	if spec == nil {
		return 0, fmt.Errorf("btf: nil spec")
	}
	if len(data) < extHeaderSize {
		return 0, fmt.Errorf("btf: .BTF.ext header out of bounds")
	}
	if order.Uint16(data) != extMagic {
		return 0, fmt.Errorf("btf: .BTF.ext bad magic %#x", order.Uint16(data))
	}
	if data[2] != 1 {
		return 0, fmt.Errorf("btf: .BTF.ext unsupported version %d", data[2])
	}

	hdrLen := int(order.Uint32(data[4:]))
	if hdrLen < extHeaderSize || hdrLen > len(data) {
		return 0, fmt.Errorf("btf: .BTF.ext header length %d out of bounds", hdrLen)
	}
	return hdrLen, nil
}

// parseExtRecords decodes one .BTF.ext subsection at the given header field
// offset. A subsection starts with its record size, followed by section
// blocks of a name offset, a record count and the records.
func parseExtRecords(data []byte, spec *Spec, order binary.ByteOrder, hdrLen, fieldOff, minRec int, what string) ([]extRecordSection, error) {
	off := int(order.Uint32(data[fieldOff:]))
	length := int(order.Uint32(data[fieldOff+4:]))
	if length == 0 {
		return nil, nil
	}
	if off > len(data)-hdrLen || length > len(data)-hdrLen-off {
		return nil, fmt.Errorf("btf: .BTF.ext %s section out of bounds", what)
	}
	if off%4 != 0 {
		return nil, fmt.Errorf("btf: .BTF.ext %s section is not 4-byte aligned", what)
	}

	block := data[hdrLen+off : hdrLen+off+length]
	if len(block) < 4 {
		return nil, fmt.Errorf("btf: .BTF.ext %s section has no record size", what)
	}
	recSize := int(order.Uint32(block))
	if recSize < minRec || recSize%4 != 0 {
		return nil, fmt.Errorf("btf: .BTF.ext %s record size %d is invalid", what, recSize)
	}
	block = block[4:]

	var sections []extRecordSection
	for len(block) > 0 {
		if len(block) < 8 {
			return nil, fmt.Errorf("btf: .BTF.ext %s section header is truncated", what)
		}
		nameOff := order.Uint32(block)
		numInfo := int(order.Uint32(block[4:]))
		block = block[8:]

		if numInfo <= 0 {
			return nil, fmt.Errorf("btf: .BTF.ext %s section has no records", what)
		}
		recordsLen := numInfo * recSize
		if recordsLen/recSize != numInfo || recordsLen > len(block) {
			return nil, fmt.Errorf("btf: .BTF.ext %s records are truncated", what)
		}

		name, err := spec.String(nameOff)
		if err != nil {
			return nil, fmt.Errorf("btf: .BTF.ext %s section name: %w", what, err)
		}
		if name == "" {
			return nil, fmt.Errorf("btf: .BTF.ext %s section has an empty name", what)
		}

		sections = append(sections, extRecordSection{name: name, recSize: recSize, records: block[:recordsLen]})
		block = block[recordsLen:]
	}

	return sections, nil
}

func decodeFuncInfos(order binary.ByteOrder, section extRecordSection) []FuncInfo {
	records := make([]FuncInfo, 0, len(section.records)/section.recSize)
	for i := 0; i < len(section.records); i += section.recSize {
		rec := section.records[i:]
		records = append(records, FuncInfo{
			InsnOff: order.Uint32(rec),
			TypeID:  order.Uint32(rec[4:]),
		})
	}
	return records
}

func decodeLineInfos(order binary.ByteOrder, section extRecordSection) []LineInfo {
	records := make([]LineInfo, 0, len(section.records)/section.recSize)
	for i := 0; i < len(section.records); i += section.recSize {
		rec := section.records[i:]
		records = append(records, LineInfo{
			InsnOff:     order.Uint32(rec),
			FileNameOff: order.Uint32(rec[4:]),
			LineOff:     order.Uint32(rec[8:]),
			LineCol:     order.Uint32(rec[12:]),
		})
	}
	return records
}

func decodeCoreRelos(order binary.ByteOrder, section extRecordSection) []CoreRelo {
	records := make([]CoreRelo, 0, len(section.records)/section.recSize)
	for i := 0; i < len(section.records); i += section.recSize {
		rec := section.records[i:]
		records = append(records, CoreRelo{
			InsnOff:      order.Uint32(rec),
			TypeID:       order.Uint32(rec[4:]),
			AccessStrOff: order.Uint32(rec[8:]),
			Kind:         CoreReloKind(order.Uint32(rec[12:])),
		})
	}
	return records
}
