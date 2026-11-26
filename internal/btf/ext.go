// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/btf.c
// libbpf-source: src/libbpf_internal.h
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: btf_ext_header, btf_ext_info_sec, bpf_core_relo

package btf

import (
	"encoding/binary"
	"fmt"
)

// extMagic is the .BTF.ext magic from the UAPI.
const extMagic = 0xeb9f

// extHeaderSize is sizeof(struct btf_ext_header).
const extHeaderSize = 32

// ExtSpec holds the CO-RE relocation records of a .BTF.ext section.
type ExtSpec struct {
	CoreRelos []CoreReloSection
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

// ParseExt parses the .BTF.ext data against the matching BTF spec. Only the
// CO-RE subsection is decoded; function and line info are skipped.
//
// The header offsets are relative to hdr_len, as the UAPI defines. The
// section names and access strings are resolved through spec, so spec must be
// the .BTF blob from the same object.
func ParseExt(data []byte, spec *Spec, order binary.ByteOrder) (*ExtSpec, error) {
	if spec == nil {
		return nil, fmt.Errorf("btf: nil spec")
	}
	if len(data) < extHeaderSize {
		return nil, fmt.Errorf("btf: .BTF.ext header out of bounds")
	}
	if order.Uint16(data) != extMagic {
		return nil, fmt.Errorf("btf: .BTF.ext bad magic %#x", order.Uint16(data))
	}
	if data[2] != 1 {
		return nil, fmt.Errorf("btf: .BTF.ext unsupported version %d", data[2])
	}

	hdrLen := int(order.Uint32(data[4:]))
	if hdrLen < extHeaderSize || hdrLen > len(data) {
		return nil, fmt.Errorf("btf: .BTF.ext header length %d out of bounds", hdrLen)
	}

	coreOff := int(order.Uint32(data[24:]))
	coreLen := int(order.Uint32(data[28:]))
	if coreLen == 0 {
		return &ExtSpec{}, nil
	}
	if coreOff > len(data)-hdrLen || coreLen > len(data)-hdrLen-coreOff {
		return nil, fmt.Errorf("btf: .BTF.ext core section out of bounds")
	}
	if coreOff%4 != 0 {
		return nil, fmt.Errorf("btf: .BTF.ext core section is not 4-byte aligned")
	}

	block := data[hdrLen+coreOff : hdrLen+coreOff+coreLen]
	if len(block) < 4 {
		return nil, fmt.Errorf("btf: .BTF.ext core section has no record size")
	}
	recSize := int(order.Uint32(block))
	if recSize < 16 || recSize%4 != 0 {
		return nil, fmt.Errorf("btf: .BTF.ext core record size %d is invalid", recSize)
	}
	block = block[4:]

	var ext ExtSpec
	for len(block) > 0 {
		if len(block) < 8 {
			return nil, fmt.Errorf("btf: .BTF.ext core section header is truncated")
		}
		secNameOff := order.Uint32(block)
		numInfo := int(order.Uint32(block[4:]))
		block = block[8:]

		if numInfo <= 0 {
			return nil, fmt.Errorf("btf: .BTF.ext core section has no records")
		}
		recordsLen := numInfo * recSize
		if recordsLen/recSize != numInfo || recordsLen > len(block) {
			return nil, fmt.Errorf("btf: .BTF.ext core records are truncated")
		}

		section, err := spec.String(secNameOff)
		if err != nil {
			return nil, fmt.Errorf("btf: .BTF.ext core section name: %w", err)
		}
		if section == "" {
			return nil, fmt.Errorf("btf: .BTF.ext core section has an empty name")
		}

		relos := make([]CoreRelo, 0, numInfo)
		for i := 0; i < numInfo; i++ {
			rec := block[i*recSize:]
			relos = append(relos, CoreRelo{
				InsnOff:      order.Uint32(rec),
				TypeID:       order.Uint32(rec[4:]),
				AccessStrOff: order.Uint32(rec[8:]),
				Kind:         CoreReloKind(order.Uint32(rec[12:])),
			})
		}
		block = block[recordsLen:]
		ext.CoreRelos = append(ext.CoreRelos, CoreReloSection{Section: section, Relos: relos})
	}

	return &ext, nil
}
