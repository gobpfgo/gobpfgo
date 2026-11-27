// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__sanitize_btf

package btf

import (
	"bytes"
	"fmt"
)

// The INT that SanitizeDeclTags writes over a DECL_TAG: one byte, with the
// encoding word BTF_INT_ENC(0, 0, 8), so no encoding flag, bit offset 0 and
// 8 bits.
const (
	sanitizedDeclTagSize   = 1
	sanitizedDeclTagIntEnc = 8
)

// SanitizeDeclTags returns a copy of the BTF blob for a kernel without
// BTF_KIND_DECL_TAG, which Linux added in 5.16. In the copy, every DECL_TAG
// is an INT of one byte with the encoding word BTF_INT_ENC(0, 0, 8), without
// kind flag, that keeps the tag's name offset. A DECL_TAG record is as long
// as an INT record, its component index word becoming the INT encoding, so
// the replacement is in place: the header, every other record, every type ID
// and the string table are the same as in Raw.
//
// The spec is not changed; its types and Raw keep the DECL_TAGs. A blob
// without DECL_TAGs comes back as an unchanged copy. A split spec, whose
// records continue a base blob, is an error.
func (s *Spec) SanitizeDeclTags() ([]byte, error) {
	if s.base != nil || s.raw == nil {
		return nil, fmt.Errorf("btf: cannot sanitize split BTF")
	}

	raw := bytes.Clone(s.raw)
	intInfo := uint32(KindInt) << 24
	for i := 1; i < len(s.Types); i++ {
		t := &s.Types[i]
		if t.Kind != KindDeclTag {
			continue
		}
		// The info, size and first payload words follow the name offset.
		for j, word := range []uint32{intInfo, sanitizedDeclTagSize, sanitizedDeclTagIntEnc} {
			if err := s.putRecordWord(raw, t, 4+4*j, word); err != nil {
				return nil, err
			}
		}
	}
	return raw, nil
}
