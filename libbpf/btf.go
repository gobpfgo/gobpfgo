// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/btf.c
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: btf__new, btf__parse, btf__type_cnt, btf__free, bpf_object__btf

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"os"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/elf"
	"golang.org/x/sys/unix"
)

// Btf is a parsed BTF type table. The dump and future BTF APIs take it as the
// type source. A Btf returned by BpfObjectBTF is owned by the object and must
// not be freed by the caller.
type Btf struct {
	spec *btf.Spec
}

// BtfNew parses a raw BTF blob, such as the contents of .BTF or
// /sys/kernel/btf/vmlinux.
func BtfNew(data []byte) (*Btf, error) {
	if len(data) == 0 {
		return nil, &Error{Op: "btf__new", Errno: unix.EINVAL}
	}
	spec, err := btf.Parse(data, binary.NativeEndian)
	if err != nil {
		return nil, &Error{Op: "btf__new", Errno: errnoFromError(err), Log: err.Error()}
	}
	return &Btf{spec: spec}, nil
}

// BtfParse parses a BTF file. It accepts a raw BTF blob or an ELF object with
// a .BTF section.
func BtfParse(path string) (*Btf, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &Error{Op: "btf__parse", Errno: errnoFromError(err), Path: path}
	}
	if len(data) >= 4 && binary.NativeEndian.Uint16(data) == 0xeb9f {
		return BtfNew(data)
	}

	obj, err := elf.OpenBytes(data)
	if err != nil {
		return nil, &Error{Op: "btf__parse", Errno: unix.EINVAL, Path: path, Log: err.Error()}
	}
	if len(obj.BTF) == 0 {
		return nil, &Error{Op: "btf__parse", Errno: unix.ENOENT, Path: path, Log: "no .BTF section"}
	}
	spec, err := btf.Parse(obj.BTF, obj.ByteOrder)
	if err != nil {
		return nil, &Error{Op: "btf__parse", Errno: errnoFromError(err), Path: path, Log: err.Error()}
	}
	if err := spec.FixupDatasecSizes(sectionSizes(obj)); err != nil {
		return nil, &Error{Op: "btf__parse", Errno: unix.EINVAL, Path: path, Log: err.Error()}
	}
	return &Btf{spec: spec}, nil
}

// BtfTypeCnt returns the number of types, including the void type at id 0.
func BtfTypeCnt(b *Btf) int {
	if b == nil || b.spec == nil {
		return 0
	}
	return len(b.spec.Types)
}

// BtfFree releases the table. It is nil-safe and idempotent. A table borrowed
// from an object must not be freed.
func BtfFree(b *Btf) {
	if b == nil {
		return
	}
	b.spec = nil
}

// BpfObjectBTF returns the object's parsed BTF table. The descriptor is
// borrowed: the caller must not free it and must not use it after
// BpfObjectClose.
func BpfObjectBTF(obj *BpfObject) *Btf {
	if obj == nil || obj.btf == nil {
		return nil
	}
	return &Btf{spec: obj.btf}
}

// btfSpec returns the underlying spec for the dump implementation.
func (b *Btf) btfSpec() (*btf.Spec, error) {
	if b == nil || b.spec == nil {
		return nil, &Error{Op: "btf", Errno: unix.EINVAL}
	}
	return b.spec, nil
}
