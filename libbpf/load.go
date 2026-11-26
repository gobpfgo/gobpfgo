// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-source: src/bpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__load, bpf_object_load, bpf_map_create, bpf_prog_load

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/gobpfgo/gobpfgo/internal/elf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

const bpfPseudoMapFD = 1

// BpfObjectLoad loads the object into the kernel. It validates and loads the
// BTF, creates the maps with their BTF type ids, relocates the map references
// in each program and loads the programs.
//
// The descriptors stay in the object and are closed by BpfObjectClose. The
// caller must have opened the object with BpfObjectOpenFile or
// BpfObjectOpenMem. A second load returns EINVAL. On failure the object is left
// unloaded and the error carries the verifier log when the kernel produced one.
func BpfObjectLoad(obj *BpfObject) error {
	if obj == nil {
		return &Error{Op: "bpf_object__load", Errno: unix.EINVAL}
	}
	if obj.closed {
		return &Error{Op: "bpf_object__load", Errno: unix.EINVAL, Log: "object is closed"}
	}
	if obj.loaded {
		return &Error{Op: "bpf_object__load", Errno: unix.EINVAL, Log: "object already loaded"}
	}
	if obj.btf == nil {
		return &Error{Op: "bpf_object__load", Errno: unix.EINVAL, Log: "object has no BTF"}
	}

	logBuf := make([]byte, 64*1024)
	btfFD, err := sys.BtfLoad(obj.btf.Raw(), logBuf, 1)
	if err != nil {
		return &Error{
			Op:    "bpf_btf_load",
			Errno: errnoFromError(err),
			Log:   strings.TrimRight(string(logBuf), "\x00"),
		}
	}
	obj.btfFD = btfFD

	ext, kernelBTF, err := objectCoreRelocations(obj)
	if err != nil {
		obj.closeLoadFDs()
		return &Error{
			Op:    "bpf_object__relocate_core",
			Errno: errnoFromError(err),
			Log:   err.Error(),
		}
	}

	for _, m := range obj.maps {
		if m.reused {
			info, err := sys.MapInfoByFD(m.fd)
			if err != nil {
				obj.closeLoadFDs()
				return &Error{
					Op:    "bpf_obj_get_info_by_fd",
					Errno: errnoFromError(err),
					Log:   m.name,
				}
			}
			m.id = info.ID
			continue
		}

		attr := &sys.MapCreateAttr{
			MapType:        uint32(m.mapType),
			KeySize:        m.keySize,
			ValueSize:      m.valueSize,
			MaxEntries:     m.maxEntries,
			MapFlags:       m.mapFlags,
			BtfFD:          uint32(btfFD),
			BtfKeyTypeID:   m.btfKeyTypeID,
			BtfValueTypeID: m.btfValueTypeID,
		}
		attr.SetMapName(m.name)

		fd, err := sys.MapCreate(attr, nil)
		if err != nil {
			obj.closeLoadFDs()
			return &Error{
				Op:    "bpf_map_create",
				Errno: errnoFromError(err),
				Log:   m.name,
			}
		}
		m.fd = fd

		info, err := sys.MapInfoByFD(fd)
		if err != nil {
			obj.closeLoadFDs()
			return &Error{
				Op:    "bpf_obj_get_info_by_fd",
				Errno: errnoFromError(err),
				Log:   m.name,
			}
		}
		m.id = info.ID
	}

	license := append([]byte(obj.license), 0)
	for _, p := range obj.programs {
		insns := append([]byte(nil), p.insns...)
		if kernelBTF != nil {
			if err := relocateCore(p, insns, ext, obj.btf, kernelBTF); err != nil {
				obj.closeLoadFDs()
				return &Error{
					Op:    "bpf_object__relocate_core",
					Errno: unix.EINVAL,
					Log:   err.Error(),
				}
			}
		}
		if err := relocateProgram(obj, p, insns); err != nil {
			obj.closeLoadFDs()
			return &Error{
				Op:    "bpf_prog_load",
				Errno: unix.EINVAL,
				Log:   err.Error(),
			}
		}

		attr := &sys.ProgLoadAttr{
			ProgType:           uint32(p.progType),
			InsnCnt:            uint32(len(insns) / 8),
			LogLevel:           1,
			ExpectedAttachType: uint32(p.expectedAttachType),
			ProgBtfFD:          uint32(btfFD),
		}
		attr.SetProgName(p.name)

		fd, err := sys.ProgLoad(attr, insns, license, logBuf)
		if err != nil {
			obj.closeLoadFDs()
			return &Error{
				Op:    "bpf_prog_load",
				Errno: errnoFromError(err),
				Log:   p.name + ": " + strings.TrimRight(string(logBuf), "\x00"),
			}
		}
		p.fd = fd

		info, err := sys.ProgInfoByFD(fd)
		if err != nil {
			obj.closeLoadFDs()
			return &Error{
				Op:    "bpf_obj_get_info_by_fd",
				Errno: errnoFromError(err),
				Log:   p.name,
			}
		}
		p.id = info.ID
		p.xlatedInsnCnt = int(info.XlatedProgLen / 8)
		p.jitedLen = info.JitedProgLen
	}

	obj.loaded = true
	return nil
}

// relocateProgram patches the map references in a private copy of the program
// instructions. The map descriptor is written into the 64-bit immediate of the
// ld_imm64 pair and src_reg is set to BPF_PSEUDO_MAP_FD.
func relocateProgram(obj *BpfObject, p *BpfProgram, insns []byte) error {
	for _, rel := range p.relocs {
		if rel.Type != elf.R_BPF_64_64 {
			return fmt.Errorf("unsupported relocation type %d for %s", rel.Type, rel.Symbol)
		}

		m := findMapBySymbol(obj, rel.Symbol)
		if m == nil {
			return fmt.Errorf("map %s not found", rel.Symbol)
		}
		if m.fd < 0 {
			return fmt.Errorf("map %s has no descriptor", rel.Symbol)
		}

		off := int(rel.Offset)
		if off < 0 || off+16 > len(insns) {
			return fmt.Errorf("relocation for %s at %d is out of range", rel.Symbol, off)
		}

		insns[off+1] = (insns[off+1] & 0x0f) | (bpfPseudoMapFD << 4)
		binary.NativeEndian.PutUint32(insns[off+4:], uint32(m.fd))
		binary.NativeEndian.PutUint32(insns[off+12:], 0)
	}
	return nil
}
