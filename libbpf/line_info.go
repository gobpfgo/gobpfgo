// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/bpf_prog_linfo.c
// libbpf-source: src/bpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_prog_linfo__new, bpf_prog_linfo__free, bpf_prog_linfo__lfind, bpf_prog_linfo__lfind_addr_func, dissect_jited_func, bpf_prog_get_info_by_fd

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// Offsets of the fields of struct bpf_line_info.
const (
	bpfLineInfoOffInsnOff     = 0
	bpfLineInfoOffFileNameOff = 4
	bpfLineInfoOffLineOff     = 8
	bpfLineInfoOffLineCol     = 12
)

// jitedLineInfoAddrSize is the size of the jited address at the start of a
// jited line record.
const jitedLineInfoAddrSize = 8

// BpfLineInfo is one line record of a program. InsnOff is the instruction
// index the line starts at; FileNameOff and LineOff are offsets of the file
// name and source line in the program BTF string table; LineCol packs the
// line number in the upper 22 bits and the column in the lower 10.
type BpfLineInfo struct {
	InsnOff     uint32
	FileNameOff uint32
	LineOff     uint32
	LineCol     uint32
}

// BpfProgInfo is the program metadata BpfProgramInfo reads from the kernel.
//
// LineInfo holds NrLineInfo records of LineInfoRecSize bytes in the kernel's
// struct bpf_line_info layout. JitedLineInfo holds NrJitedLineInfo records of
// JitedLineInfoRecSize bytes; each starts with the jited address of the
// matching line record. JitedKsyms and JitedFuncLens hold the start address
// and the length of each jited function. An array is nil when the kernel did
// not return it.
type BpfProgInfo struct {
	Type                 uint32
	ID                   uint32
	JitedProgLen         uint32
	XlatedProgLen        uint32
	Name                 string
	NrJitedKsyms         uint32
	NrJitedFuncLens      uint32
	JitedKsyms           []uint64
	JitedFuncLens        []uint32
	NrLineInfo           uint32
	LineInfo             []byte
	JitedLineInfo        []byte
	NrJitedLineInfo      uint32
	LineInfoRecSize      uint32
	JitedLineInfoRecSize uint32
}

// BpfProgramInfo returns the kernel metadata of a loaded program, including
// the line info and jited line info that BpfProgLineInfoNew takes.
//
// It returns EINVAL for a nil or unloaded program and the kernel errno when
// BPF_OBJ_GET_INFO_BY_FD fails. The kernel returns no arrays to a caller
// without CAP_BPF or CAP_SYS_ADMIN, and withholds the jited arrays from a
// caller that may not read kernel addresses; their counts are still set.
func BpfProgramInfo(prog *BpfProgram) (*BpfProgInfo, error) {
	const op = "bpf_prog_get_info_by_fd"
	fd := BpfProgramFD(prog)
	if fd < 0 {
		return nil, &Error{Op: op, Errno: unix.EINVAL}
	}

	info, err := sys.ProgInfoByFD(fd)
	if err != nil {
		return nil, &Error{Op: op, Errno: errnoFromError(err)}
	}
	return &BpfProgInfo{
		Type:                 info.Type,
		ID:                   info.ID,
		JitedProgLen:         info.JitedProgLen,
		XlatedProgLen:        info.XlatedProgLen,
		Name:                 info.Name,
		NrJitedKsyms:         info.NrJitedKsyms,
		NrJitedFuncLens:      info.NrJitedFuncLens,
		JitedKsyms:           info.JitedKsyms,
		JitedFuncLens:        info.JitedFuncLens,
		NrLineInfo:           info.NrLineInfo,
		LineInfo:             info.LineInfo,
		JitedLineInfo:        info.JitedLineInfo,
		NrJitedLineInfo:      info.NrJitedLineInfo,
		LineInfoRecSize:      info.LineInfoRecSize,
		JitedLineInfoRecSize: info.JitedLineInfoRecSize,
	}, nil
}

// BpfProgLineInfo is a searchable copy of a program's line info and, when
// available, its jited line info split by jited function. It owns its copies,
// so the BpfProgInfo it came from may change or be dropped.
type BpfProgLineInfo struct {
	rawLinfo            []byte
	rawJitedLinfo       []byte
	nrJitedLinfoPerFunc []uint32
	jitedLinfoFuncIdx   []uint32
	nrLinfo             uint32
	nrJitedFunc         uint32
	recSize             uint32
	jitedRecSize        uint32
	freed               bool
}

// BpfProgLineInfoNew copies the line info of info for BpfProgLineInfoLfind.
//
// When info also has jited line info for every line record, jited records of
// at least eight bytes, and one jited symbol address and one length per jited
// function, the jited records are copied and split by function for
// BpfProgLineInfoLfindAddrFunc. Without them the result still searches by
// instruction offset and the address search returns ENOENT. An empty array
// counts as absent.
//
// It returns EINVAL when info is nil, has no line records, has records
// smaller than the insn_off field, holds fewer bytes or elements than its
// counts and record sizes require, or has jited addresses that do not match
// the jited functions. The caller releases the result with
// BpfProgLineInfoFree.
func BpfProgLineInfoNew(info *BpfProgInfo) (*BpfProgLineInfo, error) {
	const op = "bpf_prog_linfo__new"
	if info == nil {
		return nil, &Error{Op: op, Errno: unix.EINVAL}
	}

	nrLinfo := info.NrLineInfo
	if nrLinfo == 0 {
		return nil, &Error{Op: op, Errno: unix.EINVAL}
	}
	// The search reads insn_off, the field before file_name_off.
	if info.LineInfoRecSize < bpfLineInfoOffFileNameOff {
		return nil, &Error{Op: op, Errno: unix.EINVAL}
	}
	dataSz := uint64(nrLinfo) * uint64(info.LineInfoRecSize)
	if uint64(len(info.LineInfo)) < dataSz {
		return nil, &Error{Op: op, Errno: unix.EINVAL}
	}

	linfo := &BpfProgLineInfo{
		nrLinfo:  nrLinfo,
		recSize:  info.LineInfoRecSize,
		rawLinfo: append([]byte(nil), info.LineInfo[:dataSz]...),
	}

	nrJitedFunc := info.NrJitedKsyms
	if nrJitedFunc == 0 ||
		len(info.JitedLineInfo) == 0 ||
		info.NrJitedLineInfo != nrLinfo ||
		info.JitedLineInfoRecSize < jitedLineInfoAddrSize ||
		info.NrJitedFuncLens != nrJitedFunc ||
		len(info.JitedKsyms) == 0 ||
		len(info.JitedFuncLens) == 0 {
		// Not enough info to search by jited address.
		return linfo, nil
	}

	dataSz = uint64(nrLinfo) * uint64(info.JitedLineInfoRecSize)
	if uint64(len(info.JitedLineInfo)) < dataSz ||
		uint64(len(info.JitedKsyms)) < uint64(nrJitedFunc) ||
		uint64(len(info.JitedFuncLens)) < uint64(nrJitedFunc) {
		return nil, &Error{Op: op, Errno: unix.EINVAL}
	}

	linfo.nrJitedFunc = nrJitedFunc
	linfo.jitedRecSize = info.JitedLineInfoRecSize
	linfo.rawJitedLinfo = append([]byte(nil), info.JitedLineInfo[:dataSz]...)
	linfo.nrJitedLinfoPerFunc = make([]uint32, nrJitedFunc)
	linfo.jitedLinfoFuncIdx = make([]uint32, nrJitedFunc)

	if !linfo.dissectJitedFunc(info.JitedKsyms, info.JitedFuncLens) {
		return nil, &Error{Op: op, Errno: unix.EINVAL}
	}
	return linfo, nil
}

// dissectJitedFunc finds where each jited function starts in the jited line
// records and how many records it has. The first record must be the first
// function's address, every function address must appear in order, and the
// addresses must increase within a function and stay inside its length. The
// loop stops once every function is found, so the records of the last
// function are not checked.
func (l *BpfProgLineInfo) dissectJitedFunc(ksymFunc []uint64, ksymLen []uint32) bool {
	if ksymFunc[0] != l.jitedAddr(0) {
		return false
	}

	l.jitedLinfoFuncIdx[0] = 0
	nrJitedFunc := l.nrJitedFunc
	nrLinfo := l.nrLinfo

	// i searches for the next function address; prevI is the record where
	// the last one was found; f indexes ksymFunc.
	var prevI uint32
	f := uint32(1)
	for i := uint32(1); i < nrLinfo && f < nrJitedFunc; i++ {
		lastJitedLinfo := l.jitedAddr(i - 1)
		jitedLinfo := l.jitedAddr(i)

		if ksymFunc[f] == jitedLinfo {
			l.jitedLinfoFuncIdx[f] = i

			if lastJitedLinfo-ksymFunc[f-1]+1 > uint64(ksymLen[f-1]) {
				return false
			}

			l.nrJitedLinfoPerFunc[f-1] = i - prevI
			prevI = i
			f++
		} else if jitedLinfo <= lastJitedLinfo {
			return false
		}
	}

	if f != nrJitedFunc {
		return false
	}

	l.nrJitedLinfoPerFunc[nrJitedFunc-1] = nrLinfo - prevI
	return true
}

// BpfProgLineInfoFree releases the copies held by l. It accepts nil and a
// second call; afterwards the searches return EINVAL.
func BpfProgLineInfoFree(l *BpfProgLineInfo) {
	if l == nil || l.freed {
		return
	}
	*l = BpfProgLineInfo{freed: true}
}

// BpfProgLineInfoLfindAddrFunc returns the line record of the jited function
// funcIdx that covers the jited address addr: the last record, from the
// function's record nrSkip on, whose jited address is not greater than addr.
// No upper bound is checked, so an address past the end of the function
// returns its last record.
//
// It returns ENOENT when funcIdx is not a jited function, including when l
// has no jited line info, when nrSkip is not below the function's record
// count, or when addr is before the first record searched. It returns EINVAL
// for a nil or freed l.
func BpfProgLineInfoLfindAddrFunc(l *BpfProgLineInfo, addr uint64, funcIdx uint32, nrSkip uint32) (*BpfLineInfo, error) {
	const op = "bpf_prog_linfo__lfind_addr_func"
	if l == nil || l.freed {
		return nil, &Error{Op: op, Errno: unix.EINVAL}
	}

	if funcIdx >= l.nrJitedFunc {
		return nil, &Error{Op: op, Errno: unix.ENOENT}
	}

	nrLinfo := l.nrJitedLinfoPerFunc[funcIdx]
	if nrSkip >= nrLinfo {
		return nil, &Error{Op: op, Errno: unix.ENOENT}
	}

	start := l.jitedLinfoFuncIdx[funcIdx] + nrSkip
	if addr < l.jitedAddr(start) {
		return nil, &Error{Op: op, Errno: unix.ENOENT}
	}

	nrLinfo -= nrSkip
	var i uint32
	for i = 0; i < nrLinfo; i++ {
		if addr < l.jitedAddr(start+i) {
			break
		}
	}

	return l.lineInfo(start + i - 1), nil
}

// BpfProgLineInfoLfind returns the line record that covers the instruction
// at insnOff: the last record, from record nrSkip on, whose instruction
// offset is not greater than insnOff. A caller that already found a record
// can pass its index as nrSkip to resume from it.
//
// It returns ENOENT when nrSkip is not below the record count or insnOff is
// before the first record searched, and EINVAL for a nil or freed l.
func BpfProgLineInfoLfind(l *BpfProgLineInfo, insnOff uint32, nrSkip uint32) (*BpfLineInfo, error) {
	const op = "bpf_prog_linfo__lfind"
	if l == nil || l.freed {
		return nil, &Error{Op: op, Errno: unix.EINVAL}
	}

	nrLinfo := l.nrLinfo
	if nrSkip >= nrLinfo {
		return nil, &Error{Op: op, Errno: unix.ENOENT}
	}

	if insnOff < l.insnOff(nrSkip) {
		return nil, &Error{Op: op, Errno: unix.ENOENT}
	}

	nrLinfo -= nrSkip
	var i uint32
	for i = 0; i < nrLinfo; i++ {
		if insnOff < l.insnOff(nrSkip+i) {
			break
		}
	}

	return l.lineInfo(nrSkip + i - 1), nil
}

// record returns line record i.
func (l *BpfProgLineInfo) record(i uint32) []byte {
	off := int(i) * int(l.recSize)
	return l.rawLinfo[off : off+int(l.recSize)]
}

func (l *BpfProgLineInfo) insnOff(i uint32) uint32 {
	return binary.NativeEndian.Uint32(l.record(i)[bpfLineInfoOffInsnOff:])
}

// jitedAddr returns the jited address of line record i.
func (l *BpfProgLineInfo) jitedAddr(i uint32) uint64 {
	off := int(i) * int(l.jitedRecSize)
	return binary.NativeEndian.Uint64(l.rawJitedLinfo[off:])
}

// lineInfo decodes line record i. A record smaller than struct bpf_line_info
// leaves the fields past its end zero instead of reading the next record.
func (l *BpfProgLineInfo) lineInfo(i uint32) *BpfLineInfo {
	rec := l.record(i)
	var linfo BpfLineInfo
	fields := []struct {
		off int
		val *uint32
	}{
		{bpfLineInfoOffInsnOff, &linfo.InsnOff},
		{bpfLineInfoOffFileNameOff, &linfo.FileNameOff},
		{bpfLineInfoOffLineOff, &linfo.LineOff},
		{bpfLineInfoOffLineCol, &linfo.LineCol},
	}
	for _, field := range fields {
		if field.off+4 > len(rec) {
			break
		}
		*field.val = binary.NativeEndian.Uint32(rec[field.off:])
	}
	return &linfo
}
