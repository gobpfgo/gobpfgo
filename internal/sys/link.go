// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/bpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_link_create, bpf_link_update, bpf_link_detach, bpf_raw_tracepoint_open_opts, bpf_obj_get

//go:build linux && (amd64 || arm64)

package sys

import (
	"encoding/binary"
	"runtime"

	"golang.org/x/sys/unix"
)

// LinkCreateAttrSize is offsetofend(union bpf_attr, link_create) on 64-bit
// Linux. It is the size libbpf passes to BPF_LINK_CREATE.
const LinkCreateAttrSize = 64

// Offsets inside union bpf_attr for the BPF_LINK_CREATE command, from
// offsetof(union bpf_attr, field) on 64-bit Linux. The anonymous union starts
// at 16; its members overlap.
const (
	linkCreateOffProgFD          = 0
	linkCreateOffTargetFD        = 4
	linkCreateOffAttachType      = 8
	linkCreateOffFlags           = 12
	linkCreateOffTargetBTFID     = 16
	linkCreateOffPerfEventCookie = 16
	linkCreateOffKprobeMultiFlag = 16
	linkCreateOffKprobeMultiCnt  = 20
	linkCreateOffKprobeMultiSyms = 24
	linkCreateOffKprobeMultiAddr = 32
	linkCreateOffKprobeMultiCook = 40
	linkCreateOffTracingBTFID    = 16
	linkCreateOffTracingCookie   = 24
)

// LinkCreateAttr is the BPF_LINK_CREATE view of union bpf_attr.
//
// Only one of TargetBTFID, PerfEventCookie, the KprobeMulti fields and
// TracingCookie may be set: they share the anonymous union. LinkCreate fills
// the pointer fields for the kprobe multi variant; the other callers set the
// value fields directly.
type LinkCreateAttr struct {
	ProgFD             uint32
	TargetFD           uint32
	AttachType         uint32
	Flags              uint32
	TargetBTFID        uint32
	PerfEventCookie    uint64
	KprobeMultiFlags   uint32
	KprobeMultiCnt     uint32
	KprobeMultiSyms    uint64
	KprobeMultiAddrs   uint64
	KprobeMultiCookies uint64
	TracingCookie      uint64
}

// LinkKprobeMulti carries the symbol or address arrays of a kprobe multi
// link. Exactly one of Syms and Addrs is used; Cookies, when present, has one
// entry per symbol or address.
type LinkKprobeMulti struct {
	Flags   uint32
	Syms    []string
	Addrs   []uint64
	Cookies []uint64
}

// Marshal returns the bytes passed to bpf(BPF_LINK_CREATE, ...).
func (a *LinkCreateAttr) Marshal() []byte {
	buf := make([]byte, LinkCreateAttrSize)

	binary.NativeEndian.PutUint32(buf[linkCreateOffProgFD:], a.ProgFD)
	binary.NativeEndian.PutUint32(buf[linkCreateOffTargetFD:], a.TargetFD)
	binary.NativeEndian.PutUint32(buf[linkCreateOffAttachType:], a.AttachType)
	binary.NativeEndian.PutUint32(buf[linkCreateOffFlags:], a.Flags)

	switch {
	case a.TargetBTFID != 0:
		binary.NativeEndian.PutUint32(buf[linkCreateOffTargetBTFID:], a.TargetBTFID)
	case a.KprobeMultiCnt != 0:
		binary.NativeEndian.PutUint32(buf[linkCreateOffKprobeMultiFlag:], a.KprobeMultiFlags)
		binary.NativeEndian.PutUint32(buf[linkCreateOffKprobeMultiCnt:], a.KprobeMultiCnt)
		binary.NativeEndian.PutUint64(buf[linkCreateOffKprobeMultiSyms:], a.KprobeMultiSyms)
		binary.NativeEndian.PutUint64(buf[linkCreateOffKprobeMultiAddr:], a.KprobeMultiAddrs)
		binary.NativeEndian.PutUint64(buf[linkCreateOffKprobeMultiCook:], a.KprobeMultiCookies)
	case a.PerfEventCookie != 0:
		binary.NativeEndian.PutUint64(buf[linkCreateOffPerfEventCookie:], a.PerfEventCookie)
	case a.TracingCookie != 0:
		binary.NativeEndian.PutUint32(buf[linkCreateOffTracingBTFID:], 0)
		binary.NativeEndian.PutUint64(buf[linkCreateOffTracingCookie:], a.TracingCookie)
	}

	return buf
}

// LinkCreate calls BPF_LINK_CREATE and returns the new link descriptor. When
// km is non-nil, its arrays are copied into the attribute and kept alive until
// the syscall returns.
func LinkCreate(attr *LinkCreateAttr, km *LinkKprobeMulti) (int, error) {
	var keeps [][]byte

	if km != nil {
		if attr.TargetBTFID != 0 || attr.PerfEventCookie != 0 || attr.TracingCookie != 0 {
			return -1, unix.EINVAL
		}
		if len(km.Syms) > 0 && len(km.Addrs) > 0 {
			return -1, unix.EINVAL
		}
		cnt := len(km.Syms)
		if len(km.Addrs) > 0 {
			cnt = len(km.Addrs)
		}
		if cnt == 0 || len(km.Cookies) > 0 && len(km.Cookies) != cnt {
			return -1, unix.EINVAL
		}

		attr.KprobeMultiFlags = km.Flags
		attr.KprobeMultiCnt = uint32(cnt)
		if len(km.Syms) > 0 {
			ptrs := make([]byte, cnt*8)
			for i, sym := range km.Syms {
				b := append([]byte(sym), 0)
				keeps = append(keeps, b)
				binary.NativeEndian.PutUint64(ptrs[i*8:], uint64(addr(b)))
			}
			attr.KprobeMultiSyms = uint64(addr(ptrs))
			keeps = append(keeps, ptrs)
		}
		if len(km.Addrs) > 0 {
			buf := u64Bytes(km.Addrs)
			attr.KprobeMultiAddrs = uint64(addr(buf))
			keeps = append(keeps, buf)
		}
		if len(km.Cookies) > 0 {
			buf := u64Bytes(km.Cookies)
			attr.KprobeMultiCookies = uint64(addr(buf))
			keeps = append(keeps, buf)
		}
	}

	fd, err := bpf(BPF_LINK_CREATE, attr.Marshal())
	runtime.KeepAlive(keeps)
	if err != nil {
		return -1, err
	}
	return int(fd), nil
}

func u64Bytes(vals []uint64) []byte {
	buf := make([]byte, len(vals)*8)
	for i, val := range vals {
		binary.NativeEndian.PutUint64(buf[i*8:], val)
	}
	return buf
}

// LinkUpdateAttrSize is offsetofend(union bpf_attr, link_update) on 64-bit
// Linux. It is the size libbpf passes to BPF_LINK_UPDATE.
const LinkUpdateAttrSize = 16

// Offsets inside union bpf_attr for the BPF_LINK_UPDATE command.
const (
	linkUpdateOffLinkFD    = 0
	linkUpdateOffNewProgFD = 4
	linkUpdateOffFlags     = 8
	linkUpdateOffOldProgFD = 12
)

// LinkUpdateAttr is the BPF_LINK_UPDATE view of union bpf_attr. OldProgFD is
// only used with BPF_F_REPLACE.
type LinkUpdateAttr struct {
	LinkFD    uint32
	NewProgFD uint32
	Flags     uint32
	OldProgFD uint32
}

// Marshal returns the bytes passed to bpf(BPF_LINK_UPDATE, ...).
func (a *LinkUpdateAttr) Marshal() []byte {
	buf := make([]byte, LinkUpdateAttrSize)

	binary.NativeEndian.PutUint32(buf[linkUpdateOffLinkFD:], a.LinkFD)
	binary.NativeEndian.PutUint32(buf[linkUpdateOffNewProgFD:], a.NewProgFD)
	binary.NativeEndian.PutUint32(buf[linkUpdateOffFlags:], a.Flags)
	binary.NativeEndian.PutUint32(buf[linkUpdateOffOldProgFD:], a.OldProgFD)

	return buf
}

// LinkUpdate calls BPF_LINK_UPDATE and replaces the program attached through
// linkFD with newProgFD.
func LinkUpdate(attr *LinkUpdateAttr) error {
	if attr == nil {
		return unix.EINVAL
	}
	return BPF(BPF_LINK_UPDATE, attr.Marshal())
}

// LinkDetachAttrSize is offsetofend(union bpf_attr, link_detach).
const LinkDetachAttrSize = 4

// LinkDetach calls BPF_LINK_DETACH on a link descriptor.
func LinkDetach(linkFD int) error {
	if linkFD < 0 {
		return unix.EINVAL
	}
	buf := make([]byte, LinkDetachAttrSize)
	binary.NativeEndian.PutUint32(buf, uint32(linkFD))
	return BPF(BPF_LINK_DETACH, buf)
}

// RawTracepointAttrSize is offsetofend(union bpf_attr, raw_tracepoint).
const RawTracepointAttrSize = 24

// Offsets inside union bpf_attr for the BPF_RAW_TRACEPOINT_OPEN command.
const (
	rawTracepointOffName   = 0
	rawTracepointOffProgFD = 8
	rawTracepointOffCookie = 16
)

// RawTracepointOpen calls BPF_RAW_TRACEPOINT_OPEN and returns the link
// descriptor. name is the tracepoint name, such as "sys_enter"; the kernel
// resolves it to a tracepoint.
func RawTracepointOpen(name string, progFD int, cookie uint64) (int, error) {
	if name == "" {
		return -1, unix.EINVAL
	}

	nameBytes, err := unix.ByteSliceFromString(name)
	if err != nil {
		return -1, err
	}
	return rawTracepointOpen(nameBytes, progFD, cookie)
}

// RawTracepointOpenProgram attaches a tracing program through
// BPF_RAW_TRACEPOINT_OPEN with a NULL tracepoint name. Kernels before the
// tracing link support in BPF_LINK_CREATE use this form for fentry, fexit,
// fmod_ret and LSM programs.
func RawTracepointOpenProgram(progFD int, cookie uint64) (int, error) {
	return rawTracepointOpen(nil, progFD, cookie)
}

func rawTracepointOpen(name []byte, progFD int, cookie uint64) (int, error) {
	if progFD < 0 {
		return -1, unix.EINVAL
	}

	buf := make([]byte, RawTracepointAttrSize)
	if len(name) > 0 {
		binary.NativeEndian.PutUint64(buf[rawTracepointOffName:], uint64(addr(name)))
	}
	binary.NativeEndian.PutUint32(buf[rawTracepointOffProgFD:], uint32(progFD))
	binary.NativeEndian.PutUint64(buf[rawTracepointOffCookie:], cookie)

	fd, err := bpf(BPF_RAW_TRACEPOINT_OPEN, buf)
	runtime.KeepAlive(name)
	if err != nil {
		return -1, err
	}
	return int(fd), nil
}

// ObjGet calls BPF_OBJ_GET and returns the descriptor pinned at path. It opens
// a link, map or program depending on what the path names.
func ObjGet(path string, fileFlags uint32) (int, error) {
	if path == "" {
		return -1, unix.EINVAL
	}

	pathBytes, err := unix.ByteSliceFromString(path)
	if err != nil {
		return -1, err
	}

	attr := &ObjPinAttr{
		Pathname:  uint64(addr(pathBytes)),
		FileFlags: fileFlags,
	}
	fd, err := bpf(BPF_OBJ_GET, attr.Marshal())
	runtime.KeepAlive(pathBytes)
	if err != nil {
		return -1, err
	}
	return int(fd), nil
}

// linkCreateFieldLayout is the Go claim about the C layout of the
// BPF_LINK_CREATE fields. The layout test compares it with the oracle output.
func linkCreateFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"prog_fd", linkCreateOffProgFD, 4},
		{"target_fd", linkCreateOffTargetFD, 4},
		{"attach_type", linkCreateOffAttachType, 4},
		{"flags", linkCreateOffFlags, 4},
		{"target_btf_id", linkCreateOffTargetBTFID, 4},
		{"perf_event.bpf_cookie", linkCreateOffPerfEventCookie, 8},
		{"kprobe_multi.flags", linkCreateOffKprobeMultiFlag, 4},
		{"kprobe_multi.cnt", linkCreateOffKprobeMultiCnt, 4},
		{"kprobe_multi.syms", linkCreateOffKprobeMultiSyms, 8},
		{"kprobe_multi.addrs", linkCreateOffKprobeMultiAddr, 8},
		{"kprobe_multi.cookies", linkCreateOffKprobeMultiCook, 8},
		{"tracing.target_btf_id", linkCreateOffTracingBTFID, 4},
		{"tracing.cookie", linkCreateOffTracingCookie, 8},
	}
}

// linkUpdateFieldLayout is the Go claim about the C layout of the
// BPF_LINK_UPDATE fields.
func linkUpdateFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"link_fd", linkUpdateOffLinkFD, 4},
		{"new_prog_fd", linkUpdateOffNewProgFD, 4},
		{"flags", linkUpdateOffFlags, 4},
		{"old_prog_fd", linkUpdateOffOldProgFD, 4},
	}
}

// rawTracepointFieldLayout is the Go claim about the C layout of the
// BPF_RAW_TRACEPOINT_OPEN fields.
func rawTracepointFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"name", rawTracepointOffName, 8},
		{"prog_fd", rawTracepointOffProgFD, 4},
		{"cookie", rawTracepointOffCookie, 8},
	}
}
