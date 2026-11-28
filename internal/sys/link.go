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
	linkCreateOffTargetIfindex   = 4
	linkCreateOffAttachType      = 8
	linkCreateOffFlags           = 12
	linkCreateOffTargetBTFID     = 16
	linkCreateOffIterInfo        = 16
	linkCreateOffIterInfoLen     = 24
	linkCreateOffPerfEventCookie = 16
	linkCreateOffKprobeMultiFlag = 16
	linkCreateOffKprobeMultiCnt  = 20
	linkCreateOffKprobeMultiSyms = 24
	linkCreateOffKprobeMultiAddr = 32
	linkCreateOffKprobeMultiCook = 40
	linkCreateOffTracingBTFID    = 16
	linkCreateOffTracingCookie   = 24
	linkCreateOffUprobeMultiPath = 16
	linkCreateOffUprobeMultiOffs = 24
	linkCreateOffUprobeMultiRef  = 32
	linkCreateOffUprobeMultiCook = 40
	linkCreateOffUprobeMultiCnt  = 48
	linkCreateOffUprobeMultiFlag = 52
	linkCreateOffUprobeMultiPID  = 56
	linkCreateOffCgroupRelFD     = 16
	linkCreateOffCgroupRelID     = 16
	linkCreateOffCgroupExpRev    = 24
)

// LinkCreateAttr is the BPF_LINK_CREATE view of union bpf_attr.
//
// TargetFD is the target descriptor, or the interface index of an XDP link:
// target_fd and target_ifindex share the field.
//
// The other fields after Flags share the anonymous union. Marshal writes a
// nonzero TargetBTFID alone; otherwise AttachType selects the member: the
// IterInfo fields for BPF_TRACE_ITER, PerfEventCookie for BPF_PERF_EVENT, the
// KprobeMulti fields for the kprobe multi and session types, the UprobeMulti
// fields for the uprobe multi and session types, TracingCookie for the
// tracing and LSM types and the Cgroup fields for the cgroup, LSM cgroup and
// struct_ops types. Marshal does not write the fields of the other members,
// and LinkCreate and LinkCreateUprobeMulti refuse them with EINVAL, as
// libbpf's bpf_link_create refuses options outside the selected member.
// LinkCreate fills the pointer fields for the kprobe multi variant and
// LinkCreateUprobeMulti for the uprobe multi variant; the other callers set
// the value fields directly.
type LinkCreateAttr struct {
	ProgFD                   uint32
	TargetFD                 uint32
	AttachType               uint32
	Flags                    uint32
	TargetBTFID              uint32
	IterInfo                 uint64
	IterInfoLen              uint32
	PerfEventCookie          uint64
	KprobeMultiFlags         uint32
	KprobeMultiCnt           uint32
	KprobeMultiSyms          uint64
	KprobeMultiAddrs         uint64
	KprobeMultiCookies       uint64
	TracingCookie            uint64
	UprobeMultiPath          uint64
	UprobeMultiOffsets       uint64
	UprobeMultiRefCtrOffsets uint64
	UprobeMultiCookies       uint64
	UprobeMultiCnt           uint32
	UprobeMultiFlags         uint32
	UprobeMultiPID           uint32
	CgroupRelativeFD         uint32
	CgroupRelativeID         uint32
	CgroupExpectedRevision   uint64
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

// LinkUprobeMulti carries the path and arrays of a uprobe multi link. Offsets
// holds one file offset per probe; RefCtrOffsets and Cookies, when present,
// have one entry per offset. PID 0 probes every process.
type LinkUprobeMulti struct {
	Path          string
	Offsets       []uint64
	RefCtrOffsets []uint64
	Cookies       []uint64
	Flags         uint32
	PID           uint32
}

// Marshal returns the bytes passed to bpf(BPF_LINK_CREATE, ...). The union
// member follows the selection described on LinkCreateAttr. A cgroup link
// with a nonzero CgroupRelativeID writes the id in place of CgroupRelativeFD
// and adds BPF_F_ID to the flags; the struct is not modified.
func (a *LinkCreateAttr) Marshal() []byte {
	buf := make([]byte, LinkCreateAttrSize)

	binary.NativeEndian.PutUint32(buf[linkCreateOffProgFD:], a.ProgFD)
	binary.NativeEndian.PutUint32(buf[linkCreateOffTargetFD:], a.TargetFD)
	binary.NativeEndian.PutUint32(buf[linkCreateOffAttachType:], a.AttachType)
	binary.NativeEndian.PutUint32(buf[linkCreateOffFlags:], a.Flags)

	if a.TargetBTFID != 0 {
		binary.NativeEndian.PutUint32(buf[linkCreateOffTargetBTFID:], a.TargetBTFID)
		return buf
	}

	switch linkMemberFor(a.AttachType) {
	case linkMemberIter:
		binary.NativeEndian.PutUint64(buf[linkCreateOffIterInfo:], a.IterInfo)
		binary.NativeEndian.PutUint32(buf[linkCreateOffIterInfoLen:], a.IterInfoLen)
	case linkMemberPerfEvent:
		binary.NativeEndian.PutUint64(buf[linkCreateOffPerfEventCookie:], a.PerfEventCookie)
	case linkMemberKprobeMulti:
		binary.NativeEndian.PutUint32(buf[linkCreateOffKprobeMultiFlag:], a.KprobeMultiFlags)
		binary.NativeEndian.PutUint32(buf[linkCreateOffKprobeMultiCnt:], a.KprobeMultiCnt)
		binary.NativeEndian.PutUint64(buf[linkCreateOffKprobeMultiSyms:], a.KprobeMultiSyms)
		binary.NativeEndian.PutUint64(buf[linkCreateOffKprobeMultiAddr:], a.KprobeMultiAddrs)
		binary.NativeEndian.PutUint64(buf[linkCreateOffKprobeMultiCook:], a.KprobeMultiCookies)
	case linkMemberUprobeMulti:
		binary.NativeEndian.PutUint64(buf[linkCreateOffUprobeMultiPath:], a.UprobeMultiPath)
		binary.NativeEndian.PutUint64(buf[linkCreateOffUprobeMultiOffs:], a.UprobeMultiOffsets)
		binary.NativeEndian.PutUint64(buf[linkCreateOffUprobeMultiRef:], a.UprobeMultiRefCtrOffsets)
		binary.NativeEndian.PutUint64(buf[linkCreateOffUprobeMultiCook:], a.UprobeMultiCookies)
		binary.NativeEndian.PutUint32(buf[linkCreateOffUprobeMultiCnt:], a.UprobeMultiCnt)
		binary.NativeEndian.PutUint32(buf[linkCreateOffUprobeMultiFlag:], a.UprobeMultiFlags)
		binary.NativeEndian.PutUint32(buf[linkCreateOffUprobeMultiPID:], a.UprobeMultiPID)
	case linkMemberTracing:
		binary.NativeEndian.PutUint32(buf[linkCreateOffTracingBTFID:], 0)
		binary.NativeEndian.PutUint64(buf[linkCreateOffTracingCookie:], a.TracingCookie)
	case linkMemberCgroup:
		a.marshalCgroup(buf)
	}

	return buf
}

// marshalCgroup writes the cgroup member of the union: the relative id with
// BPF_F_ID when CgroupRelativeID is set, the relative descriptor otherwise,
// and the expected revision.
func (a *LinkCreateAttr) marshalCgroup(buf []byte) {
	if a.CgroupRelativeID != 0 {
		binary.NativeEndian.PutUint32(buf[linkCreateOffCgroupRelID:], a.CgroupRelativeID)
		binary.NativeEndian.PutUint32(buf[linkCreateOffFlags:], a.Flags|BPF_F_ID)
	} else {
		binary.NativeEndian.PutUint32(buf[linkCreateOffCgroupRelFD:], a.CgroupRelativeFD)
	}
	binary.NativeEndian.PutUint64(buf[linkCreateOffCgroupExpRev:], a.CgroupExpectedRevision)
}

// validate applies the BPF_LINK_CREATE input rules that do not need the
// kernel and returns EINVAL when one is broken. A nonzero TargetBTFID is the
// union member whatever the attach type, as in libbpf, whose freplace attach
// passes it with attach type 0, BPF_CGROUP_INET_INGRESS. Otherwise AttachType
// selects the member as in Marshal, and an attach type without a member
// selects none. A nonzero field of any member but the selected one is
// refused, so iterator info needs BPF_TRACE_ITER and a target BTF id takes no
// other union field. A cgroup link also takes at most one of the relative
// descriptor and id.
func (a *LinkCreateAttr) validate() error {
	member := linkMemberFor(a.AttachType)
	if a.TargetBTFID != 0 {
		member = linkMemberNone
	}
	for m := linkMemberIter; m <= linkMemberCgroup; m++ {
		if m != member && a.memberSet(m) {
			return unix.EINVAL
		}
	}
	if member == linkMemberCgroup && a.CgroupRelativeFD != 0 && a.CgroupRelativeID != 0 {
		return unix.EINVAL
	}
	return nil
}

// linkMember names a member of the BPF_LINK_CREATE union, after the target
// BTF id.
type linkMember int

const (
	linkMemberNone linkMember = iota
	linkMemberIter
	linkMemberPerfEvent
	linkMemberKprobeMulti
	linkMemberUprobeMulti
	linkMemberTracing
	linkMemberCgroup
)

// linkMemberFor returns the union member attachType selects, or
// linkMemberNone for an attach type without one, such as BPF_XDP.
func linkMemberFor(attachType uint32) linkMember {
	switch {
	case attachType == BPF_TRACE_ITER:
		return linkMemberIter
	case attachType == BPF_PERF_EVENT:
		return linkMemberPerfEvent
	case isKprobeMultiAttach(attachType):
		return linkMemberKprobeMulti
	case isUprobeMultiAttach(attachType):
		return linkMemberUprobeMulti
	case isTracingAttach(attachType):
		return linkMemberTracing
	case isCgroupAttach(attachType):
		return linkMemberCgroup
	}
	return linkMemberNone
}

// memberSet reports whether a field of member m is nonzero.
func (a *LinkCreateAttr) memberSet(m linkMember) bool {
	switch m {
	case linkMemberIter:
		return a.IterInfo != 0 || a.IterInfoLen != 0
	case linkMemberPerfEvent:
		return a.PerfEventCookie != 0
	case linkMemberKprobeMulti:
		return a.KprobeMultiFlags != 0 || a.KprobeMultiCnt != 0 || a.KprobeMultiSyms != 0 ||
			a.KprobeMultiAddrs != 0 || a.KprobeMultiCookies != 0
	case linkMemberUprobeMulti:
		return a.UprobeMultiPath != 0 || a.UprobeMultiOffsets != 0 || a.UprobeMultiRefCtrOffsets != 0 ||
			a.UprobeMultiCookies != 0 || a.UprobeMultiCnt != 0 || a.UprobeMultiFlags != 0 || a.UprobeMultiPID != 0
	case linkMemberTracing:
		return a.TracingCookie != 0
	case linkMemberCgroup:
		return a.CgroupRelativeFD != 0 || a.CgroupRelativeID != 0 || a.CgroupExpectedRevision != 0
	}
	return false
}

func isKprobeMultiAttach(attachType uint32) bool {
	return attachType == BPF_TRACE_KPROBE_MULTI || attachType == BPF_TRACE_KPROBE_SESSION
}

func isUprobeMultiAttach(attachType uint32) bool {
	return attachType == BPF_TRACE_UPROBE_MULTI || attachType == BPF_TRACE_UPROBE_SESSION
}

// isTracingAttach reports whether attachType carries the tracing cookie.
func isTracingAttach(attachType uint32) bool {
	switch attachType {
	case BPF_TRACE_RAW_TP, BPF_TRACE_FENTRY, BPF_TRACE_FEXIT, BPF_MODIFY_RETURN,
		BPF_TRACE_FSESSION, BPF_LSM_MAC:
		return true
	}
	return false
}

// isCgroupAttach reports whether attachType carries the cgroup member: the
// cgroup hooks, BPF_LSM_CGROUP and BPF_STRUCT_OPS.
func isCgroupAttach(attachType uint32) bool {
	switch attachType {
	case BPF_CGROUP_INET_INGRESS, BPF_CGROUP_INET_EGRESS,
		BPF_CGROUP_INET_SOCK_CREATE, BPF_CGROUP_INET_SOCK_RELEASE,
		BPF_CGROUP_INET4_BIND, BPF_CGROUP_INET6_BIND,
		BPF_CGROUP_INET4_POST_BIND, BPF_CGROUP_INET6_POST_BIND,
		BPF_CGROUP_INET4_CONNECT, BPF_CGROUP_INET6_CONNECT, BPF_CGROUP_UNIX_CONNECT,
		BPF_CGROUP_INET4_GETPEERNAME, BPF_CGROUP_INET6_GETPEERNAME, BPF_CGROUP_UNIX_GETPEERNAME,
		BPF_CGROUP_INET4_GETSOCKNAME, BPF_CGROUP_INET6_GETSOCKNAME, BPF_CGROUP_UNIX_GETSOCKNAME,
		BPF_CGROUP_UDP4_SENDMSG, BPF_CGROUP_UDP6_SENDMSG, BPF_CGROUP_UNIX_SENDMSG,
		BPF_CGROUP_UDP4_RECVMSG, BPF_CGROUP_UDP6_RECVMSG, BPF_CGROUP_UNIX_RECVMSG,
		BPF_CGROUP_SOCK_OPS, BPF_CGROUP_DEVICE, BPF_CGROUP_SYSCTL,
		BPF_CGROUP_GETSOCKOPT, BPF_CGROUP_SETSOCKOPT,
		BPF_LSM_CGROUP, BPF_STRUCT_OPS:
		return true
	}
	return false
}

// LinkCreate calls BPF_LINK_CREATE and returns the new link descriptor. When
// km is non-nil, its arrays are copied into the attribute and kept alive until
// the syscall returns; AttachType must then be BPF_TRACE_KPROBE_MULTI or
// BPF_TRACE_KPROBE_SESSION, the types that select the kprobe multi member,
// or the call returns EINVAL before it fills the arrays. It also returns
// EINVAL for a nil attr and for the attributes validate refuses.
func LinkCreate(attr *LinkCreateAttr, km *LinkKprobeMulti) (int, error) {
	var keeps [][]byte

	if attr == nil {
		return -1, unix.EINVAL
	}
	if km != nil {
		if !isKprobeMultiAttach(attr.AttachType) {
			return -1, unix.EINVAL
		}
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

	return linkCreate(attr, keeps)
}

// LinkCreateUprobeMulti calls BPF_LINK_CREATE for a uprobe multi link and
// returns the new link descriptor. The path and arrays of um are copied into
// the attribute and kept alive until the syscall returns. It returns EINVAL
// before it fills the arrays when AttachType is not BPF_TRACE_UPROBE_MULTI or
// BPF_TRACE_UPROBE_SESSION, the types that select the uprobe multi member,
// when the path is empty or contains a NUL byte, when Offsets is empty, when
// RefCtrOffsets or Cookies is set with a different length, or when attr
// already uses another member of the union.
func LinkCreateUprobeMulti(attr *LinkCreateAttr, um *LinkUprobeMulti) (int, error) {
	keeps, err := setUprobeMulti(attr, um)
	if err != nil {
		return -1, err
	}
	return linkCreate(attr, keeps)
}

// setUprobeMulti validates um, copies its path and arrays into new buffers and
// points the uprobe multi fields of attr at them. It returns the buffers,
// which must stay alive until the syscall returns.
func setUprobeMulti(attr *LinkCreateAttr, um *LinkUprobeMulti) ([][]byte, error) {
	if attr == nil || um == nil || !isUprobeMultiAttach(attr.AttachType) {
		return nil, unix.EINVAL
	}
	if attr.TargetBTFID != 0 || attr.PerfEventCookie != 0 || attr.TracingCookie != 0 || attr.KprobeMultiCnt != 0 {
		return nil, unix.EINVAL
	}
	cnt := len(um.Offsets)
	if cnt == 0 || len(um.RefCtrOffsets) > 0 && len(um.RefCtrOffsets) != cnt || len(um.Cookies) > 0 && len(um.Cookies) != cnt {
		return nil, unix.EINVAL
	}
	if um.Path == "" {
		return nil, unix.EINVAL
	}
	path, err := unix.ByteSliceFromString(um.Path)
	if err != nil {
		return nil, err
	}

	offsets := u64Bytes(um.Offsets)
	keeps := [][]byte{path, offsets}
	attr.UprobeMultiPath = uint64(addr(path))
	attr.UprobeMultiOffsets = uint64(addr(offsets))
	attr.UprobeMultiCnt = uint32(cnt)
	attr.UprobeMultiFlags = um.Flags
	attr.UprobeMultiPID = um.PID
	if len(um.RefCtrOffsets) > 0 {
		buf := u64Bytes(um.RefCtrOffsets)
		attr.UprobeMultiRefCtrOffsets = uint64(addr(buf))
		keeps = append(keeps, buf)
	}
	if len(um.Cookies) > 0 {
		buf := u64Bytes(um.Cookies)
		attr.UprobeMultiCookies = uint64(addr(buf))
		keeps = append(keeps, buf)
	}
	return keeps, nil
}

// linkCreate validates attr, issues BPF_LINK_CREATE and keeps the buffers the
// attribute points to alive until the syscall returns.
func linkCreate(attr *LinkCreateAttr, keeps [][]byte) (int, error) {
	if err := attr.validate(); err != nil {
		return -1, err
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
		{"target_ifindex", linkCreateOffTargetIfindex, 4},
		{"attach_type", linkCreateOffAttachType, 4},
		{"flags", linkCreateOffFlags, 4},
		{"target_btf_id", linkCreateOffTargetBTFID, 4},
		{"iter_info", linkCreateOffIterInfo, 8},
		{"iter_info_len", linkCreateOffIterInfoLen, 4},
		{"perf_event.bpf_cookie", linkCreateOffPerfEventCookie, 8},
		{"kprobe_multi.flags", linkCreateOffKprobeMultiFlag, 4},
		{"kprobe_multi.cnt", linkCreateOffKprobeMultiCnt, 4},
		{"kprobe_multi.syms", linkCreateOffKprobeMultiSyms, 8},
		{"kprobe_multi.addrs", linkCreateOffKprobeMultiAddr, 8},
		{"kprobe_multi.cookies", linkCreateOffKprobeMultiCook, 8},
		{"tracing.target_btf_id", linkCreateOffTracingBTFID, 4},
		{"tracing.cookie", linkCreateOffTracingCookie, 8},
		{"uprobe_multi.path", linkCreateOffUprobeMultiPath, 8},
		{"uprobe_multi.offsets", linkCreateOffUprobeMultiOffs, 8},
		{"uprobe_multi.ref_ctr_offsets", linkCreateOffUprobeMultiRef, 8},
		{"uprobe_multi.cookies", linkCreateOffUprobeMultiCook, 8},
		{"uprobe_multi.cnt", linkCreateOffUprobeMultiCnt, 4},
		{"uprobe_multi.flags", linkCreateOffUprobeMultiFlag, 4},
		{"uprobe_multi.pid", linkCreateOffUprobeMultiPID, 4},
		{"cgroup.relative_fd", linkCreateOffCgroupRelFD, 4},
		{"cgroup.relative_id", linkCreateOffCgroupRelID, 4},
		{"cgroup.expected_revision", linkCreateOffCgroupExpRev, 8},
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
