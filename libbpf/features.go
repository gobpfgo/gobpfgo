// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/features.c
// libbpf-source: src/libbpf_probes.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: probe_kern_bpf_cookie, probe_uprobe_multi_link, probe_kern_btf_decl_tag, probe_kern_arg_ctx_tag, feat_supported, libbpf__load_raw_btf

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"errors"
	"sync"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// kernelFeature is one kernel capability the loader probes on first use. The
// result is kept for the life of the process, like libbpf's global feature
// cache; a probe that cannot run, for example without privileges, reports the
// feature as missing.
type kernelFeature struct {
	once  sync.Once
	ok    bool
	probe func() bool
}

func (f *kernelFeature) supported() bool {
	f.once.Do(func() {
		f.ok = f.probe()
	})
	return f.ok
}

var (
	// featBpfCookie is the BPF cookie capability behind
	// LINUX_HAS_BPF_COOKIE and the USDT spec ID lookup.
	featBpfCookie = kernelFeature{probe: probeBpfCookie}
	// featUprobeMultiLink is a uprobe multi link with process PID
	// filtering, which USDT attachment uses for all call sites at once.
	featUprobeMultiLink = kernelFeature{probe: probeUprobeMultiLink}
	// featBtfDeclTag is BTF_KIND_DECL_TAG in BPF_BTF_LOAD. Without it the
	// load passes the kernel a copy of the object BTF in which every decl
	// tag is an INT.
	featBtfDeclTag = kernelFeature{probe: probeBtfDeclTag}
	// featArgCtxTag is the verifier's own support for the arg:ctx decl
	// tag on a global function argument. Without it the load rewrites the
	// tagged arguments' BTF types to the program's context struct.
	featArgCtxTag = kernelFeature{probe: probeArgCtxTag}
)

// probeBpfCookie reports whether a program can read a BPF cookie: the kernel
// loads a tracepoint program that calls bpf_get_attach_cookie, and accepts a
// BPF perf link, the path that carries the cookie to a single probe. libbpf
// probes the helper alone; both arrived in Linux 5.15, so the result is the
// same on upstream kernels.
func probeBpfCookie() bool {
	attr := &sys.ProgLoadAttr{
		ProgType: uint32(BPF_PROG_TYPE_TRACEPOINT),
		InsnCnt:  2,
	}
	fd, err := sys.ProgLoad(attr, probeHelperInsns(BPF_FUNC_get_attach_cookie), []byte("GPL\x00"), nil, nil, nil, nil)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return perfLinkSupported()
}

// probeUprobeMultiLink reports whether the kernel creates uprobe multi links
// and filters them by process. A two-instruction program loaded for the link
// is attached to "/", which a kernel with the link type rejects with EBADF.
// The first kernels with the link filtered by thread instead of process; the
// fixed ones reject PID -1 with EINVAL before looking at the path. Without
// the fix the feature is reported missing, as USDT attachment picks the link
// at load time and only learns the PID at attach time.
func probeUprobeMultiLink() bool {
	attr := &sys.ProgLoadAttr{
		ProgType:           uint32(BPF_PROG_TYPE_KPROBE),
		InsnCnt:            2,
		ExpectedAttachType: uint32(BPF_TRACE_UPROBE_MULTI),
	}
	progFD, err := sys.ProgLoad(attr, probeProgInsns(), []byte("GPL\x00"), nil, nil, nil, nil)
	if err != nil {
		return false
	}
	defer unix.Close(progFD)

	if !uprobeMultiProbeFails(progFD, 0, unix.EBADF) {
		return false
	}
	return uprobeMultiProbeFails(progFD, ^uint32(0), unix.EINVAL)
}

// uprobeMultiProbeFails creates a uprobe multi link on "/" at offset 0 for
// pid and reports whether the kernel rejected it with want.
func uprobeMultiProbeFails(progFD int, pid uint32, want unix.Errno) bool {
	attr := &sys.LinkCreateAttr{
		ProgFD:     uint32(progFD),
		TargetFD:   ^uint32(0),
		AttachType: uint32(BPF_TRACE_UPROBE_MULTI),
	}
	um := &sys.LinkUprobeMulti{Path: "/", Offsets: []uint64{0}, PID: pid}
	linkFD, err := sys.LinkCreateUprobeMulti(attr, um)
	if err == nil {
		unix.Close(linkFD)
		return false
	}
	return errors.Is(err, want)
}

// probeBtfDeclTag reports whether BPF_BTF_LOAD accepts BTF_KIND_DECL_TAG.
func probeBtfDeclTag() bool {
	fd, err := sys.BtfLoad(declTagBTF(), nil, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// declTagBTF returns the BTF of the decl tag probe: an int, a static
// variable of it named tag, and a decl tag with the same name on the
// variable itself.
func declTagBTF() []byte {
	const strs = "\x00tag\x00"
	types := []uint32{
		// [1] INT: signed, 32 bits, 4 bytes.
		0, btfTypeInfo(btf.KindInt, 0), 4, 1<<24 | 32,
		// [2] VAR tag of [1], static.
		1, btfTypeInfo(btf.KindVar, 0), 1, btf.VarStatic,
		// [3] DECL_TAG tag on [2] itself, component -1.
		1, btfTypeInfo(btf.KindDeclTag, 0), 2, ^uint32(0),
	}
	return rawBTF(types, strs)
}

// probeArgCtxTag reports whether the verifier treats a global function
// argument tagged arg:ctx as the program context. It loads a kprobe program
// that calls a global subprogram, which passes its tagged void * argument to
// bpf_get_func_ip, a helper that needs the context. A kernel without the tag
// rejects the program; one without BTF decl tags rejects the BTF.
func probeArgCtxTag() bool {
	btfFD, err := sys.BtfLoad(argCtxTagBTF(), nil, 0)
	if err != nil {
		return false
	}
	defer unix.Close(btfFD)

	insns := make([]byte, 4*bpfInsnLength)
	for i, insn := range []bpfInsn{
		// The main program, FUNC a.
		{Code: bpfJMP | bpfCall, Src: bpfPseudoCall, Imm: 1},
		{Code: bpfJMP | bpfExit},
		// The global subprogram, FUNC b.
		{Code: bpfJMP | bpfCall, Imm: int32(BPF_FUNC_get_func_ip)},
		{Code: bpfJMP | bpfExit},
	} {
		encodeBpfInsn(insns[i*bpfInsnLength:], insn)
	}

	// One bpf_func_info per function: its first instruction and FUNC.
	var funcInfo []byte
	for _, rec := range [][2]uint32{{0, 4}, {2, 6}} {
		funcInfo = binary.NativeEndian.AppendUint32(funcInfo, rec[0])
		funcInfo = binary.NativeEndian.AppendUint32(funcInfo, rec[1])
	}

	attr := &sys.ProgLoadAttr{
		ProgType:        uint32(BPF_PROG_TYPE_KPROBE),
		InsnCnt:         4,
		ProgBtfFD:       uint32(btfFD),
		FuncInfoRecSize: btf.FuncInfoMinSize,
		FuncInfoCnt:     2,
	}
	attr.SetProgName("det_arg_ctx")
	fd, err := sys.ProgLoad(attr, insns, []byte("GPL\x00"), nil, funcInfo, nil, nil)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}

// argCtxTagBTF returns the BTF of the arg:ctx probe: the main program
// int a(void *a) and the global subprogram int b(void *b), whose argument
// carries the arg:ctx decl tag.
func argCtxTagBTF() []byte {
	const strs = "\x00a\x00b\x00arg:ctx\x00\x00"
	types := []uint32{
		// [1] INT a: signed, 32 bits, 4 bytes.
		1, btfTypeInfo(btf.KindInt, 0), 4, 1<<24 | 32,
		// [2] PTR to void.
		0, btfTypeInfo(btf.KindPtr, 0), 0,
		// [3] FUNC_PROTO int(void *a).
		0, btfTypeInfo(btf.KindFuncProto, 1), 1, 1, 2,
		// [4] FUNC a, global, the main program.
		1, btfTypeInfo(btf.KindFunc, btf.FuncGlobal), 3,
		// [5] FUNC_PROTO int(void *b __arg_ctx).
		0, btfTypeInfo(btf.KindFuncProto, 1), 1, 3, 2,
		// [6] FUNC b, global, the subprogram.
		3, btfTypeInfo(btf.KindFunc, btf.FuncGlobal), 5,
		// [7] DECL_TAG arg:ctx on parameter 0 of [6].
		5, btfTypeInfo(btf.KindDeclTag, 0), 6, 0,
	}
	return rawBTF(types, strs)
}

// btfTypeInfo returns the info word of a BTF type of kind with vlen, which
// for a FUNC is its linkage.
func btfTypeInfo(kind btf.Kind, vlen uint32) uint32 {
	return uint32(kind)<<24 | vlen&0xffff
}

// rawBTFHdrLen is the size of struct btf_header, with the layout section
// fields that a probe leaves zero.
const rawBTFHdrLen = 32

// rawBTF builds a BTF blob from the type words and the string table, with
// the types right after the header and the strings after the types.
func rawBTF(types []uint32, strs string) []byte {
	typeLen := uint32(4 * len(types))
	buf := make([]byte, rawBTFHdrLen, rawBTFHdrLen+int(typeLen)+len(strs))
	binary.NativeEndian.PutUint16(buf[0:], 0xeb9f)
	buf[2] = 1
	binary.NativeEndian.PutUint32(buf[4:], rawBTFHdrLen)
	binary.NativeEndian.PutUint32(buf[12:], typeLen)
	binary.NativeEndian.PutUint32(buf[16:], typeLen)
	binary.NativeEndian.PutUint32(buf[20:], uint32(len(strs)))
	for _, word := range types {
		buf = binary.NativeEndian.AppendUint32(buf, word)
	}
	return append(buf, strs...)
}
