// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: libbpf_find_vmlinux_btf_id, find_attach_btf_id, btf_get_kernel_prefix_kind, libbpf_find_prog_btf_id, libbpf_find_attach_btf_id, bpf_program__set_attach_target

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"fmt"
	"strings"
	"sync"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// vmlinuxBTFCache holds the parsed vmlinux BTF for attach target lookup. The
// spec is read-only, so sharing it across loads is safe.
var vmlinuxBTFCache struct {
	once sync.Once
	spec *btf.Spec
	err  error
}

// vmlinuxBTF returns the parsed vmlinux BTF, reading it once per process.
func vmlinuxBTF() (*btf.Spec, error) {
	vmlinuxBTFCache.once.Do(func() {
		vmlinuxBTFCache.spec, vmlinuxBTFCache.err = loadKernelBTF()
	})
	return vmlinuxBTFCache.spec, vmlinuxBTFCache.err
}

// resolveAttachBTFID finds the BTF function id a tracing, LSM, tp_btf,
// iterator or freplace program is loaded against, from the section target
// after the section prefix, as libbpf_find_attach_btf_id does. A program
// whose id BpfProgramSetAttachTarget already set keeps it.
//
// A bare section, such as SEC("freplace"), names no target, and its program
// returns EINVAL unless BpfProgramSetAttachTarget set the function. A
// BPF_PROG_TYPE_EXT program, and any program BpfProgramSetAttachTarget gave
// an attach program descriptor, resolves the target in that program's BTF;
// an EXT program without one returns EINVAL, as in libbpf. The other
// programs resolve it in the vmlinux BTF; module targets are not supported
// yet. An empty target after the slash is looked up like any other and
// returns ENOENT.
func resolveAttachBTFID(p *BpfProgram) error {
	if !p.attachBTF && !p.attachProg || p.attachBTFID != 0 {
		return nil
	}
	if !strings.Contains(p.sectionName, "/") {
		return fmt.Errorf("%w: prog '%s': no BTF-based attach target is specified, use BpfProgramSetAttachTarget", unix.EINVAL, p.name)
	}

	if p.progType == BPF_PROG_TYPE_EXT || p.attachProgFD != 0 {
		if p.attachProgFD == 0 {
			return fmt.Errorf("%w: prog '%s': attach program FD is not set, use BpfProgramSetAttachTarget", unix.EINVAL, p.name)
		}
		id, err := findProgBTFID(p.attachTarget, p.attachProgFD)
		if err != nil {
			return fmt.Errorf("prog '%s': failed to find BPF program (FD %d) BTF ID for '%s': %w", p.name, p.attachProgFD, p.attachTarget, err)
		}
		p.attachBTFID = id
		p.attachBTFObjFD = 0
		return nil
	}

	id, err := findVmlinuxAttachBTFID(p.expectedAttachType, p.attachTarget)
	if err != nil {
		return err
	}
	p.attachBTFID = id
	p.attachBTFObjFD = 0
	return nil
}

// findVmlinuxAttachBTFID returns the id of the vmlinux BTF type an attach
// target of attachType names, with the prefix and kind attachBTFPrefix
// gives. A module target, "module:function", returns ENOTSUP and a missing
// type ENOENT.
func findVmlinuxAttachBTFID(attachType BpfAttachType, target string) (uint32, error) {
	if strings.Contains(target, ":") {
		return 0, fmt.Errorf("%w: module attach target %s is not supported", unix.ENOTSUP, target)
	}

	name, kind := attachBTFPrefix(attachType, target)
	kernel, err := vmlinuxBTF()
	if err != nil {
		return 0, err
	}
	fn := kernel.Find(name, kind)
	if fn == nil {
		return 0, fmt.Errorf("%w: type %s not found in vmlinux BTF", unix.ENOENT, name)
	}
	return fn.ID, nil
}

// attachBTFPrefix returns the kernel BTF type name and kind for an attach
// target, as btf_get_kernel_prefix_kind does. LSM hooks are functions named
// bpf_lsm_<hook>; iterator targets are functions named bpf_iter_<target>;
// tp_btf targets are typedefs named btf_trace_<name>; fentry and fexit use
// the function name.
func attachBTFPrefix(attachType BpfAttachType, target string) (string, btf.Kind) {
	switch attachType {
	case BPF_TRACE_RAW_TP:
		return "btf_trace_" + target, btf.KindTypedef
	case BPF_LSM_MAC:
		return "bpf_lsm_" + target, btf.KindFunc
	case BPF_TRACE_ITER:
		return "bpf_iter_" + target, btf.KindFunc
	default:
		return target, btf.KindFunc
	}
}

// findProgBTFID returns the id of the BTF FUNC named name in the BTF of the
// loaded program attachProgFD, as libbpf_find_prog_btf_id does. It returns
// the kernel errno when the program's info or BTF cannot be read, such as
// EBADFD for a descriptor that is not open, EINVAL when the program has no
// BTF, as libbpf does, and ENOENT when its BTF has no FUNC named name.
func findProgBTFID(name string, attachProgFD int) (uint32, error) {
	info, err := sys.ProgInfoByFD(attachProgFD)
	if err != nil {
		return 0, fmt.Errorf("failed bpf_prog_get_info_by_fd for FD %d: %w", attachProgFD, err)
	}
	if info.BtfID == 0 {
		return 0, fmt.Errorf("%w: the target program doesn't have BTF", unix.EINVAL)
	}

	fd, err := sys.BtfGetFDByID(info.BtfID)
	if err != nil {
		return 0, fmt.Errorf("failed to get BTF %d of the program: %w", info.BtfID, err)
	}
	defer unix.Close(fd)
	data, err := btfRawFromFD(fd)
	if err != nil {
		return 0, fmt.Errorf("failed to get BTF %d of the program: %w", info.BtfID, err)
	}
	spec, err := btf.Parse(data, binary.NativeEndian)
	if err != nil {
		return 0, fmt.Errorf("failed to get BTF %d of the program: %v: %w", info.BtfID, err, unix.EINVAL)
	}

	id := findByNameKind(spec, 1, name, btf.KindFunc)
	if id == 0 {
		return 0, fmt.Errorf("%w: %s is not found in prog's BTF", unix.ENOENT, name)
	}
	return id, nil
}

// BpfProgramSetAttachTarget sets what a program is loaded against, before
// BpfObjectLoad, as bpf_program__set_attach_target does. attachProgFD is a
// loaded BPF program, such as the program a freplace program replaces a
// function of, or 0 for the kernel; attachFuncName is the function.
//
// With both set, the function's BTF id is looked up in the program's BTF
// now. With only attachProgFD, the section target is looked up in that
// program's BTF at load, and a function id an earlier call set is dropped,
// so the load does not use a function of the previous target; libbpf keeps
// that id. A bare section, such as SEC("freplace"), has no section target,
// so its program needs attachFuncName. With only attachFuncName, the
// function is looked up in the vmlinux BTF now, with the prefix and kind of
// the program's expected attach type; module functions are not supported
// yet. The program keeps attachProgFD, which the caller must keep open
// until the load.
//
// It returns EINVAL for a nil program, a negative attachProgFD, neither
// argument, and a program whose object is loaded or closed. A failed lookup
// returns the error findProgBTFID or the vmlinux lookup reports and leaves
// the program unchanged.
func BpfProgramSetAttachTarget(prog *BpfProgram, attachProgFD int, attachFuncName string) error {
	const op = "bpf_program__set_attach_target"

	if prog == nil || attachProgFD < 0 {
		return &Error{Op: op, Errno: unix.EINVAL}
	}
	if prog.obj != nil && (prog.obj.loaded || prog.obj.closed) {
		return &Error{Op: op, Errno: unix.EINVAL, Log: fmt.Sprintf("prog '%s': object is loaded or closed", prog.name)}
	}

	if attachProgFD != 0 && attachFuncName == "" {
		prog.attachProgFD = attachProgFD
		prog.attachBTFID = 0
		prog.attachBTFObjFD = 0
		return nil
	}

	var id uint32
	var err error
	switch {
	case attachProgFD != 0:
		id, err = findProgBTFID(attachFuncName, attachProgFD)
	case attachFuncName == "":
		return &Error{Op: op, Errno: unix.EINVAL}
	default:
		id, err = findVmlinuxAttachBTFID(prog.expectedAttachType, attachFuncName)
	}
	if err != nil {
		return &Error{Op: op, Errno: errnoFromError(err), Log: err.Error()}
	}

	prog.attachBTFID = id
	prog.attachBTFObjFD = 0
	prog.attachProgFD = attachProgFD
	return nil
}
