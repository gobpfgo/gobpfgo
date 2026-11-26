// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: libbpf_find_vmlinux_btf_id, find_attach_btf_id

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"fmt"
	"strings"
	"sync"

	"github.com/gobpfgo/gobpfgo/internal/btf"
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

// resolveAttachBTFID finds the kernel BTF function id a tracing, LSM or
// tp_btf program attaches to. The section target is the function name after
// the section prefix; module targets are not supported yet.
func resolveAttachBTFID(p *BpfProgram) error {
	if !p.attachBTF || p.attachBTFID != 0 {
		return nil
	}
	if p.attachTarget == "" {
		return fmt.Errorf("section %s has no attach target", p.sectionName)
	}
	if strings.Contains(p.attachTarget, ":") {
		return fmt.Errorf("%w: module attach target %s is not supported", unix.ENOTSUP, p.attachTarget)
	}

	name, kind := attachBTFPrefix(p.expectedAttachType, p.attachTarget)
	kernel, err := vmlinuxBTF()
	if err != nil {
		return err
	}
	fn := kernel.Find(name, kind)
	if fn == nil {
		return fmt.Errorf("%w: type %s not found in vmlinux BTF", unix.ENOENT, name)
	}

	p.attachBTFID = fn.ID
	p.attachBTFObjFD = 0
	return nil
}

// attachBTFPrefix returns the kernel BTF type name and kind for an attach
// target. LSM hooks are functions named bpf_lsm_<hook>; tp_btf targets are
// typedefs named btf_trace_<name>; fentry and fexit use the function name.
func attachBTFPrefix(attachType BpfAttachType, target string) (string, btf.Kind) {
	switch attachType {
	case BPF_TRACE_RAW_TP:
		return "btf_trace_" + target, btf.KindTypedef
	case BPF_LSM_MAC:
		return "bpf_lsm_" + target, btf.KindFunc
	default:
		return target, btf.KindFunc
	}
}
