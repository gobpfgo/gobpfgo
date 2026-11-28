// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"strconv"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
)

// The root tests in this file load the iterator and freplace fixtures,
// attach them, check the link through its fdinfo and destroy it, like the
// tests of attach_fd_load_test.go.

// TestBpfProgramAttachIter loads iter.bpf.o, whose iter/bpf_map program the
// load resolves to the kernel's bpf_iter_bpf_map function, attaches it with
// nil options, with nil link info and through the section name, and checks
// the iter link. The kernels that print the iterator target in the link
// fdinfo must name bpf_map. It skips with the load error when the kernel BTF
// has no bpf_iter_bpf_map.
func TestBpfProgramAttachIter(t *testing.T) {
	obj := loadIterObject(t)
	defer BpfObjectClose(obj)
	prog := findProgram(t, obj, "dump_bpf_map")

	attaches := []struct {
		name   string
		attach func() (*BpfLink, error)
	}{
		{"nil options", func() (*BpfLink, error) { return BpfProgramAttachIter(prog, nil) }},
		{"nil link info", func() (*BpfLink, error) { return BpfProgramAttachIter(prog, &BpfIterOpts{}) }},
		{"section", func() (*BpfLink, error) { return BpfProgramAttach(prog) }},
	}
	for _, a := range attaches {
		t.Run(a.name, func(t *testing.T) {
			link, err := a.attach()
			if err != nil {
				skipIfNotPermitted(t, err)
				t.Fatalf("attach: %v", err)
			}
			checkLinkFdinfo(t, link, prog, "iter", nil)
			if target, ok := fdinfo(t, BpfLinkFD(link))["target_name"]; ok && target != "bpf_map" {
				t.Errorf("target_name = %q, want bpf_map", target)
			}
			destroyLink(t, link)
		})
	}
}

// loadIterObject loads iter.bpf.o. A kernel whose BTF has no
// bpf_iter_bpf_map function makes the load fail, and the test skips with
// the load error.
func loadIterObject(t *testing.T) *BpfObject {
	t.Helper()

	path := progsDir + "/iter.bpf.o"
	obj, err := BpfObjectOpenFile(path, nil)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if err := BpfObjectLoad(obj); err != nil {
		BpfObjectClose(obj)
		skipIfNotPermitted(t, err)
		skipIfKernelLacks(t, "the bpf_map iterator", kernelFuncHas(t, "bpf_iter_bpf_map"), err)
		t.Fatalf("load %s: %v", path, err)
	}
	return obj
}

// TestBpfProgramAttachFreplace loads xdp.bpf.o as the target and
// freplace.bpf.o against its xdp_pass function, and attaches the freplace
// program in place of xdp_pass: with the target descriptor and
// function name, which sends the target and its BTF id through
// BPF_LINK_CREATE; without a target, which attaches to the load-time target;
// and through the section name. Each case loads freplace.bpf.o again,
// because the kernel forgets the load-time target after the first attach.
// The link must be a tracing link with attach type 0; the kernels that print
// the target in the link fdinfo must name the target program's id and the
// BTF id of xdp_pass in its BTF. It skips with the kernel's errno when the
// kernel BTF has no program extensions.
//
// The target is not kprobe.bpf.o's handle_open: its void * argument is not
// the kprobe context type, so the kernel marks the function's BTF
// unreliable and refuses to replace it with "Cannot replace static
// functions".
func TestBpfProgramAttachFreplace(t *testing.T) {
	target := loadTestObject(t, progsDir+"/xdp.bpf.o")
	defer BpfObjectClose(target)
	targetProg := findProgram(t, target, "xdp_pass")
	fn := target.btf.Find("xdp_pass", btf.KindFunc)
	if fn == nil {
		t.Fatal("xdp.bpf.o BTF has no FUNC xdp_pass")
	}

	attaches := []struct {
		name     string
		loadName string
		attach   func(*BpfProgram) (*BpfLink, error)
	}{
		{"target", "xdp_pass", func(p *BpfProgram) (*BpfLink, error) {
			return BpfProgramAttachFreplace(p, targetProg.fd, "xdp_pass")
		}},
		{"no target", "", func(p *BpfProgram) (*BpfLink, error) { return BpfProgramAttachFreplace(p, 0, "") }},
		{"section", "", func(p *BpfProgram) (*BpfLink, error) { return BpfProgramAttach(p) }},
	}
	for _, a := range attaches {
		t.Run(a.name, func(t *testing.T) {
			obj := loadFreplaceObject(t, targetProg.fd, a.loadName)
			defer BpfObjectClose(obj)
			prog := findProgram(t, obj, "replace_xdp")

			link, err := a.attach(prog)
			if err != nil {
				skipIfNotPermitted(t, err)
				skipIfKernelLacks(t, "program extensions", kernelEnumHas(t, "bpf_prog_type", "BPF_PROG_TYPE_EXT"), err)
				t.Fatalf("attach: %v", err)
			}
			checkLinkFdinfo(t, link, prog, "tracing", map[string]string{"attach_type": "0"})
			info := fdinfo(t, BpfLinkFD(link))
			if id, ok := info["target_obj_id"]; ok && id != strconv.FormatUint(uint64(targetProg.id), 10) {
				t.Errorf("target_obj_id = %q, want the target program id %d", id, targetProg.id)
			}
			if id, ok := info["target_btf_id"]; ok && id != strconv.FormatUint(uint64(fn.ID), 10) {
				t.Errorf("target_btf_id = %q, want the xdp_pass BTF id %d", id, fn.ID)
			}
			destroyLink(t, link)
		})
	}
}

// loadFreplaceObject opens freplace.bpf.o, sets the attach target of its
// program to the program targetFD and the function name, empty for the
// section target, and loads it. It skips with the load error when bpf() is
// not permitted or the kernel BTF has no program extensions.
func loadFreplaceObject(t *testing.T, targetFD int, name string) *BpfObject {
	t.Helper()

	path := progsDir + "/freplace.bpf.o"
	obj, err := BpfObjectOpenFile(path, nil)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if err := BpfProgramSetAttachTarget(findProgram(t, obj, "replace_xdp"), targetFD, name); err != nil {
		BpfObjectClose(obj)
		t.Fatalf("set attach target %d %q: %v", targetFD, name, err)
	}
	if err := BpfObjectLoad(obj); err != nil {
		BpfObjectClose(obj)
		skipIfNotPermitted(t, err)
		skipIfKernelLacks(t, "program extensions", kernelEnumHas(t, "bpf_prog_type", "BPF_PROG_TYPE_EXT"), err)
		t.Fatalf("load %s: %v", path, err)
	}
	return obj
}

// kernelFuncHas reports whether the running kernel's BTF has the function
// name. It fails the test when the kernel BTF cannot be read, like
// kernelEnumHas.
func kernelFuncHas(t *testing.T, name string) bool {
	t.Helper()

	kernel, err := vmlinuxBTF()
	if err != nil {
		t.Fatalf("read kernel BTF for function %s: %v", name, err)
	}
	return kernel.Find(name, btf.KindFunc) != nil
}
