// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package bpf_test

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/gobpfgo/gobpfgo/bpf"
	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/libbpf"
	"golang.org/x/sys/unix"
)

// TestAttachFD attaches through the object layer to a cgroup, a network
// namespace, an interface and a sockmap: the cgroup_skb/ingress program of
// cgroup.bpf.o with AttachCgroup and AttachCgroupOpts to the cgroup v2 root,
// the flow dissector of netns.bpf.o to the test's network namespace,
// xdp.bpf.o to the loopback interface, and the sk_msg program of
// sockmap.bpf.o to a new sockmap. Each Link must have a descriptor, which
// Destroy releases. It needs root and skips when the kernel refuses bpf() or
// the target is taken, and skips the sockmap with the kernel's errno when
// the kernel BTF has no sockmap link type.
func TestAttachFD(t *testing.T) {
	tests := []struct {
		name    string
		object  string
		program string
		attach  func(t *testing.T, p *bpf.Program) (*bpf.Link, error)
	}{
		{"cgroup", "cgroup.bpf.o", "cgroup_ingress", func(t *testing.T, p *bpf.Program) (*bpf.Link, error) {
			return p.AttachCgroup(openCgroupV2Root(t))
		}},
		{"cgroup options", "cgroup.bpf.o", "cgroup_ingress", func(t *testing.T, p *bpf.Program) (*bpf.Link, error) {
			return p.AttachCgroupOpts(openCgroupV2Root(t), &libbpf.BpfCgroupOpts{})
		}},
		{"netns", "netns.bpf.o", "dissect", func(t *testing.T, p *bpf.Program) (*bpf.Link, error) {
			netns, err := os.Open("/proc/self/ns/net")
			if err != nil {
				t.Fatalf("open network namespace: %v", err)
			}
			t.Cleanup(func() { netns.Close() })
			return p.AttachNetns(int(netns.Fd()))
		}},
		{"xdp", "xdp.bpf.o", "xdp_pass", func(t *testing.T, p *bpf.Program) (*bpf.Link, error) {
			lo, err := net.InterfaceByName("lo")
			if err != nil {
				t.Fatalf("loopback interface: %v", err)
			}
			return p.AttachXDP(lo.Index)
		}},
		{"sockmap", "sockmap.bpf.o", "msg_pass", func(t *testing.T, p *bpf.Program) (*bpf.Link, error) {
			mapFD, err := libbpf.BpfMapCreate(libbpf.BPF_MAP_TYPE_SOCKMAP, "gobpfgo_sockmap", 4, 4, 1, nil)
			if err != nil {
				skipIfNotPermitted(t, "sockmap create", err)
				t.Fatalf("create sockmap: %v", err)
			}
			t.Cleanup(func() { unix.Close(mapFD) })

			link, err := p.AttachSockmap(mapFD)
			if err != nil {
				skipIfNotPermitted(t, "sockmap attach", err)
				if !kernelEnumHas(t, "bpf_link_type", "BPF_LINK_TYPE_SOCKMAP") {
					t.Skipf("kernel lacks sockmap links: %v", err)
				}
			}
			return link, err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj, err := bpf.OpenFile(progsDir+"/"+tt.object, nil)
			if err != nil {
				t.Fatalf("OpenFile: %v", err)
			}
			defer obj.Close()
			if err := obj.Load(); err != nil {
				skipIfNotPermitted(t, "bpf()", err)
				t.Fatalf("Load: %v", err)
			}

			link, err := tt.attach(t, obj.Program(tt.program))
			if err != nil {
				skipIfNotPermitted(t, tt.name+" attach", err)
				if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.EBUSY) {
					t.Skipf("%s target is taken: %v", tt.name, err)
				}
				t.Fatalf("attach: %v", err)
			}
			if link.FD() < 0 {
				t.Fatalf("link FD = %d", link.FD())
			}
			link.Destroy()
			if link.FD() != -1 {
				t.Errorf("link FD after Destroy = %d, want -1", link.FD())
			}
		})
	}
}

// TestAttachCgroupPlacement places a cgroup link relative to another through
// the object layer. It loads cgroup.bpf.o twice, attaches the
// cgroup_skb/ingress program of the first object to the cgroup v2 root as
// the anchor link, and attaches the same program of the second object before
// it with BPF_F_BEFORE|BPF_F_LINK and the anchor's link descriptor as
// RelativeFD. The anchor takes no flags: the kernels with cgroup revisions
// refuse BPF_F_LINK without BPF_F_BEFORE or BPF_F_AFTER with EINVAL. Destroy
// must release both links. It needs root, and skips with the kernel's errno
// when the kernel BTF shows no multi-program cgroup attachment, whose
// kernels refuse link flags.
func TestAttachCgroupPlacement(t *testing.T) {
	cgroupFD := openCgroupV2Root(t)
	anchorProg := loadCgroupIngress(t)
	prog := loadCgroupIngress(t)

	anchor, err := anchorProg.AttachCgroup(cgroupFD)
	if err != nil {
		skipIfNotPermitted(t, "cgroup attach", err)
		t.Fatalf("attach anchor: %v", err)
	}
	anchorFD := anchor.FD()
	before, err := prog.AttachCgroupOpts(cgroupFD, &libbpf.BpfCgroupOpts{
		Flags:      libbpf.BPF_F_BEFORE | libbpf.BPF_F_LINK,
		RelativeFD: anchorFD,
	})
	if err != nil {
		anchor.Destroy()
		if !kernelStructHasMember(t, "cgroup_bpf", "revisions") {
			t.Skipf("kernel lacks cgroup program revisions: %v", err)
		}
		t.Fatalf("attach before anchor link fd %d: %v", anchorFD, err)
	}

	for _, l := range []struct {
		name string
		link *bpf.Link
	}{{"before", before}, {"anchor", anchor}} {
		if l.link.FD() < 0 {
			t.Errorf("%s link FD = %d", l.name, l.link.FD())
		}
		l.link.Destroy()
		if l.link.FD() != -1 {
			t.Errorf("%s link FD after Destroy = %d, want -1", l.name, l.link.FD())
		}
	}
}

// loadCgroupIngress opens and loads a new copy of cgroup.bpf.o, closed when
// the test ends, and returns its cgroup_skb/ingress program. It skips the
// test when the kernel refuses bpf().
func loadCgroupIngress(t *testing.T) *bpf.Program {
	t.Helper()

	obj, err := bpf.OpenFile(progsDir+"/cgroup.bpf.o", nil)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	t.Cleanup(func() { obj.Close() })
	if err := obj.Load(); err != nil {
		skipIfNotPermitted(t, "bpf()", err)
		t.Fatalf("Load: %v", err)
	}
	return obj.Program("cgroup_ingress")
}

// kernelBTF reads and parses the running kernel's BTF. It fails the test
// when the BTF cannot be read, so that a missing BTF does not pass for a
// missing feature.
func kernelBTF(t *testing.T) *btf.Spec {
	t.Helper()

	data, err := os.ReadFile("/sys/kernel/btf/vmlinux")
	if err != nil {
		t.Fatalf("read kernel BTF: %v", err)
	}
	spec, err := btf.Parse(data, binary.NativeEndian)
	if err != nil {
		t.Fatalf("parse kernel BTF: %v", err)
	}
	return spec
}

// kernelEnumHas reports whether the running kernel's BTF has the enum
// enumName with the value valueName.
func kernelEnumHas(t *testing.T, enumName, valueName string) bool {
	t.Helper()

	enum := kernelBTF(t).Find(enumName, btf.KindEnum)
	if enum == nil {
		return false
	}
	for _, e := range enum.Enums {
		if e.Name == valueName {
			return true
		}
	}
	return false
}

// kernelStructHasMember reports whether the running kernel's BTF has the
// struct structName with the member member.
func kernelStructHasMember(t *testing.T, structName, member string) bool {
	t.Helper()

	kernel := kernelBTF(t)
	st := kernel.Find(structName, btf.KindStruct)
	return st != nil && kernel.Member(st, member) != nil
}

// openCgroupV2Root opens the root of the cgroup v2 hierarchy, at
// /sys/fs/cgroup on a unified system or /sys/fs/cgroup/unified on a hybrid
// one, and closes it when the test ends. It skips the test when neither is a
// cgroup v2 mount.
func openCgroupV2Root(t *testing.T) int {
	t.Helper()

	for _, path := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified"} {
		var fs unix.Statfs_t
		if err := unix.Statfs(path, &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
			continue
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		return fd
	}
	t.Skip("no cgroup v2 hierarchy at /sys/fs/cgroup or /sys/fs/cgroup/unified")
	return -1
}
