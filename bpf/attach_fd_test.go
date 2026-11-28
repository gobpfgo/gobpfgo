// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package bpf_test

import (
	"errors"
	"net"
	"os"
	"testing"

	"github.com/gobpfgo/gobpfgo/bpf"
	"github.com/gobpfgo/gobpfgo/libbpf"
	"golang.org/x/sys/unix"
)

// TestAttachFD attaches through the object layer to a cgroup, a network
// namespace and an interface: the cgroup_skb/ingress program of cgroup.bpf.o
// with AttachCgroup and AttachCgroupOpts to the cgroup v2 root, the flow
// dissector of netns.bpf.o to the test's network namespace, and xdp.bpf.o to
// the loopback interface. Each Link must have a descriptor, which Destroy
// releases. It needs root and skips when the kernel refuses bpf() or the
// target is taken.
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
