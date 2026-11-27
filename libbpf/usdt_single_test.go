// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"runtime"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

// TestBpfProgramAttachUsdtCookieWithoutMulti covers a kernel with BPF cookies
// but no uprobe multi link, Linux 5.15 to 6.5. The attach is not refused: it
// allocates a spec ID for the single uprobes and fails on the spec map write
// of the unloaded fixture, which returns the ID to the free list.
func TestBpfProgramAttachUsdtCookieWithoutMulti(t *testing.T) {
	obj := openUsdtObject(t)
	man, err := newUsdtManager(obj)
	if err != nil {
		t.Fatalf("newUsdtManager: %v", err)
	}
	man.hasBpfCookie, man.hasUprobeMulti = true, false
	obj.usdtMan = man
	prog := BpfObjectFindProgramByName(obj, "handle_loop")
	prog.fd = 1 << 30

	link, err := BpfProgramAttachUsdt(prog, -1, usdtTargetPath, usdtProvider, usdtName, nil)
	if link != nil || !errors.Is(err, unix.EINVAL) {
		t.Fatalf("attach = %v, %v, want EINVAL from the spec map write", link, err)
	}
	if !slices.Equal(man.freeSpecIDs, []int32{0}) || man.nextFreeSpecID != 1 {
		t.Errorf("after rollback: free %v, next %d", man.freeSpecIDs, man.nextFreeSpecID)
	}
}

// TestUsdtUprobeOpts checks the options of a single uprobe call site: the
// semaphore is always the reference counter, and the spec ID is the BPF
// cookie only on a kernel with cookies; without them the IP map carries it.
// The uprobe uses the default attach mode either way.
func TestUsdtUprobeOpts(t *testing.T) {
	tests := []struct {
		name    string
		cookies bool
		semaOff uint64
		want    BpfUprobeOpts
	}{
		{"cookie", true, 0, BpfUprobeOpts{BpfCookie: 3}},
		{"cookie and semaphore", true, 0x2010, BpfUprobeOpts{RefCtrOffset: 0x2010, BpfCookie: 3}},
		{"IP map", false, 0, BpfUprobeOpts{}},
		{"IP map and semaphore", false, 0x2010, BpfUprobeOpts{RefCtrOffset: 0x2010}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			man := &usdtManager{hasBpfCookie: tt.cookies}
			got := man.uprobeOpts(usdtTarget{relIP: 0x1000, semaOff: tt.semaOff}, 3)
			if *got != tt.want {
				t.Errorf("uprobeOpts = %+v, want %+v", *got, tt.want)
			}
		})
	}
}

// TestBpfProgramAttachUsdtSingleCookie runs the single-uprobe cookie path of
// kernels with BPF cookies but no uprobe multi links, Linux 5.15 to 6.5, on a
// newer kernel: the program is loaded without the multi attach type and the
// manager is told the link is missing. Each call site gets a uprobe PMU event
// whose BPF perf link carries the spec ID as its cookie, and nothing goes to
// the IP map. Kernels without cookies skip.
func TestBpfProgramAttachUsdtSingleCookie(t *testing.T) {
	obj, prog := loadUsdtObjectForSingleUprobes(t)
	if !obj.usdtMan.hasBpfCookie {
		t.Skip("the kernel has no BPF cookies")
	}
	target := startUsdtTarget(t, checkedInUsdtTarget(t, usdtTargetPath))

	link := attachUsdt(t, prog, target.pid, target.path, usdtName)
	if link.usdt.multiLink != nil || len(link.usdt.uprobes) != 2 {
		t.Fatalf("multi link %v and %d uprobes, want 2 uprobes", link.usdt.multiLink, len(link.usdt.uprobes))
	}
	checkUsdtSingleUprobes(t, link.usdt)
	checkUsdtMaps(t, obj, link.usdt, target.path)

	target.trigger(t)
	checkLoopRecords(t, obj, 1, 1)
	BpfLinkDestroy(link)
	target.trigger(t)
	checkLoopRecords(t, obj, 1, 1)
}

// loadUsdtObjectForSingleUprobes loads the fixture as on a kernel without
// uprobe multi links: the program keeps the unspecified attach type a single
// uprobe needs, and the object's USDT manager attaches every call site with
// its own uprobe.
func loadUsdtObjectForSingleUprobes(t *testing.T) (*BpfObject, *BpfProgram) {
	t.Helper()

	if runtime.GOARCH != "amd64" {
		t.Skip("the USDT target is an x86-64 binary")
	}
	obj := openUsdtObject(t)
	prog := BpfObjectFindProgramByName(obj, "handle_loop")
	prog.usdt = false
	if err := BpfObjectLoad(obj); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bpf() not permitted: %v", err)
		}
		t.Fatalf("load %s: %v", usdtObjectPath, err)
	}

	man, err := objectUsdtManager(obj)
	if err != nil {
		t.Fatalf("USDT manager: %v", err)
	}
	man.hasUprobeMulti = false
	return obj, prog
}

// checkUsdtSingleUprobes requires every call site of a single-uprobe USDT
// link to be a uprobe PMU event, attached through a BPF perf link exactly
// when the kernel has one.
func checkUsdtSingleUprobes(t *testing.T, ul *usdtLink) {
	t.Helper()

	for i, link := range ul.uprobes {
		if link.legacy != nil || link.perfFD < 0 {
			t.Errorf("call site %d: tracefs event %v, perf event %d, want a PMU event", i, link.legacy, link.perfFD)
		}
		if perfLink := link.fd != link.perfFD; perfLink != perfLinkSupported() {
			t.Errorf("call site %d: perf link %v, want %v", i, perfLink, perfLinkSupported())
		}
	}
}
