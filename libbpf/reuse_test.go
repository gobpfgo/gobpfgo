// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

func TestBpfMapReuseFD(t *testing.T) {
	fd, err := BpfMapCreate(BPF_MAP_TYPE_ARRAY, "gobpfgo_reuse", 4, 8, 16, nil)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bpf() not permitted: %v", err)
		}
		t.Fatalf("BpfMapCreate: %v", err)
	}
	defer unix.Close(fd)

	obj, err := BpfObjectOpenFile("../testdata/progs/kprobe.bpf.o", nil)
	if err != nil {
		t.Fatalf("BpfObjectOpenFile: %v", err)
	}
	defer BpfObjectClose(obj)

	m := BpfObjectFindMapByName(obj, "counts")
	p := BpfObjectFindProgramByName(obj, "handle_open")
	if m == nil || p == nil {
		t.Fatal("map counts or program handle_open not found")
	}

	if err := BpfMapReuseFD(m, fd); err != nil {
		t.Fatalf("BpfMapReuseFD: %v", err)
	}
	if got := BpfMapName(m); got != "gobpfgo_reuse" {
		t.Fatalf("map name = %q, want gobpfgo_reuse", got)
	}
	if got := BpfMapMaxEntries(m); got != 16 {
		t.Fatalf("max entries = %d, want 16", got)
	}
	if BpfMapFD(m) == fd {
		t.Fatal("reuse kept the caller's fd instead of duplicating it")
	}

	if err := BpfObjectLoad(obj); err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bpf() not permitted: %v", err)
		}
		t.Fatalf("BpfObjectLoad: %v", err)
	}

	reused, err := sys.MapInfoByFD(BpfMapFD(m))
	if err != nil {
		t.Fatalf("MapInfoByFD reused: %v", err)
	}
	original, err := sys.MapInfoByFD(fd)
	if err != nil {
		t.Fatalf("MapInfoByFD original: %v", err)
	}
	if reused.ID != original.ID {
		t.Fatalf("reused map id = %d, original id = %d", reused.ID, original.ID)
	}
	if reused.Name != "gobpfgo_reuse" || reused.MaxEntries != 16 {
		t.Fatalf("reused map info = %+v", reused)
	}

	link, err := BpfProgramAttachKprobe(p, false, "do_sys_openat2")
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("kprobe attach not permitted: %v", err)
		}
		t.Fatalf("BpfProgramAttachKprobe: %v", err)
	}
	defer BpfLinkDestroy(link)

	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatalf("open /dev/null: %v", err)
	}
	_ = file.Close()

	key := make([]byte, BpfMapKeySize(m))
	value := make([]byte, BpfMapValueSize(m))
	if err := BpfMapLookupElem(m, key, value, 0); err != nil {
		t.Fatalf("BpfMapLookupElem: %v", err)
	}
	if binary.NativeEndian.Uint64(value) == 0 {
		t.Fatal("program did not increment the reused map")
	}
}

// TestBpfMapReuseFDBadFD reuses descriptor -1 for kprobe.bpf.o's counts map.
// The kernel rejects it before anything is duplicated, with EBADFD, and the
// map keeps its name and has no descriptor. It needs no privileges and skips
// where the kernel refuses unprivileged bpf() outright.
func TestBpfMapReuseFDBadFD(t *testing.T) {
	obj := openProg(t, "kprobe.bpf.o")
	m := BpfObjectFindMapByName(obj, "counts")
	if m == nil {
		t.Fatal("map counts not found")
	}

	err := BpfMapReuseFD(m, -1)
	skipIfNotPermitted(t, err)
	checkMapOpError(t, "reuse of descriptor -1", err, "bpf_map__reuse_fd", unix.EBADFD)
	if got := BpfMapName(m); got != "counts" || m.fd != -1 || m.reused {
		t.Errorf("map after the failed reuse: name %q, fd %d, reused %v, want counts, -1, false", got, m.fd, m.reused)
	}
}

// TestBpfMapReuseFailedLoad gives kconfig.bpf.o's values map an existing
// array, then loads the object with a CONFIG_TEST value that is not an
// integer, so the load fails while it resolves the externs, before it
// creates any map. The reused map counts as created from the reuse on: it
// reads through the duplicate before the load, and after the failed load the
// duplicate is closed, so the element operations fail with EINVAL. Reusing
// the array again then fails with EBADF, as there is no descriptor left to
// replace, and changes nothing. The caller's descriptor stays open. It needs
// root or CAP_BPF and skips otherwise.
func TestBpfMapReuseFailedLoad(t *testing.T) {
	fd, err := BpfMapCreate(BPF_MAP_TYPE_ARRAY, "gobpfgo_reuse", 4, 8, 4, nil)
	skipIfNotPermitted(t, err)
	if err != nil {
		t.Fatalf("BpfMapCreate: %v", err)
	}
	defer unix.Close(fd)

	kconfig := "CONFIG_TEST=gobpfgo\n"
	obj := openProgOpts(t, "kconfig.bpf.o", &BpfObjectOpenOpts{Kconfig: &kconfig})
	m := BpfObjectFindMapByName(obj, "values")
	if err := BpfMapReuseFD(m, fd); err != nil {
		t.Fatalf("BpfMapReuseFD: %v", err)
	}
	if err := BpfMapLookupElem(m, u32Key(0), make([]byte, 8), 0); err != nil {
		t.Fatalf("lookup through the reused map before the load: %v", err)
	}
	checkMapOpError(t, "set initial value of the reused map", BpfMapSetInitialValue(m, make([]byte, 8)),
		"bpf_map__set_initial_value", unix.EBUSY)

	err = BpfObjectLoad(obj)
	if err == nil || !strings.Contains(err.Error(), "isn't a valid integer") {
		t.Fatalf("load: %v, want the CONFIG_TEST parse error", err)
	}
	checkMapWithoutFD(t, m)

	checkMapOpError(t, "reuse after the failed load", BpfMapReuseFD(m, fd), "bpf_map__reuse_fd", unix.EBADF)
	checkMapWithoutFD(t, m)
	if _, err := sys.MapInfoByFD(fd); err != nil {
		t.Errorf("the caller's descriptor after the failed load: %v", err)
	}
}

// TestBpfMapReuseClosedObject reuses an existing array for kprobe.bpf.o's
// counts map after BpfObjectClose, for an object that was only opened and
// for one that was loaded. The closed object released the map, so the reuse
// fails with EBADF, closes its duplicate of the array and leaves the map
// without a descriptor. The caller's descriptor stays open. It needs root or
// CAP_BPF and skips otherwise.
func TestBpfMapReuseClosedObject(t *testing.T) {
	fd, err := BpfMapCreate(BPF_MAP_TYPE_ARRAY, "gobpfgo_reuse", 4, 8, 4, nil)
	skipIfNotPermitted(t, err)
	if err != nil {
		t.Fatalf("BpfMapCreate: %v", err)
	}
	defer unix.Close(fd)

	for _, tc := range []struct {
		name string
		load bool
	}{{"opened", false}, {"loaded", true}} {
		t.Run(tc.name, func(t *testing.T) {
			obj := openProg(t, "kprobe.bpf.o")
			m := BpfObjectFindMapByName(obj, "counts")
			if m == nil {
				t.Fatal("map counts not found")
			}
			if tc.load {
				if err := BpfObjectLoad(obj); err != nil {
					t.Fatalf("BpfObjectLoad: %v", err)
				}
			}
			BpfObjectClose(obj)

			maps := len(openMapNames(t))
			checkMapOpError(t, "reuse after close", BpfMapReuseFD(m, fd), "bpf_map__reuse_fd", unix.EBADF)
			if got := len(openMapNames(t)); got != maps {
				t.Errorf("%d BPF map descriptors open after the reuse, want %d", got, maps)
			}
			if got := BpfMapName(m); got != "counts" || m.fd != -1 || m.reused {
				t.Errorf("map after the reuse: name %q, fd %d, reused %v, want counts, -1, false", got, m.fd, m.reused)
			}
			if _, err := sys.MapInfoByFD(fd); err != nil {
				t.Errorf("the caller's descriptor after the reuse: %v", err)
			}
		})
	}
}
