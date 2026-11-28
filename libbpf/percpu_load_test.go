// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// pinToCPU binds the calling thread, which the goroutine must have locked, to
// the first CPU it may run on, so every open it makes runs there. It returns
// the slot of that CPU in a per-CPU element value, its index among the
// possible CPUs, and a function that restores the thread's affinity; call it
// before unlocking the thread.
func pinToCPU(t *testing.T) (int, func()) {
	t.Helper()

	var orig unix.CPUSet
	if err := unix.SchedGetaffinity(0, &orig); err != nil {
		t.Fatalf("sched_getaffinity: %v", err)
	}
	possible, err := readCPUMaskFile("/sys/devices/system/cpu/possible")
	if err != nil {
		t.Fatalf("read possible CPUs: %v", err)
	}

	slot := 0
	for cpu, ok := range possible {
		if !ok {
			continue
		}
		if orig.IsSet(cpu) {
			var set unix.CPUSet
			set.Set(cpu)
			if err := unix.SchedSetaffinity(0, &set); err != nil {
				t.Fatalf("sched_setaffinity CPU %d: %v", cpu, err)
			}
			return slot, func() { _ = unix.SchedSetaffinity(0, &orig) }
		}
		slot++
	}
	t.Fatal("thread may run on no possible CPU")
	return 0, nil
}

// changedSlots returns the indexes of the slots that no longer hold want.
func changedSlots(slots [][]byte, want []byte) []int {
	var changed []int
	for i, slot := range slots {
		if !bytes.Equal(slot, want) {
			changed = append(changed, i)
		}
	}
	return changed
}

// setTargetTid makes handle_percpu count the opens of thread tid only, through
// the target_tid variable in the loaded .bss map.
func setTargetTid(t *testing.T, obj *BpfObject, tid uint32) {
	t.Helper()

	value := make([]byte, 4)
	binary.NativeEndian.PutUint32(value, tid)
	bss := globalDataMap(t, obj, ".bss")
	if err := sys.MapUpdateElem(BpfMapFD(bss), make([]byte, internalMapKeySize), value, 0); err != nil {
		t.Fatalf("set target_tid: %v", err)
	}
}

// TestPercpuDataLoad loads percpu.bpf.o, whose handle_percpu reaches its
// .percpu variables. On a kernel without global per-CPU data the load does
// not create the per-CPU data maps and poisons the references, so the program
// fails to load, as checkPercpuPoisonedLoad describes. On a kernel with the
// feature the program runs, as checkPercpuDataRun describes. It needs root
// or CAP_BPF and skips with EPERM or EACCES.
func TestPercpuDataLoad(t *testing.T) {
	obj := openPercpu(t, percpuObject)
	err := BpfObjectLoad(obj)
	skipIfNotPermitted(t, err)

	if !featPercpuData.supported() {
		checkPercpuPoisonedLoad(t, obj, err)
		return
	}
	if err != nil {
		t.Fatalf("load %s: %v", percpuObject, err)
	}
	checkPercpuDataRun(t, obj)
}

// checkPercpuPoisonedLoad checks the load error of percpu.bpf.o on a kernel
// without global per-CPU data. The verifier reaches the first .percpu
// reference, a poisoned call for map 0, and handle_percpu fails with EINVAL.
// The log fixup replaces the poisoned call and the verifier's error for it
// with the instruction index and the name of the .percpu map. The load
// closes the maps it created, and the per-CPU data maps stay uncreated.
func checkPercpuPoisonedLoad(t *testing.T, obj *BpfObject, err error) {
	t.Helper()

	var lerr *Error
	if !errors.As(err, &lerr) || lerr.Op != "bpf_prog_load" || !errors.Is(err, unix.EINVAL) {
		t.Fatalf("load %s: %v, want a bpf_prog_load EINVAL for the poisoned .percpu reference", percpuObject, err)
	}

	want := fmt.Sprintf("%d: <invalid BPF map reference>\nBPF map '.percpu' is referenced but wasn't created\n", percpuRefs[1].insn)
	if !strings.HasPrefix(lerr.Log, "handle_percpu: ") || !strings.Contains(lerr.Log, want) {
		t.Errorf("load log = %q, want the handle_percpu log with %q", lerr.Log, want)
	}
	if strings.Contains(lerr.Log, "unknown#2001000000") {
		t.Errorf("load log = %q, still has the poisoned call", lerr.Log)
	}

	for _, m := range obj.maps {
		if BpfMapFD(m) != -1 {
			t.Errorf("%s: fd %d after the failed load, want -1", BpfMapName(m), BpfMapFD(m))
		}
		if want := m.libbpfType != libbpfMapPercpu; m.autocreate != want {
			t.Errorf("%s: autocreate %v, want %v", BpfMapName(m), m.autocreate, want)
		}
	}
}

// checkPercpuDataRun checks a loaded percpu.bpf.o on a kernel with global
// per-CPU data. Every possible CPU starts with the section image. The test
// then pins its thread to one CPU, attaches handle_percpu to do_sys_openat2
// for that thread, opens a file, and checks that exactly that CPU's .percpu
// value changed: the program incremented the counter and stored the thread
// id in its own CPU's copy, and every other CPU kept the initial value.
func checkPercpuDataRun(t *testing.T, obj *BpfObject) {
	t.Helper()

	for _, section := range percpuSections {
		checkPercpuSlots(t, section, lookupPercpu(t, globalDataMap(t, obj, section)), percpuImage(section))
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pinned, unpin := pinToCPU(t)
	defer unpin()
	tid := uint32(unix.Gettid())
	setTargetTid(t, obj, tid)

	prog := BpfObjectFindProgramByName(obj, "handle_percpu")
	link, err := BpfProgramAttachKprobe(prog, false, "do_sys_openat2")
	if err != nil {
		skipIfNotPermitted(t, err)
		t.Fatalf("attach kprobe: %v", err)
	}
	triggerOpen(t)
	BpfLinkDestroy(link)

	percpu := globalDataMap(t, obj, ".percpu")
	slots := percpuSlots(t, lookupPercpu(t, percpu), BpfMapValueSize(percpu))
	changed := changedSlots(slots, percpuSlot(percpuImage(".percpu")))
	if len(changed) != 1 || changed[0] != pinned {
		t.Fatalf("changed CPU slots %v, want only the pinned CPU's slot %d", changed, pinned)
	}

	slot := slots[pinned]
	if got := binary.NativeEndian.Uint64(slot[0:]); got <= percpuCounterInit {
		t.Errorf("slot %d percpu_counter = %d, want more than %d", pinned, got, percpuCounterInit)
	}
	if got := binary.NativeEndian.Uint32(slot[8:]); got != tid {
		t.Errorf("slot %d percpu_last = %d, want thread %d", pinned, got, tid)
	}
	custom := globalDataMap(t, obj, ".percpu.custom")
	checkPercpuSlots(t, ".percpu.custom", lookupPercpu(t, custom), percpuImage(".percpu.custom"))
}

// TestPercpuUnusedDataLoad loads percpu_unused.bpf.o, whose program uses a
// .bss variable and none of the .percpu ones. The object loads on every
// kernel and the .bss map is created. On a kernel without global per-CPU
// data the .percpu map is not created and keeps descriptor -1, yet counts as
// created after the load: its element operations fail with EINVAL and its
// initial value can no longer be set. With the feature it is created and
// every possible CPU holds the section image. It needs root or CAP_BPF and
// skips with EPERM or EACCES.
func TestPercpuUnusedDataLoad(t *testing.T) {
	obj := loadTestObject(t, percpuUnusedObject)
	defer BpfObjectClose(obj)

	if fd := BpfProgramFD(BpfObjectFindProgramByName(obj, "handle_percpu_unused")); fd < 0 {
		t.Errorf("handle_percpu_unused fd = %d, want a loaded program", fd)
	}
	if fd := BpfMapFD(globalDataMap(t, obj, ".bss")); fd < 0 {
		t.Errorf(".bss fd = %d, want a created map", fd)
	}

	percpu := BpfObjectFindMapByName(obj, ".percpu")
	if !featPercpuData.supported() {
		checkMapWithoutFD(t, percpu)
		return
	}
	checkPercpuSlots(t, ".percpu", lookupPercpu(t, percpu), percpuUnusedImage())
	checkMapOpError(t, ".percpu set initial value", BpfMapSetInitialValue(percpu, percpuUnusedImage()),
		"bpf_map__set_initial_value", unix.EBUSY)
}

// TestPercpuUnusedPinMaps pins the maps of a loaded percpu_unused.bpf.o under
// a bpffs directory, then unpins them through their stored pin paths. The
// .bss map is pinned. On a kernel without global per-CPU data the .percpu map
// was not created, so the pin skips it and no file is made for it; with the
// feature it is pinned like .bss. It needs root or CAP_BPF and skips with
// EPERM or EACCES, or when bpffs is unavailable.
func TestPercpuUnusedPinMaps(t *testing.T) {
	obj := loadTestObject(t, percpuUnusedObject)
	defer BpfObjectClose(obj)

	dir := bpffsTempDir(t, "gobpfgo-percpu-")
	defer func() {
		_ = BpfObjectUnpinMaps(obj, nil)
		_ = os.Remove(dir)
	}()

	if err := BpfObjectPinMaps(obj, &dir); err != nil {
		t.Fatalf("BpfObjectPinMaps: %v", err)
	}
	checkMapPin(t, globalDataMap(t, obj, ".bss"), dir, true)
	checkMapPin(t, globalDataMap(t, obj, ".percpu"), dir, featPercpuData.supported())

	// A nil path unpins every map with a stored pin path; a skipped map has
	// none.
	if err := BpfObjectUnpinMaps(obj, nil); err != nil {
		t.Fatalf("BpfObjectUnpinMaps: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	if len(entries) != 0 {
		t.Errorf("%s holds %d entries after the unpin, want none", dir, len(entries))
	}
}

// checkMapPin checks whether m is pinned at dir/<map-name>, with dots replaced
// by underscores, as BpfObjectPinMaps names it.
func checkMapPin(t *testing.T, m *BpfMap, dir string, want bool) {
	t.Helper()

	name := BpfMapName(m)
	path := sanitizePinPath(filepath.Join(dir, name))
	if got := BpfMapIsPinned(m); got != want {
		t.Errorf("%s: pinned %v, want %v", name, got, want)
	}
	_, err := os.Stat(path)
	switch {
	case want && err != nil:
		t.Errorf("%s: stat %s: %v, want a pin", name, path, err)
	case !want && !errors.Is(err, os.ErrNotExist):
		t.Errorf("%s: stat %s: %v, want no pin", name, path, err)
	}
}

// TestCreateMapRetryWithoutBTF creates the .percpu map of percpu.bpf.o with
// the object BTF loaded and the map's own BTF ids forced on the create: no
// key type and the section DATASEC as the value type. A kernel without
// global per-CPU data takes a keyless DATASEC value only for a plain array,
// so it rejects the first BPF_MAP_CREATE; the retry without BTF creates and
// populates the map and clears the ids. A kernel with the feature takes the
// BTF on the first try and the ids stay. It needs root or CAP_BPF and skips
// with EPERM or EACCES.
func TestCreateMapRetryWithoutBTF(t *testing.T) {
	obj := openPercpu(t, percpuObject)
	raw, err := sanitizeBTF(obj.btf, kernelBTFFeatures())
	if err != nil {
		t.Fatalf("sanitize the object BTF: %v", err)
	}
	btfFD, err := sys.BtfLoad(raw, nil, 0)
	if err != nil {
		skipIfNotPermitted(t, err)
		t.Fatalf("load the object BTF: %v", err)
	}
	defer unix.Close(btfFD)

	m := globalDataMap(t, obj, ".percpu")
	valueID := BpfMapBtfValueTypeID(m)
	if BpfMapBtfKeyTypeID(m) != 0 || valueID == 0 {
		t.Fatalf(".percpu BTF ids = %d/%d, want no key and a DATASEC value", BpfMapBtfKeyTypeID(m), valueID)
	}
	obj.attempted = true // as BpfObjectLoad marks the object before it creates the maps
	if err := createMap(m, btfFD); err != nil {
		t.Fatalf("create .percpu: %v", err)
	}

	info, err := sys.MapInfoByFD(BpfMapFD(m))
	if err != nil {
		t.Fatalf("MapInfoByFD(.percpu): %v", err)
	}
	wantID := uint32(0)
	if featPercpuData.supported() {
		wantID = valueID
	}
	if BpfMapBtfKeyTypeID(m) != 0 || BpfMapBtfValueTypeID(m) != wantID {
		t.Errorf(".percpu BTF ids = %d/%d, want 0/%d", BpfMapBtfKeyTypeID(m), BpfMapBtfValueTypeID(m), wantID)
	}
	if info.BtfKeyTypeID != 0 || info.BtfValueTypeID != wantID {
		t.Errorf("kernel .percpu BTF ids = %d/%d, want 0/%d", info.BtfKeyTypeID, info.BtfValueTypeID, wantID)
	}
	checkPercpuSlots(t, ".percpu", lookupPercpu(t, m), percpuImage(".percpu"))
}
