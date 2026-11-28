// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBpfMapCreateArray(t *testing.T) {
	fd, err := BpfMapCreate(BPF_MAP_TYPE_ARRAY, "gobpfgo_test", 4, 8, 16, nil)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skipf("bpf() not permitted: %v", err)
		}
		t.Fatalf("BpfMapCreate: %v", err)
	}
	defer unix.Close(fd)

	if fd < 0 {
		t.Fatalf("fd = %d", fd)
	}
}

func TestBpfMapCreateInvalidOpts(t *testing.T) {
	_, err := BpfMapCreate(BPF_MAP_TYPE_ARRAY, "gobpfgo-test", 4, 8, 16, &BpfMapCreateOpts{Sz: 1})
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("got %v, want EINVAL", err)
	}
}

func TestBpfMapCreateOptsSize(t *testing.T) {
	if NewBpfMapCreateOpts().Sz == 0 {
		t.Fatal("NewBpfMapCreateOpts returned Sz zero")
	}
}

// loadedMap makes m a map of an object whose load succeeded, so it counts as
// created, and returns it.
func loadedMap(m *BpfMap) *BpfMap {
	m.obj = &BpfObject{attempted: true, loaded: true}
	return m
}

// TestValidateMapOpOrder checks the order of the element operation checks
// and the errno of each: a nil map is EINVAL, a map that is not created yet
// is ENOENT before any size check, a wrong key size is EINVAL, then a created
// map without a descriptor is EINVAL, and the value size is checked last and
// only when asked for. A reused map counts as created before the load, and a
// map with a descriptor but no object does not. TestValidateMapOp covers the
// value sizes.
func TestValidateMapOpOrder(t *testing.T) {
	array := loadedMap(&BpfMap{name: "array", mapType: BPF_MAP_TYPE_ARRAY, fd: 0, keySize: 4, valueSize: 12})
	percpu := loadedMap(&BpfMap{name: "percpu", mapType: BPF_MAP_TYPE_PERCPU_ARRAY, fd: 0, keySize: 4, valueSize: 12})
	skipped := loadedMap(&BpfMap{name: "skipped", mapType: BPF_MAP_TYPE_ARRAY, fd: -1, keySize: 4, valueSize: 12})
	opened := &BpfMap{obj: &BpfObject{}, name: "opened", mapType: BPF_MAP_TYPE_ARRAY, fd: -1, keySize: 4, valueSize: 12}
	reused := &BpfMap{obj: &BpfObject{}, name: "reused", mapType: BPF_MAP_TYPE_ARRAY, fd: 0, reused: true, keySize: 4, valueSize: 12}
	orphan := &BpfMap{name: "orphan", mapType: BPF_MAP_TYPE_ARRAY, fd: 0, keySize: 4, valueSize: 12}

	const (
		keyLog   = "unexpected key size"
		noFDLog  = "can't use BPF map without FD (was it created?)"
		valueLog = "unexpected value size"
	)
	for _, tc := range []struct {
		name       string
		m          *BpfMap
		key, value int
		checkValue bool
		flags      uint64
		want       error
		log        string
	}{
		{"nil map", nil, 4, 12, true, 0, unix.EINVAL, ""},
		{"not created", opened, 4, 12, true, 0, unix.ENOENT, ""},
		{"not created before the key size", opened, 3, 11, true, 0, unix.ENOENT, ""},
		{"descriptor without an object", orphan, 4, 12, true, 0, unix.ENOENT, ""},
		{"reused before the load", reused, 4, 12, true, 0, nil, ""},
		{"key size before the value size", array, 3, 11, true, 0, unix.EINVAL, keyLog},
		{"key size without the value check", array, 5, 0, false, 0, unix.EINVAL, keyLog},
		{"key size before the descriptor", skipped, 3, 12, true, 0, unix.EINVAL, keyLog},
		{"no descriptor after the load", skipped, 4, 12, true, 0, unix.EINVAL, noFDLog},
		{"descriptor before the value size", skipped, 4, 11, true, 0, unix.EINVAL, noFDLog},
		{"no descriptor without the value check", skipped, 4, 0, false, 0, unix.EINVAL, noFDLog},
		{"value size", array, 4, 11, true, 0, unix.EINVAL, valueLog},
		{"value not checked", array, 4, 0, false, 0, nil, ""},
		{"per-CPU value not checked", percpu, 4, 0, false, 0, nil, ""},
		{"CPU flags not checked without the value check", percpu, 4, 0, false, BPF_F_CPU | BPF_F_ALL_CPUS, nil, ""},
		{"CPU flags ignored for an array", array, 4, 12, true, BPF_F_CPU | BPF_F_ALL_CPUS, nil, ""},
	} {
		err := validateMapOp("op", tc.m, tc.key, tc.value, tc.checkValue, tc.flags)
		if tc.want == nil {
			if err != nil {
				t.Errorf("%s: got %v, want nil", tc.name, err)
			}
			continue
		}
		checkMapOpError(t, tc.name, err, "op", tc.want)
		checkMapOpLog(t, tc.name, err, tc.log)
	}
}

// mapElemOps calls each element operation on a map with a key and a value
// buffer; the operations without a value ignore it, and the key walk passes
// key as the next key after the first.
var mapElemOps = []struct {
	name string
	call func(m *BpfMap, key, value []byte) error
}{
	{"bpf_map__lookup_elem", func(m *BpfMap, k, v []byte) error { return BpfMapLookupElem(m, k, v, 0) }},
	{"bpf_map__update_elem", func(m *BpfMap, k, v []byte) error { return BpfMapUpdateElem(m, k, v, 0) }},
	{"bpf_map__delete_elem", func(m *BpfMap, k, _ []byte) error { return BpfMapDeleteElem(m, k, 0) }},
	{"bpf_map__lookup_and_delete_elem", func(m *BpfMap, k, v []byte) error { return BpfMapLookupAndDeleteElem(m, k, v, 0) }},
	{"bpf_map__get_next_key", func(m *BpfMap, k, _ []byte) error { return BpfMapGetNextKey(m, nil, k) }},
}

// checkMapWithoutFD checks a created map that has no descriptor: every
// element operation with buffers of the right size fails with EINVAL for
// the missing descriptor, BpfMapFD is -1, and BpfMapSetInitialValue is
// EBUSY.
func checkMapWithoutFD(t *testing.T, m *BpfMap) {
	t.Helper()

	name := BpfMapName(m)
	key, value := make([]byte, BpfMapKeySize(m)), make([]byte, BpfMapValueSize(m))
	if isPercpuMapType(BpfMapTypeOf(m)) {
		value = make([]byte, percpuValueSize(BpfMapValueSize(m), libbpfNumPossibleCPUs()))
	}
	for _, op := range mapElemOps {
		err := op.call(m, key, value)
		checkMapOpError(t, name+" "+op.name, err, op.name, unix.EINVAL)
		checkMapOpLog(t, name+" "+op.name, err, "can't use BPF map without FD")
	}
	if fd := BpfMapFD(m); fd != -1 {
		t.Errorf("%s: fd %d, want -1", name, fd)
	}
	checkMapOpError(t, name+" set initial value", BpfMapSetInitialValue(m, make([]byte, BpfMapValueSize(m))),
		"bpf_map__set_initial_value", unix.EBUSY)
}

// TestBpfMapElemBeforeLoad calls every element operation on a map of an
// opened object before the load, which is ENOENT, and on a nil map, which is
// EINVAL. With a descriptor, a buffer of the wrong size is EINVAL before any
// syscall.
func TestBpfMapElemBeforeLoad(t *testing.T) {
	obj := openProg(t, "kprobe.bpf.o")
	counts := BpfObjectFindMapByName(obj, "counts")
	if counts == nil {
		t.Fatal("no counts map")
	}
	key, value := make([]byte, 4), make([]byte, 8)

	ops := mapElemOps
	for _, op := range ops {
		checkMapOpError(t, op.name+" before load", op.call(counts, key, value), op.name, unix.ENOENT)
		checkMapOpError(t, op.name+" on nil", op.call(nil, key, value), op.name, unix.EINVAL)
	}

	created := loadedMap(&BpfMap{name: "created", mapType: BPF_MAP_TYPE_ARRAY, fd: 0, keySize: 4, valueSize: 8})
	for _, op := range ops {
		checkMapOpError(t, op.name+" short key", op.call(created, key[:3], value), op.name, unix.EINVAL)
	}
	for _, op := range ops[:2] {
		checkMapOpError(t, op.name+" short value", op.call(created, key, value[:7]), op.name, unix.EINVAL)
	}
	checkMapOpError(t, "lookup and delete short value", BpfMapLookupAndDeleteElem(created, key, value[:7], 0),
		"bpf_map__lookup_and_delete_elem", unix.EINVAL)
	checkMapOpError(t, "next key with a short current key", BpfMapGetNextKey(created, key[:3], key),
		"bpf_map__get_next_key", unix.EINVAL)
}

// checkMapOpError fails the test unless err is an *Error of op with errno.
func checkMapOpError(t *testing.T, what string, err error, op string, errno error) {
	t.Helper()

	var lerr *Error
	if !errors.As(err, &lerr) || lerr.Op != op || !errors.Is(err, errno) {
		t.Errorf("%s: got %v, want a %s error with %v", what, err, op, errno)
	}
}

// checkMapOpLog fails the test unless err is an *Error whose log contains
// log. An empty log checks nothing.
func checkMapOpLog(t *testing.T, what string, err error, log string) {
	t.Helper()

	var lerr *Error
	if log != "" && (!errors.As(err, &lerr) || !strings.Contains(lerr.Log, log)) {
		t.Errorf("%s: got %v, want the log to contain %q", what, err, log)
	}
}

// TestBpfMapInitialValue checks the initial value of an internal map before
// the load: it is the section image, the returned slice aliases the object's
// buffer, and BpfMapSetInitialValue copies a value of the map value size in.
// A .maps map has none, the .kconfig map cannot be set, and a created map
// is busy: one of a loaded object, of an object whose load failed, or one
// given a descriptor with BpfMapReuseFD.
func TestBpfMapInitialValue(t *testing.T) {
	obj := openGlobalData(t)
	data := globalDataMap(t, obj, ".data")
	want := globalDataImages()[".data"]

	got := BpfMapInitialValue(data)
	if !bytes.Equal(got, want) {
		t.Fatalf(".data initial value = %x, want %x", got, want)
	}
	got[0] ^= 0xff
	if BpfMapInitialValue(data)[0] != got[0] {
		t.Error("the initial value does not alias the object's buffer")
	}

	value := bytes.Repeat([]byte{0x5a}, len(want))
	if err := BpfMapSetInitialValue(data, value); err != nil {
		t.Fatalf("BpfMapSetInitialValue: %v", err)
	}
	value[0] = 0
	if got := BpfMapInitialValue(data); !bytes.Equal(got, bytes.Repeat([]byte{0x5a}, len(want))) {
		t.Errorf(".data initial value = %x after the set, want the copied value", got)
	}

	const op = "bpf_map__set_initial_value"
	checkMapOpError(t, "short value", BpfMapSetInitialValue(data, value[1:]), op, unix.EINVAL)
	checkMapOpError(t, "long value", BpfMapSetInitialValue(data, append(value, 0)), op, unix.EINVAL)
	checkMapOpError(t, "nil map", BpfMapSetInitialValue(nil, value), op, unix.EINVAL)
	if BpfMapInitialValue(nil) != nil {
		t.Error("nil map has an initial value")
	}

	counts := BpfObjectFindMapByName(openProg(t, "kprobe.bpf.o"), "counts")
	if BpfMapInitialValue(counts) != nil {
		t.Error(".maps map has an initial value")
	}
	checkMapOpError(t, ".maps map", BpfMapSetInitialValue(counts, make([]byte, 8)), op, unix.EINVAL)

	kconfig := BpfObjectFindMapByName(openProg(t, "kconfig.bpf.o"), ".kconfig")
	if kconfig == nil || len(BpfMapInitialValue(kconfig)) != int(BpfMapValueSize(kconfig)) {
		t.Fatalf(".kconfig initial value = %x, want %d bytes", BpfMapInitialValue(kconfig), BpfMapValueSize(kconfig))
	}
	checkMapOpError(t, ".kconfig map", BpfMapSetInitialValue(kconfig, make([]byte, BpfMapValueSize(kconfig))), op, unix.EINVAL)

	for _, m := range []*BpfMap{
		loadedMap(&BpfMap{name: "loaded", libbpfType: libbpfMapData, fd: 0, valueSize: 4, initialValue: make([]byte, 4)}),
		{obj: &BpfObject{attempted: true}, name: "failed", libbpfType: libbpfMapData, fd: -1, valueSize: 4, initialValue: make([]byte, 4)},
		{obj: &BpfObject{}, name: "reused", libbpfType: libbpfMapData, fd: 0, reused: true, valueSize: 4, initialValue: make([]byte, 4)},
	} {
		checkMapOpError(t, m.name+" map", BpfMapSetInitialValue(m, make([]byte, 4)), op, unix.EBUSY)
		checkMapOpError(t, m.name+" map with a bad size", BpfMapSetInitialValue(m, nil), op, unix.EBUSY)
	}
}

// TestBpfMapInitialValueClose follows the initial value of
// link_kconfig.bpf.o's .bss map through a failed load and BpfObjectClose. A
// CONFIG_GOBPFGO_LINKED value that is not an integer fails the load while it
// resolves the externs, before any bpf() call, so the test needs no
// privileges. The failed object cannot be loaded again: the map keeps its
// initial value and a set is EBUSY. BpfObjectClose releases the buffer: the
// initial value is nil and a set is EINVAL, for the failed object, for one
// that was only opened, and for a loaded or reused map, which a set would
// otherwise find busy.
func TestBpfMapInitialValueClose(t *testing.T) {
	const op = "bpf_map__set_initial_value"

	kconfig := "CONFIG_TEST=1\nCONFIG_GOBPFGO_LINKED=gobpfgo\n"
	failed := openProgOpts(t, "link_kconfig.bpf.o", &BpfObjectOpenOpts{Kconfig: &kconfig})
	bss := globalDataMap(t, failed, ".bss")
	want := make([]byte, BpfMapValueSize(bss))
	if err := BpfObjectLoad(failed); err == nil || !strings.Contains(err.Error(), "isn't a valid integer") {
		t.Fatalf("load: %v, want the CONFIG_GOBPFGO_LINKED parse error", err)
	}
	if got := BpfMapInitialValue(bss); !bytes.Equal(got, want) {
		t.Errorf(".bss initial value after the failed load = %x, want %x", got, want)
	}
	checkMapOpError(t, "set after the failed load", BpfMapSetInitialValue(bss, want), op, unix.EBUSY)

	opened := openProg(t, "link_kconfig.bpf.o")
	loaded, reused := openProg(t, "link_kconfig.bpf.o"), openProg(t, "link_kconfig.bpf.o")
	loaded.attempted, loaded.loaded = true, true
	globalDataMap(t, reused, ".bss").reused = true
	for name, obj := range map[string]*BpfObject{"failed": failed, "opened": opened, "loaded": loaded, "reused": reused} {
		m := globalDataMap(t, obj, ".bss")
		BpfObjectClose(obj)
		if got := BpfMapInitialValue(m); got != nil {
			t.Errorf("%s: initial value after close = %x, want nil", name, got)
		}
		checkMapOpError(t, name+" set after close", BpfMapSetInitialValue(m, want), op, unix.EINVAL)
	}
}

// u32Key and u64Value encode a 4-byte key and an 8-byte value in native byte
// order.
func u32Key(v uint32) []byte {
	return binary.NativeEndian.AppendUint32(nil, v)
}

func u64Value(v uint64) []byte {
	return binary.NativeEndian.AppendUint64(nil, v)
}

// mapKeys walks m with BpfMapGetNextKey from the first key and returns the
// keys it visits, stopping at the kernel's ENOENT.
func mapKeys(t *testing.T, m *BpfMap) []uint32 {
	t.Helper()

	var keys []uint32
	var cur []byte
	for range BpfMapMaxEntries(m) + 1 {
		next := make([]byte, BpfMapKeySize(m))
		err := BpfMapGetNextKey(m, cur, next)
		if errors.Is(err, unix.ENOENT) {
			slices.Sort(keys)
			return keys
		}
		if err != nil {
			t.Fatalf("get next key after %x: %v", cur, err)
		}
		keys = append(keys, binary.NativeEndian.Uint32(next))
		cur = next
	}
	t.Fatalf("walk of %s did not end after %d keys", BpfMapName(m), len(keys))
	return nil
}

// checkLookup fails the test unless key holds want in m.
func checkLookup(t *testing.T, m *BpfMap, key uint32, want uint64) {
	t.Helper()

	value := make([]byte, 8)
	if err := BpfMapLookupElem(m, u32Key(key), value, 0); err != nil {
		t.Fatalf("lookup %d: %v", key, err)
	}
	if got := binary.NativeEndian.Uint64(value); got != want {
		t.Errorf("key %d = %#x, want %#x", key, got, want)
	}
}

// TestBpfMapElemOps loads sanitize_enum64.bpf.o and runs every element
// operation on its two-entry hash map: updates with each flag, a lookup, a
// key walk, a lookup-and-delete and deletes. The kernel errno comes back
// unchanged. A kernel before 5.14 has no lookup-and-delete for hash maps and
// returns ENOTSUPP, and the key is then deleted on its own. Last, the
// program inserts its own element into the emptied map. It needs root or
// CAP_BPF and skips otherwise.
func TestBpfMapElemOps(t *testing.T) {
	obj := loadTestObject(t, progsDir+"/"+sanitizeEnum64Object)
	defer BpfObjectClose(obj)
	m := BpfObjectFindMapByName(obj, "wide_values")
	if m == nil {
		t.Fatal("no wide_values map")
	}

	if keys := mapKeys(t, m); len(keys) != 0 {
		t.Fatalf("keys of the new map = %v, want none", keys)
	}
	if err := BpfMapUpdateElem(m, u32Key(1), u64Value(0x1111), BPF_NOEXIST); err != nil {
		t.Fatalf("update 1 with BPF_NOEXIST: %v", err)
	}
	updates := []struct {
		key   uint32
		flags uint64
		want  error
	}{
		{1, BPF_NOEXIST, unix.EEXIST},
		{2, BPF_EXIST, unix.ENOENT},
		{2, BPF_ANY, nil},
		{3, BPF_ANY, unix.E2BIG},
	}
	for _, u := range updates {
		err := BpfMapUpdateElem(m, u32Key(u.key), u64Value(0x2222), u.flags)
		if u.want == nil && err != nil || u.want != nil && !errors.Is(err, u.want) {
			t.Errorf("update %d with flags %d: %v, want %v", u.key, u.flags, err, u.want)
		}
	}
	checkLookup(t, m, 1, 0x1111)
	checkLookup(t, m, 2, 0x2222)
	if keys := mapKeys(t, m); !slices.Equal(keys, []uint32{1, 2}) {
		t.Errorf("keys = %v, want [1 2]", keys)
	}

	value := make([]byte, 8)
	err := BpfMapLookupAndDeleteElem(m, u32Key(1), value, 0)
	switch {
	case errors.Is(err, enotsupp):
		t.Logf("lookup and delete on a hash map: %v; deleting key 1 instead", err)
		if err := BpfMapDeleteElem(m, u32Key(1), 0); err != nil {
			t.Fatalf("delete 1: %v", err)
		}
	case err != nil:
		t.Fatalf("lookup and delete 1: %v", err)
	case binary.NativeEndian.Uint64(value) != 0x1111:
		t.Errorf("lookup and delete 1 = %x, want 0x1111", value)
	}
	if err := BpfMapLookupElem(m, u32Key(1), value, 0); !errors.Is(err, unix.ENOENT) {
		t.Errorf("lookup 1 after its delete: %v, want ENOENT", err)
	}
	if err := BpfMapLookupAndDeleteElem(m, u32Key(1), value, 0); !errors.Is(err, unix.ENOENT) && !errors.Is(err, enotsupp) {
		t.Errorf("lookup and delete of a missing key: %v, want ENOENT", err)
	}

	if err := BpfMapDeleteElem(m, u32Key(2), 0); err != nil {
		t.Fatalf("delete 2: %v", err)
	}
	if err := BpfMapDeleteElem(m, u32Key(2), 0); !errors.Is(err, unix.ENOENT) {
		t.Errorf("delete 2 twice: %v, want ENOENT", err)
	}
	if keys := mapKeys(t, m); len(keys) != 0 {
		t.Fatalf("keys after the deletes = %v, want none", keys)
	}

	// handle_enum64 stores WIDE_HIGH at SIGNED_NEG.
	attachKprobes(t, obj, map[string]string{"handle_enum64": "do_sys_openat2"})
	triggerOpen(t)
	const signedNeg = 0xffffffff
	if keys := mapKeys(t, m); !slices.Equal(keys, []uint32{signedNeg}) {
		t.Fatalf("keys after the program ran = %v, want [%#x]", keys, signedNeg)
	}
	checkLookup(t, m, signedNeg, 0x100000000)
}

// TestBpfMapElemOpsArray runs the element operations that an array map
// supports on kprobe.bpf.o's one-entry counts map: an update and a lookup,
// and a key walk that sees its only index. Deleting an array element is
// EINVAL from the kernel. It needs root or CAP_BPF and skips otherwise.
func TestBpfMapElemOpsArray(t *testing.T) {
	obj := loadTestObject(t, progsDir+"/kprobe.bpf.o")
	defer BpfObjectClose(obj)
	m := BpfObjectFindMapByName(obj, "counts")

	if err := BpfMapUpdateElem(m, u32Key(0), u64Value(42), BPF_EXIST); err != nil {
		t.Fatalf("update 0: %v", err)
	}
	checkLookup(t, m, 0, 42)
	if keys := mapKeys(t, m); !slices.Equal(keys, []uint32{0}) {
		t.Errorf("keys = %v, want [0]", keys)
	}
	if err := BpfMapUpdateElem(m, u32Key(1), u64Value(1), BPF_ANY); !errors.Is(err, unix.E2BIG) {
		t.Errorf("update past the end: %v, want E2BIG", err)
	}
	if err := BpfMapDeleteElem(m, u32Key(0), 0); !errors.Is(err, unix.EINVAL) {
		t.Errorf("delete an array element: %v, want EINVAL", err)
	}
}

// TestBpfMapQueueOps creates a queue map, whose key size is 0, and pushes,
// peeks and pops it through the element operations with an empty key, which
// passes a NULL key to the kernel. It needs root or CAP_BPF and skips
// otherwise.
func TestBpfMapQueueOps(t *testing.T) {
	fd, err := BpfMapCreate(BPF_MAP_TYPE_QUEUE, "gobpfgo_queue", 0, 8, 2, nil)
	skipIfNotPermitted(t, err)
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}
	defer unix.Close(fd)
	// A descriptor from outside any object, as BpfMapReuseFD leaves it.
	m := &BpfMap{name: "gobpfgo_queue", mapType: BPF_MAP_TYPE_QUEUE, valueSize: 8, maxEntries: 2, fd: fd, reused: true}

	for _, v := range []uint64{7, 8} {
		if err := BpfMapUpdateElem(m, nil, u64Value(v), BPF_ANY); err != nil {
			t.Fatalf("push %d: %v", v, err)
		}
	}
	value := make([]byte, 8)
	if err := BpfMapLookupElem(m, nil, value, 0); err != nil || binary.NativeEndian.Uint64(value) != 7 {
		t.Fatalf("peek = %x, %v, want 7", value, err)
	}
	for _, want := range []uint64{7, 8} {
		if err := BpfMapLookupAndDeleteElem(m, nil, value, 0); err != nil || binary.NativeEndian.Uint64(value) != want {
			t.Fatalf("pop = %x, %v, want %d", value, err, want)
		}
	}
	if err := BpfMapLookupAndDeleteElem(m, nil, value, 0); !errors.Is(err, unix.ENOENT) {
		t.Errorf("pop of an empty queue: %v, want ENOENT", err)
	}
	if err := BpfMapUpdateElem(m, u32Key(0), u64Value(1), BPF_ANY); !errors.Is(err, unix.EINVAL) {
		t.Errorf("push with a key: %v, want EINVAL", err)
	}
}

// TestBpfMapSetInitialValueLoad sets new initial values for the .data,
// .rodata and .bss maps of global_data.bpf.o before the load and checks that
// the load wrote them, that .rodata is still frozen, and that the attached
// program sees them: it copies the new .rodata value and counts on from the
// new .bss counter. A set after the load is EBUSY. It needs root or CAP_BPF
// and skips otherwise.
func TestBpfMapSetInitialValueLoad(t *testing.T) {
	const (
		newMagic   = 0x0102030405060708
		newRodata  = 0x8877665544332211
		newCounter = 1000
	)
	obj := openGlobalData(t)
	images := globalDataImages()
	binary.NativeEndian.PutUint64(images[".data"][0:], newMagic)
	binary.NativeEndian.PutUint64(images[".rodata"][8:], newRodata)
	binary.NativeEndian.PutUint64(images[".bss"][0:], newCounter)
	for section, image := range images {
		if err := BpfMapSetInitialValue(globalDataMap(t, obj, section), image); err != nil {
			t.Fatalf("set %s initial value: %v", section, err)
		}
	}

	err := BpfObjectLoad(obj)
	skipIfNotPermitted(t, err)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for section, image := range images {
		m := globalDataMap(t, obj, section)
		if got := lookupGlobal(t, m); !bytes.Equal(got, image) {
			t.Errorf("%s after load = %x, want %x", section, got, image)
		}
		if got := BpfMapInitialValue(m); !bytes.Equal(got, image) {
			t.Errorf("%s initial value after load = %x, want %x", section, got, image)
		}
		checkMapOpError(t, section+" set after load", BpfMapSetInitialValue(m, image), "bpf_map__set_initial_value", unix.EBUSY)
	}
	rodata := globalDataMap(t, obj, ".rodata")
	if err := BpfMapUpdateElem(rodata, u32Key(0), images[".rodata"], 0); !errors.Is(err, unix.EPERM) {
		t.Errorf("update frozen .rodata: %v, want EPERM", err)
	}

	attachKprobes(t, obj, map[string]string{"handle_global": "do_sys_openat2"})
	triggerOpen(t)
	data := lookupGlobal(t, globalDataMap(t, obj, ".data"))
	bss := lookupGlobal(t, globalDataMap(t, obj, ".bss"))
	u64 := binary.NativeEndian.Uint64
	if got := u64(data[0:]); got != newMagic {
		t.Errorf("data_magic = %#x, want %#x", got, uint64(newMagic))
	}
	if got := u64(bss[0:]); got <= newCounter {
		t.Errorf("bss_counter = %d, want more than %d", got, newCounter)
	}
	if got := u64(bss[8:]); got != newRodata {
		t.Errorf("bss_seen = %#x, want the new .rodata value %#x", got, uint64(newRodata))
	}
}

// TestBpfMapOpsAfterFailedLoad loads kfunc_missing.bpf.o, whose program fails
// on every kernel after the load created its kfunc_counts hash map and its
// .data map. Before the load the element operations are ENOENT. The failed
// load closes both descriptors, but the maps stay created: the element
// operations fail with EINVAL for the missing descriptor, BpfMapFD is -1 and
// BpfMapSetInitialValue is EBUSY. It needs root or CAP_BPF and skips
// otherwise, and skips without kernel BTF, which the extern needs.
func TestBpfMapOpsAfterFailedLoad(t *testing.T) {
	requireKernelBTF(t)
	obj := openProg(t, "kfunc_missing.bpf.o")
	counts := BpfObjectFindMapByName(obj, "kfunc_counts")
	data := globalDataMap(t, obj, ".data")
	if counts == nil {
		t.Fatal("no kfunc_counts map")
	}
	checkMapOpError(t, "lookup before the load", BpfMapLookupElem(counts, make([]byte, 4), make([]byte, 8), 0),
		"bpf_map__lookup_elem", unix.ENOENT)

	err := BpfObjectLoad(obj)
	skipIfNotPermitted(t, err)
	var lerr *Error
	if !errors.As(err, &lerr) || lerr.Op != "bpf_prog_load" || !errors.Is(err, unix.EINVAL) {
		t.Fatalf("load: %v, want the bpf_prog_load EINVAL for the poisoned kfunc call", err)
	}
	checkMapWithoutFD(t, counts)
	checkMapWithoutFD(t, data)
}
