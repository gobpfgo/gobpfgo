// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
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

func TestBpfMapLookupElemChecks(t *testing.T) {
	if err := BpfMapLookupElem(nil, nil, nil, 0); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("nil map: got %v, want EINVAL", err)
	}

	m := &BpfMap{fd: -1, keySize: 4, valueSize: 8}
	if err := BpfMapLookupElem(m, make([]byte, 4), make([]byte, 8), 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("unloaded map: got %v, want EBADF", err)
	}

	m.fd = 0
	if err := BpfMapLookupElem(m, make([]byte, 3), make([]byte, 8), 0); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("short key: got %v, want EINVAL", err)
	}
	if err := BpfMapLookupElem(m, make([]byte, 4), make([]byte, 7), 0); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("short value: got %v, want EINVAL", err)
	}

	// A per-CPU map without BPF_F_CPU or BPF_F_ALL_CPUS returns one value
	// per possible CPU, so a single value is too short.
	m.mapType = BPF_MAP_TYPE_PERCPU_ARRAY
	if err := BpfMapLookupElem(m, make([]byte, 4), make([]byte, 8), 0); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("per-CPU map with one value: got %v, want EINVAL", err)
	}
}
