// SPDX-License-Identifier: LGPL-2.1-only
// Ported from libbpf src/bpf.c at 4f05fb0.

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestBpfMapCreateArray(t *testing.T) {
	fd, err := BpfMapCreate(BPF_MAP_TYPE_ARRAY, "golbpfgo-test", 4, 8, 16, nil)
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
	_, err := BpfMapCreate(BPF_MAP_TYPE_ARRAY, "golbpfgo-test", 4, 8, 16, &BpfMapCreateOpts{Sz: 1})
	if !errors.Is(err, unix.EINVAL) {
		t.Fatalf("got %v, want EINVAL", err)
	}
}

func TestBpfMapCreateOptsSize(t *testing.T) {
	if NewBpfMapCreateOpts().Sz == 0 {
		t.Fatal("NewBpfMapCreateOpts returned Sz zero")
	}
}
