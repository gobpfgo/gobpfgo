// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package sys

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestMapElemArgs checks the argument errors the map element calls return
// before any syscall: a negative descriptor, and an empty buffer the kernel
// would write to. An empty key is not an error; it passes a NULL key.
func TestMapElemArgs(t *testing.T) {
	key, value := make([]byte, 4), make([]byte, 8)

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"lookup without fd", func() error { return MapLookupElem(-1, key, value, 0) }},
		{"lookup without value", func() error { return MapLookupElem(0, key, nil, 0) }},
		{"update without fd", func() error { return MapUpdateElem(-1, key, value, 0) }},
		{"update without value", func() error { return MapUpdateElem(0, key, nil, 0) }},
		{"delete without fd", func() error { return MapDeleteElem(-1, key, 0) }},
		{"lookup and delete without fd", func() error { return MapLookupAndDeleteElem(-1, key, value, 0) }},
		{"lookup and delete without value", func() error { return MapLookupAndDeleteElem(0, nil, nil, 0) }},
		{"next key without fd", func() error { return MapGetNextKey(-1, nil, key) }},
		{"next key without buffer", func() error { return MapGetNextKey(0, key, nil) }},
	} {
		if err := tc.call(); !errors.Is(err, unix.EINVAL) {
			t.Errorf("%s: got %v, want EINVAL", tc.name, err)
		}
	}
}
