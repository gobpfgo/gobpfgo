// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

package libbpf

import (
	"fmt"
	"syscall"
)

// Error is the error returned by the libbpf wrappers. Errno preserves the
// code from the failed operation, so errors.Is(err, unix.EINVAL) works.
type Error struct {
	Op    string
	Errno syscall.Errno
	Path  string
	Log   string
}

func (e *Error) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("%s %s: %v", e.Op, e.Path, e.Errno)
	}
	return fmt.Sprintf("%s: %v", e.Op, e.Errno)
}

// Unwrap exposes the errno to errors.Is and errors.As.
func (e *Error) Unwrap() error {
	return e.Errno
}
