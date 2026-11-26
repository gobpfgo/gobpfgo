// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

package libbpf

import "syscall"

// Error is the error returned by the libbpf wrappers. Errno preserves the
// code from the failed operation, so errors.Is(err, unix.EINVAL) works.
type Error struct {
	Op    string
	Errno syscall.Errno
	Path  string
	Log   string
}

func (e *Error) Error() string {
	msg := e.Op
	if e.Path != "" {
		msg += " " + e.Path
	}
	msg += ": " + e.Errno.Error()
	if e.Log != "" {
		msg += ": " + e.Log
	}
	return msg
}

// Unwrap exposes the errno to errors.Is and errors.As.
func (e *Error) Unwrap() error {
	return e.Errno
}
