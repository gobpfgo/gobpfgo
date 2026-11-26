// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

package libbpf

import "syscall"

// Error is a libbpf operation error.
//
// Errno preserves the kernel error code, Op names the Go operation, and Path
// and Log add context when the operation had them. Unwrap returns Errno, so
// errors.Is and errors.As work with syscall errno values:
//
//	if errors.Is(err, unix.EINVAL) {
//		...
//	}
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
