// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package sys

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

// TestRetryProgLoad checks the EAGAIN retry of a program load: a load that
// succeeds after EAGAIN returns the descriptor on the call that succeeded,
// every other error comes back at once, and an always-EAGAIN load gives up
// after the attempt limit and returns EAGAIN.
func TestRetryProgLoad(t *testing.T) {
	calls := 0
	fd, err := retryProgLoad(5, func() (uintptr, error) {
		calls++
		if calls < 3 {
			return 0, unix.EAGAIN
		}
		return 7, nil
	})
	if fd != 7 || err != nil || calls != 3 {
		t.Errorf("after two EAGAIN: fd %d err %v calls %d, want 7, nil, 3", fd, err, calls)
	}

	calls = 0
	fd, err = retryProgLoad(5, func() (uintptr, error) {
		calls++
		return 0, unix.EINVAL
	})
	if fd != 0 || !errors.Is(err, unix.EINVAL) || calls != 1 {
		t.Errorf("on EINVAL: fd %d err %v calls %d, want 0, EINVAL, 1", fd, err, calls)
	}

	calls = 0
	fd, err = retryProgLoad(5, func() (uintptr, error) {
		calls++
		return 0, unix.EAGAIN
	})
	if fd != 0 || !errors.Is(err, unix.EAGAIN) || calls != 5 {
		t.Errorf("always EAGAIN: fd %d err %v calls %d, want 0, EAGAIN, 5", fd, err, calls)
	}
}
