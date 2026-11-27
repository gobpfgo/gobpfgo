// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: perf_event_open_probe

//go:build linux && (amd64 || arm64)

package sys

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// PerfEventOpenKprobe opens a perf event of the kprobe PMU and returns its
// descriptor, which the caller owns.
//
// attr must describe the kprobe: the caller sets Type to the PMU type, Size,
// Config to the retprobe bit, and Ext2, the kernel's config2, to the offset
// into funcName or, when funcName is empty, the raw kernel address. The call
// points Ext1, the kernel's config1, at a NUL-terminated copy of funcName for
// the duration of perf_event_open, or sets it to 0 for a raw address, and
// clears it again before it returns. The event is opened with pid and cpu as
// given, no group and PERF_FLAG_FD_CLOEXEC.
//
// A nil attr or a funcName with a NUL byte returns EINVAL without calling the
// kernel; otherwise the error is the perf_event_open errno.
func PerfEventOpenKprobe(attr *unix.PerfEventAttr, funcName string, pid, cpu int) (int, error) {
	if attr == nil {
		return -1, unix.EINVAL
	}
	return perfEventOpenProbe(attr, funcName, pid, cpu)
}

// PerfEventOpenUprobe opens a perf event of the uprobe PMU on the file at
// path and returns its descriptor, which the caller owns.
//
// attr must describe the uprobe: the caller sets Type to the PMU type, Size,
// Config to the retprobe bit and reference counter offset, and Ext2, the
// kernel's config2, to the probe's file offset. The call points Ext1, the
// kernel's config1, at a NUL-terminated copy of path for the duration of
// perf_event_open and clears it again before it returns. The event is opened
// with pid and cpu as given, no group and PERF_FLAG_FD_CLOEXEC.
//
// An empty path or a path with a NUL byte returns EINVAL without calling the
// kernel; otherwise the error is the perf_event_open errno.
func PerfEventOpenUprobe(attr *unix.PerfEventAttr, path string, pid, cpu int) (int, error) {
	if attr == nil || path == "" {
		return -1, unix.EINVAL
	}
	return perfEventOpenProbe(attr, path, pid, cpu)
}

// perfEventOpenProbe opens a probe PMU event whose config1 is name, the
// kprobe function or the uprobe path, or 0 when name is empty.
func perfEventOpenProbe(attr *unix.PerfEventAttr, name string, pid, cpu int) (int, error) {
	nameBytes, err := setProbeName(attr, name)
	if err != nil {
		return -1, err
	}
	fd, err := unix.PerfEventOpen(attr, pid, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	runtime.KeepAlive(nameBytes)
	attr.Ext1 = 0
	return fd, err
}

// setProbeName points Ext1, the kernel's config1, at a NUL-terminated copy of
// name and returns the copy, which the caller keeps alive until the kernel
// has read it. An empty name sets Ext1 to 0 and returns nil. A name with a NUL
// byte is EINVAL and leaves attr unchanged.
func setProbeName(attr *unix.PerfEventAttr, name string) ([]byte, error) {
	if name == "" {
		attr.Ext1 = 0
		return nil, nil
	}
	nameBytes, err := unix.ByteSliceFromString(name)
	if err != nil {
		return nil, err
	}
	attr.Ext1 = uint64(addr(nameBytes))
	return nameBytes, nil
}
