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
	pathBytes, err := unix.ByteSliceFromString(path)
	if err != nil {
		return -1, err
	}

	attr.Ext1 = uint64(addr(pathBytes))
	fd, err := unix.PerfEventOpen(attr, pid, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	runtime.KeepAlive(pathBytes)
	attr.Ext1 = 0
	return fd, err
}
