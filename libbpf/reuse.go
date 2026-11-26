// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_map__reuse_fd

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"strings"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// BpfMapReuseFD makes a map use an existing kernel map instead of creating a
// new one.
//
// The call reads the map info from fd, duplicates fd with O_CLOEXEC, replaces
// the map descriptor and copies the type, key and value sizes, max entries,
// flags and BTF ids from the reused map. BpfObjectLoad then skips creating
// this map and uses the duplicate. The caller keeps ownership of fd; the
// duplicate is closed with the object.
//
// Call it after BpfObjectOpenFile and before BpfObjectLoad. An fd that is not
// a BPF map returns the kernel errno, and a closed map returns EBADF.
func BpfMapReuseFD(m *BpfMap, fd int) error {
	const op = "bpf_map__reuse_fd"

	if m == nil || fd < 0 {
		return &Error{Op: op, Errno: unix.EINVAL}
	}

	info, err := sys.MapInfoByFD(fd)
	if err != nil {
		return &Error{Op: op, Errno: errnoFromError(err)}
	}

	newFD, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return &Error{Op: op, Errno: errnoFromError(err)}
	}

	if m.fd >= 0 {
		unix.Close(m.fd)
	}
	m.fd = newFD
	m.reused = true
	m.name = reuseMapName(m.name, info.Name)
	m.mapType = BpfMapType(info.Type)
	m.keySize = info.KeySize
	m.valueSize = info.ValueSize
	m.maxEntries = info.MaxEntries
	m.mapFlags = info.MapFlags
	m.btfKeyTypeID = info.BtfKeyTypeID
	m.btfValueTypeID = info.BtfValueTypeID

	return nil
}

// reuseMapName keeps the object name when the kernel truncated it to 15
// bytes and the reused map carries that prefix, the same rule libbpf uses.
func reuseMapName(current, reused string) string {
	if len(reused) == sys.BPF_OBJ_NAME_LEN-1 && strings.HasPrefix(current, reused) {
		return current
	}
	return reused
}
