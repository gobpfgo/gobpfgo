// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_map__set_pin_path, bpf_map__pin, bpf_map__unpin, bpf_map__is_pinned, bpf_program__pin, bpf_program__unpin

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// BpfMapSetPinPath sets or clears the pin path stored on a map.
//
// A nil path clears the stored path; a non-nil path is copied. It does not
// touch bpffs; BpfMapPin uses the stored path later. The map does not need to
// be loaded.
func BpfMapSetPinPath(m *BpfMap, path *string) error {
	const op = "bpf_map__set_pin_path"

	if m == nil {
		return &Error{Op: op, Errno: unix.EINVAL}
	}
	if path == nil {
		m.pinPath = ""
	} else {
		m.pinPath = *path
	}
	return nil
}

// BpfMapPin pins a loaded map on bpffs.
//
// path may be nil when the map already has a pin path, in which case the
// stored path is used. A different explicit path is rejected with EINVAL.
// Pinning an already pinned map at the stored path is a no-op. The parent
// directory must be on bpffs; BpfMapPin creates a missing parent with mode
// 0700, as libbpf does. The caller must unpin the map before removing bpffs
// entries.
func BpfMapPin(m *BpfMap, path *string) error {
	const op = "bpf_map__pin"

	if m == nil || m.fd < 0 {
		return &Error{Op: op, Errno: unix.EINVAL}
	}

	switch {
	case m.pinPath != "":
		if path != nil && *path != m.pinPath {
			return &Error{Op: op, Errno: unix.EINVAL, Log: fmt.Sprintf("map %q has pin path %q", m.name, m.pinPath)}
		}
		if m.pinned {
			return nil
		}
	case path == nil:
		return &Error{Op: op, Errno: unix.EINVAL, Log: fmt.Sprintf("map %q has no pin path", m.name)}
	case m.pinned:
		return &Error{Op: op, Errno: unix.EEXIST}
	default:
		m.pinPath = *path
	}

	if err := makeParentDir(m.pinPath); err != nil {
		return pinError(op, err)
	}
	if err := checkBpfFS(m.pinPath); err != nil {
		return pinError(op, err)
	}
	if err := sys.ObjPin(m.fd, m.pinPath, 0); err != nil {
		return pinError(op, err)
	}

	m.pinned = true
	return nil
}

// BpfMapUnpin removes a pinned map from bpffs.
//
// path may be nil when the map has a stored pin path. A different explicit
// path is rejected with EINVAL. The map descriptor stays open and the stored
// pin path is kept, matching libbpf.
func BpfMapUnpin(m *BpfMap, path *string) error {
	const op = "bpf_map__unpin"

	if m == nil {
		return &Error{Op: op, Errno: unix.EINVAL}
	}

	switch {
	case m.pinPath != "":
		if path != nil && *path != m.pinPath {
			return &Error{Op: op, Errno: unix.EINVAL, Log: fmt.Sprintf("map %q has pin path %q", m.name, m.pinPath)}
		}
		path = &m.pinPath
	case path == nil:
		return &Error{Op: op, Errno: unix.EINVAL, Log: fmt.Sprintf("map %q has no pin path", m.name)}
	}

	if err := checkBpfFS(*path); err != nil {
		return pinError(op, err)
	}
	if err := os.Remove(*path); err != nil {
		return pinError(op, err)
	}

	m.pinned = false
	return nil
}

// BpfMapIsPinned reports whether the map was pinned with BpfMapPin.
func BpfMapIsPinned(m *BpfMap) bool {
	return m != nil && m.pinned
}

// BpfProgramPin pins a loaded program at path on bpffs.
//
// The parent directory must be on bpffs; a missing parent is created with
// mode 0700. The caller must unpin the program with BpfProgramUnpin.
func BpfProgramPin(p *BpfProgram, path string) error {
	const op = "bpf_program__pin"

	if p == nil || p.fd < 0 || path == "" {
		return &Error{Op: op, Errno: unix.EINVAL}
	}
	if err := makeParentDir(path); err != nil {
		return pinError(op, err)
	}
	if err := checkBpfFS(path); err != nil {
		return pinError(op, err)
	}
	if err := sys.ObjPin(p.fd, path, 0); err != nil {
		return pinError(op, err)
	}
	return nil
}

// BpfProgramUnpin removes a pinned program from bpffs. The program
// descriptor stays open.
func BpfProgramUnpin(p *BpfProgram, path string) error {
	const op = "bpf_program__unpin"

	if p == nil || p.fd < 0 || path == "" {
		return &Error{Op: op, Errno: unix.EINVAL}
	}
	if err := checkBpfFS(path); err != nil {
		return pinError(op, err)
	}
	if err := os.Remove(path); err != nil {
		return pinError(op, err)
	}
	return nil
}

// makeParentDir creates the immediate parent directory of path with mode
// 0700, ignoring an existing directory, the same rule libbpf uses.
func makeParentDir(path string) error {
	dir := filepath.Dir(path)

	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}

// checkBpfFS requires the parent directory of path to be a BPF filesystem,
// the same guard libbpf applies before pinning.
func checkBpfFS(path string) error {
	var stat unix.Statfs_t

	if err := unix.Statfs(filepath.Dir(path), &stat); err != nil {
		return err
	}
	if stat.Type != unix.BPF_FS_MAGIC {
		return fmt.Errorf("%s is not on BPF FS: %w", path, unix.EINVAL)
	}
	return nil
}

func pinError(op string, err error) error {
	return &Error{Op: op, Errno: errnoFromError(err), Log: err.Error()}
}
