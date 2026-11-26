// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_map__set_pin_path, bpf_map__pin, bpf_map__unpin, bpf_map__is_pinned, bpf_program__pin, bpf_program__unpin, bpf_object__pin_maps, bpf_object__unpin_maps, bpf_object__pin_programs, bpf_object__unpin_programs, bpf_object__pin, bpf_object__unpin

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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

// BpfObjectPinMaps pins every loaded map of obj.
//
// When path is nil, each map's stored pin path is used and maps without one
// are skipped. When path is non-nil, each map is pinned at path/<map-name>;
// dots in the resulting path become underscores, matching libbpf. If a pin
// fails, the maps pinned by this call are unpinned.
func BpfObjectPinMaps(obj *BpfObject, path *string) error {
	const op = "bpf_object__pin_maps"

	if !objectMapsLoaded(obj) {
		return &Error{Op: op, Errno: unix.ENOENT}
	}

	pinned := make([]*BpfMap, 0, len(obj.maps))
	for _, m := range obj.maps {
		var pinPath *string

		switch {
		case path != nil:
			p := sanitizePinPath(filepath.Join(*path, m.name))
			pinPath = &p
		case m.pinPath == "":
			continue
		}

		if err := BpfMapPin(m, pinPath); err != nil {
			for _, done := range pinned {
				_ = BpfMapUnpin(done, nil)
			}
			return pinError(op, err)
		}
		pinned = append(pinned, m)
	}
	return nil
}

// BpfObjectUnpinMaps removes the pinned maps of obj. When path is nil, each
// map's stored pin path is used and maps without one are skipped.
func BpfObjectUnpinMaps(obj *BpfObject, path *string) error {
	const op = "bpf_object__unpin_maps"

	if obj == nil || obj.closed {
		return &Error{Op: op, Errno: unix.ENOENT}
	}

	for _, m := range obj.maps {
		var pinPath *string

		switch {
		case path != nil:
			p := sanitizePinPath(filepath.Join(*path, m.name))
			pinPath = &p
		case m.pinPath == "":
			continue
		}

		if err := BpfMapUnpin(m, pinPath); err != nil {
			return pinError(op, err)
		}
	}
	return nil
}

// BpfObjectPinPrograms pins every loaded program of obj at path/<program-name>.
// Dots in the resulting path become underscores, matching libbpf. If a pin
// fails, the programs pinned by this call are unpinned.
func BpfObjectPinPrograms(obj *BpfObject, path string) error {
	const op = "bpf_object__pin_programs"

	if !objectProgramsLoaded(obj) {
		return &Error{Op: op, Errno: unix.ENOENT}
	}
	if path == "" {
		return &Error{Op: op, Errno: unix.EINVAL}
	}

	pinned := make([]*BpfProgram, 0, len(obj.programs))
	for _, p := range obj.programs {
		pinPath := sanitizePinPath(filepath.Join(path, p.name))
		if err := BpfProgramPin(p, pinPath); err != nil {
			for _, done := range pinned {
				_ = BpfProgramUnpin(done, sanitizePinPath(filepath.Join(path, done.name)))
			}
			return pinError(op, err)
		}
		pinned = append(pinned, p)
	}
	return nil
}

// BpfObjectUnpinPrograms removes the programs of obj from path.
func BpfObjectUnpinPrograms(obj *BpfObject, path string) error {
	const op = "bpf_object__unpin_programs"

	if obj == nil || obj.closed {
		return &Error{Op: op, Errno: unix.ENOENT}
	}
	if path == "" {
		return &Error{Op: op, Errno: unix.EINVAL}
	}

	for _, p := range obj.programs {
		pinPath := sanitizePinPath(filepath.Join(path, p.name))
		if err := BpfProgramUnpin(p, pinPath); err != nil {
			return pinError(op, err)
		}
	}
	return nil
}

// BpfObjectPin pins every map at path/<map-name> and every program at
// path/<program-name>. If the program pins fail, the map pins are undone.
func BpfObjectPin(obj *BpfObject, path string) error {
	const op = "bpf_object__pin"

	if obj == nil || obj.closed {
		return &Error{Op: op, Errno: unix.ENOENT}
	}
	if path == "" {
		return &Error{Op: op, Errno: unix.EINVAL}
	}

	if err := BpfObjectPinMaps(obj, &path); err != nil {
		return err
	}
	if err := BpfObjectPinPrograms(obj, path); err != nil {
		_ = BpfObjectUnpinMaps(obj, &path)
		return err
	}
	return nil
}

// BpfObjectUnpin removes the programs and then the maps of obj from path.
func BpfObjectUnpin(obj *BpfObject, path string) error {
	const op = "bpf_object__unpin"

	if obj == nil || obj.closed {
		return &Error{Op: op, Errno: unix.ENOENT}
	}
	if path == "" {
		return &Error{Op: op, Errno: unix.EINVAL}
	}

	if err := BpfObjectUnpinPrograms(obj, path); err != nil {
		return err
	}
	return BpfObjectUnpinMaps(obj, &path)
}

// objectMapsLoaded reports whether obj has maps and all of them are created.
func objectMapsLoaded(obj *BpfObject) bool {
	if obj == nil || obj.closed {
		return false
	}
	for _, m := range obj.maps {
		if m.fd < 0 {
			return false
		}
	}
	return true
}

// objectProgramsLoaded reports whether obj has programs and all of them are
// loaded.
func objectProgramsLoaded(obj *BpfObject) bool {
	if obj == nil || obj.closed {
		return false
	}
	for _, p := range obj.programs {
		if p.fd < 0 {
			return false
		}
	}
	return true
}

// sanitizePinPath replaces periods with underscores, the same rule libbpf
// applies to object pin paths.
func sanitizePinPath(path string) string {
	return strings.ReplaceAll(path, ".", "_")
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
