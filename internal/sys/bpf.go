// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original bpf() wrapper
// libbpf-source: src/bpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: sys_bpf, bpf_map_create, bpf_map_freeze, bpf_map_lookup_elem_flags, bpf_map_update_elem, bpf_map_delete_elem_flags, bpf_map_lookup_and_delete_elem_flags, bpf_map_get_next_key

//go:build linux && (amd64 || arm64)

package sys

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// bpf issues one bpf() syscall and returns its first return value.
func bpf(cmd uint32, attr []byte) (uintptr, error) {
	if len(attr) == 0 {
		return 0, unix.EINVAL
	}

	r1, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(cmd), addr(attr), uintptr(len(attr)))
	runtime.KeepAlive(attr)
	if errno != 0 {
		return 0, errno
	}
	return r1, nil
}

// BPF issues one bpf() syscall and discards its return value. The kernel errno
// is returned unchanged.
func BPF(cmd uint32, attr []byte) error {
	_, err := bpf(cmd, attr)
	return err
}

// MapCreate calls BPF_MAP_CREATE and returns the new map file descriptor.
//
// When exclHash is non-empty, its address and length are passed as the
// exclusive program hash and the slice is kept alive for the syscall.
func MapCreate(attr *MapCreateAttr, exclHash []byte) (int, error) {
	if len(exclHash) > 0 {
		attr.ExclProgHash = uint64(addr(exclHash))
		attr.ExclProgHashSize = uint32(len(exclHash))
	}

	fd, err := bpf(BPF_MAP_CREATE, attr.Marshal())
	runtime.KeepAlive(exclHash)
	if err != nil {
		return -1, err
	}
	return int(fd), nil
}

// ObjPin calls BPF_OBJ_PIN and pins the object fd at path.
//
// path must be a NUL-free path whose parent directory is on bpffs. The
// kernel returns EPERM when the caller lacks CAP_SYS_ADMIN and EINVAL when
// the parent is not a BPF filesystem. The path is kept alive until the
// syscall returns.
func ObjPin(fd int, path string, fileFlags uint32) error {
	if fd < 0 || path == "" {
		return unix.EINVAL
	}

	pathBytes, err := unix.ByteSliceFromString(path)
	if err != nil {
		return err
	}
	attr := &ObjPinAttr{
		Pathname:  uint64(addr(pathBytes)),
		BPFFD:     uint32(fd),
		FileFlags: fileFlags,
	}
	err = BPF(BPF_OBJ_PIN, attr.Marshal())
	runtime.KeepAlive(pathBytes)
	return err
}

// MapLookupElem calls BPF_MAP_LOOKUP_ELEM and copies the map value into value.
//
// key and value are the raw key and value buffers. value must be at least the
// map value size: the kernel writes that many bytes into it. An empty key
// passes a NULL key address, which a map without keys, such as a queue,
// stack or bloom filter, takes. The slices are kept alive until the syscall
// returns.
func MapLookupElem(fd int, key, value []byte, flags uint64) error {
	if fd < 0 || len(value) == 0 {
		return unix.EINVAL
	}

	attr := &MapElemAttr{
		MapFD: uint32(fd),
		Key:   uint64(addr(key)),
		Value: uint64(addr(value)),
		Flags: flags,
	}
	err := BPF(BPF_MAP_LOOKUP_ELEM, attr.Marshal())
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

// MapUpdateElem calls BPF_MAP_UPDATE_ELEM and copies value into the map.
//
// flags is one of BPF_ANY, BPF_NOEXIST or BPF_EXIST, possibly with other
// BPF_F_* bits. An empty key passes a NULL key address, as for
// MapLookupElem. The slices are kept alive until the syscall returns.
func MapUpdateElem(fd int, key, value []byte, flags uint64) error {
	if fd < 0 || len(value) == 0 {
		return unix.EINVAL
	}

	attr := &MapElemAttr{
		MapFD: uint32(fd),
		Key:   uint64(addr(key)),
		Value: uint64(addr(value)),
		Flags: flags,
	}
	err := BPF(BPF_MAP_UPDATE_ELEM, attr.Marshal())
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

// MapFreeze calls BPF_MAP_FREEZE. After it succeeds, user space can no longer
// update or delete the map's elements; programs keep the access the map flags
// give them.
func MapFreeze(fd int) error {
	if fd < 0 {
		return unix.EINVAL
	}
	attr := &MapFreezeAttr{MapFD: uint32(fd)}
	return BPF(BPF_MAP_FREEZE, attr.Marshal())
}

// MapDeleteElem calls BPF_MAP_DELETE_ELEM and removes key from the map.
//
// The value address is NULL, as the command does not read one. An empty key
// passes a NULL key address, as for MapLookupElem. key is kept alive until
// the syscall returns.
func MapDeleteElem(fd int, key []byte, flags uint64) error {
	if fd < 0 {
		return unix.EINVAL
	}

	attr := &MapElemAttr{
		MapFD: uint32(fd),
		Key:   uint64(addr(key)),
		Flags: flags,
	}
	err := BPF(BPF_MAP_DELETE_ELEM, attr.Marshal())
	runtime.KeepAlive(key)
	return err
}

// MapLookupAndDeleteElem calls BPF_MAP_LOOKUP_AND_DELETE_ELEM, which copies
// the value for key into value and removes the element.
//
// value must be at least the size the kernel writes, as for MapLookupElem.
// An empty key passes a NULL key address, which pops the next element of a
// queue or stack map. The slices are kept alive until the syscall returns.
func MapLookupAndDeleteElem(fd int, key, value []byte, flags uint64) error {
	if fd < 0 || len(value) == 0 {
		return unix.EINVAL
	}

	attr := &MapElemAttr{
		MapFD: uint32(fd),
		Key:   uint64(addr(key)),
		Value: uint64(addr(value)),
		Flags: flags,
	}
	err := BPF(BPF_MAP_LOOKUP_AND_DELETE_ELEM, attr.Marshal())
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	return err
}

// MapGetNextKey calls BPF_MAP_GET_NEXT_KEY and copies the key that follows
// key into nextKey.
//
// nextKey must be at least the map key size. An empty key passes a NULL key
// address, which asks for the first key. The kernel returns ENOENT after the
// last key. The slices are kept alive until the syscall returns.
func MapGetNextKey(fd int, key, nextKey []byte) error {
	if fd < 0 || len(nextKey) == 0 {
		return unix.EINVAL
	}

	attr := &MapNextKeyAttr{
		MapFD:   uint32(fd),
		Key:     uint64(addr(key)),
		NextKey: uint64(addr(nextKey)),
	}
	err := BPF(BPF_MAP_GET_NEXT_KEY, attr.Marshal())
	runtime.KeepAlive(key)
	runtime.KeepAlive(nextKey)
	return err
}
