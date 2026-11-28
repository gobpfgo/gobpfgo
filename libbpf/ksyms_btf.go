// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-source: src/btf.c
// libbpf-source: src/features.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: load_module_btfs, btf_get_from_fd, btf__load_vmlinux_btf, bpf_object__load_vmlinux_btf, obj_needs_vmlinux_btf, find_ksym_btf_id, bpf_object__resolve_ksym_var_btf_id, bpf_object__resolve_ksym_func_btf_id, bpf_object__resolve_ksyms_btf_id, bpf_object_cleanup_btf, probe_module_btf, btf_find_by_name_kind

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// moduleBTF is the BTF of one kernel module, split on top of the vmlinux
// BTF, with the descriptor the loader passes to the kernel for it and its
// slot in the object's fd array, 0 until a kfunc call needs one.
type moduleBTF struct {
	spec       *btf.Spec
	name       string
	id         uint32
	fd         int
	fdArrayIdx int
}

// btfModuleNameLen is the module name buffer of the BTF info request.
const btfModuleNameLen = 64

// btfGetFromFDSize is the first raw BTF buffer btfGetFromFD offers the
// kernel; a larger BTF is read again with a buffer of its size.
const btfGetFromFDSize = 4096

// featModuleBTF is kernel module BTF, which the kernel reports with BTF
// object names.
var featModuleBTF = kernelFeature{probe: probeModuleBTF}

// probeModuleBTF reports whether the kernel names BTF objects: it loads a
// BTF with one int type and asks for its name. Module BTF arrived together
// with the name field of the BTF info.
func probeModuleBTF() bool {
	intType := btf.Type{
		NameOff:    1,
		Kind:       btf.KindInt,
		SizeOrType: 4,
		Int:        &btf.Int{Encoding: btfIntSigned<<24 | 32},
	}
	spec, err := btf.NewSpec(binary.NativeEndian, []btf.Type{{Kind: btf.KindVoid}, intType}, []byte("\x00int\x00"))
	if err != nil {
		return false
	}
	fd, err := sys.BtfLoad(spec.Raw(), nil, 0)
	if err != nil {
		return false
	}
	defer unix.Close(fd)

	_, err = sys.BtfInfoByFD(fd, nil, make([]byte, 16))
	return err == nil
}

// ksymsNeedVmlinuxBTF reports whether a typed .ksyms extern needs the kernel
// BTF to resolve.
func ksymsNeedVmlinuxBTF(obj *BpfObject) bool {
	for i := range obj.externs {
		if obj.externs[i].typ == extKsym && obj.externs[i].ksym.typeID != 0 {
			return true
		}
	}
	return false
}

// loadVmlinuxBTF reads the running kernel's BTF into obj when a typed .ksyms
// extern needs it. A kernel without /sys/kernel/btf/vmlinux returns ESRCH;
// the vmlinux image fallbacks are not searched.
func loadVmlinuxBTF(obj *BpfObject) error {
	if obj.btfVmlinux != nil || !ksymsNeedVmlinuxBTF(obj) {
		return nil
	}
	if _, err := os.Stat(vmlinuxBTFPath); err != nil {
		return &Error{
			Op:    "bpf_object__load_vmlinux_btf",
			Errno: unix.ESRCH,
			Log:   fmt.Sprintf("kernel BTF is missing at '%s', was CONFIG_DEBUG_INFO_BTF enabled?", vmlinuxBTFPath),
		}
	}
	spec, err := loadKernelBTF()
	if err != nil {
		return &Error{Op: "bpf_object__load_vmlinux_btf", Errno: errnoFromError(err), Log: err.Error()}
	}
	obj.btfVmlinux = spec
	return nil
}

// loadModuleBTFs opens the BTF of every loaded kernel module once per load
// and keeps it with its descriptor. A kernel without module BTF, or a caller
// not allowed to list BTF objects, leaves the list empty. A BTF unloaded
// while the list is read is skipped.
func loadModuleBTFs(obj *BpfObject) error {
	if obj.btfModulesLoaded {
		return nil
	}
	obj.btfModulesLoaded = true
	if !featModuleBTF.supported() {
		return nil
	}

	var id uint32
	for {
		next, err := sys.BtfGetNextID(id)
		if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.EPERM) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to iterate BTF objects: %w", err)
		}
		id = next

		mod, skip, err := openModuleBTF(id, obj.btfVmlinux)
		if err != nil {
			return err
		}
		if !skip {
			obj.btfModules = append(obj.btfModules, mod)
		}
	}
}

// openModuleBTF opens the BTF object id and returns it when it is a module
// BTF. skip is set for a BTF that is gone, user space BTF and vmlinux.
func openModuleBTF(id uint32, vmlinux *btf.Spec) (mod moduleBTF, skip bool, err error) {
	fd, err := sys.BtfGetFDByID(id)
	if errors.Is(err, unix.ENOENT) {
		return moduleBTF{}, true, nil
	}
	if err != nil {
		return moduleBTF{}, false, fmt.Errorf("failed to get BTF object #%d FD: %w", id, err)
	}

	info, err := sys.BtfInfoByFD(fd, nil, make([]byte, btfModuleNameLen))
	if err != nil {
		unix.Close(fd)
		return moduleBTF{}, false, fmt.Errorf("failed to get BTF object #%d info: %w", id, err)
	}
	if !info.KernelBtf || info.Name == "vmlinux" {
		unix.Close(fd)
		return moduleBTF{}, true, nil
	}

	spec, err := btfGetFromFD(fd, vmlinux)
	if err != nil {
		unix.Close(fd)
		return moduleBTF{}, false, fmt.Errorf("failed to load module [%s]'s BTF object #%d: %w", info.Name, id, err)
	}
	return moduleBTF{spec: spec, name: info.Name, id: id, fd: fd}, false, nil
}

// btfGetFromFD reads the raw BTF of the descriptor fd from the kernel and
// parses it as split BTF on top of base. See btfRawFromFD for the read.
func btfGetFromFD(fd int, base *btf.Spec) (*btf.Spec, error) {
	data, err := btfRawFromFD(fd)
	if err != nil {
		return nil, err
	}
	spec, err := btf.ParseSplit(data, binary.NativeEndian, base)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", err, unix.EINVAL)
	}
	return spec, nil
}

// btfRawFromFD reads the raw BTF of the descriptor fd from the kernel. The
// first request offers 4 KiB; a larger BTF is requested again with a buffer
// of its size, and a BTF that grew in between returns E2BIG.
func btfRawFromFD(fd int) ([]byte, error) {
	data := make([]byte, btfGetFromFDSize)
	info, err := sys.BtfInfoByFD(fd, data, nil)
	if err == nil && int(info.BtfSize) > len(data) {
		data = make([]byte, info.BtfSize)
		info, err = sys.BtfInfoByFD(fd, data, nil)
	}
	if err != nil {
		return nil, err
	}
	if int(info.BtfSize) > len(data) {
		return nil, unix.E2BIG
	}
	return data[:info.BtfSize], nil
}

// closeModuleBTFs releases the module BTFs, the vmlinux BTF and the fd
// array once the programs are loaded; the kernel keeps its own references.
func (obj *BpfObject) closeModuleBTFs() {
	for _, mod := range obj.btfModules {
		unix.Close(mod.fd)
	}
	obj.btfModules = nil
	obj.btfModulesLoaded = false
	obj.btfVmlinux = nil
	obj.fdArray = nil
}

// findByNameKind returns the first type named name of kind kind with an ID
// from start on, or 0. void is never looked up and is reported as 0 too.
func findByNameKind(spec *btf.Spec, start uint32, name string, kind btf.Kind) uint32 {
	if kind == btf.KindVoid || name == "void" {
		return 0
	}
	for id := start; ; id++ {
		t, err := spec.TypeByID(id)
		if err != nil {
			return 0
		}
		if t.Kind == kind && t.Name == name {
			return id
		}
	}
}

// findKsymBtfID returns the ID of the kernel VAR or FUNC named name: in the
// vmlinux BTF, or in the first module BTF that defines it among its own
// types. It returns the BTF it found the type in and the module, nil for
// vmlinux. A missing type is ESRCH; an error loading the module BTFs is
// returned as is.
func findKsymBtfID(obj *BpfObject, name string, kind btf.Kind) (uint32, *btf.Spec, *moduleBTF, error) {
	if id := findByNameKind(obj.btfVmlinux, 1, name, kind); id != 0 {
		return id, obj.btfVmlinux, nil, nil
	}
	if err := loadModuleBTFs(obj); err != nil {
		return 0, nil, nil, err
	}
	for i := range obj.btfModules {
		mod := &obj.btfModules[i]
		if id := findByNameKind(mod.spec, mod.spec.StartID(), name, kind); id != 0 {
			return id, mod.spec, mod, nil
		}
	}
	return 0, nil, nil, unix.ESRCH
}

// resolveKsymsBtfID resolves every typed .ksyms extern against the kernel
// BTF: a variable to its VAR, a function to its FUNC. The kernel BTF must
// have been loaded into obj.btfVmlinux; without it the result is ESRCH.
func resolveKsymsBtfID(obj *BpfObject) error {
	if obj.btfVmlinux == nil {
		return fmt.Errorf("kernel BTF is not loaded: %w", unix.ESRCH)
	}
	for i := range obj.externs {
		ext := &obj.externs[i]
		if ext.typ != extKsym || ext.ksym.typeID == 0 {
			continue
		}
		t, err := obj.btf.TypeByID(ext.btfID)
		if err != nil {
			return err
		}
		if t.Kind == btf.KindVar {
			err = resolveKsymVarBtfID(obj, ext)
		} else {
			err = resolveKsymFuncBtfID(obj, ext)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// resolveKsymVarBtfID finds the kernel VAR of the typed variable ext and
// checks that its type, after modifiers and typedefs, is compatible with the
// local one. A weak variable the kernel does not have stays unset; a strong
// one, or an incompatible type, is an error.
func resolveKsymVarBtfID(obj *BpfObject, ext *externDesc) error {
	id, kernel, mod, err := findKsymBtfID(obj, ext.name, btf.KindVar)
	if err != nil {
		if errors.Is(err, unix.ESRCH) && ext.isWeak {
			return nil
		}
		return fmt.Errorf("extern (var ksym) '%s': not found in kernel BTF: %w", ext.name, err)
	}

	targVar, err := kernel.TypeByID(id)
	if err != nil {
		return err
	}
	targType, targTypeID := skipModsAndTypedefs(kernel, targVar.SizeOrType)
	if ok, _ := btf.TypesAreCompat(obj.btf, ext.ksym.typeID, kernel, targTypeID); !ok {
		localType, _ := obj.btf.TypeByID(ext.ksym.typeID)
		return fmt.Errorf("extern (var ksym) '%s': incompatible types, expected [%d] %s %s, but kernel has [%d] %s %s: %w",
			ext.name, ext.ksym.typeID, kindName(localType), typeName(localType),
			targTypeID, kindName(targType), typeName(targType), unix.EINVAL)
	}

	ext.isSet = true
	ext.ksym.kernelBtfObjFD = 0
	if mod != nil {
		ext.ksym.kernelBtfObjFD = mod.fd
	}
	ext.ksym.kernelBtfID = id
	return nil
}

// resolveKsymFuncBtfID finds the kernel FUNC of the kfunc ext, by its name
// without a flavor suffix, and checks that its prototype is compatible with
// the local one. A weak kfunc the kernel does not have, or has with another
// prototype, stays unset. A kfunc in a module takes the next slot of the fd
// array for the module's descriptor, slot 0 standing for vmlinux.
func resolveKsymFuncBtfID(obj *BpfObject, ext *externDesc) error {
	name := ext.name
	if ext.essentName != "" {
		name = ext.essentName
	}
	id, kernel, mod, err := findKsymBtfID(obj, name, btf.KindFunc)
	if err != nil {
		if errors.Is(err, unix.ESRCH) && ext.isWeak {
			return nil
		}
		return fmt.Errorf("extern (func ksym) '%s': not found in kernel or module BTFs: %w", ext.name, err)
	}

	kernFunc, err := kernel.TypeByID(id)
	if err != nil {
		return err
	}
	if ok, _ := btf.TypesAreCompat(obj.btf, ext.ksym.typeID, kernel, kernFunc.SizeOrType); !ok {
		if ext.isWeak {
			return nil
		}
		modName := "vmlinux"
		if mod != nil {
			modName = mod.name
		}
		return fmt.Errorf("extern (func ksym) '%s': func_proto [%d] incompatible with %s [%d]: %w",
			ext.name, ext.ksym.typeID, modName, kernFunc.SizeOrType, unix.EINVAL)
	}

	if mod != nil && mod.fdArrayIdx == 0 {
		if err := addFdArraySlot(obj, mod, ext.name); err != nil {
			return err
		}
	}

	ext.isSet = true
	ext.ksym.kernelBtfID = id
	ext.ksym.btfFdIdx = 0
	ext.ksym.kernelBtfObjFD = 0
	if mod != nil {
		ext.ksym.btfFdIdx = int16(mod.fdArrayIdx)
		ext.ksym.kernelBtfObjFD = mod.fd
	}
	return nil
}

// addFdArraySlot puts the descriptor of mod into the next slot of the
// object's fd array; slot 0 stays empty for vmlinux. The slot index must fit
// the 16-bit instruction offset, so the array holds at most 32767 slots.
func addFdArraySlot(obj *BpfObject, mod *moduleBTF, extName string) error {
	if len(obj.fdArray) == math.MaxInt16 {
		return fmt.Errorf("extern (func ksym) '%s': module BTF fd index %d too big to fit in bpf_insn offset: %w",
			extName, mod.fdArrayIdx, unix.E2BIG)
	}
	if len(obj.fdArray) == 0 {
		obj.fdArray = []int32{0}
	}
	mod.fdArrayIdx = len(obj.fdArray)
	obj.fdArray = append(obj.fdArray, int32(mod.fd))
	return nil
}

// fdArrayBytes encodes the object's fd array for BPF_PROG_LOAD, or returns
// nil when no kfunc call needs it.
func fdArrayBytes(obj *BpfObject) []byte {
	if len(obj.fdArray) == 0 {
		return nil
	}
	buf := make([]byte, 0, 4*len(obj.fdArray))
	for _, fd := range obj.fdArray {
		buf = binary.NativeEndian.AppendUint32(buf, uint32(fd))
	}
	return buf
}

// kindName names the kind of t for a diagnostic, or "unknown" for nil.
func kindName(t *btf.Type) string {
	if t == nil {
		return "unknown"
	}
	return t.Kind.String()
}

// typeName returns the name of t for a diagnostic, or "" for nil.
func typeName(t *btf.Type) string {
	if t == nil {
		return ""
	}
	return t.Name
}
