// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__open_file, bpf_object__open_mem, bpf_object__close, bpf_object__name, bpf_object__next_map, bpf_object__next_program, bpf_object__find_map_by_name, bpf_object__find_program_by_name, bpf_object_open, bpf_object__new, bpf_object__init_kversion, bpf_object__init_maps, bpf_object_init_progs, bpf_object_fixup_btf

package libbpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/elf"
	"golang.org/x/sys/unix"
)

// BpfObject is an opened BPF object. It owns the parsed ELF and BTF data and
// the map and program lists. Opening does not touch the kernel; the load step
// adds the descriptors.
type BpfObject struct {
	name     string
	path     string
	maps     []*BpfMap
	programs []*BpfProgram
	btf      *btf.Spec
	elf      *elf.Object
	license  string
	btfFD    int
	closed   bool

	// attempted is set once BpfObjectLoad starts the work that changes the
	// object, and stays set when that load fails: the object is then
	// prepared, in libbpf's terms, and cannot be loaded again. loaded is
	// set when the load succeeds.
	attempted bool
	loaded    bool

	// kernVersion is the kern_version every BPF_PROG_LOAD of the object
	// sends: the running kernel's KERNEL_VERSION code at open, or the
	// object's "version" section when it has one. Kernels since 5.0 ignore
	// it.
	kernVersion uint32

	// textShndx is the .text section index, or 0 without one. The programs
	// in it are subprograms, which the public iteration skips and the load
	// appends to the programs that call them. programs is sorted by section
	// and offset.
	textShndx int

	// externs are the extern variables, sorted as the loader resolves them.
	// kconfigMap holds the .kconfig externs' values, and kconfig is the
	// caller's extra config text from BpfObjectOpenOpts.Kconfig.
	externs    []externDesc
	kconfigMap *BpfMap
	kconfig    *string

	// btfVmlinux and btfModules are the kernel BTFs the typed .ksyms
	// externs resolve against, and fdArray the module BTF descriptors that
	// kfunc calls name by index, slot 0 standing for vmlinux. They live
	// only during BpfObjectLoad.
	btfVmlinux       *btf.Spec
	btfModules       []moduleBTF
	btfModulesLoaded bool
	fdArray          []int32

	// usdtMan is the USDT spec ID state, created by the first
	// BpfProgramAttachUsdt; usdtManErr is the error of that creation, which
	// later attaches return as well.
	usdtMan    *usdtManager
	usdtManErr error

	// funcPtrs are the pointers to .text functions in the read-only data
	// sections, sorted by section and offset; each read-only data map
	// holds the slice of its section. funcPtrMaps are the per-program
	// copies of those maps that the load creates for programs with callx.
	// They are not object maps and are closed with the object.
	funcPtrs    []funcPtr
	funcPtrMaps []funcPtrMap
}

// BpfObjectOpenOpts controls how an object is opened. Zero is the default.
//
// Only Sz, ObjectName and the fields used by the current open path take
// effect. The remaining fields are accepted so a caller can share one options
// value with the loader as it is ported.
type BpfObjectOpenOpts struct {
	// Sz is the layout size for forward compatibility. Set it with
	// NewBpfObjectOpenOpts; zero means the current layout.
	Sz uintptr

	// ObjectName overrides the object name. When nil, the name comes from
	// the file basename up to the first dot.
	ObjectName *string
	// RelaxedMaps allows extra map definition fields. The current parser is
	// strict.
	RelaxedMaps bool
	// PinRootPath is the base directory for maps that request pinning.
	PinRootPath *string

	// Kconfig is extra kernel config text for the CONFIG_ externs of the
	// .kconfig section, in the /boot/config format: one CONFIG_NAME=value
	// per line, where the value is y, n or m, a quoted string or an
	// integer. The load step reads it before the system config, and an
	// extern takes the first value it sees. When it sets every CONFIG_
	// extern, the system config is not read. The text is copied at open.
	Kconfig *string
	// BtfCustomPath supplies a custom BTF for CO-RE relocations.
	BtfCustomPath *string

	// KernelLogBuf receives kernel logs during load.
	KernelLogBuf []byte
	// KernelLogSize is the length of KernelLogBuf.
	KernelLogSize uintptr
	// KernelLogLevel requests verifier log verbosity.
	KernelLogLevel uint32

	// BpfTokenPath is the BPF filesystem path used to derive a token.
	BpfTokenPath *string

	// BtfModuleAllowlist limits the kernel module BTFs consulted for CO-RE.
	BtfModuleAllowlist []string
}

var bpfObjectOpenOptsSize = reflect.TypeOf(BpfObjectOpenOpts{}).Size()

// NewBpfObjectOpenOpts returns options with Sz set to the current layout.
func NewBpfObjectOpenOpts() *BpfObjectOpenOpts {
	return &BpfObjectOpenOpts{Sz: bpfObjectOpenOptsSize}
}

// BpfObjectOpenFile reads a BPF ELF object from path and returns it with its
// maps and programs described. It parses the ELF sections, the BTF types and
// the BTF-defined map definitions; it does not load anything into the kernel.
//
// The object name is the file basename up to the first dot, unless
// opts.ObjectName overrides it. opts may be nil. The caller must call
// BpfObjectClose when done.
//
// The current parser requires a 64-bit BPF ELF object with a .BTF section and
// BTF-defined maps. A malformed object returns an *Error with EINVAL.
func BpfObjectOpenFile(path string, opts *BpfObjectOpenOpts) (*BpfObject, error) {
	if path == "" {
		return nil, &Error{Op: "bpf_object__open_file", Errno: unix.EINVAL}
	}
	if err := validateOpenOpts(opts); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, &Error{
			Op:    "bpf_object__open_file",
			Path:  path,
			Errno: errnoFromError(err),
			Log:   err.Error(),
		}
	}

	name := objectNameFromPath(path)
	if opts != nil && opts.ObjectName != nil {
		name = *opts.ObjectName
	}
	return openBytes(path, data, name, opts)
}

// BpfObjectOpenMem parses a BPF ELF object from data. The object name is
// "mem" unless opts.ObjectName is set. The caller must call BpfObjectClose.
//
// libbpf uses a pointer-based default name for memory buffers; gobpfgo uses
// a stable name so diagnostics and pin paths are reproducible.
func BpfObjectOpenMem(data []byte, opts *BpfObjectOpenOpts) (*BpfObject, error) {
	if len(data) == 0 {
		return nil, &Error{Op: "bpf_object__open_mem", Errno: unix.EINVAL}
	}
	if err := validateOpenOpts(opts); err != nil {
		return nil, err
	}

	name := "mem"
	if opts != nil && opts.ObjectName != nil {
		name = *opts.ObjectName
	}
	return openBytes("", data, name, opts)
}

// validateOpenOpts rejects an options value whose Sz does not match the
// current layout. A nil or zero-Sz value is accepted.
func validateOpenOpts(opts *BpfObjectOpenOpts) error {
	if opts != nil && opts.Sz != 0 && opts.Sz != bpfObjectOpenOptsSize {
		return &Error{Op: "bpf_object__open", Errno: unix.EINVAL}
	}
	return nil
}

// openBytes parses data and builds the object for the file and memory paths.
// It requires a BPF ELF object with a .BTF section. opts may be nil.
func openBytes(path string, data []byte, name string, opts *BpfObjectOpenOpts) (*BpfObject, error) {
	e, err := elf.OpenBytes(data)
	if err != nil {
		return nil, openError(path, err)
	}
	if e.Machine != elf.EM_BPF {
		return nil, openError(path, fmt.Errorf("machine %v is not EM_BPF", e.Machine))
	}
	if len(e.BTF) == 0 {
		return nil, openError(path, fmt.Errorf("missing .BTF section"))
	}

	spec, err := btf.Parse(e.BTF, e.ByteOrder)
	if err != nil {
		return nil, openError(path, err)
	}
	externs, err := collectExterns(e, spec)
	if err != nil {
		return nil, withPath(err, path)
	}
	if err := fixupObjectBTF(e, spec); err != nil {
		return nil, openError(path, err)
	}
	maps, err := parseMaps(spec)
	if err != nil {
		return nil, openError(path, err)
	}
	maps = append(maps, initGlobalDataMaps(e, spec, name)...)
	kconfigMap := initKconfigMap(spec, name, externs, symtabIndex(e))
	if kconfigMap != nil {
		maps = append(maps, kconfigMap)
	}
	programs, textShndx, err := parsePrograms(e)
	if err != nil {
		return nil, withPath(err, path)
	}
	funcPtrs, err := collectFuncPtrs(e, textShndx)
	if err != nil {
		return nil, openError(path, err)
	}
	assignFuncPtrs(maps, funcPtrs)
	kernVersion, err := objectKernVersion(e, getKernelVersion())
	if err != nil {
		return nil, withPath(err, path)
	}

	obj := &BpfObject{
		name:        name,
		path:        path,
		maps:        maps,
		programs:    programs,
		textShndx:   textShndx,
		btf:         spec,
		elf:         e,
		license:     e.License,
		btfFD:       -1,
		kernVersion: kernVersion,
		externs:     externs,
		kconfigMap:  kconfigMap,
		funcPtrs:    funcPtrs,
	}
	for _, p := range programs {
		p.obj = obj
	}
	for _, m := range maps {
		m.obj = obj
	}
	if opts != nil && opts.Kconfig != nil {
		kconfig := *opts.Kconfig
		obj.kconfig = &kconfig
	}
	return obj, nil
}

// objectKernVersion returns the kernel version the programs of e are loaded
// with: running, the running kernel's KERNEL_VERSION code, unless e has a
// section named "version", whose 4-byte value in host byte order replaces
// it. A "version" section of any other size, or without data, is
// LIBBPF_ERRNO__FORMAT. With several such sections the last one wins.
func objectKernVersion(e *elf.Object, running uint32) (uint32, error) {
	version := running
	for _, sec := range e.Sections {
		if sec.Name != "version" {
			continue
		}
		if len(sec.Data) != 4 {
			return 0, &Error{Op: "bpf_object__open", Errno: libbpfErrnoFormat, Log: "invalid kver section"}
		}
		version = binary.NativeEndian.Uint32(sec.Data)
	}
	return version, nil
}

// withPath sets the object path on an open error that is already an *Error.
func withPath(err error, path string) error {
	var e *Error
	if errors.As(err, &e) {
		e.Path = path
		return e
	}
	return openError(path, err)
}

// openError wraps a parse failure in the public Error type. The current parser
// reports malformed objects as EINVAL with the parser reason in Log.
func openError(path string, err error) error {
	return &Error{
		Op:    "bpf_object__open",
		Path:  path,
		Errno: unix.EINVAL,
		Log:   err.Error(),
	}
}

// fixupObjectBTF fills in what the compiler leaves out of the DATASECs: the
// section sizes and the global variable offsets from the ELF. Global variables
// with hidden or internal visibility become static, and each DATASEC's
// variables are sorted by offset.
func fixupObjectBTF(e *elf.Object, spec *btf.Spec) error {
	syms := varSymbols(e)
	if err := spec.FixupDatasecSizes(sectionSizes(e)); err != nil {
		return err
	}
	if err := spec.FixupDatasecOffsets(variableOffsets(syms)); err != nil {
		return err
	}
	if err := spec.FixupDatasecHiddenVars(hiddenVariables(syms)); err != nil {
		return err
	}
	return spec.SortDatasecVars()
}

// sectionSizes maps ELF section names to their sizes for the BTF DATASEC
// fixup.
func sectionSizes(e *elf.Object) map[string]uint32 {
	sizes := make(map[string]uint32, len(e.Sections))
	for _, s := range e.Sections {
		sizes[s.Name] = uint32(s.Size)
	}
	return sizes
}

// variableOffsets maps the global and weak object symbol names to their
// offsets in the object, for the BTF DATASEC fixup.
func variableOffsets(syms map[string]elf.Symbol) map[string]uint32 {
	offsets := make(map[string]uint32, len(syms))
	for name, sym := range syms {
		offsets[name] = uint32(sym.Value)
	}
	return offsets
}

// parseMaps turns the .maps BTF data section into map specs. Each variable's
// struct members encode the map type, sizes and key and value types.
func parseMaps(spec *btf.Spec) ([]*BpfMap, error) {
	ds := spec.Find(".maps", btf.KindDatasec)
	if ds == nil {
		return nil, nil
	}

	var maps []*BpfMap
	for _, vs := range ds.DataSec {
		v, err := spec.TypeByID(vs.Type)
		if err != nil {
			return nil, err
		}
		if v.Kind != btf.KindVar {
			return nil, fmt.Errorf(".maps entry %d has kind %v, want var", vs.Type, v.Kind)
		}

		st, err := spec.TypeByID(v.SizeOrType)
		if err != nil {
			return nil, err
		}
		if st.Kind != btf.KindStruct {
			return nil, fmt.Errorf("map %s has kind %v, want struct", v.Name, st.Kind)
		}

		m := &BpfMap{name: v.Name, symbolName: v.Name, autocreate: true, fd: -1}
		if err := fillMapDef(spec, st, m); err != nil {
			return nil, fmt.Errorf("map %s: %w", v.Name, err)
		}
		maps = append(maps, m)
	}
	return maps, nil
}

// fillMapDef reads the type, max_entries, key, value and optional map_flags
// members from a BTF map definition.
func fillMapDef(spec *btf.Spec, st *btf.Type, m *BpfMap) error {
	typeMember := spec.Member(st, "type")
	if typeMember == nil {
		return fmt.Errorf("missing type member")
	}
	v, err := mapUintValue(spec, typeMember.Type)
	if err != nil {
		return fmt.Errorf("type: %w", err)
	}
	m.mapType = BpfMapType(v)

	maxMember := spec.Member(st, "max_entries")
	if maxMember == nil {
		return fmt.Errorf("missing max_entries member")
	}
	if v, err = mapUintValue(spec, maxMember.Type); err != nil {
		return fmt.Errorf("max_entries: %w", err)
	}
	m.maxEntries = v

	// Map types such as ringbuf and queue have no key or value. The kernel
	// rejects a missing key or value where the type requires one.
	if keyMember := spec.Member(st, "key"); keyMember != nil {
		if m.btfKeyTypeID, err = mapTypeID(spec, keyMember.Type); err != nil {
			return fmt.Errorf("key: %w", err)
		}
		if m.keySize, err = spec.SizeOf(m.btfKeyTypeID); err != nil {
			return fmt.Errorf("key size: %w", err)
		}
	}

	if valueMember := spec.Member(st, "value"); valueMember != nil {
		if m.btfValueTypeID, err = mapTypeID(spec, valueMember.Type); err != nil {
			return fmt.Errorf("value: %w", err)
		}
		if m.valueSize, err = spec.SizeOf(m.btfValueTypeID); err != nil {
			return fmt.Errorf("value size: %w", err)
		}
	}

	// Maps that store descriptors or raw values declare key_size and
	// value_size instead of BTF key and value types.
	if keySize := spec.Member(st, "key_size"); keySize != nil {
		if v, err = mapUintValue(spec, keySize.Type); err != nil {
			return fmt.Errorf("key_size: %w", err)
		}
		if m.keySize != 0 && m.keySize != v {
			return fmt.Errorf("conflicting key size %d != %d", m.keySize, v)
		}
		m.keySize = v
	}
	if valueSize := spec.Member(st, "value_size"); valueSize != nil {
		if v, err = mapUintValue(spec, valueSize.Type); err != nil {
			return fmt.Errorf("value_size: %w", err)
		}
		if m.valueSize != 0 && m.valueSize != v {
			return fmt.Errorf("conflicting value size %d != %d", m.valueSize, v)
		}
		m.valueSize = v
	}

	if !mapTakesBTF(m.mapType) {
		m.btfKeyTypeID = 0
		m.btfValueTypeID = 0
	}

	if flags := spec.Member(st, "map_flags"); flags != nil {
		if v, err = mapUintValue(spec, flags.Type); err != nil {
			return fmt.Errorf("map_flags: %w", err)
		}
		m.mapFlags = v
	}

	return nil
}

func mapUintValue(spec *btf.Spec, id uint32) (uint32, error) {
	t, err := spec.TypeByID(id)
	if err != nil {
		return 0, err
	}
	if t.Kind != btf.KindPtr {
		return 0, fmt.Errorf("kind %v, want ptr", t.Kind)
	}
	a, err := spec.TypeByID(t.SizeOrType)
	if err != nil {
		return 0, err
	}
	if a.Kind != btf.KindArray || a.Array == nil {
		return 0, fmt.Errorf("kind %v, want array", a.Kind)
	}
	return a.Array.Nelems, nil
}

func mapTypeID(spec *btf.Spec, id uint32) (uint32, error) {
	t, err := spec.TypeByID(id)
	if err != nil {
		return 0, err
	}
	if t.Kind != btf.KindPtr {
		return 0, fmt.Errorf("kind %v, want ptr", t.Kind)
	}
	return t.SizeOrType, nil
}

// objectNameFromPath derives the object name from the base name up to the
// first dot, matching libbpf's file-name rule.
func objectNameFromPath(path string) string {
	base := filepath.Base(path)
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	return base
}

// errnoFromError extracts a syscall errno from an os or fs error.
func errnoFromError(err error) syscall.Errno {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}
	return unix.EINVAL
}

// BpfObjectClose releases the object, closes any loaded descriptors and
// invalidates its maps and programs. A map's initial value is released too,
// so BpfMapInitialValue returns nil for it afterwards. It is safe to call
// more than once and on a nil object.
func BpfObjectClose(obj *BpfObject) {
	if obj == nil {
		return
	}
	obj.closeLoadFDs()
	for _, m := range obj.maps {
		m.initialValue = nil
	}
	obj.closed = true
	obj.maps = nil
	obj.programs = nil
	obj.btf = nil
	obj.elf = nil
	obj.externs = nil
	obj.kconfigMap = nil
	obj.usdtMan = nil
	obj.usdtManErr = nil
	obj.funcPtrs = nil
}

// closeLoadFDs closes the BTF, map and program descriptors created by
// BpfObjectLoad, including the programs' copies of the maps with function
// pointers. It is idempotent and ignores close errors.
func (obj *BpfObject) closeLoadFDs() {
	obj.closeModuleBTFs()
	obj.closeFuncPtrMaps()
	if obj.btfFD >= 0 {
		unix.Close(obj.btfFD)
		obj.btfFD = -1
	}
	for _, m := range obj.maps {
		if m.fd >= 0 {
			unix.Close(m.fd)
			m.fd = -1
		}
	}
	for _, p := range obj.programs {
		if p.fd >= 0 {
			unix.Close(p.fd)
			p.fd = -1
		}
	}
}

// BpfObjectName returns the object name used in diagnostics and pin paths.
func BpfObjectName(obj *BpfObject) string {
	if obj == nil {
		return ""
	}
	return obj.name
}

// BpfObjectNextMap returns the next map. The maps defined in the .maps BTF
// data section come first, in their declaration order, followed by the global
// data maps in ELF section order and then the .kconfig map. Pass nil to
// start; it returns nil after the last map. The order is stable for the
// lifetime of the object.
func BpfObjectNextMap(obj *BpfObject, prev *BpfMap) *BpfMap {
	if obj == nil {
		return nil
	}
	if prev == nil {
		if len(obj.maps) == 0 {
			return nil
		}
		return obj.maps[0]
	}
	for i, m := range obj.maps {
		if m == prev {
			if i+1 < len(obj.maps) {
				return obj.maps[i+1]
			}
			return nil
		}
	}
	return nil
}

// BpfObjectNextProgram returns the next program, in ELF section order and,
// within a section, in function order. Subprograms are skipped, because they
// are loaded only as part of the programs that call them. Pass nil to start;
// it returns nil after the last program.
func BpfObjectNextProgram(obj *BpfObject, prev *BpfProgram) *BpfProgram {
	if obj == nil {
		return nil
	}
	start := 0
	if prev != nil {
		i := slices.Index(obj.programs, prev)
		if i < 0 {
			return nil
		}
		start = i + 1
	}
	for _, p := range obj.programs[start:] {
		if !progIsSubprog(obj, p) {
			return p
		}
	}
	return nil
}

// BpfObjectFindMapByName returns the map with the given name, or nil.
//
// A name that starts with a dot is a section name: it finds the internal map
// of that section, such as ".data", ".rodata" or ".kconfig". Any other name
// must match the name BpfMapName returns, for example "counts" or the kernel
// name of an internal map such as "my_objec.data".
func BpfObjectFindMapByName(obj *BpfObject, name string) *BpfMap {
	if obj == nil {
		return nil
	}
	for _, m := range obj.maps {
		if strings.HasPrefix(name, ".") {
			if m.realName == name {
				return m
			}
			continue
		}
		if BpfMapName(m) == name {
			return m
		}
	}
	return nil
}

// findMapBySymbol returns the map whose ELF symbol matches, independent of a
// name changed by BpfMapReuseFD.
func findMapBySymbol(obj *BpfObject, symbol string) *BpfMap {
	if obj == nil {
		return nil
	}
	for _, m := range obj.maps {
		if m.symbolName == symbol {
			return m
		}
	}
	return nil
}

// BpfObjectFindProgramByName returns the program with the exact name, or nil.
// Subprograms are not found.
func BpfObjectFindProgramByName(obj *BpfObject, name string) *BpfProgram {
	if obj == nil {
		return nil
	}
	for _, p := range obj.programs {
		if !progIsSubprog(obj, p) && p.name == name {
			return p
		}
	}
	return nil
}
