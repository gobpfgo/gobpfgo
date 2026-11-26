// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__open_file, bpf_object__open_mem, bpf_object__close, bpf_object__name, bpf_object__next_map, bpf_object__next_program, bpf_object__find_map_by_name, bpf_object__find_program_by_name, bpf_object__init_maps, bpf_object_init_progs

package libbpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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
	loaded   bool
	closed   bool
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

	// Kconfig augments the kernel config used for CONFIG_ externs.
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
	return openBytes(path, data, name)
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
	return openBytes("", data, name)
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
// It requires a BPF ELF object with a .BTF section.
func openBytes(path string, data []byte, name string) (*BpfObject, error) {
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
	if err := spec.FixupDatasecSizes(sectionSizes(e)); err != nil {
		return nil, openError(path, err)
	}
	maps, err := parseMaps(spec)
	if err != nil {
		return nil, openError(path, err)
	}
	programs, err := parsePrograms(e)
	if err != nil {
		return nil, openError(path, err)
	}

	return &BpfObject{
		name:     name,
		path:     path,
		maps:     maps,
		programs: programs,
		btf:      spec,
		elf:      e,
		license:  e.License,
		btfFD:    -1,
	}, nil
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

// sectionSizes maps ELF section names to their sizes for the BTF DATASEC
// fixup.
func sectionSizes(e *elf.Object) map[string]uint32 {
	sizes := make(map[string]uint32, len(e.Sections))
	for _, s := range e.Sections {
		sizes[s.Name] = uint32(s.Size)
	}
	return sizes
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

		m := &BpfMap{name: v.Name, symbolName: v.Name, fd: -1}
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

	keyMember := spec.Member(st, "key")
	if keyMember == nil {
		return fmt.Errorf("missing key member")
	}
	if m.btfKeyTypeID, err = mapTypeID(spec, keyMember.Type); err != nil {
		return fmt.Errorf("key: %w", err)
	}
	if m.keySize, err = spec.SizeOf(m.btfKeyTypeID); err != nil {
		return fmt.Errorf("key size: %w", err)
	}

	valueMember := spec.Member(st, "value")
	if valueMember == nil {
		return fmt.Errorf("missing value member")
	}
	if m.btfValueTypeID, err = mapTypeID(spec, valueMember.Type); err != nil {
		return fmt.Errorf("value: %w", err)
	}
	if m.valueSize, err = spec.SizeOf(m.btfValueTypeID); err != nil {
		return fmt.Errorf("value size: %w", err)
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

// parsePrograms turns executable ELF sections into program specs using the SEC
// table and the function symbol that names each program.
func parsePrograms(e *elf.Object) ([]*BpfProgram, error) {
	var programs []*BpfProgram
	for _, p := range e.Programs {
		def, ok := secDefFor(p.Name)
		if !ok {
			continue
		}
		name := programSymbol(e, p.Name)
		if name == "" {
			return nil, fmt.Errorf("section %s has no function symbol", p.Name)
		}
		prog := &BpfProgram{
			name:               name,
			progType:           def.progType,
			expectedAttachType: def.attachType,
			progFlags:          def.progFlags,
			sectionName:        p.Name,
			insns:              p.Insns,
			relocs:             p.Relocs,
			fd:                 -1,
		}
		if def.attachBTF {
			prog.attachBTF = true
			prog.attachTarget = strings.TrimPrefix(p.Name, def.prefix)
		}
		programs = append(programs, prog)
	}
	return programs, nil
}

func programSymbol(e *elf.Object, section string) string {
	for _, s := range e.Symbols {
		if s.Type == elf.STT_FUNC && s.Section == section && s.Name != "" {
			return s.Name
		}
	}
	return ""
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
// invalidates its maps and programs. It is safe to call more than once and on
// a nil object.
func BpfObjectClose(obj *BpfObject) {
	if obj == nil {
		return
	}
	obj.closeLoadFDs()
	obj.closed = true
	obj.maps = nil
	obj.programs = nil
	obj.btf = nil
	obj.elf = nil
}

// closeLoadFDs closes the BTF, map and program descriptors created by
// BpfObjectLoad. It is idempotent and ignores close errors.
func (obj *BpfObject) closeLoadFDs() {
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

// BpfObjectNextMap returns the next map in the order of the .maps BTF data
// section. Pass nil to start; it returns nil after the last map. The order is
// stable for the lifetime of the object.
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

// BpfObjectNextProgram returns the next program in ELF section order. Pass nil
// to start; it returns nil after the last program.
func BpfObjectNextProgram(obj *BpfObject, prev *BpfProgram) *BpfProgram {
	if obj == nil {
		return nil
	}
	if prev == nil {
		if len(obj.programs) == 0 {
			return nil
		}
		return obj.programs[0]
	}
	for i, p := range obj.programs {
		if p == prev {
			if i+1 < len(obj.programs) {
				return obj.programs[i+1]
			}
			return nil
		}
	}
	return nil
}

// BpfObjectFindMapByName returns the map with the given name, or nil.
func BpfObjectFindMapByName(obj *BpfObject, name string) *BpfMap {
	if obj == nil {
		return nil
	}
	for _, m := range obj.maps {
		if m.name == name {
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
func BpfObjectFindProgramByName(obj *BpfObject, name string) *BpfProgram {
	if obj == nil {
		return nil
	}
	for _, p := range obj.programs {
		if p.name == name {
			return p
		}
	}
	return nil
}
