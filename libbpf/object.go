// SPDX-License-Identifier: LGPL-2.1-only
// Ported from libbpf src/libbpf.c at 4f05fb0.

package libbpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"github.com/golbpfgo/golbpfgo/internal/btf"
	"github.com/golbpfgo/golbpfgo/internal/elf"
	"golang.org/x/sys/unix"
)

// BpfObject is an opened BPF object. It mirrors struct bpf_object.
type BpfObject struct {
	name     string
	path     string
	maps     []*BpfMap
	programs []*BpfProgram
	btf      *btf.Spec
	elf      *elf.Object
	closed   bool
}

// BpfObjectOpenOpts mirrors struct bpf_object_open_opts. Only ObjectName and
// Sz are honored by the current open path.
type BpfObjectOpenOpts struct {
	Sz uintptr

	ObjectName  *string
	RelaxedMaps bool
	PinRootPath *string

	Kconfig       *string
	BtfCustomPath *string

	KernelLogBuf   []byte
	KernelLogSize  uintptr
	KernelLogLevel uint32

	BpfTokenPath *string

	BtfModuleAllowlist []string
}

var bpfObjectOpenOptsSize = reflect.TypeOf(BpfObjectOpenOpts{}).Size()

// NewBpfObjectOpenOpts returns options with Sz set to the current size.
func NewBpfObjectOpenOpts() *BpfObjectOpenOpts {
	return &BpfObjectOpenOpts{Sz: bpfObjectOpenOptsSize}
}

// BpfObjectOpenFile opens a BPF ELF file, mirroring bpf_object__open_file()
// in libbpf src/libbpf.c.
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

// BpfObjectOpenMem opens a BPF ELF object from memory, mirroring
// bpf_object__open_mem(). libbpf derives a pointer-based default name for a
// memory buffer; this port uses "mem" unless ObjectName is set.
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

func validateOpenOpts(opts *BpfObjectOpenOpts) error {
	if opts != nil && opts.Sz != 0 && opts.Sz != bpfObjectOpenOptsSize {
		return &Error{Op: "bpf_object__open", Errno: unix.EINVAL}
	}
	return nil
}

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
	}, nil
}

func openError(path string, err error) error {
	return &Error{
		Op:    "bpf_object__open",
		Path:  path,
		Errno: unix.EINVAL,
		Log:   err.Error(),
	}
}

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

		m := &BpfMap{name: v.Name}
		if err := fillMapDef(spec, st, m); err != nil {
			return nil, fmt.Errorf("map %s: %w", v.Name, err)
		}
		maps = append(maps, m)
	}
	return maps, nil
}

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

func parsePrograms(e *elf.Object) ([]*BpfProgram, error) {
	var programs []*BpfProgram
	for _, p := range e.Programs {
		progType, attachType, ok := secDefFor(p.Name)
		if !ok {
			continue
		}
		name := programSymbol(e, p.Name)
		if name == "" {
			return nil, fmt.Errorf("section %s has no function symbol", p.Name)
		}
		programs = append(programs, &BpfProgram{
			name:               name,
			progType:           progType,
			expectedAttachType: attachType,
			sectionName:        p.Name,
			insns:              p.Insns,
			relocs:             p.Relocs,
		})
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

func objectNameFromPath(path string) string {
	base := filepath.Base(path)
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = base[:i]
	}
	return base
}

func errnoFromError(err error) syscall.Errno {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}
	return unix.EINVAL
}

// BpfObjectClose releases an object, mirroring bpf_object__close().
func BpfObjectClose(obj *BpfObject) {
	if obj == nil {
		return
	}
	obj.closed = true
	obj.maps = nil
	obj.programs = nil
	obj.btf = nil
	obj.elf = nil
}

// BpfObjectName mirrors bpf_object__name().
func BpfObjectName(obj *BpfObject) string {
	if obj == nil {
		return ""
	}
	return obj.name
}

// BpfObjectNextMap mirrors bpf_object__next_map().
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

// BpfObjectNextProgram mirrors bpf_object__next_program().
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

// BpfObjectFindMapByName mirrors bpf_object__find_map_by_name().
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

// BpfObjectFindProgramByName mirrors bpf_object__find_program_by_name().
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
