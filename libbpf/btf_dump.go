// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/btf_dump.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: btf_dump__new, btf_dump__free, btf_dump__dump_type, btf_dump_resize, btf_dump_mark_referenced, btf_dump_order_type, btf_dump_emit_type

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"fmt"
	"sort"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

// BtfDumpPrintFunc receives one formatted chunk of the dump. It mirrors the C
// printf callback: the dumper owns the format string and the caller formats
// the arguments.
type BtfDumpPrintFunc func(format string, args ...any)

// BtfDumpOpts are the options of BtfDumpNew. The C library has only a size
// field; the Go API takes the struct as is.
type BtfDumpOpts struct{}

// dumpOrderState is the topological sort state of a type.
type dumpOrderState uint8

const (
	dumpOrderNone dumpOrderState = iota
	dumpOrdering
	dumpOrdered
)

// dumpEmitState is the definition emission state of a type.
type dumpEmitState uint8

const (
	dumpEmitNone dumpEmitState = iota
	dumpEmitting
	dumpEmitted
)

// dumpTypeState is the per-type state from the C library's
// btf_dump_type_aux_state.
type dumpTypeState struct {
	order        dumpOrderState
	emit         dumpEmitState
	fwdEmitted   bool
	nameResolved bool
	referenced   bool
}

// dumpDeclTag is one BTF_KIND_DECL_TAG sorted by target and tag id.
type dumpDeclTag struct {
	targetID uint32
	tagID    uint32
}

// BtfDump emits C declarations from a BTF type table. It caches which types
// were already emitted, so a caller can dump selected types and get only the
// dependencies that are still missing.
type BtfDump struct {
	btf    *btf.Spec
	printf BtfDumpPrintFunc
	ptrSz  int

	stripMods    bool
	skipAnonDefs bool
	lastID       int
	freed        bool

	states      []dumpTypeState
	cachedNames []string
	declTags    []dumpDeclTag

	emitQueue []uint32
	declStack []uint32

	typeNames  map[string]int
	identNames map[string]int
}

// BtfDumpNew creates a dumper for b.
func BtfDumpNew(b *Btf, printf BtfDumpPrintFunc, opts *BtfDumpOpts) (*BtfDump, error) {
	spec, err := b.btfSpec()
	if err != nil {
		return nil, err
	}
	if printf == nil {
		return nil, &Error{Op: "btf_dump__new", Errno: unix.EINVAL}
	}

	return &BtfDump{
		btf:        spec,
		printf:     printf,
		ptrSz:      8,
		typeNames:  make(map[string]int),
		identNames: make(map[string]int),
	}, nil
}

// BtfDumpFree releases the dumper. It is nil-safe and idempotent.
func BtfDumpFree(d *BtfDump) {
	if d == nil {
		return
	}
	d.freed = true
	d.btf = nil
	d.states = nil
	d.cachedNames = nil
	d.declTags = nil
	d.emitQueue = nil
	d.declStack = nil
	d.typeNames = nil
	d.identNames = nil
}

// BtfDumpDumpType emits the C definition of id and every dependent type that
// has not been emitted yet.
func BtfDumpDumpType(d *BtfDump, id uint32) error {
	if d == nil || d.freed || d.btf == nil || int(id) >= len(d.btf.Types) {
		return &Error{Op: "btf_dump__dump_type", Errno: unix.EINVAL}
	}
	if err := d.resize(); err != nil {
		return &Error{Op: "btf_dump__dump_type", Errno: errnoFromError(err), Log: err.Error()}
	}

	d.emitQueue = d.emitQueue[:0]
	if _, err := d.orderType(id, false); err != nil {
		return &Error{Op: "btf_dump__dump_type", Errno: unix.ELOOP, Log: err.Error()}
	}
	for _, queued := range d.emitQueue {
		d.emitType(queued, 0)
	}
	return nil
}

// resize grows the per-type state to cover the whole table and collects the
// declaration tags once.
func (d *BtfDump) resize() error {
	lastID := len(d.btf.Types) - 1
	if lastID <= d.lastID {
		return nil
	}

	if len(d.states) < lastID+1 {
		states := make([]dumpTypeState, lastID+1)
		copy(states, d.states)
		d.states = states
		cached := make([]string, lastID+1)
		copy(cached, d.cachedNames)
		d.cachedNames = cached
	}
	if d.lastID == 0 && len(d.states) > 0 {
		d.states[0].order = dumpOrdered
		d.states[0].emit = dumpEmitted
	}

	tagCount := len(d.declTags)
	for id := d.lastID + 1; id <= lastID; id++ {
		t := &d.btf.Types[id]
		if err := d.markReferenced(t); err != nil {
			d.declTags = d.declTags[:tagCount]
			return err
		}
		if t.Kind == btf.KindDeclTag {
			d.declTags = append(d.declTags, dumpDeclTag{targetID: t.SizeOrType, tagID: t.ID})
		}
	}
	if len(d.declTags) != tagCount {
		sort.Slice(d.declTags, func(i, j int) bool {
			if d.declTags[i].targetID != d.declTags[j].targetID {
				return d.declTags[i].targetID < d.declTags[j].targetID
			}
			return d.declTags[i].tagID < d.declTags[j].tagID
		})
	}

	d.lastID = lastID
	return nil
}

// markReferenced marks every type referenced by t, so a top-level anonymous
// enum can be distinguished from one embedded in a struct field.
func (d *BtfDump) markReferenced(t *btf.Type) error {
	mark := func(id uint32) {
		if int(id) < len(d.states) {
			d.states[id].referenced = true
		}
	}

	switch t.Kind {
	case btf.KindInt, btf.KindEnum, btf.KindEnum64, btf.KindFwd, btf.KindFloat:
		return nil
	case btf.KindVolatile, btf.KindConst, btf.KindRestrict, btf.KindPtr,
		btf.KindTypedef, btf.KindFunc, btf.KindVar, btf.KindDeclTag, btf.KindTypeTag:
		mark(t.SizeOrType)
	case btf.KindArray:
		if t.Array != nil {
			mark(t.Array.IndexType)
			mark(t.Array.Type)
		}
	case btf.KindStruct, btf.KindUnion:
		for _, member := range t.Members {
			mark(member.Type)
		}
	case btf.KindFuncProto:
		mark(t.SizeOrType)
		for _, param := range t.Params {
			mark(param.Type)
		}
	case btf.KindDatasec:
		for _, variable := range t.DataSec {
			mark(variable.Type)
		}
	default:
		return fmt.Errorf("btf: dump: unsupported kind %v", t.Kind)
	}
	return nil
}

// addEmitQueue appends a type to the emission queue.
func (d *BtfDump) addEmitQueue(id uint32) {
	d.emitQueue = append(d.emitQueue, id)
}

// orderType topologically orders the definitions id depends on. It returns
// true for a strong link, false when a forward declaration is enough, and an
// error for an unsatisfiable cycle.
func (d *BtfDump) orderType(id uint32, throughPtr bool) (bool, error) {
	state := &d.states[id]
	if state.order == dumpOrdered {
		return true, nil
	}

	t := &d.btf.Types[id]
	if state.order == dumpOrdering {
		if isComposite(t) && throughPtr && t.NameOff != 0 {
			return false, nil
		}
		return false, fmt.Errorf("unsatisfiable type cycle, id:[%d]", id)
	}

	switch t.Kind {
	case btf.KindInt, btf.KindFloat:
		state.order = dumpOrdered
		return false, nil
	case btf.KindPtr:
		strong, err := d.orderType(t.SizeOrType, true)
		state.order = dumpOrdered
		return strong, err
	case btf.KindArray:
		if t.Array == nil {
			return false, fmt.Errorf("btf: dump: type %d has no array payload", id)
		}
		return d.orderType(t.Array.Type, false)
	case btf.KindStruct, btf.KindUnion:
		if throughPtr && t.NameOff != 0 {
			return false, nil
		}
		state.order = dumpOrdering
		for _, member := range t.Members {
			if _, err := d.orderType(member.Type, false); err != nil {
				return false, err
			}
		}
		if t.NameOff != 0 {
			d.addEmitQueue(id)
		}
		state.order = dumpOrdered
		return true, nil
	case btf.KindEnum, btf.KindEnum64, btf.KindFwd:
		if t.NameOff != 0 || !state.referenced {
			d.addEmitQueue(id)
		}
		state.order = dumpOrdered
		return true, nil
	case btf.KindTypedef:
		strong, err := d.orderType(t.SizeOrType, throughPtr)
		if err != nil {
			return false, err
		}
		if throughPtr && !strong {
			return false, nil
		}
		d.addEmitQueue(id)
		state.order = dumpOrdered
		return true, nil
	case btf.KindVolatile, btf.KindConst, btf.KindRestrict, btf.KindTypeTag:
		return d.orderType(t.SizeOrType, throughPtr)
	case btf.KindFuncProto:
		strong, err := d.orderType(t.SizeOrType, throughPtr)
		if err != nil {
			return false, err
		}
		for _, param := range t.Params {
			paramStrong, err := d.orderType(param.Type, throughPtr)
			if err != nil {
				return false, err
			}
			strong = strong || paramStrong
		}
		return strong, nil
	case btf.KindFunc, btf.KindVar, btf.KindDatasec, btf.KindDeclTag:
		state.order = dumpOrdered
		return false, nil
	default:
		return false, fmt.Errorf("btf: dump: unsupported kind %v", t.Kind)
	}
}

// emitType emits the definition of id when the kind has one, and the forward
// declarations its members need. contID is the containing struct or union.
func (d *BtfDump) emitType(id, contID uint32) {
	state := &d.states[id]
	if state.emit == dumpEmitted {
		return
	}

	t := &d.btf.Types[id]
	topLevel := contID == 0

	if state.emit == dumpEmitting {
		if state.fwdEmitted {
			return
		}
		switch t.Kind {
		case btf.KindStruct, btf.KindUnion:
			if id == contID {
				return
			}
			if t.NameOff == 0 {
				return
			}
			d.emitStructFwd(id, t)
			d.print(";\n\n")
			state.fwdEmitted = true
		case btf.KindTypedef:
			if !d.blacklisted(id) {
				d.emitTypedefDef(id, t, 0)
				d.print(";\n\n")
			}
			state.fwdEmitted = true
		}
		return
	}

	switch t.Kind {
	case btf.KindInt:
		d.emitMissingAliases(id, t)
		state.emit = dumpEmitted
	case btf.KindEnum, btf.KindEnum64:
		if topLevel {
			d.emitEnumDef(id, t, 0)
			d.print(";\n\n")
		}
		state.emit = dumpEmitted
	case btf.KindPtr, btf.KindVolatile, btf.KindConst, btf.KindRestrict, btf.KindTypeTag:
		d.emitType(t.SizeOrType, contID)
	case btf.KindArray:
		if t.Array != nil {
			d.emitType(t.Array.Type, contID)
		}
	case btf.KindFwd:
		d.emitFwdDef(id, t)
		d.print(";\n\n")
		state.emit = dumpEmitted
	case btf.KindTypedef:
		state.emit = dumpEmitting
		d.emitType(t.SizeOrType, id)
		if !state.fwdEmitted && !d.blacklisted(id) {
			d.emitTypedefDef(id, t, 0)
			d.print(";\n\n")
		}
		state.emit = dumpEmitted
	case btf.KindStruct, btf.KindUnion:
		state.emit = dumpEmitting
		if topLevel || t.NameOff == 0 {
			newContID := contID
			if t.NameOff != 0 {
				newContID = id
			}
			for _, member := range t.Members {
				d.emitType(member.Type, newContID)
			}
		} else if !state.fwdEmitted && id != contID {
			d.emitStructFwd(id, t)
			d.print(";\n\n")
			state.fwdEmitted = true
		}
		if topLevel {
			d.emitStructDef(id, t, 0)
			d.print(";\n\n")
			state.emit = dumpEmitted
		} else {
			state.emit = dumpEmitNone
		}
	case btf.KindFuncProto:
		d.emitType(t.SizeOrType, contID)
		for _, param := range t.Params {
			d.emitType(param.Type, contID)
		}
	}
}

func (d *BtfDump) print(format string, args ...any) {
	d.printf(format, args...)
}

func (d *BtfDump) blacklisted(id uint32) bool {
	t := &d.btf.Types[id]
	return t.NameOff != 0 && t.Name == "__builtin_va_list"
}

func isComposite(t *btf.Type) bool {
	return t.Kind == btf.KindStruct || t.Kind == btf.KindUnion
}

func isMod(t *btf.Type) bool {
	return t.Kind == btf.KindVolatile || t.Kind == btf.KindConst ||
		t.Kind == btf.KindRestrict || t.Kind == btf.KindTypeTag
}

func isArray(t *btf.Type) bool { return t.Kind == btf.KindArray }
func isEnum(t *btf.Type) bool  { return t.Kind == btf.KindEnum }

// missingBaseTypes aliases GCC internal vector types to standard C types.
var missingBaseTypes = [][2]string{
	{"__Poly8_t", "unsigned char"},
	{"__Poly16_t", "unsigned short"},
	{"__Poly64_t", "unsigned long long"},
	{"__Poly128_t", "unsigned __int128"},
}

func (d *BtfDump) emitMissingAliases(id uint32, t *btf.Type) {
	name := d.typeName(id)
	for _, alias := range missingBaseTypes {
		if name == alias[0] {
			d.print("typedef %s %s;\n\n", alias[1], name)
			return
		}
	}
}
