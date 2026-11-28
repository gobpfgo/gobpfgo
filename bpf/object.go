// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package bpf

import (
	"errors"
	"slices"

	"github.com/gobpfgo/gobpfgo/libbpf"
)

// ErrClosed is returned by a method with an error result that is called on a
// closed Object, or on a Program or Map of a closed Object. Check it with
// errors.Is.
var ErrClosed = errors.New("bpf: object is closed")

// Object is an opened BPF object file and the Programs and Maps it defines.
//
// The Object owns the core object. Load creates the kernel descriptors and
// Close releases them; Close is the only call that ends the lifetime. The
// Programs and Maps are views into the Object and own nothing: after Close
// their methods with an error result return ErrClosed and their accessors
// return a zero value, -1 for a descriptor. A Link created from a Program is
// not owned by the Object and stays attached after Close until the caller
// destroys it.
//
// An Object is not safe for concurrent use; in particular, Close must not
// run while another goroutine uses the Object or one of its children.
type Object struct {
	obj      *libbpf.BpfObject
	programs []*Program
	maps     []*Map
	closed   bool
}

// OpenFile opens the BPF ELF object at path and describes its programs and
// maps without touching the kernel. opts may be nil. The caller must call
// Close when done. A failed open returns the core *libbpf.Error unchanged.
func OpenFile(path string, opts *libbpf.BpfObjectOpenOpts) (*Object, error) {
	obj, err := libbpf.BpfObjectOpenFile(path, opts)
	if err != nil {
		return nil, err
	}
	return newObject(obj), nil
}

// OpenMem opens a BPF ELF object from data, like OpenFile. The object is
// named "mem" unless opts sets ObjectName. The caller must call Close.
func OpenMem(data []byte, opts *libbpf.BpfObjectOpenOpts) (*Object, error) {
	obj, err := libbpf.BpfObjectOpenMem(data, opts)
	if err != nil {
		return nil, err
	}
	return newObject(obj), nil
}

// newObject wraps obj and creates one wrapper per program and map, in the
// core iteration order. The core fixes both lists at open, so the wrappers
// are created once and returned by every later call.
func newObject(obj *libbpf.BpfObject) *Object {
	o := &Object{obj: obj}
	for p := libbpf.BpfObjectNextProgram(obj, nil); p != nil; p = libbpf.BpfObjectNextProgram(obj, p) {
		o.programs = append(o.programs, &Program{prog: p, obj: o})
	}
	for m := libbpf.BpfObjectNextMap(obj, nil); m != nil; m = libbpf.BpfObjectNextMap(obj, m) {
		o.maps = append(o.maps, &Map{m: m, obj: o})
	}
	return o
}

// live returns the core object, or nil for a nil or closed Object. The core
// accessors return their zero value for nil.
func (o *Object) live() *libbpf.BpfObject {
	if o == nil || o.closed {
		return nil
	}
	return o.obj
}

// isClosed reports whether Close has been called. A nil Object is not
// closed; its methods pass nil to the core, which rejects it.
func (o *Object) isClosed() bool {
	return o != nil && o.closed
}

// Name returns the object name, or an empty string after Close.
func (o *Object) Name() string {
	return libbpf.BpfObjectName(o.live())
}

// BTF returns the object's parsed BTF, or nil when the object has none and
// after Close. The Btf is borrowed from the Object: do not free it or use it
// after Close.
func (o *Object) BTF() *libbpf.Btf {
	return libbpf.BpfObjectBTF(o.live())
}

// Load creates the object's maps and loads its programs into the kernel. It
// returns ErrClosed after Close; a load failure returns the core
// *libbpf.Error, which carries the verifier log when the kernel produced one.
//
// An Object loads only once: a second Load returns EINVAL with "load can't
// be attempted twice" in the log, whether the first one succeeded or
// failed. A failed Load leaves the Object unloaded, with every map and
// program descriptor closed, including the duplicates ReuseFD made, and the
// BTF fixups it applied stay in the object BTF. Its Maps still count as
// created: SetInitialValue returns EBUSY and the element operations EINVAL.
// Close the failed Object as usual. See libbpf.BpfObjectLoad.
func (o *Object) Load() error {
	if o.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfObjectLoad(o.live())
}

// Close closes the core object and its map, program and BTF descriptors,
// and marks the Object closed. Programs and Maps of the Object stop working,
// as described on Object; Links stay attached until destroyed. Close is
// idempotent, safe on a nil Object, and always returns nil; the error result
// lets Object satisfy io.Closer.
func (o *Object) Close() error {
	if o == nil || o.closed {
		return nil
	}
	libbpf.BpfObjectClose(o.obj)
	o.closed = true
	o.programs = nil
	o.maps = nil
	return nil
}

// Programs returns the object's programs in ELF order, without the .text
// subprograms. Every call returns the same Program values in a new slice. It
// returns nil after Close.
func (o *Object) Programs() []*Program {
	if o.live() == nil {
		return nil
	}
	return slices.Clone(o.programs)
}

// Maps returns the object's maps in core order: the .maps definitions and the
// internal data, .kconfig and per-CPU maps. Every call returns the same Map
// values in a new slice. It returns nil after Close.
func (o *Object) Maps() []*Map {
	if o.live() == nil {
		return nil
	}
	return slices.Clone(o.maps)
}

// Program returns the program named name, or nil when there is none or the
// Object is closed. The result is the same value Programs returns.
func (o *Object) Program(name string) *Program {
	prog := libbpf.BpfObjectFindProgramByName(o.live(), name)
	if prog == nil {
		return nil
	}
	for _, p := range o.programs {
		if p.prog == prog {
			return p
		}
	}
	return nil
}

// Map returns the map named name, or nil when there is none or the Object is
// closed. A name starting with a dot selects an internal map by section, such
// as ".data" or ".kconfig". The result is the same value Maps returns.
func (o *Object) Map(name string) *Map {
	bpfMap := libbpf.BpfObjectFindMapByName(o.live(), name)
	if bpfMap == nil {
		return nil
	}
	for _, m := range o.maps {
		if m.m == bpfMap {
			return m
		}
	}
	return nil
}

// Pin pins every map at path/<map-name> and every program at
// path/<program-name> on bpffs. It returns ErrClosed after Close and the core
// *libbpf.Error otherwise; a failed program pin undoes the map pins.
func (o *Object) Pin(path string) error {
	if o.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfObjectPin(o.live(), path)
}

// Unpin removes the program and map pins Pin created under path. It returns
// ErrClosed after Close and the core *libbpf.Error otherwise.
func (o *Object) Unpin(path string) error {
	if o.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfObjectUnpin(o.live(), path)
}
