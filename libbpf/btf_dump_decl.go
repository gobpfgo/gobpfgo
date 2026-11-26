// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/btf_dump.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: btf_dump__emit_type_decl, btf_dump_emit_type_decl, btf_dump_emit_type_chain, btf_dump_emit_mods, btf_dump_drop_mods, btf_dump_emit_name, btf_dump_name_dups, btf_dump_resolve_name, btf_dump_type_name, btf_dump_ident_name

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"fmt"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

// BtfDumpEmitTypeDeclOpts are the options of BtfDumpEmitTypeDecl. The zero
// value emits the declaration at indent level 0 without a field name and
// keeps the const/volatile/restrict modifiers.
type BtfDumpEmitTypeDeclOpts struct {
	FieldName   string
	IndentLevel int
	StripMods   bool
}

// BtfDumpEmitTypeDecl emits a C declaration of id, such as `const int *name`,
// without a trailing semicolon.
func BtfDumpEmitTypeDecl(d *BtfDump, id uint32, opts *BtfDumpEmitTypeDeclOpts) error {
	if d == nil || d.freed || d.btf == nil || int(id) >= len(d.btf.Types) {
		return &Error{Op: "btf_dump__emit_type_decl", Errno: unix.EINVAL}
	}
	if err := d.resize(); err != nil {
		return &Error{Op: "btf_dump__emit_type_decl", Errno: errnoFromError(err), Log: err.Error()}
	}

	var fieldName string
	level := 0
	stripMods := false
	if opts != nil {
		fieldName = opts.FieldName
		level = opts.IndentLevel
		stripMods = opts.StripMods
	}

	d.stripMods = stripMods
	d.emitTypeDecl(id, fieldName, level)
	d.stripMods = false
	return nil
}

// dumpIDStack is a view into the shared declaration stack. It stores indexes
// instead of a slice header so a nested emission that grows the stack cannot
// invalidate it.
type dumpIDStack struct {
	start int
	cnt   int
}

func (d *BtfDump) stackTop(s *dumpIDStack) uint32 {
	return d.declStack[s.start+s.cnt-1]
}

func (d *BtfDump) stackPop(s *dumpIDStack) uint32 {
	s.cnt--
	return d.declStack[s.start+s.cnt]
}

// emitTypeDecl pushes the modifier, pointer, array and function chain of id
// and emits one C declarator with fname as the identifier.
func (d *BtfDump) emitTypeDecl(id uint32, fname string, level int) {
	stackStart := len(d.declStack)

	for {
		t := &d.btf.Types[id]
		if !(d.stripMods && isMod(t)) {
			d.declStack = append(d.declStack, id)
		}
		if id == 0 {
			break
		}

		switch t.Kind {
		case btf.KindPtr, btf.KindVolatile, btf.KindConst, btf.KindRestrict,
			btf.KindFuncProto, btf.KindTypeTag:
			id = t.SizeOrType
		case btf.KindArray:
			if t.Array == nil {
				d.declStack = d.declStack[:stackStart]
				return
			}
			id = t.Array.Type
		case btf.KindInt, btf.KindEnum, btf.KindEnum64, btf.KindFwd,
			btf.KindStruct, btf.KindUnion, btf.KindTypedef, btf.KindFloat:
			d.emitTypeChain(&dumpIDStack{start: stackStart, cnt: len(d.declStack) - stackStart}, fname, level)
			d.declStack = d.declStack[:stackStart]
			return
		default:
			d.emitTypeChain(&dumpIDStack{start: stackStart, cnt: len(d.declStack) - stackStart}, fname, level)
			d.declStack = d.declStack[:stackStart]
			return
		}
	}

	d.emitTypeChain(&dumpIDStack{start: stackStart, cnt: len(d.declStack) - stackStart}, fname, level)
	d.declStack = d.declStack[:stackStart]
}

// emitMods emits the const, volatile and restrict modifiers at the top of the
// stack.
func (d *BtfDump) emitMods(s *dumpIDStack) {
	for s.cnt > 0 {
		t := &d.btf.Types[d.stackTop(s)]
		switch t.Kind {
		case btf.KindVolatile:
			d.print("volatile ")
		case btf.KindConst:
			d.print("const ")
		case btf.KindRestrict:
			d.print("restrict ")
		default:
			return
		}
		s.cnt--
	}
}

// dropMods removes leading modifiers from the stack, matching the C library's
// workaround for GCC-inserted qualifiers on arrays and function pointers.
func (d *BtfDump) dropMods(s *dumpIDStack) {
	for s.cnt > 0 {
		t := &d.btf.Types[d.stackTop(s)]
		if !isMod(t) {
			return
		}
		s.cnt--
	}
}

func (d *BtfDump) emitName(name string, lastWasPtr bool) {
	separator := ""
	if name != "" && !lastWasPtr {
		separator = " "
	}
	d.print("%s%s", separator, name)
}

func (d *BtfDump) emitTypeChain(s *dumpIDStack, fname string, level int) {
	lastWasPtr := true

	for s.cnt > 0 {
		id := d.stackPop(s)
		if id == 0 {
			d.emitMods(s)
			d.print("void")
			lastWasPtr = false
			continue
		}

		t := &d.btf.Types[id]
		switch t.Kind {
		case btf.KindInt, btf.KindFloat:
			d.emitMods(s)
			d.print("%s", t.Name)
		case btf.KindStruct, btf.KindUnion:
			d.emitMods(s)
			if t.NameOff == 0 && !d.skipAnonDefs {
				d.emitStructDef(id, t, level)
			} else {
				d.emitStructFwd(id, t)
			}
		case btf.KindEnum, btf.KindEnum64:
			d.emitMods(s)
			if t.NameOff == 0 && !d.skipAnonDefs {
				d.emitEnumDef(id, t, level)
			} else {
				d.emitEnumFwd(id)
			}
		case btf.KindFwd:
			d.emitMods(s)
			d.emitFwdDef(id, t)
		case btf.KindTypedef:
			d.emitMods(s)
			d.print("%s", d.identName(id))
		case btf.KindPtr:
			if lastWasPtr {
				d.print("*")
			} else {
				d.print(" *")
			}
		case btf.KindVolatile:
			d.print(" volatile")
		case btf.KindConst:
			d.print(" const")
		case btf.KindRestrict:
			d.print(" restrict")
		case btf.KindTypeTag:
			d.emitMods(s)
			switch {
			case t.KindFlag:
				d.print(" __attribute__((%s))", t.Name)
			case t.Name == "arena":
				d.print(" __attribute__((address_space(1))) __attribute__((btf_type_tag(\"arena\")))")
			default:
				d.print(" __attribute__((btf_type_tag(\"%s\")))", t.Name)
			}
		case btf.KindArray:
			if t.Array == nil {
				return
			}
			d.dropMods(s)
			if s.cnt == 0 {
				d.emitName(fname, lastWasPtr)
				d.print("[%d]", t.Array.Nelems)
				return
			}
			next := &d.btf.Types[d.stackTop(s)]
			multidim := isArray(next)
			if fname != "" && !lastWasPtr {
				d.print(" ")
			}
			if !multidim {
				d.print("(")
			}
			d.emitTypeChain(s, fname, level)
			if !multidim {
				d.print(")")
			}
			d.print("[%d]", t.Array.Nelems)
			return
		case btf.KindFuncProto:
			d.dropMods(s)
			if s.cnt != 0 {
				d.print(" (")
				d.emitTypeChain(s, fname, level)
				d.print(")")
			} else {
				d.emitName(fname, lastWasPtr)
			}
			d.print("(")
			params := t.Params
			if len(params) == 0 || len(params) == 1 && params[0].Type == 0 {
				d.print("void)")
				return
			}
			for i, param := range params {
				if i > 0 {
					d.print(", ")
				}
				if i == len(params)-1 && param.Type == 0 {
					d.print("...")
					break
				}
				d.emitTypeDecl(param.Type, param.Name, level)
			}
			d.print(")")
			return
		default:
			return
		}

		lastWasPtr = t.Kind == btf.KindPtr
	}

	d.emitName(fname, lastWasPtr)
}

// nameDups counts how many times name was used in the namespace and returns
// the new count. The first use returns 1.
func (d *BtfDump) nameDups(names map[string]int, name string) int {
	names[name]++
	return names[name]
}

// resolveName returns the unique C name of id, adding a ___N suffix when the
// same name was already used in that namespace.
func (d *BtfDump) resolveName(id uint32, names map[string]int) string {
	state := &d.states[id]
	t := &d.btf.Types[id]
	if t.NameOff == 0 {
		return ""
	}
	if state.nameResolved {
		if d.cachedNames[id] != "" {
			return d.cachedNames[id]
		}
		return t.Name
	}

	if t.Kind == btf.KindFwd || t.Kind == btf.KindEnum && len(t.Enums) == 0 {
		state.nameResolved = true
		return t.Name
	}

	if dups := d.nameDups(names, t.Name); dups > 1 {
		d.cachedNames[id] = fmt.Sprintf("%s___%d", t.Name, dups)
	}
	state.nameResolved = true
	if d.cachedNames[id] != "" {
		return d.cachedNames[id]
	}
	return t.Name
}

func (d *BtfDump) typeName(id uint32) string {
	return d.resolveName(id, d.typeNames)
}

func (d *BtfDump) identName(id uint32) string {
	return d.resolveName(id, d.identNames)
}
