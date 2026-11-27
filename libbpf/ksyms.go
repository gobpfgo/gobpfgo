// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: add_dummy_ksym_var, find_int_btf_id, bpf_object__collect_externs, libbpf_kallsyms_parse, kallsyms_cb, bpf_object__read_kallsyms_file, find_extern_by_name_with_len, bpf_core_essential_name_len, bpf_core_is_flavor_sep

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"golang.org/x/sys/unix"
)

// kallsymsPath lists the kernel symbols with their addresses. The addresses
// read as zero without CAP_SYSLOG when kptr_restrict hides them.
const kallsymsPath = "/proc/kallsyms"

// kallsymsNameMax is the longest symbol name the kallsyms reader keeps; the
// rest of a longer name is skipped with the rest of its line.
const kallsymsNameMax = 499

// dummyKsymName names the VAR that stands for the .ksyms functions in the
// DATASEC the kernel loads.
const dummyKsymName = "dummy_ksym"

// ksymExtern is the .ksyms part of an extern. typeID is the local BTF type
// of the extern after modifiers and typedefs, the function prototype of a
// function, or 0 for a typeless variable, which resolves through
// /proc/kallsyms to addr. A typed extern resolves through the kernel BTF to
// kernelBtfID in the vmlinux BTF or in the module BTF whose descriptor is
// kernelBtfObjFD; btfFdIdx is that module's slot in the object's fd array,
// which a kfunc call names in its offset field. Both are 0 for vmlinux.
type ksymExtern struct {
	addr           uint64
	kernelBtfObjFD int
	kernelBtfID    uint32
	typeID         uint32
	btfFdIdx       int16
}

// newKsymExtern returns the .ksyms part of the extern whose VAR or FUNC is
// t: its local type after modifiers and typedefs, which is the prototype of
// a function and 0 for a typeless variable.
func newKsymExtern(spec *btf.Spec, t *btf.Type) ksymExtern {
	_, typeID := skipModsAndTypedefs(spec, t.SizeOrType)
	return ksymExtern{typeID: typeID}
}

// bpfCoreEssentialNameLen returns the length of name without its flavor
// suffix: the part before the last triple underscore that has a character
// other than an underscore on each side, as in name___flavor.
func bpfCoreEssentialNameLen(name string) int {
	for i := len(name) - 5; i >= 0; i-- {
		if bpfCoreIsFlavorSep(name[i:]) {
			return i + 1
		}
	}
	return len(name)
}

// bpfCoreIsFlavorSep reports whether s starts with X___Y, where X and Y are
// not underscores.
func bpfCoreIsFlavorSep(s string) bool {
	return s[0] != '_' && s[1] == '_' && s[2] == '_' && s[3] == '_' && s[4] != '_'
}

// essentialName returns name without its flavor suffix, or "" when name has
// none.
func essentialName(name string) string {
	if n := bpfCoreEssentialNameLen(name); n != len(name) {
		return name[:n]
	}
	return ""
}

// addDummyKsymVar adds the dummy_ksym VAR when the .ksyms DATASEC lists a
// function and returns its ID, or 0 when there is no .ksyms DATASEC or it
// has only variables. The VAR is allocated and has the first 32-bit integer
// type of the object, or void when there is none.
func addDummyKsymVar(spec *btf.Spec) (uint32, error) {
	sec := spec.Find(btf.KsymsSec, btf.KindDatasec)
	if sec == nil {
		return 0, nil
	}
	hasFunc := false
	for _, vsi := range sec.DataSec {
		if vt, err := spec.TypeByID(vsi.Type); err == nil && vt.Kind == btf.KindFunc {
			hasFunc = true
			break
		}
	}
	if !hasFunc {
		return 0, nil
	}

	id, err := spec.AddVar(dummyKsymName, btf.VarGlobalAllocated, findIntBtfID(spec))
	if err != nil {
		return 0, externError(unix.EINVAL, "cannot create a dummy_ksym var: %v", err)
	}
	return id, nil
}

// findIntBtfID returns the first 32-bit INT type of spec, or 0.
func findIntBtfID(spec *btf.Spec) uint32 {
	for id := 1; id < len(spec.Types); id++ {
		t := &spec.Types[id]
		if t.Kind == btf.KindInt && t.Int != nil && t.Int.Encoding&0xff == 32 {
			return uint32(id)
		}
	}
	return 0
}

// layoutKsyms turns the .ksyms DATASEC secID into one the kernel accepts:
// every entry becomes a 4-byte slot at the next offset. A variable gets
// allocated linkage and the first 32-bit integer type. A function gets
// global linkage, its unnamed typed parameters take the dummy_ksym name,
// and its slot refers to the dummy_ksym VAR dummyID instead, as a DATASEC
// may hold only variables. The kernel never sees the extern types; the
// externs keep their local types in the extern descriptors. An entry without
// an extern returns ESRCH.
func layoutKsyms(spec *btf.Spec, secID, dummyID uint32, externs []externDesc) error {
	intID := findIntBtfID(spec)
	dummy, err := spec.TypeByID(dummyID)
	if err != nil {
		return externError(unix.EINVAL, "%v", err)
	}
	dummyNameOff := dummy.NameOff

	sec := &spec.Types[secID]
	off := uint32(0)
	for j := range sec.DataSec {
		vt, err := spec.TypeByID(sec.DataSec[j].Type)
		if err != nil {
			return externError(unix.EINVAL, "%v", err)
		}
		if findExternByName(externs, vt.Name) == nil {
			return externError(unix.ESRCH, "failed to find extern definition for BTF %s '%s'", vt.Kind, vt.Name)
		}

		slotType := sec.DataSec[j].Type
		if vt.Kind == btf.KindFunc {
			if err := fixupKsymFunc(spec, vt, dummyNameOff); err != nil {
				return externError(unix.EINVAL, "%v", err)
			}
			slotType = dummyID
		} else if err := fixupKsymVar(spec, vt, intID); err != nil {
			return externError(unix.EINVAL, "%v", err)
		}

		if err := spec.SetDatasecVar(secID, j, btf.VarSecInfo{Type: slotType, Offset: off, Size: 4}); err != nil {
			return externError(unix.EINVAL, "%v", err)
		}
		off += 4
	}
	if err := spec.SetDatasecSize(secID, off); err != nil {
		return externError(unix.EINVAL, "%v", err)
	}
	return nil
}

// fixupKsymFunc names the unnamed typed parameters of the .ksyms function
// fn after dummy_ksym and gives fn global linkage.
func fixupKsymFunc(spec *btf.Spec, fn *btf.Type, dummyNameOff uint32) error {
	proto, err := spec.TypeByID(fn.SizeOrType)
	if err != nil {
		return err
	}
	for j, param := range proto.Params {
		if param.Type == 0 || param.NameOff != 0 {
			continue
		}
		if err := spec.SetParamNameOff(proto.ID, j, dummyNameOff); err != nil {
			return err
		}
	}
	return spec.SetFuncLinkage(fn.ID, btfFuncGlobal)
}

// fixupKsymVar makes the .ksyms variable v an allocated integer.
func fixupKsymVar(spec *btf.Spec, v *btf.Type, intID uint32) error {
	if err := spec.SetVarLinkage(v.ID, btf.VarGlobalAllocated); err != nil {
		return err
	}
	return spec.SetVarType(v.ID, intID)
}

// kallsymsCallback receives one /proc/kallsyms entry: the address, the
// symbol type letter and the name.
type kallsymsCallback func(addr uint64, typ byte, name string) error

// kallsymsParse reads kallsyms entries from r and calls cb for each, in
// order, until the input ends or cb returns an error. An entry is a hex
// address, a type character and a name of up to 499 characters; the rest of
// the line, such as a module name, is skipped. An entry that cannot be read
// returns EINVAL.
func kallsymsParse(r io.Reader, cb kallsymsCallback) error {
	s := kallsymsScanner{r: bufio.NewReader(r)}
	for {
		addr, typ, name, n, eof := s.entry()
		if eof {
			return nil
		}
		if n != 3 {
			return fmt.Errorf("failed to read kallsyms entry: %d: %w", n, unix.EINVAL)
		}
		if err := cb(addr, typ, name); err != nil {
			return err
		}
	}
}

// readKallsymsFile resolves the typeless .ksyms variables of externs from
// /proc/kallsyms. An error opening the file is returned with its errno.
func readKallsymsFile(externs []externDesc, spec *btf.Spec) error {
	f, err := os.Open(kallsymsPath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", kallsymsPath, err)
	}
	defer f.Close()
	return kallsymsParse(f, func(addr uint64, typ byte, name string) error {
		return kallsymsCb(externs, spec, addr, typ, name)
	})
}

// kallsymsCb applies one kallsyms entry to the .ksyms variable it names. A
// local data symbol with an .llvm. suffix, which LTO kernels add, matches
// the name before the suffix. The first address sets the extern; another
// entry of the same name with a different address makes the resolution
// ambiguous and returns EINVAL. Functions and other externs are ignored.
func kallsymsCb(externs []externDesc, spec *btf.Spec, addr uint64, typ byte, name string) error {
	lookup := name
	if i := strings.Index(name, ".llvm."); typ == 'd' && i >= 0 {
		lookup = name[:i]
	}
	ext := findExternByName(externs, lookup)
	if ext == nil || ext.typ != extKsym {
		return nil
	}
	if t, err := spec.TypeByID(ext.btfID); err != nil || t.Kind != btf.KindVar {
		return nil
	}

	if ext.isSet && ext.ksym.addr != addr {
		return fmt.Errorf("extern (ksym) '%s': resolution is ambiguous: 0x%x or 0x%x: %w", name, ext.ksym.addr, addr, unix.EINVAL)
	}
	if !ext.isSet {
		ext.isSet = true
		ext.ksym.addr = addr
	}
	return nil
}

// kallsymsScanner reads kallsyms entries the way the C library's
// fscanf("%llx %c %499s%*[^\n]\n") does.
type kallsymsScanner struct {
	r *bufio.Reader
}

// entry reads one entry and returns the number of fields it assigned, as
// fscanf does. eof is set when the input ends before the first field.
func (s *kallsymsScanner) entry() (addr uint64, typ byte, name string, n int, eof bool) {
	if !s.skipSpace() {
		return 0, 0, "", 0, true
	}
	addr, ok := s.hex()
	if !ok {
		return 0, 0, "", 0, false
	}
	n = 1

	s.skipSpace()
	c, err := s.r.ReadByte()
	if err != nil {
		return addr, 0, "", n, false
	}
	typ, n = c, 2

	if !s.skipSpace() {
		return addr, typ, "", n, false
	}
	name = s.token(kallsymsNameMax)
	n = 3

	// %*[^\n] needs at least one character before the newline; without
	// one the scan stops and the newline is left for the next entry.
	if s.skipLine() {
		s.skipSpace()
	}
	return addr, typ, name, n, false
}

// skipSpace consumes white space and reports whether input remains.
func (s *kallsymsScanner) skipSpace() bool {
	for {
		c, err := s.r.ReadByte()
		if err != nil {
			return false
		}
		if !isCSpace(c) {
			_ = s.r.UnreadByte()
			return true
		}
	}
}

// hex reads a hexadecimal number with an optional sign and 0x prefix, as
// %llx does; a negative value wraps around.
func (s *kallsymsScanner) hex() (uint64, bool) {
	negative := false
	if c, err := s.r.Peek(1); err == nil && (c[0] == '+' || c[0] == '-') {
		negative = c[0] == '-'
		_, _ = s.r.ReadByte()
	}
	if c, err := s.r.Peek(3); err == nil && c[0] == '0' && (c[1] == 'x' || c[1] == 'X') && digitValue(c[2]) < 16 {
		_, _ = s.r.Discard(2)
	}

	var value uint64
	digits := 0
	for {
		c, err := s.r.Peek(1)
		if err != nil || digitValue(c[0]) >= 16 {
			break
		}
		value = value<<4 | uint64(digitValue(c[0]))
		_, _ = s.r.ReadByte()
		digits++
	}
	if negative {
		value = -value
	}
	return value, digits > 0
}

// token reads up to max characters that are not white space.
func (s *kallsymsScanner) token(max int) string {
	var b strings.Builder
	for b.Len() < max {
		c, err := s.r.ReadByte()
		if err != nil {
			break
		}
		if isCSpace(c) {
			_ = s.r.UnreadByte()
			break
		}
		b.WriteByte(c)
	}
	return b.String()
}

// skipLine consumes the characters before the next newline and reports
// whether there was at least one.
func (s *kallsymsScanner) skipLine() bool {
	skipped := false
	for {
		c, err := s.r.ReadByte()
		if err != nil {
			return skipped
		}
		if c == '\n' {
			_ = s.r.UnreadByte()
			return skipped
		}
		skipped = true
	}
}
