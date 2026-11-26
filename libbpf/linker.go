// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/linker.c
// libbpf-source: src/btf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_linker__new, bpf_linker__new_fd, bpf_linker__add_file, bpf_linker__add_fd, bpf_linker__add_buf, bpf_linker__finalize, bpf_linker__free, init_output_elf, add_dst_sec, add_new_sym, bpf_linker_add_file, init_sec, linker_append_sec_data, linker_append_elf_syms, linker_append_elf_sym, linker_append_elf_relos, finalize_btf, emit_elf_data_sec, btf_new_empty, btf_get_raw_data

package libbpf

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	objelf "github.com/gobpfgo/gobpfgo/internal/elf"
	"golang.org/x/sys/unix"
)

// BpfLinkerOpts are the options of BpfLinkerNew and BpfLinkerNewFD. The C
// library has only a size field; the Go API takes the struct as is.
type BpfLinkerOpts struct{}

// BpfLinkerFileOpts are the options of BpfLinkerAddFile, BpfLinkerAddFD and
// BpfLinkerAddBuf. The C library has only a size field; the Go API takes the
// struct as is.
type BpfLinkerFileOpts struct{}

// BpfLinker statically links relocatable BPF objects into one output object.
//
// This version links exactly one input object. The output keeps the program,
// data, map and license sections with their relocations, plus .BTF and
// .BTF.ext, and rebuilds the symbol and string tables. DWARF, the input
// string tables, .llvm_addrsig, an empty .text and the .BTF and .BTF.ext
// relocations are dropped. Adding a second object returns EOPNOTSUPP.
//
// Create a linker with BpfLinkerNew or BpfLinkerNewFD, add the object, write
// the output with BpfLinkerFinalize and release the linker with
// BpfLinkerFree. A linker is not safe for concurrent use.
type BpfLinker struct {
	filename  string
	fd        int
	fdIsOwned bool
	writable  bool
	inputs    int
	out       *linkerOutput
}

// linkerOutput is the object being built. elf.Sections[i] has ELF index i+1
// and elf.Symbols[i] has symbol index i+1. secSyms[i] is the STT_SECTION
// symbol index of section i+1, or 0.
type linkerOutput struct {
	elf     objelf.Output
	secSyms []uint32
	btf     *btf.Spec
	btfExt  []byte
}

// btfHdrLen is sizeof(struct btf_header) in the pinned libbpf, which ends
// with the kind layout offset and length.
const btfHdrLen = 32

// BpfLinkerNew creates or truncates filename with mode 0644 and returns a
// linker that writes the linked object to it. The linker owns the file
// descriptor and closes it in BpfLinkerFinalize or BpfLinkerFree. The open
// errno is returned unchanged.
func BpfLinkerNew(filename string, opts *BpfLinkerOpts) (*BpfLinker, error) {
	fd, err := unix.Open(filename, unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC, 0o644)
	if err != nil {
		return nil, &Error{Op: "bpf_linker__new", Path: filename, Errno: errnoFromError(err), Log: "failed to create output file"}
	}
	return newLinker(filename, fd, true), nil
}

// BpfLinkerNewFD returns a linker that writes the linked object to fd. The
// caller keeps ownership of fd: the linker writes from offset 0, sets the file
// size, and never closes it. A negative fd returns EINVAL.
func BpfLinkerNewFD(fd int, opts *BpfLinkerOpts) (*BpfLinker, error) {
	if fd < 0 {
		return nil, &Error{Op: "bpf_linker__new_fd", Errno: unix.EINVAL}
	}
	return newLinker(fmt.Sprintf("fd:%d", fd), fd, false), nil
}

func newLinker(filename string, fd int, owned bool) *BpfLinker {
	return &BpfLinker{
		filename:  filename,
		fd:        fd,
		fdIsOwned: owned,
		writable:  true,
		out:       newLinkerOutput(),
	}
}

// BpfLinkerAddFile reads the relocatable BPF object at filename and adds it to
// the output. It returns EINVAL after BpfLinkerFinalize or BpfLinkerFree, the
// open or read errno, EINVAL or EOPNOTSUPP for an object the linker cannot
// use, and EOPNOTSUPP when an object was already added. A failed add leaves
// the linker unchanged.
func BpfLinkerAddFile(l *BpfLinker, filename string, opts *BpfLinkerFileOpts) error {
	const op = "bpf_linker__add_file"
	if err := l.canAdd(op); err != nil {
		return err
	}

	fd, err := unix.Open(filename, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return &Error{Op: op, Path: filename, Errno: errnoFromError(err), Log: "failed to open file"}
	}
	defer unix.Close(fd)

	data, err := readFD(fd)
	if err != nil {
		return &Error{Op: op, Path: filename, Errno: errnoFromError(err), Log: "failed to read file"}
	}
	return l.add(op, filename, data)
}

// BpfLinkerAddFD adds the relocatable BPF object read from fd, starting at
// offset 0. The caller keeps ownership of fd. Errors are those of
// BpfLinkerAddFile, plus EINVAL for a negative fd.
func BpfLinkerAddFD(l *BpfLinker, fd int, opts *BpfLinkerFileOpts) error {
	const op = "bpf_linker__add_fd"
	if err := l.canAdd(op); err != nil {
		return err
	}
	if fd < 0 {
		return &Error{Op: op, Errno: unix.EINVAL}
	}

	name := fmt.Sprintf("fd:%d", fd)
	data, err := readFD(fd)
	if err != nil {
		return &Error{Op: op, Path: name, Errno: errnoFromError(err), Log: "failed to read file"}
	}
	return l.add(op, name, data)
}

// BpfLinkerAddBuf adds the relocatable BPF object in buf. buf is only read
// during the call. Errors are those of BpfLinkerAddFile.
func BpfLinkerAddBuf(l *BpfLinker, buf []byte, opts *BpfLinkerFileOpts) error {
	const op = "bpf_linker__add_buf"
	if err := l.canAdd(op); err != nil {
		return err
	}
	return l.add(op, fmt.Sprintf("mem:%d", len(buf)), buf)
}

// BpfLinkerFinalize writes the linked object and closes the output
// descriptor if the linker owns it. Further adds and finalizes return EINVAL.
// A layout or write failure returns EINVAL with the reason in Log.
func BpfLinkerFinalize(l *BpfLinker) error {
	const op = "bpf_linker__finalize"
	if l == nil || !l.writable {
		return &Error{Op: op, Errno: unix.EINVAL}
	}

	data, err := l.out.marshal()
	if err != nil {
		return linkerFail(op, l.filename, err)
	}
	if err := writeFD(l.fd, data); err != nil {
		return &Error{Op: op, Path: l.filename, Errno: unix.EINVAL, Log: fmt.Sprintf("failed to write ELF contents: %v", err)}
	}

	l.writable = false
	if l.fdIsOwned {
		unix.Close(l.fd)
	}
	l.fd = -1
	return nil
}

// BpfLinkerFree releases the linker. It closes the output descriptor when the
// linker owns it and BpfLinkerFinalize has not closed it already; an output
// file that was never finalized is left as it is. It accepts nil and may be
// called more than once.
func BpfLinkerFree(l *BpfLinker) {
	if l == nil {
		return
	}
	if l.fd >= 0 && l.fdIsOwned {
		unix.Close(l.fd)
	}
	l.fd = -1
	l.writable = false
	l.out = nil
}

// canAdd rejects an add after finalize or free, and a second input object.
func (l *BpfLinker) canAdd(op string) error {
	if l == nil || !l.writable {
		return &Error{Op: op, Errno: unix.EINVAL}
	}
	if l.inputs > 0 {
		return &Error{Op: op, Path: l.filename, Errno: unix.EOPNOTSUPP,
			Log: "the linker takes one input object; linking several objects is not supported yet"}
	}
	return nil
}

// add loads one object and appends its sections, symbols and relocations to
// a fresh output, which replaces the linker's output only on success.
func (l *BpfLinker) add(op, name string, data []byte) error {
	in, err := linkerLoadObj(name, data)
	if err != nil {
		return linkerFail(op, name, err)
	}

	out := newLinkerOutput()
	if err := out.addObject(in); err != nil {
		return linkerFail(op, name, err)
	}
	l.out = out
	l.inputs++
	return nil
}

// linkerErrorf returns an Error with errno and a reason. The public function
// that returns it fills in Op and Path.
func linkerErrorf(errno unix.Errno, format string, args ...any) error {
	return &Error{Errno: errno, Log: fmt.Sprintf(format, args...)}
}

// linkerFail sets the operation and path of an error from a linker step.
func linkerFail(op, path string, err error) error {
	var e *Error
	if !errors.As(err, &e) {
		return &Error{Op: op, Path: path, Errno: unix.EINVAL, Log: err.Error()}
	}
	e.Op = op
	e.Path = path
	return e
}

// newLinkerOutput starts the output with .strtab, which also holds the
// section names, and .symtab with its null symbol. Like libbpf, .symtab
// keeps sh_info at 0 instead of one past the last local symbol.
func newLinkerOutput() *linkerOutput {
	out := &linkerOutput{}
	out.addSec(objelf.OutputSection{Name: ".strtab", Type: elf.SHT_STRTAB, Flags: elf.SHF_STRINGS, Addralign: 1})
	out.addSec(objelf.OutputSection{Name: ".symtab", Type: elf.SHT_SYMTAB, Addralign: 8})
	return out
}

// addSec appends s and returns its ELF index.
func (out *linkerOutput) addSec(s objelf.OutputSection) int {
	out.elf.Sections = append(out.elf.Sections, s)
	out.secSyms = append(out.secSyms, 0)
	return len(out.elf.Sections)
}

// findSec returns the ELF index of the output section named name, or 0.
func (out *linkerOutput) findSec(name string) int {
	for i := range out.elf.Sections {
		if out.elf.Sections[i].Name == name {
			return i + 1
		}
	}
	return 0
}

// addObject appends the data sections, then the symbols, then the relocation
// sections of in, and keeps its fixed BTF for finalize.
func (out *linkerOutput) addObject(in *linkerInput) error {
	if err := out.appendSecData(in); err != nil {
		return err
	}
	if err := out.appendSyms(in); err != nil {
		return err
	}
	if err := out.appendRelos(in); err != nil {
		return err
	}
	out.btf = in.btf
	out.btfExt = in.btfExt
	return nil
}

// initSec adds an output section with the name, type, flags, alignment,
// entry size and contents of s, and returns its ELF index. The first object
// starts every output section, so the contents land at offset 0 and the
// alignment is at least 1. A section name that is already in the output
// needs section merging, which is not supported yet.
func (out *linkerOutput) initSec(s *objelf.Section) (int, error) {
	if out.findSec(s.Name) != 0 {
		return 0, linkerErrorf(unix.EOPNOTSUPP, "section %s appears more than once; merging sections is not supported yet", s.Name)
	}

	sec := objelf.OutputSection{
		Name:      s.Name,
		Type:      s.Type,
		Flags:     s.Flags,
		Addralign: max(s.Addralign, 1),
		Entsize:   s.Entsize,
	}
	switch s.Type {
	case elf.SHT_PROGBITS:
		sec.Data = s.Data
	case elf.SHT_NOBITS:
		sec.Size = s.Size
	}
	return out.addSec(sec), nil
}

// appendSecData copies the code and data sections that are not skipped.
func (out *linkerOutput) appendSecData(in *linkerInput) error {
	for i := 1; i < len(in.elf.Sections); i++ {
		s := &in.elf.Sections[i]
		if in.secs[i].skipped || (s.Type != elf.SHT_PROGBITS && s.Type != elf.SHT_NOBITS) {
			continue
		}

		dst, err := out.initSec(s)
		if err != nil {
			return err
		}
		in.secs[i].dst = dst
	}
	return nil
}

// appendSyms appends the input symbols in order and records their output
// indices.
func (out *linkerOutput) appendSyms(in *linkerInput) error {
	in.symMap = make([]uint32, len(in.elf.Symbols))
	for i := 1; i < len(in.elf.Symbols); i++ {
		if err := out.appendSym(in, i); err != nil {
			return err
		}
	}
	return nil
}

// appendSym appends input symbol i. A symbol in a skipped section is dropped,
// and an output section keeps one STT_SECTION symbol. Global, weak and extern
// symbols need a BTF description, except in .jumptables. Resolving globals
// against other objects belongs to multi-object linking.
func (out *linkerOutput) appendSym(in *linkerInput, i int) error {
	sym := &in.elf.Symbols[i]
	inSection := sym.SectionIndex != elf.SHN_UNDEF && sym.SectionIndex < elf.SHN_LORESERVE
	needBTF := sym.Bind != elf.STB_LOCAL
	dst := 0

	if sym.SectionIndex == elf.SHN_UNDEF && in.btf == nil {
		return linkerErrorf(unix.ENOTSUP, "externs without BTF info are not supported")
	}
	if inSection {
		src := in.secs[sym.SectionIndex]
		if src.skipped {
			return nil
		}
		dst = src.dst
		if sym.Type == elf.STT_SECTION && dst != 0 && out.secSyms[dst-1] != 0 {
			in.symMap[i] = out.secSyms[dst-1]
			return nil
		}
		if in.elf.Sections[sym.SectionIndex].Name == jumptablesSec {
			needBTF = false
		}
	}
	if needBTF {
		if _, _, err := in.findGlobSymBTF(sym.Name); err != nil {
			return err
		}
	}

	o := objelf.OutputSymbol{
		Name:    sym.Name,
		Info:    sym.Info,
		Other:   sym.Other,
		Section: sym.SectionIndex,
		Value:   sym.Value,
		Size:    sym.Size,
	}
	if inSection {
		o.Section = elf.SectionIndex(dst)
	}
	if sym.Type == elf.STT_SECTION && dst != 0 {
		o.Value = 0
	}

	out.elf.Symbols = append(out.elf.Symbols, o)
	in.symMap[i] = uint32(len(out.elf.Symbols))
	if sym.Type == elf.STT_SECTION && dst != 0 {
		out.secSyms[dst-1] = in.symMap[i]
	}
	return nil
}

// appendRelos copies the relocation sections whose target is kept, pointing
// them at the output target section and the output symbols.
func (out *linkerOutput) appendRelos(in *linkerInput) error {
	for i := 1; i < len(in.elf.Sections); i++ {
		s := &in.elf.Sections[i]
		if in.secs[i].skipped || s.Type != elf.SHT_REL || in.secs[s.Info].skipped {
			continue
		}

		relos, err := remapRelos(in, s)
		if err != nil {
			return err
		}
		dst, err := out.initSec(s)
		if err != nil {
			return err
		}
		in.secs[i].dst = dst

		sec := &out.elf.Sections[dst-1]
		sec.Info = uint32(in.secs[s.Info].dst)
		sec.Relocs = relos
	}
	return nil
}

// remapRelos rewrites the symbol of each relocation in s to its output index.
// A relocation against a section symbol is allowed in code, and in data only
// as an R_BPF_64_ABS64 pointer to code. libbpf also adds the referenced
// section's output offset to the instruction or the stored pointer; for the
// first object that offset is 0.
func remapRelos(in *linkerInput, s *objelf.Section) ([]objelf.OutputReloc, error) {
	target := &in.elf.Sections[s.Info]
	relos := decodeRelos(s.Data)
	res := make([]objelf.OutputReloc, len(relos))

	for j, r := range relos {
		sym := &in.elf.Symbols[r.sym]
		if sym.Type == elf.STT_SECTION && target.Flags&elf.SHF_EXECINSTR == 0 && !isCodePointer(in, sym, r) {
			return nil, linkerErrorf(unix.EINVAL, "relocation against STT_SECTION in non-exec section is not supported")
		}
		res[j] = objelf.OutputReloc{Offset: r.offset, Symbol: in.symMap[r.sym], Type: r.typ}
	}
	return res, nil
}

// isCodePointer reports whether r stores the address of code in data: an
// R_BPF_64_ABS64 against the section symbol of an executable section.
func isCodePointer(in *linkerInput, sym *objelf.Symbol, r elfRel) bool {
	if r.typ != objelf.R_BPF_64_ABS64 || int(sym.SectionIndex) >= len(in.elf.Sections) {
		return false
	}
	return in.elf.Sections[sym.SectionIndex].Flags&elf.SHF_EXECINSTR != 0
}

// marshal serializes the output with its .BTF and .BTF.ext sections. The
// linker's own section list is not modified, so a failed finalize can be
// retried.
func (out *linkerOutput) marshal() ([]byte, error) {
	final := objelf.Output{
		Sections: slices.Concat(out.elf.Sections, out.btfSections()),
		Symbols:  out.elf.Symbols,
	}
	data, err := objelf.Marshal(&final)
	if err != nil {
		return nil, linkerErrorf(unix.EINVAL, "failed to finalize ELF layout: %v", err)
	}
	return data, nil
}

// btfSections returns the .BTF and .BTF.ext sections, 8-byte aligned. There
// are none when the input has no BTF types besides DATASECs.
//
// .BTF holds the input types and strings after the DATASEC fixup, under the
// header libbpf writes. libbpf rebuilds and deduplicates the BTF, which can
// reorder the string table; this version keeps the input order, so .BTF and
// .BTF.ext have libbpf's sizes but not always its bytes. .BTF.ext is copied
// as it is.
func (out *linkerOutput) btfSections() []objelf.OutputSection {
	if out.btf == nil || !hasNonDatasecTypes(out.btf) {
		return nil
	}

	secs := []objelf.OutputSection{
		{Name: btfSecName, Type: elf.SHT_PROGBITS, Addralign: 8, Data: linkerBTFData(out.btf)},
	}
	if out.btfExt != nil {
		secs = append(secs, objelf.OutputSection{Name: btfExtSecName, Type: elf.SHT_PROGBITS, Addralign: 8, Data: out.btfExt})
	}
	return secs
}

func hasNonDatasecTypes(spec *btf.Spec) bool {
	for id := 1; id < len(spec.Types); id++ {
		if spec.Types[id].Kind != btf.KindDatasec {
			return true
		}
	}
	return false
}

// linkerBTFData lays out spec the way libbpf writes a BTF it built: the
// 32-byte header with no kind layout section, the types, then the strings.
func linkerBTFData(spec *btf.Spec) []byte {
	h := spec.Header
	raw := spec.Raw()
	types := raw[h.HdrLen+h.TypeOff:][:h.TypeLen]
	strs := raw[h.HdrLen+h.StrOff:][:h.StrLen]

	le := binary.LittleEndian
	b := make([]byte, 0, btfHdrLen+len(types)+len(strs))
	b = le.AppendUint16(b, h.Magic)
	b = append(b, h.Version, 0)
	b = le.AppendUint32(b, btfHdrLen)
	b = le.AppendUint32(b, 0)                  // type_off
	b = le.AppendUint32(b, uint32(len(types))) // type_len
	b = le.AppendUint32(b, uint32(len(types))) // str_off
	b = le.AppendUint32(b, uint32(len(strs)))  // str_len
	b = le.AppendUint32(b, 0)                  // layout_off
	b = le.AppendUint32(b, 0)                  // layout_len
	b = append(b, types...)
	return append(b, strs...)
}

// readFD reads the whole file behind fd from offset 0, without moving the
// file offset.
func readFD(fd int) ([]byte, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, err
	}

	data := make([]byte, st.Size)
	for off := 0; off < len(data); {
		n, err := unix.Pread(fd, data[off:], int64(off))
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return data[:off], nil
		}
		off += n
	}
	return data, nil
}

// writeFD sets the size of the file behind fd to len(data) and writes data
// from offset 0, like libelf's ELF_C_WRITE update.
func writeFD(fd int, data []byte) error {
	if err := unix.Ftruncate(fd, int64(len(data))); err != nil {
		return err
	}
	for off := 0; off < len(data); {
		n, err := unix.Pwrite(fd, data[off:], int64(off))
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return unix.EIO
		}
		off += n
	}
	return nil
}
