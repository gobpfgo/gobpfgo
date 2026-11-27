// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/linker.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_linker__new, bpf_linker__new_fd, bpf_linker__add_file, bpf_linker__add_fd, bpf_linker__add_buf, bpf_linker__finalize, bpf_linker__free, init_output_elf, add_new_sym, bpf_linker_add_file

package libbpf

import (
	"debug/elf"
	"errors"
	"fmt"
	"slices"

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
// Objects are merged in the order they are added. Sections with the same name
// are concatenated at their alignment, and symbol values, relocation offsets,
// BTF DATASEC entries and .BTF.ext records move with them. Global symbols are
// resolved by name: a strong definition replaces a weak one, two strong
// definitions are an error, and the first of several weak definitions wins.
// Local symbols are kept. The input BTF type tables are concatenated with
// their type IDs remapped, and the output BTF is deduplicated: identical
// types from different objects become one, forward declarations resolve to
// their definitions, and the .BTF.ext records follow the new type IDs.
//
// An extern, an undefined global or weak symbol whose BTF VAR or FUNC has
// extern linkage, such as one in the .extern DATASEC, is resolved by name
// against the definitions of the other objects, in either order. Its BTF
// must match the definition's. The output symbol becomes the definition and
// every relocation against the extern follows it; a strong extern makes a
// weak definition strong. The extern's BTF VAR becomes allocated and its FUNC
// global with the definition's parameter names. An extern in .extern or in
// no DATASEC that no object defines, strong or weak, stays an undefined
// symbol with extern BTF and is left out of every DATASEC; finalizing does
// not fail, and opening such an object fails later because the extern has
// no DATASEC.
//
// An extern in any other DATASEC without an ELF section, such as .kconfig or
// .ksyms, is left for the loader. It stays an undefined symbol, strong if
// any object declares it strong, with extern BTF, and the output keeps its
// DATASEC, of size 0, listing each such extern once with the offset and size
// of its first declaration. The DATASEC follows the sections the inputs had
// before it. No ELF section is written for it unless an input has one of
// that name: an object that defines a map provides .maps for another
// object's extern map, which then resolves like any extern.
//
// DWARF, the input string tables, .llvm_addrsig, an empty .text and the .BTF
// and .BTF.ext relocations are dropped.
//
// Create a linker with BpfLinkerNew or BpfLinkerNewFD, add the objects, write
// the output with BpfLinkerFinalize and release the linker with
// BpfLinkerFree. A linker is not safe for concurrent use.
type BpfLinker struct {
	filename  string
	fd        int
	fdIsOwned bool
	writable  bool
	inputs    []linkerSource
	out       *linkerOutput
}

// linkerSource is an object added to the linker: a name for errors and a copy
// of its bytes.
type linkerSource struct {
	name string
	data []byte
}

// linkerOutput is the object being built from the inputs. secs holds the
// sections in the order they were added, starting with .strtab and .symtab;
// secs[i] is at position i+1, which is also its ELF index until an ephemeral
// section, which has none, comes before it. elfSecCnt counts the sections
// with an ELF index. syms[i] is the symbol with index i+1. globSyms holds the
// global and weak symbols by name; globIdx indexes it.
type linkerOutput struct {
	secs      []*linkerSec
	elfSecCnt int
	syms      []objelf.OutputSymbol
	globSyms  []linkerGlobSym
	globIdx   map[string]int
	btf       *linkerBTF
}

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

// BpfLinkerAddFile reads the relocatable BPF object at filename and merges it
// into the output. It returns EINVAL after BpfLinkerFinalize or
// BpfLinkerFree, the open or read errno, EINVAL for a malformed object or a
// conflict with the objects already added, such as two strong definitions of
// one symbol, two sections of one name with different types or flags, or an
// extern whose BTF does not match its definition, ENOTSUP for an extern in
// an object without BTF, and EOPNOTSUPP for an object the linker cannot
// handle, such as a big-endian one. A failed add leaves the linker
// unchanged.
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

// BpfLinkerAddFD merges the relocatable BPF object read from fd, starting at
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

// BpfLinkerAddBuf merges the relocatable BPF object in buf. The linker keeps
// its own copy, so buf may be reused after the call. Errors are those of
// BpfLinkerAddFile.
func BpfLinkerAddBuf(l *BpfLinker, buf []byte, opts *BpfLinkerFileOpts) error {
	const op = "bpf_linker__add_buf"
	if err := l.canAdd(op); err != nil {
		return err
	}
	return l.add(op, fmt.Sprintf("mem:%d", len(buf)), buf)
}

// BpfLinkerFinalize writes the linked object and closes the output
// descriptor if the linker owns it. Further adds and finalizes return EINVAL.
// A layout or write failure returns EINVAL with the reason in Log; the linker
// stays usable, so the call can be retried.
func BpfLinkerFinalize(l *BpfLinker) error {
	const op = "bpf_linker__finalize"
	if l == nil || !l.writable {
		return &Error{Op: op, Errno: unix.EINVAL}
	}

	data, err := l.out.finalize()
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
	l.inputs = nil
	l.out = nil
}

// canAdd rejects an add after finalize or free.
func (l *BpfLinker) canAdd(op string) error {
	if l == nil || !l.writable {
		return &Error{Op: op, Errno: unix.EINVAL}
	}
	return nil
}

// add merges one more object. The C library merges into its output in place
// and leaves it half-updated when an object fails. To keep a failed add from
// changing the linker, the output is rebuilt from every object added so far
// plus the new one, and replaces the old output only on success. The earlier
// objects linked before and linking is deterministic, so only the new object
// can fail.
func (l *BpfLinker) add(op, name string, data []byte) error {
	sources := append(slices.Clone(l.inputs), linkerSource{name: name, data: slices.Clone(data)})

	out := newLinkerOutput()
	for _, src := range sources {
		in, err := linkerLoadObj(src.name, src.data)
		if err == nil {
			err = out.addObject(in)
		}
		if err != nil {
			return linkerFail(op, src.name, err)
		}
	}

	l.inputs = sources
	l.out = out
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
// section names, and .symtab, an empty BTF and no symbols besides the null
// one. Like libbpf, .symtab keeps sh_info at 0 instead of one past the last
// local symbol.
func newLinkerOutput() *linkerOutput {
	out := &linkerOutput{globIdx: make(map[string]int), btf: newLinkerBTF()}
	out.addSec(&linkerSec{name: ".strtab", typ: elf.SHT_STRTAB, flags: elf.SHF_STRINGS, addralign: 1})
	out.addSec(&linkerSec{name: ".symtab", typ: elf.SHT_SYMTAB, addralign: 8})
	return out
}

// addObject runs the merge steps for one loaded object in libbpf's order:
// sections, symbols, relocations, BTF, then .BTF.ext.
func (out *linkerOutput) addObject(in *linkerInput) error {
	steps := []func(*linkerInput) error{
		out.appendSecData,
		out.appendSyms,
		out.appendRelos,
		out.appendBTF,
		out.appendBTFExt,
	}
	for _, step := range steps {
		if err := step(in); err != nil {
			return err
		}
	}
	return nil
}

// addSym appends s and returns its symbol index.
func (out *linkerOutput) addSym(s objelf.OutputSymbol) uint32 {
	out.syms = append(out.syms, s)
	return uint32(len(out.syms))
}

// sym returns the output symbol with index idx.
func (out *linkerOutput) sym(idx uint32) *objelf.OutputSymbol {
	return &out.syms[idx-1]
}

// finalize serializes the output with its .BTF and .BTF.ext sections. It does
// not change the output, so a failed finalize can be retried.
func (out *linkerOutput) finalize() ([]byte, error) {
	btfSecs, err := out.finalizeBTF()
	if err != nil {
		return nil, err
	}

	final := objelf.Output{Symbols: out.syms}
	for _, s := range out.elfSecs() {
		final.Sections = append(final.Sections, s.output())
	}
	final.Sections = append(final.Sections, btfSecs...)

	data, err := objelf.Marshal(&final)
	if err != nil {
		return nil, linkerErrorf(unix.EINVAL, "failed to finalize ELF layout: %v", err)
	}
	return data, nil
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
