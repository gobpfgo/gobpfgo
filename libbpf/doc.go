// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

// Package libbpf parses BPF ELF objects and manages their maps and programs
// in pure Go.
//
// An object is opened from a file or a memory buffer and inspected without
// touching the kernel: the ELF sections, the BTF types, the BTF-defined maps
// and the program sections are parsed into Go values. The load step will use
// the same object model to create maps and programs and keep their descriptors
// in the object.
//
// Errors are *Error values that preserve the kernel errno. An object is not
// safe for concurrent use.
//
// The header of every source file records the libbpf source, commit and
// symbols it was translated from, or gobpfgo-origin for original code. The
// godocs describe the Go API, its ownership and its limits.
package libbpf
