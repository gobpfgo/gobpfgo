// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

// Package bpf is the thin object layer over libbpf.
//
// It is built last. The core libbpf package remains the 1:1 layer; this
// package will expose Object, Program, Map and Link wrappers with Go
// lifetimes and errors. A method here forwards one core call plus naming,
// lifetime or error context.
package bpf
