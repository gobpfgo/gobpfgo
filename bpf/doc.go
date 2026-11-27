// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

// Package bpf is the thin object layer over libbpf.
//
// The core libbpf package is the 1:1 port, with free functions over opaque
// types. This package wraps the same objects in four types with methods:
// Object, Program, Map and Link. Each method forwards one core call and adds
// only naming and lifetime checks; core errors are returned unchanged as
// *libbpf.Error, and the core option types are used as they are.
//
// Ownership follows the core:
//
//   - An Object owns the core object, opened with OpenFile or OpenMem. Load
//     creates the kernel maps and programs; Close releases them and is
//     idempotent.
//   - Programs and Maps belong to their Object and own nothing. Object.Programs
//     and Object.Maps list them in the core's order, and they and Object.Program
//     and Object.Map return the same values for the life of the Object. After
//     Close, their methods with an error result return ErrClosed, and their
//     accessors return a zero value, -1 for a descriptor.
//   - A Link, returned by a Program attach method or by OpenLink, is owned by
//     the caller and is independent of the Object: closing the Object does not
//     detach it. Destroy releases it and is idempotent.
//
// A typical use:
//
//	obj, err := bpf.OpenFile("kprobe.bpf.o", nil)
//	if err != nil {
//		return err
//	}
//	defer obj.Close()
//	if err := obj.Load(); err != nil {
//		return err
//	}
//	link, err := obj.Program("handle_open").AttachKprobe(false, "do_sys_openat2")
//	if err != nil {
//		return err
//	}
//	defer link.Destroy()
//
// The layer adds no locking, finalizers or hidden state beyond the wrapper
// cache, the core pointers and the closed flag. ErrClosed is its only error.
package bpf
