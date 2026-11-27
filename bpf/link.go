// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package bpf

import "github.com/gobpfgo/gobpfgo/libbpf"

// Link is an attached program, returned by the Program attach methods or by
// OpenLink.
//
// The Link owns the core link and is independent of the Object: closing the
// Object neither detaches nor destroys it, and the kernel keeps the attached
// program alive. The caller must call Destroy, which detaches the program
// and releases the link. Methods with an error result return the core
// *libbpf.Error unchanged; only UpdateProgram adds ErrClosed.
type Link struct {
	link *libbpf.BpfLink
}

// newLink wraps the core link of a successful attach and returns err
// unchanged when the attach failed.
func newLink(link *libbpf.BpfLink, err error) (*Link, error) {
	if err != nil {
		return nil, err
	}
	return &Link{link: link}, nil
}

// OpenLink opens the link pinned at path on bpffs, such as one pinned by
// another process. The Link belongs to no Object; the caller owns it and must
// call Destroy, which closes the descriptor and leaves the pin on bpffs. A
// failure returns the core *libbpf.Error unchanged.
func OpenLink(path string) (*Link, error) {
	return newLink(libbpf.BpfLinkOpen(path))
}

// live returns the core link, or nil for a nil Link, which the core treats
// as an invalid or absent link.
func (l *Link) live() *libbpf.BpfLink {
	if l == nil {
		return nil
	}
	return l.link
}

// FD returns the link descriptor, or -1 after Detach or Destroy. A kprobe or
// uprobe attached through tracefs returns its perf event descriptor.
func (l *Link) FD() int {
	return libbpf.BpfLinkFD(l.live())
}

// PinPath returns the bpffs path set by Pin or OpenLink, or an empty string
// when the link is not pinned.
func (l *Link) PinPath() string {
	return libbpf.BpfLinkPinPath(l.live())
}

// Pin pins the link at path on bpffs. Destroy does not remove the pin; Unpin
// does.
func (l *Link) Pin(path string) error {
	return libbpf.BpfLinkPin(l.live(), path)
}

// Unpin removes the link's bpffs pin. It returns EINVAL when the link is not
// pinned.
func (l *Link) Unpin() error {
	return libbpf.BpfLinkUnpin(l.live())
}

// UpdateProgram replaces the program attached through the link with p. It
// returns ErrClosed when p's Object is closed and the core *libbpf.Error
// otherwise: EINVAL for an unloaded program or a link without a BPF link
// descriptor, and EOPNOTSUPP from the kernel when the link type cannot be
// updated. The Link does not keep p or its Object.
func (l *Link) UpdateProgram(p *Program) error {
	if p.isClosed() {
		return ErrClosed
	}
	return libbpf.BpfLinkUpdateProgram(l.live(), p.live())
}

// Detach detaches the program and releases the link's descriptors. The Link
// stays valid until Destroy; a second Detach is a no-op.
func (l *Link) Detach() error {
	return libbpf.BpfLinkDetach(l.live())
}

// Disconnect makes Destroy release the Link without detaching the program or
// closing its descriptor, for an attachment that must outlive the Link, such
// as a pinned one. Detach still detaches. It is a no-op on a nil or destroyed
// Link.
func (l *Link) Disconnect() {
	libbpf.BpfLinkDisconnect(l.live())
}

// Destroy detaches the program, unless Disconnect was called, and releases
// the link. It is idempotent and safe on a nil Link. A pinned link stays on
// bpffs.
func (l *Link) Destroy() {
	libbpf.BpfLinkDestroy(l.live())
}
