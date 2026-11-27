// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-source: src/bpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_link__fd, bpf_link__pin, bpf_link__unpin, bpf_link__open, bpf_link__update_program, bpf_link__detach, bpf_link__disconnect, bpf_link__destroy

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"os"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// BpfLink is an attached program. It owns either a BPF link descriptor or,
// for the tracefs probe path, a perf event descriptor and the tracefs event.
// A USDT link owns the links of its call sites instead and has no descriptor.
// BpfLinkDestroy releases them.
type BpfLink struct {
	fd           int
	perfFD       int
	legacy       *legacyEvent
	usdt         *usdtLink
	pinPath      string
	disconnected bool
	detached     bool
	destroyed    bool
}

// BpfLinkFD returns the link descriptor, or -1 when the link has been detached
// or destroyed. For a link created through the tracefs probe path, this is the
// perf event descriptor, matching the path that created it. A USDT link has no
// descriptor of its own and returns -1.
func BpfLinkFD(link *BpfLink) int {
	if link == nil || link.detached || link.destroyed || link.usdt != nil {
		return -1
	}
	return link.fd
}

// BpfLinkPinPath returns the bpffs path the link is pinned at, or an empty
// string when it is not pinned.
func BpfLinkPinPath(link *BpfLink) string {
	if link == nil {
		return ""
	}
	return link.pinPath
}

// BpfLinkDetach detaches the program and releases the descriptors the link
// owns. The link stays allocated until BpfLinkDestroy. A second call is a
// no-op; when a step fails, Detach still releases what it can and returns the
// first error.
func BpfLinkDetach(link *BpfLink) error {
	if link == nil || link.detached {
		return nil
	}

	var firstErr error
	switch {
	case link.usdt != nil:
		link.usdt.detach()
	case link.legacy != nil:
		if err := unix.IoctlSetInt(link.fd, unix.PERF_EVENT_IOC_DISABLE, 0); err != nil {
			firstErr = err
		}
		unix.Close(link.fd)
		if err := link.legacy.remove(); err != nil && firstErr == nil {
			firstErr = err
		}
	case link.perfFD >= 0 && link.perfFD != link.fd:
		// A BPF link owns a separate perf event descriptor.
		if err := unix.IoctlSetInt(link.perfFD, unix.PERF_EVENT_IOC_DISABLE, 0); err != nil {
			firstErr = err
		}
		unix.Close(link.perfFD)
		unix.Close(link.fd)
	case link.fd >= 0:
		// A BPF link, or a perf event attached with the ioctl path.
		if link.perfFD >= 0 {
			if err := unix.IoctlSetInt(link.fd, unix.PERF_EVENT_IOC_DISABLE, 0); err != nil {
				firstErr = err
			}
		}
		unix.Close(link.fd)
	}

	link.fd = -1
	link.perfFD = -1
	link.detached = true
	return firstErr
}

// BpfLinkDisconnect marks the link so BpfLinkDestroy does not detach the
// underlying kernel resource. It is used when the program has to outlive the
// userspace process, for example after the link is pinned.
func BpfLinkDisconnect(link *BpfLink) {
	if link == nil || link.destroyed {
		return
	}
	link.disconnected = true
}

// BpfLinkDestroy detaches the link unless it is disconnected and releases its
// memory. It is idempotent and safe on a nil link. A pinned link stays in
// bpffs; destroy only forgets the pin path, matching the C library.
func BpfLinkDestroy(link *BpfLink) {
	if link == nil || link.destroyed {
		return
	}

	if !link.disconnected {
		_ = BpfLinkDetach(link)
	}
	link.destroyed = true
}

// BpfLinkPin pins the link at path on bpffs.
//
// A link that is already pinned returns EBUSY. The parent directory must
// exist on a BPF filesystem. The caller can drop the link and reopen it with
// BpfLinkOpen; destroy does not unpin it. A USDT link has no descriptor to
// pin and returns EOPNOTSUPP.
func BpfLinkPin(link *BpfLink, path string) error {
	if link != nil && link.usdt != nil {
		return &Error{Op: "bpf_link__pin", Errno: unix.EOPNOTSUPP}
	}
	if link == nil || link.destroyed || link.detached || link.fd < 0 || path == "" {
		return &Error{Op: "bpf_link__pin", Errno: unix.EINVAL}
	}
	if link.pinPath != "" {
		return &Error{Op: "bpf_link__pin", Errno: unix.EBUSY, Path: path}
	}

	if err := sys.ObjPin(link.fd, path, 0); err != nil {
		return &Error{Op: "bpf_link__pin", Errno: errnoFromError(err), Path: path}
	}
	link.pinPath = path
	return nil
}

// BpfLinkUnpin removes the link's bpffs path and clears the pin path. It
// returns EINVAL when the link is not pinned.
func BpfLinkUnpin(link *BpfLink) error {
	if link == nil {
		return &Error{Op: "bpf_link__unpin", Errno: unix.EINVAL}
	}
	if link.pinPath == "" {
		return &Error{Op: "bpf_link__unpin", Errno: unix.EINVAL}
	}

	path := link.pinPath
	if err := os.Remove(path); err != nil {
		return &Error{Op: "bpf_link__unpin", Errno: errnoFromError(err), Path: path}
	}
	link.pinPath = ""
	return nil
}

// BpfLinkOpen opens a link pinned at path and returns its descriptor. The
// caller must release it with BpfLinkDestroy.
func BpfLinkOpen(path string) (*BpfLink, error) {
	if path == "" {
		return nil, &Error{Op: "bpf_link__open", Errno: unix.EINVAL}
	}

	fd, err := sys.ObjGet(path, 0)
	if err != nil {
		return nil, &Error{Op: "bpf_link__open", Errno: errnoFromError(err), Path: path}
	}
	return &BpfLink{fd: fd, perfFD: -1, pinPath: path}, nil
}

// BpfLinkUpdateProgram replaces the program attached through the link. It
// returns EINVAL when the program is not loaded or the link is not a BPF link;
// the kernel reports EOPNOTSUPP when the link type cannot be updated.
func BpfLinkUpdateProgram(link *BpfLink, prog *BpfProgram) error {
	if link == nil || link.destroyed || link.detached || link.fd < 0 {
		return &Error{Op: "bpf_link__update_program", Errno: unix.EINVAL}
	}
	if prog == nil || prog.fd < 0 {
		return &Error{Op: "bpf_link__update_program", Errno: unix.EINVAL}
	}

	attr := &sys.LinkUpdateAttr{
		LinkFD:    uint32(link.fd),
		NewProgFD: uint32(prog.fd),
	}
	if err := sys.LinkUpdate(attr); err != nil {
		return &Error{Op: "bpf_link__update_program", Errno: errnoFromError(err)}
	}
	return nil
}
