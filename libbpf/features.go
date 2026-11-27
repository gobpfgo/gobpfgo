// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/features.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: probe_kern_bpf_cookie, probe_uprobe_multi_link, feat_supported

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"sync"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// kernelFeature is one kernel capability the loader probes on first use. The
// result is kept for the life of the process, like libbpf's global feature
// cache; a probe that cannot run, for example without privileges, reports the
// feature as missing.
type kernelFeature struct {
	once  sync.Once
	ok    bool
	probe func() bool
}

func (f *kernelFeature) supported() bool {
	f.once.Do(func() {
		f.ok = f.probe()
	})
	return f.ok
}

var (
	// featBpfCookie is the BPF cookie capability behind
	// LINUX_HAS_BPF_COOKIE and the USDT spec ID lookup.
	featBpfCookie = kernelFeature{probe: probeBpfCookie}
	// featUprobeMultiLink is a uprobe multi link with process PID
	// filtering, which USDT attachment uses for all call sites at once.
	featUprobeMultiLink = kernelFeature{probe: probeUprobeMultiLink}
)

// probeBpfCookie reports whether a program can read a BPF cookie: the kernel
// loads a tracepoint program that calls bpf_get_attach_cookie, and accepts a
// BPF perf link, the path that carries the cookie to a single probe. libbpf
// probes the helper alone; both arrived in Linux 5.15, so the result is the
// same on upstream kernels.
func probeBpfCookie() bool {
	attr := &sys.ProgLoadAttr{
		ProgType: uint32(BPF_PROG_TYPE_TRACEPOINT),
		InsnCnt:  2,
	}
	fd, err := sys.ProgLoad(attr, probeHelperInsns(BPF_FUNC_get_attach_cookie), []byte("GPL\x00"), nil, nil, nil)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return perfLinkSupported()
}

// probeUprobeMultiLink reports whether the kernel creates uprobe multi links
// and filters them by process. A two-instruction program loaded for the link
// is attached to "/", which a kernel with the link type rejects with EBADF.
// The first kernels with the link filtered by thread instead of process; the
// fixed ones reject PID -1 with EINVAL before looking at the path. Without
// the fix the feature is reported missing, as USDT attachment picks the link
// at load time and only learns the PID at attach time.
func probeUprobeMultiLink() bool {
	attr := &sys.ProgLoadAttr{
		ProgType:           uint32(BPF_PROG_TYPE_KPROBE),
		InsnCnt:            2,
		ExpectedAttachType: uint32(BPF_TRACE_UPROBE_MULTI),
	}
	progFD, err := sys.ProgLoad(attr, probeProgInsns(), []byte("GPL\x00"), nil, nil, nil)
	if err != nil {
		return false
	}
	defer unix.Close(progFD)

	if !uprobeMultiProbeFails(progFD, 0, unix.EBADF) {
		return false
	}
	return uprobeMultiProbeFails(progFD, ^uint32(0), unix.EINVAL)
}

// uprobeMultiProbeFails creates a uprobe multi link on "/" at offset 0 for
// pid and reports whether the kernel rejected it with want.
func uprobeMultiProbeFails(progFD int, pid uint32, want unix.Errno) bool {
	attr := &sys.LinkCreateAttr{
		ProgFD:     uint32(progFD),
		TargetFD:   ^uint32(0),
		AttachType: uint32(BPF_TRACE_UPROBE_MULTI),
	}
	um := &sys.LinkUprobeMulti{Path: "/", Offsets: []uint64{0}, PID: pid}
	linkFD, err := sys.LinkCreateUprobeMulti(attr, um)
	if err == nil {
		unix.Close(linkFD)
		return false
	}
	return errors.Is(err, want)
}
