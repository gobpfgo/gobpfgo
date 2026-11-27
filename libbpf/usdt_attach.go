// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/usdt.c
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_program__attach_usdt, usdt_manager_new, usdt_manager_attach_usdt, collect_usdt_targets, allocate_spec_id, bpf_link_usdt_detach

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"github.com/gobpfgo/gobpfgo/internal/usdt"
	"golang.org/x/sys/unix"
)

// The maps usdt.bpf.h adds to every object that includes it, and the sizes
// of their keys and values.
const (
	usdtSpecsMapName = "__bpf_usdt_specs"
	usdtIPMapName    = "__bpf_usdt_ip_to_spec_id"

	usdtSpecIDSize = 4
	usdtIPSize     = 8
)

// usdtRefCtrPath exists when the kernel updates USDT semaphores for uprobes.
const usdtRefCtrPath = "/sys/bus/event_source/devices/uprobe/format/ref_ctr_offset"

// BpfUsdtOpts are the optional settings of BpfProgramAttachUsdt.
type BpfUsdtOpts struct {
	// UsdtCookie is a value the program reads with bpf_usdt_cookie. It is
	// the same for every call site of the attachment. USDT attachment uses
	// the BPF cookie itself, so the program cannot use
	// bpf_get_attach_cookie for its own value.
	UsdtCookie uint64
}

// usdtManager is the USDT state of one object: its spec and IP maps, the
// spec IDs it handed out and the kernel features it probed. It is created by
// the first BpfProgramAttachUsdt on the object.
type usdtManager struct {
	specsMap *BpfMap
	ipMap    *BpfMap

	// freeSpecIDs are spec IDs released by destroyed links, reused from the
	// end; nextFreeSpecID is the lowest ID never handed out.
	freeSpecIDs    []int32
	nextFreeSpecID uint32

	hasBpfCookie   bool
	hasSemaRefcnt  bool
	hasUprobeMulti bool
}

// usdtTarget is one call site to attach: its runtime address for the IP map,
// the file offsets of the probe and its semaphore, and its spec.
type usdtTarget struct {
	absIP   uint64
	relIP   uint64
	semaOff uint64
	specStr string
	spec    []byte
}

// usdtLink is the state of a link returned by BpfProgramAttachUsdt: one uprobe
// multi link or one uprobe per call site, the runtime addresses it put in the
// IP map, and the spec IDs it allocated.
type usdtLink struct {
	man       *usdtManager
	specIDs   []int32
	ips       []uint64
	multiLink *BpfLink
	uprobes   []*BpfLink
}

// BpfProgramAttachUsdt attaches a loaded program to every call site of the
// USDT provider:name in the ELF executable or shared library binaryPath, and
// returns one link for all of them. The caller releases it with
// BpfLinkDestroy, which detaches every call site and frees the spec IDs and IP
// map entries the link used. pid -1 traces every process, 0 the calling
// process, and a positive pid that process.
//
// The program's object must include libbpf's usdt.bpf.h, whose
// __bpf_usdt_specs and __bpf_usdt_ip_to_spec_id maps hold the argument specs
// that bpf_usdt_arg reads; without them the call returns ESRCH. Each distinct
// argument spec of the probe gets a spec ID and an entry in the spec map.
// When the kernel has uprobe multi links, the program is loaded for them and
// all call sites are attached through one link, with the spec IDs as BPF
// cookies. Otherwise each call site gets its own uprobe, attached like
// BpfProgramAttachUprobeOpts in ProbeAttachModeDefault. With BPF cookies the
// uprobe carries the spec ID as its cookie through a BPF perf link. Without
// them the program finds the spec ID by instruction address, and the call
// writes the runtime address of each call site to the IP map; for a shared
// library that address comes from the load base in /proc/<pid>/maps, so pid
// -1 returns EOPNOTSUPP on such kernels.
//
// A call site with a semaphore passes its file offset to the kernel as the
// uprobe's reference counter, so the semaphore stays raised in the traced
// processes while the link exists. The uprobe multi link takes one counter
// per call site, zero for a call site without a semaphore, and a single
// uprobe takes it through the uprobe perf PMU. A kernel that does not count
// USDT semaphores returns EOPNOTSUPP for a probe that has one.
//
// A binaryPath without a slash is searched for as in
// BpfProgramAttachUprobeOpts, and a name that is not found is ENOENT.
//
// The returned link has no descriptor: BpfLinkFD returns -1, and pinning
// returns EOPNOTSUPP. Errors carry the errno of the failing step: EINVAL for
// an unloaded program or an empty path, ENOENT for a missing file or probe,
// EBADF for an unsupported ELF file, ESRCH for an address outside the
// expected segment, E2BIG when the spec map is full, and the kernel errno of
// a failed map update or attach.
func BpfProgramAttachUsdt(prog *BpfProgram, pid int, binaryPath, provider, name string, opts *BpfUsdtOpts) (*BpfLink, error) {
	const op = "bpf_program__attach_usdt"
	if err := checkAttachProgram(prog, op); err != nil {
		return nil, err
	}
	if binaryPath == "" || prog.obj == nil {
		return nil, attachErr(op, unix.EINVAL)
	}
	if opts == nil {
		opts = &BpfUsdtOpts{}
	}
	if !strings.Contains(binaryPath, "/") {
		resolved, err := resolveFullPath(binaryPath)
		if err != nil {
			return nil, &Error{Op: op, Errno: errnoFromError(err), Path: binaryPath, Log: err.Error()}
		}
		binaryPath = resolved
	}

	man, err := objectUsdtManager(prog.obj)
	if err != nil {
		return nil, err
	}
	link, err := man.attach(prog, pid, binaryPath, provider, name, opts.UsdtCookie)
	if err != nil {
		return nil, &Error{Op: op, Errno: errnoFromError(err), Path: binaryPath, Log: err.Error()}
	}
	return link, nil
}

// objectUsdtManager returns the object's USDT manager, creating it on first
// use. A failed creation is remembered and returned again.
func objectUsdtManager(obj *BpfObject) (*usdtManager, error) {
	if obj.usdtManErr != nil {
		return nil, obj.usdtManErr
	}
	if obj.usdtMan == nil {
		man, err := newUsdtManager(obj)
		if err != nil {
			obj.usdtManErr = err
			return nil, err
		}
		obj.usdtMan = man
	}
	return obj.usdtMan, nil
}

// newUsdtManager finds the usdt.bpf.h maps of obj and probes the kernel
// features the attach path depends on. Missing maps are ESRCH; maps whose key
// or value size differs from usdt.bpf.h's are EINVAL, because the spec bytes
// would not fit them.
func newUsdtManager(obj *BpfObject) (*usdtManager, error) {
	const op = "usdt_manager_new"

	specs := BpfObjectFindMapByName(obj, usdtSpecsMapName)
	ips := BpfObjectFindMapByName(obj, usdtIPMapName)
	if specs == nil || ips == nil {
		return nil, &Error{Op: op, Errno: unix.ESRCH, Log: "no USDT support maps; the object must include usdt.bpf.h"}
	}
	if specs.keySize != usdtSpecIDSize || specs.valueSize != usdt.SpecSize ||
		ips.keySize != usdtIPSize || ips.valueSize != usdtSpecIDSize {
		return nil, &Error{Op: op, Errno: unix.EINVAL, Log: fmt.Sprintf(
			"USDT maps have key/value sizes %d/%d and %d/%d, want %d/%d and %d/%d",
			specs.keySize, specs.valueSize, ips.keySize, ips.valueSize,
			usdtSpecIDSize, usdt.SpecSize, usdtIPSize, usdtSpecIDSize)}
	}

	return &usdtManager{
		specsMap:       specs,
		ipMap:          ips,
		hasBpfCookie:   featBpfCookie.supported(),
		hasSemaRefcnt:  unix.Faccessat(unix.AT_FDCWD, usdtRefCtrPath, unix.F_OK, unix.AT_EACCESS) == nil,
		hasUprobeMulti: featUprobeMultiLink.supported(),
	}, nil
}

// attach collects the call sites of provider:name in path and attaches prog
// to them. On failure it releases everything it set up.
func (man *usdtManager) attach(prog *BpfProgram, pid int, path, provider, name string, cookie uint64) (*BpfLink, error) {
	f, err := usdt.Open(path)
	if err != nil {
		return nil, err
	}

	if pid < 0 {
		pid = -1
	} else if pid == 0 {
		pid = os.Getpid()
	}

	targets, err := man.collectTargets(f, path, pid, provider, name, cookie)
	if err != nil {
		return nil, err
	}

	ul := &usdtLink{man: man}
	link := &BpfLink{fd: -1, perfFD: -1, usdt: ul}
	if err := man.attachTargets(prog, ul, pid, path, targets); err != nil {
		BpfLinkDestroy(link)
		return nil, err
	}
	return link, nil
}

// collectTargets turns every note of provider:name into a target: the file
// offsets of the probe and its semaphore, the runtime address the IP map
// needs, and the spec bytes with cookie.
func (man *usdtManager) collectTargets(f *usdt.File, path string, pid int, provider, name string, cookie uint64) ([]usdtTarget, error) {
	if len(f.Segments) == 0 {
		return nil, fmt.Errorf("%s has no PT_LOAD program headers: %w", path, unix.ESRCH)
	}
	probes, err := f.Find(provider, name)
	if err != nil {
		return nil, err
	}

	var targets []usdtTarget
	var mapped []usdt.Segment
	for _, p := range probes {
		t := usdtTarget{absIP: f.Address(p.Note), specStr: p.Args}
		if t.relIP, err = f.LocationOffset(p.Note); err != nil {
			return nil, err
		}

		// Without BPF cookies the program looks the spec ID up by its
		// runtime address, which for a shared library depends on where
		// the process mapped it.
		if f.Type == elf.ET_DYN && !man.hasBpfCookie {
			if pid < 0 {
				return nil, fmt.Errorf("attaching to a shared library without a PID needs BPF cookies: %w", unix.EOPNOTSUPP)
			}
			if mapped == nil {
				if mapped, err = usdt.ProcessSegments(pid, path); err != nil {
					return nil, err
				}
			}
			seg, ok := usdt.FindMappedSegment(mapped, t.relIP)
			if !ok {
				return nil, fmt.Errorf("%s:%s at offset %#x is not mapped in PID %d: %w", provider, name, t.relIP, pid, unix.ESRCH)
			}
			t.absIP = seg.Start - seg.Offset + t.relIP
		}

		if p.Semaphore != 0 {
			if !man.hasSemaRefcnt {
				return nil, fmt.Errorf("kernel does not count USDT semaphores for %s:%s: %w", provider, name, unix.EOPNOTSUPP)
			}
			if t.semaOff, err = f.SemaphoreOffset(p.Note); err != nil {
				return nil, err
			}
		}

		if t.spec, err = usdt.MarshalSpec(p.Spec, cookie); err != nil {
			return nil, err
		}
		targets = append(targets, t)
	}
	return targets, nil
}

// attachTargets gives every target a spec ID, writes the new specs and, without
// BPF cookies, the IP map entries, and attaches the program. Everything it
// sets up is recorded in ul as it goes, so destroying ul's link undoes it.
func (man *usdtManager) attachTargets(prog *BpfProgram, ul *usdtLink, pid int, path string, targets []usdtTarget) error {
	specIDs := make(map[string]int32)
	multi := &BpfUprobeMultiOpts{}

	for i, t := range targets {
		id, isNew, err := man.allocateSpecID(specIDs, ul, t.specStr)
		if err != nil {
			return err
		}
		if isNew {
			if err := man.writeSpec(id, t.spec); err != nil {
				return err
			}
		}
		if !man.hasBpfCookie {
			if err := man.mapIP(t.absIP, id); err != nil {
				return err
			}
			ul.ips = append(ul.ips, t.absIP)
		}

		if man.hasUprobeMulti {
			multi.Offsets = append(multi.Offsets, t.relIP)
			multi.RefCtrOffsets = append(multi.RefCtrOffsets, t.semaOff)
			multi.Cookies = append(multi.Cookies, uint64(id))
			continue
		}

		link, err := BpfProgramAttachUprobeOpts(prog, pid, path, t.relIP, man.uprobeOpts(t, id))
		if err != nil {
			return fmt.Errorf("uprobe #%d at offset %#x: %w", i, t.relIP, err)
		}
		ul.uprobes = append(ul.uprobes, link)
	}

	if man.hasUprobeMulti {
		link, err := BpfProgramAttachUprobeMulti(prog, pid, path, "", multi)
		if err != nil {
			return fmt.Errorf("uprobe multi: %w", err)
		}
		ul.multiLink = link
	}
	return nil
}

// uprobeOpts returns the options of the single uprobe at call site t with
// spec ID id: the semaphore offset as the reference counter and, on a kernel
// with BPF cookies, the spec ID as the cookie. Without cookies the program
// finds the spec ID in the IP map instead.
func (man *usdtManager) uprobeOpts(t usdtTarget, id int32) *BpfUprobeOpts {
	opts := &BpfUprobeOpts{RefCtrOffset: t.semaOff}
	if man.hasBpfCookie {
		opts.BpfCookie = uint64(id)
	}
	return opts
}

// allocateSpecID returns the spec ID for a spec string. Within one attachment
// call sites with the same spec string share an ID; a new ID comes from the
// IDs freed by destroyed links, newest first, or else is the next unused one.
// isNew reports an ID whose spec must be written. More IDs than the spec map
// holds are E2BIG.
func (man *usdtManager) allocateSpecID(specIDs map[string]int32, ul *usdtLink, specStr string) (id int32, isNew bool, err error) {
	if id, ok := specIDs[specStr]; ok {
		return id, false, nil
	}

	if n := len(man.freeSpecIDs); n > 0 {
		id = man.freeSpecIDs[n-1]
		man.freeSpecIDs = man.freeSpecIDs[:n-1]
	} else {
		if man.nextFreeSpecID >= man.specsMap.maxEntries {
			return 0, false, fmt.Errorf("all %d USDT spec IDs are in use: %w", man.specsMap.maxEntries, unix.E2BIG)
		}
		id = int32(man.nextFreeSpecID)
		man.nextFreeSpecID++
	}

	specIDs[specStr] = id
	ul.specIDs = append(ul.specIDs, id)
	return id, true, nil
}

// releaseSpecIDs returns a link's spec IDs to the manager for reuse.
func (man *usdtManager) releaseSpecIDs(ids []int32) {
	man.freeSpecIDs = append(man.freeSpecIDs, ids...)
}

// writeSpec stores the spec bytes under spec ID id.
func (man *usdtManager) writeSpec(id int32, spec []byte) error {
	key := make([]byte, usdtSpecIDSize)
	binary.NativeEndian.PutUint32(key, uint32(id))
	if err := sys.MapUpdateElem(man.specsMap.fd, key, spec, BPF_ANY); err != nil {
		return fmt.Errorf("set USDT spec #%d: %w", id, err)
	}
	return nil
}

// mapIP maps a runtime address to spec ID id. An address that is already
// mapped is EEXIST: two attachments cannot share a call site without cookies.
func (man *usdtManager) mapIP(ip uint64, id int32) error {
	key, value := usdtIPKey(ip), make([]byte, usdtSpecIDSize)
	binary.NativeEndian.PutUint32(value, uint32(id))
	err := sys.MapUpdateElem(man.ipMap.fd, key, value, BPF_NOEXIST)
	if errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("IP collision at %#x for spec #%d: %w", ip, id, err)
	}
	if err != nil {
		return fmt.Errorf("map IP %#x to spec #%d: %w", ip, id, err)
	}
	return nil
}

func (man *usdtManager) unmapIP(ip uint64) {
	_ = sys.MapDeleteElem(man.ipMap.fd, usdtIPKey(ip), 0)
}

func usdtIPKey(ip uint64) []byte {
	key := make([]byte, usdtIPSize)
	binary.NativeEndian.PutUint64(key, ip)
	return key
}

// detach destroys the uprobe links, removes the IP map entries the link added
// and returns its spec IDs to the manager. The spec map entries stay: the
// next attachment that gets an ID overwrites its spec. Removing an IP entry
// can only fail when the map is gone, so detach reports no error.
func (ul *usdtLink) detach() {
	BpfLinkDestroy(ul.multiLink)
	ul.multiLink = nil
	for _, link := range ul.uprobes {
		BpfLinkDestroy(link)
	}
	ul.uprobes = nil

	for _, ip := range ul.ips {
		ul.man.unmapIP(ip)
	}
	ul.ips = nil

	ul.man.releaseSpecIDs(ul.specIDs)
	ul.specIDs = nil
}
