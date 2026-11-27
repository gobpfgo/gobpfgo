// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: perf_event_open_tracepoint, perf_event_kprobe_open_legacy, perf_event_uprobe_open_legacy, determine_tracepoint_id, gen_probe_legacy_event_name, remove_kprobe_event_legacy, remove_uprobe_event_legacy, append_to_file, use_debugfs, tracefs_path, perf_event_open_probe, determine_kprobe_perf_type, determine_uprobe_perf_type, determine_kprobe_retprobe_bit, determine_uprobe_retprobe_bit, parse_uint_from_file

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// perfEventAttrSize is sizeof(struct perf_event_attr) on 64-bit Linux. An
// older kernel accepts the current size as long as the bytes past its own
// struct size are zero, which the zeroed Go struct guarantees.
const perfEventAttrSize = 128

// maxEventNameLen is the tracefs event name limit, including the terminator.
const maxEventNameLen = 64

// maxTracefsCommandLen is the size of libbpf's append_to_file buffer: a
// tracefs command must be shorter, leaving room for the terminator.
const maxTracefsCommandLen = 1024

// The uprobe PMU takes the reference counter offset in the upper 32 bits of
// config.
const (
	perfUprobeRefCtrOffsetBits  = 32
	perfUprobeRefCtrOffsetShift = 32
)

var (
	// attachSeq numbers the tracefs probe events of the process, as the
	// static index of libbpf's gen_probe_legacy_event_name does: from 0,
	// and wrapping to negative numbers like the C int.
	attachSeq atomic.Int32

	// debugfsTracingDir and tracefsDir are libbpf's DEBUGFS and TRACEFS,
	// the two places tracefsRoot chooses from.
	debugfsTracingDir = "/sys/kernel/debug/tracing"
	tracefsDir        = "/sys/kernel/tracing"

	// kprobePMUDir and uprobePMUDir are the sysfs directories of the
	// kprobe and uprobe perf PMUs, which hold the PMU type and the config
	// bit that selects a return probe.
	kprobePMUDir = "/sys/bus/event_source/devices/kprobe"
	uprobePMUDir = "/sys/bus/event_source/devices/uprobe"

	perfLinkProbe struct {
		once sync.Once
		ok   bool
	}
)

// legacyProbeKind selects the tracefs probe file and event group.
type legacyProbeKind int

const (
	probeKprobe legacyProbeKind = iota
	probeKretprobe
	probeUprobe
	probeUretprobe
)

// legacyEvent is one event in the tracefs kprobe_events or uprobe_events file
// and its sysfs id.
type legacyEvent struct {
	root string
	kind legacyProbeKind
	name string
}

func (e *legacyEvent) probeFile() string {
	switch e.kind {
	case probeUprobe, probeUretprobe:
		return "uprobe_events"
	default:
		return "kprobe_events"
	}
}

func (e *legacyEvent) group() string {
	switch e.kind {
	case probeKretprobe:
		return "kretprobes"
	case probeUprobe:
		return "uprobes"
	case probeUretprobe:
		return "uretprobes"
	default:
		return "kprobes"
	}
}

// add appends a completed event definition line to the probe file.
func (e *legacyEvent) add(line string) error {
	return appendTracefs(e.root, e.probeFile(), line)
}

// id reads the tracepoint id the kernel assigned to the event.
func (e *legacyEvent) id() (int, error) {
	path := filepath.Join(e.root, "events", e.group(), e.name, "id")
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	id, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("%s %s/%s: invalid id: %w", e.probeFile(), e.group(), e.name, err)
	}
	if id <= 0 {
		return 0, fmt.Errorf("%s %s/%s: id %d", e.probeFile(), e.group(), e.name, id)
	}
	return id, nil
}

// open adds the event with its definition line and opens its perf event for
// pid, as in probePidCPU. The caller owns the event and the perf descriptor;
// on failure the event is removed again.
func (e *legacyEvent) open(line string, pid int) (int, error) {
	if err := e.add(line); err != nil {
		return -1, err
	}

	pfd := -1
	id, err := e.id()
	if err == nil {
		perfPid, cpu := probePidCPU(pid)
		pfd, err = openTracepointPerf(id, perfPid, cpu)
	}
	if err != nil {
		_ = e.remove()
		return -1, err
	}
	return pfd, nil
}

// remove deletes the event from the probe file.
func (e *legacyEvent) remove() error {
	return appendTracefs(e.root, e.probeFile(), fmt.Sprintf("-:%s/%s", e.group(), e.name))
}

// probeEventName returns the name of a new tracefs probe event on name, a
// kernel function or the end of a binary path, at offset, numbered by
// attachSeq; see legacyEventName.
func probeEventName(name string, offset uint64) string {
	return legacyEventName(os.Getpid(), attachSeq.Add(1)-1, name, offset)
}

// legacyEventName builds a tracefs probe event name the way libbpf's
// gen_probe_legacy_event_name does: libbpf_<pid>_<seq>_<name>_0x<offset>,
// cut to maxEventNameLen-1 bytes, with every byte that is not an ASCII letter
// or digit replaced by '_'.
func legacyEventName(pid int, seq int32, name string, offset uint64) string {
	b := fmt.Appendf(nil, "libbpf_%d_%d_%s_0x%x", pid, seq, name, offset)
	if len(b) > maxEventNameLen-1 {
		b = b[:maxEventNameLen-1]
	}
	for i, c := range b {
		if !isAlnum(c) {
			b[i] = '_'
		}
	}
	return string(b)
}

// isAlnum is isalnum in the C locale.
func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// appendTracefs appends one command to a tracefs control file in a single
// write, as libbpf's append_to_file does: the command is written as given,
// with no newline added, and a command of maxTracefsCommandLen bytes or more
// is EINVAL before the file is opened.
func appendTracefs(root, file, line string) error {
	if len(line) >= maxTracefsCommandLen {
		return unix.EINVAL
	}
	f, err := os.OpenFile(filepath.Join(root, file), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(line)
	return err
}

// tracefsRoot returns the tracefs directory, chosen as libbpf's tracefs_path
// does: the tracing directory under debugfs when it exists for the effective
// IDs, and the tracefs mount otherwise. Neither has to hold the probe control
// files; a missing one fails when it is opened. libbpf decides once per
// process, while tracefsRoot checks again on every call.
func tracefsRoot() string {
	if unix.Faccessat(unix.AT_FDCWD, debugfsTracingDir, unix.F_OK, unix.AT_EACCESS) == nil {
		return debugfsTracingDir
	}
	return tracefsDir
}

// tracepointID reads the tracepoint id from the tracefs events directory.
func tracepointID(category, name string) (int, error) {
	path := filepath.Join(tracefsRoot(), "events", category, name, "id")
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	id, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("tracepoint %s/%s: invalid id: %w", category, name, err)
	}
	if id <= 0 {
		return 0, fmt.Errorf("tracepoint %s/%s: id %d", category, name, id)
	}
	return id, nil
}

// openTracepointPerf opens the perf event for a tracepoint id. libbpf opens
// one event with pid -1 and CPU 0 for kprobes, tracepoints and uprobes that
// apply to every process; a uprobe for one process uses that pid and every
// CPU (cpu -1).
func openTracepointPerf(id, pid, cpu int) (int, error) {
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_TRACEPOINT,
		Size:   perfEventAttrSize,
		Config: uint64(id),
	}
	return unix.PerfEventOpen(&attr, pid, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
}

// probePidCPU returns the perf_event_open pid and cpu of a probe for pid: -1
// probes every process on CPU 0, and a pid of 0 or more probes that process
// on every CPU. Any other negative pid becomes pid -1 on every CPU, which
// perf_event_open rejects. A kprobe is always opened for pid -1.
func probePidCPU(pid int) (int, int) {
	switch {
	case pid == -1:
		return -1, 0
	case pid < 0:
		return -1, -1
	default:
		return pid, -1
	}
}

// perfEventOpenProbe opens a probe through the kprobe perf PMU, or the uprobe
// perf PMU when uprobe is set, and returns the perf event descriptor, which
// the caller owns. retprobe selects a kretprobe or uretprobe.
//
// For a kprobe, name is the kernel function and offset the offset into it;
// an empty name probes the raw kernel address in offset. For a uprobe, name
// is the file and offset the file offset. Only the uprobe PMU takes a
// reference counter: a nonzero refCtrOffset is the file offset of a USDT
// semaphore that the kernel increments in every process the uprobe is
// installed in, and decrements when the event is closed.
//
// A refCtrOffset that does not fit in 32 bits is EINVAL, checked before
// anything else. A missing PMU type file, or retprobe format file for a
// return probe, is ENOENT. The pid selects the processes as in probePidCPU.
func perfEventOpenProbe(uprobe, retprobe bool, name string, offset uint64, pid int, refCtrOffset uint64) (int, error) {
	if refCtrOffset >= 1<<perfUprobeRefCtrOffsetBits {
		return -1, unix.EINVAL
	}

	determineType, determineRetprobeBit := determineKprobePerfType, determineKprobeRetprobeBit
	if uprobe {
		determineType, determineRetprobeBit = determineUprobePerfType, determineUprobeRetprobeBit
	}
	perfType, err := determineType()
	if err != nil {
		return -1, err
	}
	var retprobeBit uint32
	if retprobe {
		if retprobeBit, err = determineRetprobeBit(); err != nil {
			return -1, err
		}
	}

	attr := probePerfEventAttr(perfType, retprobe, retprobeBit, offset, refCtrOffset)
	perfPid, cpu := probePidCPU(pid)
	if uprobe {
		return sys.PerfEventOpenUprobe(&attr, name, perfPid, cpu)
	}
	return sys.PerfEventOpenKprobe(&attr, name, perfPid, cpu)
}

// probePerfEventAttr builds the perf event attribute of a kprobe or uprobe PMU
// event with the given PMU type and retprobe bit. Config carries the retprobe
// bit and the reference counter offset in its upper 32 bits, and Ext2, the
// kernel's config2, the probe offset or a kprobe's raw address. The sys open
// call sets Ext1, config1, to the function name or path.
func probePerfEventAttr(perfType uint32, retprobe bool, retprobeBit uint32, offset, refCtrOffset uint64) unix.PerfEventAttr {
	attr := unix.PerfEventAttr{
		Type:   perfType,
		Size:   perfEventAttrSize,
		Config: refCtrOffset << perfUprobeRefCtrOffsetShift,
		Ext2:   offset,
	}
	if retprobe {
		attr.Config |= 1 << retprobeBit
	}
	return attr
}

// determineKprobePerfType reads the type of the kprobe perf PMU. A kernel
// without the PMU has no type file, which is ENOENT.
func determineKprobePerfType() (uint32, error) {
	return parseUintFromFile(filepath.Join(kprobePMUDir, "type"), "")
}

// determineUprobePerfType reads the type of the uprobe perf PMU. A kernel
// without the PMU has no type file, which is ENOENT.
func determineUprobePerfType() (uint32, error) {
	return parseUintFromFile(filepath.Join(uprobePMUDir, "type"), "")
}

// determineKprobeRetprobeBit reads the config bit that turns a kprobe PMU
// event into a kretprobe. The sysfs format file says "config:<bit>"; a kernel
// without it is ENOENT.
func determineKprobeRetprobeBit() (uint32, error) {
	return parseUintFromFile(filepath.Join(kprobePMUDir, "format", "retprobe"), "config:")
}

// determineUprobeRetprobeBit reads the config bit that turns a uprobe PMU
// event into a uretprobe. The sysfs format file says "config:<bit>"; a kernel
// without it is ENOENT.
func determineUprobeRetprobeBit() (uint32, error) {
	return parseUintFromFile(filepath.Join(uprobePMUDir, "format", "retprobe"), "config:")
}

// parseUintFromFile reads the decimal number in [0, 2^31-1] that follows
// prefix at the start of file. As with scanf's %d, white space before the
// number is skipped and the number ends at the first byte that is not a
// digit. A file without such a number is EIO.
func parseUintFromFile(file, prefix string) (uint32, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return 0, err
	}
	text, ok := strings.CutPrefix(string(data), prefix)
	text = strings.TrimLeft(text, " \t\n")
	digits := text[:len(text)-len(strings.TrimLeft(text, "0123456789"))]
	v, parseErr := strconv.ParseUint(digits, 10, 31)
	if !ok || parseErr != nil {
		return 0, fmt.Errorf("%s: no number in %q: %w", file, data, unix.EIO)
	}
	return uint32(v), nil
}

// perfLinkSupported reports whether BPF_LINK_CREATE accepts BPF_PERF_EVENT.
// It probes once with a two-instruction tracepoint program and an invalid
// perf event descriptor: EBADF means the link type is supported, EINVAL means
// the kernel predates it and the ioctl path must be used.
func perfLinkSupported() bool {
	perfLinkProbe.once.Do(func() {
		const progType = uint32(BPF_PROG_TYPE_TRACEPOINT)
		insns := []byte{
			0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r0 = 0
			0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit
		}
		license := []byte("GPL\x00")
		attr := &sys.ProgLoadAttr{ProgType: progType, InsnCnt: 2}

		progFD, err := sys.ProgLoad(attr, insns, license, nil, nil, nil, nil)
		if err != nil {
			return
		}
		defer unix.Close(progFD)

		linkAttr := &sys.LinkCreateAttr{
			ProgFD:     uint32(progFD),
			TargetFD:   ^uint32(0),
			AttachType: uint32(BPF_PERF_EVENT),
		}
		linkFD, err := sys.LinkCreate(linkAttr, nil)
		if err == nil {
			unix.Close(linkFD)
			perfLinkProbe.ok = true
			return
		}
		perfLinkProbe.ok = errors.Is(err, unix.EBADF)
	})
	return perfLinkProbe.ok
}
