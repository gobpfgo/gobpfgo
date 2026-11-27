// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: perf_event_open_tracepoint, perf_event_kprobe_open_legacy, perf_event_uprobe_open_legacy, determine_tracepoint_id, gen_probe_legacy_event_name, perf_event_open_probe, determine_uprobe_perf_type, determine_uprobe_retprobe_bit, parse_uint_from_file

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

// The uprobe PMU takes the reference counter offset in the upper 32 bits of
// config.
const (
	perfUprobeRefCtrOffsetBits  = 32
	perfUprobeRefCtrOffsetShift = 32
)

var (
	attachSeq    uint64
	tracefsRoots = []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}

	// uprobePMUDir is the sysfs directory of the uprobe perf PMU, which
	// holds its type and the config bit that selects a uretprobe.
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

func (e *legacyEvent) remove() error {
	return appendTracefs(e.root, e.probeFile(), fmt.Sprintf("-:%s/%s\n", e.group(), e.name))
}

// probeEventName returns a unique, sanitized event name. libbpf uses the same
// shape, libbpf_<pid>_<seq>_<label>; the gobpfgo prefix keeps the events
// apart.
func probeEventName(label string) string {
	seq := atomic.AddUint64(&attachSeq, 1)
	name := fmt.Sprintf("gobpfgo_%d_%d_%s", os.Getpid(), seq, label)
	if len(name) > maxEventNameLen-1 {
		name = name[:maxEventNameLen-1]
	}
	return sanitizeEventName(name)
}

// sanitizeEventName replaces every byte tracefs does not accept in an event
// name, matching libbpf's isalnum rule.
func sanitizeEventName(name string) string {
	b := []byte(name)
	for i, c := range b {
		if !isEventNameByte(c) {
			b[i] = '_'
		}
	}
	return string(b)
}

func isEventNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// appendTracefs appends one command to a tracefs control file.
func appendTracefs(root, file, line string) error {
	f, err := os.OpenFile(filepath.Join(root, file), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(line)
	return err
}

// tracefsRoot returns the tracefs mount that has the probe control files.
func tracefsRoot() (string, error) {
	var statErr error

	for _, root := range tracefsRoots {
		_, err := os.Stat(filepath.Join(root, "kprobe_events"))
		if err == nil {
			return root, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			statErr = err
		}
	}
	if statErr != nil {
		return "", statErr
	}
	return "", &Error{
		Op:    "tracefs",
		Errno: unix.ENOENT,
		Log:   "tracefs kprobe_events not found",
	}
}

// tracepointID reads the tracepoint id from the tracefs events directory.
func tracepointID(category, name string) (int, error) {
	root, err := tracefsRoot()
	if err != nil {
		return 0, err
	}
	path := filepath.Join(root, "events", category, name, "id")
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

// perfEventOpenUprobe opens a uprobe or uretprobe at offset in the file at
// path through the uprobe perf PMU. Unlike the tracefs path, the PMU takes a
// reference counter: a nonzero refCtrOffset is the file offset of a USDT
// semaphore that the kernel increments in every process the uprobe is
// installed in, and decrements when the event is closed.
//
// A refCtrOffset that does not fit in 32 bits is EINVAL, checked before
// anything else. A kernel without the uprobe PMU, or without its retprobe bit
// for a uretprobe, is EOPNOTSUPP. pid -1 opens the event for every process on
// CPU 0, and a pid of 0 or more for that process on every CPU. Any other
// negative pid is passed as -1 for every CPU, which perf_event_open rejects.
func perfEventOpenUprobe(retprobe bool, path string, offset uint64, pid int, refCtrOffset uint64) (int, error) {
	if refCtrOffset >= 1<<perfUprobeRefCtrOffsetBits {
		return -1, unix.EINVAL
	}

	perfType, err := determineUprobePerfType()
	if err != nil {
		return -1, err
	}
	var retprobeBit uint32
	if retprobe {
		if retprobeBit, err = determineUprobeRetprobeBit(); err != nil {
			return -1, err
		}
	}

	attr := uprobePerfEventAttr(perfType, retprobe, retprobeBit, offset, refCtrOffset)
	cpu := -1
	if pid == -1 {
		cpu = 0
	}
	if pid < 0 {
		pid = -1
	}
	return sys.PerfEventOpenUprobe(&attr, path, pid, cpu)
}

// uprobePerfEventAttr builds the perf event attribute of a uprobe PMU event
// with the given PMU type and retprobe bit. Config carries the retprobe bit
// and the reference counter offset in its upper 32 bits, and Ext2, the
// kernel's config2, the probe offset; sys.PerfEventOpenUprobe sets Ext1,
// config1, to the path.
func uprobePerfEventAttr(perfType uint32, retprobe bool, retprobeBit uint32, offset, refCtrOffset uint64) unix.PerfEventAttr {
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

// determineUprobePerfType reads the type of the uprobe perf PMU. A kernel
// without the PMU is EOPNOTSUPP.
func determineUprobePerfType() (uint32, error) {
	return parseUprobePMUFile("type", "")
}

// determineUprobeRetprobeBit reads the config bit that turns a uprobe PMU
// event into a uretprobe. The sysfs format file says "config:<bit>". A kernel
// without the file is EOPNOTSUPP.
func determineUprobeRetprobeBit() (uint32, error) {
	return parseUprobePMUFile(filepath.Join("format", "retprobe"), "config:")
}

// parseUprobePMUFile reads the number in a file of the uprobe PMU's sysfs
// directory; a missing file means the kernel lacks the feature.
func parseUprobePMUFile(name, prefix string) (uint32, error) {
	file := filepath.Join(uprobePMUDir, name)
	v, err := parseUintFromFile(file, prefix)
	if errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("%s does not exist: %w", file, unix.EOPNOTSUPP)
	}
	return v, err
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
