// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_program__attach_kprobe, bpf_program__attach_perf_event_opts, bpf_link__fd, bpf_link__detach, bpf_link__destroy

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/sys/unix"
)

// BpfLink is an attached program. It owns the perf event descriptor and the
// tracefs kprobe event; BpfLinkDestroy releases both.
type BpfLink struct {
	perfFD    int
	probe     *kprobeEvent
	detached  bool
	destroyed bool
}

// perfEventAttrSize is sizeof(struct perf_event_attr) on 64-bit Linux. An
// older kernel accepts the current size as long as the bytes past its own
// struct size are zero, which the zeroed Go struct guarantees.
const perfEventAttrSize = 128

// maxEventNameLen is the tracefs event name limit, including the terminator.
const maxEventNameLen = 64

var (
	kprobeAttachSeq uint64
	tracefsRoots    = []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}
)

// BpfLinkFD returns the perf event descriptor, or -1 when the link has been
// detached or destroyed.
func BpfLinkFD(link *BpfLink) int {
	if link == nil || link.detached || link.destroyed {
		return -1
	}
	return link.perfFD
}

// BpfLinkDetach detaches the program from the kprobe event.
//
// It disables the perf event, closes the descriptor and removes the tracefs
// event. The link stays allocated until BpfLinkDestroy. A second call is a
// no-op; when a step fails, Detach still releases what it can and returns the
// first error.
func BpfLinkDetach(link *BpfLink) error {
	if link == nil || link.detached {
		return nil
	}

	var firstErr error
	if link.perfFD >= 0 {
		if err := unix.IoctlSetInt(link.perfFD, unix.PERF_EVENT_IOC_DISABLE, 0); err != nil {
			firstErr = err
		}
		// libbpf closes the perf event before removing the kprobe event.
		unix.Close(link.perfFD)
		link.perfFD = -1
	}
	if link.probe != nil {
		if err := link.probe.remove(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	link.detached = true
	return firstErr
}

// BpfLinkDestroy detaches the link if needed and releases its memory. It is
// idempotent and safe on a nil link.
func BpfLinkDestroy(link *BpfLink) {
	if link == nil || link.destroyed {
		return
	}

	_ = BpfLinkDetach(link)
	link.destroyed = true
}

// BpfProgramAttachKprobe attaches a loaded program to funcName on every CPU.
// retprobe selects a kretprobe instead of a kprobe.
//
// The call creates a tracefs event under the kprobes or kretprobes group and
// one perf event, then attaches the program with PERF_EVENT_IOC_SET_BPF. The
// caller must release the link with BpfLinkDestroy. Root or CAP_BPF plus write
// access to tracefs is required; the call returns an *Error with the kernel
// errno when the tracefs or perf setup fails, and removes a partially created
// event.
func BpfProgramAttachKprobe(prog *BpfProgram, retprobe bool, funcName string) (*BpfLink, error) {
	if prog == nil || prog.fd < 0 || funcName == "" {
		return nil, &Error{Op: "bpf_program__attach_kprobe", Errno: unix.EINVAL}
	}

	root, err := tracefsRoot()
	if err != nil {
		return nil, err
	}

	probe := newKprobeEvent(root, funcName, retprobe)
	if err := probe.add(funcName); err != nil {
		return nil, attachError(err)
	}
	id, err := probe.id()
	if err != nil {
		_ = probe.remove()
		return nil, attachError(err)
	}
	fd, err := openTracepoint(id)
	if err != nil {
		_ = probe.remove()
		return nil, attachError(err)
	}

	link := &BpfLink{perfFD: fd, probe: probe}
	if err := attachPerfEvent(fd, prog.fd); err != nil {
		BpfLinkDestroy(link)
		return nil, attachError(err)
	}
	return link, nil
}

func attachError(err error) error {
	return &Error{
		Op:    "bpf_program__attach_kprobe",
		Errno: errnoFromError(err),
		Log:   err.Error(),
	}
}

// tracefsRoot returns the tracefs mount that has kprobe_events. The second
// path is the debugfs compatibility mount.
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
		Op:    "bpf_program__attach_kprobe",
		Errno: unix.ENOENT,
		Log:   "tracefs kprobe_events not found",
	}
}

// kprobeEvent is one event in the tracefs kprobe_events file and its sysfs id.
type kprobeEvent struct {
	root     string
	group    string
	name     string
	retprobe bool
}

func newKprobeEvent(root, funcName string, retprobe bool) *kprobeEvent {
	group := "kprobes"
	if retprobe {
		group = "kretprobes"
	}
	return &kprobeEvent{
		root:     root,
		group:    group,
		name:     kprobeEventName(funcName),
		retprobe: retprobe,
	}
}

// add writes the probe to kprobe_events. The kernel accepts a trailing newline
// and an explicit zero offset, the same form libbpf writes.
func (e *kprobeEvent) add(funcName string) error {
	prefix := byte('p')
	if e.retprobe {
		prefix = 'r'
	}
	line := fmt.Sprintf("%c:%s/%s %s+0x0\n", prefix, e.group, e.name, funcName)
	return appendTracefs(e.root, line)
}

// id reads the tracepoint id the kernel assigned to the event.
func (e *kprobeEvent) id() (int, error) {
	path := filepath.Join(e.root, "events", e.group, e.name, "id")
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	id, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("kprobe %s/%s: invalid id: %w", e.group, e.name, err)
	}
	if id <= 0 {
		return 0, fmt.Errorf("kprobe %s/%s: id %d", e.group, e.name, id)
	}
	return id, nil
}

func (e *kprobeEvent) remove() error {
	return appendTracefs(e.root, fmt.Sprintf("-:%s/%s\n", e.group, e.name))
}

// kprobeEventName returns a unique, sanitized event name. libbpf uses the same
// shape, libbpf_<pid>_<seq>_<function>_0x<offset>; the gobpfgo prefix keeps
// the events apart.
func kprobeEventName(funcName string) string {
	seq := atomic.AddUint64(&kprobeAttachSeq, 1)
	name := fmt.Sprintf("gobpfgo_%d_%d_%s", os.Getpid(), seq, funcName)
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

// appendTracefs appends one command to kprobe_events under the tracefs root.
func appendTracefs(root, line string) error {
	f, err := os.OpenFile(filepath.Join(root, "kprobe_events"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(line)
	return err
}

// openTracepoint opens the perf event for a tracepoint id.
//
// libbpf opens one event with pid -1 and CPU 0 for kprobes and tracepoints:
// the perf event is a handle, and the kernel invokes the attached program on
// every CPU.
func openTracepoint(id int) (int, error) {
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_TRACEPOINT,
		Size:   perfEventAttrSize,
		Config: uint64(id),
	}
	return unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
}

func attachPerfEvent(perfFD, progFD int) error {
	if err := unix.IoctlSetInt(perfFD, unix.PERF_EVENT_IOC_SET_BPF, progFD); err != nil {
		return err
	}
	return unix.IoctlSetInt(perfFD, unix.PERF_EVENT_IOC_ENABLE, 0)
}
