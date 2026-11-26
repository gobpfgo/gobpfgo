// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf_probes.c
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: libbpf_probe_bpf_prog_type, libbpf_probe_bpf_map_type, libbpf_probe_bpf_helper, libbpf_num_possible_cpus, probe_prog_load, probe_map_create, get_kernel_version, parse_cpu_mask_file, parse_cpu_mask_str

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// enotsupp is the kernel's ENOTSUPP. linux/errno.h exposes it to the kernel
// only; the value is 524 on every Linux architecture.
const enotsupp = syscall.Errno(524)

// probeProgInsns is the two-instruction program every program-type probe
// loads: return 0; exit. The kernel only has to accept the type and context.
func probeProgInsns() []byte {
	insns := make([]byte, 16)
	insns[0] = 0xb7 // r0 = 0
	insns[8] = 0x95 // exit
	return insns
}

// probeHelperInsns is the two-instruction program the helper probe loads: call
// helper_id; exit.
func probeHelperInsns(helperID BpfFuncID) []byte {
	insns := make([]byte, 16)
	insns[0] = 0x85 // call helper
	binary.NativeEndian.PutUint32(insns[4:], uint32(helperID))
	insns[8] = 0x95 // exit
	return insns
}

// probeProgOpts are the BPF_PROG_LOAD fields the probe sets for a program
// type, plus the expected verifier result for types that cannot load empty.
type probeProgOpts struct {
	expectedAttachType BpfAttachType
	kernVersion        uint32
	progFlags          uint32
	attachBtfID        uint32
	log                bool
	expErr             syscall.Errno
	expMsg             string
}

// LibbpfProbeBpfProgType reports whether the running kernel supports a
// program type. It loads a two-instruction program and returns false when the
// kernel rejects it, including when the process lacks privileges. An unknown
// program type returns EOPNOTSUPP.
func LibbpfProbeBpfProgType(progType BpfProgType) (bool, error) {
	const op = "libbpf_probe_bpf_prog_type"

	supported, err := probeProgLoad(progType, probeProgInsns(), nil)
	if err != nil {
		return false, &Error{Op: op, Errno: errnoFromError(err)}
	}
	return supported == 1, nil
}

// probeProgLoad loads one probe program and applies libbpf's expected result
// for program types whose empty program must fail the verifier.
func probeProgLoad(progType BpfProgType, insns []byte, logBuf []byte) (int, error) {
	opts, err := probeProgOptsFor(progType)
	if err != nil {
		return 0, err
	}
	if opts.log && len(logBuf) == 0 {
		logBuf = make([]byte, 4096)
	}

	attr := &sys.ProgLoadAttr{
		ProgType:           uint32(progType),
		InsnCnt:            uint32(len(insns) / 8),
		KernVersion:        opts.kernVersion,
		ProgFlags:          opts.progFlags,
		ExpectedAttachType: uint32(opts.expectedAttachType),
		AttachBtfID:        opts.attachBtfID,
	}
	if len(logBuf) > 0 {
		attr.LogLevel = 1
	}

	fd, err := sys.ProgLoad(attr, insns, []byte("GPL\x00"), logBuf, nil)
	if err == nil {
		unix.Close(fd)
		if opts.expErr != 0 {
			return 0, nil
		}
		return 1, nil
	}

	errno := errnoFromError(err)
	if opts.expErr == 0 {
		return 0, nil
	}
	if errno != opts.expErr {
		return 0, nil
	}
	if opts.expMsg != "" && !strings.Contains(string(logBuf), opts.expMsg) {
		return 0, nil
	}
	return 1, nil
}

// probeProgOptsFor returns the load options and expected result for a program
// type, or EOPNOTSUPP for a type libbpf does not probe.
func probeProgOptsFor(progType BpfProgType) (probeProgOpts, error) {
	switch progType {
	case BPF_PROG_TYPE_CGROUP_SOCK_ADDR:
		return probeProgOpts{expectedAttachType: BPF_CGROUP_INET4_CONNECT}, nil
	case BPF_PROG_TYPE_CGROUP_SOCKOPT:
		return probeProgOpts{expectedAttachType: BPF_CGROUP_GETSOCKOPT}, nil
	case BPF_PROG_TYPE_SK_LOOKUP:
		return probeProgOpts{expectedAttachType: BPF_SK_LOOKUP}, nil
	case BPF_PROG_TYPE_KPROBE:
		return probeProgOpts{kernVersion: getKernelVersion()}, nil
	case BPF_PROG_TYPE_LIRC_MODE2:
		return probeProgOpts{expectedAttachType: BPF_LIRC_MODE2}, nil
	case BPF_PROG_TYPE_TRACING:
		return probeProgOpts{
			expectedAttachType: BPF_TRACE_FENTRY,
			attachBtfID:        1,
			log:                true,
			expErr:             unix.EINVAL,
			expMsg:             "attach_btf_id 1 is not a function",
		}, nil
	case BPF_PROG_TYPE_LSM:
		return probeProgOpts{
			expectedAttachType: BPF_MODIFY_RETURN,
			attachBtfID:        1,
			log:                true,
			expErr:             unix.EINVAL,
			expMsg:             "attach_btf_id 1 is not a function",
		}, nil
	case BPF_PROG_TYPE_EXT:
		return probeProgOpts{
			attachBtfID: 1,
			log:         true,
			expErr:      unix.EINVAL,
			expMsg:      "Cannot replace kernel functions",
		}, nil
	case BPF_PROG_TYPE_SYSCALL:
		return probeProgOpts{progFlags: BPF_F_SLEEPABLE}, nil
	case BPF_PROG_TYPE_STRUCT_OPS:
		return probeProgOpts{expErr: enotsupp}, nil
	case BPF_PROG_TYPE_NETFILTER:
		return probeProgOpts{expectedAttachType: BPF_NETFILTER}, nil
	case BPF_PROG_TYPE_UNSPEC,
		BPF_PROG_TYPE_SOCKET_FILTER,
		BPF_PROG_TYPE_SCHED_CLS,
		BPF_PROG_TYPE_SCHED_ACT,
		BPF_PROG_TYPE_TRACEPOINT,
		BPF_PROG_TYPE_XDP,
		BPF_PROG_TYPE_PERF_EVENT,
		BPF_PROG_TYPE_CGROUP_SKB,
		BPF_PROG_TYPE_CGROUP_SOCK,
		BPF_PROG_TYPE_LWT_IN,
		BPF_PROG_TYPE_LWT_OUT,
		BPF_PROG_TYPE_LWT_XMIT,
		BPF_PROG_TYPE_SOCK_OPS,
		BPF_PROG_TYPE_SK_SKB,
		BPF_PROG_TYPE_CGROUP_DEVICE,
		BPF_PROG_TYPE_SK_MSG,
		BPF_PROG_TYPE_RAW_TRACEPOINT,
		BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE,
		BPF_PROG_TYPE_LWT_SEG6LOCAL,
		BPF_PROG_TYPE_SK_REUSEPORT,
		BPF_PROG_TYPE_FLOW_DISSECTOR,
		BPF_PROG_TYPE_CGROUP_SYSCTL:
		return probeProgOpts{}, nil
	default:
		return probeProgOpts{}, unix.EOPNOTSUPP
	}
}

// LibbpfProbeBpfHelper reports whether a program type may call a helper. It
// loads a program that calls the helper and treats the verifier's "unknown
// func" and "cannot use helper" messages as unsupported. Tracing, EXT, LSM
// and struct_ops programs cannot be loaded empty, so they return EOPNOTSUPP.
func LibbpfProbeBpfHelper(progType BpfProgType, helperID BpfFuncID) (bool, error) {
	const op = "libbpf_probe_bpf_helper"

	switch progType {
	case BPF_PROG_TYPE_TRACING,
		BPF_PROG_TYPE_EXT,
		BPF_PROG_TYPE_LSM,
		BPF_PROG_TYPE_STRUCT_OPS:
		return false, &Error{Op: op, Errno: unix.EOPNOTSUPP}
	}

	logBuf := make([]byte, 4096)
	supported, err := probeProgLoad(progType, probeHelperInsns(helperID), logBuf)
	if err != nil {
		return false, &Error{Op: op, Errno: errnoFromError(err)}
	}
	if supported == 0 {
		log := string(logBuf)
		if strings.Contains(log, "invalid func ") ||
			strings.Contains(log, "unknown func ") ||
			strings.Contains(log, "program of this type cannot use helper ") {
			return false, nil
		}
	}

	return true, nil
}

// LibbpfProbeBpfMapType reports whether the running kernel supports a map
// type. It creates a one-entry map with libbpf's per-type geometry and
// returns false when the kernel rejects it, including without privileges.
// UNSPEC and unknown types return EOPNOTSUPP.
func LibbpfProbeBpfMapType(mapType BpfMapType) (bool, error) {
	const op = "libbpf_probe_bpf_map_type"

	supported, err := probeMapCreate(mapType)
	if err != nil {
		return false, &Error{Op: op, Errno: errnoFromError(err)}
	}
	return supported == 1, nil
}

// probeMapConfig is the map geometry and the special create options for one
// map type.
type probeMapConfig struct {
	keySize    int
	valueSize  int
	maxEntries int
	opts       *BpfMapCreateOpts
	expErr     syscall.Errno
	storage    bool
	inner      bool
}

// probeMapConfigFor returns libbpf's probe geometry for a map type.
func probeMapConfigFor(mapType BpfMapType) (probeMapConfig, error) {
	cfg := probeMapConfig{keySize: 4, valueSize: 4, maxEntries: 1}

	switch mapType {
	case BPF_MAP_TYPE_STACK_TRACE:
		cfg.valueSize = 8
	case BPF_MAP_TYPE_LPM_TRIE:
		cfg.keySize, cfg.valueSize = 8, 8
		cfg.opts = NewBpfMapCreateOpts()
		cfg.opts.MapFlags = unix.BPF_F_NO_PREALLOC
	case BPF_MAP_TYPE_RHASH:
		cfg.opts = NewBpfMapCreateOpts()
		cfg.opts.MapFlags = unix.BPF_F_NO_PREALLOC
	case BPF_MAP_TYPE_CGROUP_STORAGE, BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE:
		cfg.keySize, cfg.valueSize, cfg.maxEntries = 16, 8, 0
	case BPF_MAP_TYPE_QUEUE, BPF_MAP_TYPE_STACK:
		cfg.keySize = 0
	case BPF_MAP_TYPE_SK_STORAGE, BPF_MAP_TYPE_INODE_STORAGE,
		BPF_MAP_TYPE_TASK_STORAGE, BPF_MAP_TYPE_CGRP_STORAGE:
		cfg.valueSize, cfg.maxEntries = 8, 0
		cfg.storage = true
	case BPF_MAP_TYPE_RINGBUF, BPF_MAP_TYPE_USER_RINGBUF:
		cfg.keySize, cfg.valueSize = 0, 0
		cfg.maxEntries = unix.Getpagesize()
	case BPF_MAP_TYPE_STRUCT_OPS:
		cfg.opts = NewBpfMapCreateOpts()
		cfg.opts.BtfVmlinuxValueTypeID = 1
		cfg.opts.ValueTypeBtfObjFD = -1
		cfg.expErr = enotsupp
	case BPF_MAP_TYPE_BLOOM_FILTER:
		cfg.keySize = 0
	case BPF_MAP_TYPE_ARENA:
		cfg.keySize, cfg.valueSize = 0, 0
		cfg.opts = NewBpfMapCreateOpts()
		cfg.opts.MapFlags = unix.BPF_F_MMAPABLE
	case BPF_MAP_TYPE_INSN_ARRAY:
		cfg.valueSize = 16
	case BPF_MAP_TYPE_HASH, BPF_MAP_TYPE_ARRAY, BPF_MAP_TYPE_PROG_ARRAY,
		BPF_MAP_TYPE_PERF_EVENT_ARRAY, BPF_MAP_TYPE_PERCPU_HASH,
		BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_CGROUP_ARRAY,
		BPF_MAP_TYPE_LRU_HASH, BPF_MAP_TYPE_LRU_PERCPU_HASH,
		BPF_MAP_TYPE_ARRAY_OF_MAPS, BPF_MAP_TYPE_HASH_OF_MAPS,
		BPF_MAP_TYPE_DEVMAP, BPF_MAP_TYPE_DEVMAP_HASH,
		BPF_MAP_TYPE_SOCKMAP, BPF_MAP_TYPE_CPUMAP, BPF_MAP_TYPE_XSKMAP,
		BPF_MAP_TYPE_SOCKHASH, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY:
	case BPF_MAP_TYPE_UNSPEC:
		return probeMapConfig{}, unix.EOPNOTSUPP
	default:
		return probeMapConfig{}, unix.EOPNOTSUPP
	}

	if mapType == BPF_MAP_TYPE_ARRAY_OF_MAPS || mapType == BPF_MAP_TYPE_HASH_OF_MAPS {
		cfg.inner = true
	}
	return cfg, nil
}

// probeMapCreate creates one probe map and returns 1 when the kernel accepts
// it or when it fails with the expected errno, and 0 otherwise.
func probeMapCreate(mapType BpfMapType) (int, error) {
	cfg, err := probeMapConfigFor(mapType)
	if err != nil {
		return 0, err
	}

	btfFD, innerFD := -1, -1
	if cfg.storage {
		btfFD, err = sys.BtfLoad(localStorageBTF(), nil, 0)
		if err != nil {
			return 0, err
		}
		cfg.opts = NewBpfMapCreateOpts()
		cfg.opts.BtfFD = uint32(btfFD)
		cfg.opts.BtfKeyTypeID = 1
		cfg.opts.BtfValueTypeID = 3
		cfg.opts.MapFlags = unix.BPF_F_NO_PREALLOC
	}
	if cfg.inner {
		innerFD, err = BpfMapCreate(BPF_MAP_TYPE_HASH, "", 4, 4, 1, nil)
		if err != nil {
			closeProbeFDs(btfFD, -1)
			return 0, nil
		}
		if cfg.opts == nil {
			cfg.opts = NewBpfMapCreateOpts()
		}
		cfg.opts.InnerMapFD = uint32(innerFD)
	}

	fd, err := BpfMapCreate(mapType, "", uint32(cfg.keySize), uint32(cfg.valueSize), uint32(cfg.maxEntries), cfg.opts)
	errno := syscall.Errno(0)
	if err != nil {
		errno = errnoFromError(err)
	}
	if fd >= 0 {
		unix.Close(fd)
	}
	closeProbeFDs(btfFD, innerFD)

	if cfg.expErr != 0 {
		if fd < 0 && errno == cfg.expErr {
			return 1, nil
		}
		return 0, nil
	}
	if fd >= 0 {
		return 1, nil
	}
	return 0, nil
}

// closeProbeFDs closes the descriptors a map probe opened, ignoring errors.
func closeProbeFDs(btfFD, innerFD int) {
	if btfFD >= 0 {
		unix.Close(btfFD)
	}
	if innerFD >= 0 {
		unix.Close(innerFD)
	}
}

// localStorageBTF returns the raw BTF blob libbpf loads to probe the local
// storage map types: int, struct bpf_spin_lock and struct val.
func localStorageBTF() []byte {
	strs := []byte("\x00bpf_spin_lock\x00val\x00cnt\x00l\x00")

	var types []byte
	appendU32 := func(v uint32) {
		types = binary.NativeEndian.AppendUint32(types, v)
	}

	// int: name_off 0, info INT, size 4, signed 32-bit int data.
	appendU32(0)
	appendU32(1 << 24)
	appendU32(4)
	appendU32(1<<24 | 32)

	// struct bpf_spin_lock { int val; }: one member at bit offset 0.
	appendU32(1)
	appendU32(4<<24 | 1)
	appendU32(4)
	appendU32(15)
	appendU32(1)
	appendU32(0)

	// struct val { int cnt; struct bpf_spin_lock l; }: two members.
	appendU32(15)
	appendU32(4<<24 | 2)
	appendU32(8)
	appendU32(19)
	appendU32(1)
	appendU32(0)
	appendU32(23)
	appendU32(2)
	appendU32(32)

	buf := make([]byte, 24+len(types)+len(strs))
	binary.NativeEndian.PutUint16(buf[0:], 0xeB9F)
	buf[2] = 1
	binary.NativeEndian.PutUint32(buf[4:], 24)
	binary.NativeEndian.PutUint32(buf[8:], 0)
	binary.NativeEndian.PutUint32(buf[12:], uint32(len(types)))
	binary.NativeEndian.PutUint32(buf[16:], uint32(len(types)))
	binary.NativeEndian.PutUint32(buf[20:], uint32(len(strs)))
	copy(buf[24:], types)
	copy(buf[24+len(types):], strs)
	return buf
}

// LibbpfNumPossibleCpus returns the number of possible CPUs, including offline
// ones, like the C library. The result is cached.
func LibbpfNumPossibleCpus() (int, error) {
	const op = "libbpf_num_possible_cpus"

	count := libbpfNumPossibleCPUs()
	if count < 0 {
		return 0, &Error{Op: op, Errno: syscall.Errno(-count)}
	}
	return count, nil
}

// libbpfNumPossibleCPUs returns the number of possible CPUs, or a negative
// errno. The result is cached like the C library's static.
func libbpfNumPossibleCPUs() int {
	if count := atomic.LoadInt32(&possibleCPUs); count > 0 {
		return int(count)
	}

	mask, err := readCPUMaskFile("/sys/devices/system/cpu/possible")
	if err != nil {
		return -int(errnoFromError(err))
	}

	count := 0
	for _, cpu := range mask {
		if cpu {
			count++
		}
	}
	atomic.StoreInt32(&possibleCPUs, int32(count))
	return count
}

// readCPUMaskFile reads a kernel CPU list such as "0-31" or "0,2-3".
func readCPUMaskFile(path string) ([]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCPUMask(string(data))
}

// parseCPUMask parses the comma and newline separated CPU ranges the kernel
// prints in /sys/devices/system/cpu/{possible,online}.
func parseCPUMask(s string) ([]bool, error) {
	var mask []bool

	for _, token := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == ' ' || r == '\t'
	}) {
		start, end, err := parseCPURange(token)
		if err != nil {
			return nil, err
		}
		if end >= len(mask) {
			mask = append(mask, make([]bool, end+1-len(mask))...)
		}
		for cpu := start; cpu <= end; cpu++ {
			mask[cpu] = true
		}
	}
	if len(mask) == 0 {
		return nil, unix.EINVAL
	}
	return mask, nil
}

// parseCPURange parses "N" or "N-M".
func parseCPURange(s string) (int, int, error) {
	parts := strings.Split(s, "-")
	if len(parts) > 2 {
		return 0, 0, unix.EINVAL
	}

	start, err := strconv.Atoi(parts[0])
	if err != nil || start < 0 {
		return 0, 0, unix.EINVAL
	}
	end := start
	if len(parts) == 2 {
		end, err = strconv.Atoi(parts[1])
		if err != nil || end < start {
			return 0, 0, unix.EINVAL
		}
	}
	return start, end, nil
}

// getKernelVersion returns the KERNEL_VERSION value of the running kernel,
// preferring the Ubuntu version_signature and the Debian utsname version.
func getKernelVersion() uint32 {
	if version := ubuntuKernelVersion(); version != 0 {
		return version
	}

	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return 0
	}

	version := unix.ByteSliceToString(uts.Version[:])
	if parsed := debianKernelVersion(version); parsed != 0 {
		return parsed
	}
	return parseKernelVersion(unix.ByteSliceToString(uts.Release[:]))
}

// ubuntuKernelVersion parses /proc/version_signature when present.
func ubuntuKernelVersion() uint32 {
	data, err := os.ReadFile("/proc/version_signature")
	if err != nil {
		return 0
	}
	fields := strings.Fields(string(data))
	if len(fields) == 0 {
		return 0
	}
	return parseKernelVersion(fields[len(fields)-1])
}

// debianKernelVersion parses the "Debian X.Y.Z" part of utsname.version. The
// Debian form may carry only two components, in which case patch is zero.
func debianKernelVersion(version string) uint32 {
	const marker = "Debian "

	index := strings.Index(version, marker)
	if index < 0 {
		return 0
	}
	rest := version[index+len(marker):]
	if parsed := parseKernelVersion(rest); parsed != 0 {
		return parsed
	}

	var major, minor uint32
	count, err := fmt.Sscanf(rest, "%d.%d", &major, &minor)
	if err != nil || count != 2 {
		return 0
	}
	return major<<16 | minor<<8
}

// parseKernelVersion parses "major.minor.patch" and returns KERNEL_VERSION.
func parseKernelVersion(s string) uint32 {
	var major, minor, patch uint32

	count, err := fmt.Sscanf(s, "%d.%d.%d", &major, &minor, &patch)
	if err != nil || count != 3 {
		return 0
	}
	return major<<16 | minor<<8 | patch
}

// possibleCPUs caches libbpf_num_possible_cpus; zero means not read yet.
var possibleCPUs int32
