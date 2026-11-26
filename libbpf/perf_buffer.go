// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: perf_buffer__new, perf_buffer__free, perf_buffer__poll, perf_buffer__consume, perf_buffer__consume_buffer, perf_buffer__buffer_cnt, perf_buffer__buffer_fd, perf_buffer__buffer, perf_buffer__epoll_fd, libbpf_num_possible_cpus, parse_cpu_mask_file, parse_cpu_mask_str

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"errors"
	"syscall"

	"github.com/gobpfgo/gobpfgo/internal/mmap"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// PerfBufferSampleFunc is called for each PERF_RECORD_SAMPLE. cpu is the CPU
// that produced the record. data aliases the ring and must be copied to be
// retained.
type PerfBufferSampleFunc func(ctx any, cpu int, data []byte)

// PerfBufferLostFunc is called when the kernel reports dropped records. cpu is
// the CPU and lost is the number of records the kernel discarded.
type PerfBufferLostFunc func(ctx any, cpu int, lost uint64)

// PerfBufferOpts are the options of PerfBufferNew. SamplePeriod sets how many
// samples the kernel batches before it wakes the reader; zero means one.
type PerfBufferOpts struct {
	SamplePeriod uint32
}

// PerfBuffer reads a BPF_MAP_TYPE_PERF_EVENT_ARRAY map through one perf event
// ring per online CPU. The map descriptor stays owned by the caller.
type PerfBuffer struct {
	sampleFn PerfBufferSampleFunc
	lostFn   PerfBufferLostFunc
	ctx      any
	pageSize int
	mmapSize int
	mapFD    int
	epollFD  int
	cpuBufs  []*perfBufferCPUBuf
	events   []unix.EpollEvent
	freed    bool
}

// perfBufferCPUBuf is one CPU's perf event descriptor and mapping. base holds
// the metadata page followed by the data ring.
type perfBufferCPUBuf struct {
	base   []byte
	data   []byte
	copy   []byte
	fd     int
	cpu    int
	mapKey int
}

// PerfBufferNew creates a reader for mapFD, which must be a
// BPF_MAP_TYPE_PERF_EVENT_ARRAY map, and opens one perf event per online CPU.
// pageCnt is the data ring size in pages and must be a power of two. sampleFn
// and lostFn may be nil. The map descriptor stays owned by the caller.
func PerfBufferNew(mapFD int, pageCnt int, sampleFn PerfBufferSampleFunc, lostFn PerfBufferLostFunc, ctx any, opts *PerfBufferOpts) (*PerfBuffer, error) {
	const op = "perf_buffer__new"
	if mapFD < 0 || pageCnt <= 0 || pageCnt&(pageCnt-1) != 0 {
		return nil, &Error{Op: op, Errno: unix.EINVAL}
	}

	samplePeriod := uint32(1)
	if opts != nil && opts.SamplePeriod != 0 {
		samplePeriod = opts.SamplePeriod
	}

	maxEntries, err := perfBufferMapEntries(mapFD)
	if err != nil {
		return nil, &Error{Op: op, Errno: errnoFromError(err)}
	}

	pageSize := unix.Getpagesize()
	pb := &PerfBuffer{
		sampleFn: sampleFn,
		lostFn:   lostFn,
		ctx:      ctx,
		pageSize: pageSize,
		mmapSize: pageSize * pageCnt,
		mapFD:    mapFD,
		epollFD:  -1,
	}

	epollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, &Error{Op: op, Errno: errnoFromError(err)}
	}
	pb.epollFD = epollFD

	cpuCnt := libbpfNumPossibleCPUs()
	if cpuCnt < 0 {
		PerfBufferFree(pb)
		return nil, &Error{Op: op, Errno: syscall.Errno(-cpuCnt)}
	}
	if maxEntries > 0 && int(maxEntries) < cpuCnt {
		cpuCnt = int(maxEntries)
	}

	online, err := readCPUMaskFile("/sys/devices/system/cpu/online")
	if err != nil {
		PerfBufferFree(pb)
		return nil, &Error{Op: op, Errno: errnoFromError(err)}
	}

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_SOFTWARE,
		Size:        perfEventAttrSize,
		Config:      unix.PERF_COUNT_SW_BPF_OUTPUT,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Wakeup:      samplePeriod,
	}
	pb.events = make([]unix.EpollEvent, 0, cpuCnt)
	if err := pb.openCPUBuffers(mapFD, &attr, cpuCnt, online); err != nil {
		PerfBufferFree(pb)
		return nil, &Error{Op: op, Errno: errnoFromError(err)}
	}

	return pb, nil
}

// perfBufferMapEntries validates that mapFD is a perf event array and
// returns its max_entries. A kernel without BPF_OBJ_GET_INFO_BY_FD support
// reports the map as unknown, like the C library.
func perfBufferMapEntries(mapFD int) (uint32, error) {
	info, err := sys.MapInfoByFD(mapFD)
	if err != nil {
		if errors.Is(err, unix.EINVAL) {
			return 0, nil
		}
		return 0, err
	}
	if BpfMapType(info.Type) != BPF_MAP_TYPE_PERF_EVENT_ARRAY {
		return 0, unix.EINVAL
	}
	return info.MaxEntries, nil
}

// openCPUBuffers opens one perf event per online CPU, stores its descriptor
// in the map and adds it to the epoll set.
func (pb *PerfBuffer) openCPUBuffers(mapFD int, attr *unix.PerfEventAttr, cpuCnt int, online []bool) error {
	for cpu := 0; cpu < cpuCnt; cpu++ {
		if cpu >= len(online) || !online[cpu] {
			continue
		}
		cpuBuf, err := pb.openCPUBuf(attr, cpu, cpu)
		if err != nil {
			return err
		}
		pb.cpuBufs = append(pb.cpuBufs, cpuBuf)
		index := len(pb.cpuBufs) - 1

		if err := sys.MapUpdateElem(mapFD, uint32Bytes(cpu), uint32Bytes(cpuBuf.fd), 0); err != nil {
			return err
		}
		event := unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(index)}
		if err := unix.EpollCtl(pb.epollFD, unix.EPOLL_CTL_ADD, cpuBuf.fd, &event); err != nil {
			return err
		}
		pb.events = append(pb.events, event)
	}
	return nil
}

// openCPUBuf opens and enables one CPU's perf event and maps its ring.
func (pb *PerfBuffer) openCPUBuf(attr *unix.PerfEventAttr, cpu, mapKey int) (*perfBufferCPUBuf, error) {
	fd, err := unix.PerfEventOpen(attr, -1, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, err
	}

	base, err := mmap.Map(fd, 0, pb.pageSize+pb.mmapSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		_ = mmap.Unmap(base)
		unix.Close(fd)
		return nil, err
	}

	return &perfBufferCPUBuf{
		base:   base,
		data:   base[pb.pageSize:],
		fd:     fd,
		cpu:    cpu,
		mapKey: mapKey,
	}, nil
}

// PerfBufferFree unmaps every ring, disables and closes the perf events,
// removes their entries from the map and closes the epoll descriptor. The map
// descriptor stays owned by the caller. It is nil-safe and idempotent.
func PerfBufferFree(pb *PerfBuffer) {
	if pb == nil || pb.freed {
		return
	}

	for _, cpuBuf := range pb.cpuBufs {
		if cpuBuf == nil {
			continue
		}
		_ = sys.MapDeleteElem(pb.mapFD, uint32Bytes(cpuBuf.mapKey), 0)
		freePerfBufferCPUBuf(cpuBuf)
	}
	if pb.epollFD >= 0 {
		unix.Close(pb.epollFD)
		pb.epollFD = -1
	}
	pb.cpuBufs = nil
	pb.events = nil
	pb.freed = true
}

// freePerfBufferCPUBuf disables and closes the perf event and releases its
// mapping.
func freePerfBufferCPUBuf(cpuBuf *perfBufferCPUBuf) {
	_ = unix.IoctlSetInt(cpuBuf.fd, unix.PERF_EVENT_IOC_DISABLE, 0)
	unix.Close(cpuBuf.fd)
	_ = mmap.Unmap(cpuBuf.base)
	cpuBuf.base = nil
	cpuBuf.data = nil
	cpuBuf.copy = nil
}

// PerfBufferPoll waits up to timeoutMS milliseconds for records and reads
// them. A negative timeout blocks. It returns the number of CPU buffers that
// had records, like the C library.
func PerfBufferPoll(pb *PerfBuffer, timeoutMS int) (int, error) {
	const op = "perf_buffer__poll"
	if pb == nil || pb.freed || pb.epollFD < 0 {
		return 0, &Error{Op: op, Errno: unix.EINVAL}
	}

	ready, err := unix.EpollWait(pb.epollFD, pb.events, timeoutMS)
	if err != nil {
		return 0, &Error{Op: op, Errno: errnoFromError(err)}
	}

	for i := 0; i < ready; i++ {
		index := int(pb.events[i].Fd)
		if index < 0 || index >= len(pb.cpuBufs) {
			continue
		}
		if err := pb.processRecords(pb.cpuBufs[index]); err != nil {
			return 0, &Error{Op: op, Errno: errnoFromError(err)}
		}
	}
	return ready, nil
}

// PerfBufferConsume reads every available record without waiting.
func PerfBufferConsume(pb *PerfBuffer) error {
	const op = "perf_buffer__consume"
	if pb == nil || pb.freed {
		return &Error{Op: op, Errno: unix.EINVAL}
	}

	for _, cpuBuf := range pb.cpuBufs {
		if cpuBuf == nil {
			continue
		}
		if err := pb.processRecords(cpuBuf); err != nil {
			return &Error{Op: op, Errno: errnoFromError(err)}
		}
	}
	return nil
}

// PerfBufferConsumeBuffer reads every available record from one CPU buffer.
func PerfBufferConsumeBuffer(pb *PerfBuffer, bufIdx int) error {
	const op = "perf_buffer__consume_buffer"
	cpuBuf, err := pb.cpuBuf(bufIdx)
	if err != nil {
		return &Error{Op: op, Errno: errnoFromError(err)}
	}
	if err := pb.processRecords(cpuBuf); err != nil {
		return &Error{Op: op, Errno: errnoFromError(err)}
	}
	return nil
}

// PerfBufferBufferCnt returns the number of CPU buffers the reader opened.
func PerfBufferBufferCnt(pb *PerfBuffer) int {
	if pb == nil || pb.freed {
		return 0
	}
	return len(pb.cpuBufs)
}

// PerfBufferBufferFD returns the perf event descriptor of one CPU buffer.
func PerfBufferBufferFD(pb *PerfBuffer, bufIdx int) (int, error) {
	const op = "perf_buffer__buffer_fd"
	cpuBuf, err := pb.cpuBuf(bufIdx)
	if err != nil {
		return -1, &Error{Op: op, Errno: errnoFromError(err)}
	}
	return cpuBuf.fd, nil
}

// PerfBufferBuffer returns one CPU's mapping and the data ring size. The slice
// starts with the perf event metadata page, so its length is the size plus one
// page.
func PerfBufferBuffer(pb *PerfBuffer, bufIdx int) ([]byte, int, error) {
	const op = "perf_buffer__buffer"
	cpuBuf, err := pb.cpuBuf(bufIdx)
	if err != nil {
		return nil, 0, &Error{Op: op, Errno: errnoFromError(err)}
	}
	return cpuBuf.base, pb.mmapSize, nil
}

// PerfBufferEpollFD returns the epoll descriptor, or -1 after free.
func PerfBufferEpollFD(pb *PerfBuffer) int {
	if pb == nil || pb.freed {
		return -1
	}
	return pb.epollFD
}

// cpuBuf returns one CPU buffer or the errno the C accessors report.
func (pb *PerfBuffer) cpuBuf(bufIdx int) (*perfBufferCPUBuf, error) {
	if pb == nil || pb.freed || bufIdx < 0 || bufIdx >= len(pb.cpuBufs) {
		return nil, unix.EINVAL
	}
	if pb.cpuBufs[bufIdx] == nil {
		return nil, unix.ENOENT
	}
	return pb.cpuBufs[bufIdx], nil
}

// processRecords reads every record between data_head and data_tail and
// advances data_tail. A callback error stops the loop; the record that caused
// it stays consumed, like the C library.
func (pb *PerfBuffer) processRecords(cpuBuf *perfBufferCPUBuf) error {
	head := sys.LoadAcquire64(cpuBuf.base[sys.PerfEventDataHeadOffset:])
	tail := binary.NativeEndian.Uint64(cpuBuf.base[sys.PerfEventDataTailOffset:])

	for head != tail {
		offset := int(tail & uint64(pb.mmapSize-1))
		header := pb.recordBytes(cpuBuf, offset, sys.PerfEventHeaderSize)
		size := int(binary.NativeEndian.Uint16(header[6:]))
		if size < sys.PerfEventHeaderSize || size > pb.mmapSize {
			return unix.EINVAL
		}

		record := pb.recordBytes(cpuBuf, offset, size)
		err := pb.processRecord(cpuBuf, record)
		tail += uint64(size)
		sys.StoreRelease64(cpuBuf.base[sys.PerfEventDataTailOffset:], tail)
		if err != nil {
			return err
		}
	}
	return nil
}

// recordBytes returns size bytes at offset, copying the record into the CPU
// scratch buffer when it wraps around the end of the data ring.
func (pb *PerfBuffer) recordBytes(cpuBuf *perfBufferCPUBuf, offset, size int) []byte {
	if offset+size <= len(cpuBuf.data) {
		return cpuBuf.data[offset : offset+size]
	}
	if cap(cpuBuf.copy) < size {
		cpuBuf.copy = make([]byte, size)
	}
	record := cpuBuf.copy[:size]
	first := copy(record, cpuBuf.data[offset:])
	copy(record[first:], cpuBuf.data)
	return record
}

// processRecord dispatches one perf record to the sample or lost callback.
func (pb *PerfBuffer) processRecord(cpuBuf *perfBufferCPUBuf, record []byte) error {
	recordType := binary.NativeEndian.Uint32(record)

	switch recordType {
	case sys.PerfRecordSample:
		if len(record) < sys.PerfSampleSizeEnd {
			return unix.EINVAL
		}
		size := int(binary.NativeEndian.Uint32(record[sys.PerfSampleSizeOffset:]))
		if size < 0 || sys.PerfSampleSizeEnd+size > len(record) {
			return unix.EINVAL
		}
		if pb.sampleFn != nil {
			data := record[sys.PerfSampleSizeEnd : sys.PerfSampleSizeEnd+size]
			pb.sampleFn(pb.ctx, cpuBuf.cpu, data)
		}
	case sys.PerfRecordLost:
		if len(record) < sys.PerfLostSize {
			return unix.EINVAL
		}
		if pb.lostFn != nil {
			lost := binary.NativeEndian.Uint64(record[sys.PerfLostCountOffset:])
			pb.lostFn(pb.ctx, cpuBuf.cpu, lost)
		}
	default:
		return unix.EINVAL
	}
	return nil
}

// uint32Bytes returns a native-endian 32-bit map key or value.
func uint32Bytes(v int) []byte {
	buf := make([]byte, 4)
	binary.NativeEndian.PutUint32(buf, uint32(v))
	return buf
}
