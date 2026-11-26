// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/ringbuf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: ring_buffer__new, ring_buffer__free, ring_buffer__add, ring_buffer__poll, ring_buffer__consume, ring_buffer__consume_n, ring_buffer__epoll_fd

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"math"

	"github.com/gobpfgo/gobpfgo/internal/mmap"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// BPF ring buffer record header flags from linux/bpf.h.
const (
	ringbufBusyBit    uint32 = 1 << 31
	ringbufDiscardBit uint32 = 1 << 30
	ringbufHeaderSize        = 8
)

// RingBufferSampleFunc is called for each record. Returning a negative value
// stops the consumption and becomes the returned error's errno; the record is
// consumed either way. The data slice aliases the ring and must be copied to
// be retained.
type RingBufferSampleFunc func(ctx any, data []byte) int

// RingBufferOpts are the options of RingBufferNew. The C library has only a
// size field; the Go API takes the struct as is.
type RingBufferOpts struct{}

// RingBuffer reads one or more BPF ring buffer maps through their shared
// pages. Each ring has its own callback, like the C library.
type RingBuffer struct {
	epollFD  int
	pageSize int
	rings    []*ringBufferRing
	events   []unix.EpollEvent
	freed    bool
}

type ringBufferRing struct {
	mapFD    int
	mask     uint32
	consumer []byte
	producer []byte
	data     []byte
	sampleFn RingBufferSampleFunc
	ctx      any
}

// RingBufferNew creates a reader for mapFD, which must be a
// BPF_MAP_TYPE_RINGBUF map. The map descriptor stays owned by the caller.
func RingBufferNew(mapFD int, sampleFn RingBufferSampleFunc, ctx any, opts *RingBufferOpts) (*RingBuffer, error) {
	const op = "ring_buffer__new"
	if mapFD < 0 || sampleFn == nil {
		return nil, &Error{Op: op, Errno: unix.EINVAL}
	}

	epollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, &Error{Op: op, Errno: errnoFromError(err)}
	}

	rb := &RingBuffer{epollFD: epollFD, pageSize: unix.Getpagesize()}
	if err := rb.add(mapFD, sampleFn, ctx); err != nil {
		unix.Close(epollFD)
		return nil, &Error{Op: op, Errno: errnoFromError(err), Log: err.Error()}
	}
	return rb, nil
}

// RingBufferFree unmaps every ring and closes the epoll descriptor. The map
// descriptors stay owned by the caller. It is nil-safe and idempotent.
func RingBufferFree(rb *RingBuffer) {
	if rb == nil || rb.freed {
		return
	}
	for _, ring := range rb.rings {
		if ring == nil {
			continue
		}
		_ = mmap.Unmap(ring.consumer)
		_ = mmap.Unmap(ring.producer)
	}
	if rb.epollFD >= 0 {
		unix.Close(rb.epollFD)
		rb.epollFD = -1
	}
	rb.rings = nil
	rb.events = nil
	rb.freed = true
}

// RingBufferAdd adds another ring buffer map to the reader.
func RingBufferAdd(rb *RingBuffer, mapFD int, sampleFn RingBufferSampleFunc, ctx any) error {
	const op = "ring_buffer__add"
	if rb == nil || rb.freed || mapFD < 0 || sampleFn == nil || rb.epollFD < 0 {
		return &Error{Op: op, Errno: unix.EINVAL}
	}
	if err := rb.add(mapFD, sampleFn, ctx); err != nil {
		return &Error{Op: op, Errno: errnoFromError(err), Log: err.Error()}
	}
	return nil
}

func (rb *RingBuffer) add(mapFD int, sampleFn RingBufferSampleFunc, ctx any) error {
	info, err := sys.MapInfoByFD(mapFD)
	if err != nil {
		return err
	}
	if BpfMapType(info.Type) != BPF_MAP_TYPE_RINGBUF {
		return unix.EINVAL
	}
	if info.MaxEntries == 0 || info.MaxEntries&(info.MaxEntries-1) != 0 {
		return unix.EINVAL
	}

	pageSize := rb.pageSize
	consumer, err := mmap.Map(mapFD, 0, pageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return err
	}
	length := pageSize + 2*int(info.MaxEntries)
	producer, err := mmap.Map(mapFD, int64(pageSize), length, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		_ = mmap.Unmap(consumer)
		return err
	}

	event := unix.EpollEvent{
		Events: unix.EPOLLIN,
		Fd:     int32(len(rb.rings)),
	}
	if err := unix.EpollCtl(rb.epollFD, unix.EPOLL_CTL_ADD, mapFD, &event); err != nil {
		_ = mmap.Unmap(producer)
		_ = mmap.Unmap(consumer)
		return err
	}

	rb.rings = append(rb.rings, &ringBufferRing{
		mapFD:    mapFD,
		mask:     info.MaxEntries - 1,
		consumer: consumer,
		producer: producer,
		data:     producer[pageSize:],
		sampleFn: sampleFn,
		ctx:      ctx,
	})
	rb.events = append(rb.events, unix.EpollEvent{})
	return nil
}

// RingBufferPoll waits up to timeoutMS milliseconds for records and consumes
// them. A negative timeout blocks. It returns the number of records consumed.
func RingBufferPoll(rb *RingBuffer, timeoutMS int) (int, error) {
	const op = "ring_buffer__poll"
	if rb == nil || rb.freed || rb.epollFD < 0 {
		return 0, &Error{Op: op, Errno: unix.EINVAL}
	}

	ready, err := unix.EpollWait(rb.epollFD, rb.events, timeoutMS)
	if err != nil {
		return 0, &Error{Op: op, Errno: errnoFromError(err)}
	}

	total := 0
	for i := 0; i < ready; i++ {
		index := int(rb.events[i].Fd)
		if index < 0 || index >= len(rb.rings) {
			continue
		}
		count, err := rb.rings[index].process(math.MaxInt32)
		if err != nil {
			return total, &Error{Op: op, Errno: errnoFromError(err)}
		}
		total += count
	}
	if total > math.MaxInt32 {
		total = math.MaxInt32
	}
	return total, nil
}

// RingBufferConsume consumes every available record without waiting.
func RingBufferConsume(rb *RingBuffer) (int, error) {
	const op = "ring_buffer__consume"
	if rb == nil || rb.freed {
		return 0, &Error{Op: op, Errno: unix.EINVAL}
	}

	total := 0
	for _, ring := range rb.rings {
		count, err := ring.process(math.MaxInt32)
		if err != nil {
			return total, &Error{Op: op, Errno: errnoFromError(err)}
		}
		total += count
		if total > math.MaxInt32 {
			return math.MaxInt32, nil
		}
	}
	return total, nil
}

// RingBufferConsumeN consumes at most n records across the registered rings.
func RingBufferConsumeN(rb *RingBuffer, n int) (int, error) {
	const op = "ring_buffer__consume_n"
	if rb == nil || rb.freed || n < 0 {
		return 0, &Error{Op: op, Errno: unix.EINVAL}
	}
	if n == 0 {
		return 0, nil
	}

	total := 0
	for _, ring := range rb.rings {
		count, err := ring.process(n - total)
		if err != nil {
			return total, &Error{Op: op, Errno: errnoFromError(err)}
		}
		total += count
		if total >= n {
			break
		}
	}
	return total, nil
}

// RingBufferEpollFD returns the epoll descriptor, or -1 after free.
func RingBufferEpollFD(rb *RingBuffer) int {
	if rb == nil || rb.freed {
		return -1
	}
	return rb.epollFD
}

// process consumes records from one ring up to limit.
func (r *ringBufferRing) process(limit int) (int, error) {
	consumer := sys.LoadAcquire64(r.consumer)
	count := 0

	for count < limit {
		producer := sys.LoadAcquire64(r.producer)
		if producer == consumer {
			break
		}

		offset := uint32(consumer) & r.mask
		header := r.data[offset:]
		raw := binary.NativeEndian.Uint32(header)
		if raw&ringbufBusyBit != 0 {
			break
		}

		length := int(raw &^ (ringbufBusyBit | ringbufDiscardBit))
		total := ringRecordLen(length)
		if int(offset)+total > len(r.data) {
			return count, unix.EINVAL
		}

		if raw&ringbufDiscardBit == 0 {
			sample := header[ringbufHeaderSize : ringbufHeaderSize+length]
			if ret := r.sampleFn(r.ctx, sample); ret < 0 {
				sys.StoreRelease64(r.consumer, consumer+uint64(total))
				return count, unix.Errno(-ret)
			}
			count++
		}

		consumer += uint64(total)
		sys.StoreRelease64(r.consumer, consumer)
	}

	return count, nil
}

// ringRecordLen rounds the sample length plus the header up to the 8-byte
// record alignment used by the kernel.
func ringRecordLen(length int) int {
	return (length + ringbufHeaderSize + 7) / 8 * 8
}
