// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: include/uapi/linux/perf_event.h
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: struct perf_event_mmap_page, struct perf_event_header

//go:build linux && (amd64 || arm64)

package sys

// Perf event ring ABI from linux/perf_event.h. The kernel owns the metadata
// page and writes records after it; user space reads data_head and advances
// data_tail.
const (
	PerfEventHeaderSize     = 8
	PerfEventDataHeadOffset = 1024
	PerfEventDataTailOffset = 1032
	PerfEventDataTailEnd    = 1040

	PerfRecordLost   uint32 = 2
	PerfRecordSample uint32 = 9

	PerfSampleSizeOffset   = 8
	PerfSampleSizeEnd      = 12
	PerfLostIDOffset       = 8
	PerfLostCountOffset    = 16
	PerfLostSampleIDOffset = 24
	PerfLostSize           = 32
)

// perfEventFieldLayout is the Go claim about the perf_event_mmap_page fields
// the perf buffer reads. The layout test compares it with the C offsets.
func perfEventFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"data_head", PerfEventDataHeadOffset, 8},
		{"data_tail", PerfEventDataTailOffset, 8},
	}
}

// perfEventHeaderFieldLayout is the record header every perf record starts
// with.
func perfEventHeaderFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"type", 0, 4},
		{"misc", 4, 2},
		{"size", 6, 2},
	}
}

// perfSampleFieldLayout is the PERF_RECORD_SAMPLE payload prefix: the raw
// sample length followed by the bytes.
func perfSampleFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"size", PerfSampleSizeOffset, 4},
	}
}

// perfLostFieldLayout is the PERF_RECORD_LOST payload.
func perfLostFieldLayout() []fieldLayout {
	return []fieldLayout{
		{"id", PerfLostIDOffset, 8},
		{"lost", PerfLostCountOffset, 8},
		{"sample_id", PerfLostSampleIDOffset, 8},
	}
}
