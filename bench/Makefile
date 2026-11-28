# SPDX-License-Identifier: LGPL-2.1-only

# The C half of the benchmark suite, linked against the pinned libbpf the way
# oracle/Makefile links the oracle, and the commands that run both halves.
# Nothing here is part of the default build. LIBBPF is the libbpf source
# checkout. Its default, ../libbpf, is the Go package when make runs in this
# directory, as it is for oracle/Makefile, so pass the checkout explicitly:
#
#   make -C bench LIBBPF=/path/to/libbpf

SHELL := /bin/bash
LIBBPF ?= ../libbpf
CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -Werror -std=gnu11
CPPFLAGS += -I$(LIBBPF)/include/uapi -I$(LIBBPF)/include

BUILD := build
BENCH := bench
LIBBPF_SRC := $(BUILD)/libbpf/src
LIBBPF_OBJ := $(BUILD)/libbpf-obj
LIBBPF_A := $(LIBBPF_OBJ)/libbpf.a

# run and run-go pin every process to CPU, repeat each benchmark RUNS times,
# and run as root through SUDO; SUDO= runs unprivileged, and the load, map and
# attach benchmarks then print a skip line with the errno.
CPU ?= 2
RUNS ?= 3
SUDO ?= sudo -n
TASKSET ?= taskset -c $(CPU)
GO ?= go
LLVM_OBJCOPY ?= llvm-objcopy

# BTF replaces vmlinux as the BTF of the btf and dump benchmarks on both
# sides, through GOBPFGO_BENCH_BTF; $(BUILD)/kprobe.btf is the small fallback.
BTF ?=
BENCH_ENV := $(if $(BTF),GOBPFGO_BENCH_BTF=$(abspath $(BTF)))

# The bench.c subcommands, each run in its own process.
C_BENCHES := open load map btf linker attach dump

# The Go benchmarks, each run in its own process, with the iteration count
# bench.c uses for the same operation.
GO_TEST := $(BUILD)/libbpf.test
GO_BENCHES := ObjectOpen:2000 ObjectLoad:200 MapLookupElem:200000 \
	MapUpdateElem:200000 BtfParse:20 BtfDedup:3 Linker:200 \
	KprobeAttach:200 BtfDump:200

.PHONY: all run run-go run-all info clean $(GO_TEST)

all: $(BENCH)

$(LIBBPF_A): | $(BUILD)
	@test -f $(LIBBPF)/src/libbpf.c || { \
		echo "LIBBPF=$(LIBBPF) is not a libbpf checkout; pass LIBBPF=/path/to/libbpf" >&2; \
		exit 1; }
	rm -rf $(BUILD)/libbpf $(LIBBPF_OBJ)
	mkdir -p $(BUILD)/libbpf
	cp -a $(LIBBPF)/src $(BUILD)/libbpf/src
	cp -a $(LIBBPF)/include $(BUILD)/libbpf/include
	$(MAKE) -C $(LIBBPF_SRC) OBJDIR=$(abspath $(LIBBPF_OBJ)) BUILD_STATIC_ONLY=y

$(BENCH): bench.c $(LIBBPF_A)
	$(CC) $(CPPFLAGS) -I$(LIBBPF_SRC) -I$(BUILD)/libbpf/include/uapi \
		-I$(BUILD)/libbpf/include \
		$(CFLAGS) -o $@ bench.c $(LIBBPF_A) \
		$(shell pkg-config --libs libelf zlib)

# The Go test binary is built as the invoking user, so that root never
# writes to the user's Go cache, and always rebuilt; go caches the work.
$(GO_TEST): | $(BUILD)
	@cd .. && $(GO) test -c -o bench/$(GO_TEST) ./libbpf

$(BUILD):
	mkdir -p $@

# The raw .BTF section of kprobe.bpf.o, for BTF=$(BUILD)/kprobe.btf.
$(BUILD)/kprobe.btf: ../testdata/progs/kprobe.bpf.o | $(BUILD)
	$(LLVM_OBJCOPY) --dump-section .BTF=$@ $< $(BUILD)/kprobe.btf.o

info:
	@echo "kernel: $$(uname -r)"
	@echo "cpu: $$(lscpu | sed -n 's/^Model name: *//p')"
	@echo "pinned cpu: $(CPU), governor: $$(cat /sys/devices/system/cpu/cpu$(CPU)/cpufreq/scaling_governor 2>/dev/null)"
	@echo "cc: $$($(CC) --version | head -1)"
	@echo "go: $$($(GO) version)"
	@echo "libbpf: $$(git -C $(LIBBPF) rev-parse --short HEAD 2>/dev/null)"

# RUN_IDS numbers the runs; run-all sets it to make one C and one Go run at a
# time.
RUN_IDS ?= $(shell seq $(RUNS))

run: $(BENCH)
	@for r in $(RUN_IDS); do \
		echo "# C run $$r"; \
		for c in $(C_BENCHES); do \
			$(SUDO) env $(BENCH_ENV) $(TASKSET) ./$(BENCH) $$c || exit 1; \
		done; \
	done

# The Go benchmarks run from libbpf/, where their fixture paths resolve, as
# bench.c's do from here. -test.v makes a skipped benchmark print its reason;
# grep keeps the result, skip and failure lines.
run-go: $(GO_TEST)
	@set -o pipefail; for r in $(RUN_IDS); do \
		echo "# Go run $$r"; \
		for b in $(GO_BENCHES); do \
			(cd ../libbpf && $(SUDO) env GOMAXPROCS=1 $(BENCH_ENV) $(TASKSET) \
				$(abspath $(GO_TEST)) -test.run '^$$' -test.v \
				-test.bench "^Benchmark$${b%%:*}$$" \
				-test.benchtime "$${b##*:}x" -test.benchmem) \
				| grep -E '^(Benchmark.*/op|--- |    )' || exit 1; \
		done; \
	done

# run-all alternates one C run and one Go run RUNS times, so that drift in
# CPU frequency or host load reaches both sides alike.
run-all: $(BENCH) $(GO_TEST) info
	@for r in $$(seq $(RUNS)); do \
		$(MAKE) --no-print-directory run RUN_IDS=$$r || exit 1; \
		$(MAKE) --no-print-directory run-go RUN_IDS=$$r || exit 1; \
	done

clean:
	rm -rf $(BUILD) $(BENCH)
