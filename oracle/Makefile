# SPDX-License-Identifier: LGPL-2.1-only

LIBBPF ?= ../libbpf
CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -Werror -std=gnu11
CPPFLAGS += -I$(LIBBPF)/include/uapi -I$(LIBBPF)/include

BUILD := build
ORACLE := $(BUILD)/oracle
ORACLE_SRCS := main.c json.c oracle.c layout.c attr.c open.c load.c attach.c dump.c ringbuf.c perfbuf.c probe.c linker.c core.c linfo.c zip.c
ORACLE_HDRS := json.h oracle.h
LIBBPF_SRC := $(BUILD)/libbpf/src
LIBBPF_OBJ := $(BUILD)/libbpf-obj
LIBBPF_A := $(LIBBPF_OBJ)/libbpf.a

.PHONY: all fixtures load-fixture attach-fixture ringbuf-fixture perfbuf-fixture probe-fixture linker-fixture clean

all: $(ORACLE)

$(LIBBPF_A): | $(BUILD)
	rm -rf $(BUILD)/libbpf $(LIBBPF_OBJ)
	mkdir -p $(BUILD)/libbpf
	cp -a $(LIBBPF)/src $(BUILD)/libbpf/src
	cp -a $(LIBBPF)/include $(BUILD)/libbpf/include
	$(MAKE) -C $(LIBBPF_SRC) OBJDIR=$(abspath $(LIBBPF_OBJ)) BUILD_STATIC_ONLY=y

$(ORACLE): $(ORACLE_SRCS) $(ORACLE_HDRS) $(LIBBPF_A)
	$(CC) $(CPPFLAGS) -I$(LIBBPF_SRC) -I$(BUILD)/libbpf/include/uapi \
		$(CFLAGS) -o $@ $(ORACLE_SRCS) $(LIBBPF_A) \
		$(shell pkg-config --libs libelf zlib)

$(BUILD):
	mkdir -p $@

fixtures: $(ORACLE)
	mkdir -p ../testdata/oracle
	$(ORACLE) layout > ../testdata/oracle/layout.json
	$(ORACLE) attr > ../testdata/oracle/attr.json
	$(ORACLE) open ../testdata/progs/kprobe.bpf.o > ../testdata/oracle/open.json
	$(ORACLE) dump ../testdata/progs/dump.bpf.o > ../testdata/oracle/dump.txt
	$(ORACLE) dump-decl ../testdata/progs/dump.bpf.o > ../testdata/oracle/dump-decl.txt
	$(ORACLE) dump-decl-strip ../testdata/progs/dump.bpf.o > ../testdata/oracle/dump-decl-strip.txt
	$(ORACLE) core ../testdata/progs/core.bpf.o > ../testdata/oracle/core.json
	$(ORACLE) core-reloc ../testdata/progs/core.bpf.o ../testdata/progs/core_target.bpf.o > ../testdata/oracle/core-reloc.json
	$(ORACLE) linfo > ../testdata/oracle/linfo.json
	$(ORACLE) zip > ../testdata/oracle/zip.json

load-fixture: $(ORACLE)
	mkdir -p ../testdata/oracle
	sudo -n $(ORACLE) load ../testdata/progs/kprobe.bpf.o > ../testdata/oracle/load.json

attach-fixture: $(ORACLE)
	mkdir -p ../testdata/oracle
	sudo -n $(ORACLE) attach ../testdata/progs > ../testdata/oracle/attach.json

ringbuf-fixture: $(ORACLE)
	mkdir -p ../testdata/oracle
	sudo -n $(ORACLE) ringbuf ../testdata/progs/ringbuf.bpf.o > ../testdata/oracle/ringbuf.json

perfbuf-fixture: $(ORACLE)
	mkdir -p ../testdata/oracle
	sudo -n $(ORACLE) perfbuf ../testdata/progs/perfbuf.bpf.o > ../testdata/oracle/perfbuf.json

probe-fixture: $(ORACLE)
	mkdir -p ../testdata/oracle
	sudo -n $(ORACLE) probe > ../testdata/oracle/probe.json

linker-fixture: $(ORACLE)
	mkdir -p ../testdata/oracle
	$(ORACLE) linker ../testdata/progs/kprobe.bpf.o > ../testdata/oracle/linker.json
	$(ORACLE) linker ../testdata/progs/link_a.bpf.o ../testdata/progs/link_b.bpf.o > ../testdata/oracle/linker-merge.json
	$(ORACLE) linker ../testdata/progs/link_b.bpf.o ../testdata/progs/link_a.bpf.o > ../testdata/oracle/linker-merge-reverse.json
	$(ORACLE) linker ../testdata/progs/link_text_a.bpf.o ../testdata/progs/link_text_b.bpf.o > ../testdata/oracle/linker-text.json

clean:
	rm -rf $(BUILD)
