# SPDX-License-Identifier: LGPL-2.1-only

LIBBPF ?= ../libbpf
CC ?= cc
CFLAGS ?= -O2 -g -Wall -Wextra -Werror -std=gnu11
CPPFLAGS += -I$(LIBBPF)/include/uapi -I$(LIBBPF)/include

BUILD := build
ORACLE := $(BUILD)/oracle

.PHONY: all fixtures clean

all: $(ORACLE)

$(ORACLE): main.c | $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $<

$(BUILD):
	mkdir -p $@

fixtures: $(ORACLE)
	mkdir -p ../testdata/oracle
	$(ORACLE) layout > ../testdata/oracle/layout.json
	$(ORACLE) attr > ../testdata/oracle/attr.json

clean:
	rm -rf $(BUILD)
