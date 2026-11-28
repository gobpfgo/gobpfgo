// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

// Target BTF with one candidate for the local type of core_amb.bpf.c, the
// first one core_cands_target.c has. The global variable keeps it in the BTF.

struct cc_amb {
	int x;
	int y;
};

struct cc_amb target_amb;
