// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

// Target BTF with two candidates for each local type of core_amb.bpf.c and
// core_cands.bpf.c. The global variables keep every type in the BTF.

struct cc_amb {
	int x;
	int y;
};

struct cc_amb___v2 {
	int y;
};

struct cc_nar {
	int a;
	int b;
};

struct cc_nar___v2 {
	long pad;
	int b;
};

struct cc_pick {
	int a;
};

struct cc_pick___v2 {
	int b;
};

struct cc_amb target_amb;
struct cc_amb___v2 target_amb_v2;
struct cc_nar target_nar;
struct cc_nar___v2 target_nar_v2;
struct cc_pick target_pick;
struct cc_pick___v2 target_pick_v2;
