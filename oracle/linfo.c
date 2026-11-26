// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include "libbpf.h"

#include <linux/bpf.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LINFO_MAX_RECS 8
#define LINFO_MAX_REC_SIZE 32
#define LINFO_MAX_ADDRS (2 * LINFO_MAX_RECS + 2)

#define LINE_COL(line, col) ((line) << 10 | (col))

#define LINFO_RECS(arr) .line_info = arr, .nr_line_info = ORACLE_ARRAY_SIZE(arr)
#define LINFO_JITED(arr) .jited = arr, .jited_cnt = ORACLE_ARRAY_SIZE(arr), .nr_jited_line_info = ORACLE_ARRAY_SIZE(arr)
#define LINFO_KSYMS(arr) .ksyms = arr, .ksyms_cnt = ORACLE_ARRAY_SIZE(arr), .nr_jited_ksyms = ORACLE_ARRAY_SIZE(arr)
#define LINFO_LENS(arr) .func_lens = arr, .func_lens_cnt = ORACLE_ARRAY_SIZE(arr), .nr_jited_func_lens = ORACLE_ARRAY_SIZE(arr)

/*
 * A synthetic struct bpf_prog_info. The *_cnt fields are the lengths of the
 * arrays, zero for a NULL pointer; the nr_* fields are the counts the info
 * claims, which some cases set apart from the array lengths.
 */
struct linfo_case {
	const char *name;
	__u32 rec_size;
	const struct bpf_line_info *line_info;
	__u32 nr_line_info;
	__u32 jited_rec_size;
	const __u64 *jited;
	__u32 jited_cnt;
	__u32 nr_jited_line_info;
	const __u64 *ksyms;
	__u32 ksyms_cnt;
	__u32 nr_jited_ksyms;
	const __u32 *func_lens;
	__u32 func_lens_cnt;
	__u32 nr_jited_func_lens;
};

struct linfo_bufs {
	unsigned char line_info[LINFO_MAX_RECS * LINFO_MAX_REC_SIZE];
	unsigned char jited[LINFO_MAX_RECS * LINFO_MAX_REC_SIZE];
};

static const struct bpf_line_info xlated_linfo[] = {
	{.insn_off = 0, .file_name_off = 1, .line_off = 10, .line_col = LINE_COL(5, 2)},
	{.insn_off = 3, .file_name_off = 1, .line_off = 20, .line_col = LINE_COL(6, 4)},
	{.insn_off = 7, .file_name_off = 1, .line_off = 30, .line_col = LINE_COL(8, 1)},
	{.insn_off = 12, .file_name_off = 1, .line_off = 40, .line_col = LINE_COL(9, 3)},
};

static const struct bpf_line_info late_linfo[] = {
	{.insn_off = 2, .file_name_off = 7, .line_off = 50, .line_col = LINE_COL(3, 1)},
	{.insn_off = 5, .file_name_off = 7, .line_off = 60, .line_col = LINE_COL(4, 5)},
	{.insn_off = 9, .file_name_off = 7, .line_off = 70, .line_col = LINE_COL(7, 9)},
};

/* Records 0-2 belong to the function at 0x1000, records 3-5 to 0x2000. */
static const struct bpf_line_info two_funcs_linfo[] = {
	{.insn_off = 0, .file_name_off = 1, .line_off = 10, .line_col = LINE_COL(10, 1)},
	{.insn_off = 2, .file_name_off = 1, .line_off = 20, .line_col = LINE_COL(11, 2)},
	{.insn_off = 5, .file_name_off = 1, .line_off = 30, .line_col = LINE_COL(12, 3)},
	{.insn_off = 8, .file_name_off = 2, .line_off = 40, .line_col = LINE_COL(20, 1)},
	{.insn_off = 10, .file_name_off = 2, .line_off = 50, .line_col = LINE_COL(21, 2)},
	{.insn_off = 14, .file_name_off = 2, .line_off = 60, .line_col = LINE_COL(22, 3)},
};
static const __u64 two_funcs_jited[] = {0x1000, 0x1008, 0x1020, 0x2000, 0x2010, 0x2018};
static const __u64 two_funcs_ksyms[] = {0x1000, 0x2000};
static const __u32 two_funcs_lens[]  = {0x40, 0x30};

/* The last jited address of the first function is 0x1020: 0x21 bytes in. */
static const __u32 exact_lens[]           = {0x21, 0x30};
static const __u32 short_lens[]           = {0x20, 0x30};
static const __u64 shifted_ksyms[]        = {0x1004, 0x2000};
static const __u64 missing_ksyms[]        = {0x1000, 0x2004};
static const __u64 repeated_jited[]       = {0x1000, 0x1008, 0x1008, 0x2000, 0x2010, 0x2018};
static const __u64 last_func_decreasing[] = {0x1000, 0x1008, 0x1020, 0x2000, 0x1ff0, 0x1fe0};

/* Records 0-1, 2 and 3-6 belong to the three functions. */
static const struct bpf_line_info three_funcs_linfo[] = {
	{.insn_off = 0, .file_name_off = 3, .line_off = 11, .line_col = LINE_COL(30, 1)},
	{.insn_off = 4, .file_name_off = 3, .line_off = 12, .line_col = LINE_COL(31, 1)},
	{.insn_off = 6, .file_name_off = 3, .line_off = 13, .line_col = LINE_COL(40, 2)},
	{.insn_off = 9, .file_name_off = 4, .line_off = 14, .line_col = LINE_COL(50, 3)},
	{.insn_off = 13, .file_name_off = 4, .line_off = 15, .line_col = LINE_COL(51, 4)},
	{.insn_off = 15, .file_name_off = 4, .line_off = 16, .line_col = LINE_COL(52, 5)},
	{.insn_off = 20, .file_name_off = 4, .line_off = 17, .line_col = LINE_COL(53, 6)},
};
static const __u64 three_funcs_jited[] = {0x3000, 0x3010, 0x3100, 0x3200, 0x3208, 0x3230, 0x3270};
static const __u64 three_funcs_ksyms[] = {0x3000, 0x3100, 0x3200};
static const __u32 three_funcs_lens[]  = {0x20, 0x10, 0x80};

/* One function; its length is not checked because no later symbol follows. */
static const __u64 single_func_jited[] = {0x5000, 0x5004, 0x5010, 0x5020};
static const __u64 single_func_ksyms[] = {0x5000};
static const __u32 single_func_lens[]  = {0x8};

static const struct linfo_case linfo_cases[] = {
	{.name = "xlated", .rec_size = 16, LINFO_RECS(xlated_linfo)},
	{.name = "late_first_record", .rec_size = 16, LINFO_RECS(late_linfo)},
	{.name = "short_records", .rec_size = 8, LINFO_RECS(late_linfo)},
	{.name = "insn_off_only", .rec_size = 4, LINFO_RECS(xlated_linfo)},
	{.name = "wide_records", .rec_size = 24, LINFO_RECS(xlated_linfo)},
	{.name = "no_records", .rec_size = 16},
	{.name = "rec_size_too_small", .rec_size = 3, LINFO_RECS(xlated_linfo)},
	{.name = "two_funcs", .rec_size = 16, LINFO_RECS(two_funcs_linfo), .jited_rec_size = 8, LINFO_JITED(two_funcs_jited), LINFO_KSYMS(two_funcs_ksyms), LINFO_LENS(two_funcs_lens)},
	{.name = "three_funcs_wide", .rec_size = 24, LINFO_RECS(three_funcs_linfo), .jited_rec_size = 16, LINFO_JITED(three_funcs_jited), LINFO_KSYMS(three_funcs_ksyms), LINFO_LENS(three_funcs_lens)},
	{.name = "single_func", .rec_size = 16, LINFO_RECS(xlated_linfo), .jited_rec_size = 8, LINFO_JITED(single_func_jited), LINFO_KSYMS(single_func_ksyms), LINFO_LENS(single_func_lens)},
	{.name = "func_len_exact", .rec_size = 16, LINFO_RECS(two_funcs_linfo), .jited_rec_size = 8, LINFO_JITED(two_funcs_jited), LINFO_KSYMS(two_funcs_ksyms), LINFO_LENS(exact_lens)},
	{.name = "func_len_exceeded", .rec_size = 16, LINFO_RECS(two_funcs_linfo), .jited_rec_size = 8, LINFO_JITED(two_funcs_jited), LINFO_KSYMS(two_funcs_ksyms), LINFO_LENS(short_lens)},
	{.name = "ksym_mismatch", .rec_size = 16, LINFO_RECS(two_funcs_linfo), .jited_rec_size = 8, LINFO_JITED(two_funcs_jited), LINFO_KSYMS(shifted_ksyms), LINFO_LENS(two_funcs_lens)},
	{.name = "missing_func", .rec_size = 16, LINFO_RECS(two_funcs_linfo), .jited_rec_size = 8, LINFO_JITED(two_funcs_jited), LINFO_KSYMS(missing_ksyms), LINFO_LENS(two_funcs_lens)},
	{.name = "addr_not_increasing", .rec_size = 16, LINFO_RECS(two_funcs_linfo), .jited_rec_size = 8, LINFO_JITED(repeated_jited), LINFO_KSYMS(two_funcs_ksyms), LINFO_LENS(two_funcs_lens)},
	{.name = "last_func_unchecked", .rec_size = 16, LINFO_RECS(two_funcs_linfo), .jited_rec_size = 8, LINFO_JITED(last_func_decreasing), LINFO_KSYMS(two_funcs_ksyms), LINFO_LENS(two_funcs_lens)},
	{.name = "jited_count_mismatch", .rec_size = 16, LINFO_RECS(two_funcs_linfo), .jited_rec_size = 8, .jited = two_funcs_jited, .jited_cnt = 6, .nr_jited_line_info = 5, LINFO_KSYMS(two_funcs_ksyms), LINFO_LENS(two_funcs_lens)},
	{.name = "jited_rec_size_small", .rec_size = 16, LINFO_RECS(two_funcs_linfo), .jited_rec_size = 4, LINFO_JITED(two_funcs_jited), LINFO_KSYMS(two_funcs_ksyms), LINFO_LENS(two_funcs_lens)},
	{.name = "func_lens_count_mismatch", .rec_size = 16, LINFO_RECS(two_funcs_linfo), .jited_rec_size = 8, LINFO_JITED(two_funcs_jited), LINFO_KSYMS(two_funcs_ksyms), .func_lens = two_funcs_lens, .func_lens_cnt = 2, .nr_jited_func_lens = 1},
	{.name = "no_jited_line_info", .rec_size = 16, LINFO_RECS(two_funcs_linfo), .jited_rec_size = 8, .nr_jited_line_info = 6, LINFO_KSYMS(two_funcs_ksyms), LINFO_LENS(two_funcs_lens)},
	{.name = "no_jited_ksyms", .rec_size = 16, LINFO_RECS(two_funcs_linfo), .jited_rec_size = 8, LINFO_JITED(two_funcs_jited), .nr_jited_ksyms = 2, LINFO_LENS(two_funcs_lens)},
	{.name = "no_func_lens", .rec_size = 16, LINFO_RECS(two_funcs_linfo), .jited_rec_size = 8, LINFO_JITED(two_funcs_jited), LINFO_KSYMS(two_funcs_ksyms), .nr_jited_func_lens = 2},
};

static __u64 linfo_ptr(const void *p) {
	return (__u64)(unsigned long)p;
}

/* Copy cnt records of src_size bytes into slots of rec_size bytes. */
static void linfo_pack(unsigned char *dst, size_t dst_size, const void *src, size_t src_size, __u32 rec_size, __u32 cnt) {
	size_t copy = rec_size < src_size ? rec_size : src_size;
	__u32 i;

	if ((size_t)rec_size * cnt > dst_size) {
		fprintf(stderr, "linfo: %u records of %u bytes do not fit\n", cnt, rec_size);
		exit(1);
	}

	memset(dst, 0, dst_size);
	for (i = 0; i < cnt; i++)
		memcpy(dst + (size_t)i * rec_size, (const unsigned char *)src + i * src_size, copy);
}

static void linfo_info_init(const struct linfo_case *c, struct linfo_bufs *b, struct bpf_prog_info *info) {
	linfo_pack(b->line_info, sizeof(b->line_info), c->line_info, sizeof(*c->line_info), c->rec_size, c->nr_line_info);
	linfo_pack(b->jited, sizeof(b->jited), c->jited, sizeof(*c->jited), c->jited_rec_size, c->jited_cnt);

	memset(info, 0, sizeof(*info));
	info->nr_line_info             = c->nr_line_info;
	info->line_info_rec_size       = c->rec_size;
	info->line_info                = c->nr_line_info ? linfo_ptr(b->line_info) : 0;
	info->nr_jited_line_info       = c->nr_jited_line_info;
	info->jited_line_info_rec_size = c->jited_rec_size;
	info->jited_line_info          = c->jited_cnt ? linfo_ptr(b->jited) : 0;
	info->nr_jited_ksyms           = c->nr_jited_ksyms;
	info->jited_ksyms              = c->ksyms_cnt ? linfo_ptr(c->ksyms) : 0;
	info->nr_jited_func_lens       = c->nr_jited_func_lens;
	info->jited_func_lens          = c->func_lens_cnt ? linfo_ptr(c->func_lens) : 0;
}

/* The index of the record the search returned, found by its unique insn_off, or -errno. */
static int linfo_result(const struct linfo_case *c, const struct bpf_line_info *found, int err) {
	__u32 i;

	if (!found)
		return -err;

	for (i = 0; i < c->nr_line_info; i++) {
		if (c->line_info[i].insn_off == found->insn_off)
			return (int)i;
	}

	fprintf(stderr, "linfo: %s returned an unknown record at insn_off %u\n", c->name, found->insn_off);
	exit(1);
}

static void linfo_print_input(struct json *j, const struct linfo_case *c) {
	__u32 i;

	json_u32(j, "line_info_rec_size", c->rec_size);
	json_u32(j, "nr_line_info", c->nr_line_info);
	json_arr_begin(j, "line_info");
	for (i = 0; i < c->nr_line_info; i++) {
		json_obj_begin_compact(j, NULL);
		json_u32(j, "insn_off", c->line_info[i].insn_off);
		json_u32(j, "file_name_off", c->line_info[i].file_name_off);
		json_u32(j, "line_off", c->line_info[i].line_off);
		json_u32(j, "line_col", c->line_info[i].line_col);
		json_obj_end(j);
	}
	json_arr_end(j);

	json_u32(j, "jited_line_info_rec_size", c->jited_rec_size);
	json_u32(j, "nr_jited_line_info", c->nr_jited_line_info);
	json_arr_begin_compact(j, "jited_line_info");
	for (i = 0; i < c->jited_cnt; i++)
		json_u64(j, NULL, c->jited[i]);
	json_arr_end(j);

	json_u32(j, "nr_jited_ksyms", c->nr_jited_ksyms);
	json_arr_begin_compact(j, "jited_ksyms");
	for (i = 0; i < c->ksyms_cnt; i++)
		json_u64(j, NULL, c->ksyms[i]);
	json_arr_end(j);

	json_u32(j, "nr_jited_func_lens", c->nr_jited_func_lens);
	json_arr_begin_compact(j, "jited_func_lens");
	for (i = 0; i < c->func_lens_cnt; i++)
		json_u32(j, NULL, c->func_lens[i]);
	json_arr_end(j);
}

/* Every instruction offset from 0 to one past the last record, for every nr_skip up to nr_line_info. */
static void linfo_print_lfind(struct json *j, const struct linfo_case *c, const struct bpf_prog_linfo *prog_linfo) {
	const struct bpf_line_info *found;
	__u32 last = c->line_info[c->nr_line_info - 1].insn_off;
	__u32 insn_off, nr_skip;

	json_arr_begin_compact(j, "insn_offs");
	for (insn_off = 0; insn_off <= last + 1; insn_off++)
		json_u32(j, NULL, insn_off);
	json_arr_end(j);

	json_arr_begin(j, "lfind");
	for (nr_skip = 0; nr_skip <= c->nr_line_info; nr_skip++) {
		json_obj_begin_compact(j, NULL);
		json_u32(j, "nr_skip", nr_skip);
		json_arr_begin_compact(j, "records");
		for (insn_off = 0; insn_off <= last + 1; insn_off++) {
			found = bpf_prog_linfo__lfind(prog_linfo, insn_off, nr_skip);
			json_s32(j, NULL, linfo_result(c, found, errno));
		}
		json_arr_end(j);
		json_obj_end(j);
	}
	json_arr_end(j);
}

/* Address 0, each jited address and the byte before it, and the largest address. */
static __u32 linfo_addrs(const struct linfo_case *c, __u64 *addrs) {
	__u32 i, n = 0;

	addrs[n++] = 0;
	for (i = 0; i < c->jited_cnt; i++) {
		addrs[n++] = c->jited[i] - 1;
		addrs[n++] = c->jited[i];
	}
	addrs[n++] = UINT64_MAX;
	return n;
}

/* Every address for every func_idx up to nr_jited_ksyms and every nr_skip up to nr_line_info. */
static void linfo_print_lfind_addr_func(struct json *j, const struct linfo_case *c, const struct bpf_prog_linfo *prog_linfo) {
	const struct bpf_line_info *found;
	__u64 addrs[LINFO_MAX_ADDRS];
	__u32 nr_addrs, func_idx, nr_skip, i;

	nr_addrs = linfo_addrs(c, addrs);
	json_arr_begin_compact(j, "addrs");
	for (i = 0; i < nr_addrs; i++)
		json_u64(j, NULL, addrs[i]);
	json_arr_end(j);

	json_arr_begin(j, "lfind_addr_func");
	for (func_idx = 0; func_idx <= c->nr_jited_ksyms; func_idx++) {
		for (nr_skip = 0; nr_skip <= c->nr_line_info; nr_skip++) {
			json_obj_begin_compact(j, NULL);
			json_u32(j, "func_idx", func_idx);
			json_u32(j, "nr_skip", nr_skip);
			json_arr_begin_compact(j, "records");
			for (i = 0; i < nr_addrs; i++) {
				found = bpf_prog_linfo__lfind_addr_func(prog_linfo, addrs[i], func_idx, nr_skip);
				json_s32(j, NULL, linfo_result(c, found, errno));
			}
			json_arr_end(j);
			json_obj_end(j);
		}
	}
	json_arr_end(j);
}

static void linfo_run_case(struct json *j, const struct linfo_case *c) {
	struct bpf_prog_linfo *prog_linfo;
	struct bpf_prog_info info;
	struct linfo_bufs bufs;

	linfo_info_init(c, &bufs, &info);
	errno      = 0;
	prog_linfo = bpf_prog_linfo__new(&info);

	json_obj_begin(j, NULL);
	json_str(j, "name", c->name);
	linfo_print_input(j, c);
	json_s32(j, "new_errno", prog_linfo ? 0 : errno);

	if (prog_linfo) {
		linfo_print_lfind(j, c, prog_linfo);
		linfo_print_lfind_addr_func(j, c, prog_linfo);
	}

	json_obj_end(j);
	bpf_prog_linfo__free(prog_linfo);
}

int oracle_linfo(void) {
	struct oracle_meta meta = {.case_name = "linfo", .version = true};
	struct json j;
	size_t i;

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);

	json_arr_begin(&j, "cases");
	for (i = 0; i < ORACLE_ARRAY_SIZE(linfo_cases); i++)
		linfo_run_case(&j, &linfo_cases[i]);
	json_arr_end(&j);

	json_obj_end(&j);
	fputc('\n', stdout);
	return 0;
}
