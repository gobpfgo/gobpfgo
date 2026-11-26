// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include "libbpf.h"

#include <linux/bpf.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PERFBUF_MAP "events"
#define PERFBUF_PROG "handle_perfbuf"
#define PERFBUF_SAMPLE 0x12345678
#define PERFBUF_MAX 8
#define PERFBUF_PAGES 8

struct sample_ctx {
	__u32 cnt;
	__u32 values[PERFBUF_MAX];
	__u64 lost;
};

static void sample_cb(void *ctx, int cpu, void *data, __u32 size) {
	struct sample_ctx *samples = ctx;

	(void)cpu;
	if (size != sizeof(__u32))
		return;
	if (samples->cnt >= PERFBUF_MAX)
		return;
	memcpy(&samples->values[samples->cnt], data, size);
	samples->cnt++;
}

static void lost_cb(void *ctx, int cpu, __u64 lost) {
	struct sample_ctx *samples = ctx;

	(void)cpu;
	samples->lost += lost;
}

static bool trigger_open(void) {
	int fd = open("/dev/null", O_RDONLY);

	if (fd < 0)
		return false;
	close(fd);
	return true;
}

int oracle_perfbuf(const char *path) {
	struct oracle_meta meta   = {.case_name = "perfbuf", .version = true};
	struct sample_ctx samples = {};
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *map;
	struct bpf_link *link;
	struct perf_buffer *pb;
	struct json j;
	long err;
	int ret;

	obj = bpf_object__open_file(path, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "open %s: %s\n", path, strerror((int)-err));
		return 1;
	}

	ret = bpf_object__load(obj);
	if (ret) {
		fprintf(stderr, "load %s: %s\n", path, strerror(-ret));
		bpf_object__close(obj);
		return 1;
	}

	prog = bpf_object__find_program_by_name(obj, PERFBUF_PROG);
	map  = bpf_object__find_map_by_name(obj, PERFBUF_MAP);
	if (!prog || !map) {
		fprintf(stderr, "program or map not found\n");
		bpf_object__close(obj);
		return 1;
	}

	link = bpf_program__attach_kprobe(prog, false, "do_sys_openat2");
	err  = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "attach: %s\n", strerror((int)-err));
		bpf_object__close(obj);
		return 1;
	}

	pb  = perf_buffer__new(bpf_map__fd(map), PERFBUF_PAGES, sample_cb, lost_cb, &samples, NULL);
	err = libbpf_get_error(pb);
	if (err) {
		fprintf(stderr, "perf_buffer__new: %s\n", strerror((int)-err));
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return 1;
	}

	if (!trigger_open()) {
		fprintf(stderr, "open /dev/null: %s\n", strerror(errno));
		perf_buffer__free(pb);
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return 1;
	}
	if (perf_buffer__poll(pb, 1000) < 0) {
		fprintf(stderr, "perf_buffer__poll: %s\n", strerror(errno));
		perf_buffer__free(pb);
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return 1;
	}
	if (samples.cnt == 0 || samples.values[0] != PERFBUF_SAMPLE) {
		fprintf(stderr, "unexpected perfbuf samples\n");
		perf_buffer__free(pb);
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return 1;
	}

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);
	json_str(&j, "object_name", bpf_object__name(obj));
	json_str(&j, "program", bpf_program__name(prog));
	json_str(&j, "map", PERFBUF_MAP);
	json_u64(&j, "buffer_cnt", perf_buffer__buffer_cnt(pb));
	json_arr_begin(&j, "samples");
	for (__u32 i = 0; i < samples.cnt; i++)
		json_u32(&j, NULL, samples.values[i]);
	json_arr_end(&j);
	json_u64(&j, "lost", samples.lost);
	json_obj_end(&j);
	fputc('\n', stdout);

	perf_buffer__free(pb);
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
