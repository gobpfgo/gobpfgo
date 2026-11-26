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

#define RINGBUF_MAP "events"
#define RINGBUF_MAP2 "events2"
#define RINGBUF_PROG "handle_ringbuf"
#define RINGBUF_SAMPLE 0x12345678
#define RINGBUF_MAX 8

struct sample_ctx {
	__u32 cnt;
	__u32 values[RINGBUF_MAX];
};

static int sample_cb(void *ctx, void *data, size_t size) {
	struct sample_ctx *samples = ctx;

	if (size != sizeof(__u32))
		return -EINVAL;
	if (samples->cnt >= RINGBUF_MAX)
		return 0;
	memcpy(&samples->values[samples->cnt], data, size);
	samples->cnt++;
	return 0;
}

static bool trigger_open(void) {
	int fd = open("/dev/null", O_RDONLY);

	if (fd < 0)
		return false;
	close(fd);
	return true;
}

int oracle_ringbuf(const char *path) {
	struct oracle_meta meta    = {.case_name = "ringbuf", .version = true};
	struct sample_ctx samples  = {};
	struct sample_ctx samples2 = {};
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *map, *map2;
	struct bpf_link *link;
	struct ring_buffer *rb;
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

	prog = bpf_object__find_program_by_name(obj, RINGBUF_PROG);
	map  = bpf_object__find_map_by_name(obj, RINGBUF_MAP);
	map2 = bpf_object__find_map_by_name(obj, RINGBUF_MAP2);
	if (!prog || !map || !map2) {
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

	rb  = ring_buffer__new(bpf_map__fd(map), sample_cb, &samples, NULL);
	err = libbpf_get_error(rb);
	if (err) {
		fprintf(stderr, "ring_buffer__new: %s\n", strerror((int)-err));
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return 1;
	}
	if (ring_buffer__add(rb, bpf_map__fd(map2), sample_cb, &samples2) < 0) {
		fprintf(stderr, "ring_buffer__add: %s\n", strerror(errno));
		ring_buffer__free(rb);
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return 1;
	}

	if (!trigger_open()) {
		fprintf(stderr, "open /dev/null: %s\n", strerror(errno));
		ring_buffer__free(rb);
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return 1;
	}
	if (ring_buffer__poll(rb, 1000) < 0) {
		fprintf(stderr, "ring_buffer__poll: %s\n", strerror(errno));
		ring_buffer__free(rb);
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return 1;
	}
	if (samples.cnt == 0 || samples.values[0] != RINGBUF_SAMPLE || samples2.cnt == 0 || samples2.values[0] != RINGBUF_SAMPLE) {
		fprintf(stderr, "unexpected ringbuf samples\n");
		ring_buffer__free(rb);
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return 1;
	}

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);
	json_str(&j, "object_name", bpf_object__name(obj));
	json_str(&j, "program", bpf_program__name(prog));
	json_str(&j, "map", RINGBUF_MAP);
	json_str(&j, "map2", RINGBUF_MAP2);
	json_arr_begin(&j, "samples");
	for (__u32 i = 0; i < samples.cnt; i++)
		json_u32(&j, NULL, samples.values[i]);
	json_arr_end(&j);
	json_arr_begin(&j, "samples2");
	for (__u32 i = 0; i < samples2.cnt; i++)
		json_u32(&j, NULL, samples2.values[i]);
	json_arr_end(&j);
	json_obj_end(&j);
	fputc('\n', stdout);

	ring_buffer__free(rb);
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
