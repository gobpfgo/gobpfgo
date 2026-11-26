// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

#include "oracle.h"

#include "libbpf.h"

#include <linux/bpf.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char counts_map[]       = "counts";
static const char handle_open_prog[] = "handle_open";
static const char attach_function[]  = "do_sys_openat2";

// trigger_open issues one open syscall, the event the program counts.
static bool trigger_open(void) {
	int fd = open("/dev/null", O_RDONLY);

	if (fd < 0)
		return false;
	close(fd);
	return true;
}

static bool kprobe_fired(struct bpf_object *obj) {
	struct bpf_map *map = bpf_object__find_map_by_name(obj, counts_map);
	__u64 value         = 0;
	__u32 key           = 0;

	if (!map)
		return false;
	if (bpf_map__lookup_elem(map, &key, sizeof(key), &value, sizeof(value), 0) < 0)
		return false;
	return value > 0;
}

int oracle_attach(const char *path) {
	struct oracle_meta meta = {.case_name = "attach", .version = true};
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_link *link;
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

	prog = bpf_object__find_program_by_name(obj, handle_open_prog);
	if (!prog) {
		fprintf(stderr, "program %s not found\n", handle_open_prog);
		bpf_object__close(obj);
		return 1;
	}

	link = bpf_program__attach_kprobe(prog, false, attach_function);
	err  = libbpf_get_error(link);
	if (err) {
		fprintf(stderr, "attach %s to %s: %s\n", handle_open_prog, attach_function, strerror((int)-err));
		bpf_object__close(obj);
		return 1;
	}

	if (!trigger_open()) {
		fprintf(stderr, "open /dev/null: %s\n", strerror(errno));
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return 1;
	}
	if (!kprobe_fired(obj)) {
		fprintf(stderr, "kprobe %s did not increment %s\n", attach_function, counts_map);
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return 1;
	}

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);
	json_str(&j, "object_name", bpf_object__name(obj));
	json_str(&j, "program", bpf_program__name(prog));
	json_str(&j, "function", attach_function);
	json_bool(&j, "triggered", true);
	json_obj_end(&j);
	fputc('\n', stdout);

	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
