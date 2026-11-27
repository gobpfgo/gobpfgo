// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include "oracle.h"

#include "libbpf.h"

#include <linux/bpf.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PROG_DIR_MAX PATH_MAX
#define BPF_COOKIE 0x1234
#define COOKIE_MAP "cookies"
#define COUNTS_MAP "counts"

/*
 * A case attaches program in object as kind to target. mode is the
 * bpf_kprobe_opts or bpf_uprobe_opts attach mode of a kprobe or uprobe case
 * and PROBE_ATTACH_MODE_DEFAULT for the other kinds. A cookie case passes
 * BPF_COOKIE and reads it back from the cookies map; its kprobe and uprobe
 * cases retype cookie.bpf.o's tracepoint program as a kprobe program.
 */
struct attach_case {
	const char *kind;
	const char *object;
	const char *program;
	const char *category;
	const char *target;
	enum probe_attach_mode mode;
	bool retprobe;
	bool cookie;
};

static const struct attach_case attach_cases[] = {
	{.kind = "kprobe", .object = "kprobe.bpf.o", .program = "handle_open", .target = "do_sys_openat2"},
	{.kind = "kretprobe", .object = "kprobe.bpf.o", .program = "handle_open", .target = "do_sys_openat2", .retprobe = true},
	{.kind = "tracepoint", .object = "tracepoint.bpf.o", .program = "handle_tracepoint", .category = "syscalls", .target = "sys_enter_openat"},
	{.kind = "uprobe", .object = "uprobe.bpf.o", .program = "handle_uprobe", .target = "oracle_uprobe_target"},
	{.kind = "uretprobe", .object = "uprobe.bpf.o", .program = "handle_uretprobe", .target = "oracle_uprobe_target", .retprobe = true},
	{.kind = "fentry", .object = "fentry.bpf.o", .program = "handle_fentry", .target = "do_sys_openat2"},
	{.kind = "fexit", .object = "fentry.bpf.o", .program = "handle_fexit", .target = "do_sys_openat2"},
	{.kind = "raw_tracepoint", .object = "raw_tp.bpf.o", .program = "handle_raw_tp", .target = "sys_enter"},
	{.kind = "kprobe_multi", .object = "kprobe_multi.bpf.o", .program = "handle_open_multi", .target = "do_sys_openat2"},
	{.kind = "kretprobe_multi", .object = "kprobe_multi.bpf.o", .program = "handle_open_multi", .target = "do_sys_openat2", .retprobe = true},
	{.kind = "lsm", .object = "lsm.bpf.o", .program = "handle_lsm", .target = "file_open"},
	{.kind = "cookie", .object = "cookie.bpf.o", .program = "handle_cookie", .category = "syscalls", .target = "sys_enter_openat", .cookie = true},
	{.kind = "kprobe", .object = "kprobe.bpf.o", .program = "handle_open", .target = "do_sys_openat2", .mode = PROBE_ATTACH_MODE_LEGACY},
	{.kind = "kprobe", .object = "kprobe.bpf.o", .program = "handle_open", .target = "do_sys_openat2", .mode = PROBE_ATTACH_MODE_PERF},
	{.kind = "kprobe", .object = "kprobe.bpf.o", .program = "handle_open", .target = "do_sys_openat2", .mode = PROBE_ATTACH_MODE_LINK},
	{.kind = "kprobe", .object = "cookie.bpf.o", .program = "handle_cookie", .target = "do_sys_openat2", .mode = PROBE_ATTACH_MODE_LINK, .cookie = true},
	{.kind = "uprobe", .object = "uprobe.bpf.o", .program = "handle_uprobe", .target = "oracle_uprobe_target", .mode = PROBE_ATTACH_MODE_LEGACY},
	{.kind = "uprobe", .object = "uprobe.bpf.o", .program = "handle_uprobe", .target = "oracle_uprobe_target", .mode = PROBE_ATTACH_MODE_PERF},
	{.kind = "uprobe", .object = "uprobe.bpf.o", .program = "handle_uprobe", .target = "oracle_uprobe_target", .mode = PROBE_ATTACH_MODE_LINK},
};

struct attach_result {
	bool supported;
	bool triggered;
	__u64 cookie;
};

__attribute__((noinline)) void oracle_uprobe_target(void) {
	asm volatile("" ::: "memory");
}

static bool is_kprobe(const struct attach_case *c) {
	return !strcmp(c->kind, "kprobe") || !strcmp(c->kind, "kretprobe");
}

static bool is_uprobe(const struct attach_case *c) {
	return !strcmp(c->kind, "uprobe") || !strcmp(c->kind, "uretprobe");
}

static const char *mode_name(enum probe_attach_mode mode) {
	switch (mode) {
	case PROBE_ATTACH_MODE_DEFAULT:
		return "default";
	case PROBE_ATTACH_MODE_LEGACY:
		return "legacy";
	case PROBE_ATTACH_MODE_PERF:
		return "perf";
	case PROBE_ATTACH_MODE_LINK:
		return "link";
	}
	return "unknown";
}

static bool trigger_open(void) {
	int fd = open("/dev/null", O_RDONLY);

	if (fd < 0)
		return false;
	close(fd);
	return true;
}

static bool trigger_case(const struct attach_case *c) {
	if (is_uprobe(c)) {
		oracle_uprobe_target();
		return true;
	}
	return trigger_open();
}

static struct bpf_object *open_case_object(const char *prog_dir, const struct attach_case *c) {
	char path[PROG_DIR_MAX];
	struct bpf_object *obj;
	long err;

	if (snprintf(path, sizeof(path), "%s/%s", prog_dir, c->object) >= (int)sizeof(path))
		return NULL;

	obj = bpf_object__open_file(path, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "open %s: %s\n", path, strerror((int)-err));
		return NULL;
	}
	return obj;
}

static bool lookup_counter(struct bpf_object *obj, const char *map_name, __u64 *value) {
	struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
	__u32 key           = 0;

	if (!map)
		return false;
	return bpf_map__lookup_elem(map, &key, sizeof(key), value, sizeof(*value), 0) == 0;
}

static struct bpf_link *attach_program(const struct attach_case *c, struct bpf_program *prog) {
	__u64 cookie = c->cookie ? BPF_COOKIE : 0;

	if (is_kprobe(c)) {
		LIBBPF_OPTS(bpf_kprobe_opts, opts, .bpf_cookie = cookie, .retprobe = c->retprobe, .attach_mode = c->mode);

		return bpf_program__attach_kprobe_opts(prog, c->target, &opts);
	}

	if (!strcmp(c->kind, "tracepoint") || !strcmp(c->kind, "cookie")) {
		LIBBPF_OPTS(bpf_tracepoint_opts, opts, .bpf_cookie = cookie);

		return bpf_program__attach_tracepoint_opts(prog, c->category, c->target, &opts);
	}

	if (is_uprobe(c)) {
		LIBBPF_OPTS(bpf_uprobe_opts, opts, .bpf_cookie = cookie, .retprobe = c->retprobe, .func_name = c->target, .attach_mode = c->mode);

		return bpf_program__attach_uprobe_opts(prog, 0, "/proc/self/exe", 0, &opts);
	}

	if (!strcmp(c->kind, "fentry") || !strcmp(c->kind, "fexit"))
		return bpf_program__attach_trace(prog);

	if (!strcmp(c->kind, "lsm"))
		return bpf_program__attach_lsm(prog);

	if (!strcmp(c->kind, "raw_tracepoint"))
		return bpf_program__attach_raw_tracepoint(prog, c->target);

	if (!strcmp(c->kind, "kprobe_multi") || !strcmp(c->kind, "kretprobe_multi")) {
		LIBBPF_OPTS(bpf_kprobe_multi_opts, opts, .retprobe = c->retprobe);

		return bpf_program__attach_kprobe_multi_opts(prog, c->target, &opts);
	}

	return NULL;
}

static bool unsupported_errno(long err) {
	return err == -EOPNOTSUPP || err == -EINVAL || err == -ENOENT || err == -ESRCH;
}

static bool run_attach_case(const char *prog_dir, const struct attach_case *c, struct attach_result *result) {
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link;
	__u64 value = 0;
	long err;

	memset(result, 0, sizeof(*result));

	obj = open_case_object(prog_dir, c);
	if (!obj)
		return false;

	prog = bpf_object__find_program_by_name(obj, c->program);
	if (!prog) {
		fprintf(stderr, "program %s not found\n", c->program);
		bpf_object__close(obj);
		return false;
	}
	if (c->cookie && (is_kprobe(c) || is_uprobe(c))) {
		err = bpf_program__set_type(prog, BPF_PROG_TYPE_KPROBE);
		if (err) {
			fprintf(stderr, "retype %s: %s\n", c->program, strerror((int)-err));
			bpf_object__close(obj);
			return false;
		}
	}

	/* A kernel without the BPF LSM or BPF cookies refuses the program. */
	err = bpf_object__load(obj);
	if (err) {
		bpf_object__close(obj);
		if ((!strcmp(c->kind, "lsm") || c->cookie) && unsupported_errno(err))
			return true;
		fprintf(stderr, "load %s: %s\n", c->object, strerror((int)-err));
		return false;
	}

	link = attach_program(c, prog);
	err  = libbpf_get_error(link);
	if (err) {
		bpf_object__close(obj);
		if (!unsupported_errno(err)) {
			fprintf(stderr, "attach %s %s: %s\n", c->kind, mode_name(c->mode), strerror((int)-err));
			return false;
		}
		return true;
	}
	result->supported = true;

	if (!trigger_case(c)) {
		fprintf(stderr, "trigger %s %s failed\n", c->kind, mode_name(c->mode));
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return false;
	}

	if (!lookup_counter(obj, c->cookie ? COOKIE_MAP : COUNTS_MAP, &value)) {
		fprintf(stderr, "lookup %s failed\n", c->cookie ? COOKIE_MAP : COUNTS_MAP);
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return false;
	}

	result->cookie = value;
	if (c->cookie)
		result->triggered = value == BPF_COOKIE;
	else
		result->triggered = value > 0;
	if (!result->triggered) {
		fprintf(stderr, "%s %s did not trigger\n", c->kind, mode_name(c->mode));
		bpf_link__destroy(link);
		bpf_object__close(obj);
		return false;
	}

	bpf_link__destroy(link);
	bpf_object__close(obj);
	return true;
}

static void emit_case(struct json *j, const struct attach_case *c, const struct attach_result *result) {
	json_obj_begin(j, NULL);
	json_str(j, "kind", c->kind);
	json_str(j, "object", c->object);
	json_str(j, "program", c->program);
	if (c->category)
		json_str(j, "category", c->category);
	json_str(j, "target", c->target);
	json_str(j, "mode", mode_name(c->mode));
	json_bool(j, "retprobe", c->retprobe);
	json_bool(j, "cookie", c->cookie);
	json_u64(j, "cookie_value", result->cookie);
	json_bool(j, "supported", result->supported);
	json_bool(j, "triggered", result->triggered);
	json_obj_end(j);
}

int oracle_attach(const char *prog_dir) {
	struct oracle_meta meta = {.case_name = "attach", .version = true};
	struct json j;
	size_t i;
	bool ok;

	json_init(&j, stdout);
	json_obj_begin(&j, NULL);
	oracle_meta(&j, &meta);
	json_arr_begin(&j, "cases");

	for (i = 0; i < ORACLE_ARRAY_SIZE(attach_cases); i++) {
		struct attach_result result;

		ok = run_attach_case(prog_dir, &attach_cases[i], &result);
		if (!ok)
			return 1;
		emit_case(&j, &attach_cases[i], &result);
	}

	json_arr_end(&j);
	json_obj_end(&j);
	fputc('\n', stdout);
	return 0;
}
