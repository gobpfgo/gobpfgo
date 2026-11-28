// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

/* bench times the libbpf operations that libbpf/bench_test.go times in the Go
 * port, with the same fixtures, map and program names, iteration counts and
 * warmup. Each operation runs warmup_iters() times untimed, then its
 * iteration count timed with CLOCK_MONOTONIC, and prints one line,
 * "<name> ns/op <mean>", on stdout. A root-only operation that bpf() refuses
 * with EPERM or EACCES prints "<name> skip errno <n> (<text>)" instead.
 * Details such as type and byte counts go to stderr.
 */

#include "btf.h"
#include "libbpf.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define PROGS "../testdata/progs"
#define KPROBE_OBJECT PROGS "/kprobe.bpf.o"
#define LINK_A_OBJECT PROGS "/link_a.bpf.o"
#define LINK_B_OBJECT PROGS "/link_b.bpf.o"
#define VMLINUX_BTF "/sys/kernel/btf/vmlinux"

#define MAP_NAME "counts"
#define PROG_NAME "handle_open"
#define KPROBE_FUNC "do_sys_openat2"
#define DUMP_TYPE "task_struct"

#define OPEN_ITERS 2000
#define LOAD_ITERS 200
#define MAP_ITERS 200000
#define BTF_PARSE_ITERS 20
#define BTF_DEDUP_ITERS 3
#define LINKER_ITERS 200
#define ATTACH_ITERS 200
#define DUMP_ITERS 200

/* bench_fn runs one iteration. It returns 0 or a negative errno. */
typedef int (*bench_fn)(void *ctx);

static uint64_t now_ns(void) {
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* warmup_iters is the untimed iteration count before iters timed ones: a
 * tenth, at least one. libbpf/bench_test.go uses the same rule.
 */
static int warmup_iters(int iters) {
	return iters / 10 > 0 ? iters / 10 : 1;
}

static void print_result(const char *name, uint64_t elapsed, int iters) {
	printf("%s ns/op %.0f\n", name, (double)elapsed / iters);
	fflush(stdout);
}

/* finish reports err for name. A root-only operation refused with EPERM or
 * EACCES prints a skip line and succeeds; any other error fails.
 */
static int finish(const char *name, int err, bool root) {
	if (!err)
		return 0;
	if (root && (err == -EPERM || err == -EACCES)) {
		printf("%s skip errno %d (%s)\n", name, -err, strerror(-err));
		fflush(stdout);
		return 0;
	}
	fprintf(stderr, "%s: %s\n", name, strerror(-err));
	return 1;
}

/* run_bench runs fn warmup_iters(iters) times, then iters times timed, and
 * prints the mean. It returns 0 or the first error of fn.
 */
static int run_bench(const char *name, int iters, bench_fn fn, void *ctx) {
	uint64_t start;
	int i, err;

	for (i = 0; i < warmup_iters(iters); i++) {
		err = fn(ctx);
		if (err)
			return err;
	}

	start = now_ns();
	for (i = 0; i < iters; i++) {
		err = fn(ctx);
		if (err)
			return err;
	}
	print_result(name, now_ns() - start, iters);
	return 0;
}

static int neg_errno(void) {
	return errno ? -errno : -EINVAL;
}

/* open */

static int open_op(void *ctx) {
	struct bpf_object *obj;

	obj = bpf_object__open_file(ctx, NULL);
	if (!obj)
		return neg_errno();
	bpf_object__close(obj);
	return 0;
}

static int bench_open(const char *path) {
	return finish("open", run_bench("open", OPEN_ITERS, open_op, (void *)path), false);
}

/* load */

static int load_op(void *ctx) {
	struct bpf_object *obj;
	int err;

	obj = bpf_object__open_file(ctx, NULL);
	if (!obj)
		return neg_errno();
	err = bpf_object__load(obj);
	bpf_object__close(obj);
	return err;
}

static int bench_load(const char *path) {
	return finish("load", run_bench("load", LOAD_ITERS, load_op, (void *)path), true);
}

/* open_loaded opens and loads path into *objp. It returns 0 or a negative
 * errno.
 */
static int open_loaded(const char *path, struct bpf_object **objp) {
	struct bpf_object *obj;
	int err;

	obj = bpf_object__open_file(path, NULL);
	if (!obj)
		return neg_errno();
	err = bpf_object__load(obj);
	if (err) {
		bpf_object__close(obj);
		return err;
	}
	*objp = obj;
	return 0;
}

/* map */

struct map_ctx {
	struct bpf_map *map;
	__u32 key;
	__u64 value;
};

static int map_lookup_op(void *ctx) {
	struct map_ctx *m = ctx;

	return bpf_map__lookup_elem(m->map, &m->key, sizeof(m->key), &m->value, sizeof(m->value), 0);
}

static int map_update_op(void *ctx) {
	struct map_ctx *m = ctx;

	return bpf_map__update_elem(m->map, &m->key, sizeof(m->key), &m->value, sizeof(m->value), BPF_ANY);
}

static int bench_map(const char *path) {
	struct map_ctx m       = {.key = 0, .value = 1};
	struct bpf_object *obj = NULL;
	int err;

	err = open_loaded(path, &obj);
	if (err) {
		int ret = finish("map-lookup", err, true);
		return ret | finish("map-update", err, true);
	}

	m.map = bpf_object__find_map_by_name(obj, MAP_NAME);
	if (!m.map) {
		fprintf(stderr, "map %s not found in %s\n", MAP_NAME, path);
		bpf_object__close(obj);
		return 1;
	}

	err = finish("map-lookup", run_bench("map-lookup", MAP_ITERS, map_lookup_op, &m), true);
	if (!err) {
		m.value = 1;
		err     = finish("map-update", run_bench("map-update", MAP_ITERS, map_update_op, &m), true);
	}
	bpf_object__close(obj);
	return err;
}

/* btf */

static int btf_parse_op(void *ctx) {
	struct btf *btf;

	btf = btf__parse(ctx, NULL);
	if (!btf)
		return neg_errno();
	btf__free(btf);
	return 0;
}

/* bench_btf_dedup parses path untimed in every iteration and times only
 * btf__dedup on the parsed table, the way the Go benchmark stops its timer
 * around BtfParse.
 */
static int bench_btf_dedup(const char *path) {
	int warmup       = warmup_iters(BTF_DEDUP_ITERS);
	uint64_t elapsed = 0, start;
	__u32 before = 0, after = 0;
	struct btf *btf;
	int i, err;

	for (i = -warmup; i < BTF_DEDUP_ITERS; i++) {
		btf = btf__parse(path, NULL);
		if (!btf)
			return neg_errno();
		before = btf__type_cnt(btf);
		start  = now_ns();
		err    = btf__dedup(btf, NULL);
		if (i >= 0)
			elapsed += now_ns() - start;
		after = btf__type_cnt(btf);
		btf__free(btf);
		if (err)
			return err;
	}
	fprintf(stderr, "btf-dedup %s types %u -> %u\n", path, before, after);
	print_result("btf-dedup", elapsed, BTF_DEDUP_ITERS);
	return 0;
}

static int bench_btf(const char *path) {
	int err;

	err = finish("btf-parse", run_bench("btf-parse", BTF_PARSE_ITERS, btf_parse_op, (void *)path), false);
	if (err)
		return err;
	return finish("btf-dedup", bench_btf_dedup(path), false);
}

/* linker */

struct linker_ctx {
	const char *inputs[2];
	char output[PATH_MAX];
};

static int linker_op(void *ctx) {
	struct linker_ctx *c = ctx;
	struct bpf_linker *linker;
	int err = 0;
	int i;

	linker = bpf_linker__new(c->output, NULL);
	if (!linker)
		return neg_errno();
	for (i = 0; i < 2 && !err; i++)
		err = bpf_linker__add_file(linker, c->inputs[i], NULL);
	if (!err)
		err = bpf_linker__finalize(linker);
	bpf_linker__free(linker);
	if (unlink(c->output) && !err)
		err = neg_errno();
	return err;
}

static int bench_linker(const char *a, const char *b) {
	struct linker_ctx c = {.inputs = {a, b}};
	const char *tmp     = getenv("TMPDIR");
	char dir[PATH_MAX - 32]; /* leaves room for the output name */
	int err;

	snprintf(dir, sizeof(dir), "%s/gobpfgo-bench-XXXXXX", tmp && *tmp ? tmp : "/tmp");
	if (!mkdtemp(dir)) {
		fprintf(stderr, "mkdtemp %s: %s\n", dir, strerror(errno));
		return 1;
	}
	snprintf(c.output, sizeof(c.output), "%s/linked.bpf.o", dir);

	err = finish("linker", run_bench("linker", LINKER_ITERS, linker_op, &c), false);
	rmdir(dir);
	return err;
}

/* attach */

static int attach_op(void *ctx) {
	struct bpf_link *link;

	link = bpf_program__attach_kprobe(ctx, false, KPROBE_FUNC);
	if (!link)
		return neg_errno();
	return bpf_link__destroy(link);
}

static int bench_attach(const char *path) {
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	int err;

	err = open_loaded(path, &obj);
	if (err)
		return finish("attach", err, true);

	prog = bpf_object__find_program_by_name(obj, PROG_NAME);
	if (!prog) {
		fprintf(stderr, "program %s not found in %s\n", PROG_NAME, path);
		bpf_object__close(obj);
		return 1;
	}

	err = finish("attach", run_bench("attach", ATTACH_ITERS, attach_op, prog), true);
	bpf_object__close(obj);
	return err;
}

/* dump */

/* dump_buf collects the dump text, as the Go benchmark appends it to a
 * reused byte slice.
 */
struct dump_buf {
	char *data;
	size_t len;
	size_t cap;
};

static void dump_printf(void *ctx, const char *fmt, va_list args) {
	struct dump_buf *b = ctx;
	va_list copy;
	size_t cap;
	char *data;
	int n;

	va_copy(copy, args);
	n = vsnprintf(b->data + b->len, b->cap - b->len, fmt, copy);
	va_end(copy);
	if (n < 0)
		return;
	if ((size_t)n >= b->cap - b->len) {
		cap = b->cap * 2;
		while (cap < b->len + (size_t)n + 1)
			cap *= 2;
		data = realloc(b->data, cap);
		if (!data)
			return;
		b->data = data;
		b->cap  = cap;
		vsnprintf(b->data + b->len, b->cap - b->len, fmt, args);
	}
	b->len += n;
}

struct dump_ctx {
	struct btf *btf;
	__u32 id; /* the type to dump, or 0 for every type */
	struct dump_buf buf;
};

static int dump_op(void *ctx) {
	struct dump_ctx *c = ctx;
	struct btf_dump *d;
	__u32 id, n;
	int err = 0;

	c->buf.len = 0;
	d          = btf_dump__new(c->btf, dump_printf, &c->buf, NULL);
	if (!d)
		return neg_errno();
	if (c->id) {
		err = btf_dump__dump_type(d, c->id);
	} else {
		n = btf__type_cnt(c->btf);
		for (id = 1; id < n && !err; id++)
			err = btf_dump__dump_type(d, id);
	}
	btf_dump__free(d);
	return err;
}

/* bench_dump dumps DUMP_TYPE and the types it depends on when path has it,
 * as vmlinux does, and every type otherwise.
 */
static int bench_dump(const char *path) {
	struct dump_ctx c = {0};
	int id, err;

	c.btf = btf__parse(path, NULL);
	if (!c.btf)
		return finish("btf-dump", neg_errno(), false);
	id   = btf__find_by_name_kind(c.btf, DUMP_TYPE, BTF_KIND_STRUCT);
	c.id = id > 0 ? (__u32)id : 0;

	c.buf.cap  = 4096;
	c.buf.data = malloc(c.buf.cap);
	if (!c.buf.data) {
		btf__free(c.btf);
		return finish("btf-dump", -ENOMEM, false);
	}

	err = finish("btf-dump", run_bench("btf-dump", DUMP_ITERS, dump_op, &c), false);
	if (!err)
		fprintf(stderr, "btf-dump %s type %s bytes %zu\n", path, c.id ? DUMP_TYPE : "all", c.buf.len);
	free(c.buf.data);
	btf__free(c.btf);
	return err;
}

/* btf_path is the BTF of the btf and dump subcommands: arg when given, then
 * GOBPFGO_BENCH_BTF, which libbpf/bench_test.go reads too, then vmlinux.
 */
static const char *btf_path(const char *arg) {
	const char *env = getenv("GOBPFGO_BENCH_BTF");

	if (arg)
		return arg;
	return env && *env ? env : VMLINUX_BTF;
}

static void usage(const char *prog) {
	fprintf(stderr, "usage: %s open [object]|load [object]|map [object]|btf [btf]|linker [object object]|attach [object]|dump [btf]|all\n", prog);
}

int main(int argc, char **argv) {
	const char *arg = argc > 2 ? argv[2] : NULL;
	int err         = 0;

	if (argc < 2) {
		usage(argv[0]);
		return 2;
	}

	if (strcmp(argv[1], "open") == 0 && argc <= 3)
		return bench_open(arg ? arg : KPROBE_OBJECT);
	if (strcmp(argv[1], "load") == 0 && argc <= 3)
		return bench_load(arg ? arg : KPROBE_OBJECT);
	if (strcmp(argv[1], "map") == 0 && argc <= 3)
		return bench_map(arg ? arg : KPROBE_OBJECT);
	if (strcmp(argv[1], "btf") == 0 && argc <= 3)
		return bench_btf(btf_path(arg));
	if (strcmp(argv[1], "linker") == 0 && argc == 2)
		return bench_linker(LINK_A_OBJECT, LINK_B_OBJECT);
	if (strcmp(argv[1], "linker") == 0 && argc == 4)
		return bench_linker(argv[2], argv[3]);
	if (strcmp(argv[1], "attach") == 0 && argc <= 3)
		return bench_attach(arg ? arg : KPROBE_OBJECT);
	if (strcmp(argv[1], "dump") == 0 && argc <= 3)
		return bench_dump(btf_path(arg));
	if (strcmp(argv[1], "all") == 0 && argc == 2) {
		err |= bench_open(KPROBE_OBJECT);
		err |= bench_load(KPROBE_OBJECT);
		err |= bench_map(KPROBE_OBJECT);
		err |= bench_btf(btf_path(NULL));
		err |= bench_linker(LINK_A_OBJECT, LINK_B_OBJECT);
		err |= bench_attach(KPROBE_OBJECT);
		err |= bench_dump(btf_path(NULL));
		return err;
	}

	usage(argv[0]);
	return 2;
}
