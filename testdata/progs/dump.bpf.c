// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

// Type zoo for the BTF dump oracle. The globals force clang to emit every
// type into .BTF; the object is never loaded.

#include <linux/bpf.h>
#include <bpf_helpers.h>

#define __decl_tag(name) __attribute__((btf_decl_tag(name)))
#define __type_tag(name) __attribute__((btf_type_tag(name)))

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef signed char s8;
typedef signed short s16;
typedef signed int s32;
typedef signed long long s64;
typedef u32 u32_array[3];
typedef int (*callback_t)(int, const char *);
typedef void (*void_fn)(void);

struct fwd_only;
struct fwd_holder {
	struct fwd_only *fwd;
};

struct never_defined;
struct never_holder {
	struct never_defined *ptr;
};

struct empty {};

struct node {
	struct node *next;
	int value;
};

struct fwd_only {
	u64 id;
};

struct bits {
	unsigned int a : 3;
	unsigned int b : 5;
	signed int c : 1;
	unsigned int d : 7;
};

struct packed_sample {
	u8 a;
	u32 b;
} __attribute__((packed));

struct flex {
	u32 len;
	u8 data[];
};

struct anon_holder {
	struct {
		int x;
		int y;
	} point;
	union {
		u32 u;
		s32 i;
	};
};

struct fn_holder {
	callback_t callback;
	int (*direct)(int, const char *);
	const volatile u32 *cv;
	u32 *const fixed;
	u32 matrix[2][3];
	u32_array triple;
};

struct tricky {
	u32 (*array_ptr)[4];
	int (*fp_arr[2])(int);
	void_fn fn;
};

union sample_union {
	u32 u;
	s32 i;
	u8 bytes[4];
};

enum color {
	COLOR_RED,
	COLOR_GREEN = 5,
	COLOR_BLUE,
};

enum signed_color {
	SIGNED_NEG = -2,
	SIGNED_POS = 2,
};

enum big64 {
	BIG64_ONE  = 1ULL,
	BIG64_HIGH = 0x100000000ULL,
};

enum small8 {
	SMALL8_ONE = 1,
} __attribute__((mode(byte)));

struct tagged {
	int value __decl_tag("field_tag");
	int __type_tag("user") * ptr;
} __decl_tag("struct_tag");

struct fwd_only *fwd_ptr;
struct node *node_ptr;
struct fwd_holder *fwd_holder_ptr;
struct never_holder *never_holder_ptr;
struct empty *empty_ptr;
struct tricky *tricky_ptr;
struct bits *bits_ptr;
struct packed_sample *packed_ptr;
struct flex *flex_ptr;
struct anon_holder *anon_ptr;
struct fn_holder *fn_ptr;
union sample_union *union_ptr;
struct tagged *tagged_ptr;
enum color *color_ptr;
enum signed_color *signed_color_ptr;
enum big64 *big64_ptr;
enum small8 *small8_ptr;
u32_array *array_ptr;
callback_t *callback_ptr;
float f32;
double f64;

SEC("kprobe/do_sys_openat2")
int dump_prog(void *ctx) {
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
