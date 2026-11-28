// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>
#include <bpf_core_read.h>

// Local flavors of the types in core_match_target.c. Each check below is one
// type-based CO-RE relocation; the program is relocated against the target
// BTF and never loaded. The comment after each type says whether it matches
// its target.

enum cm_enum___sub { // matches: names, not values, count
	CM_ONE___sub   = 7,
	CM_THREE___sub = 9,
};

enum cm_enum___extra { // no match: CM_FOUR is not in the target
	CM_ONE___extra  = 1,
	CM_FOUR___extra = 4,
};

enum cm_enum64___narrow { // no match: a 4-byte enum against an 8-byte enum64
	CM64_LOW___narrow = 1,
};

enum cm_enum64___wide { // matches
	CM64_LOW___wide  = 1,
	CM64_HIGH___wide = 0x100000000ULL,
};

struct cm_struct___same { // matches: every member of the target
	int i;
	unsigned int u;
	long l;
	const volatile int cv;
	struct cm_inner {
		int a;
		long b;
	} inner;
	struct cm_inner *inner_ptr;
	struct cm_fwd *fwd_ptr;
	union cm_fwd_union *fwd_union_ptr;
	struct cm_inner *complete_ptr;
	int arr[4];
	int matrix[2][3];
	enum cm_enum {
		CM_ONE   = 1,
		CM_TWO   = 2,
		CM_THREE = 3,
	} e;
	int (*fn)(int, long);
	union {
		int ui;
		long ul;
	};
	struct {
		char c;
		short s;
	} anon_type;
	union cm_union {
		int i;
		long l;
	} un;
};

struct cm_struct___subset { // matches: fewer members, in another order
	long l;
	int i;
};

struct cm_struct___missing { // no match: no member named missing
	int i;
	int missing;
};

struct cm_struct___int_name { // no match: unsigned int is not int
	unsigned int i;
};

typedef int cm_local_int;

struct cm_struct___typedefs { // matches: typedefs on either side are skipped
	unsigned int u;
	cm_local_int i;
};

struct cm_struct___modifiers { // matches: modifiers on either side are skipped
	int cv;
	const int i;
};

struct cm_struct___inner_sub { // matches
	struct cm_inner___sub {
		long b;
	} inner;
};

struct cm_struct___inner_extra { // no match: the inner struct has more members
	struct cm_inner___extra {
		int a;
		long b;
		char c;
	} inner;
};

struct cm_struct___inner_name { // no match: another inner struct name
	struct cm_other_inner {
		int a;
	} inner;
};

struct cm_struct___ptr_loose { // matches: behind a pointer only names count
	struct cm_inner___loose {
		int nonexistent;
	} *inner_ptr;
};

struct cm_struct___ptr_union { // no match: a union pointer for a struct one
	union cm_inner___union {
		int a;
	} *inner_ptr;
};

struct cm_struct___ptr_name { // no match: a pointer to another struct
	struct cm_other_ptr {
		int a;
	} *inner_ptr;
};

struct cm_struct___not_ptr { // no match: a struct for a pointer
	struct cm_inner___not_ptr {
		int a;
	} inner_ptr;
};

struct cm_inner___fwd;
union cm_inner___ufwd;
struct cm_fwd___fwd;

struct cm_struct___local_fwd { // matches: a local struct declaration
	struct cm_inner___fwd *complete_ptr;
};

struct cm_struct___local_ufwd { // no match: a union declaration for a struct
	union cm_inner___ufwd *complete_ptr;
};

struct cm_struct___fwd_fwd { // matches: two struct declarations
	struct cm_fwd___fwd *fwd_ptr;
};

struct cm_struct___fwd_complete { // matches: a struct for a declaration
	struct cm_fwd___complete {
		int x;
	} *fwd_ptr;
};

struct cm_struct___fwd_union { // no match: a struct for a union declaration
	struct cm_fwd_union___complete {
		int x;
	} *fwd_union_ptr;
};

struct cm_struct___arrays { // matches
	int arr[4];
	int matrix[2][3];
};

struct cm_struct___arr_len { // no match
	int arr[5];
};

struct cm_struct___arr_elem { // no match
	unsigned int arr[4];
};

struct cm_struct___matrix_dims { // no match
	int matrix[3][2];
};

struct cm_struct___fn { // matches
	int (*fn)(int, long);
};

struct cm_struct___fn_args { // no match: fewer arguments
	int (*fn)(int);
};

struct cm_struct___fn_ret { // no match: another return type
	long (*fn)(int, long);
};

struct cm_struct___fn_arg_type { // no match: another argument type
	int (*fn)(long, long);
};

struct cm_struct___anon { // matches: anonymous members match each other
	union {
		long ul;
	};
};

struct cm_struct___anon_extra { // no match
	union {
		int ui;
		char missing;
	};
};

struct cm_struct___anon_type { // matches: anonymous types match each other
	struct {
		short s;
	} anon_type;
};

struct cm_struct___anon_type_bad { // no match
	struct {
		int s;
	} anon_type;
};

struct cm_struct___members { // matches
	enum cm_enum___member {
		CM_TWO___member = 5,
	} e;
	union cm_union___member {
		long l;
	} un;
};

union cm_union___sub { // matches
	long l;
};

union cm_union___bad { // no match
	int i;
	char c;
};

struct cm_union___struct { // no candidate: the target is a union
	int i;
};

struct cm_struct___a___b { // no candidate: the flavor is ___b only
	int i;
};

struct cm____odd___v { // matches cm____odd
	int x;
};

typedef struct cm_struct___td { // matches through the typedef
	int i;
} cm_struct_t___td;

typedef int (*cm_fn_t___ok)(int, long); // matches
typedef int (*cm_fn_t___bad)(int, int); // no match
typedef int *******************************cm_ptr_ok_t___l; // matches
typedef int ********************************cm_ptr_deep_t___l; // too deep

struct cm_dup___m { // matches both candidates
	int a;
};

struct cm_ptr_ok___l { // matches
	int *******************************p;
};

struct cm_ptr_deep___l { // too deep
	int ********************************p;
};

#define CM_NEST(name, n, next) \
	struct name##n##___l { \
		struct name##next##___l m; \
	}

#define CM_NEST_LEAF(name, n) \
	struct name##n##___l { \
		int leaf; \
	}

CM_NEST_LEAF(cm_deep, 31);
CM_NEST(cm_deep, 30, 31);
CM_NEST(cm_deep, 29, 30);
CM_NEST(cm_deep, 28, 29);
CM_NEST(cm_deep, 27, 28);
CM_NEST(cm_deep, 26, 27);
CM_NEST(cm_deep, 25, 26);
CM_NEST(cm_deep, 24, 25);
CM_NEST(cm_deep, 23, 24);
CM_NEST(cm_deep, 22, 23);
CM_NEST(cm_deep, 21, 22);
CM_NEST(cm_deep, 20, 21);
CM_NEST(cm_deep, 19, 20);
CM_NEST(cm_deep, 18, 19);
CM_NEST(cm_deep, 17, 18);
CM_NEST(cm_deep, 16, 17);
CM_NEST(cm_deep, 15, 16);
CM_NEST(cm_deep, 14, 15);
CM_NEST(cm_deep, 13, 14);
CM_NEST(cm_deep, 12, 13);
CM_NEST(cm_deep, 11, 12);
CM_NEST(cm_deep, 10, 11);
CM_NEST(cm_deep, 9, 10);
CM_NEST(cm_deep, 8, 9);
CM_NEST(cm_deep, 7, 8);
CM_NEST(cm_deep, 6, 7);
CM_NEST(cm_deep, 5, 6);
CM_NEST(cm_deep, 4, 5);
CM_NEST(cm_deep, 3, 4);
CM_NEST(cm_deep, 2, 3);
CM_NEST(cm_deep, 1, 2);
CM_NEST(cm_deep, 0, 1); // too deep

CM_NEST_LEAF(cm_shallow, 30);
CM_NEST(cm_shallow, 29, 30);
CM_NEST(cm_shallow, 28, 29);
CM_NEST(cm_shallow, 27, 28);
CM_NEST(cm_shallow, 26, 27);
CM_NEST(cm_shallow, 25, 26);
CM_NEST(cm_shallow, 24, 25);
CM_NEST(cm_shallow, 23, 24);
CM_NEST(cm_shallow, 22, 23);
CM_NEST(cm_shallow, 21, 22);
CM_NEST(cm_shallow, 20, 21);
CM_NEST(cm_shallow, 19, 20);
CM_NEST(cm_shallow, 18, 19);
CM_NEST(cm_shallow, 17, 18);
CM_NEST(cm_shallow, 16, 17);
CM_NEST(cm_shallow, 15, 16);
CM_NEST(cm_shallow, 14, 15);
CM_NEST(cm_shallow, 13, 14);
CM_NEST(cm_shallow, 12, 13);
CM_NEST(cm_shallow, 11, 12);
CM_NEST(cm_shallow, 10, 11);
CM_NEST(cm_shallow, 9, 10);
CM_NEST(cm_shallow, 8, 9);
CM_NEST(cm_shallow, 7, 8);
CM_NEST(cm_shallow, 6, 7);
CM_NEST(cm_shallow, 5, 6);
CM_NEST(cm_shallow, 4, 5);
CM_NEST(cm_shallow, 3, 4);
CM_NEST(cm_shallow, 2, 3);
CM_NEST(cm_shallow, 1, 2);
CM_NEST(cm_shallow, 0, 1); // matches

__u64 results[64];

SEC("kprobe/do_sys_openat2")
int handle_match(void *ctx) {
	results[0]  = bpf_core_type_matches(enum cm_enum___sub);
	results[1]  = bpf_core_type_matches(enum cm_enum___extra);
	results[2]  = bpf_core_type_matches(enum cm_enum64___narrow);
	results[3]  = bpf_core_type_matches(enum cm_enum64___wide);
	results[4]  = bpf_core_type_matches(struct cm_struct___same);
	results[5]  = bpf_core_type_matches(struct cm_struct___subset);
	results[6]  = bpf_core_type_matches(struct cm_struct___missing);
	results[7]  = bpf_core_type_matches(struct cm_struct___int_name);
	results[8]  = bpf_core_type_matches(struct cm_struct___typedefs);
	results[9]  = bpf_core_type_matches(struct cm_struct___modifiers);
	results[10] = bpf_core_type_matches(struct cm_struct___inner_sub);
	results[11] = bpf_core_type_matches(struct cm_struct___inner_extra);
	results[12] = bpf_core_type_matches(struct cm_struct___inner_name);
	results[13] = bpf_core_type_matches(struct cm_struct___ptr_loose);
	results[14] = bpf_core_type_matches(struct cm_struct___ptr_union);
	results[15] = bpf_core_type_matches(struct cm_struct___ptr_name);
	results[16] = bpf_core_type_matches(struct cm_struct___not_ptr);
	results[17] = bpf_core_type_matches(struct cm_struct___local_fwd);
	results[18] = bpf_core_type_matches(struct cm_struct___local_ufwd);
	results[19] = bpf_core_type_matches(struct cm_struct___fwd_fwd);
	results[20] = bpf_core_type_matches(struct cm_struct___fwd_complete);
	results[21] = bpf_core_type_matches(struct cm_struct___fwd_union);
	results[22] = bpf_core_type_matches(struct cm_struct___arrays);
	results[23] = bpf_core_type_matches(struct cm_struct___arr_len);
	results[24] = bpf_core_type_matches(struct cm_struct___arr_elem);
	results[25] = bpf_core_type_matches(struct cm_struct___matrix_dims);
	results[26] = bpf_core_type_matches(struct cm_struct___fn);
	results[27] = bpf_core_type_matches(struct cm_struct___fn_args);
	results[28] = bpf_core_type_matches(struct cm_struct___fn_ret);
	results[29] = bpf_core_type_matches(struct cm_struct___fn_arg_type);
	results[30] = bpf_core_type_matches(struct cm_struct___anon);
	results[31] = bpf_core_type_matches(struct cm_struct___anon_extra);
	results[32] = bpf_core_type_matches(struct cm_struct___anon_type);
	results[33] = bpf_core_type_matches(struct cm_struct___anon_type_bad);
	results[34] = bpf_core_type_matches(struct cm_struct___members);
	results[35] = bpf_core_type_matches(union cm_union___sub);
	results[36] = bpf_core_type_matches(union cm_union___bad);
	results[37] = bpf_core_type_matches(struct cm_union___struct);
	results[38] = bpf_core_type_matches(struct cm_struct___a___b);
	results[39] = bpf_core_type_matches(struct cm____odd___v);
	results[40] = bpf_core_type_matches(cm_struct_t___td);
	results[41] = bpf_core_type_matches(cm_fn_t___ok);
	results[42] = bpf_core_type_matches(cm_fn_t___bad);
	results[43] = bpf_core_type_matches(struct cm_dup___m);
	results[44] = bpf_core_type_matches(struct cm_ptr_ok___l);
	results[45] = bpf_core_type_matches(struct cm_ptr_deep___l);
	results[46] = bpf_core_type_matches(struct cm_deep0___l);
	results[47] = bpf_core_type_matches(struct cm_shallow0___l);
	results[48] = bpf_core_type_matches(cm_ptr_ok_t___l);
	results[49] = bpf_core_type_matches(cm_ptr_deep_t___l);

	// The other type-based kinds use the compatibility check instead.
	results[50] = bpf_core_type_exists(struct cm_struct___missing);
	results[51] = bpf_core_type_exists(struct cm_union___struct);
	results[52] = bpf_core_type_exists(cm_ptr_ok_t___l);
	results[53] = bpf_core_type_exists(cm_ptr_deep_t___l);
	results[54] = bpf_core_type_size(struct cm_struct___subset);
	results[55] = bpf_core_type_size(struct cm_dup___m);
	results[56] = bpf_core_type_id_kernel(struct cm_struct___subset);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
