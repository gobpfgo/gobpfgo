// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* The cookie handle_throw throws and on_throw records. */
#define EXC_THROW_COOKIE 0x6578630042ULL

/* __exception_cb names the global .text function the verifier runs when the
 * tagged main program throws. Nothing calls that function, so the loader
 * appends it to the program because of the tag, and the verifier finds it
 * through its function record.
 */
#define __exception_cb(name) __attribute__((btf_decl_tag("exception_callback:" #name)))

/* bpf_throw unwinds the program and returns through its exception callback.
 * It needs Linux 6.7.
 */
extern void bpf_throw(__u64 cookie) __ksym;

/* The slots of exc_state. User space writes the target process ID; the
 * programs write the rest for that process only.
 */
enum {
	EXC_TARGET_TGID = 0,
	EXC_COOKIE      = 1,
	EXC_CALLS       = 2,
	EXC_OPENS       = 3,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} exc_state SEC(".maps");

/* A static subprogram that only the exception callback and handle_count
 * call, so the callback's own calls are relocated after it is appended.
 */
static __noinline void exc_record(__u32 slot, __u64 value, int add) {
	__u64 *state = bpf_map_lookup_elem(&exc_state, &slot);

	if (!state)
		return;

	if (add)
		__sync_fetch_and_add(state, value);
	else
		*state = value;
}

/* exc_target reports whether the current process is the one user space
 * wrote to EXC_TARGET_TGID.
 */
static __always_inline int exc_target(void) {
	__u32 key    = EXC_TARGET_TGID;
	__u64 *tgid  = bpf_map_lookup_elem(&exc_state, &key);
	__u64 thisid = bpf_get_current_pid_tgid() >> 32;

	return tgid && *tgid != 0 && *tgid == thisid;
}

/* The exception callback: a global .text function with one integer argument
 * that receives the thrown cookie. Its return value is the program's, which
 * must be 0 for fentry.
 */
__noinline int on_throw(__u64 cookie) {
	exc_record(EXC_COOKIE, cookie, 0);
	exc_record(EXC_CALLS, 1, 1);
	return 0;
}

/* Throws for the target process only, so other processes' opens run the
 * program to its end.
 */
SEC("fentry/do_sys_openat2")
__exception_cb(on_throw) int handle_throw(void *ctx) {
	if (exc_target())
		bpf_throw(EXC_THROW_COOKIE);

	return 0;
}

/* A program without the tag. The callback is not appended to it, and the
 * open it counts still completes after handle_throw threw.
 */
SEC("fexit/do_sys_openat2")
int handle_count(void *ctx) {
	if (exc_target())
		exc_record(EXC_OPENS, 1, 1);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
