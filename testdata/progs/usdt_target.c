// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

// USDT target for the note and argument parser tests. Each probe leaves one
// SystemTap SDT note in .note.stapsdt; the program fires every probe once and
// nothing needs to trace it.

#include <sys/sdt.h>

// The address escapes, so the array stays on the stack and the third args
// operand is a memory reference.
__attribute__((noinline)) static void usdt_fill(long *values, int count) {
	int i;

	for (i = 0; i < count; i++)
		values[i] = count - i;
}

// A probe without arguments.
__attribute__((noinline)) static void usdt_start(void) {
	STAP_PROBE(gobpfgo, start);
}

// A constant, a register and a memory operand.
__attribute__((noinline)) static long usdt_args(int count) {
	long values[4];

	usdt_fill(values, 4);
	STAP_PROBE3(gobpfgo, args, -5, count, values[2]);
	return values[0];
}

// One-, two-, four- and eight-byte operands, signed and unsigned. The first
// six arrive in registers, including byte registers such as %sil; the last
// is on the stack.
__attribute__((noinline)) static void usdt_sizes(signed char s8, unsigned char u8, short s16, unsigned short u16, int s32, unsigned int u32, unsigned long u64) {
	STAP_PROBE7(gobpfgo, sizes, s8, u8, s16, u16, s32, u32, u64);
}

// sys/sdt.h gives every probe of a translation unit a semaphore or none. The
// sema probe redefines the semaphore operand so the fixture has both kinds of
// note. Only the probes below this point use it; the counter lives in
// .probes, as the header expects.
#undef _SDT_SEMAPHORE
#define _SDT_SEMAPHORE(p, n) _SDT_ASM_1(_SDT_ASM_ADDR p##_##n##_semaphore)

unsigned short gobpfgo_sema_semaphore __attribute__((section(".probes"))) = 0;

__attribute__((noinline)) static void usdt_sema(int value) {
	STAP_PROBE1(gobpfgo, sema, value);
}

int main(int argc, char **argv) {
	(void)argv;

	usdt_start();
	usdt_sizes((signed char)-argc, (unsigned char)argc, (short)-argc, (unsigned short)argc, -argc, (unsigned int)argc, (unsigned long)argc);
	usdt_sema(argc);
	return usdt_args(argc) == 4 ? 0 : 1;
}
