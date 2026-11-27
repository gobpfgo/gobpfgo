// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

// USDT target for the attach tests. It prints "ready", then fires the
// gobpfgo:loop probe at two call sites for every byte it reads from stdin and
// prints "fired" after each round. It exits at end of input, so a test can
// start it, attach, trigger rounds over a pipe and stop it by closing the
// pipe.
//
// The binary is an x86-64 static PIE without a C library: it makes its three
// system calls directly, so the checked-in file runs on any x86-64 kernel the
// tests cover, whatever C library the host has, and still loads at a random
// base like a shared library.

#include <sys/sdt.h>

#define SYS_read 0
#define SYS_write 1

static long syscall3(long nr, long a, long b, long c) {
	long ret;

	__asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
	return ret;
}

// The address escapes, so the array stays on the stack and the third probe
// operand is a memory reference.
__attribute__((noinline)) static void loop_fill(long *slots, int count) {
	int i;

	for (i = 0; i < count; i++)
		slots[i] = 100 + i;
}

// Both call sites pass a constant site number, the round in a register, a
// stack slot and the negated round as a signed two-byte value. The slots
// differ, so the two sites have different argument specs.
__attribute__((noinline)) static void loop_site_a(int round, long *slots) {
	STAP_PROBE4(gobpfgo, loop, 1, round, slots[2], (short)-round);
}

__attribute__((noinline)) static void loop_site_b(int round, long *slots) {
	STAP_PROBE4(gobpfgo, loop, 2, round, slots[3], (short)-round);
}

static int say(const char *line, long len) {
	return syscall3(SYS_write, 1, (long)line, len) == len ? 0 : -1;
}

__attribute__((used)) static int run(void) {
	long slots[4];
	int round = 0;
	char c;

	loop_fill(slots, 4);
	if (say("ready\n", 6))
		return 1;

	while (syscall3(SYS_read, 0, (long)&c, 1) == 1) {
		round++;
		loop_site_a(round, slots);
		loop_site_b(round, slots);
		if (say("fired\n", 6))
			return 1;
	}
	return 0;
}

// The kernel enters with a 16-byte aligned stack; the call leaves it as a C
// function expects. The exit status is run's result; 60 is SYS_exit.
__asm__(
	".globl _start\n"
	"_start:\n"
	"\txor %ebp, %ebp\n"
	"\tcall run\n"
	"\tmov %eax, %edi\n"
	"\tmov $60, %eax\n"
	"\tsyscall\n");
