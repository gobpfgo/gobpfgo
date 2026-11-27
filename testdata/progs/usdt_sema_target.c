// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

// USDT semaphore target for the attach tests. It prints "ready", then for
// every byte it reads from stdin fires the gobpfgo:sema probe at two call
// sites, prints "fired" and then "semaphore <n>", the current value of the
// probe's semaphore. It exits at end of input, like usdt_loop_target.
//
// Only the second call site carries the semaphore, so one attachment has a
// call site with a reference counter and one without. While a uprobe with the
// reference counter is installed in this process the kernel keeps the
// semaphore incremented, and it decrements it when the uprobe goes away; the
// printed value lets a test watch both.
//
// Like usdt_loop_target, the binary is an x86-64 static PIE without a C
// library.

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
__attribute__((noinline)) static void sema_fill(long *slots, int count) {
	int i;

	for (i = 0; i < count; i++)
		slots[i] = 100 + i;
}

// The call sites pass the same arguments as usdt_loop_target's: a constant
// site number, the round in a register, a stack slot and the negated round as
// a signed two-byte value. This one comes before the semaphore override, so
// its note has no semaphore.
__attribute__((noinline)) static void sema_site_a(int round, long *slots) {
	STAP_PROBE4(gobpfgo, sema, 1, round, slots[2], (short)-round);
}

// sys/sdt.h gives every probe of a translation unit a semaphore or none. As in
// usdt_target.c, the override gives one to the call sites below this point;
// the counter lives in .probes, as the header expects.
#undef _SDT_SEMAPHORE
#define _SDT_SEMAPHORE(p, n) _SDT_ASM_1(_SDT_ASM_ADDR p##_##n##_semaphore)

unsigned short gobpfgo_sema_semaphore __attribute__((section(".probes"))) = 0;

__attribute__((noinline)) static void sema_site_b(int round, long *slots) {
	STAP_PROBE4(gobpfgo, sema, 2, round, slots[3], (short)-round);
}

static int say(const char *line, long len) {
	return syscall3(SYS_write, 1, (long)line, len) == len ? 0 : -1;
}

// say_semaphore prints "semaphore <n>". The kernel changes the counter behind
// the compiler's back, so it is read through a volatile access.
static int say_semaphore(void) {
	unsigned int value = *(volatile unsigned short *)&gobpfgo_sema_semaphore;
	char digits[8];
	int i = sizeof(digits);

	digits[--i] = '\n';
	do {
		digits[--i] = '0' + value % 10;
		value /= 10;
	} while (value);

	if (say("semaphore ", 10))
		return -1;
	return say(digits + i, sizeof(digits) - i);
}

__attribute__((used)) static int run(void) {
	long slots[4];
	int round = 0;
	char c;

	sema_fill(slots, 4);
	if (say("ready\n", 6))
		return 1;

	while (syscall3(SYS_read, 0, (long)&c, 1) == 1) {
		round++;
		sema_site_a(round, slots);
		sema_site_b(round, slots);
		if (say("fired\n", 6) || say_semaphore())
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
