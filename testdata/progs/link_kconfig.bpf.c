// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

#include <linux/bpf.h>
#include <bpf_helpers.h>

/* Linked with kconfig.bpf.o, which declares CONFIG_TEST and
 * LINUX_KERNEL_VERSION too, so the linker keeps one undefined symbol and one
 * .kconfig variable for each. This CONFIG_TEST is weak; the strong one in
 * kconfig.bpf.o makes the linked symbol strong in either order.
 * CONFIG_GOBPFGO_LINKED is declared only here.
 */
extern int CONFIG_TEST __kconfig __weak;
extern unsigned int LINUX_KERNEL_VERSION __kconfig;
extern __u64 CONFIG_GOBPFGO_LINKED __kconfig;

/* .bss: linked_seen[i] holds what the program read from the i-th extern
 * above. The section and the tracepoint section are new to the linked object,
 * so they come after kconfig.bpf.o's ephemeral .kconfig section.
 */
__u64 linked_seen[3];

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_link_kconfig(void *ctx) {
	linked_seen[0] = CONFIG_TEST;
	linked_seen[1] = LINUX_KERNEL_VERSION;
	linked_seen[2] = CONFIG_GOBPFGO_LINKED;

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
