// SPDX-License-Identifier: LGPL-2.1-only
// Original gobpfgo code.

// Target BTF for the CO-RE test. The field order differs from the local
// core_sample, so second moves from offset 4 to offset 8.

struct core_sample {
	int first;
	int pad;
	int second;
};

struct core_sample target_sample;
