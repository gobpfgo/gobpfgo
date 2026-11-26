// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

#include "textflag.h"

// func loadAcquire64(ptr uintptr) uint64
TEXT ·loadAcquire64(SB), NOSPLIT, $0-16
	MOVD ptr+0(FP), R0
	LDAR (R0), R1
	MOVD R1, ret+8(FP)
	RET

// func storeRelease64(ptr uintptr, val uint64)
TEXT ·storeRelease64(SB), NOSPLIT, $0-16
	MOVD ptr+0(FP), R0
	MOVD val+8(FP), R1
	STLR R1, (R0)
	RET
