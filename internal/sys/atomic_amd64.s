// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

#include "textflag.h"

// func loadAcquire64(ptr uintptr) uint64
TEXT ·loadAcquire64(SB), NOSPLIT, $0-16
	MOVQ ptr+0(FP), AX
	MOVQ (AX), AX
	MOVQ AX, ret+8(FP)
	RET

// func storeRelease64(ptr uintptr, val uint64)
TEXT ·storeRelease64(SB), NOSPLIT, $0-16
	MOVQ ptr+0(FP), AX
	MOVQ val+8(FP), BX
	MOVQ BX, (AX)
	RET
