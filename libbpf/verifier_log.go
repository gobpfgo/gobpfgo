// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: fixup_verifier_log, find_prev_line, patch_log, fixup_log_failed_core_relo, find_relo_core, fixup_log_missing_map_load, fixup_log_missing_kfunc_call

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"

	"github.com/gobpfgo/gobpfgo/internal/btf"
)

// coreReloPoisonLogLine is the verifier's error line, with its newline, for
// a reachable instruction that a failed CO-RE relocation poisoned: a call to
// helper ID 195896080, 0xbad2310 in hexadecimal.
const coreReloPoisonLogLine = "invalid func unknown#195896080\n"

// poisonLdimm64MapLogPrefix starts the verifier's error line for a reachable
// poisoned map reference: the helper ID is poisonLdimm64MapBase plus the map
// index, which prints as 200100 followed by four more digits.
const poisonLdimm64MapLogPrefix = "invalid func unknown#200100"

// poisonCallKfuncLogPrefix starts the verifier's error line for a reachable
// poisoned call to an unresolved kernel function: the helper ID is
// poisonCallKfuncBase plus the extern index. libbpf matches only the first
// four digits, so the map prefix must be checked first.
const poisonCallKfuncLogPrefix = "invalid func unknown#2002"

// maxLogPatchLen is the longest replacement text the map and kfunc log
// fixups write, and maxCoreLogPatchLen the longest the CO-RE one writes.
const (
	maxLogPatchLen     = 127
	maxCoreLogPatchLen = 511
)

// coreSpecLogLen is the size of the buffer libbpf formats a CO-RE spec into
// for the log, NUL included. A longer spec is cut and followed by "...".
const coreSpecLogLen = 256

// poisonCallLine matches the verifier's line for a poisoned call instruction,
// "<insn>: (<code>) call unknown#<id>", with the optional whitespace and
// signs that the C scanf format "%d: (%*d) call unknown#%d" accepts.
var poisonCallLine = regexp.MustCompile(`^\s*([+-]?\d+):\s*\(\s*[+-]?\d+\)\s*call\s*unknown#\s*([+-]?\d+)`)

// coreReloCallLine matches the instruction index at the start of the
// verifier's line for a call that a failed CO-RE relocation poisoned. The C
// scanf format is "%d: (%*d) call unknown#195896080\n", but scanf counts only
// the instruction index as a conversion, and libbpf checks only that count,
// so the rest of the line does not have to match.
var coreReloCallLine = regexp.MustCompile(`^\s*([+-]?\d+)`)

// logFixup rewrites the log lines from line1 to line3 of the log in buf,
// which is logSz bytes long including its NUL, after a failed load of code, a
// main program of obj.
type logFixup func(obj *BpfObject, code *progCode, buf []byte, logSz, line1, line3 int)

// fixupVerifierLog rewrites the verifier log in buf after a failed load of
// code, a main program of obj; code may be nil when the log names no CO-RE
// relocation. The log is the C string at the start of buf, and len(buf) is
// its capacity. When one of the last ten lines reports a poisoned call, that
// line and the instruction line before it become two lines that name the
// instruction and what the call stands for: a CO-RE relocation that did not
// resolve, a map that the load did not create, or a kernel function extern
// that it did not resolve. Text after them moves to make room, and the end
// of the log is cut when buf is full. Any other log is left unchanged.
func fixupVerifierLog(obj *BpfObject, code *progCode, buf []byte) {
	const maxLastLineCnt = 10

	end := bytes.IndexByte(buf, 0)
	if end < 0 {
		return
	}
	next := end
	for range maxLastLineCnt {
		cur := findPrevLine(buf, next)
		if cur < 0 {
			return
		}
		var fixup logFixup
		switch {
		case bytes.HasPrefix(buf[cur:end], []byte(coreReloPoisonLogLine)):
			fixup = fixupLogFailedCoreRelo
		case bytes.HasPrefix(buf[cur:end], []byte(poisonLdimm64MapLogPrefix)):
			fixup = fixupLogMissingMapLoad
		case bytes.HasPrefix(buf[cur:end], []byte(poisonCallKfuncLogPrefix)):
			fixup = fixupLogMissingKfuncCall
		}
		if fixup != nil {
			if prev := findPrevLine(buf, cur); prev >= 0 {
				fixup(obj, code, buf, end+1, prev, next)
				return
			}
		}
		next = cur
	}
}

// findPrevLine returns the start of the line that ends right before offset
// cur in buf, or -1 when cur is the start of buf.
func findPrevLine(buf []byte, cur int) int {
	if cur == 0 {
		return -1
	}
	p := cur - 1
	for p-1 >= 0 && buf[p-1] != '\n' {
		p--
	}
	return p
}

// fixupLogFailedCoreRelo replaces the log lines from line1 to line3, a call
// that a failed CO-RE relocation poisoned and the verifier's error for it,
// with the instruction index and the relocation's local spec as
// btf.Spec.FormatCoreSpec prints it. A spec longer than libbpf's buffer is
// cut and followed by "...". The log is logSz bytes long, including its NUL.
// Lines that do not parse, an index without a CO-RE relocation in code, and
// a spec that does not resolve leave the log unchanged.
func fixupLogFailedCoreRelo(obj *BpfObject, code *progCode, buf []byte, logSz, line1, line3 int) {
	match := coreReloCallLine.FindSubmatch(buf[line1 : logSz-1])
	if match == nil {
		return
	}
	insnIdx, err := strconv.Atoi(string(match[1]))
	if err != nil {
		return
	}
	relo, ok := findReloCore(obj, code, insnIdx)
	if !ok {
		return
	}
	spec, err := obj.btf.ParseCoreSpec(relo)
	if err != nil {
		return
	}
	text, err := obj.btf.FormatCoreSpec(spec)
	if err != nil {
		return
	}
	patchLog(buf, logSz, line1, line3-line1, coreReloLogPatch(insnIdx, text))
}

// coreReloLogPatch returns the two log lines that replace a call at insnIdx
// poisoned by the failed CO-RE relocation with spec text spec. A spec that
// does not fit in libbpf's 256-byte buffer is cut to 255 bytes and followed
// by "...", and the lines are cut to maxCoreLogPatchLen bytes.
func coreReloLogPatch(insnIdx int, spec string) string {
	cut := ""
	if len(spec) >= coreSpecLogLen {
		spec, cut = spec[:coreSpecLogLen-1], "..."
	}
	patch := fmt.Sprintf("%d: <invalid CO-RE relocation>\nfailed to resolve CO-RE relocation %s%s\n", insnIdx, spec, cut)
	return truncateLogPatch(patch, maxCoreLogPatchLen)
}

// findReloCore returns the CO-RE relocation of the instruction at insnIdx in
// code, the final code of a main program: a record of the program's own
// function or of a subprogram appended to it, counted from where that copy
// starts. The records come from the object's .BTF.ext; no kernel BTF is
// needed.
func findReloCore(obj *BpfObject, code *progCode, insnIdx int) (btf.CoreRelo, bool) {
	if obj == nil || code == nil || obj.btf == nil || obj.elf == nil || len(obj.elf.BTFExt) == 0 {
		return btf.CoreRelo{}, false
	}
	ext, err := btf.ParseExt(obj.elf.BTFExt, obj.btf, obj.elf.ByteOrder)
	if err != nil {
		return btf.CoreRelo{}, false
	}

	// The copies do not overlap, so at most one holds insnIdx.
	for p, start := range code.subInsnOff {
		if insnIdx < start || insnIdx >= start+p.secInsnCnt {
			continue
		}
		secInsnIdx := insnIdx - start + p.secInsnOff
		for _, section := range ext.CoreRelos {
			if section.Section != p.sectionName {
				continue
			}
			for _, relo := range section.Relos {
				if relo.InsnOff%bpfInsnLength == 0 && int(relo.InsnOff/bpfInsnLength) == secInsnIdx {
					return relo, true
				}
			}
		}
	}
	return btf.CoreRelo{}, false
}

// fixupLogMissingMapLoad replaces the log lines from line1 to line3, a
// poisoned call instruction and the verifier's error for it, with the
// instruction index and the name of the map the call stands for. The log is
// logSz bytes long, including its NUL. Lines that do not parse, or name no
// map of obj, are left unchanged.
func fixupLogMissingMapLoad(obj *BpfObject, _ *progCode, buf []byte, logSz, line1, line3 int) {
	insnIdx, id, ok := parsePoisonCallLine(buf[line1 : logSz-1])
	if !ok {
		return
	}
	mapIdx := id - poisonLdimm64MapBase
	if mapIdx < 0 || mapIdx >= len(obj.maps) {
		return
	}

	patch := fmt.Sprintf("%d: <invalid BPF map reference>\nBPF map '%s' is referenced but wasn't created\n",
		insnIdx, obj.maps[mapIdx].name)
	patchLog(buf, logSz, line1, line3-line1, truncateLogPatch(patch, maxLogPatchLen))
}

// fixupLogMissingKfuncCall replaces the log lines from line1 to line3, a
// poisoned call instruction and the verifier's error for it, with the
// instruction index and the name of the kernel function extern the call
// stands for. The log is logSz bytes long, including its NUL. Lines that do
// not parse, or name no extern of obj, are left unchanged.
func fixupLogMissingKfuncCall(obj *BpfObject, _ *progCode, buf []byte, logSz, line1, line3 int) {
	insnIdx, id, ok := parsePoisonCallLine(buf[line1 : logSz-1])
	if !ok {
		return
	}
	extIdx := id - poisonCallKfuncBase
	if extIdx < 0 || extIdx >= len(obj.externs) {
		return
	}

	patch := fmt.Sprintf("%d: <invalid kfunc call>\nkfunc '%s' is referenced but wasn't resolved\n",
		insnIdx, obj.externs[extIdx].name)
	patchLog(buf, logSz, line1, line3-line1, truncateLogPatch(patch, maxLogPatchLen))
}

// parsePoisonCallLine parses the instruction index and the helper ID of the
// poisoned call instruction line at the start of log, as libbpf's sscanf
// format "%d: (%*d) call unknown#%d" does.
func parsePoisonCallLine(log []byte) (insnIdx, id int, ok bool) {
	match := poisonCallLine.FindSubmatch(log)
	if match == nil {
		return 0, 0, false
	}
	insnIdx, err := strconv.Atoi(string(match[1]))
	if err != nil {
		return 0, 0, false
	}
	id, err = strconv.Atoi(string(match[2]))
	if err != nil {
		return 0, 0, false
	}
	return insnIdx, id, true
}

// truncateLogPatch cuts patch to maxLen bytes, as libbpf's snprintf into a
// buffer of maxLen+1 bytes does.
func truncateLogPatch(patch string, maxLen int) string {
	if len(patch) > maxLen {
		return patch[:maxLen]
	}
	return patch
}

// patchLog replaces the origSz bytes at offset orig of the log in buf, which
// is logSz bytes long including its NUL, with patch. The rest of the log,
// with its NUL, moves to follow the patch. When the longer text does not fit
// in len(buf), the rest of the log is cut at the end of buf, or, if the patch
// itself reaches the end, the patch is cut one byte short of it and the rest
// of the log is dropped.
func patchLog(buf []byte, logSz, orig, origSz int, patch string) {
	bufSz := len(buf)
	remSz := logSz - (orig + origSz)
	patchSz := len(patch)

	if patchSz != origSz {
		if patchSz > origSz {
			if orig+patchSz >= bufSz {
				patchSz -= orig + patchSz - bufSz + 1
				remSz = 0
			} else if patchSz-origSz > bufSz-logSz {
				remSz -= patchSz - origSz - (bufSz - logSz)
			}
		}
		copy(buf[orig+patchSz:], buf[orig+origSz:orig+origSz+remSz])
	}
	copy(buf[orig:], patch[:patchSz])
}

// verifierLogString returns the log in buf: the bytes before the first NUL,
// or all of buf when the log fills it without one. Bytes after the NUL are
// left over from an earlier load or a log fixup and are not part of the log.
func verifierLogString(buf []byte) string {
	if end := bytes.IndexByte(buf, 0); end >= 0 {
		return string(buf[:end])
	}
	return string(buf)
}
