// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: fixup_verifier_log, find_prev_line, patch_log, fixup_log_missing_map_load

package libbpf

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
)

// poisonLdimm64MapLogPrefix starts the verifier's error line for a reachable
// poisoned map reference: the helper ID is poisonLdimm64MapBase plus the map
// index, which prints as 200100 followed by four more digits.
const poisonLdimm64MapLogPrefix = "invalid func unknown#200100"

// maxLogPatchLen is the longest replacement text the log fixup writes.
const maxLogPatchLen = 127

// poisonCallLine matches the verifier's line for a poisoned call instruction,
// "<insn>: (<code>) call unknown#<id>", with the optional whitespace and
// signs that the C scanf format "%d: (%*d) call unknown#%d" accepts.
var poisonCallLine = regexp.MustCompile(`^\s*([+-]?\d+):\s*\(\s*[+-]?\d+\)\s*call\s*unknown#\s*([+-]?\d+)`)

// fixupVerifierLog rewrites the verifier log in buf after a failed program
// load of obj. The log is the C string at the start of buf, and len(buf) is
// its capacity. When one of the last ten lines reports a poisoned call for a
// map that the load did not create, that line and the instruction line
// before it become two lines that name the instruction and the map. Text
// after them moves to make room, and the end of the log is cut when buf is
// full. Any other log is left unchanged.
func fixupVerifierLog(obj *BpfObject, buf []byte) {
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
		if bytes.HasPrefix(buf[cur:end], []byte(poisonLdimm64MapLogPrefix)) {
			if prev := findPrevLine(buf, cur); prev >= 0 {
				fixupLogMissingMapLoad(obj, buf, end+1, prev, next)
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

// fixupLogMissingMapLoad replaces the log lines from line1 to line3, a
// poisoned call instruction and the verifier's error for it, with the
// instruction index and the name of the map the call stands for. The log is
// logSz bytes long, including its NUL. Lines that do not parse, or name no
// map of obj, are left unchanged.
func fixupLogMissingMapLoad(obj *BpfObject, buf []byte, logSz, line1, line3 int) {
	match := poisonCallLine.FindSubmatch(buf[line1 : logSz-1])
	if match == nil {
		return
	}
	insnIdx, err := strconv.Atoi(string(match[1]))
	if err != nil {
		return
	}
	id, err := strconv.Atoi(string(match[2]))
	if err != nil {
		return
	}
	mapIdx := id - poisonLdimm64MapBase
	if mapIdx < 0 || mapIdx >= len(obj.maps) {
		return
	}

	patch := fmt.Sprintf("%d: <invalid BPF map reference>\nBPF map '%s' is referenced but wasn't created\n",
		insnIdx, obj.maps[mapIdx].name)
	if len(patch) > maxLogPatchLen {
		patch = patch[:maxLogPatchLen]
	}
	patchLog(buf, logSz, line1, line3-line1, patch)
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
