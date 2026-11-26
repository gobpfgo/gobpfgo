// SPDX-License-Identifier: LGPL-2.1-only
// Original golbpfgo code.

//go:build linux && (amd64 || arm64)

package sys

import "runtime"

func archMatches(uname string) bool {
	switch runtime.GOARCH {
	case "amd64":
		return uname == "x86_64"
	case "arm64":
		return uname == "aarch64"
	default:
		return false
	}
}
