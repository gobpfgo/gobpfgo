// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: glob_match, tracefs_available_filter_functions, tracefs_available_filter_functions_addrs, has_available_filter_functions_addrs, libbpf_available_kprobes_parse, libbpf_available_kallsyms_parse, avail_kallsyms_cb, avail_func_cmp

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// kallsymsTrimMax is the longest name a kallsyms symbol keeps once its
// .llvm. suffix is cut off for the second lookup.
const kallsymsTrimMax = 255

// globMatch reports whether str matches the pattern pat. A '*' matches any
// run of bytes, the empty run included, a '?' matches exactly one byte, and
// every other byte matches itself. There are no escapes and no character
// classes, so '[' and '\' are literal. An empty pattern matches only the
// empty string.
func globMatch(str, pat string) bool {
	for str != "" && pat != "" && pat[0] != '*' {
		if pat[0] != '?' && str[0] != pat[0] {
			return false
		}
		str, pat = str[1:], pat[1:]
	}
	if pat != "" && pat[0] == '*' {
		pat = strings.TrimLeft(pat, "*")
		if pat == "" {
			return true
		}
		for ; str != ""; str = str[1:] {
			if globMatch(str, pat) {
				return true
			}
		}
	}
	return str == "" && pat == ""
}

// hasGlobWildcard reports whether pattern has a '*' or '?'. A kprobe multi
// pattern without one names a single function, which the kernel looks up.
func hasGlobWildcard(pattern string) bool {
	return strings.ContainsAny(pattern, "*?")
}

// kprobePatternResolver returns the addresses of the kernel functions whose
// names match a pattern, in the order the kernel lists them.
type kprobePatternResolver func(pattern string) ([]uint64, error)

// resolveKprobePattern returns the addresses of the traceable kernel
// functions whose names match pattern, in file order. When the tracefs
// available_filter_functions_addrs file is readable with the real user and
// group IDs (Linux 6.5 or newer, as root), it is the only source. Otherwise
// the names in available_filter_functions select the /proc/kallsyms entries
// whose addresses are used. tracefs is found as tracefsRoot does.
//
// A file that cannot be opened returns its errno, an entry in either tracefs
// file that cannot be parsed returns EINVAL, and no match returns ENOENT.
func resolveKprobePattern(pattern string) ([]uint64, error) {
	root := tracefsRoot()
	addrsPath := root + "/available_filter_functions_addrs"
	if unix.Access(addrsPath, unix.R_OK) == nil {
		return readAvailableKprobes(addrsPath, pattern)
	}
	return readAvailableKallsyms(root+"/available_filter_functions", kallsymsPath, pattern)
}

// readAvailableKprobes opens the available_filter_functions_addrs file at path
// and parses it with parseAvailableKprobes.
func readAvailableKprobes(path, pattern string) ([]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", path, err)
	}
	defer f.Close()

	return parseAvailableKprobes(f, pattern)
}

// parseAvailableKprobes reads available_filter_functions_addrs entries, a hex
// address and a function name with an optional module after it, and returns
// the address of every entry whose name matches pattern, in order. An entry
// without both fields is EINVAL and no match is ENOENT.
func parseAvailableKprobes(r io.Reader, pattern string) ([]uint64, error) {
	s := kallsymsScanner{r: bufio.NewReader(r)}
	var addrs []uint64
	for {
		addr, name, n, eof := s.addrNameEntry()
		if eof {
			break
		}
		if n != 2 {
			return nil, fmt.Errorf("failed to parse available_filter_functions_addrs entry: %d: %w", n, unix.EINVAL)
		}
		if globMatch(name, pattern) {
			addrs = append(addrs, addr)
		}
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no traceable kernel function matches %q: %w", pattern, unix.ENOENT)
	}
	return addrs, nil
}

// readAvailableKallsyms collects the names in the available_filter_functions
// file at funcsPath that match pattern, then returns the addresses
// availableKallsymsAddrs finds for them in the kallsyms file at
// kallsymsFile. Opening funcsPath returns its errno; the kallsyms file is
// opened only when a name matched, and failing to open it is ENOENT, like no
// address at all.
func readAvailableKallsyms(funcsPath, kallsymsFile, pattern string) ([]uint64, error) {
	f, err := os.Open(funcsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w", funcsPath, err)
	}
	defer f.Close()

	names, err := parseAvailableFunctions(f, pattern)
	if err != nil {
		return nil, err
	}

	var addrs []uint64
	if k, err := os.Open(kallsymsFile); err == nil {
		addrs = availableKallsymsAddrs(k, names, pattern)
		k.Close()
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no kallsyms address for a function matching %q: %w", pattern, unix.ENOENT)
	}
	return addrs, nil
}

// parseAvailableFunctions reads available_filter_functions entries, a
// function name with an optional module after it, and returns the set of
// names that match pattern. Any word reads as a name, so no entry is
// malformed; no match is ENOENT.
func parseAvailableFunctions(r io.Reader, pattern string) (map[string]struct{}, error) {
	s := kallsymsScanner{r: bufio.NewReader(r)}
	names := make(map[string]struct{})
	for {
		name, eof := s.nameEntry()
		if eof {
			break
		}
		if globMatch(name, pattern) {
			names[name] = struct{}{}
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no traceable kernel function matches %q: %w", pattern, unix.ENOENT)
	}
	return names, nil
}

// availableKallsymsAddrs returns, in kallsyms order, the address of every
// kallsyms entry whose name matches pattern and is one of names, the
// traceable functions. A name that is not one of them is looked up again
// without its .llvm.<hash> suffix, truncated to 255 bytes: some kernels drop
// that suffix from available_filter_functions but not from kallsyms.
//
// An entry that cannot be parsed ends the scan, and the addresses found
// before it are returned; the scan error itself is dropped.
func availableKallsymsAddrs(r io.Reader, names map[string]struct{}, pattern string) []uint64 {
	var addrs []uint64
	_ = kallsymsParse(r, func(addr uint64, _ byte, name string) error {
		if !globMatch(name, pattern) || !availableFunction(names, name) {
			return nil
		}
		addrs = append(addrs, addr)
		return nil
	})
	return addrs
}

// availableFunction reports whether the kallsyms name, or the name before its
// .llvm. suffix, is one of names.
func availableFunction(names map[string]struct{}, name string) bool {
	if _, ok := names[name]; ok {
		return true
	}
	i := strings.Index(name, ".llvm.")
	if i < 0 {
		return false
	}
	_, ok := names[name[:min(i, kallsymsTrimMax)]]
	return ok
}
