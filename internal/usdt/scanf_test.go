// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package usdt

import (
	"math"
	"slices"
	"testing"
)

// TestSscanf checks the glibc rules the parser depends on. The libbpf
// patterns are covered end to end by the oracle tests.
func TestSscanf(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		format   string
		count    int
		ints     []int64
		strs     []string
		consumed int
	}{
		{"white space matches none", "8@x", " %d @ %s %n", 2, []int64{8}, []string{"x"}, 3},
		{"white space matches a run", " 8 \t@\n x ", " %d @ %s %n", 2, []int64{8}, []string{"x"}, 9},
		{"literal needs a preceding space to skip", "8 @x", "%d@%s%n", 1, []int64{8}, nil, -1},
		{"percent literal", "%rax", "%%%s%n", 1, nil, []string{"rax"}, 4},
		{"scanset does not skip space", "% rax", "%%%15[^,]%n", 1, nil, []string{" rax"}, 5},
		{"scanset skips after a space directive", "  rax", " %15[a-z]%n", 1, nil, []string{"rax"}, 5},
		{"scanset needs one byte", ",x", "%15[^,]", 0, nil, nil, -1},
		{"scanset range", "x29,", "%15[a-z0-9]%n", 1, nil, []string{"x29"}, 3},
		{"leading bracket in scanset", "]]a", "%[]]%n", 1, nil, []string{"]]"}, 2},
		{"width stops the string", "abcdefghijklmnopq", "%15s%n", 1, nil, []string{"abcdefghijklmno"}, 15},
		{"sign without digits", "-x", "%d", 0, nil, nil, -1},
		{"plus sign", "+5", "%d%n", 1, []int64{5}, nil, 2},
		{"int keeps the low 32 bits", "4294967297", "%d", 1, []int64{1}, nil, -1},
		{"int saturates then truncates", "99999999999999999999", "%d", 1, []int64{-1}, nil, -1},
		{"long saturates", "-99999999999999999999", "%ld", 1, []int64{math.MinInt64}, nil, -1},
		{"stops at a mismatch", "8@-4(%rbp", " %d @ %ld ( %%%15[^)] ) %n", 3, []int64{8, -4}, []string{"rbp"}, -1},
		{"empty input", "", " %d", 0, nil, nil, -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := sscanf(tt.input, tt.format)
			if got.count != tt.count || got.consumed != tt.consumed || !slices.Equal(got.ints, tt.ints) || !slices.Equal(got.strs, tt.strs) {
				t.Errorf("sscanf(%q, %q) = %+v, want count %d ints %v strs %q consumed %d",
					tt.input, tt.format, got, tt.count, tt.ints, tt.strs, tt.consumed)
			}
		})
	}
}
