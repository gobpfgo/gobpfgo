// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package usdt

import (
	"errors"
	"strconv"
)

// scanResult is what sscanf assigned, in format order.
type scanResult struct {
	// count is the number of assigned conversions: the value C's sscanf
	// returns once it has tried one conversion. %n is not counted.
	count int
	// ints holds the %d and %ld values and strs the %s and %[ values. A %d
	// value is already truncated to a C int.
	ints []int64
	strs []string
	// consumed is the input offset %n stored, or -1 when scanning stopped
	// before the %n directive.
	consumed int
}

// directive is one conversion specification of a scanf format.
type directive struct {
	verb  byte
	width int
	long  bool
	set   *[256]bool
}

// sscanf matches input against a C scanf format with glibc's rules, for the
// directives usdt.c uses: white space, ordinary characters, %%, %d, %ld, %Ns,
// %N[set] and %n.
//
// White space in the format matches any run of input white space, including
// none. Every conversion except %[ and %n also skips leading white space on
// its own. Numbers saturate at the int64 range, as strtol does, and %d keeps
// the low 32 bits, as the C conversion to int does. Scanning stops at the
// first directive that does not match; the conversions assigned before it
// stay in the result.
func sscanf(input, format string) scanResult {
	s := scanner{input: input}
	r := scanResult{consumed: -1}
	skipSpace := false

	for f := 0; f < len(format); {
		c := format[f]
		f++
		if c != '%' {
			if isSpace(c) {
				skipSpace = true
				continue
			}
			if skipSpace {
				s.skipSpaces()
				skipSpace = false
			}
			if !s.accept(c) {
				return r
			}
			continue
		}

		var d directive
		d, f = parseDirective(format, f)
		if skipSpace || (d.verb != '[' && d.verb != 'n') {
			s.skipSpaces()
			skipSpace = false
		}
		if !s.convert(d, &r) {
			return r
		}
	}
	return r
}

// parseDirective parses the conversion that starts at format[f], right after
// its '%': the width, the length and the verb. It returns the index after it.
func parseDirective(format string, f int) (directive, int) {
	var d directive

	for f < len(format) && isDigit(format[f]) {
		d.width = d.width*10 + int(format[f]-'0')
		f++
	}
	if f < len(format) && format[f] == 'l' {
		d.long = true
		f++
	}
	if f < len(format) {
		d.verb = format[f]
		f++
	}
	if d.verb == '[' {
		d.set, f = parseScanset(format, f)
	}
	return d, f
}

// parseScanset reads a %[ scanset that starts at format[f] and returns the
// accepted bytes and the index after the closing ']'. A leading '^' negates
// the set, a ']' or '-' right after the opening bracket is a member, and a-z
// is a range, as in glibc.
func parseScanset(format string, f int) (*[256]bool, int) {
	var set [256]bool

	negate := f < len(format) && format[f] == '^'
	if negate {
		f++
	}
	if f < len(format) && (format[f] == ']' || format[f] == '-') {
		set[format[f]] = true
		f++
	}
	for f < len(format) && format[f] != ']' {
		c := format[f]
		f++
		if c == '-' && f < len(format) && format[f] != ']' && format[f-2] <= format[f] {
			for x := int(format[f-2]); x < int(format[f]); x++ {
				set[x] = true
			}
			continue
		}
		set[c] = true
	}
	if f < len(format) {
		f++
	}
	if negate {
		for i := range set {
			set[i] = !set[i]
		}
	}
	return &set, f
}

// scanner is the input side of sscanf.
type scanner struct {
	input string
	pos   int
}

func (s *scanner) skipSpaces() {
	for s.pos < len(s.input) && isSpace(s.input[s.pos]) {
		s.pos++
	}
}

// accept consumes c if it is the next input byte.
func (s *scanner) accept(c byte) bool {
	if s.pos >= len(s.input) || s.input[s.pos] != c {
		return false
	}
	s.pos++
	return true
}

// convert runs one conversion and records its value in r.
func (s *scanner) convert(d directive, r *scanResult) bool {
	switch d.verb {
	case '%':
		return s.accept('%')
	case 'n':
		r.consumed = s.pos
		return true
	case 'd':
		v, ok := s.decimal(d.width)
		if !ok {
			return false
		}
		if !d.long {
			v = int64(int32(v))
		}
		r.ints = append(r.ints, v)
	case 's':
		v, ok := s.span(d.width, func(c byte) bool { return !isSpace(c) })
		if !ok {
			return false
		}
		r.strs = append(r.strs, v)
	case '[':
		v, ok := s.span(d.width, func(c byte) bool { return d.set[c] })
		if !ok {
			return false
		}
		r.strs = append(r.strs, v)
	default:
		return false
	}
	r.count++
	return true
}

// decimal reads an optionally signed base-10 integer of at most width bytes,
// or of any length when width is 0. It fails when no digit follows the sign.
func (s *scanner) decimal(width int) (int64, bool) {
	end := s.limit(width)
	i := s.pos
	if i < end && (s.input[i] == '+' || s.input[i] == '-') {
		i++
	}
	digits := i
	for i < end && isDigit(s.input[i]) {
		i++
	}
	if i == digits {
		return 0, false
	}

	// ParseInt saturates out-of-range values, as strtol does.
	v, err := strconv.ParseInt(s.input[s.pos:i], 10, 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return 0, false
	}
	s.pos = i
	return v, true
}

// span reads at least one and at most width bytes that satisfy in, or any
// number when width is 0.
func (s *scanner) span(width int, in func(byte) bool) (string, bool) {
	end := s.limit(width)
	i := s.pos
	for i < end && in(s.input[i]) {
		i++
	}
	if i == s.pos {
		return "", false
	}
	v := s.input[s.pos:i]
	s.pos = i
	return v, true
}

// limit returns the input offset a conversion of the given width may not
// pass.
func (s *scanner) limit(width int) int {
	if width > 0 && s.pos+width < len(s.input) {
		return s.pos + width
	}
	return len(s.input)
}

// isSpace is C isspace in the C locale.
func isSpace(c byte) bool {
	return c == ' ' || (c >= '\t' && c <= '\r')
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}
