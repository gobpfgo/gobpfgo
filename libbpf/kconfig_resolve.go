// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: src/libbpf.c
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: bpf_object__resolve_externs, bpf_object__read_kconfig_file, bpf_object__read_kconfig_mem, bpf_object__process_kconfig_line, set_kcfg_value_tri, set_kcfg_value_str, set_kcfg_value_num, is_kcfg_value_in_range, parse_u64

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// Prefixes of the .kconfig extern names the loader knows: CONFIG_ values come
// from the kernel config, LINUX_ values are computed by the loader.
const (
	kconfigPrefix = "CONFIG_"
	linuxPrefix   = "LINUX_"
)

// System kernel config locations. The /boot file is per release; either file
// may be gzip-compressed or plain text.
const (
	bootKconfigPrefix = "/boot/config-"
	procKconfigPath   = "/proc/config.gz"
)

// Values of enum libbpf_tristate.
const (
	triNo     = 0
	triYes    = 1
	triModule = 2
)

// kconfigLineMax is the line buffer of the config readers. A longer line is
// read in pieces, each processed as its own line.
const kconfigLineMax = unix.PathMax

// resolveError reports an extern the loader cannot resolve.
func resolveError(errno syscall.Errno, format string, args ...any) error {
	return &Error{Op: "bpf_object__resolve_externs", Errno: errno, Log: fmt.Sprintf(format, args...)}
}

// resolveExterns gives every extern of obj its value before the maps are
// created, writing the .kconfig values into the .kconfig map's initial value
// and the .ksyms values into the extern descriptors.
//
// The LINUX_ externs are virtual. LINUX_KERNEL_VERSION is the running
// kernel's KERNEL_VERSION code; LINUX_HAS_BPF_COOKIE is 1 when the kernel
// lets a program read a BPF cookie and 0 otherwise; LINUX_HAS_SYSCALL_WRAPPER
// is zero because its feature probe is not ported; any other weak LINUX_
// extern is zero, and a strong one is EINVAL. The CONFIG_ externs come from
// obj.kconfig first and then, while any .kconfig extern is unset, from the
// system config; a parse error, or a missing system config when it is
// needed, is EINVAL.
//
// A typeless .ksyms variable takes its address from /proc/kallsyms; two
// different addresses for one name, or a file that cannot be read, is
// EINVAL. A typed .ksyms variable or function resolves against the kernel
// BTF loaded into obj.btfVmlinux and the module BTFs; a type the kernel does
// not have, or has with an incompatible type, is EINVAL, except a missing
// weak extern and an incompatible weak function, which stay unset. A strong
// extern left unset is ESRCH; a weak one stays zero.
func resolveExterns(obj *BpfObject) error {
	if len(obj.externs) == 0 {
		return nil
	}
	var data []byte
	if obj.kconfigMap != nil {
		data = obj.kconfigMap.initialValue
	}

	needConfig, needKallsyms, needVmlinuxBTF := false, false, false
	for i := range obj.externs {
		ext := &obj.externs[i]
		switch ext.typ {
		case extKsym:
			if ext.ksym.typeID != 0 {
				needVmlinuxBTF = true
			} else {
				needKallsyms = true
			}
		case extKcfg:
			if strings.HasPrefix(ext.name, kconfigPrefix) {
				needConfig = true
				continue
			}
			value, err := virtualKcfgValue(ext)
			if err != nil {
				return err
			}
			if err := setKcfgValueNum(ext, data, value); err != nil {
				return resolveError(errnoFromError(err), "%v", err)
			}
		default:
			return resolveError(unix.EINVAL, "extern '%s': unrecognized extern kind", ext.name)
		}
	}

	if needConfig && obj.kconfig != nil {
		if err := readKconfigMem(obj.externs, *obj.kconfig, data); err != nil {
			return resolveError(unix.EINVAL, "%v", err)
		}
		needConfig = anyKcfgUnset(obj.externs)
	}
	if needConfig {
		if err := readKconfigFile(obj.externs, data); err != nil {
			return resolveError(unix.EINVAL, "%v", err)
		}
	}
	if needKallsyms {
		if err := readKallsymsFile(obj.externs, obj.btf); err != nil {
			return resolveError(unix.EINVAL, "%v", err)
		}
	}
	if needVmlinuxBTF {
		if err := resolveKsymsBtfID(obj); err != nil {
			return resolveError(unix.EINVAL, "%v", err)
		}
	}

	for i := range obj.externs {
		ext := &obj.externs[i]
		if !ext.isSet && !ext.isWeak {
			return resolveError(unix.ESRCH, "extern '%s' (strong): not resolved", ext.name)
		}
	}
	return nil
}

// virtualKcfgValue returns the value of a LINUX_ extern, or an error for an
// unknown strong one or any other name.
func virtualKcfgValue(ext *externDesc) (uint64, error) {
	switch ext.name {
	case "LINUX_KERNEL_VERSION":
		version := getKernelVersion()
		if version == 0 {
			return 0, resolveError(unix.EINVAL, "extern (kcfg) '%s': failed to get kernel version", ext.name)
		}
		return uint64(version), nil
	case "LINUX_HAS_BPF_COOKIE":
		if featBpfCookie.supported() {
			return 1, nil
		}
		return 0, nil
	case "LINUX_HAS_SYSCALL_WRAPPER":
		return 0, nil
	}
	if !strings.HasPrefix(ext.name, linuxPrefix) || !ext.isWeak {
		return 0, resolveError(unix.EINVAL, "extern (kcfg) '%s': unrecognized virtual extern", ext.name)
	}
	return 0, nil
}

// anyKcfgUnset reports whether a .kconfig extern still has no value.
func anyKcfgUnset(externs []externDesc) bool {
	for i := range externs {
		if externs[i].typ == extKcfg && !externs[i].isSet {
			return true
		}
	}
	return false
}

// readKconfigMem applies the config text to the .kconfig externs. The text
// ends at its first NUL byte, as a C string does.
func readKconfigMem(externs []externDesc, config string, data []byte) error {
	if i := strings.IndexByte(config, 0); i >= 0 {
		config = config[:i]
	}
	for _, line := range kconfigLines([]byte(config)) {
		if err := processKconfigLine(externs, line, data); err != nil {
			return fmt.Errorf("error parsing in-memory Kconfig line '%s': %w", line, err)
		}
	}
	return nil
}

// readKconfigFile applies the system kernel config: /boot/config-<release>
// or, when that cannot be opened, /proc/config.gz.
func readKconfigFile(externs []externDesc, data []byte) error {
	var uts unix.Utsname
	_ = unix.Uname(&uts)

	config, err := readKconfigSource(bootKconfigPrefix + unix.ByteSliceToString(uts.Release[:]))
	if err != nil {
		config, err = readKconfigSource(procKconfigPath)
	}
	if err != nil {
		return fmt.Errorf("failed to open system Kconfig: %w", unix.ENOENT)
	}

	for _, line := range kconfigLines(config) {
		if err := processKconfigLine(externs, line, data); err != nil {
			return fmt.Errorf("error parsing system Kconfig line '%s': %w", line, err)
		}
	}
	return nil
}

// readKconfigSource returns the text of a config file. A gzip file is
// decompressed and any other file is read as is; decompression stops at the
// first corrupt byte and keeps the text before it. Only a file that cannot be
// opened is an error.
func readKconfigSource(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	raw, _ := io.ReadAll(f)
	if !bytes.HasPrefix(raw, []byte{0x1f, 0x8b}) {
		return raw, nil
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, nil
	}
	text, _ := io.ReadAll(zr)
	return text, nil
}

// kconfigLines splits text the way the C line reader fills its buffer: each
// piece ends after a newline or after kconfigLineMax-1 bytes, and is then cut
// at its first NUL byte.
func kconfigLines(text []byte) []string {
	var lines []string
	for len(text) > 0 {
		n := min(len(text), kconfigLineMax-1)
		if i := bytes.IndexByte(text[:n], '\n'); i >= 0 {
			n = i + 1
		}
		line := text[:n]
		if i := bytes.IndexByte(line, 0); i >= 0 {
			line = line[:i]
		}
		lines = append(lines, string(line))
		text = text[n:]
	}
	return lines
}

// processKconfigLine applies one config line to the extern it names.
//
// Lines that do not start with CONFIG_ are ignored, as are names without an
// extern and externs that already have a value. A line needs an '=' and a
// value: y, n or m set a bool, tristate or char; a value starting with a
// quote sets a char array; anything else must be an integer for an integer
// or char extern.
func processKconfigLine(externs []externDesc, line string, data []byte) error {
	if !strings.HasPrefix(line, kconfigPrefix) {
		return nil
	}
	sep := strings.IndexByte(line, '=')
	if sep < 0 {
		return fmt.Errorf("failed to parse '%s': no separator: %w", line, unix.EINVAL)
	}
	line = strings.TrimSuffix(line, "\n")
	name, value := line[:sep], line[sep+1:]
	if value == "" {
		return fmt.Errorf("failed to parse '%s': no value: %w", line, unix.EINVAL)
	}

	ext := findExternByName(externs, name)
	if ext == nil || ext.isSet {
		return nil
	}

	switch value[0] {
	case 'y', 'n', 'm':
		return setKcfgValueTri(ext, data, value[0])
	case '"':
		return setKcfgValueStr(ext, data, value)
	}

	num, errno := parseU64(value)
	if errno != 0 {
		return fmt.Errorf("extern (kcfg) '%s': value '%s' isn't a valid integer: %w", ext.name, value, errno)
	}
	if ext.kcfg.typ != kcfgInt && ext.kcfg.typ != kcfgChar {
		return fmt.Errorf("extern (kcfg) '%s': value '%s' implies integer type: %w", ext.name, value, unix.EINVAL)
	}
	return setKcfgValueNum(ext, data, num)
}

// setKcfgValueTri writes a y, n or m value. A bool takes y as true and n as
// false and rejects m; a tristate takes TRI_YES, TRI_NO or TRI_MODULE as a
// 4-byte value; a char takes the letter itself. Other types are EINVAL.
func setKcfgValueTri(ext *externDesc, data []byte, value byte) error {
	val := data[ext.kcfg.dataOff:]
	switch ext.kcfg.typ {
	case kcfgBool:
		if value == 'm' {
			return fmt.Errorf("extern (kcfg) '%s': value '%c' implies tristate or char type: %w", ext.name, value, unix.EINVAL)
		}
		val[0] = 0
		if value == 'y' {
			val[0] = 1
		}
	case kcfgTristate:
		tri := uint32(triNo)
		switch value {
		case 'y':
			tri = triYes
		case 'm':
			tri = triModule
		}
		binary.NativeEndian.PutUint32(val, tri)
	case kcfgChar:
		val[0] = value
	default:
		return fmt.Errorf("extern (kcfg) '%s': value '%c' implies bool, tristate, or char type: %w", ext.name, value, unix.EINVAL)
	}
	ext.isSet = true
	return nil
}

// setKcfgValueStr writes a quoted string value into a char array, without
// the quotes and NUL-terminated, cut to fit the array. The value must end in
// a quote; other types are EINVAL.
func setKcfgValueStr(ext *externDesc, data []byte, value string) error {
	if ext.kcfg.typ != kcfgCharArr {
		return fmt.Errorf("extern (kcfg) '%s': value '%s' implies char array type: %w", ext.name, value, unix.EINVAL)
	}
	if len(value) < 2 || value[len(value)-1] != '"' {
		return fmt.Errorf("extern (kcfg) '%s': invalid string config '%s': %w", ext.name, value, unix.EINVAL)
	}

	str := value[1 : len(value)-1]
	if len(str) >= ext.kcfg.sz {
		str = str[:ext.kcfg.sz-1]
	}
	val := data[ext.kcfg.dataOff:]
	copy(val, str)
	val[len(str)] = 0
	ext.isSet = true
	return nil
}

// isKcfgValueInRange reports whether v fits the extern's integer size without
// loss: a signed extern of Y bits holds -2^(Y-1) to 2^(Y-1)-1, taking v as
// two's complement, and an unsigned one needs the bits above Y clear.
func isKcfgValueInRange(ext *externDesc, v uint64) bool {
	if ext.kcfg.sz == 8 {
		return true
	}
	bits := uint(ext.kcfg.sz * 8)
	if ext.kcfg.isSigned {
		return v+(1<<(bits-1)) < 1<<bits
	}
	return v>>bits == 0
}

// setKcfgValueNum writes an integer into an integer, char or bool extern in
// the native byte order. A bool takes only 0 or 1, and a value that does not
// fit the size is ERANGE.
func setKcfgValueNum(ext *externDesc, data []byte, value uint64) error {
	if ext.kcfg.typ != kcfgInt && ext.kcfg.typ != kcfgChar && ext.kcfg.typ != kcfgBool {
		return fmt.Errorf("extern (kcfg) '%s': value '%d' implies integer, char, or boolean type: %w", ext.name, value, unix.EINVAL)
	}
	if ext.kcfg.typ == kcfgBool && value > 1 {
		return fmt.Errorf("extern (kcfg) '%s': value '%d' isn't boolean compatible: %w", ext.name, value, unix.EINVAL)
	}
	if !isKcfgValueInRange(ext, value) {
		return fmt.Errorf("extern (kcfg) '%s': value '%d' doesn't fit in %d bytes: %w", ext.name, value, ext.kcfg.sz, unix.ERANGE)
	}

	val := data[ext.kcfg.dataOff:]
	switch ext.kcfg.sz {
	case 1:
		val[0] = uint8(value)
	case 2:
		binary.NativeEndian.PutUint16(val, uint16(value))
	case 4:
		binary.NativeEndian.PutUint32(val, uint32(value))
	case 8:
		binary.NativeEndian.PutUint64(val, value)
	default:
		return fmt.Errorf("extern (kcfg) '%s': unsupported size %d: %w", ext.name, ext.kcfg.sz, unix.EINVAL)
	}
	ext.isSet = true
	return nil
}

// parseU64 parses the whole of s as an unsigned integer like strtoull with
// base 0: leading white space, an optional sign, and a 0x prefix for hex or
// a leading 0 for octal. A negative value wraps around. Overflow is ERANGE
// and trailing characters or no digits are EINVAL.
func parseU64(s string) (uint64, syscall.Errno) {
	value, end, errno := strtoull(s)
	if errno != 0 {
		return 0, errno
	}
	if end != len(s) {
		return 0, unix.EINVAL
	}
	return value, 0
}

// strtoull converts the prefix of s as the C library does with base 0 and
// returns the value and the index after the last digit used. Without digits
// the index is 0. Overflow returns the maximum value and ERANGE.
func strtoull(s string) (uint64, int, syscall.Errno) {
	i := 0
	for i < len(s) && isCSpace(s[i]) {
		i++
	}
	negative := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		negative = s[i] == '-'
		i++
	}

	base := uint64(10)
	switch {
	case i+2 < len(s) && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') && digitValue(s[i+2]) < 16:
		base = 16
		i += 2
	case i < len(s) && s[i] == '0':
		base = 8
	}

	start := i
	var value uint64
	overflow := false
	for ; i < len(s); i++ {
		d := uint64(digitValue(s[i]))
		if d >= base {
			break
		}
		if value > (^uint64(0)-d)/base {
			overflow = true
		}
		value = value*base + d
	}
	if i == start {
		return 0, 0, 0
	}
	if overflow {
		return ^uint64(0), i, unix.ERANGE
	}
	if negative {
		value = -value
	}
	return value, i, 0
}

// isCSpace reports whether c is white space in the C locale.
func isCSpace(c byte) bool {
	return c == ' ' || (c >= '\t' && c <= '\r')
}

// digitValue returns the value of c as a digit in bases up to 36, or 36 when
// c is not a digit or letter.
func digitValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'z':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'Z':
		return int(c-'A') + 10
	}
	return 36
}
