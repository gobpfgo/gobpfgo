// SPDX-License-Identifier: LGPL-2.1-only
// gobpfgo-origin: original

//go:build linux && (amd64 || arm64)

package libbpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/gobpfgo/gobpfgo/internal/btf"
	"github.com/gobpfgo/gobpfgo/internal/sys"
	"golang.org/x/sys/unix"
)

// The root tests in this file load the slice's fixtures, attach them to a
// real target, check the link through its fdinfo and destroy it. They skip
// when bpf() is not permitted, and skip with the kernel's errno when the
// running kernel lacks the link type, which they learn from the kernel BTF
// rather than from its version.

// TestBpfProgramAttachCgroup attaches each program of cgroup.bpf.o to the
// cgroup v2 root, with and without options, and checks the cgroup link, its
// attach type and its cgroup id, which on 64-bit Linux is the inode number of
// the cgroup directory.
func TestBpfProgramAttachCgroup(t *testing.T) {
	obj := loadTestObject(t, progsDir+"/cgroup.bpf.o")
	defer BpfObjectClose(obj)
	cgroupFD := openCgroupV2Root(t)
	var st unix.Stat_t
	if err := unix.Fstat(cgroupFD, &st); err != nil {
		t.Fatalf("stat cgroup: %v", err)
	}

	attaches := map[string]func(*BpfProgram) (*BpfLink, error){
		"plain":       func(p *BpfProgram) (*BpfLink, error) { return BpfProgramAttachCgroup(p, cgroupFD) },
		"nil options": func(p *BpfProgram) (*BpfLink, error) { return BpfProgramAttachCgroupOpts(p, cgroupFD, nil) },
		"zero options": func(p *BpfProgram) (*BpfLink, error) {
			return BpfProgramAttachCgroupOpts(p, cgroupFD, &BpfCgroupOpts{})
		},
	}
	for _, name := range []string{"cgroup_ingress", "cgroup_egress", "cgroup_skb"} {
		prog := findProgram(t, obj, name)
		for how, attach := range attaches {
			t.Run(name+"/"+how, func(t *testing.T) {
				link, err := attach(prog)
				if err != nil {
					skipIfNotPermitted(t, err)
					t.Fatalf("attach: %v", err)
				}
				checkLinkFdinfo(t, link, prog, "cgroup", map[string]string{
					"cgroup_id":   strconv.FormatUint(st.Ino, 10),
					"attach_type": strconv.Itoa(int(prog.expectedAttachType)),
				})
				destroyLink(t, link)
			})
		}
	}
}

// TestBpfProgramAttachCgroupOptsPlacement places cgroup_skb before and after
// the link of cgroup_ingress at the cgroup v2 root, by link id and by link
// descriptor, and checks that the kernel reads the relative id, the
// relative descriptor and the expected revision: a missing link id returns
// ENOENT, which a relative id sent as a descriptor would not, and a stale
// revision returns ESTALE. The kernel places a link only relative to another
// link, so every placement carries BPF_F_LINK. Kernels without
// multi-program cgroup attachment refuse the flags with EINVAL and skip.
func TestBpfProgramAttachCgroupOptsPlacement(t *testing.T) {
	obj := loadTestObject(t, progsDir+"/cgroup.bpf.o")
	defer BpfObjectClose(obj)
	cgroupFD := openCgroupV2Root(t)
	anchor := findProgram(t, obj, "cgroup_ingress")
	prog := findProgram(t, obj, "cgroup_skb")

	anchorLink, err := BpfProgramAttachCgroup(anchor, cgroupFD)
	if err != nil {
		skipIfNotPermitted(t, err)
		t.Fatalf("attach %s: %v", anchor.name, err)
	}
	defer destroyLink(t, anchorLink)

	anchorID := linkID(t, anchorLink)

	before, err := BpfProgramAttachCgroupOpts(prog, cgroupFD, &BpfCgroupOpts{
		Flags:      BPF_F_BEFORE | BPF_F_LINK,
		RelativeID: anchorID,
	})
	if err != nil {
		skipIfKernelLacks(t, "cgroup program revisions", kernelStructHasMember(t, "cgroup_bpf", "revisions"), err)
		t.Fatalf("attach before link id %d: %v", anchorID, err)
	}
	defer destroyLink(t, before)

	after, err := BpfProgramAttachCgroupOpts(prog, cgroupFD, &BpfCgroupOpts{
		Flags:      BPF_F_AFTER | BPF_F_LINK,
		RelativeFD: BpfLinkFD(anchorLink),
	})
	if err != nil {
		t.Fatalf("attach after link fd %d: %v", BpfLinkFD(anchorLink), err)
	}
	defer destroyLink(t, after)

	refused := map[string]struct {
		opts  BpfCgroupOpts
		errno unix.Errno
	}{
		"missing link id": {BpfCgroupOpts{Flags: BPF_F_BEFORE | BPF_F_LINK, RelativeID: ^uint32(0)}, unix.ENOENT},
		"stale revision":  {BpfCgroupOpts{ExpectedRevision: ^uint64(0)}, unix.ESTALE},
	}
	for name, c := range refused {
		t.Run(name, func(t *testing.T) {
			link, err := BpfProgramAttachCgroupOpts(prog, cgroupFD, &c.opts)
			checkAttachError(t, link, err, "bpf_program__attach_cgroup_opts", c.errno)
		})
	}
}

// TestBpfProgramAttachNetns attaches the flow dissector of netns.bpf.o to
// the test's network namespace and checks the netns link. It skips with
// EEXIST when another namespace already has a flow dissector.
func TestBpfProgramAttachNetns(t *testing.T) {
	obj := loadTestObject(t, progsDir+"/netns.bpf.o")
	defer BpfObjectClose(obj)
	prog := findProgram(t, obj, "dissect")

	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("open network namespace: %v", err)
	}
	defer netns.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(netns.Fd()), &st); err != nil {
		t.Fatalf("stat network namespace: %v", err)
	}

	link, err := BpfProgramAttachNetns(prog, int(netns.Fd()))
	if err != nil {
		skipIfNotPermitted(t, err)
		if errors.Is(err, unix.EEXIST) {
			t.Skipf("another flow dissector is attached: %v", err)
		}
		t.Fatalf("attach: %v", err)
	}
	checkLinkFdinfo(t, link, prog, "netns", map[string]string{
		"netns_ino":   strconv.FormatUint(st.Ino, 10),
		"attach_type": strconv.Itoa(int(BPF_FLOW_DISSECTOR)),
	})
	destroyLink(t, link)
}

// TestBpfProgramAttachXDP attaches xdp.bpf.o to the loopback interface and
// checks the XDP link. It skips when the interface already has an XDP
// program or the kernel refuses the attach.
func TestBpfProgramAttachXDP(t *testing.T) {
	obj := loadTestObject(t, progsDir+"/xdp.bpf.o")
	defer BpfObjectClose(obj)
	prog := findProgram(t, obj, "xdp_pass")

	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("loopback interface: %v", err)
	}
	link, err := BpfProgramAttachXDP(prog, lo.Index)
	if err != nil {
		if errors.Is(err, unix.EEXIST) || errors.Is(err, unix.EBUSY) || errors.Is(err, unix.EPERM) {
			t.Skipf("XDP attach to lo refused: %v", err)
		}
		t.Fatalf("attach: %v", err)
	}
	checkLinkFdinfo(t, link, prog, "xdp", map[string]string{"ifindex": strconv.Itoa(lo.Index)})
	destroyLink(t, link)
}

// TestBpfProgramAttachSockmap creates a sockmap, attaches the sk_msg program
// of sockmap.bpf.o to it and checks the sockmap link. Kernels without
// sockmap links refuse the attach and skip.
func TestBpfProgramAttachSockmap(t *testing.T) {
	obj := loadTestObject(t, progsDir+"/sockmap.bpf.o")
	defer BpfObjectClose(obj)
	prog := findProgram(t, obj, "msg_pass")

	mapFD, err := BpfMapCreate(BPF_MAP_TYPE_SOCKMAP, "gobpfgo_sockmap", 4, 4, 1, nil)
	if err != nil {
		skipIfNotPermitted(t, err)
		t.Fatalf("create sockmap: %v", err)
	}
	defer unix.Close(mapFD)
	info, err := sys.MapInfoByFD(mapFD)
	if err != nil {
		t.Fatalf("sockmap info: %v", err)
	}

	link, err := BpfProgramAttachSockmap(prog, mapFD)
	if err != nil {
		skipIfNotPermitted(t, err)
		skipIfKernelLacks(t, "sockmap links", kernelEnumHas(t, "bpf_link_type", "BPF_LINK_TYPE_SOCKMAP"), err)
		t.Fatalf("attach: %v", err)
	}
	checkLinkFdinfo(t, link, prog, "sockmap", map[string]string{
		"map_id":      strconv.FormatUint(uint64(info.ID), 10),
		"attach_type": strconv.Itoa(int(BPF_SK_MSG_VERDICT)),
	})
	destroyLink(t, link)
}

// TestBpfProgramAttachKprobeSession attaches the kprobe.session program of
// kprobe_session.bpf.o to do_sys_openat2, explicitly and through the section
// name, opens a file from a locked thread, and requires two runs on that
// thread: the entry run returns 0, so the return run follows. Kernels
// without kprobe sessions refuse the load or the attach and skip, as do
// kernels without kprobe multi links.
func TestBpfProgramAttachKprobeSession(t *testing.T) {
	obj := loadKprobeSessionObject(t)
	defer BpfObjectClose(obj)
	prog := findProgram(t, obj, "handle_session")

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	setMapU32(t, obj, "target_tid", uint32(unix.Gettid()))

	attaches := []struct {
		name   string
		attach func() (*BpfLink, error)
	}{
		{"opts", func() (*BpfLink, error) {
			return BpfProgramAttachKprobeMulti(prog, &BpfKprobeMultiOpts{Symbols: []string{"do_sys_openat2"}, Session: true})
		}},
		{"section", func() (*BpfLink, error) { return BpfProgramAttach(prog) }},
	}
	for _, a := range attaches {
		link, err := a.attach()
		if err != nil {
			skipIfKernelLacksKprobeSession(t, err)
			t.Fatalf("%s attach: %v", a.name, err)
		}
		checkLinkFdinfo(t, link, prog, "kprobe_multi", nil)

		// Reading fdinfo opened a file on this thread too, so count
		// from here.
		start := mapValue(t, obj, "counts")
		triggerOpen(t)
		if got := mapValue(t, obj, "counts") - start; got != 2 {
			t.Fatalf("%s: one open counted %d runs, want 2: an entry and a return run", a.name, got)
		}
		destroyLink(t, link)
	}
}

// loadKprobeSessionObject loads kprobe_session.bpf.o. A kernel without
// kprobe sessions may refuse the program's expected attach type; the test
// then skips with the load error.
func loadKprobeSessionObject(t *testing.T) *BpfObject {
	t.Helper()

	path := progsDir + "/kprobe_session.bpf.o"
	obj, err := BpfObjectOpenFile(path, nil)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if err := BpfObjectLoad(obj); err != nil {
		BpfObjectClose(obj)
		skipIfNotPermitted(t, err)
		skipIfKernelLacksKprobeSession(t, err)
		t.Fatalf("load %s: %v", path, err)
	}
	return obj
}

// skipIfKernelLacksKprobeSession skips with err when the kernel has no
// BPF_TRACE_KPROBE_SESSION or no kprobe multi links, which it reports with
// EOPNOTSUPP.
func skipIfKernelLacksKprobeSession(t *testing.T, err error) {
	t.Helper()

	if errors.Is(err, unix.EOPNOTSUPP) {
		t.Skipf("kprobe multi links are not supported by this kernel: %v", err)
	}
	skipIfKernelLacks(t, "kprobe sessions", kernelEnumHas(t, "bpf_attach_type", "BPF_TRACE_KPROBE_SESSION"), err)
}

// skipIfKernelLacks skips the test with err when has is false, that is when
// the running kernel lacks feature. Otherwise it returns and the caller
// reports err as a failure.
func skipIfKernelLacks(t *testing.T, feature string, has bool, err error) {
	t.Helper()

	if !has {
		t.Skipf("kernel lacks %s: %v", feature, err)
	}
}

// kernelEnumHas reports whether the running kernel's BTF has the enum
// enumName with the value valueName. It fails the test when the kernel BTF
// cannot be read, so that an unreadable BTF does not pass for a missing
// feature and skip the test.
func kernelEnumHas(t *testing.T, enumName, valueName string) bool {
	t.Helper()

	kernel, err := vmlinuxBTF()
	if err != nil {
		t.Fatalf("read kernel BTF for enum %s: %v", enumName, err)
	}
	enum := kernel.Find(enumName, btf.KindEnum)
	if enum == nil {
		return false
	}
	for _, e := range enum.Enums {
		if e.Name == valueName {
			return true
		}
	}
	return false
}

// kernelStructHasMember reports whether the running kernel's BTF has the
// struct structName with the member member. It fails the test when the
// kernel BTF cannot be read, like kernelEnumHas.
func kernelStructHasMember(t *testing.T, structName, member string) bool {
	t.Helper()

	kernel, err := vmlinuxBTF()
	if err != nil {
		t.Fatalf("read kernel BTF for struct %s: %v", structName, err)
	}
	st := kernel.Find(structName, btf.KindStruct)
	return st != nil && kernel.Member(st, member) != nil
}

// openCgroupV2Root opens the root of the cgroup v2 hierarchy, at
// /sys/fs/cgroup on a unified system or /sys/fs/cgroup/unified on a hybrid
// one, and closes it when the test ends. It skips the test when neither is a
// cgroup v2 mount.
func openCgroupV2Root(t *testing.T) int {
	t.Helper()

	for _, path := range []string{"/sys/fs/cgroup", "/sys/fs/cgroup/unified"} {
		var fs unix.Statfs_t
		if err := unix.Statfs(path, &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
			continue
		}
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		t.Cleanup(func() { unix.Close(fd) })
		return fd
	}
	t.Skip("no cgroup v2 hierarchy at /sys/fs/cgroup or /sys/fs/cgroup/unified")
	return -1
}

// findProgram returns the program name of obj or fails the test.
func findProgram(t *testing.T, obj *BpfObject, name string) *BpfProgram {
	t.Helper()

	prog := BpfObjectFindProgramByName(obj, name)
	if prog == nil {
		t.Fatalf("program %s not found", name)
	}
	return prog
}

// setMapU32 writes value at key 0 of the map name of obj.
func setMapU32(t *testing.T, obj *BpfObject, name string, value uint32) {
	t.Helper()

	m := BpfObjectFindMapByName(obj, name)
	if m == nil {
		t.Fatalf("map %s not found", name)
	}
	key := make([]byte, 4)
	val := binary.NativeEndian.AppendUint32(nil, value)
	if err := BpfMapUpdateElem(m, key, val, BPF_ANY); err != nil {
		t.Fatalf("update %s: %v", name, err)
	}
}

// checkLinkFdinfo requires link to hold a descriptor whose fdinfo names
// linkType and prog's id, and has every field in want.
func checkLinkFdinfo(t *testing.T, link *BpfLink, prog *BpfProgram, linkType string, want map[string]string) {
	t.Helper()

	fd := BpfLinkFD(link)
	if fd < 0 {
		t.Fatalf("link fd = %d", fd)
	}
	info := fdinfo(t, fd)
	if got := info["link_type"]; got != linkType {
		t.Errorf("link_type = %q, want %q", got, linkType)
	}
	if got, id := info["prog_id"], strconv.FormatUint(uint64(prog.id), 10); got != id {
		t.Errorf("prog_id = %q, want %s", got, id)
	}
	for key, value := range want {
		if got := info[key]; got != value {
			t.Errorf("%s = %q, want %q", key, got, value)
		}
	}
}

// linkID returns the kernel id of link from its fdinfo.
func linkID(t *testing.T, link *BpfLink) uint32 {
	t.Helper()

	value := fdinfo(t, BpfLinkFD(link))["link_id"]
	id, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		t.Fatalf("link_id %q: %v", value, err)
	}
	return uint32(id)
}

// fdinfo returns the "key:\tvalue" lines of /proc/self/fdinfo/<fd>.
func fdinfo(t *testing.T, fd int) map[string]string {
	t.Helper()

	data, err := os.ReadFile(fmt.Sprintf("/proc/self/fdinfo/%d", fd))
	if err != nil {
		t.Fatalf("read fdinfo: %v", err)
	}
	info := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			info[key] = strings.TrimSpace(value)
		}
	}
	return info
}

// destroyLink destroys link and requires its descriptor to be released.
func destroyLink(t *testing.T, link *BpfLink) {
	t.Helper()

	BpfLinkDestroy(link)
	if fd := BpfLinkFD(link); fd != -1 {
		t.Errorf("link fd after destroy = %d, want -1", fd)
	}
}
