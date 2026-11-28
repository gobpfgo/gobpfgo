// SPDX-License-Identifier: LGPL-2.1-only
// libbpf-source: include/uapi/linux/bpf.h
// libbpf-commit: 4f05fb027a08a8a66d03916cf6a68a91e2c720ea
// libbpf-symbols: enum bpf_cmd, enum bpf_map_type, enum bpf_attach_type, BPF_OBJ_NAME_LEN, BPF_F_ID

//go:build linux && (amd64 || arm64)

// Package sys contains the Linux UAPI layouts and the bpf() syscall wrapper.
//
// Attribute structs are serialized into []byte with encoding/binary at offsets
// checked against the oracle fixtures. The bpf() wrapper is the only place a
// Go slice address is converted for the syscall.
package sys

// UAPI values from linux/bpf.h used by the first slices.
const (
	BPF_MAP_CREATE                 = 0
	BPF_MAP_LOOKUP_ELEM            = 1
	BPF_MAP_UPDATE_ELEM            = 2
	BPF_MAP_DELETE_ELEM            = 3
	BPF_MAP_GET_NEXT_KEY           = 4
	BPF_PROG_LOAD                  = 5
	BPF_OBJ_PIN                    = 6
	BPF_OBJ_GET                    = 7
	BPF_OBJ_GET_INFO_BY_FD         = 15
	BPF_RAW_TRACEPOINT_OPEN        = 17
	BPF_BTF_LOAD                   = 18
	BPF_BTF_GET_FD_BY_ID           = 19
	BPF_MAP_LOOKUP_AND_DELETE_ELEM = 21
	BPF_MAP_FREEZE                 = 22
	BPF_BTF_GET_NEXT_ID            = 23
	BPF_LINK_CREATE                = 28
	BPF_LINK_UPDATE                = 29
	BPF_LINK_DETACH                = 34
	BPF_MAP_TYPE_ARRAY             = 2
	BPF_OBJ_NAME_LEN               = 16
)

// BPF_F_ID marks relative_fd in BPF_LINK_CREATE as an object id rather than
// a descriptor.
const BPF_F_ID = 1 << 5

// Attach types from enum bpf_attach_type that select a member of the
// BPF_LINK_CREATE union in LinkCreateAttr.Marshal.
const (
	BPF_CGROUP_INET_INGRESS      = 0
	BPF_CGROUP_INET_EGRESS       = 1
	BPF_CGROUP_INET_SOCK_CREATE  = 2
	BPF_CGROUP_SOCK_OPS          = 3
	BPF_CGROUP_DEVICE            = 6
	BPF_CGROUP_INET4_BIND        = 8
	BPF_CGROUP_INET6_BIND        = 9
	BPF_CGROUP_INET4_CONNECT     = 10
	BPF_CGROUP_INET6_CONNECT     = 11
	BPF_CGROUP_INET4_POST_BIND   = 12
	BPF_CGROUP_INET6_POST_BIND   = 13
	BPF_CGROUP_UDP4_SENDMSG      = 14
	BPF_CGROUP_UDP6_SENDMSG      = 15
	BPF_CGROUP_SYSCTL            = 18
	BPF_CGROUP_UDP4_RECVMSG      = 19
	BPF_CGROUP_UDP6_RECVMSG      = 20
	BPF_CGROUP_GETSOCKOPT        = 21
	BPF_CGROUP_SETSOCKOPT        = 22
	BPF_TRACE_RAW_TP             = 23
	BPF_TRACE_FENTRY             = 24
	BPF_TRACE_FEXIT              = 25
	BPF_MODIFY_RETURN            = 26
	BPF_LSM_MAC                  = 27
	BPF_TRACE_ITER               = 28
	BPF_CGROUP_INET4_GETPEERNAME = 29
	BPF_CGROUP_INET6_GETPEERNAME = 30
	BPF_CGROUP_INET4_GETSOCKNAME = 31
	BPF_CGROUP_INET6_GETSOCKNAME = 32
	BPF_CGROUP_INET_SOCK_RELEASE = 34
	BPF_PERF_EVENT               = 41
	BPF_TRACE_KPROBE_MULTI       = 42
	BPF_LSM_CGROUP               = 43
	BPF_STRUCT_OPS               = 44
	BPF_TRACE_UPROBE_MULTI       = 48
	BPF_CGROUP_UNIX_CONNECT      = 49
	BPF_CGROUP_UNIX_SENDMSG      = 50
	BPF_CGROUP_UNIX_RECVMSG      = 51
	BPF_CGROUP_UNIX_GETPEERNAME  = 52
	BPF_CGROUP_UNIX_GETSOCKNAME  = 53
	BPF_TRACE_KPROBE_SESSION     = 56
	BPF_TRACE_UPROBE_SESSION     = 57
	BPF_TRACE_FSESSION           = 58
)
