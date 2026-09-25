// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// This file includes modifications by gomaja.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied. See the License for the specific language governing permissions
// and limitations under the License.

//go:build linux && !386

// syscall_linux_other.go issues the four raw system calls every Linux
// socket operation runs inside a syscall.RawConn callback (setsockopt(2),
// getsockopt(2), sendmsg(2), recvmsg(2)), on every Linux architecture
// except 386, which reaches them through socketcall(2) instead
// (syscall_linux_386.go, the other half of this pair). Every non-386
// GOARCH the syscall package supports declares SYS_SETSOCKOPT,
// SYS_GETSOCKOPT, SYS_SENDMSG and SYS_RECVMSG as ordinary syscall numbers,
// so syscall.Syscall6/syscall.Syscall reach the kernel directly, with no
// socketcall(2) multiplexer in between.
//
// syscall.Syscall and syscall.Syscall6 carry the uintptrkeepalive compiler
// directive in the syscall package itself: for a uintptr argument written
// at the call site as a direct conversion from unsafe.Pointer (or, as
// here, from an unsafe.Pointer-typed parameter), the compiler keeps the
// converted value's referent alive and immovable for the call's duration,
// without forcing it to the heap. That is exactly what every argument
// below needs and no more, so none of these four functions repeats that
// directive, or the stronger uintptrescapes one, on itself — the guarantee
// already comes from how syscall.Syscall and syscall.Syscall6 are
// declared, triggered here by writing the conversion inline in the call.

package sctp

import (
	"runtime"
	"syscall"
	"unsafe"
)

// rawSetsockopt calls setsockopt(2) directly, bypassing syscall.SetsockoptInt
// and friends so the caller controls optval's exact byte layout: every
// option this package sets is a kernel struct (RtoInfo, SndInfo defaults,
// peer address parameters, ...) encoded byte-wise by abi.go, not always a
// bare int.
//
// The returned error, when non-nil, is always a syscall.Errno, never
// wrapped: callers map it to the package's own error contract (opError,
// optError) or compare it against specific errno values directly.
func rawSetsockopt(fd, level, opt int, p unsafe.Pointer, l uintptr) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(opt), uintptr(p), l, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// rawGetsockopt calls getsockopt(2) directly. l is both input (the buffer
// p points to holds l bytes) and output (the kernel overwrites it with the
// length it actually reports). What a length shorter than the option's own
// value does depends on the option's level, and this function has no
// opinion of its own about it either way: at level SOL_SOCKET,
// net/core/sock.c's sk_getsockopt — the generic path every socket falls
// back to there, independent of protocol — copies only what fits and
// reports that shorter length back unchanged ("if (len > lv) len = lv;",
// then copying exactly that many bytes); at level IPPROTO_SCTP, the
// individual SCTP getters each check the buffer themselves and refuse a
// short one with EINVAL instead of truncating (for example
// sctp_getsockopt_nodelay, net/sctp/socket.c: "if (len < sizeof(int))
// return -EINVAL;" — one representative getter, not a rule every SCTP
// option necessarily repeats identically, since each is its own function).
func rawGetsockopt(fd, level, opt int, p unsafe.Pointer, l *uint32) error {
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(fd), uintptr(level), uintptr(opt), uintptr(p),
		uintptr(unsafe.Pointer(l)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// rawSendmsg calls sendmsg(2) directly on msg, exactly as msg already
// describes it, rather than through syscall.SendmsgN. On Linux,
// syscall.SendmsgN substitutes a one-byte scratch iovec whenever the
// payload is empty and control data (ancillary SNDINFO/PRINFO/AUTHINFO) is
// present — a workaround that makes sense for stream sockets sending
// control data with no payload of their own, but wrong for SCTP in two
// different ways, which sctp_sendmsg_parse and sctp_sendmsg_check_sflags
// (net/sctp/socket.c) do not treat alike:
//
//   - A message with neither SCTP_EOF nor SCTP_ABORT set must carry a
//     non-empty payload — sctp_sendmsg_parse refuses
//     "(!(sflags & (SCTP_EOF | SCTP_ABORT)) && msg_len == 0)" with EINVAL
//     — so SendmsgN's dummy byte would turn a message this package has
//     already refused as empty (or one a caller reaches by some other
//     path) into a real one-byte DATA chunk on the wire while still
//     reporting n == 0, silently sending data the caller never asked to
//     send.
//   - A message that does carry SCTP_EOF must instead carry no payload at
//     all — the same function refuses "(sflags & SCTP_EOF) && msg_len > 0"
//     the same way — and CloseAssoc's and a peeled-off Conn.Close's own
//     empty send (abi.go's sndFlagEOF) is exactly that legitimate,
//     deliberately zero-length shutdown request, so SendmsgN's dummy byte
//     would turn a valid one into an EINVAL instead. SCTP_ABORT carries no
//     such restriction: sctp_sendmsg_check_sflags hands msg and msg_len
//     straight to sctp_make_abort_user (net/sctp/sm_make_chunk.c), which
//     accepts a payload of any length, including zero, and sends it
//     verbatim as the ABORT's User-Initiated Abort cause — this is how
//     AbortAssoc(id, cause []byte) carries cause onto the wire, cause
//     possibly empty (abi.go's sndFlagAbort). An empty AbortAssoc call is
//     therefore never refused by the kernel either way, but SendmsgN's
//     dummy byte would still corrupt it silently: the call would
//     "succeed" while putting a spurious one-byte cause the caller never
//     supplied onto the wire in place of the empty one it asked for.
//
// Building and issuing the sendmsg(2) call directly from msg, whatever
// msg.Iov and msg.Iovlen say, goes through none of these failure modes: a
// zero-length iovec reaches the kernel as a zero-length iovec. Refusing an
// empty payload that carries neither flag before any system call (the
// caller's job, not this function's) is a second, independent guard for
// the first case — this behaviour is what keeps it from being the only
// one.
//
// runtime.KeepAlive(msg) is belt-and-braces alongside syscall.Syscall's
// own uintptrkeepalive treatment of the uintptr(unsafe.Pointer(msg))
// argument. The real mechanism that keeps msg.Name, msg.Iov and
// msg.Control's own memory reachable through the call is more basic than
// either: msg is an ordinary, live *syscall.Msghdr for as long as this
// function still refers to it, and the runtime's garbage-collector stack
// scan — using the liveness maps the compiler emits for exactly this,
// not the compiler itself doing any scanning — treats a live pointer as
// live, tracing through every field it points to, msg's three included,
// the way it does for any other pointer, with nothing special about this
// call needed for that part. Naming msg again in
// runtime.KeepAlive after the syscall simply makes that liveness explicit
// at the one point (right after the argument's own value has already been
// read into registers) where a future refactor could otherwise leave msg
// looking unused for the rest of the function.
func rawSendmsg(fd int, msg *syscall.Msghdr, flags int) (int, error) {
	r0, _, errno := syscall.Syscall(syscall.SYS_SENDMSG, uintptr(fd),
		uintptr(unsafe.Pointer(msg)), uintptr(flags))
	runtime.KeepAlive(msg)
	if errno != 0 {
		return 0, errno
	}
	return int(r0), nil
}

// rawRecvmsg calls recvmsg(2) directly on msg. See rawSendmsg for
// runtime.KeepAlive(msg)'s belt-and-braces role alongside syscall.Syscall's
// own treatment of the pointer argument.
func rawRecvmsg(fd int, msg *syscall.Msghdr, flags int) (int, error) {
	r0, _, errno := syscall.Syscall(syscall.SYS_RECVMSG, uintptr(fd),
		uintptr(unsafe.Pointer(msg)), uintptr(flags))
	runtime.KeepAlive(msg)
	if errno != 0 {
		return 0, errno
	}
	return int(r0), nil
}
