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

//go:build linux && 386

// syscall_linux_386.go is syscall_linux_other.go's counterpart for
// linux/386. Every kernel this package supports has direct i386
// getsockopt(2), setsockopt(2), sendmsg(2) and recvmsg(2) entries
// (arch/x86/entry/syscalls/syscall_32.tbl, v6.12: 365, 366, 370, 372), so
// the kernel is not the reason this file exists. The standard library is: the syscall
// package's GOARCH=386 build defines SYS_SOCKETCALL and no per-operation
// SYS_SETSOCKOPT/SYS_GETSOCKOPT/SYS_SENDMSG/SYS_RECVMSG at all (confirmed
// with "go doc syscall.SYS_SETSOCKOPT" under GOOS=linux GOARCH=386 —
// "no symbol"), so every one of its own socket wrappers for this GOARCH
// already goes through socketcall(2), never the direct numbers. This file
// follows the same route for the same reason: consistency with what the
// only syscall numbers this build actually has route through, selected by
// the call number constants below (include/uapi/linux/net.h, v6.12,
// SYS_SETSOCKOPT=14, SYS_GETSOCKOPT=15, SYS_SENDMSG=16, SYS_RECVMSG=17).

package sctp

import (
	"runtime"
	"syscall"
	"unsafe"
)

const (
	socketcallSetsockopt = 14
	socketcallGetsockopt = 15
	socketcallSendmsg    = 16
	socketcallRecvmsg    = 17
)

// socketcall issues one socketcall(2) trap. Unlike syscall.Syscall6, which
// the standard library declares go:uintptrkeepalive (keeping a converted
// pointer argument's referent alive and immovable for the call, without
// forcing it to the heap), socketcall is a plain hand-written wrapper with
// no such treatment of its own arguments — until marked go:uintptrescapes,
// below.
//
// The kernel does not read a0..a5 as an argument list the way
// syscall.Syscall6 reads its trailing uintptr parameters: socketcall(2)
// takes one pointer to an in-memory array of the real call's arguments
// (include/uapi/linux/net.h; net/socket.c: sys_socketcall copies
// sizeof(unsigned long) * nargs from that pointer with copy_from_user
// before dispatching on call). args is that array, and its address, not
// a0..a5 themselves, is what crosses into the kernel — so args itself must
// stay put for the same reason a0..a5's own pointees must: the runtime's
// stack-copying machinery, which relocates pointers on a goroutine stack
// growth using the liveness maps the compiler emits for exactly that, has
// no way to know that some of the uintptr values now sitting in args used
// to be pointers, so a stack growth between here and the trap could
// relocate what they still point to, or a collection could free it
// outright once nothing pointer-typed appears to reference it any longer,
// unless the go:uintptrescapes directive below tells the compiler to keep
// the original operand alive and immovable, at whichever call to this
// function wrote it as
// uintptr(x). runtime.KeepAlive(&args) covers only args itself, the local
// copy, not what its elements used to point to before this function
// converted them to plain integers — see cmd/compile's Compiler
// Directives documentation for go:uintptrescapes.
//
//go:uintptrescapes
func socketcall(call, a0, a1, a2, a3, a4, a5 uintptr) (uintptr, uintptr, syscall.Errno) {
	args := [...]uintptr{a0, a1, a2, a3, a4, a5}
	r0, r1, errno := syscall.Syscall(syscall.SYS_SOCKETCALL, call,
		uintptr(unsafe.Pointer(&args[0])), 0)
	runtime.KeepAlive(&args)
	return r0, r1, errno
}

// rawSetsockopt calls setsockopt(2) through socketcall(2). See
// syscall_linux_other.go's rawSetsockopt for optval's byte layout and the
// error contract; both are identical here, only the trap differs.
//
// p is a genuine unsafe.Pointer parameter, not a pre-converted uintptr, so
// nothing between a caller of rawSetsockopt and this line needs any
// special treatment: an ordinary Go pointer stays live and correctly
// updated across any number of stack moves on its own. It is only this
// call to socketcall, where p is converted to uintptr to cross into
// untyped argument territory, that needs socketcall's go:uintptrescapes
// pragma — written as uintptr(p) directly in this call expression, as the
// directive requires.
func rawSetsockopt(fd, level, opt int, p unsafe.Pointer, l uintptr) error {
	_, _, errno := socketcall(socketcallSetsockopt, uintptr(fd),
		uintptr(level), uintptr(opt), uintptr(p), l, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// rawGetsockopt calls getsockopt(2) through socketcall(2). See
// syscall_linux_other.go's rawGetsockopt for what l means on both sides of
// the call.
func rawGetsockopt(fd, level, opt int, p unsafe.Pointer, l *uint32) error {
	_, _, errno := socketcall(socketcallGetsockopt, uintptr(fd),
		uintptr(level), uintptr(opt), uintptr(p),
		uintptr(unsafe.Pointer(l)), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// rawSendmsg calls sendmsg(2) through socketcall(2). See
// syscall_linux_other.go's rawSendmsg for why this never goes through
// syscall.SendmsgN. runtime.KeepAlive(msg) here is belt-and-braces even
// more plainly than on that file's own copy: socketcall's go:uintptrescapes
// already pins msg itself alive and immovable for the call, and an
// ordinary live *syscall.Msghdr's own pointer fields — msg.Name, msg.Iov
// and msg.Control, whatever separate memory they point to — are reachable
// through the normal way the garbage collector traces a live struct's
// fields, not through anything go:uintptrescapes does beyond keeping msg
// itself alive.
func rawSendmsg(fd int, msg *syscall.Msghdr, flags int) (int, error) {
	r0, _, errno := socketcall(socketcallSendmsg, uintptr(fd),
		uintptr(unsafe.Pointer(msg)), uintptr(flags), 0, 0, 0)
	runtime.KeepAlive(msg)
	if errno != 0 {
		return 0, errno
	}
	return int(r0), nil
}

// rawRecvmsg calls recvmsg(2) through socketcall(2). See rawSendmsg.
func rawRecvmsg(fd int, msg *syscall.Msghdr, flags int) (int, error) {
	r0, _, errno := socketcall(socketcallRecvmsg, uintptr(fd),
		uintptr(unsafe.Pointer(msg)), uintptr(flags), 0, 0, 0)
	runtime.KeepAlive(msg)
	if errno != 0 {
		return 0, errno
	}
	return int(r0), nil
}
