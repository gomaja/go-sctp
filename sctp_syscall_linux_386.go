//go:build linux && 386
// +build linux,386

// Copyright 2026 gomaja. All rights reserved.
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

package sctp

import (
	"runtime"
	"syscall"
	"unsafe"
)

// Linux/i386 multiplexes socket operations through socketcall(2). Keep the
// compatibility entry point used by Go's syscall package instead of relying on
// the newer per-operation syscall numbers.
const (
	socketcallSetsockopt = 14
	socketcallGetsockopt = 15
	socketcallSendmsg    = 16
	socketcallRecvmsg    = 17
)

func socketcall(call, a0, a1, a2, a3, a4, a5 uintptr) (uintptr, uintptr, syscall.Errno) {
	args := [...]uintptr{a0, a1, a2, a3, a4, a5}
	r0, r1, errno := syscall.Syscall(syscall.SYS_SOCKETCALL, call,
		uintptr(unsafe.Pointer(&args[0])), 0)
	runtime.KeepAlive(&args)
	return r0, r1, errno
}

//go:uintptrescapes
func rawSetsockopt(fd int, level, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	r0, r1, errno := socketcall(socketcallSetsockopt, uintptr(fd), level,
		optname, optval, optlen, 0)
	if errno != 0 {
		return r0, r1, errno
	}
	return r0, r1, nil
}

//go:uintptrescapes
func rawGetsockopt(fd int, level, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	r0, r1, errno := socketcall(socketcallGetsockopt, uintptr(fd), level,
		optname, optval, optlen, 0)
	if errno != 0 {
		return r0, r1, errno
	}
	return r0, r1, nil
}

func rawRecvmsg(fd int, msg *syscall.Msghdr, flags int) (uintptr, error) {
	r0, _, errno := socketcall(socketcallRecvmsg, uintptr(fd),
		uintptr(unsafe.Pointer(msg)), uintptr(flags), 0, 0, 0)
	runtime.KeepAlive(msg)
	if errno != 0 {
		return 0, errno
	}
	return r0, nil
}

func rawSendmsg(fd int, msg *syscall.Msghdr, flags int) (uintptr, error) {
	r0, _, errno := socketcall(socketcallSendmsg, uintptr(fd),
		uintptr(unsafe.Pointer(msg)), uintptr(flags), 0, 0, 0)
	runtime.KeepAlive(msg)
	if errno != 0 {
		return 0, errno
	}
	return r0, nil
}
