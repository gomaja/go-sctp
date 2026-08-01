//go:build linux && !386
// +build linux,!386

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

//go:uintptrescapes
func rawSetsockopt(fd int, level, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	r0, r1, errno := syscall.Syscall6(syscall.SYS_SETSOCKOPT,
		uintptr(fd), level, optname, optval, optlen, 0)
	if errno != 0 {
		return r0, r1, errno
	}
	return r0, r1, nil
}

//go:uintptrescapes
func rawGetsockopt(fd int, level, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	r0, r1, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT,
		uintptr(fd), level, optname, optval, optlen, 0)
	if errno != 0 {
		return r0, r1, errno
	}
	return r0, r1, nil
}

func rawRecvmsg(fd int, msg *syscall.Msghdr, flags int) (uintptr, error) {
	r0, _, errno := syscall.Syscall(syscall.SYS_RECVMSG, uintptr(fd),
		uintptr(unsafe.Pointer(msg)), uintptr(flags))
	runtime.KeepAlive(msg)
	if errno != 0 {
		return 0, errno
	}
	return r0, nil
}

func rawSendmsg(fd int, msg *syscall.Msghdr, flags int) (uintptr, error) {
	r0, _, errno := syscall.Syscall(syscall.SYS_SENDMSG, uintptr(fd),
		uintptr(unsafe.Pointer(msg)), uintptr(flags))
	runtime.KeepAlive(msg)
	if errno != 0 {
		return 0, errno
	}
	return r0, nil
}
