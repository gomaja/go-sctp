//go:build linux
// +build linux

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

package sctp

import (
	"bytes"
	"syscall"
	"testing"
	"unsafe"
)

func socketpair(t *testing.T) [2]int {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX,
		syscall.SOCK_SEQPACKET|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
	})
	return fds
}

func TestRawSockoptSyscalls(t *testing.T) {
	fds := socketpair(t)

	want := int32(1)
	if _, _, err := rawSetsockopt(fds[0], syscall.SOL_SOCKET,
		syscall.SO_PASSCRED, uintptr(unsafe.Pointer(&want)), unsafe.Sizeof(want)); err != nil {
		t.Fatalf("setsockopt(SO_PASSCRED): %v", err)
	}

	var got int32
	optlen := uint32(unsafe.Sizeof(got))
	if _, _, err := rawGetsockopt(fds[0], syscall.SOL_SOCKET,
		syscall.SO_PASSCRED, uintptr(unsafe.Pointer(&got)),
		uintptr(unsafe.Pointer(&optlen))); err != nil {
		t.Fatalf("getsockopt(SO_PASSCRED): %v", err)
	}
	if optlen != uint32(unsafe.Sizeof(got)) {
		t.Fatalf("getsockopt(SO_PASSCRED) length = %d, want %d",
			optlen, unsafe.Sizeof(got))
	}
	if got != want {
		t.Fatalf("getsockopt(SO_PASSCRED) = %d, want %d", got, want)
	}
}

func TestRawMessageSyscalls(t *testing.T) {
	fds := socketpair(t)
	want := []byte("socketcall boundary")

	sendIov := syscall.Iovec{Base: &want[0]}
	sendIov.SetLen(len(want))
	sendMsg := syscall.Msghdr{Iov: &sendIov}
	sendMsg.Iovlen = 1
	n, err := rawSendmsg(fds[0], &sendMsg, 0)
	if err != nil {
		t.Fatalf("sendmsg: %v", err)
	}
	if n != uintptr(len(want)) {
		t.Fatalf("sendmsg = %d bytes, want %d", n, len(want))
	}

	got := make([]byte, len(want))
	recvIov := syscall.Iovec{Base: &got[0]}
	recvIov.SetLen(len(got))
	recvMsg := syscall.Msghdr{Iov: &recvIov}
	recvMsg.Iovlen = 1
	n, err = rawRecvmsg(fds[1], &recvMsg, 0)
	if err != nil {
		t.Fatalf("recvmsg: %v", err)
	}
	if n != uintptr(len(want)) {
		t.Fatalf("recvmsg = %d bytes, want %d", n, len(want))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("recvmsg payload = %q, want %q", got, want)
	}
}

// Both the payload and the kernel-updated header must survive a stack move
// between converting the header pointer and entering the syscall. Keeping all
// receive storage local exercises this path with the compiler's maymorestack
// stack-movement diagnostic, including the additional socketcall frame on 386.
func TestRawRecvmsgStackStorage(t *testing.T) {
	fds := socketpair(t)
	if err := syscall.Sendmsg(fds[0], []byte{0x19, 0x72}, nil, nil, 0); err != nil {
		t.Fatal(err)
	}
	var payload [1]byte
	iov := syscall.Iovec{Base: &payload[0]}
	iov.SetLen(len(payload))
	msg := syscall.Msghdr{Iov: &iov}
	msg.Iovlen = 1
	n, err := rawRecvmsg(fds[1], &msg, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || payload[0] != 0x19 || msg.Flags&syscall.MSG_TRUNC == 0 {
		t.Fatalf("recvmsg n=%d payload=%x flags=%x; want n=1 payload=19 and MSG_TRUNC",
			n, payload[0], msg.Flags)
	}
}
