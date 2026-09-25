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

//go:build linux

package sctp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"runtime/debug"
	"syscall"
	"testing"
	"unsafe"
)

// socketpair returns a connected pair of AF_UNIX/SOCK_SEQPACKET descriptors,
// closed on test cleanup. Used where a real SCTP association is not the
// point: exercising the raw syscall plumbing itself needs only a socket
// that supports sendmsg/recvmsg, and AF_UNIX avoids any dependency on the
// SCTP module or network setup.
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

// sctpSocket opens a one-to-one SCTP socket (SOCK_STREAM, RFC 6458 §4.1.1)
// and registers it to close on test cleanup.
func sctpSocket(t *testing.T) int {
	t.Helper()
	fd, err := syscall.Socket(syscall.AF_INET,
		syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, ipprotoSCTP)
	if err != nil {
		t.Fatalf("socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP): %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(fd) })
	return fd
}

// sctpLoopbackPair binds, listens, connects and accepts a one-to-one SCTP
// association over 127.0.0.1, entirely with the standard library's plain
// syscall.Bind/Listen/Connect/Accept, ahead of any syscall.RawConn-owning
// machinery. Both descriptors close on test cleanup.
func sctpLoopbackPair(t *testing.T) (client, server int) {
	t.Helper()

	listener := sctpSocket(t)
	if err := syscall.Bind(listener, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := syscall.Listen(listener, 1); err != nil {
		t.Fatalf("listen: %v", err)
	}
	sa, err := syscall.Getsockname(listener)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	port := sa.(*syscall.SockaddrInet4).Port

	client = sctpSocket(t)
	if err := syscall.Connect(client, &syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("connect: %v", err)
	}

	server, _, err = syscall.Accept(listener)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Close(server) })
	return client, server
}

// requireSCTPProtocolOptions skips the calling test in exactly one known,
// narrow circumstance: a 32-bit (GOARCH=386) test binary, running under
// QEMU's linux-user i386 emulation because Rosetta 2 cannot execute a
// 32-bit binary at all, on a non-x86 host (this repository's own Linux
// test harness on Apple Silicon needs this path for a GOARCH=386 binary,
// since there is no way to get genuinely native x86 execution there).
// QEMU's own do_setsockopt (linux-user/syscall.c) has no case for level
// SOL_SCTP/IPPROTO_SCTP at all — every level it does not recognize falls
// to that function's own "unimplemented" default, which logs "Unsupported
// setsockopt level=%d optname=%d" and returns exactly ENOPROTOOPT — while
// every SOL_SOCKET-level option on the same descriptor, and
// socket/bind/connect/accept/sendmsg/recvmsg themselves, keep working
// normally, since QEMU does implement those.
//
// The check calls the standard library's own syscall.SetsockoptInt, not
// this package's rawSetsockopt, specifically so that a real regression in
// this package's own code — the thing this file exists to catch — still
// fails the test it belongs to instead of being absorbed into a skip: if
// the standard library's call also fails, the limitation is not this
// package's.
//
// The skip is gated on both GOARCH=386 and the specific errno, not on the
// failure alone: any other GOARCH, or a GOARCH=386 failure with some
// other errno, is not the one known circumstance above and fails the
// test instead, so this can never quietly absorb an unrelated regression.
// On real x86 hardware (this repository's CI runs linux/386 natively on
// an x86_64 runner) the standard library's call is expected to succeed
// and this never skips.
func requireSCTPProtocolOptions(t *testing.T) {
	t.Helper()
	fd := sctpSocket(t)
	err := syscall.SetsockoptInt(fd, ipprotoSCTP, optNoDelay, 1)
	if err == nil {
		return
	}
	if runtime.GOARCH == "386" && errors.Is(err, syscall.ENOPROTOOPT) {
		t.Skipf("SCTP-level socket options are unavailable under QEMU's i386 emulation on this host (verified via the standard library's own syscall.SetsockoptInt, independently of this package): %v", err)
	}
	t.Fatalf("syscall.SetsockoptInt(SCTP_NODELAY): %v (not the known GOARCH=386/ENOPROTOOPT case this package treats as an environment limit)", err)
}

// TestRawSockoptRoundTrip proves rawSetsockopt and rawGetsockopt reach the
// real kernel option, not just each other: SCTP_NODELAY is set, read back,
// then cleared and read back again, so an implementation that only ever
// returned its own input would fail the second half.
func TestRawSockoptRoundTrip(t *testing.T) {
	requireSCTPProtocolOptions(t)
	fd := sctpSocket(t)

	for _, want := range []int32{1, 0} {
		if err := rawSetsockopt(fd, ipprotoSCTP, optNoDelay,
			unsafe.Pointer(&want), unsafe.Sizeof(want)); err != nil {
			t.Fatalf("rawSetsockopt(SCTP_NODELAY, %d): %v", want, err)
		}

		var got int32
		l := uint32(unsafe.Sizeof(got))
		if err := rawGetsockopt(fd, ipprotoSCTP, optNoDelay,
			unsafe.Pointer(&got), &l); err != nil {
			t.Fatalf("rawGetsockopt(SCTP_NODELAY): %v", err)
		}
		if l != uint32(unsafe.Sizeof(got)) {
			t.Fatalf("reported length = %d, want %d", l, unsafe.Sizeof(got))
		}
		// sctp_getsockopt_nodelay (net/sctp/socket.c) reports
		// (sp->nodelay == 1), always exactly 0 or 1.
		if got != want {
			t.Fatalf("SCTP_NODELAY = %d, want %d", got, want)
		}
	}
}

// TestRawGetsockoptShortLengthTruncatesRatherThanFails pins that a buffer
// smaller than an option's value is not itself an error at this layer, and
// that rawGetsockopt passes the caller's length through unchanged rather
// than enlarging it. SO_TYPE (level SOL_SOCKET) is used rather than an
// SCTP-specific option because the property belongs to the generic path
// every socket falls back to for SOL_SOCKET options, independent of the
// underlying protocol: net/core/sock.c's sk_getsockopt clamps
// ("if (len > lv) len = lv;"), copies exactly that many bytes, and writes
// the same, unenlarged length back to *optlen — it neither refuses the
// call nor reports the option's true size.
func TestRawGetsockoptShortLengthTruncatesRatherThanFails(t *testing.T) {
	fd := sctpSocket(t)

	var want [4]byte
	binary.NativeEndian.PutUint32(want[:], uint32(syscall.SOCK_STREAM))

	var got [4]byte
	l := uint32(1)
	if err := rawGetsockopt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE,
		unsafe.Pointer(&got[0]), &l); err != nil {
		t.Fatalf("rawGetsockopt(SO_TYPE, len=1): %v", err)
	}
	if l != 1 {
		t.Fatalf("reported length = %d, want 1 (the kernel echoes back what it copied, not SO_TYPE's real size)", l)
	}
	if got[0] != want[0] {
		t.Fatalf("first byte = %#x, want %#x (SOCK_STREAM)", got[0], want[0])
	}
	if got[1] != 0 || got[2] != 0 || got[3] != 0 {
		t.Fatalf("bytes past the requested length were written: %v", got)
	}
}

// TestRawMessageSyscalls proves rawSendmsg/rawRecvmsg reach the kernel
// directly: a payload sent on one AF_UNIX descriptor of a pair arrives on
// the other. This is the same property v1's TestRawMessageSyscalls pinned
// (also over a socketpair, since the syscalls themselves do not care what
// kind of socket they are handed), and it needs no SCTP association to
// hold.
func TestRawMessageSyscalls(t *testing.T) {
	fds := socketpair(t)
	want := []byte("socketcall boundary")

	sendIov := syscall.Iovec{Base: &want[0]}
	sendIov.SetLen(len(want))
	sendMsg := syscall.Msghdr{Iov: &sendIov, Iovlen: 1}
	n, err := rawSendmsg(fds[0], &sendMsg, 0)
	if err != nil {
		t.Fatalf("rawSendmsg: %v", err)
	}
	if n != len(want) {
		t.Fatalf("rawSendmsg = %d bytes, want %d", n, len(want))
	}

	got := make([]byte, len(want))
	recvIov := syscall.Iovec{Base: &got[0]}
	recvIov.SetLen(len(got))
	recvMsg := syscall.Msghdr{Iov: &recvIov, Iovlen: 1}
	n, err = rawRecvmsg(fds[1], &recvMsg, 0)
	if err != nil {
		t.Fatalf("rawRecvmsg: %v", err)
	}
	if n != len(want) {
		t.Fatalf("rawRecvmsg = %d bytes, want %d", n, len(want))
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("recvmsg payload = %q, want %q", got, want)
	}
}

// TestRawRecvmsgStackStorage proves both the payload buffer and the
// kernel-updated Msghdr survive a stack move between converting the
// header's address and entering the kernel — the property the 386 storage
// fix protects (go:uintptrescapes on socketcall, syscall_linux_386.go),
// and which applies the same way on every other architecture too: nothing
// about a pointer surviving a stack move is architecture-specific, only
// 386 needs the pragma to survive it (non-386 already gets the same
// guarantee from syscall.Syscall's own uintptrkeepalive, syscall_linux_other.go).
//
// Every value below is a plain local, none of it captured by a closure.
// What that buys depends on the architecture, checked directly with
// "go test -gcflags=-m -c" rather than assumed: on every architecture but
// 386, it is ordinary stack-resident storage ("moved to heap" does not
// appear for payload, iov or msg there), with nothing already pinning it
// off the stack before the property under test gets a chance to matter.
// 386 is different by design: socketcall's own go:uintptrescapes
// (syscall_linux_386.go) itself moves payload, iov and msg to the heap
// for the call's duration ("moved to heap" does appear for all three
// under GOARCH=386) — that pinning is the whole point of the pragma, and
// Go's heap does not move, so once there a stack relocation cannot reach
// them at all. They are only stack-resident, and so only reachable by a
// stack move, in the one state this test exists to catch: the pragma
// removed (confirmed the same way — with go:uintptrescapes deliberately
// deleted for this check alone, "moved to heap" no longer appears for any
// of the three under GOARCH=386 either).
//
// An earlier version of this test wrapped the syscall in a closure passed
// to a stack-growing helper. On amd64 that closure-capture alone already
// moved payload and iov to the heap ("moved to heap" for exactly those
// two, confirmed the same way; not msg, whose own by-reference capture
// evidently did not need to), regardless of the pragma — so the stack
// move the helper was trying to force could never have corrupted what
// they held. A plain, straight-line function has no such capture-driven
// escape of its own, so on non-386, and on 386 with the pragma correctly
// in place, an ordinary run without special build flags is a baseline
// correctness check, not a reliable reproducer of a broken pragma
// (confirmed empirically: naive re-runs alone did not catch it once the
// pragma was deliberately removed for testing). The
// deterministic version of this diagnostic is
// -gcflags=all=-d=maymorestack=runtime.mayMoreStackMove, which forces a
// stack check, and so a stack move, at every function's own entry —
// including rawRecvmsg's and socketcall's — regardless of call depth, and
// is what the project's arch-32bit CI job runs this test under.
func TestRawRecvmsgStackStorage(t *testing.T) {
	fds := socketpair(t)
	if err := syscall.Sendmsg(fds[0], []byte{0x19, 0x72}, nil, nil, 0); err != nil {
		t.Fatal(err)
	}

	var payload [1]byte
	iov := syscall.Iovec{Base: &payload[0]}
	iov.SetLen(len(payload))
	msg := syscall.Msghdr{Iov: &iov, Iovlen: 1}
	n, err := rawRecvmsg(fds[1], &msg, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || payload[0] != 0x19 || msg.Flags&syscall.MSG_TRUNC == 0 {
		t.Fatalf("recvmsg n=%d payload=%x flags=%x; want n=1 payload=19 and MSG_TRUNC",
			n, payload[0], msg.Flags)
	}
}

// TestRawSockoptStackStorage is TestRawRecvmsgStackStorage's counterpart
// for rawSetsockopt/rawGetsockopt, plain and closure-free for the same
// reason: v1 pinned this property indirectly, through
// SCTPConn.Setsockopt/Getsockopt wrapper methods v2 removes in favor of
// SyscallConn (sctp_sockopt_stack_test.go's TestRawSetsockoptKeepsOptionAlive
// and TestRawGetsockoptSurvivesStackGrowth). This package now pins it
// directly at the raw layer those wrappers used to sit on top of,
// independently of whether anything above that layer exists yet.
func TestRawSockoptStackStorage(t *testing.T) {
	requireSCTPProtocolOptions(t)
	fd := sctpSocket(t)

	want := int32(1)
	if err := rawSetsockopt(fd, ipprotoSCTP, optNoDelay,
		unsafe.Pointer(&want), unsafe.Sizeof(want)); err != nil {
		t.Fatal(err)
	}
	var got int32
	l := uint32(unsafe.Sizeof(got))
	if err := rawGetsockopt(fd, ipprotoSCTP, optNoDelay,
		unsafe.Pointer(&got), &l); err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("SCTP_NODELAY after stack storage = %d, want 1", got)
	}
}

// TestRawSendRecvCarriesSndRcvInfo moves one message with SNDINFO over a
// real SCTP association and checks that RCVINFO decodes back the values
// that actually travel with it: the encoder (appendSendCmsgs) and parser
// (parseRecvCmsgs) are exercised against the kernel itself, not against
// each other.
//
// RcvInfo.Context is not one of them: rcv_context is the receiving
// association's own default_rcv_context (SCTP_CONTEXT, set independently
// on the receiving socket), never the sender's sinfo_context — RFC 6458
// §8.1.25 ("the setting of this value only affects received messages from
// the peer and does not affect the value that is saved with outbound
// messages"; net/sctp/ulpevent.c: sctp_ulpevent_read_rcvinfo sets
// rinfo.rcv_context from event->asoc->default_rcv_context, never from
// anything the DATA chunk carried). So this sets SCTP_CONTEXT on the
// receiver to its own, independent value and checks that one instead,
// which both proves decodeRcvInfo's Context field against a real,
// controllable kernel value and pins the asymmetry itself.
func TestRawSendRecvCarriesSndRcvInfo(t *testing.T) {
	requireSCTPProtocolOptions(t)
	client, server := sctpLoopbackPair(t)

	// RCVINFO is attached only when SCTP_RECVRCVINFO is on
	// (sctp_ulpevent_read_rcvinfo, net/sctp/ulpevent.c); every socket
	// starts with it off.
	on := int32(1)
	if err := rawSetsockopt(server, ipprotoSCTP, optRecvRcvInfo,
		unsafe.Pointer(&on), unsafe.Sizeof(on)); err != nil {
		t.Fatalf("rawSetsockopt(SCTP_RECVRCVINFO): %v", err)
	}

	// struct sctp_assoc_value { assoc_id(4) assoc_value(4) } (abi.go).
	// assoc_id is ignored on a one-to-one socket once an association is
	// established (sctp_id2assoc, net/sctp/socket.c: "If this is not a
	// UDP-style socket, assoc id should be ignored"), so 0 reaches the
	// same, already-accepted association regardless of its real id.
	const wantContext = 99
	var contextOpt [sizeAssocValue]byte
	binary.NativeEndian.PutUint32(contextOpt[assocValueValueOff:], wantContext)
	if err := rawSetsockopt(server, ipprotoSCTP, optContext,
		unsafe.Pointer(&contextOpt[0]), sizeAssocValue); err != nil {
		t.Fatalf("rawSetsockopt(SCTP_CONTEXT): %v", err)
	}

	payload := []byte("raw sendmsg/recvmsg carries SNDINFO/RCVINFO")
	snd := SndInfo{Stream: 3, PPID: 0x11223344, Context: 7}
	cbuf := make([]byte, 0, cmsgSpace(sizeSndInfo))
	cbuf = cbuf[:appendSendCmsgs(cbuf, &snd, 0, nil, nil)]

	sendIov := syscall.Iovec{Base: &payload[0]}
	sendIov.SetLen(len(payload))
	sendMsg := syscall.Msghdr{Iov: &sendIov, Iovlen: 1, Control: &cbuf[0]}
	sendMsg.SetControllen(len(cbuf))

	sent, err := rawSendmsg(client, &sendMsg, 0)
	if err != nil {
		t.Fatalf("rawSendmsg: %v", err)
	}
	if sent != len(payload) {
		t.Fatalf("rawSendmsg = %d bytes, want %d", sent, len(payload))
	}

	got := make([]byte, len(payload)+16)
	oob := make([]byte, cmsgSpace(sizeRcvInfo)+cmsgSpace(sizeNxtInfo))
	recvIov := syscall.Iovec{Base: &got[0]}
	recvIov.SetLen(len(got))
	recvMsg := syscall.Msghdr{Iov: &recvIov, Iovlen: 1, Control: &oob[0]}
	recvMsg.SetControllen(len(oob))

	received, err := rawRecvmsg(server, &recvMsg, 0)
	if err != nil {
		t.Fatalf("rawRecvmsg: %v", err)
	}
	if received != len(payload) || !bytes.Equal(got[:received], payload) {
		t.Fatalf("payload = %q (n=%d), want %q", got[:received], received, payload)
	}

	var info MsgInfo
	if err := parseRecvCmsgs(oob[:recvMsg.Controllen], int(recvMsg.Flags), &info); err != nil {
		t.Fatalf("parseRecvCmsgs: %v", err)
	}
	if !info.EOR {
		t.Fatalf("MSG_EOR not reported, flags=%#x", recvMsg.Flags)
	}
	if info.Rcv.Stream != snd.Stream || info.Rcv.PPID != snd.PPID || info.Rcv.Context != wantContext {
		t.Fatalf("RcvInfo = %+v, want Stream=%d PPID=%#x Context=%d (the receiver's own SCTP_CONTEXT, not the sender's SNDINFO.Context)",
			info.Rcv, snd.Stream, snd.PPID, uint32(wantContext))
	}
}

// TestRawSyscallsAllocateNothing pins the zero-allocation contract of all
// four raw functions together, over one real send/receive round trip per
// measured iteration, with the garbage collector paused so a collection
// mid-measurement cannot be miscounted against it.
//
// It is skipped on 386: socketcall's go:uintptrescapes (syscall_linux_386.go)
// forces the pointer argument named at its call site onto the heap for the
// call's duration — that is what the directive is for — so rawSetsockopt,
// rawGetsockopt, rawSendmsg and rawRecvmsg cannot be zero-allocation on
// this architecture without giving up the storage guarantee the pragma
// exists to provide. Every other architecture reaches the kernel through
// syscall.Syscall/Syscall6 directly, declared only go:uintptrkeepalive in
// the syscall package, which does not force a heap escape.
func TestRawSyscallsAllocateNothing(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector")
	}
	if runtime.GOARCH == "386" {
		t.Skip("socketcall's go:uintptrescapes forces its pointer argument onto the heap on this architecture")
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	client, server := sctpLoopbackPair(t)
	on := int32(1)
	if err := rawSetsockopt(server, ipprotoSCTP, optRecvRcvInfo,
		unsafe.Pointer(&on), unsafe.Sizeof(on)); err != nil {
		t.Fatalf("rawSetsockopt(SCTP_RECVRCVINFO): %v", err)
	}

	var nodelay int32 = 1
	var got int32
	payload := [1]byte{0x5a}
	rbuf := make([]byte, 32)
	oob := make([]byte, cmsgSpace(sizeRcvInfo))

	allocs := testing.AllocsPerRun(200, func() {
		if err := rawSetsockopt(client, ipprotoSCTP, optNoDelay,
			unsafe.Pointer(&nodelay), unsafe.Sizeof(nodelay)); err != nil {
			t.Fatal(err)
		}
		l := uint32(unsafe.Sizeof(got))
		if err := rawGetsockopt(client, ipprotoSCTP, optNoDelay,
			unsafe.Pointer(&got), &l); err != nil {
			t.Fatal(err)
		}

		sendIov := syscall.Iovec{Base: &payload[0]}
		sendIov.SetLen(len(payload))
		sendMsg := syscall.Msghdr{Iov: &sendIov, Iovlen: 1}
		if _, err := rawSendmsg(client, &sendMsg, 0); err != nil {
			t.Fatal(err)
		}

		recvIov := syscall.Iovec{Base: &rbuf[0]}
		recvIov.SetLen(len(rbuf))
		recvMsg := syscall.Msghdr{Iov: &recvIov, Iovlen: 1, Control: &oob[0]}
		recvMsg.SetControllen(len(oob))
		if _, err := rawRecvmsg(server, &recvMsg, 0); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Errorf("rawSetsockopt+rawGetsockopt+rawSendmsg+rawRecvmsg allocated %.1f times per run, want 0", allocs)
	}
}
