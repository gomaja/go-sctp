// Copyright 2019 Wataru Ishida. All rights reserved.
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
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package sctp

import (
	"errors"
	"net"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// rawSocketFile opens a socket with socket(2) and hands it to an
// *os.File, as a parent process or a service manager would pass one on.
func rawSocketFile(t testing.TB, family, typ, proto int) *os.File {
	t.Helper()
	fd, err := syscall.Socket(family, typ|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		t.Fatalf("socket(%d, %d, %d): %v", family, typ, proto, err)
	}
	f := os.NewFile(uintptr(fd), "inherited")
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// fdOf is f's descriptor number, read through its RawConn so that f stays
// in whatever blocking mode it has.
func fdOf(t testing.TB, f *os.File) int {
	t.Helper()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	fd := -1
	rawFd(t, rc, func(d int) { fd = d })
	return fd
}

// wantFileRefusal asserts that err is a *net.OpError with Op "file"
// matching target, and that the call opened no descriptor.
func wantFileRefusal(t testing.TB, what string, err, target error) {
	t.Helper()
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "file" {
		t.Errorf("%s = %#v, want a *net.OpError with Op file", what, err)
		return
	}
	if !errors.Is(err, target) {
		t.Errorf("%s = %v, want it to match %v", what, err, target)
	}
}

// TestFileConnRefusals: FileConn adopts only a one-to-one SCTP socket
// holding an established association. A one-to-many socket, an
// unconnected one-to-one socket, a listening one and a TCP socket are
// refused with an error matching EINVAL; a pipe, which is not a socket,
// with the kernel's ENOTSOCK; a nil file with EINVAL and a closed one
// with EBADF. The Config form accepts only the package-side fields. No
// refusal leaves a descriptor behind.
func TestFileConnRefusals(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = pr.Close(); _ = pw.Close() })
	closed := rawSocketFile(t, syscall.AF_INET, syscall.SOCK_STREAM, ipprotoSCTP)
	_ = closed.Close()

	cases := []struct {
		name   string
		f      *os.File
		target error
	}{
		{"one-to-many socket", rawSocketFile(t, syscall.AF_INET, syscall.SOCK_SEQPACKET, ipprotoSCTP), syscall.EINVAL},
		{"unconnected one-to-one socket", rawSocketFile(t, syscall.AF_INET, syscall.SOCK_STREAM, ipprotoSCTP), syscall.EINVAL},
		{"listening socket", listenerFile(t, l), syscall.EINVAL},
		{"TCP socket", rawSocketFile(t, syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP), syscall.EINVAL},
		{"pipe", pr, syscall.ENOTSOCK},
		{"nil file", nil, syscall.EINVAL},
		{"closed file", closed, syscall.EBADF},
	}
	before := openFds(t)
	for _, tc := range cases {
		c, err := FileConn(tc.f)
		if c != nil {
			_ = c.Abort()
		}
		wantFileRefusal(t, "FileConn("+tc.name+")", err, tc.target)
	}
	if after := openFds(t); after != before {
		t.Errorf("descriptor count went %d -> %d across refused adoptions", before, after)
	}

	client, _ := dialAccept(t, nil, l)
	f := connFile(t, client)
	_, err = (&Config{NoDelay: new(true)}).FileConn(f)
	wantFileRefusal(t, "Config{NoDelay}.FileConn", err, syscall.EINVAL)
	if err == nil || !strings.Contains(err.Error(), "NoDelay") {
		t.Errorf("Config{NoDelay}.FileConn = %v, want it to name NoDelay", err)
	}
}

// connFile duplicates c's descriptor into an *os.File of its own.
func connFile(t testing.TB, c *Conn) *os.File {
	t.Helper()
	var f *os.File
	rawFd(t, mustSyscallConn(t, c), func(fd int) {
		dup, err := syscall.Dup(fd)
		if err != nil {
			t.Fatalf("dup: %v", err)
		}
		f = os.NewFile(uintptr(dup), "conn")
	})
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// TestFileListenerRefusals: FileListener adopts only a listening
// one-to-one SCTP socket.
func TestFileListenerRefusals(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	manyListening := rawSocketFile(t, syscall.AF_INET, syscall.SOCK_SEQPACKET, ipprotoSCTP)
	rawFd(t, mustRawConn(t, manyListening), func(fd int) {
		if err := syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			t.Fatalf("bind: %v", err)
		}
		if err := syscall.Listen(fd, 1); err != nil {
			t.Fatalf("listen: %v", err)
		}
	})
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = pr.Close(); _ = pw.Close() })
	for _, tc := range []struct {
		name   string
		f      *os.File
		target error
	}{
		{"connected one-to-one socket", connFile(t, client), syscall.EINVAL},
		{"unconnected one-to-one socket", rawSocketFile(t, syscall.AF_INET, syscall.SOCK_STREAM, ipprotoSCTP), syscall.EINVAL},
		{"listening one-to-many socket", manyListening, syscall.EINVAL},
		{"TCP socket", rawSocketFile(t, syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP), syscall.EINVAL},
		{"pipe", pr, syscall.ENOTSOCK},
		{"nil file", nil, syscall.EINVAL},
	} {
		l, err := FileListener(tc.f)
		if l != nil {
			_ = l.Close()
		}
		wantFileRefusal(t, "FileListener("+tc.name+")", err, tc.target)
	}
	_, err = (&Config{ReadBuffer: new(4096)}).FileListener(rawSocketFile(t, syscall.AF_INET, syscall.SOCK_STREAM, ipprotoSCTP))
	wantFileRefusal(t, "Config{ReadBuffer}.FileListener", err, syscall.EINVAL)
	if err == nil || !strings.Contains(err.Error(), "ReadBuffer") {
		t.Errorf("Config{ReadBuffer}.FileListener = %v, want it to name ReadBuffer", err)
	}
}

// mustRawConn is f.SyscallConn that fails the test on an error.
func mustRawConn(t testing.TB, f *os.File) syscall.RawConn {
	t.Helper()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	return rc
}

// TestFileListenerRejectsNilFile: a nil *os.File is refused without a
// panic.
func TestFileListenerRejectsNilFile(t *testing.T) {
	if l, err := FileListener(nil); l != nil || !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("FileListener(nil) = (%v, %v), want (nil, EINVAL)", l, err)
	}
}

// TestFileConnAdoptsEstablishedAssociation: a one-to-one socket connected
// outside the package, with none of the package's settings, is adopted:
// the Conn has the association's id and addresses, the package's own
// SCTP_ASSOC_CHANGE subscription and SCTP_RECVRCVINFO are switched on,
// the notifications the creator subscribed are taken as the caller's
// (EventAssocChange excepted), the Config's handler and grace period
// apply, and the association carries data.
func TestFileConnAdoptsEstablishedAssociation(t *testing.T) {
	cfd, sfd := sctpLoopbackPair(t)
	// The creator subscribed to SHUTDOWN events and nothing else.
	if err := setEvent(cfd, EventShutdown, true); err != nil {
		t.Fatalf("SCTP_EVENT: %v", err)
	}
	dup, err := syscall.Dup(cfd)
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	f := os.NewFile(uintptr(dup), "inherited")

	var handled atomic.Int32
	cfg := &Config{NotificationHandler: func(Notification) error { handled.Add(1); return nil }, CloseTimeout: 777 * time.Millisecond}
	c, err := cfg.FileConn(f)
	if err != nil {
		t.Fatalf("FileConn: %v", err)
	}
	// As with net.FileConn, the caller closes its own file once the Conn
	// has the socket.
	if err := f.Close(); err != nil {
		t.Fatalf("closing the caller's file: %v", err)
	}
	t.Cleanup(func() { _ = c.Abort() })

	if c.AssocID() == 0 {
		t.Error("AssocID = 0 for an established association")
	}
	if got := ipStrings(c.RemoteAddr().(*Addr)); !equalStrings(got, []string{"127.0.0.1"}) {
		t.Errorf("RemoteAddr = %v, want [127.0.0.1]", got)
	}
	if c.kind != kindAdopted {
		t.Errorf("kind = %d, want kindAdopted", c.kind)
	}
	rc := mustSyscallConn(t, c)
	if !subscribedInKernel(t, rc, EventAssocChange) {
		t.Error("SCTP_ASSOC_CHANGE is not subscribed on the adopted association")
	}
	if got := getIntOpt(t, rc, ipprotoSCTP, optRecvRcvInfo); got != 1 {
		t.Errorf("SCTP_RECVRCVINFO = %d, want 1", got)
	}
	if got, want := eventSet(c.subs.Load()), eventBit(EventShutdown); got != want {
		t.Errorf("logical subscriptions = %#x, want the creator's EventShutdown only (%#x)", got, want)
	}
	if c.closeWait != cfg.CloseTimeout {
		t.Errorf("grace period = %v, want %v", c.closeWait, cfg.CloseTimeout)
	}
	if c.handler == nil {
		t.Fatal("the adopted connection has no handler")
	}
	_ = c.handler(nil)
	if handled.Load() != 1 {
		t.Error("the adopted connection's handler is not the Config's")
	}

	if err := sendRaw(c, []byte("adopted")); err != nil {
		t.Fatalf("send: %v", err)
	}
	buf := make([]byte, 64)
	n, _, _, _, err := syscall.Recvmsg(sfd, buf, nil, 0)
	if err != nil || string(buf[:n]) != "adopted" {
		t.Fatalf("peer read %q, %v; want %q", buf[:n], err, "adopted")
	}
	if !fdIsOpen(cfd) {
		t.Error("adopting the socket closed the caller's original descriptor")
	}
}

// TestFileListenerAdoptsQueuedAssociations: a listener set up outside the
// package, without the SCTP_ASSOC_CHANGE subscription, is adopted with
// associations already queued on it. Each association took its own copy
// of the listener's subscriptions when it was created
// (net/sctp/associola.c: sctp_association_init), so the subscription the
// package switches on for the listener does not reach the queued ones;
// Accept switches it on for every accepted socket, which does.
func TestFileListenerAdoptsQueuedAssociations(t *testing.T) {
	lfd := sctpSocket(t)
	if err := syscall.Bind(lfd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := syscall.Listen(lfd, 8); err != nil {
		t.Fatalf("listen: %v", err)
	}
	// The creator subscribed to peer address changes.
	if err := setEvent(lfd, EventPeerAddrChange, true); err != nil {
		t.Fatalf("SCTP_EVENT: %v", err)
	}
	sa, err := syscall.Getsockname(lfd)
	if err != nil {
		t.Fatalf("getsockname: %v", err)
	}
	laddr := loopback4(uint16(sa.(*syscall.SockaddrInet4).Port))

	early, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, laddr)
	if err != nil {
		t.Fatalf("Dial before the adoption: %v", err)
	}
	t.Cleanup(func() { _ = early.Abort() })

	dup, err := syscall.Dup(lfd)
	if err != nil {
		t.Fatalf("dup: %v", err)
	}
	f := os.NewFile(uintptr(dup), "inherited")
	l, err := FileListener(f)
	if err != nil {
		t.Fatalf("FileListener: %v", err)
	}
	_ = f.Close()
	t.Cleanup(func() { _ = l.Close() })
	if got := listenerAddr(t, l).Port; got != laddr.Port {
		t.Errorf("Addr port = %d, want %d", got, laddr.Port)
	}
	if !subscribedInKernel(t, mustListenerRawConn(t, l), EventAssocChange) {
		t.Error("SCTP_ASSOC_CHANGE is not subscribed on the adopted listener")
	}

	late, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, laddr)
	if err != nil {
		t.Fatalf("Dial after the adoption: %v", err)
	}
	t.Cleanup(func() { _ = late.Abort() })

	for i := range 2 {
		c, err := l.AcceptSCTP()
		if err != nil {
			t.Fatalf("AcceptSCTP %d: %v", i, err)
		}
		t.Cleanup(func() { _ = c.Abort() })
		if c.AssocID() == 0 {
			t.Errorf("accepted %d: AssocID 0 for a live association", i)
		}
		if !subscribedInKernel(t, mustSyscallConn(t, c), EventAssocChange) {
			t.Errorf("accepted %d: SCTP_ASSOC_CHANGE is not subscribed on the association", i)
		}
		if got, want := eventSet(c.subs.Load()), eventBit(EventPeerAddrChange); got != want {
			t.Errorf("accepted %d: logical subscriptions = %#x, want the creator's EventPeerAddrChange only (%#x)", i, got, want)
		}
	}
}

// TestListenerSurvivesGCAfterFileListener: adopting a duplicate of a live
// *Listener's own descriptor must not leave the original descriptor
// exposed to a finalizer. os.NewFile takes ownership of the descriptor it
// is handed and closes it once the *os.File becomes unreachable
// (os/file_unix.go); FileListener dups again for the *Listener it
// returns, so the temporary file it was given has no owner left once it
// returns and must be closed explicitly, never dropped for the finalizer
// to find. This proves that under real GC pressure: two collections after
// dropping every reference to the temporary file, the original listener's
// descriptor is still open and the listener it belongs to still accepts.
func TestListenerSurvivesGCAfterFileListener(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	laddr := listenerAddr(t, l)

	var lnFd int
	var fln *Listener
	rc := mustListenerRawConn(t, l)
	if cerr := rc.Control(func(fd uintptr) {
		lnFd = int(fd)
		dup, derr := syscall.Dup(int(fd))
		if derr != nil {
			t.Errorf("dup: %v", derr)
			return
		}
		f := os.NewFile(uintptr(dup), "listener")
		defer func() { _ = f.Close() }()
		var err error
		fln, err = FileListener(f)
		if err != nil {
			t.Errorf("FileListener: %v", err)
		}
	}); cerr != nil {
		t.Fatalf("control: %v", cerr)
	}
	if fln == nil {
		t.Fatal("FileListener returned no listener")
	}
	t.Cleanup(func() { _ = fln.Close() })

	// Run finalizers for anything the block above dropped. Twice: the
	// first collection queues the finalizer, the second lets it run.
	runtime.GC()
	runtime.GC()

	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(lnFd), syscall.F_GETFD, 0); errno != 0 {
		t.Fatalf("listener descriptor %d was closed by a finalizer while the listener still owned it: %v", lnFd, errno)
	}

	// The listener must still be usable, not merely still hold a
	// descriptor: a dial that completes proves the socket is the one
	// still listening.
	conn, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, laddr)
	if err != nil {
		t.Fatalf("dial listener after GC: %v", err)
	}
	_ = conn.Close()
}

// mustListenerRawConn is l.SyscallConn that fails the test on an error.
func mustListenerRawConn(t testing.TB, l *Listener) syscall.RawConn {
	t.Helper()
	rc, err := l.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	return rc
}

// TestFileListenerDoesNotLeakDescriptors: FileListener owns its duplicate
// from the moment it exists, so every path through it must release it or
// hand it over: a failed duplication owns nothing, a listener closed after
// adoption leaves the count where it was, and the caller's own file keeps
// working after the adopted listener is closed.
func TestFileListenerDoesNotLeakDescriptors(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))

	t.Run("a closed file", func(t *testing.T) {
		bad := listenerFile(t, l)
		_ = bad.Close()
		before := openFds(t)
		for range 50 {
			got, err := FileListener(bad)
			if got != nil {
				_ = got.Close()
			}
			if !errors.Is(err, syscall.EBADF) {
				t.Fatalf("FileListener on a closed file = %v, want EBADF", err)
			}
		}
		if after := openFds(t); after != before {
			t.Errorf("descriptor count went %d -> %d over 50 failed adoptions", before, after)
		}
	})

	t.Run("create and close", func(t *testing.T) {
		f := listenerFile(t, l)
		for range 3 {
			a, err := FileListener(f)
			if err != nil {
				t.Fatalf("FileListener: %v", err)
			}
			_ = a.Close()
		}
		before := openFds(t)
		for range 50 {
			a, err := FileListener(f)
			if err != nil {
				t.Fatalf("FileListener: %v", err)
			}
			if err := a.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		}
		if after := openFds(t); after != before {
			t.Errorf("descriptor count went %d -> %d over 50 adoptions", before, after)
		}
	})

	t.Run("the caller keeps its file", func(t *testing.T) {
		f := listenerFile(t, l)
		a, err := FileListener(f)
		if err != nil {
			t.Fatalf("FileListener: %v", err)
		}
		if err := a.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, err := f.Stat(); err != nil {
			t.Errorf("the caller's file is unusable after the adopted listener was closed: %v", err)
		}
		if !fdIsOpen(fdOf(t, f)) {
			t.Error("the caller's descriptor was closed")
		}
	})
}
