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
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// readSysctl reads /proc/sys/net/sctp/name, skipping the test when it
// cannot.
func readSysctl(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile("/proc/sys/net/sctp/" + name)
	if err != nil {
		t.Skipf("cannot read net.sctp.%s: %v", name, err)
	}
	return strings.TrimSpace(string(b))
}

// --- Listener lifecycle ------------------------------------------------------

// TestListenErrorCarriesOperationAndAddress: a Control failure comes back
// as a *net.OpError with Op "listen", a nil Source and Addr laddr,
// wrapping the cause; the snapshot survives the caller changing laddr
// afterward (see netAddr, TestDialErrorCarriesOperationAndAddresses).
func TestListenErrorCarriesOperationAndAddress(t *testing.T) {
	cause := errors.New("control failed")
	laddr := loopback4(0)
	cfg := &Config{Control: func(string, string, syscall.RawConn) error { return cause }}

	ln, err := cfg.Listen("sctp4", laddr)
	if ln != nil {
		_ = ln.Close()
		t.Fatal("Listen returned a listener with a failing Control hook")
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "listen" || opErr.Net != "sctp4" || opErr.Source != nil {
		t.Fatalf("err = %#v, want a *net.OpError with Op listen, Net sctp4 and a nil Source", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("err = %v, want it to wrap %v", err, cause)
	}
	wantAddr := laddr.String()
	if got := opErr.Addr.String(); got != wantAddr {
		t.Fatalf("Addr = %q, want laddr %q", got, wantAddr)
	}

	laddr.Port = 1
	laddr.IPs[0] = netip.MustParseAddr("10.0.0.9")
	if got := opErr.Addr.String(); got != wantAddr {
		t.Errorf("Addr changed after caller mutation: got %q, want %q", got, wantAddr)
	}
}

// TestListenWrapsForeignOperationError: a Control hook that returns a
// *net.OpError from some other operation must not have that operation's
// Op and Net leak into the error Listen itself reports; the result is
// still Op "listen", Net "sctp4", with this call's own Addr, and
// errors.Is still reaches the foreign error's own root cause.
func TestListenWrapsForeignOperationError(t *testing.T) {
	root := errors.New("control failed")
	foreign := &net.OpError{Op: "control", Net: "tcp", Err: root}
	laddr := loopback4(0)
	cfg := &Config{Control: func(string, string, syscall.RawConn) error { return foreign }}

	_, err := cfg.Listen("sctp4", laddr)
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "listen" || opErr.Net != "sctp4" || opErr.Source != nil {
		t.Fatalf("err = %#v, want a *net.OpError with Op listen, Net sctp4 and a nil Source", err)
	}
	if got, want := opErr.Addr.String(), laddr.String(); got != want {
		t.Errorf("Addr = %q, want %q", got, want)
	}
	if !errors.Is(err, root) {
		t.Fatalf("err = %v, want it to reach the foreign error's own root cause %v", err, root)
	}
	if errors.Unwrap(opErr) != foreign {
		t.Errorf("opError's cause is %#v, want the foreign *net.OpError %#v itself", errors.Unwrap(opErr), foreign)
	}
}

// TestListenPreservesMatchingOperationError: a Control hook that returns
// a *net.OpError which already describes exactly this listen comes back
// unchanged, not wrapped a second time.
func TestListenPreservesMatchingOperationError(t *testing.T) {
	root := errors.New("control failed")
	laddr := loopback4(0)
	matching := &net.OpError{Op: "listen", Net: "sctp4", Addr: netAddr(laddr), Err: root}
	cfg := &Config{Control: func(string, string, syscall.RawConn) error { return matching }}

	_, err := cfg.Listen("sctp4", laddr)
	if err != matching {
		t.Errorf("err = %#v, want the matching *net.OpError %#v unchanged", err, matching)
	}
}

// TestSocketConfigListenControlWithoutLocalAddress: Control still runs,
// with an empty address string, when Listen is given a nil laddr; there
// is no wildcard *Addr to stringify before the bind that gives the socket
// its address.
func TestSocketConfigListenControlWithoutLocalAddress(t *testing.T) {
	var sawControl bool
	var controlNetwork, controlAddress string
	cfg := &Config{Control: func(network, address string, c syscall.RawConn) error {
		sawControl, controlNetwork, controlAddress = true, network, address
		return nil
	}}
	l, err := cfg.Listen("sctp4", nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if !sawControl {
		t.Error("Control never ran")
	}
	if controlNetwork != "sctp4" || controlAddress != "" {
		t.Errorf("Control(%q, %q), want (%q, %q)", controlNetwork, controlAddress, "sctp4", "")
	}
}

// TestListenDoesNotMutateItsAddr: the caller's *Addr survives Listen
// unchanged (v1 TestListenDoesNotMutateItsAddr). localBindAddrs
// (socket_linux.go) only ever reads laddr.IPs to build encodeAddrs' own
// destination buffer, so this cannot fail today, but a regression here
// would be exactly the kind of bug this test caught in v1: the bind path
// once appended the wildcard address into the caller's own slice, which
// is a data race whenever the address is shared between goroutines (the
// ordinary way to run a client and server against one fixed endpoint)
// and changes the address's own meaning for whoever reuses it afterward.
func TestListenDoesNotMutateItsAddr(t *testing.T) {
	// A wildcard laddr (no IPs) is the scenario that exercises the
	// vulnerable path: localBindAddrs' own wildcard branch, not the one
	// that packs the caller's own list.
	laddr := &Addr{}
	before := slices.Clone(laddr.IPs)

	l, err := Listen("sctp4", laddr)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	if !slices.Equal(laddr.IPs, before) {
		t.Errorf("Listen changed the caller's IPs: %v -> %v", before, laddr.IPs)
	}
}

// TestListenerDoubleCloseDoesNotCloseRecycledFd: a second Close must not
// close the descriptor number again, since by then the kernel may have
// handed it to an unrelated socket, which it would tear down silently.
func TestListenerDoubleCloseDoesNotCloseRecycledFd(t *testing.T) {
	l, err := Listen("sctp4", loopback4(0))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	victim, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer func() { _ = syscall.Close(victim) }()
	second := l.Close()
	if !fdIsOpen(victim) {
		t.Fatalf("second Close released descriptor %d, which belonged to an unrelated socket (it returned %v)", victim, second)
	}
	if !errors.Is(second, net.ErrClosed) {
		t.Errorf("second Close = %v, want net.ErrClosed", second)
	}
}

// TestListenerCloseIsIdempotent: every Close after the first keeps
// reporting net.ErrClosed.
func TestListenerCloseIsIdempotent(t *testing.T) {
	l, err := Listen("sctp4", loopback4(0))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	for i := range 5 {
		err := l.Close()
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Close #%d = %v, want net.ErrClosed", i+2, err)
		}
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr.Op != "close" {
			t.Fatalf("Close #%d = %#v, want a *net.OpError with Op close", i+2, err)
		}
	}
}

// TestListenerConcurrentClose: of several racing Close calls exactly one
// takes the descriptor.
func TestListenerConcurrentClose(t *testing.T) {
	for round := range 25 {
		l, err := Listen("sctp4", loopback4(0))
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		var ok atomic.Int32
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if l.Close() == nil {
					ok.Add(1)
				}
			}()
		}
		wg.Wait()
		if n := ok.Load(); n != 1 {
			t.Fatalf("round %d: %d callers reported success, want exactly 1", round, n)
		}
	}
}

// TestListenerCloseUnblocksAccept: an Accept waiting in the poller returns
// net.ErrClosed once the listener is closed.
func TestListenerCloseUnblocksAccept(t *testing.T) {
	l, err := Listen("sctp4", loopback4(0))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := l.AcceptSCTP()
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept = %v, want net.ErrClosed", err)
		}
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr.Op != "accept" {
			t.Errorf("Accept = %#v, want a *net.OpError with Op accept", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
}

// TestListenerAcceptAfterCloseFails: Accept on a closed listener reports
// it instead of touching a recycled descriptor.
func TestListenerAcceptAfterCloseFails(t *testing.T) {
	l, err := Listen("sctp4", loopback4(0))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	local := l.Addr()
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err = l.AcceptSCTP()
	if !errors.Is(err, net.ErrClosed) {
		t.Errorf("AcceptSCTP = %v, want net.ErrClosed", err)
	}
	// TestClosedListenerAcceptErrorRetainsListenerContext: the closed
	// listener's own address, not a nil one, since Addr stays readable
	// (below) and the error the caller sees should say which listener
	// this was.
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "accept" || opErr.Addr == nil || opErr.Addr.String() != local.String() {
		t.Errorf("AcceptSCTP = %#v, want a *net.OpError with Op accept and Addr %v", err, local)
	}
	if l.Addr() == nil {
		t.Error("Addr is nil after Close; the snapshot stays readable")
	}
}

// TestListenBacklogUsesKernelMaximum: a listener that never accepts takes
// more associations than syscall.SOMAXCONN (128) when the kernel allows
// more, since Listen asks for net.core.somaxconn.
func TestListenBacklogUsesKernelMaximum(t *testing.T) {
	want, err := readSomaxconn()
	if err != nil {
		t.Skipf("cannot read net.core.somaxconn: %v", err)
	}
	if want <= syscall.SOMAXCONN {
		t.Skipf("net.core.somaxconn is %d, not above syscall.SOMAXCONN (%d)", want, syscall.SOMAXCONN)
	}
	l := mustListen(t, nil, "sctp4", loopback4(0))
	raddr := listenerAddr(t, l)
	var conns []*Conn
	defer func() {
		for _, c := range conns {
			_ = c.Abort()
		}
	}()
	for i := range 200 {
		c, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, raddr)
		if err != nil {
			t.Fatalf("association %d of 200 refused: %v; the backlog is below the kernel's %d", i+1, err, want)
		}
		conns = append(conns, c)
	}
}

// TestReadSomaxconnMatchesProc: the helper reads a positive backlog.
func TestReadSomaxconnMatchesProc(t *testing.T) {
	n, err := readSomaxconn()
	if err != nil {
		t.Skipf("cannot read net.core.somaxconn: %v", err)
	}
	if n <= 0 {
		t.Errorf("readSomaxconn() = %d, want a positive backlog", n)
	}
}

// TestListenerAcceptDeadline: Accept honours the listener's deadline
// through the poller, and the listener works again once it is cleared.
func TestListenerAcceptDeadline(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	if err := l.SetDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	start := time.Now()
	_, err := l.AcceptSCTP()
	elapsed := time.Since(start)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("AcceptSCTP = %v, want os.ErrDeadlineExceeded", err)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Errorf("AcceptSCTP = %v, want a net.Error with Timeout() true", err)
	}
	// TestAcceptErrorCarriesListenerContext: the listener's own address is
	// the error's Addr, since Accept has no remote peer to name.
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "accept" || opErr.Source != nil || opErr.Addr == nil || opErr.Addr.String() != listenerAddr(t, l).String() {
		t.Errorf("AcceptSCTP = %#v, want a *net.OpError with Op accept, a nil Source and Addr %v", err, listenerAddr(t, l))
	}
	if elapsed < 250*time.Millisecond || elapsed > 10*time.Second {
		t.Errorf("Accept gave up after %v against a 300 ms deadline", elapsed)
	}
	if err := l.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing the deadline: %v", err)
	}
	dialAccept(t, nil, l)
}

// TestAcceptSurvivesSignals: Accept must retry accept4 itself when a
// signal interrupts it, rather than reporting EINTR as an accept failure
// (v1 TestAcceptSurvivesSignals; see signalStorm).
func TestAcceptSurvivesSignals(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	stop := signalStorm(t)
	defer stop()

	const peers = 20
	accepted := make(chan error, peers)
	go func() {
		for range peers {
			c, err := l.AcceptSCTP()
			if err != nil {
				accepted <- err
				return
			}
			_ = c.Close()
			accepted <- nil
		}
	}()

	raddr := listenerAddr(t, l)
	for i := range peers {
		// A gap between dials, so Accept is usually blocked in the
		// poller when a signal lands.
		time.Sleep(2 * time.Millisecond)
		c, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, raddr)
		if err != nil {
			t.Fatalf("peer %d dial: %v", i, err)
		}
		if err := <-accepted; err != nil {
			if errors.Is(err, syscall.EINTR) {
				t.Fatalf("accept %d returned EINTR: a signal during accept4 must be retried, not reported as a failure", i)
			}
			t.Fatalf("accept %d: %v", i, err)
		}
		_ = c.Close()
	}
}

// TestRawSocketTimeoutDoesNotBecomeListenerDeadline: SO_RCVTIMEO set
// through SyscallConn changes nothing, since the descriptor is non-blocking
// and every wait is the poller's.
func TestRawSocketTimeoutDoesNotBecomeListenerDeadline(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	rc, err := l.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var serr error
	rawFd(t, rc, func(fd int) {
		tv := syscall.NsecToTimeval(int64(300 * time.Millisecond))
		serr = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	})
	if serr != nil {
		t.Fatalf("SO_RCVTIMEO: %v", serr)
	}
	type result struct {
		c   *Conn
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, err := l.AcceptSCTP()
		done <- result{c, err}
	}()
	select {
	case r := <-done:
		if r.c != nil {
			_ = r.c.Abort()
		}
		t.Fatalf("AcceptSCTP returned after the raw socket timeout alone: %v", r.err)
	case <-time.After(500 * time.Millisecond):
	}
	client, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, listenerAddr(t, l))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = client.Abort() }()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("AcceptSCTP after a peer connected: %v", r.err)
		}
		_ = r.c.Abort()
	case <-time.After(5 * time.Second):
		t.Fatal("AcceptSCTP did not wake after a peer connected")
	}
}

// TestListenerDeadlineInThePast: an elapsed deadline fails at once.
func TestListenerDeadlineInThePast(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	if err := l.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	start := time.Now()
	if _, err := l.AcceptSCTP(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("AcceptSCTP = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("took %v; an elapsed deadline must not wait", elapsed)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := l.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("SetDeadline after Close = %v, want net.ErrClosed", err)
	}
}

// TestListenerSyscallConnReadWriteReturnEINVAL: a listener's RawConn
// supports Control only, as the standard library's listeners' do.
func TestListenerSyscallConnReadWriteReturnEINVAL(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	rc, err := l.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	fd := -1
	rawFd(t, rc, func(f int) { fd = f })
	if fd < 0 {
		t.Error("Control did not hand out the descriptor")
	}
	if err := rc.Read(func(uintptr) bool { return true }); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("Read = %v, want syscall.EINVAL", err)
	}
	if err := rc.Write(func(uintptr) bool { return true }); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("Write = %v, want syscall.EINVAL", err)
	}
}

// TestListenerRawConnAfterCloseDoesNotUseRecycledFD: a RawConn kept past
// Close reports net.ErrClosed without calling back with a descriptor
// number the kernel may have reused.
func TestListenerRawConnAfterCloseDoesNotUseRecycledFD(t *testing.T) {
	l, err := Listen("sctp4", loopback4(0))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	rc, err := l.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	called := false
	if err := rc.Control(func(uintptr) { called = true }); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Control after Close = %v, want net.ErrClosed", err)
	}
	if called {
		t.Error("Control ran its callback after the listener was closed")
	}
}

// TestSocketConfigRawConnReadWriteReturnEINVAL: the RawConn Config.Control
// receives supports Control only; the socket is neither connected nor
// listening yet.
func TestSocketConfigRawConnReadWriteReturnEINVAL(t *testing.T) {
	var sawControl bool
	var readErr, writeErr error
	cfg := &Config{Control: func(_, _ string, c syscall.RawConn) error {
		if err := c.Control(func(uintptr) { sawControl = true }); err != nil {
			return err
		}
		readErr = c.Read(func(uintptr) bool { return true })
		writeErr = c.Write(func(uintptr) bool { return true })
		return nil
	}}
	mustListen(t, cfg, "sctp4", loopback4(0))
	if !sawControl {
		t.Error("Control never ran")
	}
	if !errors.Is(readErr, syscall.EINVAL) || !errors.Is(writeErr, syscall.EINVAL) {
		t.Errorf("Read = %v, Write = %v; want syscall.EINVAL for both", readErr, writeErr)
	}
}

// --- associations that ended before Accept ---------------------------------

// waitAssocClosed polls /proc/net/sctp/assocs until no association on
// local port lport is in a state other than CLOSED (ST 0), so that an
// association the peer has ended is known to have ended here too before
// the test accepts it.
func waitAssocClosed(t testing.TB, lport uint16) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		f, err := os.Open("/proc/net/sctp/assocs")
		if err != nil {
			t.Skipf("cannot read /proc/net/sctp/assocs: %v", err)
		}
		live := false
		stCol, lportCol := -1, -1
		s := bufio.NewScanner(f)
		for s.Scan() {
			fields := strings.Fields(s.Text())
			if len(fields) > 0 && fields[0] == "ASSOC" {
				for i, name := range fields {
					switch name {
					case "ST":
						stCol = i
					case "LPORT":
						lportCol = i
					}
				}
				continue
			}
			if stCol < 0 || lportCol < 0 || len(fields) <= max(stCol, lportCol) {
				continue
			}
			if p, _ := strconv.Atoi(fields[lportCol]); p == int(lport) && fields[stCol] != "0" {
				live = true
			}
		}
		_ = f.Close()
		if !live {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("an association on port %d is still open 5 s after the peer ended it", lport)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestAcceptAfterPeerClosedWithData: a client sends one message and ends
// the association, gracefully or with an ABORT, before the server calls
// Accept. Linux keeps the ended association queued so that accept(2) can
// return it, as a closed socket (net/sctp/sm_sideeffect.c:
// sctp_cmd_delete_tcb; net/sctp/socket.c: sctp_sock_migrate), and Accept
// returns it rather than dropping the peer's data: with AssocID 0, address
// snapshots that hold no IPs, and live address queries that fail. The
// message is still queued on it, and after a graceful end the stream then
// ends.
func TestAcceptAfterPeerClosedWithData(t *testing.T) {
	for _, abort := range []bool{false, true} {
		name := "graceful"
		if abort {
			name = "abort"
		}
		t.Run(name, func(t *testing.T) {
			l := mustListen(t, nil, "sctp4", loopback4(0))
			laddr := listenerAddr(t, l)
			client, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, laddr)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			msg := []byte("sent before accept")
			if err := sendRaw(client, msg); err != nil {
				t.Fatalf("send: %v", err)
			}
			if abort {
				// The send put the message on the wire at once (nothing was
				// outstanding), ahead of the ABORT, and loopback keeps the
				// order; the server queued it as it arrived, and the ABORT
				// does not take a queued message back.
				err = client.Abort()
			} else {
				err = client.Close()
			}
			if err != nil {
				t.Fatalf("client end: %v", err)
			}
			waitAssocClosed(t, laddr.Port)

			server, err := l.AcceptSCTP()
			if err != nil {
				t.Fatalf("AcceptSCTP of an association that ended first: %v", err)
			}
			t.Cleanup(func() { _ = server.Abort() })
			if id := server.AssocID(); id != 0 {
				t.Errorf("AssocID = %d, want 0 for an association that ended before Accept", id)
			}
			for what, a := range map[string]net.Addr{"LocalAddr": server.LocalAddr(), "RemoteAddr": server.RemoteAddr()} {
				ad, ok := a.(*Addr)
				if !ok || ad == nil {
					t.Errorf("%s = %#v, want a non-nil *Addr", what, a)
					continue
				}
				if len(ad.IPs) != 0 {
					t.Errorf("%s IPs = %v, want none: Linux no longer knows them", what, ad.IPs)
				}
			}
			if _, err := server.LocalAddrs(); !errors.Is(err, syscall.EINVAL) {
				t.Errorf("LocalAddrs = %v, want an error matching EINVAL", err)
			}
			if _, err := server.PeerAddrs(); !errors.Is(err, syscall.EINVAL) {
				t.Errorf("PeerAddrs = %v, want an error matching EINVAL", err)
			}

			if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			buf := make([]byte, 64)
			n, err := server.Read(buf)
			if err != nil || string(buf[:n]) != string(msg) {
				t.Fatalf("the queued message: read %q, %v; want %q", buf[:n], err, msg)
			}
			if !abort {
				if _, err := server.Read(buf); err != io.EOF {
					t.Errorf("read after the message = %v, want io.EOF", err)
				}
			}
			// Linux handed the socket over closed, and answers shutdown(2)
			// on a closed socket with ENOTCONN (net/ipv4/af_inet.c:
			// inet_shutdown).
			if err := server.Shutdown(); !errors.Is(err, syscall.ENOTCONN) {
				t.Errorf("Shutdown = %v, want an error matching ENOTCONN", err)
			} else if opErr, ok := err.(*net.OpError); !ok || opErr.Op != "close" {
				t.Errorf("Shutdown's error = %#v, want a *net.OpError with Op close", err)
			}
			start := time.Now()
			if err := server.Close(); err != nil {
				t.Errorf("Close = %v, want nil", err)
			}
			if d := time.Since(start); d > time.Second {
				t.Errorf("Close took %v on a connection whose association was already gone", d)
			}
		})
	}
}

// --- Config application ------------------------------------------------------

// TestConfigInheritance: an accepted connection inherits the listener's
// Config. The kernel-side settings are copied into the accepted socket by
// the kernel (net/sctp/socket.c: sctp_sock_migrate, and the association's
// own copies in net/sctp/associola.c: sctp_association_init) and are read
// back here with getsockopt; the package-side ones, the handler, the
// grace period of Close and the caller's subscriptions, come from the
// listener's Config.
func TestConfigInheritance(t *testing.T) {
	const rbuf, wbuf = 100000, 90000
	var handled atomic.Int32
	cfg := &Config{
		ReadBuffer:          new(rbuf),
		WriteBuffer:         new(wbuf),
		NoDelay:             new(true),
		DefaultSndInfo:      &SndInfo{Stream: 1, PPID: 46, Context: 7, Flags: SendUnordered},
		DefaultPrInfo:       &PrInfo{Policy: PRTTL, TTL: time.Second},
		Notifications:       []EventType{EventSendFailed, EventShutdown},
		NotificationHandler: func(Notification) error { handled.Add(1); return nil },
		CloseTimeout:        1234 * time.Millisecond,
	}
	l := mustListen(t, cfg, "sctp4", loopback4(0))
	_, server := dialAccept(t, nil, l)
	rc := mustSyscallConn(t, server)

	capped := func(v int, sysctl string) int {
		b, err := os.ReadFile("/proc/sys/net/core/" + sysctl)
		if err != nil {
			return 2 * v
		}
		if m, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && m < v {
			return 2 * m
		}
		return 2 * v
	}
	if got, want := getIntOpt(t, rc, syscall.SOL_SOCKET, syscall.SO_RCVBUF), capped(rbuf, "rmem_max"); got != want {
		t.Errorf("SO_RCVBUF = %d, want %d (Linux doubles the value set)", got, want)
	}
	if got, want := getIntOpt(t, rc, syscall.SOL_SOCKET, syscall.SO_SNDBUF), capped(wbuf, "wmem_max"); got != want {
		t.Errorf("SO_SNDBUF = %d, want %d", got, want)
	}
	if got := getIntOpt(t, rc, ipprotoSCTP, optNoDelay); got != 1 {
		t.Errorf("SCTP_NODELAY = %d, want 1", got)
	}

	var snd [sizeSndInfo]byte
	getRawOpt(t, rc, optDefaultSndInfo, snd[:])
	if stream := binary.NativeEndian.Uint16(snd[sndInfoStreamOff:]); stream != 1 {
		t.Errorf("default stream = %d, want 1", stream)
	}
	if ppid := binary.BigEndian.Uint32(snd[sndInfoPPIDOff:]); ppid != 46 {
		t.Errorf("default PPID = %d, want 46 (the kernel keeps it in network order)", ppid)
	}
	if ctx := binary.NativeEndian.Uint32(snd[sndInfoContextOff:]); ctx != 7 {
		t.Errorf("default context = %d, want 7", ctx)
	}
	if flags := binary.NativeEndian.Uint16(snd[sndInfoFlagsOff:]) &^ prPolicyMask; flags != uint16(SendUnordered) {
		t.Errorf("default flags = %#x, want SendUnordered", flags)
	}
	var pr [sizeDefaultPRInfo]byte
	getRawOpt(t, rc, optDefaultPRInfo, pr[:])
	if policy, value := binary.NativeEndian.Uint16(pr[defaultPRInfoPolicyOff:]), binary.NativeEndian.Uint32(pr[defaultPRInfoValueOff:]); policy != uint16(PRTTL) || value != 1000 {
		t.Errorf("default PR = policy %#x value %d, want PRTTL and 1000 ms", policy, value)
	}

	for _, typ := range []EventType{EventSendFailed, EventShutdown, EventAssocChange} {
		if !subscribedInKernel(t, rc, typ) {
			t.Errorf("%v is not subscribed on the accepted socket", typ)
		}
	}
	if subscribedInKernel(t, rc, EventPeerAddrChange) {
		t.Error("EventPeerAddrChange is subscribed on the accepted socket, though the Config did not ask for it")
	}

	if got, want := eventSet(server.subs.Load()), eventBit(EventSendFailed)|eventBit(EventShutdown); got != want {
		t.Errorf("logical subscriptions = %#x, want %#x", got, want)
	}
	if server.closeWait != cfg.CloseTimeout {
		t.Errorf("grace period = %v, want the listener Config's %v", server.closeWait, cfg.CloseTimeout)
	}
	if server.handler == nil {
		t.Fatal("the accepted connection has no NotificationHandler")
	}
	_ = server.handler(nil)
	if handled.Load() != 1 {
		t.Error("the accepted connection's handler is not the listener Config's")
	}
}

// TestMessageInterleavingNeedsSysctl: MessageInterleaving is refused by
// Linux with EPERM unless net.sctp.intl_enable is on
// (net/sctp/socket.c: sctp_setsockopt_interleaving_supported). The test
// reads the sysctl and asserts the outcome that matches it.
func TestMessageInterleavingNeedsSysctl(t *testing.T) {
	enabled := readSysctl(t, "intl_enable") == "1"
	cfg := &Config{MessageInterleaving: true, FragmentInterleave: new(InterleaveAssocs)}
	l, err := cfg.Listen("sctp4", loopback4(0))
	if !enabled {
		if l != nil {
			_ = l.Close()
		}
		if !errors.Is(err, syscall.EPERM) {
			t.Fatalf("with net.sctp.intl_enable=0 Listen = %v, want an error matching EPERM", err)
		}
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr.Op != "listen" || !strings.Contains(err.Error(), "Config.MessageInterleaving") {
			t.Fatalf("Listen = %#v, want a *net.OpError with Op listen naming Config.MessageInterleaving", err)
		}
		return
	}
	if err != nil {
		t.Fatalf("with net.sctp.intl_enable=1 Listen = %v, want success", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	rc, err := l.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if v := getAssocValueOpt(t, rc, optInterleavingSupported, 0); v != 1 {
		t.Errorf("SCTP_INTERLEAVING_SUPPORTED = %d, want 1", v)
	}
}

// TestAuthHelpersWithSysctlOff: InstallAuthKey and ActivateAuthKey inside
// Config.Control succeed whatever net.sctp.auth_enable says, because they
// switch AUTH on for the socket first (lksctp-tools #69: Linux refuses key
// operations with EACCES while AUTH is off). A later
// Config.Authentication=false switches it off again, as Config documents.
func TestAuthHelpersWithSysctlOff(t *testing.T) {
	secret := []byte("0123456789abcdef")
	helpers := func(_, _ string, c syscall.RawConn) error {
		if err := InstallAuthKey(c, 7, secret); err != nil {
			return err
		}
		return ActivateAuthKey(c, 7)
	}

	l := mustListen(t, &Config{Control: helpers}, "sctp4", loopback4(0))
	rc, err := l.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if v := getAssocValueOpt(t, rc, optAuthSupported, 0); v != 1 {
		t.Errorf("SCTP_AUTH_SUPPORTED = %d after the helpers, want 1", v)
	}
	var key [sizeAuthKeyID]byte
	getRawOpt(t, rc, optAuthActiveKey, key[:])
	if got := binary.NativeEndian.Uint16(key[authKeyIDKeyNumberOff:]); got != 7 {
		t.Errorf("active key = %d, want 7", got)
	}

	off := mustListen(t, &Config{Control: helpers, Authentication: new(false)}, "sctp4", loopback4(0))
	rc, err = off.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if v := getAssocValueOpt(t, rc, optAuthSupported, 0); v != 0 {
		t.Errorf("SCTP_AUTH_SUPPORTED = %d with Config.Authentication=false, want 0", v)
	}

	// The keys carry into an association.
	client, server := dialAccept(t, &Config{Control: helpers}, l)
	if v := getAssocValueOpt(t, mustSyscallConn(t, server), optAuthSupported, server.AssocID()); v != 1 {
		t.Errorf("AUTH negotiated = %d on the association, want 1", v)
	}
	_ = client
}

// TestAuthHelpersRefuseBadArguments: the key helpers refuse what they can
// before any system call, with errors matching EINVAL.
func TestAuthHelpersRefuseBadArguments(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	rc, err := l.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	for name, err := range map[string]error{
		"InstallAuthKey nil RawConn":  InstallAuthKey(nil, 1, []byte("k")),
		"ActivateAuthKey nil RawConn": ActivateAuthKey(nil, 1),
		"empty secret":                InstallAuthKey(rc, 1, nil),
		"secret over 65535 bytes":     InstallAuthKey(rc, 1, make([]byte, 65536)),
	} {
		if !errors.Is(err, syscall.EINVAL) {
			t.Errorf("%s = %v, want EINVAL", name, err)
		}
	}
}

// TestConfigListenerReadback: every typed setting of a Config reaches the
// listening socket, after, and so winning over, what Control wrote.
func TestConfigListenerReadback(t *testing.T) {
	const adaptation = 0x10203040
	var controlCalled atomic.Bool
	cfg := &Config{
		InitMsg: InitMsg{OutStreams: 11, MaxInStreams: 13, MaxAttempts: 3},
		Control: func(_, _ string, c syscall.RawConn) error {
			controlCalled.Store(true)
			var cerr error
			if err := c.Control(func(fd uintptr) {
				// Values the typed settings below must override.
				for _, e := range []error{
					setIntOpt(int(fd), ipprotoSCTP, optDisableFragments, 0),
					setIntOpt(int(fd), ipprotoSCTP, optFragmentInterleave, 0),
					applyOp(int(fd), &configOp{kind: opRTOInfo, initialMS: 1000, maxMS: 60000, minMS: 1000}),
					applyOp(int(fd), &configOp{kind: opAdaptationLayer, u32: 0xdeadbeef}),
				} {
					if e != nil && cerr == nil {
						cerr = e
					}
				}
			}); err != nil {
				return err
			}
			return cerr
		},
		PartialReliability:            new(false),
		StreamReconfiguration:         new(true),
		DynamicAddressReconfiguration: new(true),
		Authentication:                new(true),
		ExperimentalECN:               new(false),
		ReusePort:                     new(true),
		FragmentsDisabled:             new(true),
		ReceiveNxtInfo:                new(true),
		AdaptationLayer:               new(uint32(adaptation)),
		FragmentInterleave:            new(InterleaveAssocs),
		StreamResetMask:               new(EnableResetStreamReq | EnableChangeAssocReq),
		RTOInfo:                       &RTOInfo{Initial: 500 * time.Millisecond, Max: 2 * time.Second, Min: 200 * time.Millisecond},
		DelayedSACK:                   &DelayedSACK{Delay: 250 * time.Millisecond, Frequency: 4},
		HMACIdentifiers:               []HMACID{HMACSHA256, HMACSHA1},
		AuthChunks:                    []uint8{0}, // DATA, RFC 9260 §3.3.1
		Notifications:                 []EventType{EventAssocChange},
	}
	l := mustListen(t, cfg, "sctp4", loopback4(0))
	if !controlCalled.Load() {
		t.Fatal("Control was not called")
	}
	rc, err := l.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}

	var init [sizeInitMsg]byte
	getRawOpt(t, rc, optInitMsg, init[:])
	if o, i, a := binary.NativeEndian.Uint16(init[initMsgOutStreamsOff:]), binary.NativeEndian.Uint16(init[initMsgMaxInStreamsOff:]), binary.NativeEndian.Uint16(init[initMsgMaxAttemptsOff:]); o != 11 || i != 13 || a != 3 {
		t.Errorf("InitMsg = %d/%d/%d, want 11/13/3", o, i, a)
	}
	for _, c := range []struct {
		name  string
		level int
		opt   int
		want  int
	}{
		{"FragmentInterleave", ipprotoSCTP, optFragmentInterleave, 1},
		{"FragmentsDisabled", ipprotoSCTP, optDisableFragments, 1},
		{"ReusePort", ipprotoSCTP, optReusePort, 1},
		{"SCTP_RECVRCVINFO", ipprotoSCTP, optRecvRcvInfo, 1},
		{"ReceiveNxtInfo", ipprotoSCTP, optRecvNxtInfo, 1},
	} {
		if got := getIntOpt(t, rc, c.level, c.opt); got != c.want {
			t.Errorf("%s = %d, want %d", c.name, got, c.want)
		}
	}
	for _, c := range []struct {
		name string
		opt  int
		want uint32
	}{
		{"Authentication", optAuthSupported, 1},
		{"DynamicAddressReconfiguration", optASCONFSupported, 1},
		{"PartialReliability", optPRSupported, 0},
		{"StreamReconfiguration", optReconfigSupported, 1},
		{"StreamResetMask", optEnableStreamReset, uint32(EnableResetStreamReq | EnableChangeAssocReq)},
		{"ExperimentalECN", optECNSupported, 0},
	} {
		if got := getAssocValueOpt(t, rc, c.opt, 0); got != c.want {
			t.Errorf("%s = %d, want %d", c.name, got, c.want)
		}
	}
	var adapt [sizeSetAdaptation]byte
	getRawOpt(t, rc, optAdaptationLayer, adapt[:])
	if got := binary.NativeEndian.Uint32(adapt[:]); got != adaptation {
		t.Errorf("AdaptationLayer = %#x, want %#x", got, adaptation)
	}
	var rto [sizeRTOInfo]byte
	getRawOpt(t, rc, optRTOInfo, rto[:])
	if i, mx, mn := binary.NativeEndian.Uint32(rto[rtoInfoInitialOff:]), binary.NativeEndian.Uint32(rto[rtoInfoMaxOff:]), binary.NativeEndian.Uint32(rto[rtoInfoMinOff:]); i != 500 || mx != 2000 || mn != 200 {
		t.Errorf("RTOInfo = %d/%d/%d ms, want 500/2000/200", i, mx, mn)
	}
	var sack [sizeDelayedSACK]byte
	getRawOpt(t, rc, optDelayedAckTime, sack[:])
	if d, f := binary.NativeEndian.Uint32(sack[delayedSACKDelayOff:]), binary.NativeEndian.Uint32(sack[delayedSACKFrequencyOff:]); d != 250 || f != 4 {
		t.Errorf("DelayedSACK = %d ms/%d, want 250/4", d, f)
	}
	hmac := make([]byte, sizeHMACAlgo+2*8)
	getRawOpt(t, rc, optHMACIdent, hmac)
	if n := binary.NativeEndian.Uint32(hmac[hmacAlgoNumIdentsOff:]); n != 2 ||
		binary.NativeEndian.Uint16(hmac[hmacAlgoIdentsOff:]) != uint16(HMACSHA256) ||
		binary.NativeEndian.Uint16(hmac[hmacAlgoIdentsOff+2:]) != uint16(HMACSHA1) {
		t.Errorf("HMACIdentifiers = %x, want [SHA-256 SHA-1]", hmac)
	}
	if chunks := authChunksOf(t, rc, optLocalAuthChunks, 0); !slices.Contains(chunks, 0) {
		t.Errorf("local AUTH chunks = %v, want DATA (0) among them", chunks)
	}
	if !subscribedInKernel(t, rc, EventAssocChange) || subscribedInKernel(t, rc, EventSenderDry) {
		t.Error("subscriptions are not the Config's: want EventAssocChange on and EventSenderDry off")
	}
}

// authChunksOf reads SCTP_LOCAL_AUTH_CHUNKS or SCTP_PEER_AUTH_CHUNKS for
// assoc (struct sctp_authchunks).
func authChunksOf(t testing.TB, rc syscall.RawConn, opt int, assoc AssocID) []uint8 {
	t.Helper()
	b := make([]byte, sizeAuthChunks+64)
	binary.NativeEndian.PutUint32(b[authChunksAssocIDOff:], uint32(assoc))
	getRawOpt(t, rc, opt, b)
	n := int(binary.NativeEndian.Uint32(b[authChunksNumChunksOff:]))
	if n > len(b)-sizeAuthChunks {
		t.Fatalf("AUTH chunk list claims %d entries", n)
	}
	return append([]uint8(nil), b[authChunksChunksOff:authChunksChunksOff+n]...)
}

// TestConfigRTOInfoOnDial: Config.RTOInfo reaches a dialed association
// under either AbandonPolicy.
func TestConfigRTOInfoOnDial(t *testing.T) {
	for _, policy := range []AbandonPolicy{AbandonAbort, AbandonQuiet} {
		t.Run(policy.String(), func(t *testing.T) {
			cfg := &Config{
				AbandonPolicy: policy,
				RTOInfo:       &RTOInfo{Initial: 500 * time.Millisecond, Max: 2 * time.Second, Min: 200 * time.Millisecond},
			}
			client, _ := connPair(t, cfg, nil)
			var rto [sizeRTOInfo]byte
			binary.NativeEndian.PutUint32(rto[rtoInfoAssocIDOff:], uint32(client.AssocID()))
			getRawOpt(t, mustSyscallConn(t, client), optRTOInfo, rto[:])
			if i, mx, mn := binary.NativeEndian.Uint32(rto[rtoInfoInitialOff:]), binary.NativeEndian.Uint32(rto[rtoInfoMaxOff:]), binary.NativeEndian.Uint32(rto[rtoInfoMinOff:]); i != 500 || mx != 2000 || mn != 200 {
				t.Errorf("client RTOInfo = %d/%d/%d ms, want 500/2000/200", i, mx, mn)
			}
		})
	}
}

// TestConfigNegotiatesOnDial: the extensions a Config offers are
// negotiated on both ends of a dialed association, and the association
// carries the chunk lists, stream reset mask and delayed SACK settings.
// Message interleaving is included when net.sctp.intl_enable allows it.
func TestConfigNegotiatesOnDial(t *testing.T) {
	intl := readSysctl(t, "intl_enable") == "1"
	cfg := func(init InitMsg) *Config {
		return &Config{
			InitMsg:               init,
			PartialReliability:    new(true),
			StreamReconfiguration: new(true),
			Authentication:        new(true),
			MessageInterleaving:   intl,
			AuthChunks:            []uint8{4, 5}, // HEARTBEAT and HEARTBEAT ACK
			FragmentInterleave:    new(InterleaveAssocs),
			StreamResetMask:       new(EnableResetStreamReq),
			DelayedSACK:           &DelayedSACK{Delay: 137 * time.Millisecond, Frequency: 2},
		}
	}
	client, server := connPair(t, cfg(InitMsg{OutStreams: 9, MaxInStreams: 10}), cfg(InitMsg{}))
	for side, c := range map[string]*Conn{"client": client, "server": server} {
		rc := mustSyscallConn(t, c)
		id := c.AssocID()
		for name, opt := range map[string]int{"PR-SCTP": optPRSupported, "stream reconfiguration": optReconfigSupported, "AUTH": optAuthSupported} {
			if v := getAssocValueOpt(t, rc, opt, id); v != 1 {
				t.Errorf("%s: %s negotiated = %d, want 1", side, name, v)
			}
		}
		if intl {
			if v := getAssocValueOpt(t, rc, optInterleavingSupported, id); v != 1 {
				t.Errorf("%s: I-DATA negotiated = %d, want 1", side, v)
			}
		}
		for name, opt := range map[string]int{"local": optLocalAuthChunks, "peer": optPeerAuthChunks} {
			if got := authChunksOf(t, rc, opt, id); !slices.Equal(got, []uint8{4, 5}) {
				t.Errorf("%s: %s AUTH chunks = %v, want exactly [4 5]", side, name, got)
			}
		}
		if v := getAssocValueOpt(t, rc, optEnableStreamReset, id); v != uint32(EnableResetStreamReq) {
			t.Errorf("%s: stream reset mask = %#x, want %#x", side, v, EnableResetStreamReq)
		}
		var sack [sizeDelayedSACK]byte
		binary.NativeEndian.PutUint32(sack[delayedSACKAssocIDOff:], uint32(id))
		getRawOpt(t, rc, optDelayedAckTime, sack[:])
		if d, f := binary.NativeEndian.Uint32(sack[delayedSACKDelayOff:]), binary.NativeEndian.Uint32(sack[delayedSACKFrequencyOff:]); d != 137 || f != 2 {
			t.Errorf("%s: delayed SACK = %d ms/%d, want 137/2", side, d, f)
		}
	}
	var init [sizeInitMsg]byte
	getRawOpt(t, mustSyscallConn(t, client), optInitMsg, init[:])
	if o, i := binary.NativeEndian.Uint16(init[initMsgOutStreamsOff:]), binary.NativeEndian.Uint16(init[initMsgMaxInStreamsOff:]); o != 9 || i != 10 {
		t.Errorf("client InitMsg = %d/%d, want 9/10", o, i)
	}
}

// TestConfigValidationPrecedesSocketAndControl: a Config refused by
// validation opens no socket and never runs Control.
func TestConfigValidationPrecedesSocketAndControl(t *testing.T) {
	before := openFds(t)
	var controlCalls atomic.Int32
	cfg := &Config{
		Control:     func(string, string, syscall.RawConn) error { controlCalls.Add(1); return nil },
		DelayedSACK: &DelayedSACK{Delay: 501 * time.Millisecond, Frequency: 2},
	}
	for name, call := range map[string]func() error{
		"Listen":         func() error { _, err := cfg.Listen("sctp4", loopback4(0)); return err },
		"Dial":           func() error { _, err := cfg.Dial(context.Background(), "sctp4", nil, loopback4(9)); return err },
		"ListenEndpoint": func() error { _, err := cfg.ListenEndpoint("sctp4", loopback4(0)); return err },
		"OpenEndpoint":   func() error { _, err := cfg.OpenEndpoint("sctp4", loopback4(0)); return err },
	} {
		if err := call(); err == nil || !strings.Contains(err.Error(), "500 ms maximum") || !errors.Is(err, syscall.EINVAL) {
			t.Errorf("%s = %v, want the delayed-SACK maximum refusal matching EINVAL", name, err)
		}
	}
	if n := controlCalls.Load(); n != 0 {
		t.Errorf("Control ran %d times for Configs refused before any socket exists", n)
	}
	if after := openFds(t); after != before {
		t.Errorf("descriptor count went %d -> %d", before, after)
	}
}

// TestConfigLevelTwoFailsClosedOnOneToOne: FragmentInterleave
// InterleaveStreams, which Linux cannot deliver, is refused with
// ErrUnsupported rather than quietly given level 1.
func TestConfigLevelTwoFailsClosedOnOneToOne(t *testing.T) {
	l, err := (&Config{FragmentInterleave: new(InterleaveStreams)}).Listen("sctp4", loopback4(0))
	if l != nil {
		_ = l.Close()
	}
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("Listen with InterleaveStreams = %v, want errors.ErrUnsupported", err)
	}
}

// --- BindAdd and BindRemove --------------------------------------------------

// TestRemovesEveryLocalAddress pins the check behind BindRemove's refusal
// to remove every address (RFC 6458 §9.1).
func TestRemovesEveryLocalAddress(t *testing.T) {
	a := func(s ...string) []netip.Addr { return addrOf(0, s...).IPs }
	bound := a("127.0.0.1", "127.0.0.2")
	for _, tc := range []struct {
		name   string
		bound  []netip.Addr
		remove []netip.Addr
		want   bool
	}{
		{"one remains", bound, a("127.0.0.2"), false},
		{"same set", bound, a("127.0.0.2", "127.0.0.1"), true},
		{"superset", bound, a("127.0.0.3", "127.0.0.1", "127.0.0.2"), true},
		{"unspecified IPv4", bound, a("0.0.0.0"), true},
		{"unspecified IPv6", bound, a("::"), true},
		{"nothing bound", nil, a("127.0.0.1"), false},
		{"IPv4-mapped spelling", a("127.0.0.1"), a("::ffff:127.0.0.1"), true},
		{"zones stay distinct", a("fe80::1%1"), a("fe80::1%2"), false},
		{"same zone", a("fe80::1%1"), a("fe80::1%1"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := removesEveryAddress(tc.bound, tc.remove); got != tc.want {
				t.Errorf("removesEveryAddress(%v, %v) = %v, want %v", tc.bound, tc.remove, got, tc.want)
			}
		})
	}
}

// FuzzBindxAddrs: whatever address a caller passes, bindxAddrs either
// refuses it with an error matching EINVAL or packs whole sockaddr entries
// with port 0, and never panics; removesEveryAddress accepts anything it
// may then be compared with.
func FuzzBindxAddrs(f *testing.F) {
	f.Add([]byte{127, 0, 0, 2}, false, false)
	f.Add(netip.MustParseAddr("::1").AsSlice(), true, true)
	f.Add([]byte{1, 2, 3}, true, false)
	f.Fuzz(func(t *testing.T, raw []byte, v6 bool, zoned bool) {
		ip, ok := netip.AddrFromSlice(raw)
		if zoned && ok && ip.Is6() {
			ip = ip.WithZone("1")
		}
		family := afInet
		if v6 {
			family = afInet6
		}
		buf, err := bindxAddrs(family, "BindAdd", []netip.Addr{ip})
		if err != nil {
			if !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("bindxAddrs(%v) = %v, want a refusal matching EINVAL", ip, err)
			}
			return
		}
		size, _ := sockaddrSize(family)
		if len(buf) != size {
			t.Fatalf("bindxAddrs packed %d bytes for one address, want %d", len(buf), size)
		}
		if port := binary.BigEndian.Uint16(buf[sockaddrInPortOff:]); port != 0 {
			t.Fatalf("packed port %d, want 0 (the bound port)", port)
		}
		_ = removesEveryAddress([]netip.Addr{ip}, []netip.Addr{ip})
	})
}

// TestListenerBindAddRemoveRefreshesAddr: BindAdd and BindRemove change
// the listening endpoint and refresh the Addr snapshot as a whole; a
// snapshot a caller holds is never modified; refusals leave the set alone;
// and removing the last address is refused with EINVAL (RFC 6458 §9.1).
func TestListenerBindAddRemoveRefreshesAddr(t *testing.T) {
	avail := requireLoopbacks(t, 2)
	base, extra := avail[0], avail[1]
	l := mustListen(t, nil, "sctp4", addrOf(0, base))
	initial := listenerAddr(t, l)
	wantSet := func(want ...string) {
		t.Helper()
		got := listenerAddr(t, l)
		if got.Port != initial.Port || !equalStrings(ipStrings(got), sortedCopy(want)) {
			t.Errorf("Addr = %v, want %v on port %d", got, want, initial.Port)
		}
	}

	if err := l.BindAdd(netip.MustParseAddr(extra)); err != nil {
		t.Fatalf("BindAdd(%s): %v", extra, err)
	}
	wantSet(base, extra)
	held := listenerAddr(t, l)
	heldCopy := held.String()

	if err := l.BindRemove(netip.MustParseAddr(extra)); err != nil {
		t.Fatalf("BindRemove(%s): %v", extra, err)
	}
	wantSet(base)
	if held.String() != heldCopy {
		t.Errorf("a snapshot the caller held changed from %s to %s", heldCopy, held)
	}

	if err := l.BindRemove(netip.MustParseAddr(base)); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("removing the last address = %v, want EINVAL", err)
	} else {
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr.Op != "bindx" {
			t.Errorf("refusal = %#v, want a *net.OpError with Op bindx", err)
		}
	}
	if err := l.BindAdd(netip.MustParseAddr("::1")); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("BindAdd of an IPv6 address on an AF_INET listener = %v, want EINVAL", err)
	}
	wantSet(base)

	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := l.BindAdd(netip.MustParseAddr(extra)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("BindAdd after Close = %v, want net.ErrClosed", err)
	}
}

// TestConcurrentListenerBindAddKeepsCacheInSync: concurrent BindAdd calls
// leave the snapshot equal to the kernel's list; an older refresh never
// overwrites a newer one.
func TestConcurrentListenerBindAddKeepsCacheInSync(t *testing.T) {
	avail := requireLoopbacks(t, 3)
	l := mustListen(t, nil, "sctp4", addrOf(0, avail[0]))
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, a := range avail[1:3] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- l.BindAdd(netip.MustParseAddr(a))
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent BindAdd: %v", err)
		}
	}
	cached := listenerAddr(t, l)
	kernel, err := l.sock.getAddrs(optGetLocalAddrs, 0)
	if err != nil {
		t.Fatalf("SCTP_GET_LOCAL_ADDRS: %v", err)
	}
	if got, want := ipStrings(cached), ipStrings(kernel); !equalStrings(got, want) || len(got) != 3 {
		t.Errorf("snapshot %v, kernel %v; want the same three addresses", got, want)
	}
}

// TestConnectedBindAddRemoveUpdatesPeerAddressReadback: on an association
// with ASCONF (RFC 5061) negotiated, BindAdd adds the address to the
// association, which the LocalAddr snapshot shows at once and the peer's
// PeerAddrs once the ASCONF is acknowledged; BindRemove takes it away the
// same way.
func TestConnectedBindAddRemoveUpdatesPeerAddressReadback(t *testing.T) {
	avail := requireLoopbacks(t, 3)
	clientBase, added, serverBase := avail[0], avail[1], avail[2]
	cfg := &Config{Authentication: new(true), DynamicAddressReconfiguration: new(true)}
	l := mustListen(t, cfg, "sctp4", addrOf(0, serverBase))

	type result struct {
		c   *Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := l.AcceptSCTP()
		ch <- result{c, err}
	}()
	client, err := cfg.Dial(testContext(t, 10*time.Second), "sctp4", addrOf(0, clientBase), listenerAddr(t, l))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Abort() })
	r := <-ch
	if r.err != nil {
		t.Fatalf("AcceptSCTP: %v", r.err)
	}
	server := r.c
	t.Cleanup(func() { _ = server.Abort() })
	if v := getAssocValueOpt(t, mustSyscallConn(t, client), optASCONFSupported, client.AssocID()); v != 1 {
		t.Skip("ASCONF was not negotiated despite the Config")
	}

	if err := client.BindAdd(netip.MustParseAddr(added)); err != nil {
		t.Fatalf("BindAdd(%s): %v", added, err)
	}
	local := client.LocalAddr().(*Addr)
	if got := ipStrings(local); !equalStrings(got, sortedCopy([]string{clientBase, added})) {
		t.Errorf("client LocalAddr after BindAdd = %v, want [%s %s]", got, clientBase, added)
	}
	waitForPeerAddresses(t, server, clientBase, added)

	if err := client.BindRemove(netip.MustParseAddr(added)); err != nil {
		t.Fatalf("BindRemove(%s): %v", added, err)
	}
	if got := ipStrings(client.LocalAddr().(*Addr)); !equalStrings(got, []string{clientBase}) {
		t.Errorf("client LocalAddr after BindRemove = %v, want [%s]", got, clientBase)
	}
	waitForPeerAddresses(t, server, clientBase)
	if got := ipStrings(local); !equalStrings(got, sortedCopy([]string{clientBase, added})) {
		t.Errorf("a LocalAddr snapshot the caller held changed to %v", got)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := client.BindRemove(netip.MustParseAddr(clientBase)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("BindRemove after Close = %v, want net.ErrClosed", err)
	}
}

// waitForPeerAddresses polls c.PeerAddrs until it lists want.
func waitForPeerAddresses(t testing.TB, c *Conn, want ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last []string
	for time.Now().Before(deadline) {
		if a, err := c.PeerAddrs(); err == nil {
			last = ipStrings(a)
			if equalStrings(last, sortedCopy(want)) {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("PeerAddrs = %v, want %v after the ASCONF was acknowledged", last, sortedCopy(want))
}

// --- multi-homing ------------------------------------------------------------

// TestMultihomedAssociationExchangesAddresses: a multi-homed client and
// listener each see their own addresses and all of the peer's, live and
// in the snapshots, and the association carries data.
func TestMultihomedAssociationExchangesAddresses(t *testing.T) {
	avail := requireLoopbacks(t, 3)
	serverIPs, clientIPs := avail[:2], avail[2:]
	if len(clientIPs) > 2 {
		clientIPs = clientIPs[:2]
	}
	l := mustListen(t, nil, "sctp", addrOf(0, serverIPs...))
	la := listenerAddr(t, l)
	if got := ipStrings(la); !equalStrings(got, sortedCopy(serverIPs)) {
		t.Errorf("listener bound %v, want %v", got, sortedCopy(serverIPs))
	}
	type result struct {
		c   *Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := l.AcceptSCTP()
		ch <- result{c, err}
	}()
	client, err := Dial(testContext(t, 20*time.Second), "sctp", addrOf(0, clientIPs...), la)
	if err != nil {
		t.Fatalf("multi-homed dial from %v to %v: %v", clientIPs, serverIPs, err)
	}
	t.Cleanup(func() { _ = client.Abort() })
	r := <-ch
	if r.err != nil {
		t.Fatalf("AcceptSCTP: %v", r.err)
	}
	server := r.c
	t.Cleanup(func() { _ = server.Abort() })

	for _, c := range []struct {
		what string
		get  func() (*Addr, error)
		snap net.Addr
		want []string
	}{
		{"client local", client.LocalAddrs, client.LocalAddr(), clientIPs},
		{"client peer", client.PeerAddrs, client.RemoteAddr(), serverIPs},
		{"server local", server.LocalAddrs, server.LocalAddr(), serverIPs},
		{"server peer", server.PeerAddrs, server.RemoteAddr(), clientIPs},
	} {
		a, err := c.get()
		if err != nil {
			t.Errorf("%s addresses: %v", c.what, err)
			continue
		}
		if got := ipStrings(a); !equalStrings(got, sortedCopy(c.want)) {
			t.Errorf("%s addresses = %v, want %v", c.what, got, sortedCopy(c.want))
		}
		if got := ipStrings(c.snap.(*Addr)); !equalStrings(got, sortedCopy(c.want)) {
			t.Errorf("%s snapshot = %v, want %v", c.what, got, sortedCopy(c.want))
		}
	}
	const msg = "multihomed-payload"
	if err := sendRaw(client, []byte(msg)); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 256)
	if n, err := server.Read(buf); err != nil || string(buf[:n]) != msg {
		t.Errorf("read %q, %v; want %q", buf[:n], err, msg)
	}
}

// TestMultihomedListenerAcceptsEveryBoundAddress: an association set up
// through any one of a multi-homed listener's addresses spans all of them
// (RFC 9260 §§1.2, 6.4), and carries data both ways.
func TestMultihomedListenerAcceptsEveryBoundAddress(t *testing.T) {
	serverIPs := requireLoopbacks(t, 2)[:2]
	for _, target := range serverIPs {
		t.Run(target, func(t *testing.T) {
			l := mustListen(t, nil, "sctp4", addrOf(0, serverIPs...))
			bound := listenerAddr(t, l)
			type result struct {
				c   *Conn
				err error
			}
			ch := make(chan result, 1)
			go func() {
				c, err := l.AcceptSCTP()
				ch <- result{c, err}
			}()
			client, err := Dial(testContext(t, 20*time.Second), "sctp4", nil, addrOf(bound.Port, target))
			if err != nil {
				t.Fatalf("dial %s: %v", target, err)
			}
			t.Cleanup(func() { _ = client.Abort() })
			r := <-ch
			if r.err != nil {
				t.Fatalf("AcceptSCTP: %v", r.err)
			}
			server := r.c
			t.Cleanup(func() { _ = server.Abort() })
			for what, get := range map[string]func() (*Addr, error){"client peer": client.PeerAddrs, "server local": server.LocalAddrs} {
				a, err := get()
				if err != nil {
					t.Errorf("%s: %v", what, err)
				} else if got := ipStrings(a); !equalStrings(got, sortedCopy(serverIPs)) {
					t.Errorf("%s after dialing %s = %v, want %v", what, target, got, sortedCopy(serverIPs))
				}
			}
			want := []byte("dial-" + target)
			if err := sendRaw(client, want); err != nil {
				t.Fatalf("send: %v", err)
			}
			buf := make([]byte, 64)
			if n, err := server.Read(buf); err != nil || string(buf[:n]) != string(want) {
				t.Fatalf("server read %q, %v; want %q", buf[:n], err, want)
			}
			if err := sendRaw(server, want); err != nil {
				t.Fatalf("reply: %v", err)
			}
			if n, err := client.Read(buf); err != nil || string(buf[:n]) != string(want) {
				t.Fatalf("client read %q, %v; want %q", buf[:n], err, want)
			}
		})
	}
}

// TestMultihomedListenerServesManyPeers: one multi-homed listener, twelve
// multi-homed peers, all associations live at once; each peer sees the
// server's whole address set and gets back its own messages only, and the
// server sees each peer's whole set.
func TestMultihomedListenerServesManyPeers(t *testing.T) {
	avail := requireLoopbacks(t, 3)
	serverIPs, clientIPs := avail[:2], avail[2:]
	l, err := Listen("sctp", addrOf(0, serverIPs...))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	la := listenerAddr(t, l)

	var (
		mu    sync.Mutex
		views [][]string
		srvWG sync.WaitGroup
	)
	srvWG.Add(1)
	go func() {
		defer srvWG.Done()
		for {
			c, err := l.AcceptSCTP()
			if err != nil {
				return
			}
			mu.Lock()
			views = append(views, ipStrings(c.RemoteAddr().(*Addr)))
			mu.Unlock()
			srvWG.Add(1)
			go func() {
				defer srvWG.Done()
				defer func() { _ = c.Close() }()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					if err := sendRaw(c, buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()

	const peers = 12
	var wg sync.WaitGroup
	errs := make(chan error, peers)
	for id := range peers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := Dial(context.Background(), "sctp", addrOf(0, clientIPs...), la)
			if err != nil {
				errs <- fmt.Errorf("peer %d dial: %w", id, err)
				return
			}
			defer func() { _ = c.Close() }()
			if err := c.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				errs <- err
				return
			}
			if got := ipStrings(c.RemoteAddr().(*Addr)); !equalStrings(got, sortedCopy(serverIPs)) {
				errs <- fmt.Errorf("peer %d sees server addresses %v, want %v", id, got, sortedCopy(serverIPs))
				return
			}
			buf := make([]byte, 4096)
			for j := range 10 {
				want := fmt.Sprintf("mh-peer-%d-msg-%d", id, j)
				if err := sendRaw(c, []byte(want)); err != nil {
					errs <- fmt.Errorf("peer %d send %d: %w", id, j, err)
					return
				}
				n, err := c.Read(buf)
				if err != nil || string(buf[:n]) != want {
					errs <- fmt.Errorf("peer %d msg %d: got %q, %v; want %q", id, j, buf[:n], err, want)
					return
				}
			}
			errs <- nil
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	_ = l.Close()
	srvWG.Wait()
	mu.Lock()
	defer mu.Unlock()
	if len(views) != peers {
		t.Errorf("the server accepted %d associations, want %d", len(views), peers)
	}
	for i, v := range views {
		if !equalStrings(v, sortedCopy(clientIPs)) {
			t.Errorf("association %d sees peer addresses %v, want %v", i, v, sortedCopy(clientIPs))
		}
	}
}

// TestMultihomedBindRejectsAnUnusableAddress: a list containing an address
// the host does not own is refused as a whole, rather than bound partly.
func TestMultihomedBindRejectsAnUnusableAddress(t *testing.T) {
	avail := requireLoopbacks(t, 1)
	l, err := Listen("sctp4", addrOf(0, avail[0], "192.0.2.1"))
	if err == nil {
		got := ipStrings(listenerAddr(t, l))
		_ = l.Close()
		t.Fatalf("Listen on %s and 192.0.2.1 succeeded, bound %v", avail[0], got)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "listen" {
		t.Errorf("err = %#v, want a *net.OpError with Op listen", err)
	}
}
