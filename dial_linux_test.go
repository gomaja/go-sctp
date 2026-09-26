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
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// wantDialError asserts that err is a *net.OpError with Op "dial" matching
// target.
func wantDialError(t testing.TB, err, target error) {
	t.Helper()
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "dial" {
		t.Fatalf("err = %#v, want a *net.OpError with Op dial", err)
	}
	if !errors.Is(err, target) {
		t.Fatalf("err = %v, want it to match %v", err, target)
	}
}

// TestDialErrorCarriesOperationAndAddresses: a Control failure — the one
// error every Dial path can fail with before any association setup starts
// — comes back as a *net.OpError with Op "dial", Source laddr and Addr
// raddr, wrapping the cause; the snapshot survives the caller changing
// laddr and raddr afterward, since Dial copies both into the error before
// it returns (see netAddr).
func TestDialErrorCarriesOperationAndAddresses(t *testing.T) {
	cause := errors.New("control failed")
	laddr := loopback4(0)
	raddr := &Addr{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.2")}, Port: 2905}
	cfg := &Config{Control: func(string, string, syscall.RawConn) error { return cause }}

	conn, err := cfg.Dial(testContext(t, 5*time.Second), "sctp4", laddr, raddr)
	if conn != nil {
		_ = conn.Abort()
		t.Fatal("Dial returned a connection with a failing Control hook")
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "dial" || opErr.Net != "sctp4" {
		t.Fatalf("err = %#v, want a *net.OpError with Op dial, Net sctp4", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("err = %v, want it to wrap %v", err, cause)
	}
	wantSource, wantAddr := laddr.String(), raddr.String()
	if got := opErr.Source.String(); got != wantSource {
		t.Fatalf("Source = %q, want laddr %q", got, wantSource)
	}
	if got := opErr.Addr.String(); got != wantAddr {
		t.Fatalf("Addr = %q, want raddr %q", got, wantAddr)
	}

	laddr.Port = 1
	laddr.IPs[0] = netip.MustParseAddr("10.0.0.9")
	raddr.Port = 1
	raddr.IPs[0] = netip.MustParseAddr("10.0.0.9")
	if got := opErr.Source.String(); got != wantSource {
		t.Errorf("Source changed after caller mutation: got %q, want %q", got, wantSource)
	}
	if got := opErr.Addr.String(); got != wantAddr {
		t.Errorf("Addr changed after caller mutation: got %q, want %q", got, wantAddr)
	}
}

// TestDialWrapsForeignOperationError: a Control hook that returns a
// *net.OpError from some other operation entirely — a TCP dialer it
// wraps, say — must not have that operation's Op and Net leak into the
// error Dial itself reports. The result is still Op "dial", Net "sctp4",
// with this call's own Source and Addr, and errors.Is still reaches the
// foreign error's own root cause.
func TestDialWrapsForeignOperationError(t *testing.T) {
	raddr := &Addr{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.2")}, Port: 2905}
	for name, laddr := range map[string]*Addr{
		"nil laddr":     nil,
		"non-nil laddr": loopback4(0),
	} {
		t.Run(name, func(t *testing.T) {
			root := errors.New("control failed")
			foreign := &net.OpError{Op: "control", Net: "tcp", Err: root}
			cfg := &Config{Control: func(string, string, syscall.RawConn) error { return foreign }}

			_, err := cfg.Dial(testContext(t, 5*time.Second), "sctp4", laddr, raddr)
			var opErr *net.OpError
			if !errors.As(err, &opErr) || opErr.Op != "dial" || opErr.Net != "sctp4" {
				t.Fatalf("err = %#v, want a *net.OpError with Op dial, Net sctp4", err)
			}
			if laddr == nil {
				if opErr.Source != nil {
					t.Errorf("Source = %v, want nil (no laddr)", opErr.Source)
				}
			} else if got, want := opErr.Source.String(), laddr.String(); got != want {
				t.Errorf("Source = %q, want %q", got, want)
			}
			if got, want := opErr.Addr.String(), raddr.String(); got != want {
				t.Errorf("Addr = %q, want %q", got, want)
			}
			if !errors.Is(err, root) {
				t.Fatalf("err = %v, want it to reach the foreign error's own root cause %v", err, root)
			}
			if errors.Unwrap(opErr) != foreign {
				t.Errorf("opError's cause is %#v, want the foreign *net.OpError %#v itself", errors.Unwrap(opErr), foreign)
			}
		})
	}
}

// TestDialPreservesMatchingOperationError: a Control hook that returns a
// *net.OpError which already describes exactly this dial — same Op, Net,
// Source and Addr — comes back unchanged, not wrapped a second time.
func TestDialPreservesMatchingOperationError(t *testing.T) {
	root := errors.New("control failed")
	raddr := &Addr{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.2")}, Port: 2905}
	matching := &net.OpError{Op: "dial", Net: "sctp4", Addr: netAddr(raddr), Err: root}
	cfg := &Config{Control: func(string, string, syscall.RawConn) error { return matching }}

	_, err := cfg.Dial(testContext(t, 5*time.Second), "sctp4", nil, raddr)
	if err != matching {
		t.Errorf("err = %#v, want the matching *net.OpError %#v unchanged", err, matching)
	}
}

// TestDialContextCancelsSilentPeer is the case a context exists for: a
// peer that never answers, and a caller that stops waiting. Canceled
// after 200 ms, Dial must return within a second with context.Canceled
// inside a *net.OpError with Op "dial", having released the attempt: no
// association left in the kernel retransmitting INITs, no descriptor left
// open.
func TestDialContextCancelsSilentPeer(t *testing.T) {
	if !silentPeerAvailable(t) {
		t.Skip("SCTP to 192.0.2.1 is answered rather than dropped here, so no setup stays in COOKIE-WAIT; the Linux suite routes it to a dummy link")
	}
	baseline := countAssocs(t)
	fds := openFds(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(200*time.Millisecond, cancel)

	start := time.Now()
	c, err := Dial(ctx, "sctp4", nil, unreachableAddr())
	elapsed := time.Since(start)
	if err == nil {
		_ = c.Abort()
		t.Fatal("Dial to a silent peer succeeded")
	}
	wantDialError(t, err, context.Canceled)
	if elapsed > time.Second+200*time.Millisecond {
		t.Errorf("Dial returned %v after it started, more than a second after the cancel", elapsed)
	}
	if got := waitAssocsAtMost(t, baseline); got > baseline {
		t.Errorf("%d associations remain against a baseline of %d; the abandoned setup is still in the kernel", got, baseline)
	}
	if after := openFds(t); after > fds {
		t.Errorf("descriptor count went %d -> %d; the socket was not released", fds, after)
	}
}

// TestDialContextAlreadyCancelledOpensNoSocket checks that a context that
// is already done opens nothing. A descriptor count alone cannot show it,
// since a socket opened and closed within the call leaves the count
// unchanged; Control, which runs on the new socket, is the witness.
func TestDialContextAlreadyCancelledOpensNoSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := openFds(t)
	sawControl := false
	cfg := &Config{Control: func(string, string, syscall.RawConn) error {
		sawControl = true
		return nil
	}}
	raddr := unreachableAddr()
	_, err := cfg.Dial(ctx, "sctp4", nil, raddr)
	wantDialError(t, err, context.Canceled)
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Source != nil || opErr.Addr.String() != raddr.String() {
		t.Errorf("err = %#v, want a *net.OpError with a nil Source and Addr %v", err, raddr)
	}
	if sawControl {
		t.Error("a socket was created for a context that was already done")
	}
	if after := openFds(t); after != before {
		t.Errorf("descriptor count went %d -> %d", before, after)
	}
	if _, err := Dial(ctx, "sctp4", nil, unreachableAddr()); !errors.Is(err, context.Canceled) {
		t.Errorf("Dial err = %v, want context.Canceled", err)
	}
}

// abandonCase dials the silent peer with policy under ctx and checks the
// outcome: ctx's error, returned near the deadline or cancel, and nothing
// left behind.
func abandonCase(t *testing.T, policy AbandonPolicy, ctx context.Context, want error, earliest, latest time.Duration) {
	t.Helper()
	if !silentPeerAvailable(t) {
		t.Skip("needs a silent peer at 192.0.2.1; the Linux suite routes it to a dummy link")
	}
	baseline := countAssocs(t)
	fds := openFds(t)
	start := time.Now()
	c, err := (&Config{AbandonPolicy: policy}).Dial(ctx, "sctp4", nil, unreachableAddr())
	elapsed := time.Since(start)
	if err == nil {
		_ = c.Abort()
		t.Fatal("Dial to a silent peer succeeded")
	}
	wantDialError(t, err, want)
	if elapsed < earliest || elapsed > latest {
		t.Errorf("Dial returned after %v, want between %v and %v", elapsed, earliest, latest)
	}
	if got := waitAssocsAtMost(t, baseline); got > baseline {
		t.Errorf("%d associations remain against a baseline of %d; the setup was not released", got, baseline)
	}
	if after := openFds(t); after > fds {
		t.Errorf("descriptor count went %d -> %d", fds, after)
	}
}

// TestDialContextTimeoutAbandonsTheAttempt: against a silent peer, Dial
// returns at the context's deadline, not when the kernel's INIT schedule
// runs out, with the association already gone.
func TestDialContextTimeoutAbandonsTheAttempt(t *testing.T) {
	const budget = 1500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	abandonCase(t, AbandonAbort, ctx, context.DeadlineExceeded, budget/2, budget*4)
}

// TestDialContextCancelDuringDial: a generous budget canceled early ends
// the call at the cancel.
func TestDialContextCancelDuringDial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	time.AfterFunc(500*time.Millisecond, cancel)
	abandonCase(t, AbandonAbort, ctx, context.Canceled, 0, 10*time.Second)
}

// TestDialContextQuietAbandonPolicyReleasesAttempt: AbandonQuiet releases
// the setup at the deadline just as completely, without the ABORT (which
// only a capture can show).
func TestDialContextQuietAbandonPolicyReleasesAttempt(t *testing.T) {
	const budget = 1500 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()
	abandonCase(t, AbandonQuiet, ctx, context.DeadlineExceeded, budget/2, budget*4)
}

// TestDialContextQuietAbandonPolicyCancelDuringDial is the same for a
// cancel.
func TestDialContextQuietAbandonPolicyCancelDuringDial(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	time.AfterFunc(500*time.Millisecond, cancel)
	abandonCase(t, AbandonQuiet, ctx, context.Canceled, 0, 10*time.Second)
}

// TestDialContextInvalidAbandonPolicyOpensNoSocket: an AbandonPolicy the
// package does not name is refused before any socket exists, so Control
// never runs for an unusable request.
func TestDialContextInvalidAbandonPolicyOpensNoSocket(t *testing.T) {
	before := openFds(t)
	sawControl := false
	cfg := &Config{
		AbandonPolicy: AbandonPolicy(99),
		Control: func(string, string, syscall.RawConn) error {
			sawControl = true
			return nil
		},
	}
	_, err := cfg.Dial(context.Background(), "sctp4", nil, unreachableAddr())
	wantDialError(t, err, syscall.EINVAL)
	if !strings.Contains(err.Error(), "AbandonPolicy") {
		t.Errorf("err = %v, want it to name AbandonPolicy", err)
	}
	if sawControl {
		t.Error("Control ran for an invalid abandon policy")
	}
	if after := openFds(t); after != before {
		t.Errorf("descriptor count went %d -> %d", before, after)
	}
}

// TestDialContextAbandonedAttemptsLeakNothing runs the abandon path often
// enough that a leak per attempt would show.
func TestDialContextAbandonedAttemptsLeakNothing(t *testing.T) {
	if !silentPeerAvailable(t) {
		t.Skip("needs a silent peer at 192.0.2.1; the Linux suite routes it to a dummy link")
	}
	attempts := 50
	if testing.Short() {
		attempts = 10
	}
	baseline := countAssocs(t)
	before := openFds(t)
	for i := range attempts {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := Dial(ctx, "sctp4", nil, unreachableAddr())
		cancel()
		if err == nil {
			t.Fatalf("attempt %d: Dial to a silent peer succeeded", i)
		}
	}
	if after := openFds(t); after > before+2 {
		t.Errorf("descriptor count went %d -> %d over %d abandoned attempts", before, after, attempts)
	}
	if got := waitAssocsAtMost(t, baseline); got > baseline {
		t.Errorf("%d associations remain against a baseline of %d after %d abandoned attempts", got, baseline, attempts)
	}
}

// TestDialContextSucceeds is the ordinary dial: an association that
// carries a message.
func TestDialContextSucceeds(t *testing.T) {
	client, server := connPair(t, nil, nil)
	want := []byte("over a context dial")
	if err := sendRaw(client, want); err != nil {
		t.Fatalf("send: %v", err)
	}
	buf := make([]byte, 64)
	n, err := server.Read(buf)
	if err != nil || string(buf[:n]) != string(want) {
		t.Fatalf("read %q, %v; want %q", buf[:n], err, want)
	}
	if client.AssocID() == 0 || server.AssocID() == 0 {
		t.Errorf("AssocID = %d (client), %d (server); an established association has a non-zero id", client.AssocID(), server.AssocID())
	}
}

// TestDialContextReturnsPollableDescriptor: the dialed descriptor is
// non-blocking and owned by the runtime poller, so an idle read lasts until
// its deadline instead of answering EAGAIN at once, and the dial's own
// context left no deadline behind: a read with no deadline of its own
// waits until a message comes.
func TestDialContextReturnsPollableDescriptor(t *testing.T) {
	client, server := connPair(t, nil, nil)
	rawFd(t, mustSyscallConn(t, client), func(fd int) {
		if !isNonblocking(fd) {
			t.Error("the dialed descriptor is blocking")
		}
	})
	got := make(chan error, 1)
	go func() {
		_, err := client.Read(make([]byte, 64))
		got <- err
	}()
	select {
	case err := <-got:
		t.Fatalf("a read with no deadline returned %v before anything was sent; Dial left a deadline behind", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := sendRaw(server, []byte("wake")); err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := <-got; err != nil {
		t.Fatalf("read: %v", err)
	}

	const budget = 400 * time.Millisecond
	if err := client.SetReadDeadline(time.Now().Add(budget)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	start := time.Now()
	_, err := client.Read(make([]byte, 64))
	elapsed := time.Since(start)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("idle read = %v, want os.ErrDeadlineExceeded", err)
	}
	if elapsed < budget/2 {
		t.Errorf("an idle read returned after %v against a %v deadline", elapsed, budget)
	}
}

// TestDialEstablishedThenEndedBeforeItLooks: a peer that accepts and at
// once ends the association gracefully can take it through ESTABLISHED to
// CLOSING and free it before Dial first checks. The setup succeeded, so
// Dial must return a connection rather than wait for a state that has
// come and gone. A look after the end finds SCTP_STATUS answering EINVAL,
// as it does before establishment, and the edge-triggered poller signals
// no further writability change to look again at; the COMM_UP
// notification the setup queued stays on the socket, which is the lasting
// evidence Dial waits for and peeks at. The connection then behaves as one
// whose association ended before Accept.
func TestDialEstablishedThenEndedBeforeItLooks(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	laddr := listenerAddr(t, l)
	ended := make(chan error, 1)
	go func() {
		c, err := l.AcceptSCTP()
		if err != nil {
			ended <- err
			return
		}
		ended <- c.Close()
	}()
	testHookDialStarted = func() {
		if err := <-ended; err != nil {
			t.Errorf("server: %v", err)
		}
		waitAssocClosed(t, laddr.Port)
	}
	t.Cleanup(func() { testHookDialStarted = nil })

	c, err := Dial(testContext(t, 5*time.Second), "sctp4", nil, laddr)
	if err != nil {
		t.Fatalf("Dial of an association that was established and then ended = %v, want a connection", err)
	}
	t.Cleanup(func() { _ = c.Abort() })
	if id := c.AssocID(); id != 0 {
		t.Errorf("AssocID = %d, want 0 for an association that has already ended", id)
	}
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := c.Read(make([]byte, 64)); err != io.EOF {
		t.Errorf("read = %v, want io.EOF", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close = %v, want nil", err)
	}
}

// TestDialContextRefusedPeerReportsTheError: a refusal arrives through
// SO_ERROR, after the non-blocking connect returned, and must end the dial
// at once instead of the context's deadline. The kernel's choice of local
// port can be the dead port itself, and the setup would then complete with
// the socket's own association; Dial refuses that self-connection
// (TestDialRefusesSelfConnect), so a dial to the dead port can succeed
// only if another socket has taken the port since.
func TestDialContextRefusedPeerReportsTheError(t *testing.T) {
	dead := deadPort(t)
	const budget = 5 * time.Second
	start := time.Now()
	c, err := Dial(testContext(t, budget), "sctp4", nil, dead)
	elapsed := time.Since(start)
	if err == nil {
		// Dial never connects the socket to itself, so the success is
		// either that, which must not happen, or a socket that has taken
		// the port since.
		explainDeadPortDial(t, c, dead)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a dial to a refused port ran out its %v context instead of reporting the refusal", budget)
	}
	wantDialError(t, err, syscall.ECONNREFUSED)
	if elapsed > budget/2 {
		t.Errorf("took %v to report a refusal", elapsed)
	}
}

// explainDeadPortDial is called when a dial to dead, a port whose listener
// was closed, succeeded, and it releases c. A connection of the socket to
// itself, which the kernel can make when its choice of local port is the
// dead port, must not happen: Dial refuses it. Otherwise only a socket
// that has taken the port since explains the success, which a Listen on
// the port failing with EADDRINUSE shows, and the test is skipped; any
// other outcome fails it.
func explainDeadPortDial(t testing.TB, c *Conn, dead *Addr) {
	t.Helper()
	local, _ := c.LocalAddr().(*Addr)
	self := c.selfConnected()
	_ = c.Abort()
	if self || (local != nil && local.Port == dead.Port) {
		t.Fatalf("a dial to %v connected the socket to itself (local %v); Dial must refuse that", dead, local)
	}
	l, err := Listen("sctp4", dead)
	if err == nil {
		_ = l.Close()
		t.Fatalf("a dial to %v, whose listener was closed, succeeded, and the port is not bound by anyone else", dead)
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("a dial to %v succeeded; checking whether the port was taken since gave %v, not EADDRINUSE", dead, err)
	}
	t.Skip("the port was taken by another socket before the dial")
}

// deadPort is a 127.0.0.1 address whose port had a listener that is now
// closed, so that nothing answers there but an ABORT.
func deadPort(t testing.TB) *Addr {
	t.Helper()
	return deadPortOn(t, "sctp4", loopback4(0))
}

// deadPortOn is laddr with a port that had a listener on network, now
// closed, so that nothing answers there but an ABORT.
func deadPortOn(t testing.TB, network string, laddr *Addr) *Addr {
	t.Helper()
	l, err := Listen(network, laddr)
	if err != nil {
		t.Fatalf("Listen(%q, %v): %v", network, laddr, err)
	}
	dead := listenerAddr(t, l)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return dead
}

// bindTo returns a testHookDialConnecting that binds an attempt's socket
// to addr — the family's wildcard on addr's port when addr names no IP —
// as the kernel's own choice of local port could have, when
// which(attempt) says so; attempts counts the calls.
func bindTo(addr *Addr, attempts *int, which func(attempt int) bool) func(*socket) error {
	return func(s *socket) error {
		*attempts++
		if !which(*attempts) {
			return nil
		}
		b, err := localBindAddrs(s.family, addr)
		if err != nil {
			return err
		}
		return s.bindx(optSockoptBindxAdd, b)
	}
}

// TestDialRefusesSelfConnect: when the kernel's choice of local port is
// the port being dialed and nothing listens there, the socket's setup
// completes with itself (RFC 9260 §5.2.1, an initialization collision).
// A hook binds every attempt's socket to the dialed address, so that each
// attempt connects to itself; Dial aborts each of those associations and
// starts over, twice, then fails with ECONNREFUSED inside a *net.OpError
// with Op dial, leaving no association or descriptor behind. Three
// attempts show that each one completed a self-connection, since a
// refusal would have ended the dial after the first.
func TestDialRefusesSelfConnect(t *testing.T) {
	dead := deadPort(t)
	baseline := countAssocs(t)
	fds := openFds(t)
	attempts := 0
	testHookDialConnecting = bindTo(dead, &attempts, func(int) bool { return true })
	t.Cleanup(func() { testHookDialConnecting = nil })

	c, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, dead)
	if err == nil {
		self := c.selfConnected()
		_ = c.Abort()
		t.Fatalf("Dial returned a connection (to itself: %v), want a refusal", self)
	}
	wantDialError(t, err, syscall.ECONNREFUSED)
	if attempts != 1+maxSelfConnectRetries {
		t.Errorf("%d attempts, want %d: each self-connection must be retried, and only those", attempts, 1+maxSelfConnectRetries)
	}
	if got := waitAssocsAtMost(t, baseline); got > baseline {
		t.Errorf("%d associations remain against a baseline of %d", got, baseline)
	}
	if after := openFds(t); after != fds {
		t.Errorf("descriptor count went %d -> %d", fds, after)
	}
}

// TestDialRetriesAfterSelfConnect: the first attempt connects to itself;
// before the second starts, a listener takes the port, and the retry
// reaches it. Dial returns that connection, not the first.
func TestDialRetriesAfterSelfConnect(t *testing.T) {
	dead := deadPort(t)
	attempts := 0
	var l *Listener
	selfBind := bindTo(dead, &attempts, func(a int) bool { return a == 1 })
	testHookDialConnecting = func(s *socket) error {
		if err := selfBind(s); err != nil || attempts != 2 {
			return err
		}
		var err error
		l, err = Listen("sctp4", dead)
		return err
	}
	t.Cleanup(func() { testHookDialConnecting = nil })

	c, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, dead)
	if l != nil {
		t.Cleanup(func() { _ = l.Close() })
	}
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Abort() })
	if attempts != 2 {
		t.Errorf("%d attempts, want 2: one self-connection, then the retry", attempts)
	}
	if c.selfConnected() {
		t.Fatalf("Dial returned a connection to itself: local %v, remote %v", c.LocalAddr(), c.RemoteAddr())
	}
	s, err := l.AcceptSCTP()
	if err != nil {
		t.Fatalf("AcceptSCTP: %v", err)
	}
	t.Cleanup(func() { _ = s.Abort() })
	if got, want := s.RemoteAddr().(*Addr).Port, c.LocalAddr().(*Addr).Port; got != want {
		t.Errorf("the accepted association's peer port = %d, want the dialed connection's %d", got, want)
	}
}

// TestDialKeepsSelfConnectWithExplicitPort: a laddr that names its port is
// the caller's choice, as with net's TCP dialer, so a self-connection
// made with it is returned.
func TestDialKeepsSelfConnectWithExplicitPort(t *testing.T) {
	dead := deadPort(t)
	c, err := Dial(testContext(t, 10*time.Second), "sctp4", dead, dead)
	if err != nil {
		t.Fatalf("Dial from and to %v: %v", dead, err)
	}
	t.Cleanup(func() { _ = c.Abort() })
	if !c.selfConnected() {
		t.Errorf("local %v, remote %v; want a connection to itself", c.LocalAddr(), c.RemoteAddr())
	}
}

// TestSelfConnectedDetection pins the test the guard applies to the
// address snapshots: the same port, and a peer set that is not empty and
// lies wholly within the local set, where a link-local peer address
// without a zone matches the local address that equals it without its
// zone. A shared address alone is not enough: two hosts can both hold a
// private address, and a genuine peer on the dialed port can then share
// it with a wildcard dialer's local set.
func TestSelfConnectedDetection(t *testing.T) {
	conn := func(l, r *Addr) *Conn {
		c := &Conn{}
		c.laddr.Store(l)
		c.raddr.Store(r)
		return c
	}
	for _, tc := range []struct {
		name string
		l, r *Addr
		want bool
	}{
		// The sets observed on genuine self-connections are identical.
		{"self via 127.0.0.1", addrOf(9, "127.0.0.1", "172.17.0.2", "127.0.0.2", "10.99.0.1"), addrOf(9, "10.99.0.1", "127.0.0.2", "127.0.0.1", "172.17.0.2"), true},
		{"self via 10.99.0.1", addrOf(9, "172.17.0.2", "10.99.0.1"), addrOf(9, "10.99.0.1", "172.17.0.2"), true},
		{"peer set within the local set", addrOf(9, "127.0.0.1", "127.0.0.2"), addrOf(9, "127.0.0.2"), true},
		// A genuine peer on another host that shares a private address.
		{"cross-host peer sharing one address", addrOf(9, "172.30.99.20", "10.99.0.1"), addrOf(9, "172.30.99.10", "10.99.0.1"), false},
		{"same port, disjoint addresses", addrOf(9, "127.0.0.1"), addrOf(9, "127.0.0.2"), false},
		{"shared address, other port", addrOf(9, "127.0.0.1"), addrOf(10, "127.0.0.1"), false},
		{"empty peer set", addrOf(9, "127.0.0.1"), &Addr{Port: 9}, false},
		{"ended association", &Addr{}, &Addr{}, false},
		{"zones differ", addrOf(9, "fe80::1%1"), addrOf(9, "fe80::1%2"), false},
		// Linux keeps the interface index only on the local copy of a
		// link-local address; the peer's copy, learned from an INIT or
		// INIT ACK address parameter, has scope id 0 (net/sctp/ipv6.c:
		// sctp_v6_from_addr_param, whose every caller passes iif 0), so
		// it decodes without a zone.
		{"link-local peer without the local zone", addrOf(9, "::1", "fe80::1%eth0"), addrOf(9, "::1", "fe80::1"), true},
		// The other way round does not arise — a local link-local address
		// always carries its interface index — so a zoned peer address
		// must match a local address exactly.
		{"zoned peer, zone-less local", addrOf(9, "fe80::1"), addrOf(9, "fe80::1%eth0"), false},
	} {
		if got := conn(tc.l, tc.r).selfConnected(); got != tc.want {
			t.Errorf("%s: selfConnected = %v, want %v", tc.name, got, tc.want)
		}
	}
	if (&Conn{}).selfConnected() {
		t.Error("a Conn with no snapshots reported a self-connection")
	}
}

// TestDialRefusesSelfConnectWithLinkLocalAddresses: on an AF_INET6 socket
// bound to the wildcard, the association's local set holds the host's
// link-local addresses with their zones, while the peer set of a
// self-connection, which the socket learns from its own INIT and INIT ACK
// address parameters, holds the same addresses without one (net/sctp/ipv6.c:
// sctp_v6_from_addr_param stores scope id 0, its iif argument at every
// call; sctp_v6_copy_addrlist stores the interface index on the local
// list). A self-connection through a loopback address must be detected
// all the same, on "sctp6" and on a dual-stack "sctp" socket, dialing
// ::1 or 127.0.0.1. A dial from an explicit wildcard port, which the
// guard leaves alone, shows the two sets in that shape first, and then
// the guarded dial, whose hook binds each attempt to the wildcard on the
// dialed port as the kernel's own port choice could have, must be refused
// after the bounded retries. The Linux suite's dummy link zone0 carries
// fe80::1.
func TestDialRefusesSelfConnectWithLinkLocalAddresses(t *testing.T) {
	for _, tc := range []struct {
		network  string // the network dialed
		deadNet  string // the network of the listener whose port is dialed
		loopback string
	}{
		{"sctp6", "sctp6", "::1"},
		{"sctp", "sctp6", "::1"},
		{"sctp", "sctp4", "127.0.0.1"},
	} {
		network := tc.network
		t.Run(network+" via "+tc.loopback, func(t *testing.T) {
			dead := deadPortOn(t, tc.deadNet, addrOf(0, tc.loopback))
			baseline := countAssocs(t)
			fds := openFds(t)

			c, err := Dial(testContext(t, 10*time.Second), network, &Addr{Port: dead.Port}, dead)
			if err != nil {
				t.Fatalf("Dial(%q) from the wildcard port %d to %v: %v", network, dead.Port, dead, err)
			}
			local, peer := c.laddr.Load(), c.raddr.Load()
			self := c.selfConnected()
			_ = c.Abort()
			zoned, bare := linkLocalTwins(local, peer)
			if !zoned.IsValid() {
				t.Skipf("local %v, peer %v: no link-local address held with a zone locally and without one by the peer (the Linux suite adds fe80::1 on zone0)", local, peer)
			}
			if !self {
				t.Errorf("local %v, peer %v: selfConnected = false, want true (%v is %v without its zone)", local, peer, bare, zoned)
			}
			if got := waitAssocsAtMost(t, baseline); got > baseline {
				t.Fatalf("%d associations remain after the abort, against a baseline of %d", got, baseline)
			}

			attempts := 0
			testHookDialConnecting = bindTo(&Addr{Port: dead.Port}, &attempts, func(int) bool { return true })
			t.Cleanup(func() { testHookDialConnecting = nil })
			c, err = Dial(testContext(t, 10*time.Second), network, nil, dead)
			if err == nil {
				local, peer := c.laddr.Load(), c.raddr.Load()
				_ = c.Abort()
				t.Fatalf("Dial(%q, nil, %v) returned a connection after %d attempts (local %v, peer %v), want a refusal", network, dead, attempts, local, peer)
			}
			wantDialError(t, err, syscall.ECONNREFUSED)
			if attempts != 1+maxSelfConnectRetries {
				t.Errorf("%d attempts, want %d: each self-connection must be retried, and only those", attempts, 1+maxSelfConnectRetries)
			}
			if got := waitAssocsAtMost(t, baseline); got > baseline {
				t.Errorf("%d associations remain against a baseline of %d", got, baseline)
			}
			if after := openFds(t); after != fds {
				t.Errorf("descriptor count went %d -> %d", fds, after)
			}
		})
	}
}

// linkLocalTwins returns a link-local address that local holds with a
// zone and that peer holds without one, or invalid addresses when there
// is no such pair.
func linkLocalTwins(local, peer *Addr) (zoned, bare netip.Addr) {
	for _, l := range local.IPs {
		if !l.IsLinkLocalUnicast() || l.Zone() == "" {
			continue
		}
		for _, p := range peer.IPs {
			if p == l.WithZone("") {
				return l, p
			}
		}
	}
	return netip.Addr{}, netip.Addr{}
}

// TestSocketConfigDialContext: Config.Control runs on the dial's socket,
// with the network and the remote address as a string.
func TestSocketConfigDialContext(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	var (
		sawControl     bool
		controlNetwork string
		controlAddress string
	)
	cfg := &Config{Control: func(network, address string, c syscall.RawConn) error {
		controlNetwork, controlAddress = network, address
		return c.Control(func(uintptr) { sawControl = true })
	}}
	client, _ := dialAccept(t, cfg, l)
	if !sawControl {
		t.Error("Control never reached the descriptor")
	}
	if controlNetwork != "sctp4" || controlAddress != listenerAddr(t, l).String() {
		t.Errorf("Control(%q, %q), want (%q, %q)", controlNetwork, controlAddress, "sctp4", listenerAddr(t, l).String())
	}
	_ = client
}

// TestDialUnderChurnSucceeds: a dial hard against a listener that accepts
// and closes as fast as it can reports no failure except the backlog
// being momentarily full (ECONNREFUSED). The non-blocking setup always
// confirms establishment through the poller, so an association the kernel
// completed inside the connect call can never be reported as a failure;
// and since the listener ends each association as soon as it has it, this
// is also where an association that was established and ended before the
// dial looked turns up (TestDialEstablishedThenEndedBeforeItLooks pins
// that case alone).
func TestDialUnderChurnSucceeds(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(4))
	l, err := Listen("sctp4", loopback4(0))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	raddr := listenerAddr(t, l)
	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				c, err := l.AcceptSCTP()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}
	failures := map[string]int{}
	refused := 0
	for range 200 {
		c, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, raddr)
		if err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) {
				refused++
				continue
			}
			failures[err.Error()]++
			continue
		}
		_ = c.Close()
	}
	if err := l.Close(); err != nil {
		t.Fatalf("listener Close: %v", err)
	}
	wg.Wait()
	if refused > 0 {
		t.Logf("%d of 200 dials hit a full backlog (ECONNREFUSED)", refused)
	}
	for msg, n := range failures {
		t.Errorf("%d of 200 dials failed with: %s", n, msg)
	}
}

// TestRapidDialAbortCyclesSucceed: dials and aborts in quick succession,
// against a listener that aborts every accepted connection. A fresh
// socket never finds a stale association, so no dial fails with EISCONN
// or EALREADY. Two failures are the peer's, not the dial's: ECONNREFUSED
// when the backlog is momentarily full, and ECONNRESET when the listener's
// ABORT of the just-accepted association arrives before the dial has
// looked (the association was established, then reset: sctp_sf_do_9_1_abort
// sets ECONNRESET, where an ABORT during the setup gives ECONNREFUSED).
// Both are counted and logged.
func TestRapidDialAbortCyclesSucceed(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	raddr := listenerAddr(t, l)
	go func() {
		for {
			c, err := l.AcceptSCTP()
			if err != nil {
				return
			}
			_ = c.Abort()
		}
	}()
	refused, reset := 0, 0
	for i := range 300 {
		c, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, raddr)
		if err != nil {
			switch {
			case errors.Is(err, syscall.ECONNREFUSED):
				refused++
				continue
			case errors.Is(err, syscall.ECONNRESET):
				reset++
				continue
			}
			t.Fatalf("dial %d: %v", i, err)
		}
		if err := c.Abort(); err != nil {
			t.Fatalf("abort %d: %v", i, err)
		}
	}
	if refused > 0 || reset > 0 {
		t.Logf("300 dial/abort cycles: %d refused (full backlog), %d reset by the listener's abort before the dial looked", refused, reset)
	}
}

// TestAbandonDialUsesPolicy pins which close step each policy takes: an
// abortive close for AbandonAbort (the default), a plain release for
// AbandonQuiet, and the step's own error either way.
func TestAbandonDialUsesPolicy(t *testing.T) {
	for _, tc := range []struct {
		policy       AbandonPolicy
		wantAbortive int
		wantRelease  int
	}{
		{AbandonAbort, 1, 0},
		{AbandonQuiet, 0, 1},
	} {
		t.Run(tc.policy.String(), func(t *testing.T) {
			ops := &fakeOps{fakeClock: newAutoClock(), abortiveErr: syscall.ECONNRESET, releaseErr: syscall.EBADF}
			err := abandonDial(ops, tc.policy)
			got := ops.counts()
			if got.abortive != tc.wantAbortive || got.release != tc.wantRelease || got.shutdown != 0 || got.gone != 0 {
				t.Fatalf("calls = %+v, want %d abortive and %d release only", got, tc.wantAbortive, tc.wantRelease)
			}
			want := error(syscall.ECONNRESET)
			if tc.policy == AbandonQuiet {
				want = syscall.EBADF
			}
			if !errors.Is(err, want) {
				t.Fatalf("err = %v, want %v", err, want)
			}
		})
	}
}

// TestConnectxReportsEALREADYWhileSetupInFlight: on the non-blocking
// socket Dial uses, the first CONNECTX3 starts the setup and answers
// EINPROGRESS, and a second one to the same peer finds that setup and
// answers EALREADY, never success (net/sctp/socket.c: __sctp_connect
// returns EALREADY for an association below ESTABLISHED). Dial tolerates
// both answers, and confirms establishment itself.
func TestConnectxReportsEALREADYWhileSetupInFlight(t *testing.T) {
	if !silentPeerAvailable(t) {
		t.Skip("needs a silent peer at 192.0.2.1; the Linux suite routes it to a dummy link")
	}
	s, err := newSocket(afInet, "sctp4")
	if err != nil {
		t.Fatalf("newSocket: %v", err)
	}
	t.Cleanup(func() { _ = (&sockCloseOps{sock: &s}).abortive() })
	addrs, err := encodeAddrs(afInet, unreachableAddr().IPs, unreachableAddr().Port)
	if err != nil {
		t.Fatalf("encodeAddrs: %v", err)
	}
	if err := s.connectx(addrs); err != syscall.EINPROGRESS {
		t.Fatalf("first connectx = %v, want EINPROGRESS", err)
	}
	sawAlready := false
	for i := range 4 {
		err := s.connectx(addrs)
		switch err {
		case syscall.EALREADY:
			sawAlready = true
		case syscall.EINPROGRESS:
		default:
			t.Fatalf("connectx %d = %v, want EALREADY or EINPROGRESS while the setup is in flight", i+2, err)
		}
	}
	if !sawAlready {
		t.Error("no connectx on the in-flight setup answered EALREADY")
	}
}

// TestLocalAddrsAssociationScope (the loopback part): a wildcard-bound
// client's LocalAddrs asks with its own association id and returns the
// association's list, the same list an independent SCTP_GET_LOCAL_ADDRS
// for that id returns, and the LocalAddr snapshot holds it too. With a
// loopback peer every address is in scope, so the association's list and
// the endpoint's coincide here; telling them apart needs a peer at a
// private address, on another host.
func TestLocalAddrsAssociationScope(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	client, err := Dial(testContext(t, 10*time.Second), "sctp", nil, listenerAddr(t, l))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Abort() })

	live, err := client.LocalAddrs()
	if err != nil {
		t.Fatalf("LocalAddrs: %v", err)
	}
	direct, err := client.sock.getAddrs(optGetLocalAddrs, client.AssocID())
	if err != nil {
		t.Fatalf("SCTP_GET_LOCAL_ADDRS for id %d: %v", client.AssocID(), err)
	}
	if got, want := ipStrings(live), ipStrings(direct); !equalStrings(got, want) {
		t.Errorf("LocalAddrs = %v, want the association's list %v", got, want)
	}
	if live.Port == 0 || live.Port != direct.Port {
		t.Errorf("LocalAddrs port = %d, want the association's port %d", live.Port, direct.Port)
	}
	if got := ipStrings(client.LocalAddr().(*Addr)); !equalStrings(got, ipStrings(live)) {
		t.Errorf("LocalAddr snapshot = %v, want %v", got, ipStrings(live))
	}
	found := false
	for _, ip := range live.IPs {
		found = found || ip == netip.MustParseAddr("127.0.0.1")
		if ip.Is4In6() {
			t.Errorf("LocalAddrs reports %v in IPv4-mapped form", ip)
		}
	}
	if !found {
		t.Errorf("LocalAddrs = %v, want it to include the address the association runs over, 127.0.0.1", live)
	}

	peers, err := client.PeerAddrs()
	if err != nil {
		t.Fatalf("PeerAddrs: %v", err)
	}
	if got := ipStrings(peers); !equalStrings(got, []string{"127.0.0.1"}) {
		t.Errorf("PeerAddrs = %v, want [127.0.0.1]", got)
	}
	if got := client.RemoteAddr().String(); got != peers.String() {
		t.Errorf("RemoteAddr = %q, want %q", got, peers.String())
	}
}

// TestZonedLinkLocalConnectionRoundTrip is the socket half of
// TestZonedLinkLocalRoundTrip: it carries an IPv6 link-local address with
// a zone through Listen, Dial and the address snapshots of both ends,
// against the Linux suite's dummy link zone0, which holds fe80::1.
func TestZonedLinkLocalConnectionRoundTrip(t *testing.T) {
	ifi, err := net.InterfaceByName("zone0")
	if err != nil {
		t.Skipf("no interface zone0 (the Linux suite adds a dummy link zone0 with fe80::1): %v", err)
	}
	laddr, err := ResolveAddr("sctp6", "[fe80::1%zone0]:0")
	if err != nil {
		t.Fatalf("ResolveAddr: %v", err)
	}
	l, err := Listen("sctp6", laddr)
	if err != nil {
		t.Skipf("cannot listen on fe80::1%%zone0 (index %d): %v", ifi.Index, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	if got := l.Addr().String(); !strings.Contains(got, "%zone0") {
		t.Errorf("listener Addr = %q, want the zone zone0", got)
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
	client, err := Dial(testContext(t, 10*time.Second), "sctp6", nil, listenerAddr(t, l))
	if err != nil {
		t.Fatalf("Dial %v: %v", l.Addr(), err)
	}
	t.Cleanup(func() { _ = client.Abort() })
	r := <-ch
	if r.err != nil {
		t.Fatalf("AcceptSCTP: %v", r.err)
	}
	t.Cleanup(func() { _ = r.c.Abort() })

	if got := client.RemoteAddr().String(); !strings.Contains(got, "fe80::1%zone0") {
		t.Errorf("client RemoteAddr = %q, want it to contain fe80::1%%zone0", got)
	}
	if got := r.c.LocalAddr().String(); !strings.Contains(got, "fe80::1%zone0") {
		t.Errorf("server LocalAddr = %q, want it to contain fe80::1%%zone0", got)
	}
	if got := r.c.RemoteAddr().String(); !strings.Contains(got, "%zone0") {
		t.Errorf("server RemoteAddr = %q, want the client's link-local address on zone0", got)
	}
	back, err := ResolveAddr("sctp6", client.RemoteAddr().String())
	if err != nil {
		t.Fatalf("ResolveAddr(%q): %v", client.RemoteAddr(), err)
	}
	if back.String() != client.RemoteAddr().String() {
		t.Errorf("round trip: %q parsed back as %q", client.RemoteAddr(), back)
	}
}

// TestDialDoesNotMutateItsAddr is TestListenDoesNotMutateItsAddr's twin
// for the dial path (v1 TestDialDoesNotMutateItsAddr), and additionally
// shows the consequence a mutation would have: the same laddr value,
// reused for a second dial, must still mean "any local address, any
// port" — if the first dial had appended a wildcard into it, the second
// would bind an address the caller never asked for.
func TestDialDoesNotMutateItsAddr(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	go func() {
		for {
			c, err := l.AcceptSCTP()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Abort() })
		}
	}()
	raddr := listenerAddr(t, l)

	laddr := &Addr{}
	before := slices.Clone(laddr.IPs)

	first, err := Dial(testContext(t, 10*time.Second), "sctp4", laddr, raddr)
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	t.Cleanup(func() { _ = first.Abort() })

	if !slices.Equal(laddr.IPs, before) {
		t.Fatalf("Dial changed the caller's IPs: %v -> %v", before, laddr.IPs)
	}

	second, err := Dial(testContext(t, 10*time.Second), "sctp4", laddr, raddr)
	if err != nil {
		t.Fatalf("second dial with the same laddr: %v", err)
	}
	_ = second.Abort()
}

// BenchmarkDial (v1 BenchmarkDial): one dial-and-accept round trip
// against a listener that accepts and closes as fast as it can.
func BenchmarkDial(b *testing.B) {
	l, err := Listen("sctp4", loopback4(0))
	if err != nil {
		b.Fatalf("listen: %v", err)
	}
	b.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.AcceptSCTP()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	raddr := listenerAddr(b, l)

	// One context for every iteration, not a fresh one per dial:
	// testContext registers a b.Cleanup, and calling it inside the loop
	// below would pile up one per iteration, none of them running until
	// the whole benchmark ends, skewing both the allocation count
	// b.ReportAllocs() takes and the per-iteration timer b.Loop() keeps.
	// Unbounded, not a fixed deadline: a dial against this loopback
	// listener, which accepts and closes as fast as it can, returns near
	// instantly, so nothing here needs one, and a bounded context shared
	// across every iteration would expire partway through a long run
	// regardless.
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		c, err := Dial(ctx, "sctp4", nil, raddr)
		if err != nil {
			b.Fatalf("dial: %v", err)
		}
		_ = c.Close()
	}
}
