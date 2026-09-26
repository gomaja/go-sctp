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
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// --- Close, Abort and Shutdown on real associations -----------------------

// TestDoubleCloseReturnsNetErrClosed (the socket half; the state machine
// half is TestLifecycleClosedAfterRelease): a second Close and an Abort
// after Close report net.ErrClosed, once wrapped in a *net.OpError with
// Op "close".
func TestDoubleCloseReturnsNetErrClosed(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	if err := client.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	for name, err := range map[string]error{
		"second Close":          client.Close(),
		"Abort after Close":     client.Abort(),
		"Shutdown after Close":  client.Shutdown(),
		"CloseWithTimeout(0)":   client.CloseWithTimeout(0),
		"CloseWithTimeout(1 s)": client.CloseWithTimeout(time.Second),
	} {
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s = %v, want net.ErrClosed", name, err)
			continue
		}
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr.Op != "close" || opErr.Err != net.ErrClosed {
			t.Errorf("%s = %#v, want a *net.OpError with Op close around the bare net.ErrClosed", name, err)
		}
	}
	if client.LocalAddr() == nil || client.RemoteAddr() == nil {
		t.Error("an address snapshot is gone after Close; it stays readable")
	}
}

// TestConcurrentCloseAndAbort (the socket half; the state machine half is
// TestLifecycleConcurrentCloseAndAbort): racing Close and Abort calls
// release the descriptor exactly once. An Abort that overtakes a waiting
// Close returns nil and so does that Close, so the invariant is the state
// machine's: every call returns nil or net.ErrClosed, at most one Close
// returns nil, and when none does, exactly one Abort does.
func TestConcurrentCloseAndAbort(t *testing.T) {
	for round := range 25 {
		client, _ := connPair(t, nil, nil)
		var closes, aborts atomic.Int32
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for i := range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var err error
				if i%2 == 0 {
					if err = client.Close(); err == nil {
						closes.Add(1)
					}
				} else {
					if err = client.Abort(); err == nil {
						aborts.Add(1)
					}
				}
				if err != nil && !errors.Is(err, net.ErrClosed) {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Errorf("round %d: %v, want nil or net.ErrClosed", round, err)
		}
		c, a := closes.Load(), aborts.Load()
		if c > 1 || (c == 0 && a != 1) {
			t.Fatalf("round %d: %d Close and %d Abort calls returned nil; want at most one Close, and exactly one Abort when no Close did", round, c, a)
		}
		if err := client.Abort(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("round %d: Abort after the race = %v, want net.ErrClosed", round, err)
		}
	}
}

// TestCloseDoesNotLeakDescriptors: dial/close cycles return the
// descriptor count to where it started.
func TestCloseDoesNotLeakDescriptors(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	for range 3 { // warm up
		c, s := dialAccept(t, nil, l)
		_ = c.Close()
		_ = s.Abort()
	}
	before := openFds(t)
	for i := range 50 {
		c, s := dialAccept(t, nil, l)
		if err := c.Close(); err != nil {
			t.Fatalf("close %d: %v", i, err)
		}
		if err := s.Abort(); err != nil {
			t.Fatalf("abort %d: %v", i, err)
		}
	}
	if after := openFds(t); after > before {
		t.Errorf("descriptor count grew from %d to %d over 50 dial/close cycles", before, after)
	}
}

// TestCloseReleasesPortForRebind: once both ends and the listener are
// closed, the exact address can be bound again at once.
func TestCloseReleasesPortForRebind(t *testing.T) {
	for attempt := range 5 {
		l, err := Listen("sctp4", loopback4(0))
		if err != nil {
			t.Fatalf("Listen: %v", err)
		}
		bound := listenerAddr(t, l)
		c, s := dialAccept(t, nil, l)
		if err := c.Close(); err != nil {
			t.Fatalf("client Close: %v", err)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("server Close: %v", err)
		}
		if err := l.Close(); err != nil {
			t.Fatalf("listener Close: %v", err)
		}
		l2, err := Listen("sctp4", bound)
		if err != nil {
			t.Fatalf("attempt %d: rebinding %s: %v", attempt, bound, err)
		}
		_ = l2.Close()
	}
}

// TestCloseWithUnreachablePeerReturnsWithinTimeout: with the peer gone
// without answering the SHUTDOWN, Close still returns within its grace
// period.
func TestCloseWithUnreachablePeerReturnsWithinTimeout(t *testing.T) {
	client, server := connPair(t, nil, nil)
	if err := server.Abort(); err != nil {
		t.Fatalf("server Abort: %v", err)
	}
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- client.Close() }()
	select {
	case err := <-done:
		if elapsed := time.Since(start); elapsed > client.closeWait+2*time.Second {
			t.Errorf("Close took %v against a %v grace period", elapsed, client.closeWait)
		}
		if err != nil {
			t.Errorf("Close = %v, want nil", err)
		}
	case <-time.After(client.closeWait + 5*time.Second):
		t.Fatal("Close did not return")
	}
}

// TestCloseAfterCompletedHandshakeGivesPeerEOF: a graceful Close whose
// SHUTDOWN handshake completed releases the descriptor without an ABORT,
// so the peer sees the end of the stream, never ECONNRESET.
func TestCloseAfterCompletedHandshakeGivesPeerEOF(t *testing.T) {
	for i := range 5 {
		client, server := connPair(t, nil, nil)
		for range 4 {
			if err := sendRaw(client, []byte("payload")); err != nil {
				t.Fatalf("round %d: send: %v", i, err)
			}
		}
		buf := make([]byte, 512)
		for range 4 {
			if _, err := server.Read(buf); err != nil {
				t.Fatalf("round %d: drain: %v", i, err)
			}
		}
		if err := client.Close(); err != nil {
			t.Fatalf("round %d: Close: %v", i, err)
		}
		if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		_, err := server.Read(buf)
		if errors.Is(err, syscall.ECONNRESET) {
			t.Errorf("round %d: the peer saw ECONNRESET after a graceful Close", i)
		} else if err != io.EOF {
			t.Errorf("round %d: peer read = %v, want io.EOF", i, err)
		}
	}
}

// TestGracefulCloseSurvivesSignals: a Close under a storm of signals must
// still read as a graceful end at the peer, not an ABORT. A signal
// arriving during the close path's own status-query read makes it return
// EINTR (v1 TestGracefulCloseSurvivesSignals; see signalStorm).
func TestGracefulCloseSurvivesSignals(t *testing.T) {
	stop := signalStorm(t)
	defer stop()
	const rounds = 25
	var reset int
	for i := range rounds {
		client, server := connPair(t, nil, nil)
		if err := server.Close(); err != nil {
			t.Fatalf("round %d: server close: %v", i, err)
		}
		if err := client.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatalf("round %d: deadline: %v", i, err)
		}
		buf := make([]byte, 256)
		_, err := client.Read(buf)
		switch {
		case err == nil:
			// Application data ahead of the shutdown; keep draining.
		case errors.Is(err, syscall.ECONNRESET):
			reset++
		case err != io.EOF:
			t.Errorf("round %d: client read = %v, want io.EOF or a message", i, err)
		}
		_ = client.Close()
	}
	if reset > 0 {
		t.Errorf("%d of %d graceful closes were reported as an ABORT: a "+
			"signal during the close path's own read must not be mistaken "+
			"for the peer having failed", reset, rounds)
	}
}

// TestCloseTerminatesPromptlyUnderSignals bounds Close's retry loop under
// continuous signals: whatever EINTR does to any one syscall in the poll,
// the whole call still returns within its grace period, not after it (v1
// TestCloseTerminatesPromptlyUnderSignals).
func TestCloseTerminatesPromptlyUnderSignals(t *testing.T) {
	stop := signalStorm(t)
	defer stop()
	const rounds = 20
	const grace = 700 * time.Millisecond
	var worst time.Duration
	for range rounds {
		client, _ := connPair(t, nil, nil)
		start := time.Now()
		if err := client.CloseWithTimeout(grace); err != nil {
			t.Fatalf("CloseWithTimeout: %v", err)
		}
		if d := time.Since(start); d > worst {
			worst = d
		}
	}
	t.Logf("worst CloseWithTimeout(%v) across %d rounds under signals: %v", grace, rounds, worst)
	if worst > grace*4 {
		t.Errorf("a close took %v against a %v grace period; the retry loop is not bounded under signals", worst, grace)
	}
}

// TestAssocQueryAnswersForALiveAssociation: the status query Close polls
// reports a live association as live; if it did not, Close would stop
// waiting for the handshake with no other test noticing.
func TestAssocQueryAnswersForALiveAssociation(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	gone, err := client.newCloseOps().assocGone()
	if err != nil || gone {
		t.Fatalf("assocGone = %v, %v; want false, nil for an established association", gone, err)
	}
}

// stalledPair is an association whose client cannot complete a SHUTDOWN:
// its send buffer is full and the server never reads, so the SHUTDOWN
// waits behind data the peer's zero window will not take (RFC 9260 §9.2).
func stalledPair(t *testing.T, cfg *Config) (client, server *Conn) {
	t.Helper()
	client, server = connPair(t, cfg, cfg)
	fillSendBuffer(t, client, fill(512))
	return client, server
}

// TestCloseTimeoutBoundsTheShutdownWait (the socket half of
// TestLifecycleCloseGraceExpiry): against a peer that cannot answer, Close
// spends its grace period and then aborts.
func TestCloseTimeoutBoundsTheShutdownWait(t *testing.T) {
	client, _ := stalledPair(t, nil)
	const budget = 700 * time.Millisecond
	start := time.Now()
	if err := client.CloseWithTimeout(budget); err != nil {
		t.Fatalf("CloseWithTimeout: %v", err)
	}
	if elapsed := time.Since(start); elapsed < budget/2 || elapsed > budget*4 {
		t.Errorf("Close took %v against a %v grace period and a peer that cannot answer", elapsed, budget)
	}
}

// TestCloseWithRespondingPeerReturnsPromptly (the socket half of
// TestLifecycleCloseGraceful): against a peer that answers, Close returns
// as soon as the association is gone, not when its grace period ends.
func TestCloseWithRespondingPeerReturnsPromptly(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	start := time.Now()
	if err := client.CloseWithTimeout(5 * time.Second); err != nil {
		t.Fatalf("CloseWithTimeout: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Close took %v against a peer that answered", elapsed)
	}
}

// TestCloseReleasesPortAfterUnresponsivePeer: the abort at the end of the
// grace period frees the association and its address at once, so it can
// be bound again.
func TestCloseReleasesPortAfterUnresponsivePeer(t *testing.T) {
	client, _ := stalledPair(t, nil)
	local := client.LocalAddr().(*Addr)
	if err := client.CloseWithTimeout(500 * time.Millisecond); err != nil {
		t.Fatalf("CloseWithTimeout: %v", err)
	}
	l, err := Listen("sctp4", &Addr{IPs: local.IPs[:1], Port: local.Port})
	if err != nil {
		t.Fatalf("rebinding %v after closing on an unresponsive peer: %v", local, err)
	}
	_ = l.Close()
}

// TestShutdownThenClose: Shutdown starts the graceful shutdown and returns
// nil, a second Shutdown returns nil too without starting another, the
// peer's reads end with io.EOF once it completes, and a later Close
// returns nil at once since the association is already gone.
func TestShutdownThenClose(t *testing.T) {
	client, server := connPair(t, nil, nil)
	if err := client.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := client.Shutdown(); err != nil {
		t.Fatalf("second Shutdown: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := server.Read(make([]byte, 64)); err != io.EOF {
		t.Errorf("peer read after Shutdown = %v, want io.EOF", err)
	}
	// The association goes away once the peer's kernel has answered.
	deadline := time.Now().Add(5 * time.Second)
	for {
		gone, err := client.newCloseOps().assocGone()
		if err != nil {
			t.Fatalf("assocGone: %v", err)
		}
		if gone {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the association outlived its completed shutdown by 5 s")
		}
		time.Sleep(5 * time.Millisecond)
	}
	start := time.Now()
	if err := client.Close(); err != nil {
		t.Fatalf("Close after Shutdown = %v, want nil", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("Close after a completed Shutdown took %v; it should find the association gone at once", d)
	}
	if err := client.Shutdown(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Shutdown after Close = %v, want net.ErrClosed", err)
	}
}

// TestCloseAbortOvertakes: a Close waiting for a SHUTDOWN handshake that
// cannot complete (a full send buffer, a peer that never reads) is ended
// by an Abort from another goroutine: both return nil, well before the
// grace period would have run out.
func TestCloseAbortOvertakes(t *testing.T) {
	cfg := &Config{CloseTimeout: 10 * time.Second}
	client, _ := stalledPair(t, cfg)
	done := make(chan error, 1)
	go func() { done <- client.Close() }()
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("Close returned %v before the Abort, although the handshake cannot complete", err)
	default:
	}
	start := time.Now()
	if err := client.Abort(); err != nil {
		t.Fatalf("Abort during Close = %v, want nil", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("the overtaken Close = %v, want nil", err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("Close returned %v after the Abort", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close was still waiting 3 s after Abort; the Abort did not overtake it")
	}
	if err := client.Abort(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("a second Abort = %v, want net.ErrClosed", err)
	}
}

// parkRead parks a read through c's RawConn until something ends it, and
// reports what did. It skips notification records, and a zero-length read
// (the end of the stream, or RCV_SHUTDOWN set by the abortive close) sends
// it back to wait: a caller that sees the stream end while the connection
// is being released must still be released with net.ErrClosed, which is
// what the eviction reports.
func parkRead(c *Conn, parked chan<- struct{}) <-chan error {
	done := make(chan error, 1)
	rc, err := c.SyscallConn()
	if err != nil {
		done <- err
		return done
	}
	go func() {
		var once sync.Once
		buf := make([]byte, 256)
		done <- rc.Read(func(fd uintptr) bool {
			once.Do(func() { close(parked) })
			for {
				n, _, flags, _, err := syscall.Recvmsg(int(fd), buf, nil, syscall.MSG_DONTWAIT)
				switch {
				case err == syscall.EAGAIN:
					return false
				case err == nil && flags&msgNotification != 0:
					continue
				case err == nil && n == 0:
					return false
				default:
					return true
				}
			}
		})
	}()
	return done
}

// parkWrite parks a send through c's RawConn on a full send buffer.
func parkWrite(c *Conn, parked chan<- struct{}) <-chan error {
	done := make(chan error, 1)
	rc, err := c.SyscallConn()
	if err != nil {
		done <- err
		return done
	}
	go func() {
		var once sync.Once
		payload := fill(512)
		done <- rc.Write(func(fd uintptr) bool {
			_, err := syscall.SendmsgN(int(fd), payload, nil, nil, syscall.MSG_DONTWAIT|syscall.MSG_NOSIGNAL)
			if err == syscall.EAGAIN {
				once.Do(func() { close(parked) })
				return false
			}
			return true
		})
	}()
	return done
}

// TestCloseReleasesParkedReaderAndWriter: Close from one goroutine while
// another is parked in a read and a third in a send on a full buffer. The
// peer never reads, so the graceful shutdown cannot complete, Close aborts
// at the end of its grace period and releases the descriptor, and both
// parked calls return with net.ErrClosed within a second of Close
// returning. Afterwards the descriptor count is back where it started. It
// runs on a dialed, an accepted and a peeled connection.
func TestCloseReleasesParkedReaderAndWriter(t *testing.T) {
	for _, side := range []string{"dialed", "accepted", "peeled"} {
		t.Run(side, func(t *testing.T) {
			before := openFds(t)
			// Each side gets a receive buffer whose window the other's
			// messages close (closingReadBuffer), whichever side sends.
			cfg := &Config{CloseTimeout: 300 * time.Millisecond, ReadBuffer: new(closingReadBuffer)}
			var (
				c, client, server *Conn
				release           func()
			)
			if side == "peeled" {
				e, err := cfg.ListenEndpoint("sctp4", loopback4(0))
				if err != nil {
					t.Fatalf("ListenEndpoint: %v", err)
				}
				client, err = cfg.Dial(testContext(t, 10*time.Second), "sctp4", nil, endpointAddr(t, e))
				if err != nil {
					t.Fatalf("Dial: %v", err)
				}
				if server, err = e.PeelOff(onlyAssoc(t, e)); err != nil {
					t.Fatalf("PeelOff: %v", err)
				}
				c = server
				release = func() { _ = e.Abort() }
			} else {
				l, err := cfg.Listen("sctp4", loopback4(0))
				if err != nil {
					t.Fatalf("Listen: %v", err)
				}
				client, server = dialAccept(t, cfg, l)
				c = client
				if side == "accepted" {
					c = server
				}
				release = func() { _ = l.Close() }
			}
			receiver := server
			if c == server {
				receiver = client
			}
			fillSendBufferStable(t, c, receiver, fill(512))

			readParked, writeParked := make(chan struct{}), make(chan struct{})
			readDone := parkRead(c, readParked)
			writeDone := parkWrite(c, writeParked)
			<-readParked
			<-writeParked
			time.Sleep(100 * time.Millisecond) // both are waiting in the poller now

			if err := c.Close(); err != nil {
				t.Fatalf("Close = %v, want nil", err)
			}
			closed := time.Now()
			for name, done := range map[string]<-chan error{"read": readDone, "send": writeDone} {
				select {
				case err := <-done:
					if !errors.Is(err, net.ErrClosed) {
						t.Errorf("parked %s returned %v, want net.ErrClosed", name, err)
					}
					if d := time.Since(closed); d > time.Second {
						t.Errorf("parked %s returned %v after Close", name, d)
					}
				case <-time.After(time.Second):
					t.Fatalf("parked %s was still waiting 1 s after Close returned", name)
				}
			}
			_ = client.Abort()
			_ = server.Abort()
			release()
			if after := openFds(t); after != before {
				t.Errorf("descriptor count went %d -> %d", before, after)
			}
		})
	}
}

// TestAbortWithParkedReaderResetsThePeer: Abort while a read is parked on
// the connection still puts the ABORT on the wire at once, so the peer's
// read fails with ECONNRESET. The final close(2), which sends it, runs
// only once the parked read has left the descriptor (internal/poll:
// FD.Close waits for the last reference), which the release's eviction of
// every poller wait guarantees.
func TestAbortWithParkedReaderResetsThePeer(t *testing.T) {
	client, server := connPair(t, nil, nil)
	parked := make(chan struct{})
	done := parkRead(client, parked)
	<-parked
	time.Sleep(100 * time.Millisecond)
	if err := client.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	if err := <-done; !errors.Is(err, net.ErrClosed) {
		t.Errorf("parked read = %v, want net.ErrClosed", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := server.Read(make([]byte, 64)); !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("the peer's read after Abort = %v, want ECONNRESET", err)
	}
}

// TestRawWaitTerminatesOnAbortedAssociation: a send parked on a full
// buffer ends when the peer aborts the association, with the send's own
// error, instead of spinning on a level-triggered EPOLLERR.
func TestRawWaitTerminatesOnAbortedAssociation(t *testing.T) {
	client, server := connPair(t, nil, nil)
	fillSendBuffer(t, client, fill(512))
	if err := server.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	rc := mustSyscallConn(t, client)
	var sendErr error
	done := make(chan error, 1)
	go func() {
		done <- rc.Write(func(fd uintptr) bool {
			_, sendErr = syscall.SendmsgN(int(fd), []byte("x"), nil, nil, syscall.MSG_DONTWAIT|syscall.MSG_NOSIGNAL)
			return sendErr != syscall.EAGAIN
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		if sendErr == nil || sendErr == syscall.EAGAIN {
			t.Errorf("the send ended with %v, want the association's failure", sendErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the parked send never ended on an aborted association")
	}
}

// --- descriptor zero ---------------------------------------------------------

// fdZeroChild runs in a child process: it closes stdin so that the next
// socket the package opens lands on descriptor 0, and checks that closing
// the connection (with Close or Abort, per mode) reports success and
// releases that association's descriptor.
func fdZeroChild(mode string) error {
	l, err := Listen("sctp4", loopback4(0))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	laddr := l.Addr().(*Addr)
	accepted := make(chan *Conn, 1)
	go func() {
		c, err := l.AcceptSCTP()
		if err == nil {
			accepted <- c
		}
	}()
	if err := syscall.Close(0); err != nil {
		return fmt.Errorf("SKIP cannot close stdin: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := Dial(ctx, "sctp4", nil, laddr)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	fd := -1
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	_ = rc.Control(func(f uintptr) { fd = int(f) })
	if fd != 0 {
		return fmt.Errorf("SKIP the association landed on descriptor %d, not 0", fd)
	}
	port, err := localPortOf(0)
	if err != nil {
		return fmt.Errorf("SKIP cannot read the local port of descriptor 0: %w", err)
	}
	// Let the accept finish first, so that its descriptor is allocated
	// before descriptor 0 is released and cannot take 0 back.
	select {
	case <-accepted:
	case <-time.After(10 * time.Second):
		return fmt.Errorf("the association was never accepted")
	}
	if mode == "close" {
		err = c.Close()
	} else {
		err = c.Abort()
	}
	if err != nil {
		return fmt.Errorf("%s on descriptor 0 = %w, want nil", mode, err)
	}
	if !fdIsOpen(0) {
		return nil
	}
	if p, err := localPortOf(0); err == nil && p == port {
		return fmt.Errorf("descriptor 0 is still the association (port %d) after %s", port, mode)
	}
	return nil
}

// localPortOf is the port fd is bound to.
func localPortOf(fd int) (int, error) {
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		return 0, err
	}
	switch a := sa.(type) {
	case *syscall.SockaddrInet4:
		return a.Port, nil
	case *syscall.SockaddrInet6:
		return a.Port, nil
	default:
		return 0, fmt.Errorf("descriptor %d is a %T", fd, sa)
	}
}

// runFdZero runs fdZeroChild(mode) in a child process.
func runFdZero(t *testing.T, test, mode string) {
	if os.Getenv("SCTP_FD_ZERO_CHILD") == mode {
		if err := fdZeroChild(mode); err != nil {
			if strings.HasPrefix(err.Error(), "SKIP") {
				fmt.Println(err)
				return
			}
			t.Fatal(err)
		}
		fmt.Println("descriptor 0 released")
		return
	}
	out, err := runChild(t, test, "SCTP_FD_ZERO_CHILD="+mode)
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	if strings.Contains(out, "SKIP") {
		t.Skipf("child could not set up the case:\n%s", out)
	}
	if !strings.Contains(out, "descriptor 0 released") {
		t.Fatalf("child did not confirm the release:\n%s", out)
	}
}

// TestCloseReleasesFdZero: a connection on descriptor 0, which a daemon
// that closed stdin hands out, is closed and released like any other.
func TestCloseReleasesFdZero(t *testing.T) { runFdZero(t, "TestCloseReleasesFdZero", "close") }

// TestAbortReleasesFdZero is the same for Abort.
func TestAbortReleasesFdZero(t *testing.T) { runFdZero(t, "TestAbortReleasesFdZero", "abort") }

// TestZeroValueConnectionNeverOwnsDescriptorZero: a Conn the package never
// opened (the zero value) owns no descriptor, and its Close and Abort
// report net.ErrClosed without touching descriptor 0.
func TestZeroValueConnectionNeverOwnsDescriptorZero(t *testing.T) {
	var c Conn
	for name, call := range map[string]func() error{"Close": c.Close, "Abort": c.Abort, "Shutdown": c.Shutdown} {
		if err := call(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("zero Conn.%s = %v, want net.ErrClosed", name, err)
		}
	}
	if !fdIsOpen(0) {
		t.Error("descriptor 0 is closed after the zero Conn's Close and Abort")
	}
	if _, err := c.SyscallConn(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("zero Conn.SyscallConn = %v, want net.ErrClosed", err)
	}
}

// --- SyscallConn ---------------------------------------------------------------

// TestSyscallConnWriteWaitsForWritability: a raw send that finds the
// buffer full waits in the poller and retries once the peer drains it.
func TestSyscallConnWriteWaitsForWritability(t *testing.T) {
	client, server := connPair(t, nil, nil)
	payload := fill(512)
	sent := fillSendBuffer(t, client, payload)
	begin := make(chan struct{})
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-begin
		buf := make([]byte, 1<<16)
		for range sent {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()
	if err := client.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	var (
		start sync.Once
		werr  error
		calls int
	)
	if err := mustSyscallConn(t, client).Write(func(fd uintptr) bool {
		calls++
		_, werr = syscall.SendmsgN(int(fd), payload, nil, nil, syscall.MSG_DONTWAIT|syscall.MSG_NOSIGNAL)
		if werr == syscall.EAGAIN {
			start.Do(func() { close(begin) })
			return false
		}
		return true
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if werr != nil {
		t.Fatalf("send: %v", werr)
	}
	if calls < 2 {
		t.Errorf("the callback ran %d time(s); the buffer was full, so it had to wait and retry", calls)
	}
	<-drained
}

// TestSyscallConnReadWaitsForData: a raw read that finds nothing waits in
// the poller and retries once a message arrives.
func TestSyscallConnReadWaitsForData(t *testing.T) {
	client, server := connPair(t, nil, nil)
	if err := server.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	want := []byte("through the raw conn")
	var start sync.Once
	buf := make([]byte, 128)
	var (
		n     int
		rerr  error
		calls int
	)
	if err := mustSyscallConn(t, server).Read(func(fd uintptr) bool {
		calls++
		for {
			var flags int
			n, _, flags, _, rerr = syscall.Recvmsg(int(fd), buf, nil, syscall.MSG_DONTWAIT)
			if rerr == nil && flags&msgNotification != 0 {
				continue
			}
			break
		}
		if rerr == syscall.EAGAIN {
			start.Do(func() { go func() { _ = sendRaw(client, want) }() })
			return false
		}
		return true
	}); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if rerr != nil || string(buf[:n]) != string(want) {
		t.Fatalf("read %q, %v; want %q", buf[:n], rerr, want)
	}
	if calls < 2 {
		t.Errorf("the callback ran %d time(s); nothing was queued, so it had to wait and retry", calls)
	}
}

// TestSyscallConnStopsWhenDone: a callback that reports done on its first
// call ends Read and Write at once.
func TestSyscallConnStopsWhenDone(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	rc := mustSyscallConn(t, client)
	for name, call := range map[string]func(func(uintptr) bool) error{"Read": rc.Read, "Write": rc.Write} {
		calls := 0
		done := make(chan error, 1)
		go func() { done <- call(func(uintptr) bool { calls++; return true }) }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not return although the callback reported done", name)
		}
		if calls != 1 {
			t.Errorf("%s ran the callback %d times, want 1", name, calls)
		}
	}
}

// TestSyscallConnHonoursDeadline: a raw wait ends at the connection's
// deadline with os.ErrDeadlineExceeded inside a *net.OpError.
func TestSyscallConnHonoursDeadline(t *testing.T) {
	for _, tc := range []struct {
		name  string
		full  bool
		setDl func(*Conn, time.Time) error
		call  func(syscall.RawConn, func(uintptr) bool) error
		op    string
	}{
		{"Read", false, (*Conn).SetReadDeadline, func(rc syscall.RawConn, f func(uintptr) bool) error { return rc.Read(f) }, "raw-read"},
		{"Write", true, (*Conn).SetWriteDeadline, func(rc syscall.RawConn, f func(uintptr) bool) error { return rc.Write(f) }, "raw-write"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := connPair(t, nil, nil)
			if tc.full {
				fillSendBuffer(t, client, fill(512))
			}
			if err := tc.setDl(client, time.Now().Add(300*time.Millisecond)); err != nil {
				t.Fatalf("set deadline: %v", err)
			}
			start := time.Now()
			err := tc.call(mustSyscallConn(t, client), func(uintptr) bool { return false })
			elapsed := time.Since(start)
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
			}
			var opErr *net.OpError
			if !errors.As(err, &opErr) || opErr.Op != tc.op || !opErr.Timeout() {
				t.Errorf("err = %#v, want a timeout *net.OpError with Op %s", err, tc.op)
			}
			if elapsed < 250*time.Millisecond || elapsed > 10*time.Second {
				t.Errorf("returned after %v against a 300 ms deadline", elapsed)
			}
		})
	}
}

// TestSyscallConnAfterCloseReturnsNetErrClosed: a RawConn kept past Close
// reports net.ErrClosed without running its callback, and SyscallConn
// itself refuses a released connection.
func TestSyscallConnAfterCloseReturnsNetErrClosed(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	rc := mustSyscallConn(t, client)
	if err := client.CloseWithTimeout(200 * time.Millisecond); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for name, call := range map[string]func(*bool) error{
		"Control": func(c *bool) error { return rc.Control(func(uintptr) { *c = true }) },
		"Read":    func(c *bool) error { return rc.Read(func(uintptr) bool { *c = true; return true }) },
		"Write":   func(c *bool) error { return rc.Write(func(uintptr) bool { *c = true; return true }) },
	} {
		called := false
		if err := call(&called); !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s after Close = %v, want net.ErrClosed", name, err)
		}
		if called {
			t.Errorf("%s ran its callback on a released descriptor", name)
		}
	}
	if _, err := client.SyscallConn(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("SyscallConn after Close = %v, want net.ErrClosed", err)
	}
	for name, err := range map[string]error{
		"SetDeadline": client.SetDeadline(time.Now()),
		"LocalAddrs":  func() error { _, err := client.LocalAddrs(); return err }(),
		"PeerAddrs":   func() error { _, err := client.PeerAddrs(); return err }(),
	} {
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s after Close = %v, want net.ErrClosed", name, err)
		}
	}
}

// TestSyscallConnDoesNotSpinWhenReadyButNotDone: with the descriptor
// writable and a callback that never reports done, the edge-triggered
// poller parks instead of calling the callback in a loop.
func TestSyscallConnDoesNotSpinWhenReadyButNotDone(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	if err := client.SetWriteDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	calls := 0
	err := mustSyscallConn(t, client).Write(func(uintptr) bool { calls++; return false })
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("err = %v, want os.ErrDeadlineExceeded", err)
	}
	if calls < 1 || calls > 5000 {
		t.Errorf("the callback ran %d times over 300 ms", calls)
	}
}

// TestSyscallConnCloseUnblocksWait: a raw read parked with no deadline
// returns net.ErrClosed when Close releases the descriptor.
func TestSyscallConnCloseUnblocksWait(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	parked := make(chan struct{})
	done := parkRead(client, parked)
	<-parked
	time.Sleep(100 * time.Millisecond)
	if err := client.CloseWithTimeout(200 * time.Millisecond); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("parked read = %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the parked read never returned after Close")
	}
}

// TestSyscallConnAbortUnblocksWait is the same for Abort.
func TestSyscallConnAbortUnblocksWait(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	parked := make(chan struct{})
	done := parkRead(client, parked)
	<-parked
	time.Sleep(150 * time.Millisecond)
	if err := client.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("parked read = %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the parked read never returned after Abort")
	}
}

// TestSyscallConnConcurrent: several raw writers and a raw reader on one
// association, for the race detector.
func TestSyscallConnConcurrent(t *testing.T) {
	client, server := connPair(t, nil, nil)
	if err := client.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	const writers, each = 4, 50
	var delivered atomic.Int64
	stop := make(chan struct{})
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		buf := make([]byte, 1<<16)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := server.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
				return
			}
			if _, err := server.Read(buf); err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					continue
				}
				return
			}
			delivered.Add(1)
		}
	}()
	payload := fill(1024)
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				if err := sendRaw(client, payload); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent raw send: %v", err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && delivered.Load() < writers*each {
		time.Sleep(10 * time.Millisecond)
	}
	if got := delivered.Load(); got != writers*each {
		t.Errorf("delivered %d of %d messages", got, writers*each)
	}
	close(stop)
	<-drained
}
