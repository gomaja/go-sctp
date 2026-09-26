// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

// --- a Conn without a descriptor ----------------------------------------------

// fakeRawConn is a syscall.RawConn with no poller behind it: Read and Write
// call their callback, and when the callback asks to wait, park decides
// what happens: nil tries again, as a wake-up would, and an error ends the
// call with it, as a deadline or Close would. Control runs its callback
// once. The descriptor number handed to callbacks is meaningless; the
// system calls are the tests' hooks.
type fakeRawConn struct {
	park      func() error // Read's wait; nil means it never waits
	parkWrite func() error // Write's wait
	before    func()       // called before every Read callback
}

// errNeverWakes is what a fake poller wait reports when nothing would ever
// wake the call.
var errNeverWakes = errors.New("parked with nothing to wake it")

func (r *fakeRawConn) Control(f func(fd uintptr)) error { f(^uintptr(0)); return nil }

func (r *fakeRawConn) Read(f func(fd uintptr) bool) error {
	for {
		if r.before != nil {
			r.before()
		}
		if f(^uintptr(0)) {
			return nil
		}
		if r.park == nil {
			return errNeverWakes
		}
		if err := r.park(); err != nil {
			return err
		}
	}
}

func (r *fakeRawConn) Write(f func(fd uintptr) bool) error {
	for !f(^uintptr(0)) {
		if r.parkWrite == nil {
			return errNeverWakes
		}
		if err := r.parkWrite(); err != nil {
			return err
		}
	}
	return nil
}

// fakeConn builds a Conn over raw that never touches a descriptor, with
// handler and the caller's subscriptions subs. Its reads and sends run
// through the package's own paths, with every recvmsg and sendmsg handed
// to testHookRecvmsg and testHookSendmsg.
func fakeConn(raw *fakeRawConn, handler NotificationHandler, subs ...EventType) *Conn {
	c := &Conn{
		sock:    socket{raw: raw, family: afInet, network: "sctp4"},
		kind:    kindDialed,
		assoc:   7,
		handler: handler,
	}
	var set eventSet
	for _, t := range subs {
		set |= eventBit(t)
	}
	c.subs.Store(uint32(set))
	c.laddr.Store(&Addr{})
	c.raddr.Store(&Addr{})
	c.life.init()
	c.recv.init(c)
	c.send.bind(&c.term)
	return c
}

// hookRecvmsg installs f as the receive path's recvmsg for the rest of the
// test.
func hookRecvmsg(t testing.TB, f func(fd int, msg *syscall.Msghdr, flags int) (int, error)) {
	t.Helper()
	testHookRecvmsg = f
	t.Cleanup(func() { testHookRecvmsg = nil })
}

// iovBytes is the buffer msg's one iovec points at.
func iovBytes(msg *syscall.Msghdr) []byte {
	return unsafe.Slice(msg.Iov.Base, int(msg.Iov.Len))
}

// assocChangeRecord builds an SCTP_ASSOC_CHANGE record (RFC 6458 §6.1.1)
// for state and association id, with info as sac_info.
func assocChangeRecord(state AssocChangeState, id AssocID, info []byte) []byte {
	b := notif(EventAssocChange, sizeAssocChange+len(info))
	binary.NativeEndian.PutUint16(b[assocChangeStateOff:], uint16(state))
	binary.NativeEndian.PutUint32(b[assocChangeAssocIDOff:], uint32(id))
	copy(b[assocChangeInfoOff:], info)
	return b
}

// deliver writes up to what fits of rec[off:] into msg as recvmsg would,
// flagged MSG_NOTIFICATION when note is set and MSG_EOR when it ends rec,
// and returns how much it wrote. It is what a scripted recvmsg returns
// for a record the kernel delivers in pieces.
func deliver(msg *syscall.Msghdr, rec []byte, off int, note bool) int {
	n := copy(iovBytes(msg), rec[off:])
	var flags int32
	if note {
		flags |= msgNotification
	}
	if off+n == len(rec) {
		flags |= msgEOR
	}
	msg.Flags = flags
	msg.SetControllen(0)
	return n
}

// --- the latch helpers --------------------------------------------------------

// TestTermStateRules checks the latch helpers the send and receive paths
// share, without a socket.
func TestTermStateRules(t *testing.T) {
	var term termState
	if err := term.latched(); err != nil {
		t.Fatalf("a new latch holds %v", err)
	}
	term.mu.Lock()
	if term.storeLocked(syscall.EPIPE) || term.storeLocked(syscall.EAGAIN) || term.err != nil {
		t.Error("an errno that is not an association failure was latched")
	}
	if !term.storeLocked(syscall.ETIMEDOUT) {
		t.Error("ETIMEDOUT was not recognised as an association failure")
	}
	term.storeLocked(syscall.ECONNRESET)
	if term.err != syscall.ETIMEDOUT {
		t.Errorf("latch = %v after a second failure, want the first, ETIMEDOUT", term.err)
	}
	if got := term.sendErrorLocked(syscall.EPIPE); got != syscall.ETIMEDOUT {
		t.Errorf("EPIPE with the latch set = %v, want the latched ETIMEDOUT", got)
	}
	term.mu.Unlock()

	var fresh termState
	fresh.markFailed()
	fresh.mu.Lock()
	if got := fresh.sendErrorLocked(syscall.EPIPE); got != syscall.ENOTCONN || fresh.err != syscall.ENOTCONN {
		t.Errorf("EPIPE on a failed connection = %v, latch %v; want ENOTCONN latched", got, fresh.err)
	}
	fresh.mu.Unlock()
}

// TestTermReadRules checks the read side of the latch: what one recvmsg's
// result becomes, for every state the latch can be in, and what later
// reads report without a system call.
func TestTermReadRules(t *testing.T) {
	for _, tc := range []struct {
		name           string
		latch          error
		failed, ended  bool
		got            error // what recvmsg found: an errno, or io.EOF for zero bytes
		want           error
		wantLatch      error
		wantEndWithout error // what the next read reports without a system call
	}{
		{name: "EAGAIN, nothing known", got: syscall.EAGAIN, want: syscall.EAGAIN},
		{name: "end of stream, nothing known", got: io.EOF, want: io.EOF},
		{name: "ECONNRESET taken", got: syscall.ECONNRESET, want: syscall.ECONNRESET, wantLatch: syscall.ECONNRESET, wantEndWithout: syscall.ECONNRESET},
		{name: "ETIMEDOUT taken", got: syscall.ETIMEDOUT, want: syscall.ETIMEDOUT, wantLatch: syscall.ETIMEDOUT, wantEndWithout: syscall.ETIMEDOUT},
		{name: "ECONNABORTED taken", got: syscall.ECONNABORTED, want: syscall.ECONNABORTED, wantLatch: syscall.ECONNABORTED, wantEndWithout: syscall.ECONNABORTED},
		{name: "EAGAIN, a send took the error", latch: syscall.ECONNRESET, got: syscall.EAGAIN, want: syscall.ECONNRESET, wantLatch: syscall.ECONNRESET, wantEndWithout: syscall.ECONNRESET},
		{name: "end of stream, a send took the error", latch: syscall.ETIMEDOUT, got: io.EOF, want: syscall.ETIMEDOUT, wantLatch: syscall.ETIMEDOUT, wantEndWithout: syscall.ETIMEDOUT},
		{name: "a second failure keeps the first", latch: syscall.ETIMEDOUT, got: syscall.ECONNRESET, want: syscall.ETIMEDOUT, wantLatch: syscall.ETIMEDOUT, wantEndWithout: syscall.ETIMEDOUT},
		{name: "EAGAIN after AssocCommLost, error out of reach", failed: true, got: syscall.EAGAIN, want: syscall.ENOTCONN, wantLatch: syscall.ENOTCONN, wantEndWithout: syscall.ENOTCONN},
		{name: "end of stream after AssocCommLost, failed before Accept", failed: true, got: io.EOF, want: syscall.ENOTCONN, wantLatch: syscall.ENOTCONN, wantEndWithout: syscall.ENOTCONN},
		{name: "the error after AssocCommLost", failed: true, got: syscall.ECONNRESET, want: syscall.ECONNRESET, wantLatch: syscall.ECONNRESET, wantEndWithout: syscall.ECONNRESET},
		{name: "EAGAIN after AssocShutdownComplete", ended: true, got: syscall.EAGAIN, want: io.EOF, wantEndWithout: io.EOF},
		{name: "another errno", got: syscall.EIO, want: syscall.EIO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			term := termState{err: tc.latch, failed: tc.failed, ended: tc.ended}
			term.mu.Lock()
			got := term.readErrorLocked(tc.got)
			latch := term.err
			term.mu.Unlock()
			if got != tc.want {
				t.Errorf("readErrorLocked(%v) = %v, want %v", tc.got, got, tc.want)
			}
			if latch != tc.wantLatch {
				t.Errorf("latch = %v, want %v", latch, tc.wantLatch)
			}
			if end := term.readEnd(); end != tc.wantEndWithout {
				t.Errorf("readEnd = %v, want %v", end, tc.wantEndWithout)
			}
		})
	}

	var term termState
	term.mu.Lock()
	if got := term.observe(syscall.EAGAIN); got != syscall.EAGAIN || term.err != nil {
		t.Errorf("observe(EAGAIN) on an empty latch = %v, latch %v", got, term.err)
	}
	if got := term.observe(syscall.ECONNABORTED); got != syscall.ECONNABORTED || term.err != syscall.ECONNABORTED {
		t.Errorf("observe(ECONNABORTED) = %v, latch %v", got, term.err)
	}
	if got := term.observe(syscall.EPIPE); got != syscall.ECONNABORTED {
		t.Errorf("observe(EPIPE) with the latch set = %v, want the latch", got)
	}
	term.mu.Unlock()
	if term.readEnd() != nil {
		t.Error("observe alone marked the reads drained")
	}
}

// TestAbortedErrorRepeatsOnReadsAndSends checks the public paths over a
// scripted connection after the association error has been latched.
func TestAbortedErrorRepeatsOnReadsAndSends(t *testing.T) {
	c := fakeConn(&fakeRawConn{}, nil)
	var recvCalls, sendCalls int
	hookRecvmsg(t, func(int, *syscall.Msghdr, int) (int, error) {
		recvCalls++
		return 0, syscall.ECONNABORTED
	})
	hookSendmsg(t, func(int, *syscall.Msghdr, int) (int, error) {
		sendCalls++
		return 0, syscall.EIO
	})
	for i := range 3 {
		if _, err := c.Read(make([]byte, 16)); !errors.Is(err, syscall.ECONNABORTED) {
			t.Errorf("Read %d = %v, want ECONNABORTED", i, err)
		}
		if _, _, err := c.RecvMsg(make([]byte, 16)); !errors.Is(err, syscall.ECONNABORTED) {
			t.Errorf("RecvMsg %d = %v, want ECONNABORTED", i, err)
		}
		if _, err := c.Write([]byte("x")); !errors.Is(err, syscall.ECONNABORTED) {
			t.Errorf("Write %d = %v, want ECONNABORTED", i, err)
		}
		if _, err := c.SendMsg([]byte("x"), SendOptions{}); !errors.Is(err, syscall.ECONNABORTED) {
			t.Errorf("SendMsg %d = %v, want ECONNABORTED", i, err)
		}
	}
	if recvCalls != 1 || sendCalls != 0 {
		t.Errorf("system calls after latching ECONNABORTED: %d recvmsg, %d sendmsg; want 1 and 0", recvCalls, sendCalls)
	}
}

// --- every ordering of the end ------------------------------------------------

// latchWorld is a model of one socket at the moment its association fails:
// Linux sets the socket error, queues an AssocCommLost record unless
// record is false (it gives up on the record when it cannot allocate it:
// net/sctp/sm_sideeffect.c, sctp_cmd_assoc_failed), and wakes whoever
// waits on the socket (sctp_cmd_new_state calls sk_state_change). Each
// recvmsg dequeues the record, then takes the error, then answers EAGAIN
// (net/sctp/socket.c: sctp_skb_recv_datagram); each sendmsg takes the
// error, or answers EPIPE (sctp_error); SO_ERROR read from outside takes
// it too (sock_error).
type latchWorld struct {
	record  bool
	skErr   syscall.Errno
	queued  int
	wakes   int
	takenBy string // who took the socket error: "reader", "sender" or "outside"

	recvCalls, sendCalls int
	recordSeen           bool // the reader has dequeued the record
}

func (w *latchWorld) fail() {
	w.skErr = syscall.ECONNRESET
	if w.record {
		w.queued++
	}
	w.wakes++
}

func (w *latchWorld) take(who string) syscall.Errno {
	e := w.skErr
	w.skErr = 0
	if e != 0 && w.takenBy == "" {
		w.takenBy = who
	}
	return e
}

// TestLatchOrdering drives the read and send callbacks through every
// ordering of what can happen when an association fails: the failure
// itself, before or after a reader has parked; a sender taking the socket
// error; something outside the package taking it (SO_ERROR); the
// AssocCommLost record queued or not. The reader must never park while
// the latch holds an error, and must end with the error Linux reported
// (ECONNRESET) whenever a call of the package took it, or ENOTCONN when
// something outside did, with every later read and send reporting the
// same without a system call. The one ordering that parks for ever is
// the one nothing can resolve: the error taken outside and no record
// queued, which Linux reports nowhere else.
func TestLatchOrdering(t *testing.T) {
	type event struct {
		slot int
		what byte // 'F' failure, 'S' send, 'X' SO_ERROR taken outside
	}
	var scripts [][]event
	for slotF := 0; slotF <= 1; slotF++ {
		for s := -1; s <= 2; s++ {
			for x := -1; x <= 2; x++ {
				for _, xFirst := range []bool{false, true} {
					if (s < 0 || x < 0 || s != x) && xFirst {
						continue // the order within a slot matters only when both share it
					}
					script := []event{{slotF, 'F'}}
					evs := []event{}
					if s >= 0 {
						evs = append(evs, event{slotF + s, 'S'})
					}
					if x >= 0 {
						evs = append(evs, event{slotF + x, 'X'})
					}
					if xFirst {
						evs[0], evs[1] = evs[1], evs[0]
					}
					scripts = append(scripts, append(script, evs...))
				}
			}
		}
	}

	for _, record := range []bool{true, false} {
		for _, script := range scripts {
			var name strings.Builder
			fmt.Fprintf(&name, "record=%t", record)
			for _, e := range script {
				fmt.Fprintf(&name, "/%c@%d", e.what, e.slot)
			}
			t.Run(name.String(), func(t *testing.T) {
				w := &latchWorld{record: record}
				raw := &fakeRawConn{}
				c := fakeConn(raw, nil)
				var sendErr error
				sent := false
				recordSeenAtSend := false
				attempt := 0
				apply := func(slot int) {
					for _, e := range script {
						if e.slot != slot {
							continue
						}
						switch e.what {
						case 'F':
							w.fail()
						case 'X':
							_ = w.take("outside")
						case 'S':
							recordSeenAtSend = w.recordSeen
							_, sendErr = c.SendMsg([]byte("x"), SendOptions{})
							sent = true
						}
					}
				}
				raw.before = func() { apply(attempt); attempt++ }
				raw.park = func() error {
					if err := c.term.latched(); err != nil {
						t.Errorf("the reader parked with %v latched", err)
					}
					for w.wakes == 0 {
						if attempt > 4 {
							return errNeverWakes
						}
						apply(attempt) // what happens while it waits
						attempt++
					}
					w.wakes--
					return nil
				}
				hookRecvmsg(t, func(_ int, msg *syscall.Msghdr, _ int) (int, error) {
					w.recvCalls++
					switch {
					case w.queued > 0:
						w.queued--
						w.recordSeen = true
						return deliver(msg, assocChangeRecord(AssocCommLost, 7, nil), 0, true), nil
					case w.skErr != 0:
						return 0, w.take("reader")
					}
					return 0, syscall.EAGAIN
				})
				hookSendmsg(t, func(int, *syscall.Msghdr, int) (int, error) {
					w.sendCalls++
					if e := w.take("sender"); e != 0 {
						return 0, e
					}
					return 0, syscall.EPIPE
				})

				_, err := c.Read(make([]byte, 256))
				// Events the reader never reached still happen.
				for ; attempt <= 4; attempt++ {
					apply(attempt)
				}

				if errors.Is(err, errNeverWakes) {
					if w.takenBy != "outside" || record {
						t.Fatalf("the reader parked for ever (error taken by %q, record %t)", w.takenBy, record)
					}
					return
				}
				want := syscall.ECONNRESET
				if w.takenBy == "outside" {
					want = syscall.ENOTCONN
				}
				if !errors.Is(err, want) {
					t.Fatalf("Read = %v, want %v (error taken by %q)", err, want, w.takenBy)
				}
				if sent {
					switch {
					case w.takenBy == "sender":
						if !errors.Is(sendErr, syscall.ECONNRESET) {
							t.Errorf("the send that took the error returned %v", sendErr)
						}
					case errors.Is(sendErr, syscall.EPIPE):
						// Only a send that came before the reader saw
						// the failure, with the error gone outside.
						if w.takenBy != "outside" || recordSeenAtSend {
							t.Errorf("send = EPIPE, but the error was taken by %q (record seen %t)", w.takenBy, recordSeenAtSend)
						}
					case !errors.Is(sendErr, want):
						t.Errorf("send = %v, want %v", sendErr, want)
					}
				}

				recvCalls, sendCalls := w.recvCalls, w.sendCalls
				for range 3 {
					if _, err := c.Read(make([]byte, 16)); !errors.Is(err, want) {
						t.Errorf("a later Read = %v, want %v", err, want)
					}
					if _, err := c.Write([]byte("y")); !errors.Is(err, want) {
						t.Errorf("a later Write = %v, want %v", err, want)
					}
				}
				if w.recvCalls != recvCalls || w.sendCalls != sendCalls {
					t.Errorf("later calls made %d recvmsg and %d sendmsg calls, want none",
						w.recvCalls-recvCalls, w.sendCalls-sendCalls)
				}
			})
		}
	}
}

// TestPeeledEOFSendLatches: the SCTP_EOF send that shuts a peeled
// connection down is made under the latch, like every send, so that when
// it takes the error Linux set for a failed association, the error is
// latched for every later read and send; once the latch holds an error,
// there is nothing to shut down and no send is made.
func TestPeeledEOFSendLatches(t *testing.T) {
	c := fakeConn(&fakeRawConn{}, nil)
	c.kind = kindPeeled
	var calls int
	var held bool
	hookSendmsg(t, func(_ int, msg *syscall.Msghdr, _ int) (int, error) {
		calls++
		held = !c.term.mu.TryLock()
		if !held {
			c.term.mu.Unlock()
		}
		if msg.Iov != nil && msg.Iovlen != 0 {
			t.Error("the SCTP_EOF send carries a payload")
		}
		return 0, syscall.ECONNRESET
	})
	err := c.Shutdown()
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("Shutdown = %v, want ECONNRESET", err)
	}
	if !held {
		t.Error("the SCTP_EOF send was made without the latch mutex")
	}
	if got := c.term.latched(); got != syscall.ECONNRESET {
		t.Fatalf("the latch holds %v after the SCTP_EOF send took ECONNRESET", got)
	}
	if _, err := c.Write([]byte("x")); !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("Write after the latched EOF send = %v", err)
	}

	d := fakeConn(&fakeRawConn{}, nil)
	d.kind = kindPeeled
	d.term.err = syscall.ETIMEDOUT
	calls = 0
	if err := d.Shutdown(); !errors.Is(err, syscall.ETIMEDOUT) {
		t.Errorf("Shutdown with the latch set = %v, want the latched ETIMEDOUT", err)
	}
	if calls != 0 {
		t.Errorf("Shutdown with the latch set made %d sends, want none", calls)
	}
}
