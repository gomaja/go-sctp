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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// A Conn is a net.Conn, and a Listener a net.Listener.
var (
	_ net.Conn     = (*Conn)(nil)
	_ net.Listener = (*Listener)(nil)
)

// --- helpers ------------------------------------------------------------------

// scriptConn builds a Conn over one end of an AF_UNIX socket pair, whose
// every recvmsg is a test's hook: the runtime poller, the receive lock, the
// latch, reassembly, the ancillary-data parser and the notification policy
// are the package's own, and a read the script leaves waiting waits in the
// poller, where a deadline or Close ends it. The connection has handler and
// the caller's subscriptions subs.
func scriptConn(t testing.TB, handler NotificationHandler, subs ...EventType) *Conn {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	s, err := wrapSocketFile(fds[0], afInet, "sctp4")
	if err != nil {
		_ = syscall.Close(fds[1])
		t.Fatalf("wrapSocketFile: %v", err)
	}
	c := &Conn{sock: s, kind: kindDialed, assoc: 7, handler: handler}
	var set eventSet
	for _, e := range subs {
		set |= eventBit(e)
	}
	c.subs.Store(uint32(set))
	c.laddr.Store(&Addr{})
	c.raddr.Store(&Addr{})
	c.life.init()
	c.recv.init(c)
	c.send.bind(&c.term)
	scriptPeers.Store(c, fds[1])
	t.Cleanup(func() {
		_ = c.Abort()
		scriptPeers.Delete(c)
		_ = syscall.Close(fds[1])
	})
	return c
}

// scriptPeers holds the other end of each scriptConn's socket pair.
var scriptPeers sync.Map

// wakeScripted makes a scriptConn's descriptor readable, as a record
// arriving would, so that a read parked in the poller runs its callback
// again.
func wakeScripted(t testing.TB, c *Conn) {
	t.Helper()
	fd, ok := scriptPeers.Load(c)
	if !ok {
		t.Fatal("not a scripted connection")
	}
	if _, err := syscall.Write(fd.(int), []byte{0}); err != nil {
		t.Fatalf("waking the scripted connection: %v", err)
	}
}

// recvStep is one record the scripted kernel holds: data delivered in as
// many pieces as the reader's buffer needs, flagged as a notification or
// ending a message, with an SCTP_RCVINFO or SCTP_NXTINFO record, or raw
// control bytes, attached to every piece; or an error recvmsg returns
// instead.
type recvStep struct {
	data  []byte
	rcv   *RcvInfo
	nxt   *NxtInfo
	ctl   []byte
	flags int32 // msgNotification, msgEOR, msgCtrunc
	err   error
}

// recvScript is a scripted receive queue. A step's data is handed over as
// recvmsg would hand it over, what does not fit left for the next call,
// without MSG_EOR until its last piece; an empty step with no error is the
// end of the stream. The control buffer is poisoned before every call, so
// that a result still pointing into it changes as soon as the next call
// comes. Once the script is over, recvmsg returns done, EIO when that is
// nil.
type recvScript struct {
	steps []recvStep
	step  int
	off   int
	calls int
	done  error
}

func (s *recvScript) recvmsg(_ int, msg *syscall.Msghdr, _ int) (int, error) {
	s.calls++
	ctl := unsafe.Slice(msg.Control, int(msg.Controllen))
	for i := range ctl {
		ctl[i] = byte(0xa0 + s.calls%31)
	}
	msg.SetControllen(0)
	msg.Flags = 0
	if s.step >= len(s.steps) {
		if s.done != nil {
			return 0, s.done
		}
		return 0, syscall.EIO
	}
	cur := &s.steps[s.step]
	if cur.err != nil {
		s.step++
		return 0, cur.err
	}
	control := cur.ctl
	if control == nil {
		control = recvControl(cur.rcv, cur.nxt)
	}
	msg.SetControllen(copy(ctl, control))
	n := copy(iovBytes(msg), cur.data[s.off:])
	s.off += n
	flags := cur.flags
	if s.off < len(cur.data) {
		flags &^= msgEOR
	} else {
		s.step++
		s.off = 0
	}
	msg.Flags = flags
	return n, nil
}

// recvControl builds the ancillary data recvmsg returns with rcv and nxt:
// NXTINFO first, as sctp_recvmsg writes it (net/sctp/socket.c).
func recvControl(rcv *RcvInfo, nxt *NxtInfo) []byte {
	var b []byte
	if nxt != nil {
		b = buildRecvCmsg(b, cmsgNxtInfo, nxtInfoPayload(nxt.Stream, nxt.Unordered, nxt.Notification, nxt.PPID, nxt.Length, uint32(nxt.AssocID)))
	}
	if rcv != nil {
		b = buildRecvCmsg(b, cmsgRcvInfo, rcvInfoPayload(rcv.Stream, rcv.SSN, rcv.Unordered, rcv.PPID, rcv.TSN, rcv.CumTSN, rcv.Context, uint32(rcv.AssocID)))
	}
	return b
}

// wantReadError asserts that err is a *net.OpError with Op "read"
// matching target.
func wantReadError(t testing.TB, err, target error) {
	t.Helper()
	_ = readOpError(t, err, target)
}

// readOpError is wantReadError, returning the *net.OpError.
func readOpError(t testing.TB, err, target error) *net.OpError {
	t.Helper()
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "read" {
		t.Fatalf("err = %#v (%v), want a *net.OpError with Op read", err, err)
	}
	if !errors.Is(err, target) {
		t.Fatalf("err = %v, want it to match %v", err, target)
	}
	return opErr
}

// setReadDeadline sets c's read deadline d from now, failing the test when
// it cannot.
func setReadDeadline(t testing.TB, c *Conn, d time.Duration) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
}

// waitGone waits until c's association is gone, as SCTP_STATUS reports it,
// without taking anything from the socket: the error Linux sets when the
// association fails stays for a read or send to take.
func waitGone(t testing.TB, c *Conn) {
	t.Helper()
	rc := mustSyscallConn(t, c)
	deadline := time.Now().Add(5 * time.Second)
	for {
		gone := false
		if err := rc.Control(func(fd uintptr) { gone = assocEnded(int(fd)) }); err != nil {
			t.Fatalf("Control: %v", err)
		}
		if gone {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the association is still there 5 s after it was ended")
		}
		time.Sleep(time.Millisecond)
	}
}

// readAll reads c with RecvMsg into a buffer of size bytes until the read
// fails, returning every message and notification, each reassembled from
// its pieces, and the error that ended it.
type recvItem struct {
	data []byte
	info MsgInfo
}

func readAll(c *Conn, size int) ([]recvItem, error) {
	var (
		items []recvItem
		cur   []byte
	)
	buf := make([]byte, size)
	for {
		n, info, err := c.RecvMsg(buf)
		if err != nil {
			return items, err
		}
		cur = append(cur, buf[:n]...)
		if info.EOR {
			items = append(items, recvItem{data: cur, info: info})
			cur = nil
		}
	}
}

// --- RecvMsg and Read ---------------------------------------------------------

// TestRecvMsgReportsTruncation: a message longer than the buffer comes back
// in pieces, EOR clear until the last, every piece with the message's
// SCTP_RCVINFO, and nothing of it lost; one that fits comes back whole with
// EOR (v1 TestSCTPReadFlagsReportsTruncation). Read returns the same
// pieces with nothing to mark where the message ends
// (v1 TestSCTPReadLosesTruncationSignal).
func TestRecvMsgReportsTruncation(t *testing.T) {
	client, server := connPair(t, nil, nil)
	setReadDeadline(t, server, 10*time.Second)
	const bufSize = 1500
	for i, size := range []int{1024, 1400, 1500, 1600, 4096, 16384} {
		msg := bytes.Repeat([]byte{byte(size % 251)}, size)
		info := &SndInfo{Stream: uint16(i % 3), PPID: uint32(0x1000 + i)}
		if _, err := client.SendMsg(msg, SendOptions{Info: info}); err != nil {
			t.Fatalf("SendMsg %d: %v", size, err)
		}
		var (
			got       []byte
			reads     int
			truncated bool
		)
		buf := make([]byte, bufSize)
		for {
			n, mi, err := server.RecvMsg(buf)
			if err != nil {
				t.Fatalf("size %d: RecvMsg: %v", size, err)
			}
			reads++
			got = append(got, buf[:n]...)
			if mi.Notification || mi.Rcv.Stream != info.Stream || mi.Rcv.PPID != info.PPID {
				t.Fatalf("size %d: piece %d metadata %+v, want stream %d and PPID %#x", size, reads, mi, info.Stream, info.PPID)
			}
			if mi.EOR {
				break
			}
			truncated = true
			if reads > 64 {
				t.Fatalf("size %d: 64 reads without EOR", size)
			}
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("size %d: reassembled %d bytes, want %d", size, len(got), size)
		}
		if want := size > bufSize; truncated != want {
			t.Errorf("size %d: EOR clear on some piece = %t, want %t", size, truncated, want)
		}
	}

	msg := bytes.Repeat([]byte{0xab}, 4096)
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, bufSize)
	var got []byte
	for len(got) < len(msg) {
		n, err := server.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if len(got) == 0 && n != bufSize {
			t.Fatalf("the first Read of a longer message returned %d bytes, want a full %d", n, bufSize)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, msg) {
		t.Error("Read's pieces do not make up the message")
	}
}

// TestReadWithZeroLengthBufferConsumesNothing: Read and RecvMsg with an
// empty buffer return 0 and nil, as io.Reader requires, and consume nothing
// (v1 TestReadWithZeroLengthBufferConsumesNothing,
// TestReadIntoFullBufferTailIsNotAConsumingRead).
func TestReadWithZeroLengthBufferConsumesNothing(t *testing.T) {
	client, server := connPair(t, nil, nil)
	const payload = "ABCDEFGH"
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	for _, tc := range []struct {
		name string
		read func() (int, error)
	}{
		{"Read(nil)", func() (int, error) { return server.Read(nil) }},
		{"Read([]byte{})", func() (int, error) { return server.Read([]byte{}) }},
		{"Read(full tail)", func() (int, error) { b := make([]byte, 4); return server.Read(b[4:]) }},
		{"RecvMsg(nil)", func() (int, error) { n, _, err := server.RecvMsg(nil); return n, err }},
	} {
		if n, err := tc.read(); n != 0 || err != nil {
			t.Errorf("%s = (%d, %v), want (0, nil)", tc.name, n, err)
		}
	}
	setReadDeadline(t, server, 5*time.Second)
	buf := make([]byte, 64)
	n, err := server.Read(buf)
	if err != nil || string(buf[:n]) != payload {
		t.Fatalf("Read after the empty reads = %q, %v; want %q whole", buf[:n], err, payload)
	}
}

// TestRecvMsgControlBufferHoldsEveryRecord: with ReceiveNxtInfo on and a
// second message queued, one read carries both SCTP_NXTINFO and
// SCTP_RCVINFO, and the control buffer holds them without MSG_CTRUNC
// (v1 TestPooledOobHoldsEveryInfoCmsgAtOnce); Nxt describes the next
// message, and a value kept from one read is unchanged by the next
// (v1 TestPooledOobSurvivesReuse).
func TestRecvMsgControlBufferHoldsEveryRecord(t *testing.T) {
	client, server := connPair(t, &Config{NoDelay: new(true)}, &Config{ReceiveNxtInfo: new(true)})
	first, second := []byte("first message"), []byte("the second, longer message")
	if _, err := client.SendMsg(first, SendOptions{Info: &SndInfo{Stream: 1, PPID: 11}}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	if _, err := client.SendMsg(second, SendOptions{Info: &SndInfo{Stream: 2, PPID: 22}}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	// Both messages must be queued before the first read, so that the
	// kernel has a next message to describe; on loopback, with NoDelay,
	// they arrive at once.
	time.Sleep(100 * time.Millisecond)
	setReadDeadline(t, server, 5*time.Second)
	buf := make([]byte, 256)
	n, kept, err := server.RecvMsg(buf)
	if err != nil {
		t.Fatalf("RecvMsg: %v", err)
	}
	if string(buf[:n]) != string(first) || !kept.EOR || kept.Rcv.Stream != 1 || kept.Rcv.PPID != 11 {
		t.Fatalf("first message %q, %+v", buf[:n], kept)
	}
	if !kept.HasNxt || kept.Nxt.Stream != 2 || kept.Nxt.PPID != 22 || kept.Nxt.Length != uint32(len(second)) || kept.Nxt.Notification {
		t.Errorf("Nxt = %+v (HasNxt %t), want the second message: stream 2, PPID 22, %d bytes", kept.Nxt, kept.HasNxt, len(second))
	}
	snapshot := kept
	n, info, err := server.RecvMsg(buf)
	if err != nil || string(buf[:n]) != string(second) || info.Rcv.Stream != 2 {
		t.Fatalf("second message %q, %+v, %v", buf[:n], info, err)
	}
	if info.HasNxt {
		t.Errorf("HasNxt with nothing queued after the second message: %+v", info.Nxt)
	}
	if kept != snapshot {
		t.Error("a MsgInfo kept from one read changed with the next")
	}

	// Measured on the kernel, what one read with both records carries fits
	// the connection's control buffer.
	if _, err := client.SendMsg([]byte("a"), SendOptions{}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	if _, err := client.SendMsg([]byte("b"), SendOptions{}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	var controllen int
	rawFd(t, mustSyscallConn(t, server), func(fd int) {
		var oob [4096]byte
		b := make([]byte, 16)
		iov := syscall.Iovec{Base: &b[0]}
		iov.SetLen(len(b))
		msg := syscall.Msghdr{Iov: &iov, Iovlen: 1, Control: &oob[0]}
		msg.SetControllen(len(oob))
		if _, err := rawRecvmsg(fd, &msg, syscall.MSG_DONTWAIT); err != nil {
			t.Errorf("recvmsg: %v", err)
		}
		controllen = int(msg.Controllen)
	})
	if controllen > rcvCmsgSpace || controllen == 0 {
		t.Errorf("one read carried %d bytes of ancillary data; the connection's buffer holds %d", controllen, rcvCmsgSpace)
	}
}

// --- the end of an association ------------------------------------------------

// endPair sets up an association for the end-of-association tests and
// returns the side under test ("dialed" or "accepted") and its peer.
func endPair(t *testing.T, side string, cfg *Config) (c, peer *Conn) {
	t.Helper()
	switch side {
	case "dialed":
		c, peer = connPair(t, cfg, nil)
	case "accepted":
		peer, c = connPair(t, nil, cfg)
	default:
		t.Fatalf("unknown side %q", side)
	}
	return c, peer
}

// TestAssociationErrorSticky: once the association has failed, every read
// and every send returns the error Linux reported for it, not once (v1
// returned ECONNRESET to one call and then left reads waiting and sends
// failing with EPIPE), and no read waits on a descriptor that will never
// become ready again. Every read has a deadline far beyond the expected
// result, so a hang fails the test instead of passing it. It runs on a
// dialed and on an accepted connection; connections peeled off an Endpoint
// share the same receive path.
func TestAssociationErrorSticky(t *testing.T) {
	const bound = 5 * time.Second
	for _, side := range []string{"dialed", "accepted"} {
		t.Run(side+"/reads", func(t *testing.T) {
			c, peer := endPair(t, side, nil)
			if err := peer.Abort(); err != nil {
				t.Fatalf("peer Abort: %v", err)
			}
			for i := range 3 {
				setReadDeadline(t, c, bound)
				start := time.Now()
				_, err := c.Read(make([]byte, 64))
				wantReadError(t, err, syscall.ECONNRESET)
				if d := time.Since(start); d > time.Second {
					t.Errorf("read %d took %v", i, d)
				}
			}
			_, _, err := c.RecvMsg(make([]byte, 64))
			wantReadError(t, err, syscall.ECONNRESET)
			_, _, err = c.ReadMsg(64)
			wantReadError(t, err, syscall.ECONNRESET)
			_, err = c.Write([]byte("x"))
			wantWriteError(t, err, syscall.ECONNRESET)
		})

		t.Run(side+"/write first", func(t *testing.T) {
			c, peer := endPair(t, side, nil)
			if err := peer.Abort(); err != nil {
				t.Fatalf("peer Abort: %v", err)
			}
			waitGone(t, c)
			_, err := c.Write([]byte("x"))
			wantWriteError(t, err, syscall.ECONNRESET)
			if got := c.term.latched(); got != syscall.ECONNRESET {
				t.Fatalf("the send took the error without latching it: latch %v", got)
			}
			for range 3 {
				setReadDeadline(t, c, bound)
				_, err := c.Read(make([]byte, 64))
				wantReadError(t, err, syscall.ECONNRESET)
			}
			_, err = c.Write([]byte("y"))
			wantWriteError(t, err, syscall.ECONNRESET)
		})

		t.Run(side+"/parked reader and looping writer", func(t *testing.T) {
			c, peer := endPair(t, side, &Config{NoDelay: new(true)})
			setReadDeadline(t, c, bound)
			if err := c.SetWriteDeadline(time.Now().Add(bound)); err != nil {
				t.Fatalf("SetWriteDeadline: %v", err)
			}
			readDone := make(chan error, 1)
			go func() {
				buf := make([]byte, 1<<16)
				for {
					if _, err := c.Read(buf); err != nil {
						readDone <- err
						return
					}
				}
			}()
			writeDone := make(chan error, 1)
			go func() {
				msg := make([]byte, 256)
				for {
					if _, err := c.Write(msg); err != nil {
						writeDone <- err
						return
					}
					time.Sleep(100 * time.Microsecond)
				}
			}()
			time.Sleep(100 * time.Millisecond)
			if err := peer.Abort(); err != nil {
				t.Fatalf("peer Abort: %v", err)
			}
			aborted := time.Now()
			for what, ch := range map[string]chan error{"parked read": readDone, "looping write": writeDone} {
				select {
				case err := <-ch:
					if !errors.Is(err, syscall.ECONNRESET) {
						t.Errorf("%s ended with %v, want ECONNRESET", what, err)
					}
					if d := time.Since(aborted); d > time.Second {
						t.Errorf("%s ended %v after the ABORT", what, d)
					}
				case <-time.After(2 * bound):
					t.Fatalf("%s did not end", what)
				}
			}
		})

		t.Run(side+"/SO_ERROR taken outside", func(t *testing.T) {
			c, peer := endPair(t, side, nil)
			if err := peer.Abort(); err != nil {
				t.Fatalf("peer Abort: %v", err)
			}
			waitGone(t, c)
			var soErr int
			rawFd(t, mustSyscallConn(t, c), func(fd int) {
				v, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
				if err != nil {
					t.Errorf("SO_ERROR: %v", err)
				}
				soErr = v
			})
			if syscall.Errno(soErr) != syscall.ECONNRESET {
				t.Fatalf("SO_ERROR = %v, want ECONNRESET: nothing was left to take", syscall.Errno(soErr))
			}
			for range 3 {
				setReadDeadline(t, c, bound)
				_, err := c.Read(make([]byte, 64))
				wantReadError(t, err, syscall.ENOTCONN)
			}
			_, err := c.Write([]byte("x"))
			wantWriteError(t, err, syscall.ENOTCONN)
		})
	}
}

// TestAssociationErrorAfterQueuedData: what the peer sent before it
// aborted is still read, in order, and the error comes after it, as Linux
// orders it (net/sctp/socket.c: sctp_skb_recv_datagram dequeues before it
// looks at the socket error), even when a send took the error first.
func TestAssociationErrorAfterQueuedData(t *testing.T) {
	for _, sendFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("send first=%t", sendFirst), func(t *testing.T) {
			c, peer := connPair(t, nil, &Config{NoDelay: new(true)})
			for i := range 3 {
				if _, err := peer.Write(numbered(i)); err != nil {
					t.Fatalf("peer Write: %v", err)
				}
			}
			time.Sleep(50 * time.Millisecond)
			if err := peer.Abort(); err != nil {
				t.Fatalf("peer Abort: %v", err)
			}
			waitGone(t, c)
			if sendFirst {
				_, err := c.Write([]byte("x"))
				wantWriteError(t, err, syscall.ECONNRESET)
			}
			setReadDeadline(t, c, 5*time.Second)
			buf := make([]byte, 64)
			for i := range 3 {
				n, err := c.Read(buf)
				if err != nil || numberOf(buf[:n]) != i {
					t.Fatalf("read %d = %q, %v; want message %d", i, buf[:n], err, i)
				}
			}
			for range 2 {
				_, err := c.Read(buf)
				wantReadError(t, err, syscall.ECONNRESET)
			}
		})
	}
}

// TestGracefulEndReachesEOF: every graceful end reaches io.EOF, unwrapped,
// and every later read returns it again: a reader parked before the peer's
// Close; one parked before a local Shutdown, where Linux marks nothing on
// the socket and only the AssocShutdownComplete record ends the stream; and
// an association whose SHUTDOWN arrived before Accept, which Linux hands
// over on a socket it never marks shut for reading. The records are not
// delivered to a caller who did not subscribe to EventAssocChange, and
// are delivered to one who did, from RecvMsg or to the handler.
func TestGracefulEndReachesEOF(t *testing.T) {
	const bound = 5 * time.Second
	wantEOFs := func(t *testing.T, c *Conn) {
		t.Helper()
		for i := range 3 {
			setReadDeadline(t, c, bound)
			if n, err := c.Read(make([]byte, 64)); n != 0 || err != io.EOF {
				t.Fatalf("read %d after the end = (%d, %v), want (0, io.EOF)", i, n, err)
			}
		}
		if _, _, err := c.RecvMsg(make([]byte, 64)); err != io.EOF {
			t.Errorf("RecvMsg after the end = %v, want io.EOF", err)
		}
		if _, _, err := c.ReadMsg(64); err != io.EOF {
			t.Errorf("ReadMsg after the end = %v, want io.EOF", err)
		}
	}
	parked := func(c *Conn) <-chan error {
		done := make(chan error, 1)
		go func() {
			_, err := c.Read(make([]byte, 64))
			done <- err
		}()
		time.Sleep(100 * time.Millisecond)
		return done
	}
	for _, side := range []string{"dialed", "accepted"} {
		t.Run(side+"/peer Close", func(t *testing.T) {
			c, peer := endPair(t, side, nil)
			setReadDeadline(t, c, bound)
			done := parked(c)
			if err := peer.Close(); err != nil {
				t.Fatalf("peer Close: %v", err)
			}
			if err := <-done; err != io.EOF {
				t.Fatalf("parked read = %v, want io.EOF", err)
			}
			wantEOFs(t, c)
		})
		t.Run(side+"/local Shutdown", func(t *testing.T) {
			c, _ := endPair(t, side, nil)
			setReadDeadline(t, c, bound)
			done := parked(c)
			if err := c.Shutdown(); err != nil {
				t.Fatalf("Shutdown: %v", err)
			}
			if err := <-done; err != io.EOF {
				t.Fatalf("parked read = %v, want io.EOF", err)
			}
			if !c.term.hasEnded() {
				t.Error("the stream ended without the AssocShutdownComplete record")
			}
			wantEOFs(t, c)
		})
	}

	// The SHUTDOWN arrives while the association waits to be accepted.
	// When the handshake completes before Accept, which on loopback it
	// always does, the connection comes out closed and shut for reading
	// (net/sctp/socket.c: sctp_sock_migrate).
	t.Run("SHUTDOWN before Accept", func(t *testing.T) {
		l := mustListen(t, nil, "sctp4", loopback4(0))
		laddr := listenerAddr(t, l)
		for i := range 20 {
			client, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, laddr)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			if err := client.Shutdown(); err != nil {
				t.Fatalf("Shutdown: %v", err)
			}
			time.Sleep(time.Duration(i%4) * 50 * time.Microsecond)
			server, err := l.AcceptSCTP()
			if err != nil {
				t.Fatalf("AcceptSCTP: %v", err)
			}
			setReadDeadline(t, server, bound)
			if _, err := server.Read(make([]byte, 64)); err != io.EOF {
				t.Fatalf("attempt %d: read = %v, want io.EOF", i, err)
			}
			_ = server.Close()
			_ = client.Close()
		}
	})

	// When only the SHUTDOWN has arrived by Accept, the connection comes
	// out ESTABLISHED, and Linux never marks it shut for reading: it sets
	// RCV_SHUTDOWN only on the transition out of an ESTABLISHED socket,
	// which happened on the listener (net/sctp/sm_sideeffect.c:
	// sctp_cmd_new_state). Once the association is gone, recvmsg answers
	// EAGAIN for ever and the socket is never readable again, so the
	// record is the only end the reader can see; a reader parked before it
	// arrives must be woken by it and end, not park again. The window is
	// a round trip on loopback, so the kernel's side is scripted here.
	t.Run("only the record ends the stream", func(t *testing.T) {
		c := scriptConn(t, nil)
		script := &recvScript{
			steps: []recvStep{
				{data: []byte("last"), flags: msgEOR},
				{err: syscall.EAGAIN},
				{data: assocChangeRecord(AssocShutdownComplete, 7, nil), flags: msgNotification | msgEOR},
			},
			done: syscall.EAGAIN,
		}
		hookRecvmsg(t, script.recvmsg)
		setReadDeadline(t, c, bound)
		buf := make([]byte, 64)
		if n, err := c.Read(buf); err != nil || string(buf[:n]) != "last" {
			t.Fatalf("Read = %q, %v", buf[:n], err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := c.Read(buf)
			done <- err
		}()
		time.Sleep(50 * time.Millisecond)
		// The record arrives: the socket becomes readable.
		wakeScripted(t, c)
		if err := <-done; err != io.EOF {
			t.Fatalf("the parked read = %v, want io.EOF", err)
		}
		calls := script.calls
		wantEOFs(t, c)
		if script.calls != calls {
			t.Errorf("reads after the end made %d recvmsg calls, want none", script.calls-calls)
		}
	})

	for _, handler := range []bool{false, true} {
		t.Run(fmt.Sprintf("records/handler=%t", handler), func(t *testing.T) {
			var (
				mu     sync.Mutex
				states []AssocChangeState
			)
			cfg := &Config{}
			if handler {
				cfg.NotificationHandler = func(n Notification) error {
					if ac, ok := n.(*AssocChange); ok {
						mu.Lock()
						states = append(states, ac.State)
						mu.Unlock()
					}
					return nil
				}
			}
			// Unsubscribed first: RecvMsg never returns a notification.
			peer, plain := connPair(t, nil, cfg)
			if _, err := peer.Write([]byte("last")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := peer.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			waitGone(t, plain)
			setReadDeadline(t, plain, bound)
			items, err := readAll(plain, 8)
			if err != io.EOF {
				t.Fatalf("unsubscribed: reads ended with %v, want io.EOF", err)
			}
			if len(items) != 1 || string(items[0].data) != "last" || items[0].info.Notification {
				t.Fatalf("unsubscribed: read %+v, want only the message", items)
			}
			mu.Lock()
			if len(states) != 0 {
				t.Errorf("unsubscribed: the handler received %v", states)
			}
			mu.Unlock()

			// Subscribed: the records come, before the end, in pieces
			// through a small buffer or to the handler.
			peer, sub := connPair(t, nil, &Config{NotificationHandler: cfg.NotificationHandler, Notifications: []EventType{EventAssocChange}})
			if on, err := sub.Subscribed(EventAssocChange); err != nil || !on {
				t.Fatalf("Subscribed(EventAssocChange) = %t, %v", on, err)
			}
			if _, err := peer.Write([]byte("last")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if err := peer.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			waitGone(t, sub)
			setReadDeadline(t, sub, bound)
			items, err = readAll(sub, 8)
			if err != io.EOF {
				t.Fatalf("subscribed: reads ended with %v, want io.EOF", err)
			}
			var got []AssocChangeState
			if handler {
				mu.Lock()
				got = states
				mu.Unlock()
			} else {
				for _, it := range items {
					if !it.info.Notification {
						continue
					}
					n, err := ParseNotification(it.data)
					if err != nil {
						t.Fatalf("a notification from RecvMsg does not parse: %v", err)
					}
					if ac, ok := n.(*AssocChange); ok {
						got = append(got, ac.State)
					}
				}
			}
			if !reflect.DeepEqual(got, []AssocChangeState{AssocCommUp, AssocShutdownComplete}) {
				t.Errorf("subscribed: association changes %v, want [AssocCommUp AssocShutdownComplete]", got)
			}
		})
	}
}

// TestAcceptedAfterEnd: a client connects, sends one message and ends the
// association before the server calls Accept. Accept returns the
// connection (AssocID 0, empty address snapshots: Linux no longer knows
// them), and reads deliver the queued message, then io.EOF after a
// graceful end, or an error matching syscall.ENOTCONN after an ABORT,
// whose error Linux left on the listening socket (net/sctp/socket.c:
// sctp_sock_migrate). Sends then fail the same way. The records Linux
// queued reach a caller who subscribed to EventAssocChange, and no other.
func TestAcceptedAfterEnd(t *testing.T) {
	for _, abort := range []bool{false, true} {
		for _, subscribe := range []bool{false, true} {
			t.Run(fmt.Sprintf("abort=%t/subscribed=%t", abort, subscribe), func(t *testing.T) {
				cfg := &Config{}
				if subscribe {
					cfg.Notifications = []EventType{EventAssocChange}
				}
				l := mustListen(t, cfg, "sctp4", loopback4(0))
				laddr := listenerAddr(t, l)
				client, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, laddr)
				if err != nil {
					t.Fatalf("Dial: %v", err)
				}
				msg := []byte("sent before accept")
				if _, err := client.Write(msg); err != nil {
					t.Fatalf("Write: %v", err)
				}
				if abort {
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
					t.Fatalf("AcceptSCTP: %v", err)
				}
				t.Cleanup(func() { _ = server.Abort() })
				if server.AssocID() != 0 {
					t.Errorf("AssocID = %d, want 0", server.AssocID())
				}
				setReadDeadline(t, server, 5*time.Second)
				items, err := readAll(server, 256)
				var data []string
				var states []AssocChangeState
				for _, it := range items {
					if !it.info.Notification {
						data = append(data, string(it.data))
						continue
					}
					n, perr := ParseNotification(it.data)
					if perr != nil {
						t.Fatalf("notification: %v", perr)
					}
					if ac, ok := n.(*AssocChange); ok {
						states = append(states, ac.State)
					}
				}
				if !reflect.DeepEqual(data, []string{string(msg)}) {
					t.Errorf("messages %q, want the one sent", data)
				}
				end := AssocShutdownComplete
				if abort {
					wantReadError(t, err, syscall.ENOTCONN)
					end = AssocCommLost
				} else if err != io.EOF {
					t.Fatalf("reads ended with %v, want io.EOF", err)
				}
				if subscribe {
					if len(states) == 0 || states[len(states)-1] != end {
						t.Errorf("association changes %v, want them to end with %v", states, end)
					}
				} else if len(states) != 0 {
					t.Errorf("an unsubscribed caller received %v", states)
				}
				for range 2 {
					_, err := server.Read(make([]byte, 64))
					if abort {
						wantReadError(t, err, syscall.ENOTCONN)
					} else if err != io.EOF {
						t.Errorf("a later read = %v, want io.EOF", err)
					}
				}
				_, err = server.Write([]byte("reply"))
				if abort {
					wantWriteError(t, err, syscall.ENOTCONN)
				} else {
					wantWriteError(t, err, syscall.EPIPE)
				}
			})
		}
	}
}

// --- notifications ------------------------------------------------------------

// setMaxSeg returns a Control that sets SCTP_MAXSEG (RFC 6458 §8.1.16) to
// n before the association exists, so that its messages are cut into
// DATA chunks of at most n bytes.
func setMaxSeg(n uint32) func(string, string, syscall.RawConn) error {
	return func(_, _ string, rc syscall.RawConn) error {
		var cerr error
		if err := rc.Control(func(fd uintptr) { cerr = setAssocValue(int(fd), optMaxSeg, n) }); err != nil {
			return err
		}
		return cerr
	}
}

// failedSends leaves a message of size bytes, with SndInfo.Context 2, queued
// and unsent on a connection whose peer's window is closed, has the peer
// abort, and returns the connection, whose Config subscribes to
// EventSendFailed and carries handler. The message is cut into DATA chunks
// of 1024 bytes, so its SendFailed notifications (RFC 6458 §6.1.11) are
// many, one per chunk (net/sctp/chunk.c: sctp_datamsg_destroy), and Linux
// queues them after the AssocCommLost record, when it frees the
// association (net/sctp/sm_sideeffect.c: sctp_cmd_assoc_failed,
// sctp_cmd_delete_tcb).
func failedSends(t *testing.T, msg []byte, handler NotificationHandler) *Conn {
	t.Helper()
	clientCfg := &Config{
		Control:             setMaxSeg(1024),
		WriteBuffer:         new(1 << 20),
		NoDelay:             new(true),
		Notifications:       []EventType{EventSendFailed},
		NotificationHandler: handler,
	}
	client, server := connPair(t, clientCfg, &Config{ReadBuffer: new(8192)})
	// Fill the peer's window with messages it never reads, and a few more,
	// which then wait in the queue ahead of msg.
	filler := make([]byte, 1024)
	for range 24 {
		if _, err := client.SendMsg(filler, SendOptions{Info: &SndInfo{Context: 1}}); err != nil {
			t.Fatalf("SendMsg filler: %v", err)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := client.SendMsg(msg, SendOptions{Info: &SndInfo{Context: 2, PPID: 99}}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := server.Abort(); err != nil {
		t.Fatalf("peer Abort: %v", err)
	}
	waitGone(t, client)
	setReadDeadline(t, client, 10*time.Second)
	return client
}

// checkFailedFragments checks the SendFailed notifications of msg's chunks
// (Context 2): in order, from FirstFragment to LastFragment, none of them
// sent, their Data concatenating to msg.
func checkFailedFragments(t *testing.T, msg []byte, all []*SendFailed) {
	t.Helper()
	var frags []*SendFailed
	for _, sf := range all {
		if sf.Context == 2 {
			frags = append(frags, sf)
		}
	}
	if len(frags) < 2 {
		t.Fatalf("%d SendFailed notifications for the message, want one per chunk, many", len(frags))
	}
	var data []byte
	for i, sf := range frags {
		if sf.FirstFragment != (i == 0) || sf.LastFragment != (i == len(frags)-1) {
			t.Errorf("fragment %d of %d: FirstFragment %t, LastFragment %t", i, len(frags), sf.FirstFragment, sf.LastFragment)
		}
		if sf.Sent || sf.PPID != 99 || sf.Error != frags[0].Error {
			t.Errorf("fragment %d: Sent %t, PPID %d, Error %v", i, sf.Sent, sf.PPID, sf.Error)
		}
		data = append(data, sf.Data...)
	}
	if !bytes.Equal(data, msg) {
		t.Errorf("the %d fragments carry %d bytes that are not the message's %d", len(frags), len(data), len(msg))
	}
}

// TestLargeSendFailedReassembly: a 64 KiB message that the peer's ABORT
// left unsent comes back as one SendFailed notification per DATA chunk,
// each larger than a small read buffer. RecvMsg with a 16-byte buffer and
// no handler returns each notification in pieces, Notification set on
// every piece and EOR on the last; with a handler, the handler receives
// each whole, and their Data concatenate to the message. The reads then
// end with the ABORT's error.
func TestLargeSendFailedReassembly(t *testing.T) {
	msg := make([]byte, 64<<10)
	for i := range msg {
		msg[i] = byte(i*7 + i>>10)
	}

	t.Run("pieces", func(t *testing.T) {
		c := failedSends(t, msg, nil)
		buf := make([]byte, 16)
		var (
			record []byte
			failed []*SendFailed
			pieces int
		)
		var err error
		for {
			var (
				n    int
				info MsgInfo
			)
			n, info, err = c.RecvMsg(buf)
			if err != nil {
				break
			}
			if !info.Notification {
				t.Fatalf("RecvMsg returned %d bytes of data after the ABORT", n)
			}
			pieces++
			record = append(record, buf[:n]...)
			if !info.EOR {
				if n != len(buf) {
					t.Fatalf("a piece of %d bytes without EOR from a %d-byte buffer", n, len(buf))
				}
				continue
			}
			note, perr := ParseNotification(record)
			if perr != nil {
				t.Fatalf("a reassembled notification of %d bytes: %v", len(record), perr)
			}
			if sf, ok := note.(*SendFailed); ok {
				failed = append(failed, sf)
			}
			record = nil
		}
		wantReadError(t, err, syscall.ECONNRESET)
		if record != nil {
			t.Fatalf("the reads ended in the middle of a notification")
		}
		checkFailedFragments(t, msg, failed)
		if pieces < 2*len(failed) {
			t.Errorf("%d pieces for %d notifications through a 16-byte buffer", pieces, len(failed))
		}
	})

	t.Run("handler", func(t *testing.T) {
		var (
			mu     sync.Mutex
			failed []*SendFailed
		)
		c := failedSends(t, msg, func(n Notification) error {
			if sf, ok := n.(*SendFailed); ok {
				mu.Lock()
				failed = append(failed, sf)
				mu.Unlock()
			}
			return nil
		})
		for {
			if _, err := c.Read(make([]byte, 16)); err != nil {
				wantReadError(t, err, syscall.ECONNRESET)
				break
			}
			t.Fatal("Read returned data after the ABORT")
		}
		mu.Lock()
		defer mu.Unlock()
		checkFailedFragments(t, msg, failed)
	})
}

// TestSendFailedEventExceedsNotificationMaxSize: an SCTP_SEND_FAILED_EVENT
// carries the undelivered chunk, so it outgrows NotificationMaxSize, which
// is documented as holding the fixed-size notifications only; with a read
// buffer that large, it arrives whole, with EOR (v1
// TestSendFailedEventExceedsNotificationMaxSize).
func TestSendFailedEventExceedsNotificationMaxSize(t *testing.T) {
	msg := make([]byte, 200<<10)
	clientCfg := &Config{WriteBuffer: new(1 << 20), Notifications: []EventType{EventSendFailed}}
	client, server := connPair(t, clientCfg, &Config{ReadBuffer: new(8192)})
	if err := client.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	for range 2 {
		if _, err := client.Write(msg); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := server.Abort(); err != nil {
		t.Fatalf("peer Abort: %v", err)
	}
	waitGone(t, client)
	setReadDeadline(t, client, 5*time.Second)
	items, err := readAll(client, len(msg))
	wantReadError(t, err, syscall.ECONNRESET)
	large := 0
	for _, it := range items {
		n, perr := ParseNotification(it.data)
		if perr != nil {
			t.Fatalf("ParseNotification: %v", perr)
		}
		if sf, ok := n.(*SendFailed); ok && len(it.data) > NotificationMaxSize {
			large++
			if len(sf.Data) == 0 {
				t.Errorf("a %d-byte SendFailed decoded with no data", len(it.data))
			}
		}
	}
	if large == 0 {
		t.Fatalf("none of %d notifications outgrew NotificationMaxSize (%d)", len(items), NotificationMaxSize)
	}
}

// TestNotificationValuesOwnBytes: the value a handler receives owns every
// byte it holds. A handler keeps each notification; the reads that follow
// reuse the connection's notification buffer for records of the same size
// and other contents; the kept Info and Data still hold the bytes they
// arrived with. It covers RecvMsg, Read and ReadMsg.
func TestNotificationValuesOwnBytes(t *testing.T) {
	type reader func(c *Conn) error
	for name, read := range map[string]reader{
		"RecvMsg": func(c *Conn) error { _, _, err := c.RecvMsg(make([]byte, 7)); return err },
		"Read":    func(c *Conn) error { _, err := c.Read(make([]byte, 7)); return err },
		"ReadMsg": func(c *Conn) error { _, _, err := c.ReadMsg(64); return err },
	} {
		t.Run(name, func(t *testing.T) {
			var kept []Notification
			c := scriptConn(t, func(n Notification) error {
				kept = append(kept, n)
				return nil
			}, EventAssocChange)
			var steps []recvStep
			want := map[int][]byte{}
			for i := range 6 {
				payload := bytes.Repeat([]byte{byte(0x10 * (i + 1))}, 40)
				want[i] = payload
				var rec []byte
				if i%2 == 0 {
					rec = notif(EventRemoteError, sizeRemoteError+len(payload))
					copy(rec[remoteErrorDataOff:], payload)
				} else {
					rec = assocChangeRecord(AssocCommUp, 7, payload)
				}
				steps = append(steps, recvStep{data: rec, flags: msgNotification | msgEOR})
			}
			for i := range 3 {
				steps = append(steps, recvStep{data: []byte(fmt.Sprintf("message %d", i)), flags: msgEOR})
			}
			script := &recvScript{steps: steps}
			hookRecvmsg(t, script.recvmsg)
			for range 3 {
				if err := read(c); err != nil {
					t.Fatalf("read: %v", err)
				}
			}
			if len(kept) != 6 {
				t.Fatalf("the handler received %d notifications, want 6", len(kept))
			}
			for i, n := range kept {
				var got []byte
				switch v := n.(type) {
				case *RemoteError:
					got = v.Data
				case *AssocChange:
					got = v.Info
				default:
					t.Fatalf("notification %d is %T", i, n)
				}
				if !bytes.Equal(got, want[i]) {
					t.Errorf("notification %d holds % x, want % x: its bytes were reused", i, got[:4], want[i][:4])
				}
			}
		})
	}
}

// TestHandlerReentry: the receive lock is released before a
// NotificationHandler runs, so a handler may read from the connection it
// was called for. The handler consumes the first message with a nested
// read; the outer read returns the second (v1
// TestReadMsgNotificationHandlerMayReenterRead). A handler's error ends the
// read it came from, and the connection stays usable.
func TestHandlerReentry(t *testing.T) {
	type outer func(c *Conn) ([]byte, error)
	for name, read := range map[string]outer{
		"Read":    func(c *Conn) ([]byte, error) { b := make([]byte, 256); n, err := c.Read(b); return b[:n], err },
		"RecvMsg": func(c *Conn) ([]byte, error) { b := make([]byte, 256); n, _, err := c.RecvMsg(b); return b[:n], err },
		"ReadMsg": func(c *Conn) ([]byte, error) { b, _, err := c.ReadMsg(256); return b, err },
	} {
		t.Run(name, func(t *testing.T) {
			var (
				server  *Conn
				calls   atomic.Int32
				nested  []byte
				nestErr error
			)
			handler := func(n Notification) error {
				if calls.Add(1) != 1 {
					return nil
				}
				if ac, ok := n.(*AssocChange); !ok || ac.State != AssocCommUp {
					return fmt.Errorf("first notification %#v, want AssocCommUp", n)
				}
				nested, _, nestErr = server.ReadMsg(256)
				return nestErr
			}
			client, s := connPair(t, nil, &Config{NotificationHandler: handler, Notifications: []EventType{EventAssocChange}})
			server = s
			first, second := []byte("read by the handler"), []byte("returned by the outer read")
			for _, m := range [][]byte{first, second} {
				if _, err := client.Write(m); err != nil {
					t.Fatalf("Write: %v", err)
				}
			}
			setReadDeadline(t, server, 5*time.Second)
			done := make(chan struct{})
			var (
				got []byte
				err error
			)
			go func() {
				defer close(done)
				got, err = read(server)
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				_ = server.Abort()
				t.Fatal("the handler deadlocked re-entering the connection")
			}
			if err != nil || nestErr != nil {
				t.Fatalf("outer read %v, nested read %v", err, nestErr)
			}
			if !bytes.Equal(nested, first) || !bytes.Equal(got, second) {
				t.Errorf("nested read %q and outer read %q, want %q and %q", nested, got, first, second)
			}
			if calls.Load() != 1 {
				t.Errorf("the handler ran %d times, want 1", calls.Load())
			}
		})
	}

	t.Run("handler error", func(t *testing.T) {
		errHandler := errors.New("handler refused")
		refuse := atomic.Bool{}
		refuse.Store(true)
		client, server := connPair(t, nil, &Config{
			NotificationHandler: func(Notification) error {
				if refuse.Load() {
					return errHandler
				}
				return nil
			},
			Notifications: []EventType{EventAssocChange},
		})
		if _, err := client.Write([]byte("after")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		setReadDeadline(t, server, 5*time.Second)
		_, err := server.Read(make([]byte, 64))
		wantReadError(t, err, errHandler)
		buf := make([]byte, 64)
		n, err := server.Read(buf)
		if err != nil || string(buf[:n]) != "after" {
			t.Fatalf("the read after the handler's error = %q, %v", buf[:n], err)
		}
	})
}

// TestSubscribe: Subscribe changes the kernel's subscription for every type
// but EventAssocChange, whose kernel subscription the package keeps on,
// and Subscribed reports what the caller set. A notification the caller
// switched on arrives; one switched off does not.
func TestSubscribe(t *testing.T) {
	client, server := connPair(t, nil, nil)
	rc := mustSyscallConn(t, server)
	var all []EventType
	for typ := range eventTypeNames {
		all = append(all, typ)
	}
	slices.Sort(all)
	for _, typ := range all {
		if on, err := server.Subscribed(typ); err != nil || on {
			t.Fatalf("Subscribed(%v) on a new connection = %t, %v", typ, on, err)
		}
		if err := server.Subscribe(typ, true); err != nil {
			t.Fatalf("Subscribe(%v, true): %v", typ, err)
		}
		if on, err := server.Subscribed(typ); err != nil || !on {
			t.Errorf("Subscribed(%v) after Subscribe = %t, %v", typ, on, err)
		}
		if !subscribedInKernel(t, rc, typ) {
			t.Errorf("%v is not subscribed in the kernel after Subscribe", typ)
		}
		if err := server.Subscribe(typ, false); err != nil {
			t.Fatalf("Subscribe(%v, false): %v", typ, err)
		}
		if on, _ := server.Subscribed(typ); on {
			t.Errorf("Subscribed(%v) after unsubscribing = true", typ)
		}
		if wantKernel := typ == EventAssocChange; subscribedInKernel(t, rc, typ) != wantKernel {
			t.Errorf("%v in the kernel after unsubscribing = %t, want %t", typ, !wantKernel, wantKernel)
		}
	}

	for _, bad := range []EventType{0, 0x8000, 0x800e, EventType(0xffff)} {
		err := server.Subscribe(bad, true)
		if !errors.Is(err, syscall.EINVAL) {
			t.Errorf("Subscribe(%#x) = %v, want EINVAL", uint16(bad), err)
		}
		if _, err := server.Subscribed(bad); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("Subscribed(%#x) = %v, want EINVAL", uint16(bad), err)
		}
	}

	// Switched on, EventShutdown arrives when the peer shuts down.
	if err := server.Subscribe(EventShutdown, true); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	waitGone(t, server)
	setReadDeadline(t, server, 5*time.Second)
	items, err := readAll(server, 256)
	if err != io.EOF {
		t.Fatalf("reads ended with %v", err)
	}
	var types []EventType
	for _, it := range items {
		n, _ := ParseNotification(it.data)
		types = append(types, n.Type())
	}
	// Subscribing to EventSenderDry with nothing outstanding queues one at
	// once (net/sctp/socket.c: sctp_assoc_ulpevent_type_set); queued while
	// subscribed, it is delivered. Nothing else of the types switched off
	// arrives.
	if !reflect.DeepEqual(types, []EventType{EventSenderDry, EventShutdown}) {
		t.Errorf("notifications %v, want [EventSenderDry EventShutdown]", types)
	}

	if err := server.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	var opErr *net.OpError
	if err := server.Subscribe(EventShutdown, true); !errors.Is(err, net.ErrClosed) || !errors.As(err, &opErr) || opErr.Op != "set" {
		t.Errorf("Subscribe after Abort = %v, want a set error matching net.ErrClosed", err)
	}
	if _, err := server.Subscribed(EventShutdown); !errors.Is(err, net.ErrClosed) {
		t.Errorf("Subscribed after Abort = %v, want net.ErrClosed", err)
	}
}

// TestNotificationHandlerReassemblesKernelNotification: records Linux
// hands over in pieces through an 8-byte buffer reach the handler whole,
// and each parses as the kernel wrote it: the stream counts of AssocCommUp
// sit where the layout says (v1 TestParseNotificationAgainstKernel,
// TestNotificationHandlerReassemblesKernelNotification).
func TestNotificationHandlerReassemblesKernelNotification(t *testing.T) {
	var (
		mu    sync.Mutex
		notes []Notification
	)
	cfg := &Config{
		InitMsg:             InitMsg{OutStreams: 7, MaxInStreams: 9},
		Notifications:       []EventType{EventAssocChange, EventShutdown},
		NotificationHandler: func(n Notification) error { mu.Lock(); notes = append(notes, n); mu.Unlock(); return nil },
	}
	client, server := connPair(t, &Config{InitMsg: InitMsg{OutStreams: 9, MaxInStreams: 7}}, cfg)
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	setReadDeadline(t, server, 5*time.Second)
	for {
		if _, err := server.Read(make([]byte, 8)); err != nil {
			if err != io.EOF {
				t.Fatalf("Read: %v", err)
			}
			break
		}
	}
	mu.Lock()
	defer mu.Unlock()
	var types []EventType
	for _, n := range notes {
		types = append(types, n.Type())
		if ac, ok := n.(*AssocChange); ok && ac.State == AssocCommUp {
			// Outbound: the server's 7, within the client's inbound 7;
			// inbound: the client's 9, within the server's inbound 9
			// (RFC 9260 §5.1.1).
			if ac.OutStreams != 7 || ac.InStreams != 9 || ac.AssocID != server.AssocID() {
				t.Errorf("AssocCommUp = %+v, want 7 outbound and 9 inbound streams on association %d", ac, server.AssocID())
			}
		}
	}
	if len(types) < 2 || types[0] != EventAssocChange {
		t.Errorf("notifications %v, want AssocCommUp first and then the shutdown's", types)
	}
}

// TestRawNotificationReadPreservesFragments: without a handler, RecvMsg
// returns a subscribed notification in pieces as long as the buffer, the
// first too short to parse alone, and EOR only on the last (v1
// TestRawNotificationReadPreservesFragments).
func TestRawNotificationReadPreservesFragments(t *testing.T) {
	_, server := connPair(t, nil, &Config{Notifications: []EventType{EventAssocChange}})
	setReadDeadline(t, server, 5*time.Second)
	buf := make([]byte, 8)
	var record []byte
	for {
		n, info, err := server.RecvMsg(buf)
		if err != nil {
			t.Fatalf("RecvMsg: %v", err)
		}
		if !info.Notification {
			t.Fatal("data before the AssocCommUp record")
		}
		if record == nil {
			if _, err := ParseNotification(buf[:n]); !errors.Is(err, ErrShortNotification) {
				t.Fatalf("ParseNotification(first piece) = %v, want ErrShortNotification", err)
			}
			if info.EOR {
				t.Fatal("the first 8-byte piece of AssocCommUp came with EOR")
			}
		}
		record = append(record, buf[:n]...)
		if info.EOR {
			break
		}
	}
	n, err := ParseNotification(record)
	if err != nil {
		t.Fatalf("ParseNotification(%d bytes): %v", len(record), err)
	}
	if ac, ok := n.(*AssocChange); !ok || ac.State != AssocCommUp {
		t.Errorf("reassembled %#v, want AssocCommUp", n)
	}
}

// --- ReadMsg ------------------------------------------------------------------

// patterned returns n bytes of a pattern that does not repeat within 251
// bytes, so that a misplaced or lost piece shows.
func patterned(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + i/251)
	}
	return b
}

// TestReadMsgReassembles: ReadMsg returns whole messages whatever their
// size, without the caller sizing a buffer (v1 TestReadMsgReassembles,
// TestReadMsgSizeMaxMatrix, TestReadMsgExactMaxIsComplete,
// TestReadMsgOneOverMax, TestReadMsgRespectsMax): a message of at most max
// bytes whole, with the SCTP_RCVINFO of its first piece, and a longer one
// cut at max with an error matching ErrMessageTooLong, its rest drained so
// that the next ReadMsg returns the next message (v1
// TestReadMsgTooLongDrainsRemainder).
func TestReadMsgReassembles(t *testing.T) {
	client, server := connPair(t, &Config{NoDelay: new(true)}, nil)
	setReadDeadline(t, server, 30*time.Second)
	sizes := []int{1, 100, 168, 255, 256, 257, 1400, 2047, 2048, 2049, 4095, 4096, 4097, 8192, 20000, 65536}
	maxes := []int{64, 255, 256, 257, 2048, 4096, 65536, 1 << 20}
	for i, max := range maxes {
		for j, size := range sizes {
			msg := patterned(size)
			info := &SndInfo{Stream: uint16(j % 3), PPID: uint32(i<<8 | j)}
			if _, err := client.SendMsg(msg, SendOptions{Info: info}); err != nil {
				t.Fatalf("SendMsg %d: %v", size, err)
			}
			next := []byte(fmt.Sprintf("after %d/%d", max, size))
			if _, err := client.Write(next); err != nil {
				t.Fatalf("Write: %v", err)
			}
			got, rcv, err := server.ReadMsg(max)
			if size <= max {
				if err != nil || !bytes.Equal(got, msg) {
					t.Fatalf("size %d max %d: %d bytes, %v; want the whole message", size, max, len(got), err)
				}
			} else {
				wantReadError(t, err, ErrMessageTooLong)
				if !bytes.Equal(got, msg[:max]) {
					t.Fatalf("size %d max %d: %d bytes, want the first %d", size, max, len(got), max)
				}
			}
			if rcv.Stream != info.Stream || rcv.PPID != info.PPID {
				t.Errorf("size %d max %d: RcvInfo %+v, want stream %d PPID %#x", size, max, rcv, info.Stream, info.PPID)
			}
			got, _, err = server.ReadMsg(max)
			if want := next[:min(len(next), max)]; !bytes.Equal(got, want) {
				t.Fatalf("size %d max %d: the next message %q, %v; want %q", size, max, got, err, want)
			}
		}
	}
}

// TestReadMsgRejectsNonPositiveMax: a max of zero or less is refused with
// an error matching syscall.EINVAL (v1 TestReadMsgRejectsNonPositiveMax).
func TestReadMsgRejectsNonPositiveMax(t *testing.T) {
	_, server := connPair(t, nil, nil)
	for _, max := range []int{0, -1} {
		_, _, err := server.ReadMsg(max)
		wantReadError(t, err, syscall.EINVAL)
	}
}

// TestFragmentedMessages: messages around the association's fragmentation
// point, which the peer receives as several DATA chunks, come back whole
// from ReadMsg, and RecvMsg marks only the last piece of one with EOR (v1
// TestMessagesAcrossTheFragmentationPoint,
// TestFragmentedMessageReportsEORCorrectly).
func TestFragmentedMessages(t *testing.T) {
	client, server := connPair(t, &Config{Control: setMaxSeg(1200)}, nil)
	point := statusFragPoint(t, client)
	setReadDeadline(t, server, 30*time.Second)
	for _, n := range []int{point / 2, point - 1, point, point + 1, 2*point + 3, 8*point + 1} {
		msg := patterned(n)
		if _, err := client.Write(msg); err != nil {
			t.Fatalf("Write %d: %v", n, err)
		}
		got, _, err := server.ReadMsg(2 * n)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("%d bytes around the fragmentation point %d: %d bytes, %v", n, point, len(got), err)
		}
	}
	msg := patterned(point + 1024)
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, point/2)
	var got []byte
	for reads := 1; ; reads++ {
		n, info, err := server.RecvMsg(buf)
		if err != nil {
			t.Fatalf("RecvMsg: %v", err)
		}
		got = append(got, buf[:n]...)
		if info.EOR {
			if reads < 2 || !bytes.Equal(got, msg) {
				t.Fatalf("EOR after %d reads and %d bytes of %d", reads, len(got), len(msg))
			}
			break
		}
		if len(got) >= len(msg) {
			t.Fatalf("the whole %d-byte message read without EOR", len(msg))
		}
	}
}

// TestEverySendIsACompleteRecord: every send is one whole message, even
// with SendOptions.More, which asks only to delay it: the first read of two
// sends returns the first alone, with EOR (v1
// TestEverySendIsACompleteRecord). Linux defines neither SCTP_EOR nor
// explicit-EOR mode (RFC 6458 §8.1.26, Verified Erratum 6111), so nothing
// could leave a record open.
func TestEverySendIsACompleteRecord(t *testing.T) {
	client, server := connPair(t, nil, nil)
	if _, err := client.SendMsg([]byte("AAAA"), SendOptions{More: true}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	if _, err := client.Write([]byte("BBBB")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	setReadDeadline(t, server, 5*time.Second)
	buf := make([]byte, 64)
	n, info, err := server.RecvMsg(buf)
	if err != nil || string(buf[:n]) != "AAAA" || !info.EOR {
		t.Fatalf("the first read = %q, EOR %t, %v; want AAAA alone, with EOR", buf[:n], info.EOR, err)
	}
}

// TestReadMsgSkipsNotifications: ReadMsg never returns a notification as a
// message, subscribed or not, with a handler or without (v1
// TestReadMsgSkipsNotifications, TestReadMsgWithNotificationsSubscribed).
func TestReadMsgSkipsNotifications(t *testing.T) {
	for _, handler := range []bool{false, true} {
		t.Run(fmt.Sprintf("handler=%t", handler), func(t *testing.T) {
			var notes atomic.Int32
			cfg := &Config{Notifications: []EventType{EventAssocChange, EventShutdown, EventSenderDry, EventPeerAddrChange}}
			if handler {
				cfg.NotificationHandler = func(Notification) error { notes.Add(1); return nil }
			}
			client, server := connPair(t, nil, cfg)
			setReadDeadline(t, server, 10*time.Second)
			for _, size := range []int{1, 2048, 4096, 20000, 60000} {
				msg := patterned(size)
				if _, err := client.Write(msg); err != nil {
					t.Fatalf("Write: %v", err)
				}
				got, _, err := server.ReadMsg(1 << 20)
				if err != nil || !bytes.Equal(got, msg) {
					t.Fatalf("size %d: %d bytes, %v", size, len(got), err)
				}
			}
			if err := client.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if _, _, err := server.ReadMsg(1 << 20); err != io.EOF {
				t.Fatalf("ReadMsg after the peer's Close = %v, want io.EOF", err)
			}
			if handler && notes.Load() == 0 {
				t.Error("no notification reached the handler; the path between records was not exercised")
			}
		})
	}
}

// TestReadMsgPeerAbortMidMessage: an ABORT while a long message is still
// arriving surfaces as an error, never as a short message reported whole
// (v1 TestReadMsgPeerAbortMidMessage).
func TestReadMsgPeerAbortMidMessage(t *testing.T) {
	client, server := connPair(t, &Config{WriteBuffer: new(1 << 20)}, &Config{ReadBuffer: new(1 << 16)})
	msg := patterned(200000)
	if err := client.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if _, err := client.Write(msg); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := client.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	setReadDeadline(t, server, 5*time.Second)
	got, _, err := server.ReadMsg(1 << 20)
	if err == nil {
		if !bytes.Equal(got, msg) {
			t.Fatalf("ReadMsg reported success with %d of %d bytes", len(got), len(msg))
		}
		return
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadMsg waited for the rest of an aborted message: %v", err)
	}
}

// TestReadMsgControlTruncation: ancillary data switched on outside the
// package can outgrow the control buffer, which holds SCTP_RCVINFO and
// SCTP_NXTINFO. Here SO_TIMESTAMP's record, which sctp_recvmsg writes
// first (net/sctp/socket.c: sctp_recvmsg, through sock_recv_cmsgs), with
// ReceiveNxtInfo on and a next message queued, leaves no room for the
// SCTP_RCVINFO written last, and Linux sets MSG_CTRUNC (net/core/scm.c:
// put_cmsg). RecvMsg and
// ReadMsg return the message whole, with what they could parse, NXTINFO
// here, and an error matching ErrControlTruncated; Read, which returns no
// ancillary data, ignores it. SO_TIMESTAMP without NXTINFO still fits, and
// reports nothing (v1 TestSCTPReadFlagsReportsControlTruncation,
// TestReadMsgReportsControlTruncation).
func TestReadMsgControlTruncation(t *testing.T) {
	client, server := connPair(t, &Config{NoDelay: new(true)}, &Config{ReceiveNxtInfo: new(true)})
	rawFd(t, mustSyscallConn(t, server), func(fd int) {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1); err != nil {
			t.Fatalf("SO_TIMESTAMP: %v", err)
		}
	})
	// Every read below has a next message queued, so NXTINFO comes with
	// it; the last message is read with nothing after it.
	for _, m := range []string{"RecvMsg", "ReadMsg", "Read", "last"} {
		if _, err := client.Write([]byte(m)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	time.Sleep(100 * time.Millisecond)
	setReadDeadline(t, server, 5*time.Second)

	buf := make([]byte, 64)
	n, mi, err := server.RecvMsg(buf)
	wantReadError(t, err, ErrControlTruncated)
	if string(buf[:n]) != "RecvMsg" || !mi.EOR || !mi.HasNxt || mi.Nxt.Length != uint32(len("ReadMsg")) {
		t.Errorf("RecvMsg = %q, %+v; want the message, with the NXTINFO written before the truncation", buf[:n], mi)
	}

	got, _, err := server.ReadMsg(64)
	wantReadError(t, err, ErrControlTruncated)
	if string(got) != "ReadMsg" {
		t.Errorf("ReadMsg = %q", got)
	}

	if n, err := server.Read(buf); err != nil || string(buf[:n]) != "Read" {
		t.Errorf("Read = %q, %v; want the message, the truncation ignored", buf[:n], err)
	}

	// Nothing queued after the last message: no NXTINFO, and the
	// timestamp and RCVINFO fit together.
	n, mi, err = server.RecvMsg(buf)
	if err != nil || string(buf[:n]) != "last" || mi.HasNxt || mi.Rcv.AssocID != server.AssocID() {
		t.Errorf("the last RecvMsg = %q, %+v, %v; want it whole, with its RCVINFO", buf[:n], mi, err)
	}
}

// TestConcurrentReadersNeverSplit: concurrent readers each get whole
// messages, with their own metadata, and results that later reads never
// change (v1 TestConcurrentReadMsgResultsRemainIndependent,
// TestReadMsgLargeConcurrentMixedRecords). Each message names itself in
// its first bytes and in its PPID.
func TestConcurrentReadersNeverSplit(t *testing.T) {
	client, server := connPair(t, &Config{WriteBuffer: new(1 << 20)}, nil)
	deadline := time.Now().Add(20 * time.Second)
	if err := client.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if err := server.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	sizes := []int{4136, 168, 65535, 256, 65536, 4095, 4096, 4097, 4200, 9000, 12, 70000}
	wants := make([][]byte, len(sizes))
	for i, size := range sizes {
		wants[i] = patterned(size)
		binary.BigEndian.PutUint32(wants[i], uint32(i))
	}
	type result struct {
		payload []byte
		info    RcvInfo
		err     error
	}
	results := make(chan result, len(sizes))
	start := make(chan struct{})
	for i := range sizes {
		go func() {
			<-start
			if i%2 == 0 {
				p, info, err := server.ReadMsg(1 << 17)
				results <- result{p, info, err}
				return
			}
			// A RecvMsg reader reassembles on its own, which only works if
			// no other reader takes a piece of its message.
			var p []byte
			buf := make([]byte, 1<<17)
			for {
				n, mi, err := server.RecvMsg(buf)
				if err != nil {
					results <- result{err: err}
					return
				}
				p = append(p, buf[:n]...)
				if mi.EOR {
					results <- result{p, mi.Rcv, nil}
					return
				}
			}
		}()
	}
	close(start)
	for i, w := range wants {
		if _, err := client.SendMsg(w, SendOptions{Info: &SndInfo{Stream: uint16(i % 4), PPID: uint32(i)}}); err != nil {
			t.Fatalf("SendMsg %d: %v", i, err)
		}
	}
	var kept []result
	seen := map[uint32]bool{}
	for range sizes {
		r := <-results
		if r.err != nil || len(r.payload) < 4 {
			t.Errorf("a reader: %d bytes, %v", len(r.payload), r.err)
			continue
		}
		id := binary.BigEndian.Uint32(r.payload)
		if id >= uint32(len(wants)) || seen[id] {
			t.Errorf("a message names itself %d, unknown or already read", id)
			continue
		}
		seen[id] = true
		if !bytes.Equal(r.payload, wants[id]) {
			t.Errorf("message %d came back as %d bytes that differ", id, len(r.payload))
		}
		if r.info.PPID != id || r.info.Stream != uint16(id%4) {
			t.Errorf("message %d arrived with metadata %+v", id, r.info)
		}
		kept = append(kept, r)
	}
	for _, r := range kept {
		id := binary.BigEndian.Uint32(r.payload)
		if !bytes.Equal(r.payload, wants[id]) {
			t.Errorf("message %d changed after the other reads", id)
		}
	}
}

// TestReadMsgBufferCacheExclusiveAndBounded: the shared assembly buffers
// are lent exclusively, a class holds at most four, and a warm class lends
// without allocating (v1 TestReadMsgBufferCacheExclusiveAndBounded,
// TestReadMsgBufferCacheConcurrent).
func TestReadMsgBufferCacheExclusiveAndBounded(t *testing.T) {
	for _, size := range []int{2048, 8192, 32768, 65536} {
		p := readMsgBufferCache{size: size}
		borrowed := make([][]byte, 12)
		for i := range borrowed {
			borrowed[i] = p.get()
			for j := range borrowed[i] {
				borrowed[i][j] = byte(i + 1)
			}
		}
		for i, b := range borrowed {
			if len(b) != size || cap(b) != size || !bytes.Equal(b, bytes.Repeat([]byte{byte(i + 1)}, size)) {
				t.Fatalf("size %d: borrowed buffer %d was shared or missized", size, i)
			}
			p.put(b[:17]) // ReadMsg may have cut its length to max
		}
		if p.count != 4 {
			t.Fatalf("size %d: the class keeps %d buffers, want 4", size, p.count)
		}
		for range 4 {
			if b := p.get(); len(b) != size || cap(b) != size {
				t.Fatalf("size %d: a reused buffer has length %d, capacity %d", size, len(b), cap(b))
			}
		}
		for _, b := range p.buffers {
			if b != nil {
				t.Fatal("the class kept a reference to a lent buffer")
			}
		}
		p.put(borrowed[0])
		if !underRaceDetector {
			if allocs := testing.AllocsPerRun(100, func() { p.put(p.get()) }); allocs != 0 {
				t.Fatalf("a warm class allocates %v times per loan", allocs)
			}
		}
	}

	p := readMsgBufferCache{size: 8192}
	var wg sync.WaitGroup
	for i := 1; i <= 32; i++ {
		wg.Go(func() {
			for range 100 {
				b := p.get()
				for j := range b {
					b[j] = byte(i)
				}
				runtime.Gosched()
				for _, got := range b {
					if got != byte(i) {
						t.Errorf("a lent buffer was shared: %d, want %d", got, i)
						return
					}
				}
				p.put(b)
			}
		})
	}
	wg.Wait()
	if p.count > 4 {
		t.Fatalf("concurrent returns left %d buffers in a class of 4", p.count)
	}
}

// --- ReadMsg against a scripted kernel ----------------------------------------

// commUp is an AssocCommUp record of the given length, its tail filled
// with fill, which a connection subscribed to EventAssocChange delivers.
func commUp(length int, fill byte) []byte {
	b := notifSized(EventAssocChange, length, length, fill)
	binary.NativeEndian.PutUint16(b[assocChangeStateOff:], uint16(AssocCommUp))
	return b
}

// requireOwned checks a ReadMsg result against what it must still hold.
func requireOwned(t *testing.T, name string, got, want []byte, info, wantInfo RcvInfo) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s: payload changed or wrong (%d bytes, want %d)", name, len(got), len(want))
	}
	if info != wantInfo {
		t.Errorf("%s: RcvInfo %+v, want %+v", name, info, wantInfo)
	}
}

// TestReadMsgResultsSurviveInterleavedNotificationReentry: a handler
// reading the next message from inside a ReadMsg, between two pieces of
// the outer message, leaves both results whole and each with its own first
// piece's RcvInfo, through later reads and the caller changing one result
// (v1 test of the same name).
func TestReadMsgResultsSurviveInterleavedNotificationReentry(t *testing.T) {
	first := RcvInfo{Stream: 1, SSN: 2, Unordered: true, PPID: 0x11223344, TSN: 10, CumTSN: 11, Context: 5, AssocID: 12}
	later := RcvInfo{Stream: 21, PPID: 0xa1a2a3a4, AssocID: 29}
	nested := RcvInfo{Stream: 31, PPID: 0xb1b2b3b4, AssocID: 39}
	third := RcvInfo{Stream: 41, PPID: 0xc1c2c3c4, AssocID: 49}
	note := commUp(sizeAssocChange, 0x5a)
	script := &recvScript{steps: []recvStep{
		{data: []byte("outer-prefix/"), rcv: &first},
		{data: note[:7], flags: msgNotification},
		{data: note[7:], flags: msgNotification | msgEOR},
		{data: []byte("outer-suffix"), rcv: &later, flags: msgEOR},
		{data: []byte("nested-record"), rcv: &nested, flags: msgEOR},
		{data: []byte("third-record"), rcv: &third, flags: msgEOR},
	}}
	var (
		c          *Conn
		nestedData []byte
		nestedInfo RcvInfo
		nestedErr  error
		handled    int
	)
	c = scriptConn(t, func(n Notification) error {
		handled++
		nestedData, nestedInfo, nestedErr = c.ReadMsg(128)
		return nestedErr
	}, EventAssocChange)
	hookRecvmsg(t, script.recvmsg)

	outer, outerInfo, err := c.ReadMsg(128)
	if err != nil || handled != 1 {
		t.Fatalf("ReadMsg: %v, handler calls %d", err, handled)
	}
	requireOwned(t, "outer", outer, []byte("outer-prefix/outer-suffix"), outerInfo, first)
	requireOwned(t, "nested", nestedData, []byte("nested-record"), nestedInfo, nested)
	thirdData, thirdInfo, err := c.ReadMsg(128)
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	thirdData[0] ^= 0xff
	requireOwned(t, "outer after later reads", outer, []byte("outer-prefix/outer-suffix"), outerInfo, first)
	requireOwned(t, "nested after later reads", nestedData, []byte("nested-record"), nestedInfo, nested)
	requireOwned(t, "third", thirdData[1:], []byte("hird-record"), thirdInfo, third)
}

// TestReadMsgLaterPieceControlTruncation: MSG_CTRUNC on a later piece of a
// message is reported, and does not replace the first piece's RcvInfo (v1
// TestReadMsgLaterFragmentControlTruncationPreservesFirstInfo,
// TestReadMsgLargeControlTruncationRetainsPayload). Control data the walk
// cannot parse is not an error, and loses no payload (v1
// TestReadMsgMalformedFirstControlDoesNotLosePayload): parseRecvCmsgs
// ends its walk at a record that does not fit, as Linux never writes one.
func TestReadMsgLaterPieceControlTruncation(t *testing.T) {
	want := RcvInfo{Stream: 3, SSN: 4, Unordered: true, PPID: 0x01020304, Context: 6, TSN: 8, CumTSN: 9, AssocID: 10}
	other := RcvInfo{Stream: 13, PPID: 0xaabbccdd, AssocID: 20}
	next := RcvInfo{Stream: 23, PPID: 0x23232323, AssocID: 24}
	bad := make([]byte, sizeCmsghdr)
	putCmsgHeader(bad, 0, 1, cmsgRcvInfo) // declares a byte that is not there
	large := patterned(4136)
	c := scriptConn(t, nil)
	hookRecvmsg(t, (&recvScript{steps: []recvStep{
		{data: []byte("trusted-"), rcv: &want},
		{data: []byte("payload"), rcv: &other, flags: msgCtrunc | msgEOR},
		{data: large[:4096], rcv: &want},
		{data: large[4096:], rcv: &other, flags: msgCtrunc | msgEOR},
		{data: []byte("complete-with-bad-control"), ctl: bad, flags: msgEOR},
		{data: []byte("next"), rcv: &next, flags: msgEOR},
	}}).recvmsg)

	got, info, err := c.ReadMsg(64)
	wantReadError(t, err, ErrControlTruncated)
	requireOwned(t, "truncated", got, []byte("trusted-payload"), info, want)
	got, info, err = c.ReadMsg(65535)
	wantReadError(t, err, ErrControlTruncated)
	requireOwned(t, "large truncated", got, large, info, want)
	got, info, err = c.ReadMsg(64)
	if err != nil {
		t.Fatalf("malformed control: %v", err)
	}
	requireOwned(t, "malformed control", got, []byte("complete-with-bad-control"), info, RcvInfo{})
	got, info, err = c.ReadMsg(64)
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	requireOwned(t, "next", got, []byte("next"), info, next)
}

// TestReadMsgBoundsQueuedNotificationRetention: notifications arriving
// between the pieces of one message are held until it has been read,
// NotificationReassemblyLimit bytes in total; one that would exceed it is
// read through and dropped, with an error matching ErrNotificationTooLong,
// and the message and the next are still framed right (v1 test of the same
// name).
func TestReadMsgBoundsQueuedNotificationRetention(t *testing.T) {
	atLimit := commUp(NotificationReassemblyLimit, 0x66)
	over := commUp(sizeAssocChange+4, 0x77)
	after := commUp(sizeAssocChange+8, 0x88)
	var infos []int
	c := scriptConn(t, func(n Notification) error {
		infos = append(infos, len(n.(*AssocChange).Info))
		return nil
	}, EventAssocChange)
	hookRecvmsg(t, (&recvScript{steps: []recvStep{
		{data: []byte("before/")},
		{data: atLimit, flags: msgNotification | msgEOR},
		{data: over, flags: msgNotification | msgEOR},
		{data: []byte("after"), flags: msgEOR},
		{data: []byte("next-")},
		{data: after, flags: msgNotification | msgEOR},
		{data: []byte("record"), flags: msgEOR},
	}}).recvmsg)
	got, _, err := c.ReadMsg(64)
	wantReadError(t, err, ErrNotificationTooLong)
	if string(got) != "before/after" {
		t.Fatalf("payload %q, want before/after", got)
	}
	if !reflect.DeepEqual(infos, []int{NotificationReassemblyLimit - sizeAssocChange}) {
		t.Fatalf("delivered Info lengths %v, want only the one at the limit", infos)
	}
	got, _, err = c.ReadMsg(64)
	if err != nil || string(got) != "next-record" {
		t.Fatalf("the next ReadMsg = %q, %v", got, err)
	}
	if !reflect.DeepEqual(infos, []int{NotificationReassemblyLimit - sizeAssocChange, 8}) {
		t.Fatalf("delivered Info lengths %v: the notification after the overflow was lost", infos)
	}
}

// TestReadMsgLargeMixedResultsRemainOwned: results of every size class,
// with exact and larger maxima, stay whole across the reads that reuse the
// shared buffers, and a caller changing one leaves the others alone (v1
// TestReadMsgLargeMixedResultsRemainOwned,
// TestReadMsgLargeRejectedPrefixSurvivesNextRecord).
func TestReadMsgLargeMixedResultsRemainOwned(t *testing.T) {
	type kept struct {
		got, want []byte
		info      RcvInfo
		wantInfo  RcvInfo
	}
	c := scriptConn(t, nil)
	var all []kept
	sizes := []int{4095, 168, 4096, 255, 4097, 256, 4136, 257, 2047, 2048, 2049, 8191, 8192, 8193, 32767, 32768, 32769, 65535, 65536, 70000}
	for i, size := range sizes {
		payload := patterned(size)
		payload[0] = byte(i)
		first := RcvInfo{Stream: uint16(i), SSN: uint16(i + 1), Unordered: true, PPID: uint32(0x11220000 + i), Context: uint32(i + 3), AssocID: AssocID(-i - 1)}
		other := RcvInfo{Stream: 31, PPID: 0xffffffff, AssocID: 32}
		hookRecvmsg(t, (&recvScript{steps: []recvStep{
			{data: payload[:size/2], rcv: &first},
			{data: payload[size/2:], rcv: &other, flags: msgEOR},
		}}).recvmsg)
		max := size
		if i%2 == 0 {
			max += 4096
		}
		got, info, err := c.ReadMsg(max)
		if err != nil {
			t.Fatalf("size %d max %d: %v", size, max, err)
		}
		all = append(all, kept{got, payload, info, first})
		for j, k := range all {
			requireOwned(t, fmt.Sprintf("result %d after read %d", j, i), k.got, k.want, k.info, k.wantInfo)
		}
	}
	for i := range all {
		all[i].got[0] ^= 0xff
		for j := i + 1; j < len(all); j++ {
			requireOwned(t, fmt.Sprintf("result %d after changing %d", j, i), all[j].got, all[j].want, all[j].info, all[j].wantInfo)
		}
	}

	for _, max := range []int{257, 2048, 4095, 4096, 4097, 8192, 32768, 65535} {
		over := patterned(max + 8193)
		next := bytes.Repeat([]byte{0xd3, 0x19, 0x6e}, (max+2)/3)[:max]
		first, nextInfo := RcvInfo{Stream: 1, PPID: 7}, RcvInfo{Stream: 2, PPID: 8}
		hookRecvmsg(t, (&recvScript{steps: []recvStep{
			{data: over, rcv: &first, flags: msgEOR},
			{data: next, rcv: &nextInfo, flags: msgEOR},
		}}).recvmsg)
		got, info, err := c.ReadMsg(max)
		wantReadError(t, err, ErrMessageTooLong)
		requireOwned(t, "cut message", got, over[:max], info, first)
		later, laterInfo, err := c.ReadMsg(max)
		if err != nil {
			t.Fatalf("max %d: the next message: %v", max, err)
		}
		requireOwned(t, "next message", later, next, laterInfo, nextInfo)
		requireOwned(t, "cut message after the next", got, over[:max], info, first)
	}
}

// TestReadMsgNestedCacheExhaustion: handlers nested deeper than a size
// class holds buffers each get storage of their own, never one an outer
// read still uses, and never wait for one (v1
// TestReadMsgLargeNestedCacheExhaustion,
// TestReadMsgLargeInterleavedNotificationReentry).
func TestReadMsgNestedCacheExhaustion(t *testing.T) {
	const records = 6
	var steps []recvStep
	wants := make([][]byte, records)
	infos := make([]RcvInfo, records)
	for i := range records {
		wants[i] = bytes.Repeat([]byte{byte(i + 1)}, 4136)
		infos[i] = RcvInfo{Stream: uint16(i + 1), PPID: uint32(0x100 + i), AssocID: AssocID(i + 1)}
		steps = append(steps, recvStep{data: wants[i][:4096], rcv: &infos[i]})
		if i < records-1 {
			steps = append(steps, recvStep{data: commUp(4097, byte(i)), flags: msgNotification | msgEOR})
		}
		steps = append(steps, recvStep{data: wants[i][4096:], flags: msgEOR})
	}
	var (
		c                     *Conn
		started, active, peak int
		gots                  = make([][]byte, records)
		gotInfos              = make([]RcvInfo, records)
		read                  func() error
	)
	read = func() error {
		i := started
		started++
		active++
		peak = max(peak, active)
		defer func() { active-- }()
		got, info, err := c.ReadMsg(65535)
		gots[i], gotInfos[i] = got, info
		return err
	}
	c = scriptConn(t, func(Notification) error { return read() }, EventAssocChange)
	hookRecvmsg(t, (&recvScript{steps: steps}).recvmsg)
	if err := read(); err != nil {
		t.Fatal(err)
	}
	if started != records || peak != records {
		t.Fatalf("nested reads: %d started, %d at once; want %d", started, peak, records)
	}
	for i := range records {
		requireOwned(t, fmt.Sprintf("nested %d", i), gots[i], wants[i], gotInfos[i], infos[i])
	}
}

// TestReadMsgInterruptionFailsClosed: a message that cannot be read to its
// end, because recvmsg failed, the stream ended, or the deadline passed in
// the middle of it, returns what was read, with an error matching
// ErrMessageInterrupted and why, and aborts the connection; a notification
// record cut short does the same with ErrShortNotification, for every
// reader (v1 TestReadMsgApplicationInterruptionAlwaysFailsClosed,
// TestReadMsgLargeInterruptedPrefix,
// TestReadMsgNotificationInterruptionAlwaysFailsClosed,
// TestRecvmsgNotificationInterruptionAlwaysFailsClosed,
// TestInterruptedNotificationFailsConnectionClosed). A read the lifecycle
// is releasing reports net.ErrClosed with it (v1
// TestReadMsgLargePollInterruptionRetainsPrefix).
func TestReadMsgInterruptionFailsClosed(t *testing.T) {
	prefix := patterned(4136)
	first := RcvInfo{Stream: 1, PPID: 0x12345678}
	for _, tc := range []struct {
		name  string
		then  recvStep
		park  bool // the script then waits: the deadline or Close ends it
		close bool
		cause error
	}{
		{name: "recvmsg error", then: recvStep{err: syscall.EIO}, cause: syscall.EIO},
		{name: "end of stream", then: recvStep{}, cause: io.EOF},
		{name: "deadline", park: true, cause: os.ErrDeadlineExceeded},
		{name: "Close", park: true, close: true, cause: net.ErrClosed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := scriptConn(t, nil)
			steps := []recvStep{{data: prefix, rcv: &first}}
			if !tc.park {
				steps = append(steps, tc.then)
			}
			hookRecvmsg(t, (&recvScript{steps: steps, done: syscall.EAGAIN}).recvmsg)
			if tc.park {
				go func() {
					time.Sleep(50 * time.Millisecond)
					if tc.close {
						_ = c.Close()
					} else {
						_ = c.SetReadDeadline(time.Now())
					}
				}()
			}
			got, info, err := c.ReadMsg(65535)
			wantReadError(t, err, ErrMessageInterrupted)
			if !errors.Is(err, tc.cause) {
				t.Errorf("err = %v, want it to match %v too", err, tc.cause)
			}
			requireOwned(t, "interrupted", got, prefix, info, first)
			if c.opened() {
				t.Error("the connection is still open after an interrupted message")
			}
			// The shared buffers are reused; the prefix stays the caller's.
			other := scriptConn(t, nil)
			hookRecvmsg(t, (&recvScript{steps: []recvStep{{data: bytes.Repeat([]byte{0xa5}, 4136), flags: msgEOR}}}).recvmsg)
			if _, _, err := other.ReadMsg(65535); err != nil {
				t.Fatal(err)
			}
			requireOwned(t, "interrupted after reuse", got, prefix, info, first)
		})
	}

	// A record between the pieces of the message that says it will never
	// be completed ends the ReadMsg too; the record still reaches a
	// subscribed handler.
	pdAbort := notif(EventPartialDelivery, sizePDAPIEvent)
	for _, rec := range []struct {
		name  string
		data  []byte
		sub   EventType
		cause error
	}{
		{"restart", assocChangeRecord(AssocRestart, 7, nil), EventAssocChange, errAssocRestarted},
		{"partial delivery aborted", pdAbort, EventPartialDelivery, errPartialDeliveryAborted},
	} {
		for _, subscribed := range []bool{false, true} {
			if !subscribed && rec.sub != EventAssocChange {
				continue // Linux queues it only for a subscriber
			}
			t.Run(fmt.Sprintf("%s/subscribed=%t", rec.name, subscribed), func(t *testing.T) {
				var got []Notification
				var subs []EventType
				if subscribed {
					subs = []EventType{rec.sub}
				}
				c := scriptConn(t, func(n Notification) error { got = append(got, n); return nil }, subs...)
				hookRecvmsg(t, (&recvScript{steps: []recvStep{
					{data: prefix[:100], rcv: &first},
					{data: rec.data, flags: msgNotification | msgEOR},
					{data: []byte("the next message"), flags: msgEOR},
				}}).recvmsg)
				data, info, err := c.ReadMsg(65535)
				wantReadError(t, err, ErrMessageInterrupted)
				if !errors.Is(err, rec.cause) {
					t.Errorf("err = %v, want it to match %v too", err, rec.cause)
				}
				requireOwned(t, "cut", data, prefix[:100], info, first)
				if subscribed != (len(got) == 1) {
					t.Errorf("the handler received %d notifications, subscribed %t", len(got), subscribed)
				}
				if c.opened() {
					t.Error("the connection is still open after its message was cut")
				}
			})
		}
	}

	header := commUp(sizeAssocChange, 0)[:notificationHeaderSize]
	for _, cut := range []struct {
		name  string
		then  recvStep
		cause error
	}{
		{"recvmsg error", recvStep{err: syscall.EIO}, syscall.EIO},
		{"end of stream", recvStep{}, io.EOF},
		{"data", recvStep{data: []byte{0xbb}, flags: msgEOR}, syscall.EPROTO},
		{"nothing", recvStep{err: syscall.EAGAIN}, syscall.EAGAIN},
	} {
		for name, read := range map[string]func(c *Conn) error{
			"RecvMsg": func(c *Conn) error { _, _, err := c.RecvMsg(make([]byte, notificationHeaderSize)); return err },
			"Read":    func(c *Conn) error { _, err := c.Read(make([]byte, notificationHeaderSize)); return err },
			"ReadMsg": func(c *Conn) error { _, _, err := c.ReadMsg(64); return err },
		} {
			t.Run("notification/"+cut.name+"/"+name, func(t *testing.T) {
				c := scriptConn(t, func(Notification) error { return nil }, EventAssocChange)
				script := &recvScript{steps: []recvStep{{data: header, flags: msgNotification}, cut.then}}
				hookRecvmsg(t, script.recvmsg)
				err := read(c)
				wantReadError(t, err, ErrShortNotification)
				if !errors.Is(err, cut.cause) {
					t.Errorf("err = %v, want it to match %v too", err, cut.cause)
				}
				if script.calls != 2 {
					t.Errorf("%d recvmsg calls, want 2", script.calls)
				}
				if c.opened() {
					t.Error("the connection is still open after a notification was cut short")
				}
			})
		}
	}
}

// TestReadMsgHandlerPanicReleasesBuffers: a handler that panics in the
// middle of a ReadMsg returns the shared buffers the read borrowed, and the
// connection keeps working (v1 TestReadMsgLargeHandlerPanicReleasesScratch).
func TestReadMsgHandlerPanicReleasesBuffers(t *testing.T) {
	payload := patterned(4136)
	boom := errors.New("handler panic")
	var panicking atomic.Bool
	c := scriptConn(t, func(Notification) error {
		if panicking.Load() {
			panic(boom)
		}
		return nil
	}, EventAssocChange)
	counts := func() (r [4]int) {
		for i := range readMsgBuffers {
			p := &readMsgBuffers[i]
			p.mu.Lock()
			r[i] = p.count
			p.mu.Unlock()
		}
		return r
	}
	hookRecvmsg(t, (&recvScript{steps: []recvStep{{data: payload, flags: msgEOR}}}).recvmsg)
	if _, _, err := c.ReadMsg(65535); err != nil {
		t.Fatal(err)
	}
	before := counts()
	panicking.Store(true)
	hookRecvmsg(t, (&recvScript{steps: []recvStep{
		{data: payload[:4096]},
		{data: commUp(sizeAssocChange, 0x5a), flags: msgNotification | msgEOR},
		{data: payload[4096:], flags: msgEOR},
		{data: payload, flags: msgEOR},
	}}).recvmsg)
	func() {
		defer func() {
			if got := recover(); got != boom {
				t.Errorf("recovered %v, want the handler's panic", got)
			}
		}()
		_, _, _ = c.ReadMsg(65535)
	}()
	if after := counts(); after != before {
		t.Fatalf("the panic kept shared buffers: class counts %v, want %v", after, before)
	}
	panicking.Store(false)
	got, _, err := c.ReadMsg(65535)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("ReadMsg after the panic: %d bytes, %v", len(got), err)
	}
}

// FuzzReadMsgScriptedOwnership varies where a message is cut in two, where
// a notification between its pieces is cut, the message's size and max;
// each case reads the next message before checking the first result again
// (v1 test of the same name).
func FuzzReadMsgScriptedOwnership(f *testing.F) {
	f.Add([]byte("two fragments"), uint16(64), uint16(4), uint8(7))
	f.Add(patterned(2048), uint16(2048), uint16(2047), uint8(1))
	f.Add(patterned(2049), uint16(2048), uint16(2048), uint8(19))
	f.Add(patterned(4097), uint16(4096), uint16(2049), uint8(8))
	f.Add(patterned(65533), uint16(65534), uint16(32767), uint8(8))
	handled := 0
	c := scriptConn(f, func(Notification) error { handled++; return nil }, EventAssocChange)
	// One hook for the whole run, reading the case's script: a hook set
	// and cleared per case could be cleared while a later case reads, when
	// the fuzzing engine runs cases back to back.
	var script *recvScript
	hookRecvmsg(f, func(fd int, msg *syscall.Msghdr, flags int) (int, error) { return script.recvmsg(fd, msg, flags) })
	f.Fuzz(func(t *testing.T, input []byte, rawMax, rawCut uint16, rawNoteCut uint8) {
		if len(input) > 65534 {
			input = input[:65534]
		}
		payload := append(append([]byte{0x91}, input...), 0x6e)
		max := int(rawMax) + 1
		cut := int(rawCut)%(len(payload)-1) + 1
		first := RcvInfo{Stream: 1, SSN: 2, Unordered: true, PPID: 0x10203040, AssocID: -9}
		laterInfo := RcvInfo{Stream: 11, PPID: 0xa0b0c0d0}
		note := commUp(sizeAssocChange, 0x4c)
		noteCut := int(rawNoteCut)%(len(note)-1) + 1
		next := []byte("later-fuzz-record")
		nextInfo := RcvInfo{Stream: 21, PPID: 0x51525354}
		script = &recvScript{steps: []recvStep{
			{data: payload[:cut], rcv: &first},
			{data: note[:noteCut], flags: msgNotification},
			{data: note[noteCut:], flags: msgNotification | msgEOR},
			{data: payload[cut:], rcv: &laterInfo, flags: msgEOR},
			{data: next, rcv: &nextInfo, flags: msgEOR},
		}}
		before := handled
		got, info, err := c.ReadMsg(max)
		want := payload
		if len(payload) > max {
			want = payload[:max]
			if !errors.Is(err, ErrMessageTooLong) {
				t.Fatalf("len %d max %d: %v, want ErrMessageTooLong", len(payload), max, err)
			}
		} else if err != nil {
			t.Fatalf("len %d max %d: %v", len(payload), max, err)
		}
		want = append([]byte(nil), want...)
		requireOwned(t, "first", got, want, info, first)
		if handled != before+1 {
			t.Fatalf("the handler ran %d times, want once", handled-before)
		}
		later, li, err := c.ReadMsg(64)
		if err != nil {
			t.Fatalf("later read: %v", err)
		}
		requireOwned(t, "later", later, next, li, nextInfo)
		requireOwned(t, "first after the later read", got, want, info, first)
	})
}

// FuzzReadMsg sends a message of a fuzzed size on a live association and
// reads it with a fuzzed max: whole when it fits, cut at max with
// ErrMessageTooLong otherwise, and the next message intact after it (v1
// test of the same name).
func FuzzReadMsg(f *testing.F) {
	for _, seed := range [][2]int{{1, 4096}, {255, 256}, {256, 256}, {257, 256}, {2048, 2048}, {2049, 2048}, {8192, 2048}, {65535, 65536}, {4097, 65535}, {65536, 65535}} {
		f.Add(seed[0], seed[1])
	}
	client, server := connPair(f, &Config{NoDelay: new(true)}, nil)
	f.Fuzz(func(t *testing.T, size, max int) {
		size = int(uint(size)%70000) + 1
		max = int(uint(max)%70000) + 1
		msg := patterned(size)
		if _, err := client.Write(msg); err != nil {
			t.Fatalf("Write %d: %v", size, err)
		}
		if _, err := client.Write([]byte("sentinel")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		setReadDeadline(t, server, 5*time.Second)
		got, _, err := server.ReadMsg(max)
		if size <= max {
			if err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("size %d max %d: %d bytes, %v", size, max, len(got), err)
			}
		} else if !errors.Is(err, ErrMessageTooLong) || !bytes.Equal(got, msg[:max]) {
			t.Fatalf("size %d max %d: %d bytes, %v; want the first %d and ErrMessageTooLong", size, max, len(got), err, max)
		}
		got, _, err = server.ReadMsg(64)
		if err != nil || string(got) != "sentinel" {
			t.Fatalf("the next message = %q, %v", got, err)
		}
	})
}

// --- allocations --------------------------------------------------------------

// readMsgFixture is a scripted recvmsg that hands payload over, again and
// again, in as many pieces as the reader's buffer needs, with control
// attached to each, and allocates nothing: the poller, reassembly, the
// ancillary-data parser and result ownership stay under measurement, and
// no sender's allocations are in this process's totals.
func readMsgFixture(payload, control []byte) func(int, *syscall.Msghdr, int) (int, error) {
	off := 0
	return func(_ int, msg *syscall.Msghdr, _ int) (int, error) {
		n := copy(unsafe.Slice(msg.Iov.Base, int(msg.Iov.Len)), payload[off:])
		off += n
		var flags int32
		if off == len(payload) {
			flags = msgEOR
			off = 0
		}
		msg.SetControllen(copy(unsafe.Slice(msg.Control, int(msg.Controllen)), control))
		msg.Flags = flags
		return n, nil
	}
}

// clearReadMsgClass empties one size class of the shared buffers, so that
// the next loan allocates. It clears the slots directly: draining through
// get would allocate inside the measurement.
func clearReadMsgClass(p *readMsgBufferCache) {
	p.mu.Lock()
	for i := range p.buffers {
		p.buffers[i] = nil
	}
	p.count = 0
	p.mu.Unlock()
}

// measureReadMsg reports the mean allocations and bytes of one ReadMsg of
// size bytes with max, over 1000 reads after 100 to warm up, with the
// collector paused, so that the counts land on whole numbers rather than
// carrying the collections the cold case would otherwise provoke. before
// runs inside the measured loop, and must not allocate.
func measureReadMsg(t *testing.T, c *Conn, size, max int, control []byte, before func()) (allocs, bytesPer float64) {
	t.Helper()
	payload := patterned(size)
	want := payload[:min(size, max)]
	hookRecvmsg(t, readMsgFixture(payload, control))
	var bad bool
	read := func() {
		if before != nil {
			before()
		}
		got, _, err := c.ReadMsg(max)
		if !bytes.Equal(got, want) || (err != nil) != (size > max) {
			bad = true
		}
	}
	for range 100 {
		read()
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	const records = 1000
	for range records {
		read()
	}
	runtime.ReadMemStats(&m1)
	if bad {
		t.Fatalf("ReadMsg(%d) of a %d-byte message returned the wrong result", max, size)
	}
	return float64(m1.Mallocs-m0.Mallocs) / records, float64(m1.TotalAlloc-m0.TotalAlloc) / records
}

// within reports whether got is within margin of want.
func within(got, want, margin float64) bool {
	return got-want < margin && want-got < margin
}

// TestReadMsgMemoryFollowsMessage pins the allocation figures ReadMsg
// documents (v1 TestReadMsgDocumentedAllocationContract, with v1's two
// allocations for metadata gone, since RcvInfo is a value): warm, 3 for a
// message of 256 bytes or fewer and 4 for a larger one, with SCTP_RCVINFO
// or without; cold, one more, of a whole size class. Memory follows the
// message, never max: ReadMsg(1<<24-1) of a 100-byte message costs what
// ReadMsg(256) does. The counts are process-wide, so the margins are on
// two scales: counts land on whole numbers, bytes carry the heap's own
// bookkeeping.
func TestReadMsgMemoryFollowsMessage(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector, whose instrumentation allocates on its own account")
	}
	const (
		allocMargin     = 0.05
		allocByteMargin = 16.0
	)
	c := scriptConn(t, nil)
	meta := recvControl(&RcvInfo{Stream: 3, PPID: 0x11223344}, nil)

	for _, tc := range []struct {
		name      string
		size, max int
		want      int
	}{
		// A message within the first buffer never grows and never borrows.
		{"below-boundary", 168, 65535, 3},
		{"at-boundary", 256, 65535, 3},
		{"above-boundary", 257, 65535, 4},
		{"large", 65535, 65535, 4},
		// The first buffer is min(256, max), so a small max admits its
		// own largest message without growing.
		{"small-max", 168, 168, 3},
	} {
		for _, metadata := range []bool{false, true} {
			t.Run(fmt.Sprintf("warm/%s/metadata=%t", tc.name, metadata), func(t *testing.T) {
				var control []byte
				if metadata {
					control = meta
				}
				got, _ := measureReadMsg(t, c, tc.size, tc.max, control, nil)
				if !within(got, float64(tc.want), allocMargin) {
					t.Fatalf("a warm ReadMsg allocated %.4f times, documented %d", got, tc.want)
				}
			})
		}
	}

	t.Run("cold", func(t *testing.T) {
		const size, max = 257, 65535
		class := &readMsgBuffers[0]
		warmAllocs, warmBytes := measureReadMsg(t, c, size, max, nil, nil)
		coldAllocs, coldBytes := measureReadMsg(t, c, size, max, nil, func() { clearReadMsgClass(class) })
		if !within(coldAllocs, warmAllocs+1, allocMargin) {
			t.Errorf("a cold ReadMsg allocated %.4f times, want warm+1 = %.4f", coldAllocs, warmAllocs+1)
		}
		if grew := coldBytes - warmBytes; !within(grew, float64(class.size), allocByteMargin) {
			t.Errorf("a cold ReadMsg allocated %.1f more bytes, want the whole %d-byte class", grew, class.size)
		}
	})

	t.Run("max does not cost memory", func(t *testing.T) {
		smallAllocs, smallBytes := measureReadMsg(t, c, 100, 256, meta, nil)
		hugeAllocs, hugeBytes := measureReadMsg(t, c, 100, 1<<24-1, meta, nil)
		if !within(hugeAllocs, smallAllocs, allocMargin) || !within(hugeBytes, smallBytes, allocByteMargin) {
			t.Errorf("ReadMsg(1<<24-1) of 100 bytes: %.4f allocations, %.1f bytes; ReadMsg(256): %.4f, %.1f",
				hugeAllocs, hugeBytes, smallAllocs, smallBytes)
		}
		if hugeBytes > 1024 {
			t.Errorf("ReadMsg(1<<24-1) of 100 bytes allocated %.1f bytes", hugeBytes)
		}
	})
}

// TestReadMsgAllocationBudget keeps loose ceilings on ReadMsg's
// allocations for every size class, with and without metadata and for
// messages cut at max, including a long drain (v1
// TestReadMsgAllocationBudget). It also runs under the race detector,
// whose counts are higher, with ceilings to match.
func TestReadMsgAllocationBudget(t *testing.T) {
	c := scriptConn(t, nil)
	scale := 1.0
	if underRaceDetector {
		scale = 4
	}
	for _, metadata := range []bool{false, true} {
		var control []byte
		if metadata {
			control = recvControl(&RcvInfo{Stream: 3, SSN: 7, PPID: 0x11223344, Context: 11, TSN: 17, CumTSN: 19, AssocID: 23}, nil)
		}
		for _, tc := range []struct {
			size, max int
			bytes     float64
			allocs    float64
		}{
			{168, 168, 1024, 4},
			{256, 65535, 1024, 4},
			{257, 65535, 4096, 5},
			{2048, 65535, 4096, 5},
			{2049, 65535, 8192, 5},
			{4097, 65535, 6144, 5},
			{8193, 65535, 12288, 5},
			{65535, 65535, 70000, 5},
			// A message cut at max also returns ErrMessageTooLong in a
			// *net.OpError, which carries copies of the connection's two
			// address snapshots: on this scripted connection, which has no
			// addresses, one allocation each, so 6 in all.
			{169, 168, 1024, 7},
			{65535, 168, 1024, 7},
		} {
			t.Run(fmt.Sprintf("size=%d/max=%d/metadata=%t", tc.size, tc.max, metadata), func(t *testing.T) {
				allocs, bytesPer := measureReadMsg(t, c, tc.size, tc.max, control, nil)
				if bytesPer > tc.bytes*scale || allocs > tc.allocs*scale {
					t.Fatalf("ReadMsg allocated %.1f times and %.0f bytes; ceilings %v and %v", allocs, bytesPer, tc.allocs*scale, tc.bytes*scale)
				}
			})
		}
	}
}

// BenchmarkReadMsgAssembly measures ReadMsg's reassembly and ownership
// across the size classes, with the kernel scripted (v1
// BenchmarkReadMsgAssembly).
func BenchmarkReadMsgAssembly(b *testing.B) {
	for _, size := range []int{168, 256, 257, 2048, 2049, 4096, 4097, 8193, 65535} {
		for _, metadata := range []bool{false, true} {
			b.Run(fmt.Sprintf("size=%d/metadata=%t", size, metadata), func(b *testing.B) {
				c := scriptConn(b, nil)
				var control []byte
				if metadata {
					control = recvControl(&RcvInfo{Stream: 3, PPID: 0x11223344}, nil)
				}
				hookRecvmsg(b, readMsgFixture(patterned(size), control))
				b.SetBytes(int64(size))
				b.ReportAllocs()
				for b.Loop() {
					if got, _, err := c.ReadMsg(65535); err != nil || len(got) != size {
						b.Fatalf("ReadMsg: %d bytes, %v", len(got), err)
					}
				}
			})
		}
	}
}

// TestRecvZeroAllocs pins that RecvMsg and Read allocate nothing per call
// for data, with ReceiveNxtInfo on and off, on a real association to a
// peer in another process (the helper sender), so that only this
// process's reads are counted: warm, over many reads; and for the first
// read of a fresh connection, which consumes the AssocCommUp record the
// package keeps subscribed before it reaches the message, measured one
// read at a time over many connections.
func TestRecvZeroAllocs(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector, whose instrumentation allocates on its own account")
	}
	const (
		runs          = 1000
		size          = 64
		mallocsMargin = 0.05 // per read: fewer than 1 in 20 reads saw a stray allocation
		bytesMargin   = 4.0  // per read: less than the smallest allocation, 8 bytes
		fresh         = 25   // connections measured on their first read
	)
	type reader func(c *Conn, buf []byte) (int, MsgInfo, error)
	readers := []struct {
		name string
		read reader
	}{
		{"RecvMsg", func(c *Conn, buf []byte) (int, MsgInfo, error) { return c.RecvMsg(buf) }},
		{"Read", func(c *Conn, buf []byte) (int, MsgInfo, error) { n, err := c.Read(buf); return n, MsgInfo{}, err }},
	}
	for _, nxt := range []bool{false, true} {
		for _, r := range readers {
			cfg := &Config{NoDelay: new(true), ReceiveNxtInfo: new(nxt)}
			t.Run(fmt.Sprintf("%s/nxtinfo=%t", r.name, nxt), func(t *testing.T) {
				peer := startHelperSender(t, "sctp4", "127.0.0.1:0", 1)
				c, err := cfg.Dial(testContext(t, 10*time.Second), "sctp4", nil, peer)
				if err != nil {
					t.Fatalf("Dial: %v", err)
				}
				defer func() { _ = c.Abort() }()
				if _, err := fmt.Fprintf(c, "%d %d", 2*runs+2, size); err != nil {
					t.Fatalf("request: %v", err)
				}
				setReadDeadline(t, c, 60*time.Second)
				buf := make([]byte, 256)
				var (
					bad    bool
					hasNxt int
				)
				read := func() {
					n, info, err := r.read(c, buf)
					if err != nil || n != size {
						bad = true
					}
					if info.HasNxt {
						hasNxt++
					}
				}
				read()
				allocs, mallocs, bytes := sendAllocs(runs, read)
				if bad {
					t.Fatal("a read returned an error or the wrong length")
				}
				if allocs != 0 || mallocs >= mallocsMargin || bytes >= bytesMargin {
					t.Errorf("AllocsPerRun %v; %.4f allocations and %.2f bytes per read, want 0", allocs, mallocs, bytes)
				}
				if nxt && r.name == "RecvMsg" && hasNxt == 0 {
					t.Error("no read reported a next message: NXTINFO was not exercised")
				}
			})

			t.Run(fmt.Sprintf("%s/nxtinfo=%t/first read", r.name, nxt), func(t *testing.T) {
				peer := startHelperSender(t, "sctp4", "127.0.0.1:0", fresh)
				buf := make([]byte, 256)
				var mallocs, total uint64
				for i := range fresh {
					c, err := cfg.Dial(testContext(t, 10*time.Second), "sctp4", nil, peer)
					if err != nil {
						t.Fatalf("Dial %d: %v", i, err)
					}
					if _, err := fmt.Fprintf(c, "1 %d", size); err != nil {
						t.Fatalf("request: %v", err)
					}
					setReadDeadline(t, c, 10*time.Second)
					var (
						m0, m1 runtime.MemStats
						n      int
					)
					func() {
						defer debug.SetGCPercent(debug.SetGCPercent(-1))
						defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
						runtime.ReadMemStats(&m0)
						n, _, err = r.read(c, buf)
						runtime.ReadMemStats(&m1)
					}()
					if err != nil || n != size {
						t.Fatalf("connection %d: the first read = %d, %v", i, n, err)
					}
					if c.recv.typ != EventAssocChange {
						t.Fatalf("connection %d: the first read consumed no AssocCommUp record", i)
					}
					mallocs += m1.Mallocs - m0.Mallocs
					total += m1.TotalAlloc - m0.TotalAlloc
					_ = c.Abort()
				}
				if mean := float64(mallocs) / fresh; mean >= 0.25 {
					t.Errorf("the first read of a connection allocated %.2f times on average (%d over %d), want 0", mean, mallocs, fresh)
				}
				if mean := float64(total) / fresh; mean >= 8 {
					t.Errorf("the first read of a connection allocated %.1f bytes on average, want 0", mean)
				}
			})
		}
	}
}

// --- net.Conn contract and errors -----------------------------------------------

// TestReadErrorsCarryConnectionContext: every read error is a *net.OpError
// with Op "read", the connection's network, its local address snapshot as
// Source and its peer's as Addr, wrapping the cause once; io.EOF is
// returned as it is; a closed, nil or zero Conn gives net.ErrClosed, never
// nested (v1 TestNetConnIOErrorsCarryConnectionContext,
// TestNetConnIOErrorsPreserveExplicitNetwork,
// TestClosedNetConnErrorsRetainConnectionContext,
// TestErrorsAfterCloseWrapNetErrClosed,
// TestNetConnGracefulCloseReturnsDirectEOF,
// TestClosedOperationErrorRetainsNetErrorContract: the read halves).
func TestReadErrorsCarryConnectionContext(t *testing.T) {
	calls := map[string]func(c *Conn) error{
		"Read":    func(c *Conn) error { _, err := c.Read(make([]byte, 8)); return err },
		"RecvMsg": func(c *Conn) error { _, _, err := c.RecvMsg(make([]byte, 8)); return err },
		"ReadMsg": func(c *Conn) error { _, _, err := c.ReadMsg(8); return err },
	}
	for _, network := range []string{"sctp4", "sctp"} {
		t.Run(network, func(t *testing.T) {
			l := mustListen(t, nil, "sctp4", loopback4(0))
			client, server := dialAcceptNetwork(t, network, l)
			for name, call := range calls {
				if err := client.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
					t.Fatalf("SetReadDeadline: %v", err)
				}
				opErr := readOpError(t, call(client), os.ErrDeadlineExceeded)
				if opErr.Net != network || !reflect.DeepEqual(opErr.Source, client.LocalAddr()) || !reflect.DeepEqual(opErr.Addr, client.RemoteAddr()) {
					t.Errorf("%s: %#v, want Net %q with the connection's snapshots", name, opErr, network)
				}
				if _, nested := opErr.Err.(*net.OpError); nested {
					t.Errorf("%s: a *net.OpError inside the *net.OpError", name)
				}
				if ne, ok := call(client).(net.Error); !ok || !ne.Timeout() {
					t.Errorf("%s: the deadline error is not a net.Error with Timeout", name)
				}
			}
			if err := server.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			for name, call := range calls {
				if err := call(client); err != io.EOF {
					t.Errorf("%s after the peer's graceful Close = %#v, want io.EOF itself", name, err)
				}
			}
			if err := client.Abort(); err != nil {
				t.Fatalf("Abort: %v", err)
			}
			for name, call := range calls {
				opErr := readOpError(t, call(client), net.ErrClosed)
				if opErr.Err != net.ErrClosed {
					t.Errorf("%s after Abort: Err = %#v, want net.ErrClosed itself", name, opErr.Err)
				}
			}
		})
	}
	for name, c := range map[string]*Conn{"nil": nil, "zero": {}} {
		for call, f := range calls {
			if err := f(c); !errors.Is(err, net.ErrClosed) {
				t.Errorf("%s on a %s Conn = %v, want net.ErrClosed", call, name, err)
			}
		}
	}
}

// TestPendingReadObservesLaterDeadline: a Read parked with no deadline
// ends when a deadline set afterwards passes (v1
// TestNetConnPendingReadObservesLaterDeadline,
// TestReadWithoutDeadlineWaitsForData,
// TestReadWithDeadlineStillReportsTheDeadline).
func TestPendingReadObservesLaterDeadline(t *testing.T) {
	client, server := connPair(t, nil, nil)
	var conn net.Conn = server
	done := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 8))
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("a Read with no deadline returned %v with nothing sent", err)
	case <-time.After(200 * time.Millisecond):
	}
	deadline := time.Now().Add(150 * time.Millisecond)
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	select {
	case err := <-done:
		wantReadError(t, err, os.ErrDeadlineExceeded)
		if time.Now().Before(deadline.Add(-50 * time.Millisecond)) {
			t.Error("the Read returned well before the deadline")
		}
	case <-time.After(5 * time.Second):
		_, _ = client.Write([]byte("x"))
		t.Fatal("a parked Read did not observe the deadline set after it parked")
	}

	// A deadline in the future lets a message through, and a Read with no
	// deadline waits for one.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := client.Write([]byte("in time")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	buf := make([]byte, 16)
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "in time" {
		t.Fatalf("Read = %q, %v", buf[:n], err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		_, _ = client.Write([]byte("late"))
	}()
	if n, err := conn.Read(buf); err != nil || string(buf[:n]) != "late" {
		t.Fatalf("a Read with no deadline = %q, %v; want it to wait for the message", buf[:n], err)
	}
}

// TestAbortWakesAParkedReader: Abort releases a Read parked on the
// connection with net.ErrClosed, and the peer sees the ABORT (v1
// TestAbortWakesAParkedReader). Close does the same once its grace period
// ends.
func TestAbortWakesAParkedReader(t *testing.T) {
	for _, closer := range []string{"Abort", "Close"} {
		t.Run(closer, func(t *testing.T) {
			client, server := connPair(t, nil, &Config{CloseTimeout: 100 * time.Millisecond})
			done := make(chan error, 1)
			go func() {
				_, err := server.Read(make([]byte, 64))
				done <- err
			}()
			time.Sleep(100 * time.Millisecond)
			var err error
			if closer == "Abort" {
				err = server.Abort()
			} else {
				// The peer's kernel completes the SHUTDOWN at once; the
				// parked Read, woken by the end or by the release, reports
				// the close, which is under way (v1 TestSCTPCloseRecv).
				err = server.Close()
			}
			if err != nil {
				t.Fatalf("%s: %v", closer, err)
			}
			select {
			case err := <-done:
				wantReadError(t, err, net.ErrClosed)
			case <-time.After(5 * time.Second):
				t.Fatalf("a parked Read was still waiting 5 s after %s returned", closer)
			}
			setReadDeadline(t, client, 5*time.Second)
			_, err = client.Read(make([]byte, 64))
			want := error(io.EOF)
			if closer == "Abort" {
				want = syscall.ECONNRESET
			}
			if !errors.Is(err, want) {
				t.Errorf("the peer's read after %s = %v, want %v", closer, err, want)
			}
		})
	}
}

// mutateAddr changes every part of an address a caller was handed: the
// port, an IP in place, and the length of the list.
func mutateAddr(a net.Addr) {
	ad := a.(*Addr)
	ad.Port++
	if len(ad.IPs) > 0 {
		ad.IPs[0] = netip.MustParseAddr("192.0.2.99")
	}
	ad.IPs = append(ad.IPs, netip.MustParseAddr("198.51.100.1"))
}

// TestNetConnAfterClose: once the connection is closed, the deadline
// setters and a zero-length Read or Write report net.ErrClosed (v1
// TestNetConnDeadlineSettersAfterClose, TestNetConnZeroLengthClosedParity),
// and the address snapshots stay what they were; each call returns a copy
// of its own, so a caller changing one changes neither later calls nor the
// addresses errors carry (v1 TestNetConnAddressesRemainStableAfterClose).
func TestNetConnAfterClose(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	local, remote := client.LocalAddr().String(), client.RemoteAddr().String()
	mutateAddr(client.LocalAddr())
	mutateAddr(client.RemoteAddr())
	if client.LocalAddr().String() != local || client.RemoteAddr().String() != remote {
		t.Fatalf("changing returned addresses changed later calls: %v, %v; want %s, %s", client.LocalAddr(), client.RemoteAddr(), local, remote)
	}
	if err := client.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, err := client.Read(make([]byte, 8))
	opErr := readOpError(t, err, os.ErrDeadlineExceeded)
	mutateAddr(opErr.Source)
	mutateAddr(opErr.Addr)
	if client.LocalAddr().String() != local || client.RemoteAddr().String() != remote {
		t.Fatalf("changing an error's addresses changed the connection's: %v, %v", client.LocalAddr(), client.RemoteAddr())
	}
	if err := client.CloseWithTimeout(200 * time.Millisecond); err != nil {
		t.Fatalf("CloseWithTimeout: %v", err)
	}
	var conn net.Conn = client
	for name, err := range map[string]error{
		"SetDeadline":      conn.SetDeadline(time.Now().Add(time.Second)),
		"SetReadDeadline":  conn.SetReadDeadline(time.Now().Add(time.Second)),
		"SetWriteDeadline": conn.SetWriteDeadline(time.Now().Add(time.Second)),
	} {
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s after Close = %v, want net.ErrClosed", name, err)
		}
	}
	if n, err := conn.Read(nil); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Errorf("Read(nil) after Close = %d, %v; want net.ErrClosed", n, err)
	}
	if n, err := conn.Write(nil); n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Errorf("Write(nil) after Close = %d, %v; want net.ErrClosed", n, err)
	}
	if client.LocalAddr().String() != local || client.RemoteAddr().String() != remote {
		t.Errorf("addresses after Close %v, %v; want %s, %s", client.LocalAddr(), client.RemoteAddr(), local, remote)
	}
	mutateAddr(client.LocalAddr())
	if client.LocalAddr().String() != local {
		t.Errorf("changing a returned address after Close changed the next: %v, want %s", client.LocalAddr(), local)
	}
}

// TestAcceptReturnsNetConn: Accept returns the *Conn AcceptSCTP would, as a
// net.Conn, and on failure a nil net.Conn rather than one holding a nil
// *Conn (v1 TestAcceptDoesNotReturnATypedNilConn); the accepted
// connection does not inherit the listener's accept deadline (v1
// TestAcceptedConnDoesNotInheritTheAcceptDeadline).
func TestAcceptReturnsNetConn(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	var ln net.Listener = l
	if err := l.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	c, err := ln.Accept()
	if err == nil || c != nil {
		t.Fatalf("Accept past its deadline = %#v, %v; want a nil net.Conn and an error", c, err)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "accept" || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("Accept error = %v, want an accept error matching os.ErrDeadlineExceeded", err)
	}

	if err := l.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	client, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, listenerAddr(t, l))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Abort() })
	c, err = ln.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	server, ok := c.(*Conn)
	if !ok || server.AssocID() == 0 {
		t.Fatalf("Accept returned %T with association %v", c, server)
	}
	if err := l.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 8))
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("a Read on the accepted connection returned %v: it inherited the accept deadline", err)
	case <-time.After(300 * time.Millisecond):
	}
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("Read: %v", err)
	}
}

// TestSyscallConnReadSharesReceiveSerialization: a read through
// SyscallConn takes the connection's receive lock, so it never runs in the
// middle of one of the package's reads (v1 test of the same name).
func TestSyscallConnReadSharesReceiveSerialization(t *testing.T) {
	_, server := connPair(t, nil, nil)
	rc := mustSyscallConn(t, server)
	server.recv.mu.Lock()
	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- rc.Read(func(uintptr) bool { close(entered); return true })
	}()
	select {
	case <-entered:
		server.recv.mu.Unlock()
		t.Fatal("SyscallConn's Read ran while the receive lock was held")
	case <-time.After(50 * time.Millisecond):
	}
	server.recv.mu.Unlock()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("SyscallConn's Read did not run once the receive lock was free")
	}
	if err := <-done; err != nil {
		t.Fatalf("Read: %v", err)
	}
}

// TestRecvMsgMetadataStaysWithItsConnection: many associations read at
// once, each echoing on a stream and PPID of its own; every echo comes back
// with its own connection's metadata, never another's (v1
// TestPooledOobDoesNotCrossAssociations).
func TestRecvMsgMetadataStaysWithItsConnection(t *testing.T) {
	const peers, msgs, streams = 16, 30, 8
	cfg := &Config{InitMsg: InitMsg{OutStreams: streams, MaxInStreams: streams}, NoDelay: new(true)}
	l := mustListen(t, cfg, "sctp4", loopback4(0))
	laddr := listenerAddr(t, l)
	var srv sync.WaitGroup
	srv.Go(func() {
		for {
			c, err := l.AcceptSCTP()
			if err != nil {
				return
			}
			srv.Go(func() {
				defer func() { _ = c.Close() }()
				_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
				buf := make([]byte, 256)
				for {
					n, info, err := c.RecvMsg(buf)
					if err != nil {
						return
					}
					if _, err := c.SendMsg(buf[:n], SendOptions{Info: &SndInfo{Stream: info.Rcv.Stream, PPID: info.Rcv.PPID}}); err != nil {
						return
					}
				}
			})
		}
	})
	var wg sync.WaitGroup
	for p := range peers {
		wg.Go(func() {
			c, err := cfg.Dial(context.Background(), "sctp4", nil, laddr)
			if err != nil {
				t.Errorf("peer %d: Dial: %v", p, err)
				return
			}
			defer func() { _ = c.Close() }()
			_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
			stream, ppid := uint16(p%streams), uint32(0x1000+p)
			buf := make([]byte, 256)
			for m := range msgs {
				msg := []byte(fmt.Sprintf("peer %d message %d", p, m))
				if _, err := c.SendMsg(msg, SendOptions{Info: &SndInfo{Stream: stream, PPID: ppid}}); err != nil {
					t.Errorf("peer %d: SendMsg: %v", p, err)
					return
				}
				n, info, err := c.RecvMsg(buf)
				if err != nil {
					t.Errorf("peer %d: RecvMsg: %v", p, err)
					return
				}
				if string(buf[:n]) != string(msg) || info.Rcv.Stream != stream || info.Rcv.PPID != ppid || info.Rcv.AssocID != c.AssocID() {
					t.Errorf("peer %d message %d: %q with %+v, want its own stream %d, PPID %#x and association %d", p, m, buf[:n], info.Rcv, stream, ppid, c.AssocID())
					return
				}
			}
		})
	}
	wg.Wait()
	_ = l.Close()
	srv.Wait()
}

// TestReadDeadlines: a read deadline bounds a read that finds nothing, in
// the future or already passed; cleared, it lets a read wait; set from
// another goroutine, it reaches a parked read; it never cuts a message a
// read has, and it bounds a whole ReadMsg, not each of its recvmsg calls
// (v1 TestReadDeadlineExpires, TestReadDeadlineInThePast,
// TestReadDeadlineCleared, TestReadDeadlineDoesNotTruncateData,
// TestReadMsgDeadlineBoundsWholeCall, TestDeadlineSetFromAnotherGoroutine).
func TestReadDeadlines(t *testing.T) {
	client, server := connPair(t, &Config{WriteBuffer: new(1 << 20)}, nil)
	for _, d := range []time.Duration{-time.Second, 100 * time.Millisecond} {
		setReadDeadline(t, server, d)
		start := time.Now()
		_, err := server.Read(make([]byte, 8))
		wantReadError(t, err, os.ErrDeadlineExceeded)
		if elapsed := time.Since(start); elapsed > time.Second || (d > 0 && elapsed < d/2) {
			t.Errorf("a %v deadline ended the read after %v", d, elapsed)
		}
	}
	if err := server.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := server.Read(make([]byte, 8))
		done <- err
	}()
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("a read with the deadline cleared returned %v", err)
	default:
	}
	go func() { _ = server.SetReadDeadline(time.Now()) }()
	select {
	case err := <-done:
		wantReadError(t, err, os.ErrDeadlineExceeded)
	case <-time.After(5 * time.Second):
		t.Fatal("a deadline set from another goroutine did not reach the parked read")
	}

	setReadDeadline(t, server, 5*time.Second)
	for _, size := range []int{64, 4096, 20000} {
		msg := patterned(size)
		if _, err := client.Write(msg); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if got, _, err := server.ReadMsg(1 << 20); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("size %d under a deadline: %d bytes, %v", size, len(got), err)
		}
	}

	// A message far longer than one read, sent in the background: ReadMsg
	// either has it all within the deadline or ends at it, never later.
	msg := patterned(200000)
	go func() { _, _ = client.Write(msg) }()
	setReadDeadline(t, server, 500*time.Millisecond)
	start := time.Now()
	got, _, err := server.ReadMsg(1 << 20)
	if err == nil {
		if !bytes.Equal(got, msg) {
			t.Fatalf("ReadMsg succeeded with %d of %d bytes", len(got), len(msg))
		}
	} else if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ReadMsg = %v, want the message or os.ErrDeadlineExceeded", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("ReadMsg took %v under a 500 ms deadline", elapsed)
	}
}

// TestReadRetriesEINTR: a recvmsg interrupted by a signal is made again,
// in place, for data and between the pieces of a notification, by every
// reader (v1 TestSCTPReadRetriesEINTRDeterministically).
func TestReadRetriesEINTR(t *testing.T) {
	note := commUp(sizeAssocChange, 0x33)
	for name, read := range map[string]func(c *Conn) ([]byte, error){
		"Read":    func(c *Conn) ([]byte, error) { b := make([]byte, 16); n, err := c.Read(b); return b[:n], err },
		"RecvMsg": func(c *Conn) ([]byte, error) { b := make([]byte, 16); n, _, err := c.RecvMsg(b); return b[:n], err },
		"ReadMsg": func(c *Conn) ([]byte, error) { b, _, err := c.ReadMsg(16); return b, err },
	} {
		t.Run(name, func(t *testing.T) {
			var notes int
			c := scriptConn(t, func(Notification) error { notes++; return nil }, EventAssocChange)
			script := &recvScript{steps: []recvStep{
				{err: syscall.EINTR},
				{data: note[:9], flags: msgNotification},
				{err: syscall.EINTR},
				{data: note[9:], flags: msgNotification | msgEOR},
				{err: syscall.EINTR},
				{data: []byte("message"), flags: msgEOR},
			}}
			hookRecvmsg(t, script.recvmsg)
			got, err := read(c)
			if err != nil || string(got) != "message" || notes != 1 {
				t.Fatalf("read = %q, %v, %d notifications; want the message after the notification", got, err, notes)
			}
			if script.calls != 6 {
				t.Errorf("%d recvmsg calls, want 6", script.calls)
			}
		})
	}
}

// TestReadSurvivesSignals: reads through a storm of signals, which
// interrupt recvmsg and the poller's waits, deliver every message once and
// in order (v1 TestReadSurvivesSignals, TestSCTPReadRetriesEINTRUnderLoad).
func TestReadSurvivesSignals(t *testing.T) {
	client, server := connPair(t, &Config{NoDelay: new(true)}, nil)
	stop := signalStorm(t)
	defer stop()
	const messages = 2000
	setReadDeadline(t, server, 30*time.Second)
	errs := make(chan error, 1)
	go func() {
		buf := make([]byte, 64)
		for i := range messages {
			var (
				b   []byte
				err error
			)
			switch i % 3 {
			case 0:
				var n int
				n, err = server.Read(buf)
				b = buf[:n]
			case 1:
				var n int
				n, _, err = server.RecvMsg(buf)
				b = buf[:n]
			default:
				b, _, err = server.ReadMsg(64)
			}
			if err != nil {
				errs <- fmt.Errorf("read %d: %w", i, err)
				return
			}
			if numberOf(b) != i {
				errs <- fmt.Errorf("read message %d, want %d", numberOf(b), i)
				return
			}
		}
		errs <- nil
	}()
	for i := range messages {
		if _, err := client.Write(numbered(i)); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	if err := <-errs; err != nil {
		t.Fatal(err)
	}
}

// TestRecvMsgNxtInfoOnlyWithTheOption: with ReceiveNxtInfo off, no read
// reports a next message, even with one queued (v1
// TestSCTPReadNextInfoIsNilWithoutTheOption); with it on, the read
// reports it (v1 TestSCTPReadNextInfoReportsTheQueuedMessage).
func TestRecvMsgNxtInfoOnlyWithTheOption(t *testing.T) {
	for _, on := range []bool{false, true} {
		client, server := connPair(t, &Config{NoDelay: new(true)}, &Config{ReceiveNxtInfo: new(on)})
		for _, m := range []string{"a", "bb"} {
			if _, err := client.Write([]byte(m)); err != nil {
				t.Fatalf("Write: %v", err)
			}
		}
		time.Sleep(100 * time.Millisecond)
		setReadDeadline(t, server, 5*time.Second)
		_, info, err := server.RecvMsg(make([]byte, 64))
		if err != nil {
			t.Fatalf("RecvMsg: %v", err)
		}
		if info.HasNxt != on || (on && info.Nxt.Length != 2) {
			t.Errorf("ReceiveNxtInfo %t: HasNxt %t, Nxt %+v", on, info.HasNxt, info.Nxt)
		}
	}
}

// TestReadMsgHandlerReassemblesNotification: with a max of one byte, a
// notification still reaches the handler once and whole, and the one-byte
// message after it is returned (v1 TestReadMsgHandlerReassemblesNotification).
func TestReadMsgHandlerReassemblesNotification(t *testing.T) {
	var got []Notification
	client, server := connPair(t, nil, &Config{
		Notifications:       []EventType{EventAssocChange},
		NotificationHandler: func(n Notification) error { got = append(got, n); return nil },
	})
	if _, err := client.Write([]byte{'x'}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	setReadDeadline(t, server, 5*time.Second)
	b, _, err := server.ReadMsg(1)
	if err != nil || string(b) != "x" {
		t.Fatalf("ReadMsg(1) = %q, %v", b, err)
	}
	if len(got) != 1 {
		t.Fatalf("the handler ran %d times, want once", len(got))
	}
	if ac, ok := got[0].(*AssocChange); !ok || ac.State != AssocCommUp {
		t.Errorf("the handler received %#v, want AssocCommUp", got[0])
	}
}

// TestListenerDeadlinesAndAfterClose: a pending Accept observes a deadline
// set after it started, and once the listener is closed SetDeadline
// reports net.ErrClosed while Addr stays what it was; each Addr call
// returns a copy of its own, which the caller may change (v1
// TestSCTPListenerPendingAcceptObservesLaterDeadline, the listener halves
// of TestNetConnDeadlineSettersAfterClose and
// TestNetConnAddressesRemainStableAfterClose).
func TestListenerDeadlinesAndAfterClose(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	done := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if c != nil {
			_ = c.Close()
		}
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	if err := l.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Errorf("Accept = %v, want os.ErrDeadlineExceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a pending Accept did not observe the deadline set after it started")
	}
	addr := l.Addr().String()
	mutateAddr(l.Addr())
	if l.Addr().String() != addr {
		t.Fatalf("changing a returned Addr changed the next: %v, want %s", l.Addr(), addr)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := l.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Errorf("SetDeadline after Close = %v, want net.ErrClosed", err)
	}
	if l.Addr().String() != addr {
		t.Errorf("Addr after Close = %v, want %s", l.Addr(), addr)
	}
	mutateAddr(l.Addr())
	if l.Addr().String() != addr {
		t.Errorf("changing a returned Addr after Close changed the next: %v, want %s", l.Addr(), addr)
	}
}

// BenchmarkRecvMsg reads 512-byte messages a helper-process peer sends,
// so that allocs/op counts the reader alone (v1 BenchmarkSCTPRead).
func BenchmarkRecvMsg(b *testing.B) {
	peer := startHelperSender(b, "sctp4", "127.0.0.1:0", 1)
	c, err := (&Config{NoDelay: new(true)}).Dial(testContext(b, 10*time.Second), "sctp4", nil, peer)
	if err != nil {
		b.Fatalf("Dial: %v", err)
	}
	defer func() { _ = c.Abort() }()
	const size = 512
	buf := make([]byte, size)
	b.ReportAllocs()
	b.SetBytes(size)
	requested := 0
	for b.Loop() {
		if requested == 0 {
			b.StopTimer()
			if _, err := fmt.Fprintf(c, "%d %d", 10000, size); err != nil {
				b.Fatalf("request: %v", err)
			}
			requested = 10000
			b.StartTimer()
		}
		if _, _, err := c.RecvMsg(buf); err != nil {
			b.Fatalf("RecvMsg: %v", err)
		}
		requested--
	}
}

// TestRecvFlagsMatchKernel pins the msg_flags bits the receive path reads
// to the kernel's (v1 TestMsgEORMatchesKernel): MSG_EOR and MSG_CTRUNC from
// include/linux/socket.h, MSG_NOTIFICATION from include/uapi/linux/sctp.h.
func TestRecvFlagsMatchKernel(t *testing.T) {
	for _, tc := range []struct {
		name      string
		got, want int
	}{
		{"MSG_EOR", msgEOR, syscall.MSG_EOR},
		{"MSG_CTRUNC", msgCtrunc, syscall.MSG_CTRUNC},
		{"MSG_NOTIFICATION", msgNotification, 0x8000},
		{"MSG_DONTWAIT", recvFlags, syscall.MSG_DONTWAIT},
	} {
		if tc.got != tc.want {
			t.Errorf("%s = %#x, the kernel's is %#x", tc.name, tc.got, tc.want)
		}
	}
}

// TestIPv6AssociationRoundTrip: an sctp6 listener bound to the wildcard
// accepts an association from ::1, and a message crosses it (v1
// TestIPv6AssociationRoundTrip). Whether the
// host has IPv6 SCTP is decided with a raw socket, never with the code
// under test, so that a broken bind cannot skip the test meant to catch it.
func TestIPv6AssociationRoundTrip(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, ipprotoSCTP)
	if err != nil {
		t.Skipf("no IPv6 SCTP socket: %v", err)
	}
	berr := syscall.Bind(fd, &syscall.SockaddrInet6{Addr: [16]byte{15: 1}})
	_ = syscall.Close(fd)
	if berr != nil {
		t.Skipf("::1 cannot be bound: %v", berr)
	}
	l := mustListen(t, nil, "sctp6", &Addr{})
	accepted := make(chan *Conn, 1)
	go func() {
		c, err := l.AcceptSCTP()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	client, err := Dial(testContext(t, 10*time.Second), "sctp6", nil, addrOf(listenerAddr(t, l).Port, "::1"))
	if err != nil {
		t.Fatalf("Dial ::1: %v", err)
	}
	t.Cleanup(func() { _ = client.Abort() })
	server, ok := <-accepted
	if !ok {
		t.Fatal("AcceptSCTP failed")
	}
	t.Cleanup(func() { _ = server.Abort() })
	if _, err := client.Write([]byte("over v6")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	setReadDeadline(t, server, 3*time.Second)
	buf := make([]byte, 64)
	if n, err := server.Read(buf); err != nil || string(buf[:n]) != "over v6" {
		t.Fatalf("Read = %q, %v", buf[:n], err)
	}
	// Both sockets are dual-stack, so the association also carries their
	// IPv4 addresses (RFC 9260 §5.1.2); the address dialed must be among
	// the client's peer addresses, and ::1 among the server's.
	for side, a := range map[string]net.Addr{"client": client.RemoteAddr(), "server": server.RemoteAddr()} {
		if !slices.Contains(a.(*Addr).IPs, netip.IPv6Loopback()) {
			t.Errorf("the %s's peer addresses %v lack ::1", side, a)
		}
	}
}

// TestNotificationBufferReleasedAfterDelivery: the connection's
// notification buffer is reset as soon as a record has been delivered, so
// a connection that received one large notification does not keep a
// buffer that large while it waits for the next.
func TestNotificationBufferReleasedAfterDelivery(t *testing.T) {
	big := notif(EventRemoteError, sizeRemoteError+200<<10)
	for name, read := range map[string]func(c *Conn) error{
		"RecvMsg": func(c *Conn) error { _, _, err := c.RecvMsg(make([]byte, 64)); return err },
		"Read":    func(c *Conn) error { _, err := c.Read(make([]byte, 64)); return err },
		"ReadMsg": func(c *Conn) error { _, _, err := c.ReadMsg(64); return err },
	} {
		t.Run(name, func(t *testing.T) {
			var got int
			c := scriptConn(t, func(n Notification) error { got = len(n.(*RemoteError).Data); return nil })
			hookRecvmsg(t, (&recvScript{steps: []recvStep{
				{data: big, flags: msgNotification | msgEOR},
				{data: []byte("x"), flags: msgEOR},
			}}).recvmsg)
			if err := read(c); err != nil {
				t.Fatalf("read: %v", err)
			}
			if got != 200<<10 {
				t.Fatalf("the handler received %d bytes of data, want %d", got, 200<<10)
			}
			if n := cap(c.recv.notes.data); n > notificationDataDropCap {
				t.Errorf("after the delivery the connection keeps a %d-byte notification buffer", n)
			}
		})
	}
}

// TestSuccessPathsAllocateNothing pins that calls which succeed build no
// error, and so copy no address: the deadline setters, the SyscallConn
// handles' Control, Read and Write, and Listener.SetDeadline allocate
// nothing when they succeed. An error carries copies of the address
// snapshots, made only on the error branch. Close's success path releases
// the descriptor and cannot be measured apart from that, so its error
// wrapping is pinned on its own.
func TestSuccessPathsAllocateNothing(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector, whose instrumentation allocates on its own account")
	}
	const (
		runs          = 1000
		mallocsMargin = 0.05
		bytesMargin   = 4.0
	)
	client, _ := connPair(t, nil, nil)
	l := mustListen(t, nil, "sctp4", loopback4(0))
	rc := mustSyscallConn(t, client)
	lrc := mustListenerRawConn(t, l)
	later := time.Now().Add(time.Hour)
	control := func(uintptr) {}
	done := func(uintptr) bool { return true }
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"Conn.SetReadDeadline", func() error { return client.SetReadDeadline(later) }},
		{"Conn.SetWriteDeadline", func() error { return client.SetWriteDeadline(later) }},
		{"Conn.SetDeadline", func() error { return client.SetDeadline(later) }},
		{"SyscallConn Control", func() error { return rc.Control(control) }},
		{"SyscallConn Read", func() error { return rc.Read(done) }},
		{"SyscallConn Write", func() error { return rc.Write(done) }},
		{"Listener.SetDeadline", func() error { return l.SetDeadline(later) }},
		{"Listener SyscallConn Control", func() error { return lrc.Control(control) }},
		{"Close's error wrapping of nil", func() error { return client.closeError(nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var failed error
			call := func() {
				if err := tc.call(); err != nil {
					failed = err
				}
			}
			call()
			allocs, mallocs, bytes := sendAllocs(runs, call)
			if failed != nil {
				t.Fatalf("the call failed: %v", failed)
			}
			if allocs != 0 || mallocs >= mallocsMargin || bytes >= bytesMargin {
				t.Errorf("AllocsPerRun %v; %.4f allocations and %.2f bytes per call, want 0", allocs, mallocs, bytes)
			}
		})
	}
}
