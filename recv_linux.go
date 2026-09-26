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

// recv_linux.go is a Conn's receive path: RecvMsg, Read and ReadMsg, the
// notification subscriptions Subscribe and Subscribed, and the end of an
// association as reads see it.
//
// Every read goes through the connection's own storage (recvState) under
// its receive lock, and every recvmsg(2) runs in a callback bound once,
// when the Conn is built, while the latch mutex is held (termState), so
// that an association error the kernel hands a read is latched before any
// other call can look. Reading data allocates nothing.

package sctp

import (
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
)

// recvFlags is what every receive passes to recvmsg(2): MSG_DONTWAIT makes
// an empty queue an EAGAIN, which the receive path turns into a wait in
// the runtime poller, where a deadline or Close can end it.
const recvFlags = syscall.MSG_DONTWAIT

// testHookRecvmsg, when a test sets it, is called in place of rawRecvmsg
// by the receive path, to count, inspect or script its system calls.
var testHookRecvmsg func(fd int, msg *syscall.Msghdr, flags int) (int, error)

// recvState is a Conn's receive storage, reused by every read under mu, the
// connection's receive lock, which is held from the first recvmsg of a read
// until the read has what it returns, and released before a
// NotificationHandler runs. The descriptor's read lock (internal/poll:
// FD.readLock) is taken inside it, by raw.Read.
//
// Linux queues notifications on the same receive queue as data. A record
// larger than the buffer it is read into arrives in pieces: sctp_recvmsg
// hands over what fits, without MSG_EOR, and puts the rest back at the
// head of the queue (net/sctp/socket.c). Every notification record is
// reassembled in notes, whether or not the caller receives it: the first
// piece lands in the caller's buffer and the rest in scratch, all within
// one callback, so a deadline cannot cut a record in two. A record the
// caller receives is retained whole; one it does not, only its first bytes,
// which is all the package reads of it (assocChangeInfo), so consuming it
// allocates nothing.
type recvState struct {
	mu    sync.Mutex
	cbuf  [rcvCmsgSpace]byte // SCTP_RCVINFO and SCTP_NXTINFO
	msg   syscall.Msghdr     // points at iov and cbuf
	iov   syscall.Iovec      // points at b, or at scratch while a record continues
	b     []byte             // the destination of the next recvmsg, set only while mu is held
	notes notificationAccumulator
	fn    func(fd uintptr) bool // attempt, bound once

	// n, flags and err carry one attempt's result out; record and cut say
	// that it consumed a whole notification record, or one that ended
	// early, err saying why.
	n      int
	flags  int
	err    error
	record bool
	cut    bool

	term *termState     // the connection's association-error latch
	subs *atomic.Uint32 // the connection's logical subscriptions (Conn.subs)

	// keepNotes is set by the reader before each attempt: whether a record
	// the caller receives is retained, for its handler or to be returned
	// by RecvMsg.
	keepNotes bool

	// The notification record in progress.
	scratch [NotificationMaxSize]byte // where its pieces after the first land
	noting  bool                      // it has started and not yet ended
	typed   bool                      // its header is complete and typ holds its type
	typ     EventType
	kept    bool // it is retained whole in notes

	// A reassembled notification RecvMsg returns in pieces, to a caller
	// with no NotificationHandler: served bytes of it have been returned.
	serving   bool
	served    int
	serveInfo MsgInfo
}

// init prepares s for c's reads; newConn calls it for every connection.
// It binds the attempt callback, so that no read makes a closure, and
// needs no socket.
func (s *recvState) init(c *Conn) {
	s.term = &c.term
	s.subs = &c.subs
	s.fn = s.attempt
	s.msg.Iov = &s.iov
	s.msg.Iovlen = 1
	s.msg.Control = &s.cbuf[0]
}

// RecvMsg reads with one recvmsg (RFC 6458 §9.13's sctp_recvv) into b and
// returns the number of bytes read, with what the kernel reported about
// them: MSG_EOR says whether b received the end of the message, and the
// SCTP_RCVINFO record (RFC 6458 §5.3.5), which the package enables on
// every socket, fills Rcv. When b is shorter than the message, the rest is
// returned by the next reads, and EOR is false until the last. With
// ReceiveNxtInfo on, Nxt describes the next message queued, if there is
// one (RFC 6458 §5.3.6). A read of data makes no allocation. An empty b
// returns 0 at once, and consumes nothing.
//
// Notifications share the receive queue with data. With a
// NotificationHandler, RecvMsg hands each notification the caller receives
// to the handler, parsed, and goes on reading; an error the handler returns
// is returned by RecvMsg. Without one, RecvMsg returns the notification's
// bytes with MsgInfo.Notification set, in pieces as long as b, with EOR on
// the last, as for a message; ParseNotification decodes the whole. The
// caller receives the notifications Subscribe and Config.Notifications
// switch on. The package keeps EventAssocChange subscribed in the kernel on
// every socket, because its records are how the package sees the
// association end, and consumes them unseen unless the caller subscribed to
// EventAssocChange. A type switched on outside the package, through
// Config.Control or SyscallConn, is delivered when the kernel queues it,
// but Subscribed reports only what Config.Notifications and Subscribe set.
//
// The control buffer holds SCTP_RCVINFO and SCTP_NXTINFO. Other ancillary
// data switched on through Config.Control or SyscallConn can outgrow it:
// SO_TIMESTAMP's record together with SCTP_NXTINFO, for example, or the
// SCTP_SNDRCV record of SCTP_DATA_IO_EVENT. Linux then sets MSG_CTRUNC
// (net/core/scm.c: put_cmsg), and RecvMsg returns the bytes it read, with
// what it could parse, and an error matching ErrControlTruncated. It
// reports the flag for data only: no SCTP_RCVINFO accompanies a
// notification record (net/sctp/ulpevent.c: sctp_ulpevent_read_rcvinfo), so
// the flag is not reported for one, and a truncated SCTP_NXTINFO is then
// simply absent.
//
// Every error is a *net.OpError with Op "read", except io.EOF, which is
// returned unwrapped once the association has shut down gracefully, after
// the last message. Once the association has failed, and every message
// queued before the failure has been read, every read returns the error
// Linux reported for it: syscall.ECONNRESET after the peer's ABORT,
// syscall.ETIMEDOUT when retransmissions ran out, syscall.ECONNABORTED
// when this side aborted it, or syscall.ENOTCONN when that error was taken
// outside the package, through SyscallConn, or left on the listening
// socket because the association failed before Accept.
func (c *Conn) RecvMsg(b []byte) (int, MsgInfo, error) {
	if !c.opened() {
		return 0, MsgInfo{}, c.readError(net.ErrClosed)
	}
	if len(b) == 0 {
		return 0, MsgInfo{}, nil
	}
	for {
		n, info, note, err := c.recvNext(b, true)
		if note != nil {
			if err := c.handler(note); err != nil {
				return 0, MsgInfo{}, c.readError(err)
			}
			continue
		}
		if err != nil {
			return n, info, c.readError(err)
		}
		return n, info, nil
	}
}

// Read reads message bytes into b, as RecvMsg does without the metadata:
// it never returns a notification's bytes, handing each notification the
// caller receives to the NotificationHandler, when there is one, and
// skipping it otherwise. A message longer than b is returned over several
// reads, with nothing to mark where it ends; use RecvMsg or ReadMsg when
// the message boundary matters. A read of data makes no allocation. Errors
// are as for RecvMsg, except that Read ignores MSG_CTRUNC, since it returns
// no ancillary data.
func (c *Conn) Read(b []byte) (int, error) {
	if !c.opened() {
		return 0, c.readError(net.ErrClosed)
	}
	if len(b) == 0 {
		return 0, nil
	}
	for {
		n, _, note, err := c.recvNext(b, false)
		if note != nil {
			if err := c.handler(note); err != nil {
				return 0, c.readError(err)
			}
			continue
		}
		if err != nil {
			return 0, c.readError(err)
		}
		return n, nil
	}
}

// readError wraps a read's error once, with Op "read", the connection's
// network, and its address snapshots as Source and Addr; io.EOF is
// returned as it is. An error joined from several causes (an interrupted
// record, and why it was interrupted) is wrapped whole (ioOpError), its
// causes having been normalised when they were joined, so that none of
// them is lost to the collapse of a closed descriptor's errors into
// net.ErrClosed.
func (c *Conn) readError(err error) error {
	return ioOpError("read", c.network(), c.LocalAddr(), c.RemoteAddr(), err)
}

// readEnded is what a read that ends with err, or with the end of the
// stream, reports: net.ErrClosed while the connection is being closed or
// once it is, since the abortive close shuts the socket for reading
// (sockCloseOps.abortive) and so wakes a parked read with a zero-length
// result; err otherwise, with a closed descriptor's error normalised.
func (c *Conn) readEnded(err error) error {
	if lifeState(c.life.state.Load()) != lifeOpen {
		return net.ErrClosed
	}
	return closedCause(err)
}

// closedCause returns net.ErrClosed for any of the ways the standard
// library reports a closed descriptor (opError), and err otherwise.
func closedCause(err error) error {
	if err != nil && (errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) || isFileClosingErr(err)) {
		return net.ErrClosed
	}
	return err
}

// recvNext is one read of RecvMsg (raw) or Read (not raw) under the receive
// lock. It returns data, a notification's piece for RecvMsg without a
// handler, a parsed notification for the caller to hand to the handler
// once the lock is released, or how the read ends.
func (c *Conn) recvNext(b []byte, raw bool) (int, MsgInfo, Notification, error) {
	s := &c.recv
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if s.serving {
			if raw {
				n, info := s.servePiece(b)
				return n, info, nil, nil
			}
			s.stopServing()
		}
		if end := c.term.readEnd(); end != nil {
			return 0, MsgInfo{}, nil, c.readEnded(end)
		}

		s.b, s.keepNotes = b, raw || c.handler != nil
		perr := c.sock.raw.Read(s.fn)
		s.b = nil
		n, flags, record, cut, err := s.take()
		switch {
		case perr != nil:
			return 0, MsgInfo{}, nil, c.readEnded(perr)
		case cut:
			return 0, MsgInfo{}, nil, c.abortInterruptedNotification(err)
		case err != nil:
			return 0, MsgInfo{}, nil, c.readEnded(err)
		case record:
			if !s.kept {
				// Not the caller's: consumed. After AssocShutdownComplete,
				// the check above ends the read with io.EOF.
				s.notes.reset()
				continue
			}
			data, ferr := s.notes.finish()
			if ferr != nil {
				s.notes.reset()
				return 0, MsgInfo{}, nil, ferr
			}
			if c.handler != nil {
				// Parsed while the lock is held; the value copies every
				// byte it keeps, so the buffer is free for the next
				// record at once.
				note, perr := ParseNotification(data)
				s.notes.reset()
				if perr != nil {
					return 0, MsgInfo{}, nil, perr
				}
				return 0, MsgInfo{}, note, nil
			}
			// RecvMsg without a handler: the record is returned in
			// pieces, with the metadata of its last recvmsg (NXTINFO
			// describes what follows the whole record).
			_ = parseRecvCmsgs(s.control(), flags, &s.serveInfo)
			s.serving, s.served = true, 0
			n, info := s.servePiece(b)
			return n, info, nil, nil
		}
		if !raw {
			return n, MsgInfo{}, nil, nil
		}
		var info MsgInfo
		err = parseRecvCmsgs(s.control(), flags, &info)
		return n, info, nil, err
	}
}

// control returns the ancillary data the last recvmsg wrote.
func (s *recvState) control() []byte {
	return s.cbuf[:min(int(s.msg.Controllen), len(s.cbuf))]
}

// take returns one attempt's result and clears it.
func (s *recvState) take() (n, flags int, record, cut bool, err error) {
	n, flags, record, cut, err = s.n, s.flags, s.record, s.cut, s.err
	s.n, s.flags, s.record, s.cut, s.err = 0, 0, false, false, nil
	return n, flags, record, cut, err
}

// servePiece copies the next piece of the notification being served into
// b, and ends the serving, freeing the buffer, with its last.
func (s *recvState) servePiece(b []byte) (int, MsgInfo) {
	data := s.notes.data
	n := copy(b, data[s.served:])
	s.served += n
	info := s.serveInfo
	info.Notification = true
	info.EOR = s.served == len(data)
	if info.EOR {
		s.stopServing()
	}
	return n, info
}

// stopServing drops the rest of the notification being served: a Read or
// ReadMsg that comes in the middle of it skips it, as it skips every
// notification it does not hand to a handler.
func (s *recvState) stopServing() {
	s.serving, s.served = false, 0
	s.notes.reset()
}

// attempt is the raw.Read callback: it reads one thing, data, a whole
// notification record, or the end, into s.b, making each recvmsg while the
// latch mutex is held, so that an association error the kernel hands this
// read is latched before any other call can look (termState). It returns
// false, so that the poller waits, only when recvmsg finds nothing queued
// and the latch rules leave nothing to report (termState.readErrorLocked);
// it retries EINTR in place.
//
// A notification record's pieces after the first are read into scratch in
// the same callback, never waiting: Linux puts what did not fit back at
// the head of the queue before its recvmsg returns (net/sctp/socket.c:
// sctp_recvmsg), so anything else in its place means the record was cut
// short, which is reported with cut.
func (s *recvState) attempt(fd uintptr) bool {
	for {
		dst := s.b
		if s.noting {
			dst = s.scratch[:]
		}
		s.iov.Base = &dst[0]
		s.iov.SetLen(len(dst))
		s.msg.SetControllen(len(s.cbuf))
		s.msg.Flags = 0

		t := s.term
		t.mu.Lock()
		n, err := s.recvmsg(int(fd))
		flags := int(s.msg.Flags)
		piece := err == nil && flags&msgNotification != 0
		switch {
		case err == syscall.EINTR:
		case piece:
			s.addPiece(dst[:n])
			if flags&msgEOR != 0 {
				s.endRecordLocked()
			}
		case s.noting:
			// Whatever cut the record short, an association error it
			// took must still be latched.
			t.storeLocked(err)
		default:
			if err == nil && n == 0 {
				err = io.EOF
			}
			if err != nil {
				err = t.readErrorLocked(err)
			}
		}
		t.mu.Unlock()

		switch {
		case err == syscall.EINTR, piece && s.noting:
			continue
		case piece:
			s.n, s.flags, s.err, s.record = 0, flags, nil, true
		case s.noting:
			s.noting = false
			if err == nil {
				err = syscall.EPROTO // data where the record's next piece belonged
				if n == 0 {
					err = io.EOF
				}
			}
			s.n, s.flags, s.err, s.cut = 0, flags, err, true
		case err == syscall.EAGAIN:
			return false
		default:
			s.n, s.flags, s.err = n, flags, err
		}
		return true
	}
}

// recvmsg makes the one system call of an attempt.
func (s *recvState) recvmsg(fd int) (int, error) {
	if hook := testHookRecvmsg; hook != nil {
		return hook(fd, &s.msg, recvFlags)
	}
	return rawRecvmsg(fd, &s.msg, recvFlags)
}

// addPiece adds one piece of a notification record to notes, starting the
// record with its first. Once the record's header is complete, its type
// decides whether it is retained: a record the caller receives is, when
// the reader keeps notes; an SCTP_ASSOC_CHANGE the caller did not
// subscribe to never is, and every other type the kernel queued is one the
// caller subscribed to, since Subscribe changes the kernel's subscription
// for it.
func (s *recvState) addPiece(p []byte) {
	a := &s.notes
	if !s.noting {
		a.reset()
		s.noting, s.typed, s.kept = true, false, false
	}
	if !s.typed {
		if typ, ok := a.peekType(p); ok {
			s.typed, s.typ = true, typ
			if s.keepNotes && (typ != EventAssocChange || eventSet(s.subs.Load()).has(EventAssocChange)) {
				s.kept = a.keep()
			}
		}
	}
	a.add(p)
}

// endRecordLocked ends the record in progress and applies what an
// SCTP_ASSOC_CHANGE record says about the association (RFC 6458 §6.1.1),
// while the latch mutex is held, so that sends see it at once:
// AssocCommLost marks it failed, and AssocShutdownComplete marks it ended.
// Linux queues one of the two for every end (net/sctp/sm_sideeffect.c:
// sctp_cmd_assoc_failed; net/sctp/sm_statefuns.c: sctp_sf_do_9_2_final,
// sctp_sf_do_4_C), and the package keeps the event subscribed so that it
// does. AssocCommUp and AssocRestart change nothing: a restart keeps the
// association and its id (sctp_sf_do_dupcook_a), though it flushes any
// partial reassembly, and AssocCantStart ends only a setup that never made
// a Conn.
func (s *recvState) endRecordLocked() {
	s.noting = false
	if !s.typed || s.typ != EventAssocChange {
		return
	}
	state, _, ok := assocChangeInfo(s.notes.head())
	if !ok {
		return
	}
	switch state {
	case AssocCommLost:
		s.term.failed = true
	case AssocShutdownComplete:
		s.term.ended = true
	}
}

// abortInterruptedNotification ends a read whose notification record was
// cut short: its tail could otherwise be read as a record of its own, so
// the connection is aborted rather than left to misread its receive queue.
// Linux puts a record's rest back at the head of the queue at once, so this
// is a defensive path. c.recv.mu must be held.
func (c *Conn) abortInterruptedNotification(cause error) error {
	err := errors.Join(c.recv.notes.interrupted(), closedCause(cause))
	c.recv.notes.reset()
	return c.abortInterrupted(err)
}

// abortInterruptedMessage ends a ReadMsg that could not reach the end of
// its record.
func (c *Conn) abortInterruptedMessage(cause error) error {
	return c.abortInterrupted(errors.Join(ErrMessageInterrupted, closedCause(cause)))
}

// abortInterrupted aborts the connection after an interrupted record and
// returns err, joined with net.ErrClosed when the connection was already
// released, or with the abort's own failure.
func (c *Conn) abortInterrupted(err error) error {
	switch aerr := c.Abort(); {
	case aerr == nil:
	case errors.Is(aerr, net.ErrClosed):
		err = errors.Join(err, net.ErrClosed)
	default:
		err = errors.Join(err, aerr)
	}
	return err
}

// ReadMsg reads one whole message, reassembling it across as many recvmsg
// calls as the kernel needs to deliver it (RFC 6458 §3.1.4: MSG_EOR marks
// where a message ends), and returns it with the SCTP_RCVINFO of its first
// piece. The returned bytes belong to the caller; later reads never touch
// them. Notifications are consumed on the way: those the caller receives
// go to the NotificationHandler, if there is one, and none is ever
// returned as a message. Once the first piece of the message has arrived,
// the receive lock is held until its last, so a concurrent reader cannot
// take a piece of it; notifications that arrive in between are handed to
// the handler after it.
//
// At most max bytes are kept. A longer message is read to its end and
// dropped past max, and ReadMsg returns its first max bytes with an error
// matching ErrMessageTooLong: the next read starts at the next message. When
// the message cannot be read to its end, because the association ended or
// restarted, a partial delivery was aborted, or a deadline passed in the
// middle of it, ReadMsg returns what it read with an error matching
// ErrMessageInterrupted, and aborts the connection, whose receive queue
// could otherwise be misread from there. A max of zero or
// less is refused with an error matching syscall.EINVAL. Errors are as for
// RecvMsg.
//
// Memory follows the size of the message, never max: ReadMsg starts with a
// buffer of 256 bytes, or max when that is smaller, and grows it with the
// message, through bounded intermediate buffers shared across the process,
// copying the finished message into its own before it releases them.
// Warm, with the shared buffers populated, a call allocates 3 times for a
// message of 256 bytes or fewer and 4 times for a larger one. A call that
// finds no shared buffer free, the first calls in a process or more
// concurrent readers in one size class than it holds, adds one allocation
// of that whole size class, which for a small message exceeds the message
// itself: cold, a 257-byte message allocates 2048 bytes it did not need.
// Budget against the cold case; the warm figures are not a floor.
func (c *Conn) ReadMsg(max int) ([]byte, RcvInfo, error) {
	if max <= 0 {
		return nil, RcvInfo{}, c.readError(invalidArg("ReadMsg needs a positive max, got %d", max))
	}
	if !c.opened() {
		return nil, RcvInfo{}, c.readError(net.ErrClosed)
	}
	data, info, err := c.readMsg(max)
	if err != nil {
		err = c.readError(err)
	}
	return data, info, err
}

// readMsgState is one ReadMsg call's own state. The poller callback that
// fills it escapes, so the call keeps its captures together in one value,
// apart from the connection's storage, which a nested read from a
// NotificationHandler reuses.
type readMsgState struct {
	buf                 []byte
	bufferClass         int
	total               int
	first               RcvInfo
	haveFirstFragment   bool
	applicationComplete bool
	tooLong             bool
	resultErr           error

	queued      []Notification // for the handler, once the message is read
	queuedBytes int
	queueFull   bool
	immediate   Notification // for the handler before the message starts

	completedReceive      bool
	cutNotification       error // why a notification record ended early
	partialApplicationErr error // why the message ended early
}

// addError adds err to the call's result, joining it with any earlier.
func (s *readMsgState) addError(err error) {
	if err == nil {
		return
	}
	if s.resultErr == nil {
		s.resultErr = err
		return
	}
	s.resultErr = errors.Join(s.resultErr, err)
}

// readMsg is ReadMsg's reassembly. It holds the receive lock across one
// raw.Read for the message, and releases it to hand a notification to the
// handler before the message starts.
func (c *Conn) readMsg(max int) (data []byte, info RcvInfo, err error) {
	// Keep small messages inexpensive without changing the accepted
	// maximum.
	const chunk = 2048
	state := readMsgState{buf: make([]byte, min(256, max)), bufferClass: -1}
	defer func() {
		if state.bufferClass >= 0 {
			// Copy on every return, including partial results. The shared
			// buffer stays borrowed through any handler call.
			owned := make([]byte, len(data))
			copy(owned, data)
			data = owned
			readMsgBuffers[state.bufferClass].put(state.buf)
		}
	}()

	s := &c.recv
	for {
		state.immediate = nil
		state.completedReceive = false
		state.cutNotification = nil
		state.partialApplicationErr = nil

		s.mu.Lock()
		if s.serving {
			s.stopServing()
		}
		if end := c.term.readEnd(); end != nil {
			s.mu.Unlock()
			state.addError(c.readEnded(end))
			return state.buf[:state.total], state.first, state.resultErr
		}
		pollErr := c.sock.raw.Read(func(fd uintptr) bool {
			for {
				if !state.tooLong && state.total == len(state.buf) && state.total < max {
					grow := len(state.buf)
					if len(state.buf) < chunk {
						grow = chunk - len(state.buf)
					}
					if room := max - state.total; room < grow {
						grow = room
					}
					grown, class := getReadMsgBuffer(len(state.buf) + grow)
					if len(grown) > max {
						grown = grown[:max]
					}
					copy(grown, state.buf)
					if state.bufferClass >= 0 {
						readMsgBuffers[state.bufferClass].put(state.buf)
					}
					state.buf = grown
					state.bufferClass = class
				}

				// Past max, the rest of the message is drained through
				// the connection's scratch buffer.
				s.b = s.scratch[:]
				if !state.tooLong && state.total < len(state.buf) {
					s.b = state.buf[state.total:]
				}
				s.keepNotes = c.handler != nil && (!state.haveFirstFragment || !state.queueFull)
				if !s.attempt(fd) {
					return false
				}
				n, flags, record, cut, rerr := s.take()
				switch {
				case cut:
					state.cutNotification = rerr
					return true
				case rerr != nil:
					if state.haveFirstFragment && !state.applicationComplete {
						state.partialApplicationErr = rerr
					} else {
						state.addError(c.readEnded(rerr))
					}
					return true
				case record:
					state.completedReceive = true
					if !c.readMsgNotification(&state) {
						return true
					}
					continue
				}

				if !state.tooLong {
					state.total += n
					if !state.haveFirstFragment {
						state.haveFirstFragment = true
						var mi MsgInfo
						state.addError(parseRecvCmsgs(s.control(), flags, &mi))
						state.first = mi.Rcv
					} else if flags&msgCtrunc != 0 {
						state.addError(ErrControlTruncated)
					}
					if state.total == max && flags&msgEOR == 0 {
						state.tooLong = true
					}
				}
				if flags&msgEOR != 0 {
					state.completedReceive = true
					state.applicationComplete = true
					if state.tooLong {
						state.addError(ErrMessageTooLong)
					}
					return true
				}
			}
		})
		s.b = nil

		// A handler must run after raw.Read has returned: it may read from
		// the same connection. Before the message starts, the lock is
		// released for each notification, and the read resumes; the
		// notifications that come while the message is being read wait
		// until it has been read, so that no other reader can take a piece
		// of it meanwhile. A record cut short fails the connection before
		// any handler runs, so that none can read its orphaned tail as a
		// record of its own.
		recordInterrupted := state.haveFirstFragment && !state.applicationComplete
		switch {
		case state.cutNotification != nil:
			state.addError(c.abortInterruptedNotification(state.cutNotification))
			if recordInterrupted {
				state.addError(ErrMessageInterrupted)
			}
		case recordInterrupted:
			cause := state.partialApplicationErr
			if pollErr != nil {
				cause = pollErr
			}
			state.addError(c.abortInterruptedMessage(cause))
		case pollErr != nil:
			state.addError(c.readEnded(pollErr))
		}
		s.mu.Unlock()

		if state.immediate != nil {
			if err := c.handler(state.immediate); err != nil {
				state.addError(err)
				return state.buf[:state.total], state.first, state.resultErr
			}
			continue
		}
		for _, note := range state.queued {
			if err := c.handler(note); err != nil {
				state.addError(err)
				break
			}
		}
		state.queued = nil
		state.queuedBytes = 0
		return state.buf[:state.total], state.first, state.resultErr
	}
}

// readMsgNotification takes a whole notification record ReadMsg consumed,
// and reports whether the read goes on in the same callback. A record the
// caller does not receive is dropped, and ends the read with io.EOF when it
// was the association's AssocShutdownComplete. One for the handler before
// the message starts ends the callback, so that the handler can run; one
// that comes while the message is being read is queued, bounded by
// NotificationReassemblyLimit in total, and past that dropped with an
// error matching ErrNotificationTooLong.
func (c *Conn) readMsgNotification(state *readMsgState) bool {
	s := &c.recv
	if state.haveFirstFragment && !state.applicationComplete {
		if cut := s.messageCut(); cut != nil {
			// The message in progress will never be completed. The record
			// still goes to the handler, after the read, if it is the
			// caller's.
			state.partialApplicationErr = cut
			if s.kept {
				if data, err := s.notes.finish(); err == nil {
					if note, err := ParseNotification(data); err == nil {
						state.queued = append(state.queued, note)
					}
				}
			}
			s.notes.reset()
			return false
		}
	}
	if !s.kept {
		s.notes.reset()
		if c.term.hasEnded() {
			if state.haveFirstFragment && !state.applicationComplete {
				state.partialApplicationErr = io.EOF
			} else {
				state.addError(c.readEnded(io.EOF))
			}
			return false
		}
		return true
	}
	data, err := s.notes.finish()
	size := len(data)
	var note Notification
	if err == nil {
		note, err = ParseNotification(data)
	}
	s.notes.reset()
	if err != nil {
		state.addError(err)
		if errors.Is(err, ErrNotificationTooLong) {
			state.queueFull = true
		}
		return state.haveFirstFragment
	}
	if !state.haveFirstFragment {
		state.immediate = note
		return false
	}
	if state.queueFull {
		return true
	}
	if size > NotificationReassemblyLimit-state.queuedBytes {
		state.addError(ErrNotificationTooLong)
		state.queueFull = true
		return true
	}
	state.queued = append(state.queued, note)
	state.queuedBytes += size
	return true
}

// The causes ReadMsg joins with ErrMessageInterrupted when a record that
// arrives between the pieces of a message says that the message will never
// be completed.
var (
	errPartialDeliveryAborted = errors.New("sctp: the partial delivery of the message was aborted")
	errAssocRestarted         = errors.New("sctp: the association restarted")
)

// messageCut reports, for the record just consumed, whether it ends the
// message a ReadMsg is reading, and why: an SCTP_PARTIAL_DELIVERY_EVENT
// (RFC 6458 §6.1.7) says that the partial delivery in progress was
// aborted, and an AssocRestart that the restart flushed the reassembly of
// every message in progress (net/sctp/associola.c: sctp_assoc_update calls
// sctp_ulpq_flush). An AssocCommLost or AssocShutdownComplete ends the
// message through the reads that follow it.
func (s *recvState) messageCut() error {
	if !s.typed {
		return nil
	}
	switch s.typ {
	case EventPartialDelivery:
		return errPartialDeliveryAborted
	case EventAssocChange:
		if state, _, ok := assocChangeInfo(s.notes.head()); ok && state == AssocRestart {
			return errAssocRestarted
		}
	}
	return nil
}

// readMsgBuffers caches ReadMsg's intermediate assembly buffers, never a
// result the caller owns. Four buffers per class bound the idle storage to
// 424 KiB across all connections. A read borrows a buffer exclusively;
// neither a miss nor a return waits for one to become free. A larger
// message uses storage of its own, so this is no limit on the size of a
// message.
var readMsgBuffers = [...]readMsgBufferCache{
	{size: 2048},
	{size: 8192},
	{size: 32768},
	{size: 65536},
}

// readMsgBufferCache is one size class of readMsgBuffers.
type readMsgBufferCache struct {
	mu      sync.Mutex
	size    int
	buffers [4][]byte
	count   int
}

// get borrows a buffer of the class, allocating one when none is free.
func (p *readMsgBufferCache) get() []byte {
	p.mu.Lock()
	if p.count > 0 {
		p.count--
		b := p.buffers[p.count]
		p.buffers[p.count] = nil
		p.mu.Unlock()
		return b
	}
	p.mu.Unlock()
	return make([]byte, p.size)
}

// put returns a buffer of the class, dropping it when the class is full.
func (p *readMsgBufferCache) put(b []byte) {
	p.mu.Lock()
	if p.count < len(p.buffers) {
		p.buffers[p.count] = b[:cap(b)]
		p.count++
	}
	p.mu.Unlock()
}

// getReadMsgBuffer borrows a buffer of at least size bytes from the
// smallest class that holds it, and returns the class, or -1 for a buffer
// of its own when none does.
func getReadMsgBuffer(size int) ([]byte, int) {
	for i := range readMsgBuffers {
		if size <= readMsgBuffers[i].size {
			return readMsgBuffers[i].get(), i
		}
	}
	return make([]byte, size), -1
}

// Subscribe starts (on) or stops delivery of one notification type (RFC
// 6458 §6.2.2) to the caller: to the NotificationHandler, or from RecvMsg.
// For every type but EventAssocChange it sets the kernel's subscription
// with SCTP_EVENT (RFC 6458 §8.1.28), which on a connected socket applies
// to the association (net/sctp/socket.c: sctp_setsockopt_event). The
// package keeps EventAssocChange subscribed in the kernel either way,
// because its records are how the package sees the association end, and
// Subscribe decides only whether they reach the caller. A record already
// queued when the subscription changes is delivered as the subscription was
// when it was queued, except that an EventAssocChange record is delivered
// as the subscription is when it is read. A type switched on outside the
// package, through Config.Control or SyscallConn, is delivered when the
// kernel queues it, but Subscribed reports only what Config.Notifications
// and Subscribe set. A type EventType does not name is refused with an
// error matching syscall.EINVAL. Errors are *net.OpError with Op "set".
func (c *Conn) Subscribe(t EventType, on bool) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	if _, known := eventTypeNames[t]; !known {
		return c.argError("set", invalidArg("Subscribe: %v is not a notification type", t))
	}
	c.subMu.Lock()
	defer c.subMu.Unlock()
	if t != EventAssocChange {
		if err := c.sock.control(func(fd int) error { return setEvent(fd, t, on) }); err != nil {
			return c.optionError("set", err)
		}
	}
	if on {
		c.subs.Or(uint32(eventBit(t)))
	} else {
		c.subs.And(^uint32(eventBit(t)))
	}
	return nil
}

// Subscribed reports whether the caller subscribed to notifications of
// type t: the subscriptions Config.Notifications and Subscribe set, or,
// for a connection FileConn adopted, those the descriptor had. EventAssocChange
// is reported as the caller set it, although the package keeps it
// subscribed in the kernel. A type switched on outside the package, through
// Config.Control or SyscallConn, is delivered when the kernel queues it,
// but Subscribed reports only what Config.Notifications and Subscribe set.
// A type EventType does not name is refused with an error matching
// syscall.EINVAL. Errors are *net.OpError with Op "get".
func (c *Conn) Subscribed(t EventType) (bool, error) {
	if !c.opened() {
		return false, c.optionError("get", net.ErrClosed)
	}
	if _, known := eventTypeNames[t]; !known {
		return false, c.argError("get", invalidArg("Subscribed: %v is not a notification type", t))
	}
	return eventSet(c.subs.Load()).has(t), nil
}
