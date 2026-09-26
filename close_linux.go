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

// close_linux.go is the Linux half of the close state machine (close.go):
// the system calls behind closeOps, and the Conn methods that drive the
// machine with them.

package sctp

import (
	"errors"
	"net"
	"os"
	"syscall"
	"time"
)

// sockCloseOps is closeOps for one socket. Every step is one system call in
// a raw.Control callback of its own, so that each finds the descriptor
// pinned for its duration and none of them waits: the waits happen in the
// lifecycle, between steps. raw.Write is never used, because it would queue
// behind a send parked for buffer space, which holds the descriptor's write
// lock while it waits (internal/poll: FD.writeLock).
//
// Its closeClock serves one close call only (close.go), so every Close,
// CloseWithTimeout, Abort and Shutdown builds a sockCloseOps of its own.
type sockCloseOps struct {
	sock *socket
	kind connKind
	term *termState // the connection's association-error latch; nil for a socket that has none
	closeClock
}

// newCloseOps returns the steps that close c's descriptor.
func (c *Conn) newCloseOps() *sockCloseOps {
	return &sockCloseOps{sock: &c.sock, kind: c.kind, term: &c.term}
}

// assocGone asks SCTP_STATUS (RFC 6458 §8.2.1) whether the association
// still exists. The kernel keeps answering through every shutdown state,
// because sctp_id2assoc resolves a one-to-one or peeled socket's
// association while the socket is ESTABLISHED or CLOSING, and fails with
// EINVAL once the association has been freed (net/sctp/socket.c:
// sctp_getsockopt_sctp_status). An answer for an association in state
// CLOSED, which is one that ended before Accept (socket.status), is taken
// the same way. ENOTCONN is too, defensively, as v1's assocGone did:
// sctp_getsockopt_sctp_status itself answers only EINVAL or EFAULT. Any
// other error is not evidence that the shutdown completed and is
// returned.
func (o *sockCloseOps) assocGone() (bool, error) {
	_, state, err := o.sock.status()
	switch {
	case err == nil:
		return state == StateClosed, nil
	case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOTCONN):
		return true, nil
	default:
		return false, os.NewSyscallError("getsockopt", err)
	}
}

// startShutdown starts the graceful shutdown (RFC 9260 §9.2) with one call
// that returns at once. On a one-to-one socket that is shutdown(2) with
// SHUT_WR (RFC 6458 §4.1.7): sctp_shutdown moves the socket to CLOSING and
// issues the SHUTDOWN primitive. SHUT_WR, not SHUT_RDWR, leaves the socket
// readable, so that reads keep delivering what the peer still sends. On a
// peeled socket, where sctp_shutdown returns at once because the socket is
// not one-to-one style (net/sctp/socket.c), it is an empty send carrying
// SCTP_EOF: sctp_sendmsg_check_sflags issues the SHUTDOWN primitive and
// returns before sctp_sendmsg_to_asoc, the only path that waits for buffer
// space, so the send never waits.
func (o *sockCloseOps) startShutdown() error {
	if o.kind == kindPeeled {
		return o.sock.control(o.sendEOF)
	}
	err := o.sock.control(func(fd int) error { return syscall.Shutdown(fd, syscall.SHUT_WR) })
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return os.NewSyscallError("shutdown", err)
	}
	return err
}

// sendEOF makes the empty SCTP_EOF send of a peeled socket's graceful
// shutdown through the connection's latch, as every send does: the send is
// made while the latch mutex is held, so that an association error it
// takes from the socket, which Linux hands to the first send to find the
// association gone (net/sctp/socket.c: sctp_error), is latched for every
// later read and send. Once the latch holds an error, the association has
// failed, there is nothing to shut down, and that error is returned
// without a system call.
func (o *sockCloseOps) sendEOF(fd int) error {
	if o.term == nil {
		return eofSendError(rawSendEOF(fd))
	}
	o.term.mu.Lock()
	defer o.term.mu.Unlock()
	if err := o.term.err; err != nil {
		return err
	}
	err := rawSendEOF(fd)
	if err != nil {
		err = o.term.sendErrorLocked(err)
	}
	return eofSendError(err)
}

// eofSendError wraps the errno of an SCTP_EOF send.
func eofSendError(err error) error {
	if err != nil {
		return os.NewSyscallError("sendmsg", err)
	}
	return nil
}

// rawSendEOF makes the send itself: one SCTP_SNDINFO control message with
// SCTP_EOF set (RFC 6458 §5.3.4), and no payload at all, which is what
// sctp_sendmsg_parse requires of an SCTP_EOF send (net/sctp/socket.c).
// rawSendmsg passes the empty iovec through as it is. MSG_NOSIGNAL keeps a
// send to an association that is already gone from raising SIGPIPE. The
// error is the bare errno.
func rawSendEOF(fd int) error {
	var cbuf [sndCmsgSpace]byte
	n := appendSendCmsgs(cbuf[:0], &SndInfo{Flags: sndFlagEOF}, 0, nil, nil)
	var msg syscall.Msghdr
	msg.Control = &cbuf[0]
	msg.SetControllen(n)
	flags := syscall.MSG_DONTWAIT | syscall.MSG_NOSIGNAL
	if hook := testHookSendmsg; hook != nil {
		_, err := hook(fd, &msg, flags)
		return err
	}
	_, err := rawSendmsg(fd, &msg, flags)
	return err
}

// abortive ends the association with an ABORT (RFC 9260 §§9.1, 11.1.4) and
// releases the descriptor. SO_LINGER with l_onoff 1 and l_linger 0 (RFC
// 6458 §8.1.4) makes the final close send an ABORT instead of starting a
// SHUTDOWN (net/sctp/socket.c: sctp_close), and makes that close return at
// once instead of waiting out a linger time (sctp_wait_for_close).
//
// shutdown(2) with SHUT_RD comes between the two, carried over from v1's
// prepareSctpAbort: it sets RCV_SHUTDOWN and wakes anything waiting on the
// socket without starting a SHUTDOWN (sctp_shutdown acts only on
// SEND_SHUTDOWN), so that a callback blocked inside recvmsg(2) returns and
// drops its reference to the file. A blocked callback holds that reference,
// the descriptor's final close(2), the one that sends the ABORT, waits for
// the last reference (internal/poll: FD.Close), and a descriptor put back
// in blocking mode through SyscallConn would otherwise keep Close waiting
// for data that may never come. Its error is ignored: a socket with no
// association answers ENOTCONN (net/ipv4/af_inet.c: inet_shutdown), which
// is no reason to skip the release.
//
// The release happens whatever the SO_LINGER step reported. Its error is
// returned, joined with the release's, since without it the close starts a
// SHUTDOWN rather than sending an ABORT.
func (o *sockCloseOps) abortive() error {
	lerr := o.sock.control(func(fd int) error {
		return syscall.SetsockoptLinger(fd, syscall.SOL_SOCKET, syscall.SO_LINGER, &syscall.Linger{Onoff: 1, Linger: 0})
	})
	if lerr != nil && !errors.Is(lerr, net.ErrClosed) {
		lerr = os.NewSyscallError("setsockopt", lerr)
	}
	_ = o.sock.control(func(fd int) error { return syscall.Shutdown(fd, syscall.SHUT_RD) })
	return errors.Join(lerr, o.release())
}

// release releases the descriptor, through the *os.File that owns it: the
// one close(2) the descriptor ever gets. It wakes every call waiting on the
// descriptor in the runtime poller, which returns net.ErrClosed, and the
// close(2) itself runs once the last of them has left its callback
// (internal/poll: FD.Close).
func (o *sockCloseOps) release() error {
	return o.sock.file.Close()
}

// closeError wraps an error of Close, CloseWithTimeout, Abort or Shutdown
// once, with Op "close" and the connection's network and addresses; nil
// stays nil, without copying the addresses.
func (c *Conn) closeError(err error) error {
	if err == nil {
		return nil
	}
	return opError("close", c.sock.network, c.LocalAddr(), c.RemoteAddr(), err)
}

// Close shuts the association down gracefully (RFC 9260 §9.2) and releases
// the descriptor, waiting up to Config.CloseTimeout (3 s when it is zero)
// for the peer to complete the SHUTDOWN handshake and sending an ABORT
// (RFC 9260 §9.1) if it has not by then. It returns nil in both cases:
// running out of time is an outcome, not an error. An Abort from another
// goroutine during the wait sends the ABORT at once and makes Close return
// nil. Whatever arrives from the peer during the wait is discarded with the
// descriptor. A second Close, or any close after Abort, returns an error
// matching net.ErrClosed.
func (c *Conn) Close() error {
	if c == nil {
		return opError("close", "sctp", nil, nil, net.ErrClosed)
	}
	return c.closeError(c.life.close(c.newCloseOps(), c.closeWait))
}

// CloseWithTimeout is Close with a grace period of d. A d of zero or less
// aborts at once, as Abort does.
func (c *Conn) CloseWithTimeout(d time.Duration) error {
	if c == nil {
		return opError("close", "sctp", nil, nil, net.ErrClosed)
	}
	return c.closeError(c.life.close(c.newCloseOps(), d))
}

// Abort ends the association with an ABORT (RFC 9260 §§9.1, 11.1.4) and
// releases the descriptor. While a Close waits for the graceful shutdown,
// Abort makes that Close send the ABORT at once, waits until it has
// released the descriptor, and returns nil. After the descriptor has been
// released it returns an error matching net.ErrClosed.
func (c *Conn) Abort() error {
	if c == nil {
		return opError("close", "sctp", nil, nil, net.ErrClosed)
	}
	return c.closeError(c.life.abortNow(c.newCloseOps()))
}

// Shutdown starts the graceful shutdown (RFC 9260 §9.2) and returns at
// once, without releasing the descriptor. While the shutdown is in
// progress, sends fail with an error matching syscall.ESHUTDOWN, and once
// the association is gone with syscall.EPIPE. Reads keep delivering what
// the peer still sends, since the peer finishes its outstanding data
// before it answers, and then return io.EOF when the shutdown completes.
// Close is still needed afterwards to release the descriptor; it returns
// at once when the association is already gone. If the peer never
// answers, Linux ends the association when its SHUTDOWN retransmissions
// run out, and reads return that error.
//
// On a one-to-one socket this is shutdown(2) with SHUT_WR; on a
// connection peeled off an Endpoint, where Linux ignores shutdown(2), it
// is an empty SCTP_EOF send. A second Shutdown returns nil: Linux ignores
// a second SHUTDOWN primitive in every shutdown state
// (net/sctp/sm_statetable.c: sctp_sf_ignore_primitive).
func (c *Conn) Shutdown() error {
	if c == nil {
		return opError("close", "sctp", nil, nil, net.ErrClosed)
	}
	return c.closeError(c.life.shutdown(c.newCloseOps()))
}
