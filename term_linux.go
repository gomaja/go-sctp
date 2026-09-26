// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// term_linux.go holds the association-error latch the send and receive
// paths share (termState, conn.go): the errors Linux reports once for a
// failed association, kept for every later call, and the rules by which
// reads and sends see the end of an association.

package sctp

import (
	"io"
	"syscall"
)

// isAssocFailure reports whether err is one of the errors Linux sets on a
// one-to-one or peeled socket when its association fails: ECONNRESET after
// a peer ABORT, ETIMEDOUT when retransmissions run out, ECONNABORTED when
// this side aborted it (net/sctp/sm_sideeffect.c: sctp_cmd_set_sk_err,
// from SCTP_CMD_SET_SK_ERR in net/sctp/sm_statefuns.c).
func isAssocFailure(err error) bool {
	return err == syscall.ECONNRESET || err == syscall.ETIMEDOUT || err == syscall.ECONNABORTED
}

// latched returns the error the latch holds, or nil.
func (t *termState) latched() error {
	t.mu.Lock()
	err := t.err
	t.mu.Unlock()
	return err
}

// storeLocked latches err when it is an association failure and the latch
// is empty, and reports whether it is one. Linux sets the socket error
// once per association and hands it to one call (net/sctp/socket.c:
// sock_error from sctp_error and sctp_skb_recv_datagram), so the first
// error stored is the one to keep. t.mu must be held, and have been held
// since before the system call that returned err, so that no other call
// can observe the socket after Linux handed the error over and before it
// is latched.
func (t *termState) storeLocked(err error) bool {
	if !isAssocFailure(err) {
		return false
	}
	if t.err == nil {
		t.err = err
	}
	return true
}

// markFailed records that the association has failed (an AssocCommLost
// record was seen) although the error Linux reported for it may not have
// been latched.
func (t *termState) markFailed() {
	t.mu.Lock()
	t.failed = true
	t.mu.Unlock()
}

// sendErrorLocked applies the latch's rules to the error one sendmsg
// returned, and returns what the send reports. t.mu must be held, and
// have been held around the sendmsg.
//
// An association failure is latched. EPIPE means the association is gone
// with no error pending (net/sctp/socket.c: sctp_error turns EPIPE into the
// pending socket error when there is one): it becomes the latched error
// when there is one; otherwise, when the connection has seen its
// association fail, the error Linux reported was taken outside the
// package, or left on the listening socket for an association that failed
// before Accept (sctp_sock_migrate), and the send reports ENOTCONN, which
// is latched for every later call; otherwise the association ended
// gracefully and EPIPE stands.
func (t *termState) sendErrorLocked(err error) error {
	switch {
	case t.storeLocked(err):
		return err
	case err != syscall.EPIPE:
		return err
	case t.err != nil:
		return t.err
	case t.failed:
		t.err = syscall.ENOTCONN
		return t.err
	default:
		return err
	}
}

// observe latches err when it is an association failure, and returns what
// the call that got err reports: the latched error once the latch is set,
// whichever call set it, and err otherwise. t.mu must be held, and have
// been held around the system call that returned err.
func (t *termState) observe(err error) error {
	if t.storeLocked(err) || t.err != nil {
		return t.err
	}
	return err
}

// readErrorLocked applies the latch's rules to what one recvmsg found when
// it found no data and no notification: its errno, or io.EOF for a
// zero-length result, which Linux gives once the socket is shut for
// reading. t.mu must be held, and have been held around the recvmsg.
//
// An association failure is latched, and once the latch is set it is what
// the read reports: EAGAIN then means that another call took the error
// Linux set, and a zero-length result that the association failed after
// the socket was shut for reading. When the latch is empty but an
// AssocCommLost record has been seen (failed), the error Linux set for the
// failure is out of reach: something outside the package took it, for
// example by reading SO_ERROR through SyscallConn, or the association
// failed before Accept and Linux set it on the listening socket
// (net/sctp/socket.c: sctp_sock_migrate); EAGAIN or the end of the stream
// then becomes ENOTCONN, which is latched. After an AssocShutdownComplete
// record (ended) nothing more can arrive, and EAGAIN is the end of the
// stream, io.EOF. Otherwise EAGAIN is left for the caller to wait on, and
// io.EOF is the graceful end of the stream.
//
// Whenever the read reports the latch, the receive queue was empty
// (sctp_skb_recv_datagram looks at the socket error and the shutdown flags
// only once the queue is empty), so every later read reports it without a
// system call.
func (t *termState) readErrorLocked(err error) error {
	err = t.observe(err)
	switch {
	case t.err == nil && t.failed && (err == syscall.EAGAIN || err == io.EOF):
		t.err = syscall.ENOTCONN
		err = t.err
	case t.err == nil && t.ended && err == syscall.EAGAIN:
		err = io.EOF
	}
	if t.err != nil {
		t.drained = true
	}
	return err
}

// hasEnded reports whether an AssocShutdownComplete record has been seen.
func (t *termState) hasEnded() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ended
}

// readEnd returns what a read reports without a system call, or nil when
// it must make one: io.EOF once an AssocShutdownComplete record has been
// seen, since Linux marks nothing on the socket after a local shutdown or
// on a peeled socket (net/sctp/sm_sideeffect.c: sctp_cmd_new_state sets
// RCV_SHUTDOWN only on a one-to-one socket, when the peer's SHUTDOWN
// arrives on an ESTABLISHED one), and the latched error once a read has
// found nothing more after the association failed.
func (t *termState) readEnd() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	switch {
	case t.drained:
		return t.err
	case t.ended:
		return io.EOF
	}
	return nil
}
