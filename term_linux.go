// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// term_linux.go holds the association-error latch the send and receive
// paths share (termState, conn.go): the errors Linux reports once for a
// failed association, kept for every later call.

package sctp

import "syscall"

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
