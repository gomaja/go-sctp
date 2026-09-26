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

// close.go is the state machine behind Conn.Close, Conn.CloseWithTimeout,
// Conn.Abort and Conn.Shutdown, and behind Endpoint.Close and
// Endpoint.Abort. It decides what happens and when; the system calls it
// needs are behind closeOps, so the machine itself is the same, and is
// tested the same, on every platform.

package sctp

import (
	"errors"
	"net"
	"sync/atomic"
	"time"
)

// lifeState is where a lifecycle is. It only moves forward:
//
//   - lifeOpen to lifeClosing: close with a grace period;
//   - lifeOpen to lifeClosed: abortNow, or close with no grace period;
//   - lifeClosing to lifeAborting: abortNow while close waits;
//   - lifeClosing or lifeAborting to lifeClosed: close, once it has
//     released the descriptor.
type lifeState int32

const (
	// lifeOpen: the descriptor is in use. Shutdown keeps the lifecycle here.
	lifeOpen lifeState = iota
	// lifeClosing: a close is waiting for the graceful shutdown.
	lifeClosing
	// lifeAborting: still closing, but an Abort has arrived and closed the
	// abort channel. It is a state of its own so that exactly one Abort,
	// the one that moves the lifecycle here, closes that channel.
	lifeAborting
	// lifeClosed: the descriptor has been released, or is being released
	// by the call that moved the lifecycle here.
	lifeClosed
)

const (
	// shutdownPollMin and shutdownPollMax bound the backoff between two
	// association status polls while close waits for the graceful shutdown.
	// It starts short because the common case, a peer on the same host that
	// answers at once, completes in microseconds, and grows so that waiting
	// out a peer that never answers costs a handful of system calls rather
	// than thousands.
	shutdownPollMin = 200 * time.Microsecond
	shutdownPollMax = 20 * time.Millisecond
)

// lifecycle is the close state machine of one descriptor. A lifecycle must
// be initialised with init before it is shared; the zero value reports
// every call as closed, which is what a zero Conn, one the package never
// opened, should do.
//
// Its methods return the causes of a failure as they are: the bare
// net.ErrClosed for a descriptor already released or being released, and
// the errors closeOps reports. They know nothing of the connection's
// network or addresses, so the method calling them wraps what they return
// once, with opError and Op "close", to give it that context.
type lifecycle struct {
	state atomic.Int32  // a lifeState
	abort chan struct{} // closed by the Abort that moves the lifecycle to lifeAborting
	done  chan struct{} // closed once the descriptor has been released
	shut  atomic.Bool   // the graceful shutdown has been started, by shutdown or close
}

// closeOps are the system-level steps of closing one descriptor, injected
// so that the lifecycle is testable on every platform. Each step is one
// short, non-blocking operation. None of them waits: every wait happens in
// the lifecycle, between two steps, where an Abort can interrupt it.
type closeOps interface {
	// assocGone reports whether the association has been freed. On Linux
	// it is an SCTP_STATUS query (RFC 6458 §8.2.1), which keeps answering
	// through every shutdown state and fails with EINVAL only once the
	// association is gone (net/sctp/socket.c: sctp_id2assoc still resolves
	// it while the socket is ESTABLISHED or CLOSING, and
	// sctp_getsockopt_sctp_status refuses the query once it does not). An
	// error is a query that failed for another reason, and is not evidence
	// that the shutdown completed.
	//
	// For an Endpoint it is compound: it reports whether every
	// association of the one-to-many socket is gone, reading the
	// association list (RFC 6458 §8.2.6), and, since associations can end
	// and appear while it waits, it also starts the shutdown of any that
	// appeared since the last look (endpointCloseOps).
	assocGone() (bool, error)

	// startShutdown starts the graceful shutdown (RFC 9260 §9.2) with one
	// call that returns at once: shutdown(2) with SHUT_WR on a one-to-one
	// socket (RFC 6458 §4.1.7), or an empty send with SCTP_EOF on a peeled
	// one, where Linux ignores shutdown(2) (net/sctp/socket.c:
	// sctp_shutdown returns at once unless the socket is one-to-one), and
	// one such send for each association of an Endpoint. The SCTP_EOF
	// send cannot wait for buffer space: sctp_sendmsg_check_sflags starts
	// the SHUTDOWN primitive and returns before sctp_sendmsg_to_asoc, the
	// only path that waits. An error means the association is already gone
	// or already shutting down.
	startShutdown() error

	// abortive ends the association with an ABORT (RFC 9260 §§9.1, 11.1.4)
	// and releases the descriptor: SO_LINGER with a zero linger time makes
	// the close send the ABORT (RFC 6458 §8.1.4).
	abortive() error

	// release releases the descriptor, once the association is gone.
	release() error

	// now and after are the clock close waits on: the current time, and a
	// channel that fires once d has passed.
	now() time.Time
	after(d time.Duration) <-chan time.Time
}

// init makes the channels. It must run before the lifecycle is shared.
func (l *lifecycle) init() {
	l.abort = make(chan struct{})
	l.done = make(chan struct{})
}

// close shuts the association down gracefully and releases the descriptor,
// falling back to an ABORT if the shutdown has not completed within grace
// (RFC 9260 §9.2). A grace of zero or less aborts at once, exactly as
// abortNow does. Only the first close or abortNow proceeds: a later close,
// including one that arrives while this one is waiting, returns
// net.ErrClosed, and an abortNow that arrives during the wait overtakes it.
//
// It returns nil when the association ended during the wait, and also when
// the grace period ran out or an Abort overtook the wait: those are
// outcomes, not errors. It returns the error of release or abortive when
// that step failed, and a failed status query joined with the error of the
// abortive close it leads to.
func (l *lifecycle) close(ops closeOps, grace time.Duration) error {
	if l.done == nil {
		return net.ErrClosed
	}
	if grace <= 0 {
		// Straight to the abortive close, without passing through
		// lifeClosing: there is no wait for an Abort to overtake.
		return l.abortOpen(ops)
	}
	if !l.state.CompareAndSwap(int32(lifeOpen), int32(lifeClosing)) {
		return net.ErrClosed
	}
	deadline := ops.now().Add(grace)

	// Start the shutdown unless Shutdown already has: Linux would ignore a
	// second SHUTDOWN primitive anyway (net/sctp/sm_statetable.c:
	// TYPE_SCTP_PRIMITIVE_SHUTDOWN maps every shutdown state to
	// sctp_sf_ignore_primitive). Its error only says that the association
	// is already gone or shutting down; the poll below finds out which.
	if l.shut.CompareAndSwap(false, true) {
		_ = ops.startShutdown()
	}

	// Wait for the association to go away by asking about the association
	// itself, with one short query at a time and the waits in between, here,
	// where an Abort can end them. Waiting in a read instead would consume
	// data the caller may still be reading, and would queue behind a Read
	// parked on the descriptor: internal/poll holds the read lock while a
	// read waits, as it holds the write lock while a send waits for buffer
	// space.
	for step := shutdownPollMin; ; step = min(2*step, shutdownPollMax) {
		gone, err := ops.assocGone()
		if err != nil {
			// Not evidence of completion: abort rather than leave a live
			// association behind, and report why.
			return l.finish(errors.Join(err, ops.abortive()))
		}
		if gone {
			// The association has ended: release the descriptor as it is.
			// There is nothing left to abort.
			return l.finish(ops.release())
		}
		remaining := deadline.Sub(ops.now())
		if remaining <= 0 {
			// The peer has not completed the shutdown in time: abort, so
			// the association and its port are released now rather than
			// when the SHUTDOWN retransmissions give up.
			return l.finish(ops.abortive())
		}
		select {
		case <-l.abort:
			return l.finish(ops.abortive())
		case <-ops.after(min(step, remaining)):
		}
	}
}

// abortNow ends the association with an ABORT and releases the descriptor
// (RFC 9260 §§9.1, 11.1.4). On an open lifecycle it does so itself and
// returns the abortive close's error. While a close is waiting, it makes
// that close abort at once, waits until the descriptor has been released,
// and returns nil. Once the descriptor has been released it returns
// net.ErrClosed.
func (l *lifecycle) abortNow(ops closeOps) error {
	if l.done == nil {
		return net.ErrClosed
	}
	for {
		switch lifeState(l.state.Load()) {
		case lifeOpen:
			if l.state.CompareAndSwap(int32(lifeOpen), int32(lifeClosed)) {
				return l.finishAbortive(ops)
			}
		case lifeClosing:
			if l.state.CompareAndSwap(int32(lifeClosing), int32(lifeAborting)) {
				close(l.abort)
				<-l.done
				return nil
			}
		case lifeAborting:
			// Another Abort has already interrupted the wait.
			<-l.done
			return nil
		default:
			return net.ErrClosed
		}
		// A compare-and-swap lost to a concurrent transition: look again.
	}
}

// shutdown starts the graceful shutdown and returns at once, leaving the
// lifecycle open. The first call reports startShutdown's result; every
// later one returns nil without another attempt. After close or abortNow
// it returns net.ErrClosed.
func (l *lifecycle) shutdown(ops closeOps) error {
	if l.done == nil || lifeState(l.state.Load()) != lifeOpen {
		return net.ErrClosed
	}
	if !l.shut.CompareAndSwap(false, true) {
		return nil
	}
	return ops.startShutdown()
}

// abortOpen is close with no grace period: from open straight to closed and
// the abortive close, as abortNow does from open.
func (l *lifecycle) abortOpen(ops closeOps) error {
	if !l.state.CompareAndSwap(int32(lifeOpen), int32(lifeClosed)) {
		return net.ErrClosed
	}
	return l.finishAbortive(ops)
}

// finishAbortive runs the abortive close for a caller that has already
// moved the lifecycle to lifeClosed, then reports the release.
func (l *lifecycle) finishAbortive(ops closeOps) error {
	err := ops.abortive()
	close(l.done)
	return err
}

// finish records that close has released the descriptor: the lifecycle
// becomes closed before done is closed, so anyone who sees done closed
// also sees the lifecycle closed. It returns err unchanged.
func (l *lifecycle) finish(err error) error {
	l.state.Store(int32(lifeClosed))
	close(l.done)
	return err
}

// closeClock is the clock of the real closeOps. The wait uses one timer,
// made on the first step and reset for every later one, so the only
// allocation is that first time.NewTimer. Two properties of the timers of
// Go 1.23 and later, which this module gets from its go directive, make
// that safe: a receive from the channel after Reset returns never yields a
// value from the timer's earlier setting, and a timer nothing refers to
// any more is collected whether or not it was stopped, so the clock needs
// no cleanup when close returns with a step still pending.
//
// A closeClock has one caller: the close call whose wait it times. Its
// timer is reset in place, so two closes sharing one clock would reset
// each other's waits; every close builds closeOps, and with them a
// closeClock, of its own.
type closeClock struct {
	timer *time.Timer
}

func (c *closeClock) now() time.Time { return time.Now() }

func (c *closeClock) after(d time.Duration) <-chan time.Time {
	if c.timer == nil {
		c.timer = time.NewTimer(d)
	} else {
		c.timer.Reset(d)
	}
	return c.timer.C
}
