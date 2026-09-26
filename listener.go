// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"sync"
	"sync/atomic"
)

// Listener is a one-to-one SCTP socket (RFC 6458 §4) listening for
// associations, which Accept returns as net.Conn values and AcceptSCTP as
// *Conn values, as net.TCPListener's Accept and AcceptTCP do. *Listener
// implements net.Listener. Addr returns an *Addr holding every bound
// address, which a single net.TCPAddr-style value cannot express.
//
// Accepted connections inherit the listening socket's settings. That
// covers the kernel-side options, which the kernel copies into the accepted
// socket, and the package-side Config.NotificationHandler and
// Config.CloseTimeout.
//
// An association that ended before Accept is still returned by Accept.
// Linux keeps such an association queued so that accept(2) can return it,
// and hands the connection over already closed: the association's error,
// if it failed, was set on the listening socket, and the association and
// address queries fail. Dropping it would lose the data the peer may have
// sent, a peer that sends one message and closes before the server accepts
// being the usual case. On such a connection AssocID returns 0, and
// LocalAddr and RemoteAddr return an *Addr with no IPs, since Linux no
// longer knows them. Reads deliver the queued data, then return io.EOF
// after a graceful end or an error matching syscall.ENOTCONN after a
// failure.
//
// Every method may be called from several goroutines at once.
//
//lint:ignore U1000 only the Linux code listens and accepts; on other platforms the fields stay unused
type Listener struct {
	sock socket
	prep *prepared // the Config snapshot every accepted Conn is built from

	// addr is the snapshot Addr copies: the endpoint's bound addresses,
	// replaced as a whole after a successful BindAdd or BindRemove.
	addr atomic.Pointer[Addr]

	// bindMu serialises BindAdd and BindRemove, each with the snapshot
	// refresh that follows it.
	bindMu sync.Mutex
}
