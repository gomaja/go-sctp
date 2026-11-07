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
// Accepted connections inherit the listening socket's options: the kernel
// copies them into the accepted socket, and the package passes on
// Config.NotificationHandler and Config.CloseTimeout. The extensions
// negotiated in the INIT are the exception. Linux gives the accepted socket
// an SCTP endpoint of its own (net/sctp/endpointola.c: sctp_endpoint_new),
// whatever the Config said: its PR-SCTP, ECN, stream reconfiguration, ASCONF
// and AUTH switches start from the namespace's net.sctp sysctls, its AUTH
// lists from the kernel's defaults (HMAC-SHA-1 alone, and no chunk types
// beyond ASCONF's), and its I-DATA switch off (sctp_endpoint_init). The
// listener answers the handshake, so the association negotiates what the
// Config asks for. A restart of the association by its peer is answered by
// the accepted socket's endpoint instead (net/sctp/sm_statefuns.c:
// sctp_sf_do_unexpected_init), although RFC 9260 §5.2.2 asks for the
// association's own parameters there
// (https://github.com/sctp/lksctp-tools/issues/81).
//
// After such a restart, the two ends disagree on each of PR-SCTP, ECN,
// stream reconfiguration, ASCONF and I-DATA that the answer changed: Linux
// keeps the association's own capabilities (net/sctp/associola.c:
// sctp_assoc_update), while the peer takes those of the new INIT ACK. A
// peer that then abandons a message has its FORWARD TSN rejected as an
// unknown chunk, and the messages after it on that stream are not
// delivered; an association that negotiated I-DATA is aborted at the first
// message either side sends. AUTH is negotiated afresh on both ends, so it
// follows the namespace, with the default lists in place of
// Config.HMACIdentifiers and Config.AuthChunks: the chunk types the Config
// required to be authenticated, DATA included, are accepted without AUTH.
// Setting the sysctls to match the Config keeps PR-SCTP, ECN, stream
// reconfiguration, ASCONF and AUTH itself consistent across a restart, but
// not I-DATA or the AUTH lists.
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
//lint:ignore U1000 staticcheck flags every field below as unused (U1000) on GOOS=darwin and GOOS=windows without this: only listener_linux.go's methods open, read or write them
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
