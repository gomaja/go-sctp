// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Conn is one association on a one-to-one socket (RFC 6458 §4), or on a
// socket peeled off an Endpoint. *Conn implements net.Conn. Write sends b
// as one message with the socket's default send parameters. Read returns
// message bytes and skips notifications.
//
// Every method of Conn may be called from several goroutines at once.
//
//lint:ignore U1000 staticcheck flags sock, assoc, peerPort, laddr, raddr, pathScope, bindMu, optMu, handler, closeWait, subs, subMu, send, recv and term as unused (U1000) on GOOS=darwin and GOOS=windows without this (kind and life are not flagged): only conn_linux.go's methods read or write them, and the portable stubs in unsupported.go never touch a real Conn's fields at all
type Conn struct {
	sock     socket
	kind     connKind
	assoc    AssocID // fixed at creation; 0 when the association ended before Accept
	peerPort uint16

	// laddr and raddr are the snapshots LocalAddr and RemoteAddr copy: the
	// association's local and peer address sets, taken when it is
	// established. A refresh stores a new *Addr and never modifies the old
	// one, so a reader gets one whole set. Callers only ever get copies.
	laddr atomic.Pointer[Addr]
	raddr atomic.Pointer[Addr]

	// pathScope is the scope id a link-local path without a zone gets, in a
	// path option or SendOptions.Path: linkLocalPathScope over the address
	// snapshots, worked out whenever they are taken or refreshed, so that
	// no send pays for it. 0 means none.
	pathScope atomic.Uint32

	// bindMu serialises BindAdd and BindRemove, each with the snapshot
	// refresh that follows it, so that an older refresh never replaces the
	// snapshots a newer one stored.
	bindMu sync.Mutex

	// optMu serialises every option sequence that reads and writes one
	// kernel object in more than one system call, so that no concurrent
	// call sees it half done or loses its update: SetPathThresholds'
	// read-modify-write, with SetPathParams, which writes the same
	// retransmission limit; and SetDefaultSndInfo, which writes
	// SCTP_DEFAULT_SNDINFO and then the default PR-SCTP policy that write
	// clears, with DefaultSndInfo and DefaultPrInfo reading under it. It
	// is a leaf: nothing else is locked while it is held, and the one lock
	// ever held when it is taken is send.mu, by SetDefaultSndInfo and
	// SetDefaultPrInfo, which update the send path's cached defaults.
	optMu sync.Mutex

	handler   NotificationHandler
	closeWait time.Duration // Config.CloseTimeout, resolved: the grace period of Close

	// subs is the caller's logical subscription set, an eventSet (config.go)
	// widened to fit an atomic word. It decides which notification records
	// reach the caller; the kernel-side SCTP_ASSOC_CHANGE subscription the
	// package keeps for itself does not depend on it. subMu serialises
	// Subscribe, so that the kernel subscription and subs change together.
	subs  atomic.Uint32
	subMu sync.Mutex

	life lifecycle // the close state machine (close.go)
	send sendState
	recv recvState
	term termState
}

// socket is the descriptor a Conn, Listener or Endpoint owns. file is the
// only thing that closes it, exactly once; raw, taken from file, is how
// every system call reaches it, so none can run on a descriptor number
// after file has released it.
//
//lint:ignore U1000 staticcheck flags file, raw and family as unused (U1000) on GOOS=darwin and GOOS=windows without this: only socket_linux.go and its siblings open a descriptor and set them
type socket struct {
	file    *os.File
	raw     syscall.RawConn
	family  int    // afInet or afInet6
	network string // "sctp", "sctp4" or "sctp6"
}

// connKind is how a Conn's descriptor came to exist. The zero value is no
// kind at all: a Conn the package never opened.
type connKind uint8

const (
	// kindDialed is a one-to-one socket this package connected.
	kindDialed connKind = iota + 1
	// kindAccepted is a one-to-one socket accepted from a Listener.
	kindAccepted
	// kindPeeled is a socket branched off an Endpoint's one-to-many socket
	// (RFC 6458 §9.2). Linux gives it a style of its own
	// (SCTP_SOCKET_UDP_HIGH_BANDWIDTH, net/sctp/socket.c:
	// sctp_do_peeloff), on which shutdown(2) does nothing (sctp_shutdown
	// returns at once unless the socket is one-to-one), so its graceful
	// shutdown is an SCTP_EOF send instead.
	kindPeeled
	// kindAdopted is a connected one-to-one socket the caller handed over
	// through FileConn.
	kindAdopted
)

// termState records how the association ended, so that every read and send
// after the end reports it, without a system call, instead of parking on a
// descriptor that will never become ready again.
//
// Linux sets the socket error of a one-to-one or peeled socket when its
// association fails (net/sctp/sm_sideeffect.c: sctp_cmd_set_sk_err) and
// hands it to the first recvmsg or sendmsg that looks
// (net/sctp/socket.c: sctp_skb_recv_datagram, sctp_error). mu is held
// around every recvmsg and sendmsg, inside the RawConn callbacks and never
// while waiting, and the error such a call takes is stored before mu is
// released, so no call can take the error without the latch holding it.
//
//lint:ignore U1000 staticcheck flags every field below as unused (U1000) on GOOS=darwin and GOOS=windows without this: only the Linux receive and send paths (recv_linux.go, send_linux.go) read or latch into them. Removing Conn's own directive (above) too, rather than only this one, makes it flag termState itself as unused, not merely its fields, since nothing would then reference the Conn.term field that keeps the type alive
type termState struct {
	mu     sync.Mutex
	err    error // the latched errno: ECONNRESET, ETIMEDOUT, ECONNABORTED or ENOTCONN
	failed bool  // an AssocCommLost record was seen
	ended  bool  // an AssocShutdownComplete record was seen

	// drained is set once a read has found nothing more queued after the
	// association failed and returned err: from then on reads return err
	// without a system call. Until then they make one, so that what Linux
	// queued before the error, data and the records that report the end,
	// is still read, as Linux orders it (net/sctp/socket.c:
	// sctp_skb_recv_datagram dequeues before it looks at the socket
	// error).
	drained bool
}
