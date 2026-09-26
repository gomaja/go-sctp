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

// endpoint_linux.go opens Endpoints and holds every Endpoint method that
// reaches the descriptor: setting up and ending associations, sending and
// receiving, peeling an association off, the association and address
// queries, and closing the endpoint through the close state machine
// (close.go) with a shutdown taken association by association.

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
	"unsafe"
)

// ListenEndpoint opens a one-to-many SCTP socket that accepts
// associations, with a zero Config. See Config.ListenEndpoint.
func ListenEndpoint(network string, laddr *Addr) (*Endpoint, error) {
	return (*Config)(nil).ListenEndpoint(network, laddr)
}

// OpenEndpoint opens a one-to-many SCTP socket that only sets up
// associations of its own, with a zero Config. See Config.OpenEndpoint.
func OpenEndpoint(network string, laddr *Addr) (*Endpoint, error) {
	return (*Config)(nil).OpenEndpoint(network, laddr)
}

// ListenEndpoint opens a one-to-many SCTP socket (RFC 6458 §3.1.1),
// applies c, binds it to laddr and marks it listening, so that it accepts
// associations from peers as well as setting them up with Connect. There
// is no Accept: Linux accepts each association itself (RFC 6458 §3.1.3),
// and RecvMsg reports it with an AssocCommUp record naming its id.
//
// network is "sctp", "sctp4" or "sctp6". A nil laddr, or one with no IPs,
// is the wildcard address: with a port of 0 the kernel chooses one, and
// with "sctp" the socket is AF_INET6 dual-stack, so that it listens on the
// host's IPv4 and IPv6 addresses alike. Several IPs make a multi-homed
// endpoint, bound atomically (RFC 6458 §9.1).
//
// Before any association can exist, and after Config.Control, whatever
// Control did, the package enables SCTP_RECVRCVINFO and the
// SCTP_ASSOC_CHANGE subscription, which the Endpoint needs to name every
// message's association and to report every association's start and end;
// neither can be switched off. The fragment interleave level is
// InterleaveAssocs unless Config.FragmentInterleave says otherwise, as RFC
// 6458 §8.1.20 recommends for one-to-many sockets. Config.ReusePort, which
// applies to one-to-one sockets only (RFC 6458 §8.1.27), and
// Config.AbandonPolicy, which applies to Dial only, are refused.
//
// Errors are *net.OpError with Op "listen", as net.ListenPacket's are for
// a socket that is only bound.
func (c *Config) ListenEndpoint(network string, laddr *Addr) (*Endpoint, error) {
	e, err := c.openEndpoint(styleListenEndpoint, network, laddr)
	if err != nil {
		return nil, opError("listen", canonicalName(network), nil, netAddr(laddr), err)
	}
	return e, nil
}

// OpenEndpoint is ListenEndpoint without the listening: the endpoint sets
// up associations with Connect, and peers cannot set any up with it (RFC
// 6458 §3.1.3). Linux enters a one-to-many socket in its endpoint table
// only when it starts listening (net/sctp/socket.c: sctp_listen_start),
// so an INIT for one that is not finds no endpoint and is answered with an
// ABORT as out of the blue (RFC 9260 §8.4; net/sctp/sm_statefuns.c:
// sctp_sf_do_5_1B_init). A nil laddr leaves the socket unbound until its
// first Connect, which binds it to the wildcard address and a port the
// kernel chooses (net/sctp/socket.c: sctp_autobind); Addr reports that
// port afterwards. Errors are *net.OpError with Op "listen".
func (c *Config) OpenEndpoint(network string, laddr *Addr) (*Endpoint, error) {
	e, err := c.openEndpoint(styleOpenEndpoint, network, laddr)
	if err != nil {
		return nil, opError("listen", canonicalName(network), nil, netAddr(laddr), err)
	}
	return e, nil
}

func (c *Config) openEndpoint(style socketStyle, network string, laddr *Addr) (*Endpoint, error) {
	family, err := socketFamily(network, laddr, nil)
	if err != nil {
		return nil, err
	}
	p, err := c.prepare(style)
	if err != nil {
		return nil, err
	}
	var bind []byte
	address := ""
	if laddr != nil {
		if bind, err = localBindAddrs(family, laddr); err != nil {
			return nil, err
		}
		address = laddr.String()
	}

	s, err := openSocket(family, syscall.SOCK_SEQPACKET, canonicalName(network))
	if err != nil {
		return nil, err
	}
	var control func(string, string, syscall.RawConn) error
	if c != nil {
		control = c.Control
	}
	if err := setupEndpoint(&s, address, control, p.ops, bind, style == styleListenEndpoint); err != nil {
		// Control may have set up an association already: the abortive
		// close ends it, rather than leaving a handshake behind a
		// descriptor nobody owns.
		_ = (&sockCloseOps{sock: &s}).abortive()
		return nil, err
	}
	return newEndpoint(s, p, c.ownSubscriptions()), nil
}

// setupEndpoint configures and binds a new one-to-many socket, and marks
// it listening when listening is set: a non-zero backlog is what enables
// listening on a one-to-many socket (RFC 6458 §3.1.3).
func setupEndpoint(s *socket, address string, control func(string, string, syscall.RawConn) error, ops []configOp, bind []byte, listening bool) error {
	if listening {
		return setupListener(s, address, control, ops, bind)
	}
	if err := setupSocket(s, address, control, ops); err != nil {
		return err
	}
	if bind != nil {
		if err := s.bindx(optSockoptBindxAdd, bind); err != nil {
			return os.NewSyscallError("sctp_bindx", err)
		}
	}
	return nil
}

// ownSubscriptions is the logical subscription set c.Notifications asks
// for, without the EventAssocChange delivery an Endpoint adds for itself:
// what a connection PeelOff returns reports and delivers. prepare has
// already refused any entry EventType does not name.
func (c *Config) ownSubscriptions() eventSet {
	var set eventSet
	if c != nil {
		for _, t := range c.Notifications {
			set |= eventBit(t)
		}
	}
	return set
}

// newEndpoint builds an Endpoint around s, a one-to-many socket this
// package owns, with the handler, grace period and subscriptions of p,
// and own as the subscriptions of the connections PeelOff returns. It
// reads the endpoint's default send parameters, which every send carries
// explicitly (sendState.encode), and takes the Addr snapshot.
func newEndpoint(s socket, p *prepared, own eventSet) *Endpoint {
	peel := *p
	peel.subscribed = own
	e := &Endpoint{sock: s, peel: &peel, handler: p.handler, closeWait: p.closeTimeout}
	e.subs.Store(uint32(p.subscribed))
	e.life.init()
	e.recv.bind(nil, &e.subs)
	e.send.bind(nil)
	e.send.explicit = true
	e.send.readDefaults(&e.sock)
	e.refreshAddr()
	return e
}

// refreshAddr replaces the Addr snapshot with the endpoint's bound
// addresses, SCTP_GET_LOCAL_ADDRS for association id 0 (RFC 6458 §9.5),
// which for a wildcard bind lists every address in the namespace. A list
// that cannot be read leaves the snapshot as it was, or, on the first
// read, empty.
func (e *Endpoint) refreshAddr() {
	if a, err := e.sock.getAddrs(optGetLocalAddrs, 0); err == nil {
		e.addr.Store(a)
	} else if e.addr.Load() == nil {
		e.addr.Store(&Addr{})
	}
}

// opened reports whether e is an Endpoint this package opened and has not
// yet released: false for a nil or zero Endpoint, and once Close or Abort
// has released the descriptor.
func (e *Endpoint) opened() bool {
	return e != nil && e.sock.raw != nil && lifeState(e.life.state.Load()) != lifeClosed
}

// network is the network name e's errors carry.
func (e *Endpoint) network() string {
	if e == nil || e.sock.network == "" {
		return "sctp"
	}
	return e.sock.network
}

// ioError wraps an error of a read or a write once, with Op op, the
// endpoint's network, and its address snapshot as Source: an Endpoint has
// no one peer to name. io.EOF is returned as it is.
func (e *Endpoint) ioError(op string, err error) error {
	return ioOpError(op, e.network(), e.Addr(), nil, err)
}

// optionError wraps a socket-option failure of e: a *net.OpError with Op
// op ("get" or "set") around an *os.SyscallError naming getsockopt or
// setsockopt, or net.ErrClosed on a released descriptor.
func (e *Endpoint) optionError(op string, err error) error {
	call := "getsockopt"
	if op == "set" {
		call = "setsockopt"
	}
	return optError(op, call, e.network(), nil, e.Addr(), err)
}

// argError wraps an argument a method refused before any system call, or
// another failure that is not a system call's errno, with Op op.
func (e *Endpoint) argError(op string, err error) error {
	return opError(op, e.network(), nil, e.Addr(), err)
}

// getError wraps a query's failure: the kernel's errno as optionError
// does, and anything else, a malformed reply say, as argError does.
func (e *Endpoint) getError(err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return e.optionError("get", errno)
	}
	return e.argError("get", err)
}

// Addr returns an *Addr holding every address the endpoint is bound to: a
// snapshot, taken when the endpoint is opened and replaced as a whole
// after a successful BindAdd or BindRemove, and after the first Connect of
// an endpoint opened without a local address, which binds it. For a
// wildcard bind it lists every address in the network namespace. Each
// call returns a copy of its own, which the caller may keep and change.
// It stays readable after Close. It is nil for a nil Endpoint.
func (e *Endpoint) Addr() net.Addr {
	if e == nil {
		return nil
	}
	return netAddr(e.addr.Load())
}

// --- associations ------------------------------------------------------------------

// Connect starts setting up an association with raddr (RFC 9260 §5.1; RFC
// 6458 §3.1.6) and returns its id at once, without waiting for the setup:
// EventAssocChange reports the outcome, AssocCommUp or AssocCantStart for
// that id (RFC 6458 §3.2). Several IPs in raddr are all given to the
// kernel for the setup (sctp_connectx, RFC 6458 §9.9). The socket is
// non-blocking, so Linux answers with EINPROGRESS, and writes the new
// association's id all the same (net/sctp/socket.c:
// sctp_getsockopt_connectx3); Connect returns that id with a nil error
// (erlang/otp PR #1592). An endpoint may set up associations with many
// peers, one Connect each.
//
// A peer the endpoint already has an association with is refused by the
// kernel: with EISCONN once the association is established, and with
// EALREADY while it is being set up (net/sctp/socket.c: __sctp_connect);
// no id is returned then. A nil raddr, one with no IPs, and an address the
// socket's family cannot carry are refused with an error matching
// syscall.EINVAL before any system call. Errors are *net.OpError with Op
// "dial".
func (e *Endpoint) Connect(raddr *Addr) (AssocID, error) {
	if !e.opened() {
		return 0, e.dialError(raddr, net.ErrClosed)
	}
	if raddr == nil || len(raddr.IPs) == 0 {
		return 0, e.dialError(raddr, invalidArg("Connect needs a remote address with at least one IP"))
	}
	peer, err := encodeAddrs(e.sock.family, raddr.IPs, raddr.Port)
	if err != nil {
		return 0, e.dialError(raddr, err)
	}
	id, err := e.sock.connectxID(peer)
	if err != nil && err != syscall.EINPROGRESS {
		return 0, e.dialError(raddr, os.NewSyscallError("sctp_connectx", err))
	}
	if a := e.addr.Load(); a == nil || a.Port == 0 {
		// The setup bound an unbound endpoint to a port of the kernel's
		// choosing (net/sctp/socket.c: sctp_autobind).
		e.bindMu.Lock()
		e.refreshAddr()
		e.bindMu.Unlock()
	}
	return id, nil
}

// dialError wraps an error of Connect, with the endpoint's addresses as
// Source and the peer asked for as Addr.
func (e *Endpoint) dialError(raddr *Addr, err error) error {
	return opError("dial", e.network(), e.Addr(), netAddr(raddr), err)
}

// CloseAssoc starts the graceful shutdown of association id (RFC 9260
// §9.2) and returns at once, leaving every other association and the
// endpoint as they are: an empty send carrying SCTP_EOF for that
// association (RFC 6458 §§3.1.5, 5.3.4), which never waits for buffer
// space (net/sctp/socket.c: sctp_sendmsg_check_sflags acts on the flag
// before sctp_sendmsg_to_asoc, the only path that waits). An
// AssocShutdownComplete record for id reports the end (RFC 6458 §3.2).
// A second CloseAssoc during the shutdown does nothing more.
//
// A scope selector or a negative id is refused with an error matching
// syscall.EINVAL before any system call; an id the endpoint does not hold,
// because its association has ended or was peeled off, fails with the
// kernel's syscall.EPIPE (sctp_sendmsg). Errors are *net.OpError with Op
// "close".
func (e *Endpoint) CloseAssoc(id AssocID) error {
	return e.endAssoc("CloseAssoc", id, sndFlagEOF, nil)
}

// AbortAssoc ends association id at once with an ABORT (RFC 9260 §9.1),
// leaving every other association and the endpoint as they are: an
// SCTP_ABORT send for that association (RFC 6458 §§3.1.5, 5.3.4), whose
// ABORT carries a User-Initiated Abort error cause with cause as its Upper
// Layer Abort Reason (RFC 9260 §3.3.10.12). cause may be empty. An
// AssocCommLost record for id reports the end, and the peer receives the
// cause in its own AssocCommLost's Info.
//
// A cause longer than 65524 bytes, the most one ABORT chunk carries on
// Linux (net/sctp/sm_make_chunk.c: _sctp_make_chunk caps a chunk at
// 65532 bytes padded, 8 of which are the chunk's and the error cause's
// headers), is refused with an error matching syscall.EINVAL before any
// system call, as are ids as for CloseAssoc. Linux checks the send's
// length against the socket's send buffer before it looks at the flag
// (net/sctp/socket.c: sctp_sendmsg_parse), so a shorter cause that is
// still longer than the send buffer, as WriteBuffer reports it, fails with
// the kernel's syscall.EMSGSIZE, and the association is not aborted.
// Errors are as for CloseAssoc.
func (e *Endpoint) AbortAssoc(id AssocID, cause []byte) error {
	return e.endAssoc("AbortAssoc", id, sndFlagAbort, cause)
}

// maxAbortCause is the longest cause AbortAssoc sends. It is the Upper
// Layer Abort Reason of the ABORT's User-Initiated Abort error cause (RFC
// 9260 §3.3.10.12), so the chunk holds its own 4-byte header, the error
// cause's 4-byte header and the reason; Linux builds no chunk whose
// length, padded to a multiple of 4, exceeds SCTP_MAX_CHUNK_LEN, 65532
// bytes (net/sctp/sm_make_chunk.c: _sctp_make_chunk), and answers a
// longer one with ENOMEM (sctp_make_abort_user fails, net/sctp/socket.c:
// sctp_sendmsg_check_sflags).
const maxAbortCause = 65532 - 8

// endAssoc is CloseAssoc and AbortAssoc: one send carrying flag for
// association id, with cause as its payload, made in raw.Control, not
// raw.Write, so that it never queues behind a send waiting for buffer
// space, which holds the descriptor's write lock while it waits
// (internal/poll: FD.writeLock).
func (e *Endpoint) endAssoc(method string, id AssocID, flag uint16, cause []byte) error {
	if !e.opened() {
		return e.closeError(net.ErrClosed)
	}
	if err := assocIDArg(method, id); err != nil {
		return e.closeError(err)
	}
	if len(cause) > maxAbortCause {
		return e.closeError(invalidArg("%s: a cause of %d bytes is longer than the %d bytes one ABORT chunk carries (RFC 9260 §3.3.10.12; net/sctp/sm_make_chunk.c: _sctp_make_chunk)", method, len(cause), maxAbortCause))
	}
	if err := e.sock.control(func(fd int) error { return eofSendError(rawSendEnd(fd, flag, id, cause)) }); err != nil {
		return e.closeError(err)
	}
	return nil
}

// assocIDsFirstBuffer is how many ids AssocIDs makes room for on its first
// read; a longer list doubles the room, up to assocIDListLimit.
const assocIDsFirstBuffer = 16

// AssocIDs returns the ids of the associations the endpoint holds now
// (SCTP_GET_ASSOC_ID_LIST, RFC 6458 §8.2.6), in ascending order, as a
// slice of the caller's own: a snapshot, which may be out of date by the
// time it is read. A
// list longer than 1<<20 ids fails with an error matching
// ErrAssocListTooLarge, and one the kernel reports malformed with one
// matching ErrInvalidAssocList; neither is ever returned in part. An
// endpoint with no association returns an empty, non-nil slice. Errors are
// *net.OpError with Op "get".
func (e *Endpoint) AssocIDs() ([]AssocID, error) {
	if !e.opened() {
		return nil, e.optionError("get", net.ErrClosed)
	}
	ids, err := e.sock.assocIDs()
	if err != nil {
		return nil, e.getError(err)
	}
	return ids, nil
}

// assocIDs reads SCTP_GET_ASSOC_ID_LIST into a buffer of room for
// assocIDsFirstBuffer ids, and a larger one each time Linux refuses the
// buffer as too small, which it does with EINVAL (net/sctp/socket.c:
// sctp_getsockopt_assoc_ids), up to assocIDListLimit ids. No count the
// kernel reports sizes an allocation.
func (s *socket) assocIDs() ([]AssocID, error) {
	for room := assocIDsFirstBuffer; ; room *= 2 {
		buf := make([]byte, sizeAssocIDs+room*sizeAssocID)
		l := uint32(len(buf))
		err := s.getsockopt(optGetAssocIDList, unsafe.Pointer(&buf[0]), &l)
		switch {
		case err == syscall.EINVAL && room < assocIDListLimit:
			continue
		case err == syscall.EINVAL:
			return nil, fmt.Errorf("%w: more than %d ids", ErrAssocListTooLarge, assocIDListLimit)
		case err != nil:
			return nil, err
		case int(l) > len(buf):
			return nil, fmt.Errorf("%w: the kernel reported %d bytes of a %d-byte buffer", ErrInvalidAssocList, l, len(buf))
		}
		return decodeAssocIDs(buf[:l])
	}
}

// AssocCount returns how many associations the endpoint holds now
// (SCTP_GET_ASSOC_NUMBER, RFC 6458 §8.2.5): a snapshot, which may be out
// of date by the time it is read. Errors are *net.OpError with Op "get".
func (e *Endpoint) AssocCount() (int, error) {
	if !e.opened() {
		return 0, e.optionError("get", net.ErrClosed)
	}
	var b [sizeInt]byte
	l := uint32(len(b))
	if err := e.sock.getsockopt(optGetAssocNumber, unsafe.Pointer(&b[0]), &l); err != nil {
		return 0, e.optionError("get", err)
	}
	return int(binary.NativeEndian.Uint32(b[:])), nil
}

// LocalAddrs returns association id's local addresses as they are now
// (RFC 6458 §9.5): the association's own list, which for a wildcard bind
// is the endpoint's addresses restricted to the scope of the peer's
// (net/sctp/bind_addr.c: sctp_bind_addr_copy). The *Addr is the caller's
// own. A scope selector or a negative id is refused with an error matching
// syscall.EINVAL before any system call, so the endpoint's own bound
// addresses, which id 0 would report (RFC 6458 §9.5; Held Erratum 6114
// writes that 0 as SCTP_FUTURE_ASSOC), are never taken for an
// association's; an id the endpoint does not hold fails with the kernel's
// EINVAL (net/sctp/socket.c: sctp_getsockopt_local_addrs). Errors are
// *net.OpError with Op "get".
func (e *Endpoint) LocalAddrs(id AssocID) (*Addr, error) {
	return e.assocAddrs("LocalAddrs", optGetLocalAddrs, id)
}

// PeerAddrs returns association id's peer addresses as they are now (RFC
// 6458 §9.3), following the changes the peer makes with ASCONF. The
// *Addr is the caller's own. Arguments and errors are as for LocalAddrs.
func (e *Endpoint) PeerAddrs(id AssocID) (*Addr, error) {
	return e.assocAddrs("PeerAddrs", optGetPeerAddrs, id)
}

func (e *Endpoint) assocAddrs(method string, opt int, id AssocID) (*Addr, error) {
	if !e.opened() {
		return nil, e.optionError("get", net.ErrClosed)
	}
	if err := assocIDArg(method, id); err != nil {
		return nil, e.argError("get", err)
	}
	a, err := e.sock.getAddrs(opt, id)
	if err != nil {
		return nil, e.getError(err)
	}
	return a, nil
}

// AutoClose returns how long an association may stay idle, sending and
// receiving no user data, before Linux shuts it down gracefully
// (SCTP_AUTOCLOSE, RFC 6458 §8.1.8); 0 means never, which is the default.
// It reports the value in force, which may be lower than the one
// SetAutoClose was given. Errors are *net.OpError with Op "get".
func (e *Endpoint) AutoClose() (time.Duration, error) {
	if !e.opened() {
		return 0, e.optionError("get", net.ErrClosed)
	}
	var b [sizeInt]byte
	l := uint32(len(b))
	if err := e.sock.getsockopt(optAutoClose, unsafe.Pointer(&b[0]), &l); err != nil {
		return 0, e.optionError("get", err)
	}
	return time.Duration(binary.NativeEndian.Uint32(b[:])) * time.Second, nil
}

// SetAutoClose sets how long an association may stay idle before Linux
// shuts it down gracefully (SCTP_AUTOCLOSE, RFC 6458 §8.1.8); 0 switches
// automatic close off. It applies to the associations set up afterwards:
// each takes the endpoint's value when it is created
// (net/sctp/associola.c: sctp_association_init), so an association
// already there keeps the one it started with. Linux caps the value at
// the net.sctp.max_autoclose sysctl without reporting it
// (net/sctp/socket.c: sctp_setsockopt_autoclose); AutoClose returns the
// value in force. The end of an association closed this way is
// reported with AssocShutdownComplete, and its id may then be reused, so
// ids must be retired on that record. A negative d, one that is not a
// whole number of seconds, or one beyond the kernel's 32-bit count of
// seconds is refused with an error matching syscall.EINVAL before any
// system call. Errors are *net.OpError with Op "set".
func (e *Endpoint) SetAutoClose(d time.Duration) error {
	if !e.opened() {
		return e.optionError("set", net.ErrClosed)
	}
	secs, err := durationToSeconds("SetAutoClose", d, math.MaxUint32)
	if err != nil {
		return e.argError("set", err)
	}
	var b [sizeInt]byte
	binary.NativeEndian.PutUint32(b[:], secs)
	if err := e.sock.setsockopt(optAutoClose, unsafe.Pointer(&b[0]), uintptr(len(b))); err != nil {
		return e.optionError("set", err)
	}
	return nil
}

// BindAdd adds ips to the endpoint's local addresses (RFC 6458 §9.1,
// sctp_bindx with SCTP_BINDX_ADD_ADDR), on the port it is bound to;
// associations set up afterwards can use them, and, when ASCONF (RFC
// 5061) was negotiated, Linux also adds them to its associations and asks
// their peers to. IPv4 addresses are passed IPv4-mapped on an AF_INET6
// socket, so an sctp6 endpoint takes both families. The Addr snapshot is
// refreshed afterwards. A zero netip.Addr, an empty list, or an address the
// socket's family cannot carry is refused with an error matching
// syscall.EINVAL before any system call. Errors are *net.OpError with Op
// "bindx".
func (e *Endpoint) BindAdd(ips ...netip.Addr) error {
	return e.bindx(optSockoptBindxAdd, "BindAdd", ips)
}

// BindRemove removes ips from the endpoint's local addresses (RFC 6458
// §9.1, sctp_bindx with SCTP_BINDX_REM_ADDR). RFC 6458 §9.1 forbids
// removing every local address, and a list that would is refused with an
// error matching syscall.EINVAL (Linux itself answers EBUSY:
// net/sctp/socket.c, sctp_bindx_rem); so is a list naming the unspecified
// address. Arguments, errors and the Addr refresh are as for BindAdd.
func (e *Endpoint) BindRemove(ips ...netip.Addr) error {
	return e.bindx(optSockoptBindxRemove, "BindRemove", ips)
}

func (e *Endpoint) bindx(opt int, name string, ips []netip.Addr) error {
	if !e.opened() {
		return opError("bindx", e.network(), nil, e.Addr(), net.ErrClosed)
	}
	buf, err := bindxAddrs(e.sock.family, name, ips)
	if err != nil {
		return opError("bindx", e.network(), nil, e.Addr(), err)
	}

	e.bindMu.Lock()
	defer e.bindMu.Unlock()
	if opt == optSockoptBindxRemove {
		if bound, err := e.sock.getAddrs(optGetLocalAddrs, 0); err == nil && removesEveryAddress(bound.IPs, ips) {
			return opError("bindx", e.network(), nil, e.Addr(), invalidArg("%s would remove every local address, which RFC 6458 §9.1 forbids", name))
		}
	}
	if err := e.sock.bindx(opt, buf); err != nil {
		return optError("bindx", "setsockopt", e.network(), nil, e.Addr(), err)
	}
	e.refreshAddr()
	return nil
}

// --- messages ----------------------------------------------------------------------

// SendMsg sends b as one message on association id, with the per-message
// parameters in opts (RFC 6458 §§5.3, 9.12), and returns len(b) once the
// kernel has queued it. The id is an argument of its own, so that it
// cannot be left at a zero value by accident: a scope selector or a
// negative id is refused with an error matching syscall.EINVAL before any
// system call, and an id the endpoint does not hold, because its
// association has ended or was peeled off, fails with the kernel's
// syscall.EPIPE (net/sctp/socket.c: sctp_sendmsg).
//
// Unless opts.NoWait is set, SendMsg waits for send-buffer space in the
// runtime poller, until the write deadline passes or the endpoint is
// closed; the buffer is the endpoint's, so another association's progress
// can release the wait (RFC 6458 §3.2). With NoWait, a send that finds no
// space fails at once with an error matching syscall.EAGAIN, and nothing
// of the message is queued. A successful SendMsg makes no allocation, and
// SendMsg keeps nothing of b or opts after it returns.
//
// Every send carries SCTP_SNDINFO, since that is where the association id
// travels (RFC 6458 §5.3.4). A nil opts.Info or opts.PR means the
// endpoint's default, as on a Conn: Linux applies no default to a message
// that carries SNDINFO (sctp_sendmsg_update_sinfo), so the package sends
// Config.DefaultSndInfo and Config.DefaultPrInfo itself, as they were when
// the endpoint was opened, Control's changes included. An association
// keeps the defaults it was created with, so a default changed for one
// association through SyscallConn is not seen.
//
// A message has at least one byte: an empty b is refused with an error
// matching syscall.EINVAL (RFC 9260 §6.2). opts.Path is refused the same
// way, because the kernel would look the association up by the address
// instead of by id, and flags SendFlags does not name, SCTP_EOF and
// SCTP_ABORT among them, are refused too: CloseAssoc and AbortAssoc do
// what those flags do. Every error is a *net.OpError with Op "write".
func (e *Endpoint) SendMsg(id AssocID, b []byte, opts SendOptions) (int, error) {
	if !e.opened() {
		return 0, e.ioError("write", net.ErrClosed)
	}
	if err := checkEndpointSend(id, b, &opts); err != nil {
		return 0, e.ioError("write", err)
	}
	n, err := e.send.send(&e.sock, b, &opts, nil, id)
	if err != nil {
		return 0, e.ioError("write", err)
	}
	return n, nil
}

// checkEndpointSend validates an Endpoint send without any lock or system
// call. Every refusal matches syscall.EINVAL.
func checkEndpointSend(id AssocID, b []byte, opts *SendOptions) error {
	if err := assocIDArg("SendMsg", id); err != nil {
		return err
	}
	if len(b) == 0 {
		// RFC 9260 §6.2; net/sctp/socket.c: sctp_sendmsg_parse.
		return invalidArg("SendMsg needs a message of at least one byte")
	}
	if err := validateSendOptions(opts); err != nil {
		return err
	}
	if opts.Path.IsValid() {
		return invalidArg("SendOptions.Path is set on an Endpoint, where Linux would find the association by the address rather than by the id given (net/sctp/socket.c: sctp_sendmsg)")
	}
	return nil
}

// RecvMsg reads with one recvmsg (RFC 6458 §9.13's sctp_recvv) into b and
// returns the number of bytes read, with what the kernel reported about
// them, as Conn.RecvMsg does: MSG_EOR says whether b received the end of
// the message, and Rcv holds its SCTP_RCVINFO record (RFC 6458 §5.3.5),
// whose AssocID names the association it came on. When b is shorter than
// the message, the rest is returned by the next reads, and EOR is false
// until the last; readers that share the endpoint must keep one message's
// pieces together themselves. A read of data makes no allocation. An empty
// b returns 0 at once, and consumes nothing.
//
// Every message names one real association: data that arrives without
// SCTP_RCVINFO, which the package enables before any association exists
// and which only SyscallConn can switch off, fails with an error matching
// ErrMissingRcvInfo, and a record that names a scope selector, or is
// short, repeated or malformed, with one matching ErrInvalidRcvInfo. The
// bytes are returned all the same, with a zero Rcv, so that they cannot be
// taken for another association's. MSG_CTRUNC is reported as for a Conn,
// with ErrControlTruncated, and Rcv then only when its record arrived
// whole.
//
// Notifications share the queue with data. An Endpoint always delivers
// EventAssocChange records, since they report every association's start,
// its id included, and end, and Config.Notifications chooses the rest.
// With a NotificationHandler, RecvMsg hands each to the handler, parsed,
// and goes on reading; an error the handler returns is returned by
// RecvMsg. Without one, RecvMsg returns the notification's bytes with
// MsgInfo.Notification set, in pieces as long as b, with EOR on the last;
// ParseNotification decodes the whole.
//
// An Endpoint has no end of stream and no sticky error: the end of an
// association is its AssocChange record, and an error belongs to the
// read that got it. RecvMsg returns io.EOF, unwrapped, only when the
// socket has been shut for reading outside the package, through
// SyscallConn. Every other error is a *net.OpError with Op "read".
func (e *Endpoint) RecvMsg(b []byte) (int, MsgInfo, error) {
	if !e.opened() {
		return 0, MsgInfo{}, e.ioError("read", net.ErrClosed)
	}
	if len(b) == 0 {
		return 0, MsgInfo{}, nil
	}
	for {
		n, info, note, err := e.recvNext(b)
		if note != nil {
			if err := e.handler(note); err != nil {
				return 0, MsgInfo{}, e.ioError("read", err)
			}
			continue
		}
		if err != nil {
			return n, info, e.ioError("read", err)
		}
		return n, info, nil
	}
}

// recvNext is one read of RecvMsg under the receive lock, as
// Conn.recvNext is, without the end-of-association rules a Conn has. It
// returns data with its checked metadata, a notification's piece when
// there is no handler, a parsed notification for the caller to hand to
// the handler once the lock is released, or the read's error.
func (e *Endpoint) recvNext(b []byte) (int, MsgInfo, Notification, error) {
	s := &e.recv
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if s.serving {
			n, info := s.servePiece(b)
			return n, info, nil, nil
		}
		s.b, s.keepNotes = b, true
		perr := e.sock.raw.Read(s.fn)
		s.b, s.iov.Base = nil, nil
		n, flags, record, cut, err := s.take()
		switch {
		case perr != nil:
			return 0, MsgInfo{}, nil, e.readEnded(perr)
		case cut:
			return 0, MsgInfo{}, nil, e.abortInterruptedNotification(err)
		case err != nil:
			return 0, MsgInfo{}, nil, e.readEnded(err)
		case record:
			if !s.kept {
				// A record whose start could not be read whole.
				s.notes.reset()
				continue
			}
			data, ferr := s.notes.finish()
			if ferr != nil {
				s.notes.reset()
				return 0, MsgInfo{}, nil, ferr
			}
			if e.handler != nil {
				note, perr := ParseNotification(data)
				s.notes.reset()
				if perr != nil {
					return 0, MsgInfo{}, nil, perr
				}
				return 0, MsgInfo{}, note, nil
			}
			_ = parseRecvCmsgs(s.control(), flags, &s.serveInfo)
			s.serving, s.served = true, 0
			n, info := s.servePiece(b)
			return n, info, nil, nil
		}
		var info MsgInfo
		err = parseEndpointRecvCmsgs(s.control(), flags, &info)
		return n, info, nil, err
	}
}

// readEnded is what a read that ends with err reports: net.ErrClosed
// while the endpoint is being closed or once it is, and err otherwise,
// with a closed descriptor's error normalised.
func (e *Endpoint) readEnded(err error) error {
	if lifeState(e.life.state.Load()) != lifeOpen {
		return net.ErrClosed
	}
	return closedCause(err)
}

// abortInterruptedNotification ends a read whose notification record was
// cut short, as on a Conn: its tail could otherwise be read as a record of
// its own, so the endpoint is aborted rather than left to misread its
// receive queue, and so misroute what follows. Linux puts a record's rest
// back at the head of the queue at once, so this is a defensive path.
// e.recv.mu must be held.
func (e *Endpoint) abortInterruptedNotification(cause error) error {
	err := errors.Join(e.recv.notes.interrupted(), closedCause(cause))
	e.recv.notes.reset()
	return joinAbortCause(err, e.Abort())
}

// --- PeelOff -----------------------------------------------------------------------

// PeelOff branches association id off the endpoint onto a socket of its
// own (RFC 6458 §9.2), and returns it as a *Conn. The association leaves
// the endpoint entirely: what was queued for it moves with it
// (net/sctp/socket.c: sctp_sock_migrate), its later messages and
// notifications arrive on the Conn, and the endpoint no longer knows its
// id, so a SendMsg to it fails with EPIPE. Closing the endpoint leaves
// the Conn alone.
//
// The Conn is a third kind of socket: Linux clones it from the endpoint's,
// in a style of its own (SCTP_SOCKET_UDP_HIGH_BANDWIDTH, sctp_do_peeloff),
// not a one-to-one socket. It keeps every kernel setting the endpoint had,
// its subscriptions included (sctp_sock_migrate), and its association
// keeps the send defaults it was created with, which the Conn reads from
// it. It takes the NotificationHandler and CloseTimeout of the endpoint's
// Config, and the Config's own Notifications as its subscriptions: an
// EventAssocChange record reaches it only when those list
// EventAssocChange, as on any Conn, the Endpoint's own delivery of every
// such record staying with the Endpoint. A peer's SHUTDOWN never marks
// the socket shut for reading (net/sctp/sm_sideeffect.c:
// sctp_cmd_new_state), so the package ends its reads with io.EOF on the
// AssocShutdownComplete record, and a failed association's error is
// sticky, as on any Conn. Close, CloseWithTimeout and Shutdown start the
// graceful shutdown with an empty SCTP_EOF send, since Linux ignores
// shutdown(2) on this socket kind (sctp_shutdown), and SendOptions.Path is
// refused, since Linux ignores the destination there
// (sctp_sendmsg_get_daddr).
//
// The descriptor is created close-on-exec and non-blocking
// (SCTP_SOCKOPT_PEELOFF_FLAGS with SOCK_CLOEXEC and SOCK_NONBLOCK). Linux
// moves the association to the new socket before it allocates the new
// descriptor, and when the process has none to spare it releases the new
// socket, and the association with it (sctp_getsockopt_peeloff_common).
// So PeelOff first makes sure the process can take one more descriptor,
// by taking one and giving it back, and fails with an error matching
// syscall.EMFILE otherwise, the association staying on the endpoint. A
// descriptor another goroutine takes between that check and the peel-off
// can still cost the association, and PeelOff then fails with the
// kernel's EMFILE. So can the system running out of open files as a
// whole: when the new socket's file cannot be allocated, Linux releases
// the socket with the association, and PeelOff fails with the kernel's
// ENFILE (net/socket.c: sock_alloc_file; fs/file_table.c:
// alloc_empty_file). The descriptor check cannot see that limit coming,
// since a duplicate descriptor shares its file.
//
// A scope selector or a negative id is refused with an error matching
// syscall.EINVAL before any system call, and an id the endpoint does not
// hold fails with the kernel's EINVAL (sctp_do_peeloff). Errors are
// *net.OpError with Op "peeloff".
func (e *Endpoint) PeelOff(id AssocID) (*Conn, error) {
	if !e.opened() {
		return nil, e.peelError(net.ErrClosed)
	}
	if err := assocIDArg("PeelOff", id); err != nil {
		return nil, e.peelError(err)
	}
	fd := -1
	if err := e.sock.control(func(efd int) error {
		var err error
		fd, err = peelOff(efd, id)
		return err
	}); err != nil {
		return nil, e.peelError(err)
	}
	s, err := wrapSocketFile(fd, e.sock.family, e.sock.network)
	if err != nil {
		return nil, e.peelError(err)
	}
	c, err := newConn(s, kindPeeled, e.peel)
	if err != nil {
		return nil, e.peelError(err)
	}
	return c, nil
}

// peelError wraps an error of PeelOff, with the endpoint's addresses as
// Addr, as Listener.AcceptSCTP's errors carry the listener's.
func (e *Endpoint) peelError(err error) error {
	return opError("peeloff", e.network(), nil, e.Addr(), err)
}

// peelOff branches association id off the one-to-many socket fd with
// SCTP_SOCKOPT_PEELOFF_FLAGS (RFC 6458 §9.2's sctp_peeloff) and returns the
// new descriptor, close-on-exec and non-blocking (net/sctp/socket.c:
// sctp_getsockopt_peeloff_common passes SOCK_CLOEXEC to
// get_unused_fd_flags and sets O_NONBLOCK for SOCK_NONBLOCK). The
// descriptor is read from the argument, where the kernel writes it
// (sctp_peeloff_arg_t's sd). Before that, it checks that the process can
// take one more descriptor, by duplicating fd, close-on-exec, and closing
// the duplicate at once: the duplicate is allocated as the peel-off's
// descriptor would be, lowest free number under RLIMIT_NOFILE
// (fs/file.c: alloc_fd), and closing it is its one close, since nothing
// else ever knows its number.
func peelOff(fd int, id AssocID) (int, error) {
	spare, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return -1, fmt.Errorf("sctp: no descriptor to spare for the peeled-off association: %w", os.NewSyscallError("fcntl", errno))
	}
	_ = syscall.Close(int(spare))

	var arg [sizePeeloffFlagsArg]byte
	binary.NativeEndian.PutUint32(arg[peeloffFlagsArgAssocIDOff:], uint32(id))
	binary.NativeEndian.PutUint32(arg[peeloffFlagsArgFlagsOff:], uint32(syscall.SOCK_CLOEXEC|syscall.SOCK_NONBLOCK))
	l := uint32(len(arg))
	if err := rawGetsockopt(fd, ipprotoSCTP, optSockoptPeeloffFlags, unsafe.Pointer(&arg[0]), &l); err != nil {
		return -1, os.NewSyscallError("getsockopt", err)
	}
	return int(int32(binary.NativeEndian.Uint32(arg[peeloffFlagsArgSDOff:]))), nil
}

// --- deadlines, raw access and closing ----------------------------------------------

// SetDeadline sets the read and write deadlines: a RecvMsg or SendMsg
// waiting when the deadline passes returns an error wrapping
// os.ErrDeadlineExceeded, and a zero t means no deadline. They are the
// endpoint's, whatever association a call is for (RFC 6458 §3.2).
func (e *Endpoint) SetDeadline(t time.Time) error {
	return e.setDeadline(t, (*os.File).SetDeadline)
}

// SetReadDeadline sets the deadline for RecvMsg.
func (e *Endpoint) SetReadDeadline(t time.Time) error {
	return e.setDeadline(t, (*os.File).SetReadDeadline)
}

// SetWriteDeadline sets the deadline for SendMsg.
func (e *Endpoint) SetWriteDeadline(t time.Time) error {
	return e.setDeadline(t, (*os.File).SetWriteDeadline)
}

func (e *Endpoint) setDeadline(t time.Time, set func(*os.File, time.Time) error) error {
	if e == nil || e.sock.file == nil {
		return opError("set", e.network(), nil, nil, net.ErrClosed)
	}
	if err := set(e.sock.file, t); err != nil {
		return opError("set", e.network(), nil, e.Addr(), err)
	}
	return nil
}

// SyscallConn returns raw access to the endpoint's descriptor, for socket
// options the package does not type, the per-association ones among
// them. Read and Write wait through the runtime poller and follow the
// endpoint's deadlines; Read also takes the endpoint's receive lock, so
// that it never runs in the middle of one of the package's reads. Once
// the descriptor has been released, every call returns an error matching
// net.ErrClosed without running the callback.
func (e *Endpoint) SyscallConn() (syscall.RawConn, error) {
	if !e.opened() {
		return nil, opError("syscallconn", e.network(), nil, e.Addr(), net.ErrClosed)
	}
	return &endpointRawConn{e: e}, nil
}

// endpointRawConn is the syscall.RawConn Endpoint.SyscallConn returns,
// with errors wrapped as connRawConn wraps a Conn's, and the addresses an
// error carries copied only when there is one.
type endpointRawConn struct{ e *Endpoint }

func (r *endpointRawConn) Control(f func(fd uintptr)) error {
	if err := r.e.sock.raw.Control(f); err != nil {
		return opError("raw-control", r.e.network(), nil, r.e.Addr(), err)
	}
	return nil
}

func (r *endpointRawConn) Read(f func(fd uintptr) bool) error {
	r.e.recv.mu.Lock()
	defer r.e.recv.mu.Unlock()
	if err := r.e.sock.raw.Read(f); err != nil {
		return opError("raw-read", r.e.network(), r.e.Addr(), nil, err)
	}
	return nil
}

func (r *endpointRawConn) Write(f func(fd uintptr) bool) error {
	if err := r.e.sock.raw.Write(f); err != nil {
		return opError("raw-write", r.e.network(), r.e.Addr(), nil, err)
	}
	return nil
}

// endpointCloseOps is closeOps for an Endpoint: the release and the
// abortive close of any socket (sockCloseOps), which on a one-to-many
// socket aborts every association it holds (net/sctp/socket.c:
// sctp_close), and a graceful shutdown taken association by association.
// Linux ignores shutdown(2) on a one-to-many socket (sctp_shutdown), and
// an SCTP_EOF send names one association, so RFC 6458 §3.1.5's close of
// every association is one SCTP_EOF send each.
//
// Its closeClock serves one close call only (close.go), so every Close
// and Abort builds endpointCloseOps of its own.
type endpointCloseOps struct {
	sockCloseOps

	// shut is the set of associations an SCTP_EOF send has been made for,
	// as of the last look at the list.
	shut map[AssocID]struct{}
}

// newCloseOps returns the steps that close e's descriptor.
func (e *Endpoint) newCloseOps() *endpointCloseOps {
	return &endpointCloseOps{sockCloseOps: sockCloseOps{sock: &e.sock}}
}

// startShutdown starts the graceful shutdown of every association the
// endpoint holds. Its error says only that the list could not be read;
// the waits that follow read it again.
func (o *endpointCloseOps) startShutdown() error {
	ids, err := o.sock.assocIDs()
	if err != nil {
		return err
	}
	o.shutdownEach(ids)
	return nil
}

// assocGone reports whether every association of the endpoint is gone: it
// is the compound form the lifecycle's wait needs for a socket holding
// many. Associations can end and appear while the endpoint closes, a new
// one from a peer's INIT on a listening endpoint for example, so it reads
// the association list again each time, and starts the shutdown of any
// association it has not yet shut down. An error is a list that could not
// be read, which is not evidence that the associations are gone.
func (o *endpointCloseOps) assocGone() (bool, error) {
	ids, err := o.sock.assocIDs()
	if err != nil {
		return false, err
	}
	if len(ids) == 0 {
		return true, nil
	}
	o.shutdownEach(ids)
	return false, nil
}

// shutdownEach makes one SCTP_EOF send for each association of ids not
// already shut down, and forgets those no longer listed: Linux gives an
// ended association's id to a later one (net/sctp/associola.c:
// idr_alloc_cyclic), which must not be taken for one already shut down.
// The send never waits and is never retried: an error means the
// association is already gone or already shutting down, and the next look
// at the list tells which (net/sctp/socket.c: sctp_sendmsg_check_sflags
// starts the SHUTDOWN primitive and returns before sctp_sendmsg_to_asoc,
// the only path that waits).
func (o *endpointCloseOps) shutdownEach(ids []AssocID) {
	next := make(map[AssocID]struct{}, len(ids))
	for _, id := range ids {
		if _, done := o.shut[id]; !done {
			_ = o.sock.control(func(fd int) error { return rawSendEnd(fd, sndFlagEOF, id, nil) })
		}
		next[id] = struct{}{}
	}
	o.shut = next
}

// closeError wraps an error of Close or Abort once, with Op "close", the
// endpoint's network and its addresses; nil stays nil, without copying
// the addresses.
func (e *Endpoint) closeError(err error) error {
	if err == nil {
		return nil
	}
	return opError("close", e.network(), e.Addr(), nil, err)
}

// Close shuts down every association the endpoint still holds (RFC 9260
// §9.2; RFC 6458 §3.1.5) and releases the descriptor, waiting up to
// Config.CloseTimeout (3 s when it is zero) for the peers to complete the
// SHUTDOWN handshakes and aborting (RFC 9260 §9.1) every association
// still there when it runs out. It returns nil in both cases: running out
// of time is an outcome, not an error. Associations that appear while it
// waits are shut down too, and associations already peeled off are not
// affected. An Abort from another goroutine during the wait sends the
// ABORTs at once and makes Close return nil. Whatever arrives during the
// wait is discarded with the descriptor. A second Close, or any close
// after Abort, returns an error matching net.ErrClosed. Errors are
// *net.OpError with Op "close".
func (e *Endpoint) Close() error {
	if e == nil {
		return opError("close", "sctp", nil, nil, net.ErrClosed)
	}
	return e.closeError(e.life.close(e.newCloseOps(), e.closeWait))
}

// Abort ends every association the endpoint holds with an ABORT (RFC
// 9260 §§9.1, 11.1.4) and releases the descriptor. While a Close waits for
// the graceful shutdowns, Abort makes that Close send the ABORTs at once,
// waits until it has released the descriptor, and returns nil. After the
// descriptor has been released it returns an error matching net.ErrClosed.
// Associations already peeled off are not affected.
func (e *Endpoint) Abort() error {
	if e == nil {
		return opError("close", "sctp", nil, nil, net.ErrClosed)
	}
	return e.closeError(e.life.abortNow(e.newCloseOps()))
}
