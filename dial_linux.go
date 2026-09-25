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
	"context"
	"errors"
	"net/netip"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

// Dial connects to raddr with a zero Config. See Config.Dial.
func Dial(ctx context.Context, network string, laddr, raddr *Addr) (*Conn, error) {
	return (*Config)(nil).Dial(ctx, network, laddr, raddr)
}

// Dial opens a one-to-one SCTP socket, applies c, binds it to laddr when
// laddr is not nil, and sets up an association with raddr (RFC 9260 §5.1),
// returning once the association is established. network is "sctp",
// "sctp4" or "sctp6"; with "sctp" and a wildcard laddr the socket is
// AF_INET6 dual-stack, so that the peer's addresses of either family can
// join the association. Several IPs in raddr are all given to the kernel
// for the setup (sctp_connectx, RFC 6458 §9.9), and several in laddr make
// a multi-homed local endpoint.
//
// The setup can be abandoned with ctx at any point, and then ends at once:
// Dial releases the attempt the way c.AbandonPolicy says (AbandonAbort by
// default, which sends an ABORT, RFC 9260 §9.1) and returns ctx's error.
// A context that is already done opens no socket at all. Against a peer
// that never answers, the kernel alone would give up only when its INIT
// retransmissions run out (RFC 9260 §5.1): on Linux's defaults (rto_initial
// 3 s, rto_max 60 s, max_init_retransmits 8) that is about 333 s. A
// refusal, such as the ABORT a peer with no listener on the port answers
// with, ends the call as soon as it arrives.
//
// Config.Control must not connect the socket: Dial sets up the
// association itself, and when an association Control started has already
// been established, the kernel refuses Dial's setup with EISCONN
// (net/sctp/socket.c: __sctp_connect), which Dial returns.
//
// Dial never returns a connection to itself. When laddr names no port, the
// kernel picks one, and on a local address it can pick the very port
// being dialed; with nothing listening there, the socket's INIT reaches
// its own association, which takes it for an initialization collision
// (RFC 9260 §5.2.1; net/sctp/sm_statefuns.c: sctp_sf_do_5_2_1_siminit)
// and completes the setup with itself. As net's TCP dialer does
// (net/tcpsock_posix.go: selfConnect), Dial detects that case — the
// association's local port is raddr's port and every one of its peer
// addresses is one of its own local addresses, a link-local one compared
// without the zone the peer's copy lacks — aborts that association and
// starts over with a new socket, at most twice more, under the same ctx;
// if the setup still ends up connected to itself, Dial fails with an error
// matching syscall.ECONNREFUSED, as for a port nobody listens on. A
// laddr that names its port is the caller's choice and is left alone.
//
// Errors are *net.OpError with Op "dial", wrapping the context's error, a
// validation error matching syscall.EINVAL, or the kernel's errno.
func (c *Config) Dial(ctx context.Context, network string, laddr, raddr *Addr) (*Conn, error) {
	conn, err := c.dial(ctx, network, laddr, raddr)
	if err != nil {
		return nil, opError("dial", canonicalName(network), netAddr(laddr), netAddr(raddr), err)
	}
	return conn, nil
}

func (c *Config) dial(ctx context.Context, network string, laddr, raddr *Addr) (*Conn, error) {
	if ctx == nil {
		return nil, invalidArg("Dial needs a non-nil context")
	}
	if raddr == nil || len(raddr.IPs) == 0 {
		return nil, invalidArg("Dial needs a remote address with at least one IP")
	}
	family, err := socketFamily(network, laddr, raddr)
	if err != nil {
		return nil, err
	}
	p, err := c.prepare(styleDial)
	if err != nil {
		return nil, err
	}
	var bind []byte
	if laddr != nil {
		if bind, err = localBindAddrs(family, laddr); err != nil {
			return nil, err
		}
	}
	peer, err := encodeAddrs(family, raddr.IPs, raddr.Port)
	if err != nil {
		return nil, err
	}
	var control func(string, string, syscall.RawConn) error
	if c != nil {
		control = c.Control
	}
	d := dialAttempt{
		network: canonicalName(network),
		family:  family,
		address: raddr.String(),
		control: control,
		p:       p,
		bind:    bind,
		peer:    peer,
	}

	// The kernel chose the local port when laddr names none, and only then
	// can a self-connection be a chance the dial may undo (see Dial).
	guard := laddr == nil || laddr.Port == 0
	for retries := 0; ; retries++ {
		conn, err := d.run(ctx)
		if err != nil || !guard || !conn.selfConnected() {
			return conn, err
		}
		_ = conn.Abort()
		if retries == maxSelfConnectRetries {
			return nil, os.NewSyscallError("sctp_connectx", syscall.ECONNREFUSED)
		}
	}
}

// maxSelfConnectRetries is how many times Dial starts over after its
// setup connected the socket to itself (see Dial), as net's TCP dialer
// does (net/tcpsock_posix.go).
const maxSelfConnectRetries = 2

// dialAttempt is what one attempt of Dial needs, validated once for all of
// them.
type dialAttempt struct {
	network string
	family  int
	address string // raddr as a string, for Config.Control
	control func(string, string, syscall.RawConn) error
	p       *prepared
	bind    []byte // the packed laddr, or nil
	peer    []byte // the packed raddr
}

// run makes one attempt: a new socket, set up, bound, connected and
// waited for.
func (d *dialAttempt) run(ctx context.Context) (*Conn, error) {
	// Every check that needs no socket is done: a context that has already
	// ended must not open one.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s, err := newSocket(d.family, d.network)
	if err != nil {
		return nil, err
	}
	if err := connectSocket(ctx, &s, d.address, d.control, d.p.ops, d.bind, d.peer); err != nil {
		_ = abandonDial(&sockCloseOps{sock: &s, kind: kindDialed}, d.p.abandon)
		return nil, err
	}
	return newConn(s, kindDialed, d.p)
}

// selfConnected reports whether c's association runs from its socket back
// to itself: its local port is its peer port, and it has peer addresses,
// every one of which is also one of its local addresses, as peerIsLocal
// tells (net/tcpsock_posix.go: selfConnect makes the port-and-address
// test for TCP, where each end has one address).
//
// A shared address alone would not do. Hosts on different networks often
// hold the same private address (a container bridge's 172.17.0.1, say),
// Linux adds every in-scope address a peer lists to the association
// (net/sctp/sm_make_chunk.c: sctp_process_param), and a wildcard dialer's
// local set holds every in-scope local address, so a genuine peer whose
// port happens to equal the ephemeral one can share an address with it.
// In a self-connection the socket is its own peer, so its peer set is
// what its own INIT listed, which is its local set (sctp_make_init lists
// the association's bind address list), and processing the INIT ACK
// drops any dialed address the peer did not list (sctp_process_init
// removes the transports still in state UNKNOWN). Every peer address is
// thus one of the local addresses, with one difference in form: a
// link-local address comes back from the INIT's address parameter with
// no interface index, while the local copy carries one (see peerIsLocal).
//
// It reads the address snapshots newConn took, which hold no IPs for an
// association that has already ended.
func (c *Conn) selfConnected() bool {
	l, r := c.laddr.Load(), c.raddr.Load()
	if l == nil || r == nil || l.Port == 0 || l.Port != r.Port || len(r.IPs) == 0 {
		return false
	}
	for _, peer := range r.IPs {
		found := false
		for _, local := range l.IPs {
			if peerIsLocal(peer, local) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// peerIsLocal reports whether the peer address peer is the local address
// local. netip.Addr equality compares zones as well, and the two copies
// of a link-local address differ in that: a local address carries its
// interface's index as its scope id (net/sctp/ipv6.c:
// sctp_v6_copy_addrlist), whereas a peer address learned from an INIT or
// INIT ACK address parameter carries scope id 0, since
// sctp_v6_from_addr_param stores its iif argument and every caller passes
// 0 (net/sctp/sm_make_chunk.c: sctp_process_init, sctp_process_param,
// sctp_add_asconf_response, sctp_asconf_param_success; net/sctp/input.c:
// __sctp_rcv_init_lookup, __sctp_rcv_asconf_lookup); only a peer address
// taken from a packet's source keeps its receiving interface
// (sctp_v6_from_skb). The decoder keeps a zone only for a link-local
// address with a non-zero scope id (decodeSockaddrEntry), so a zone-less
// link-local peer address is matched against the local address without
// its zone, as the kernel's own comparison does when either scope id is 0
// (__sctp_v6_cmp_addr). A peer address that carries a zone must match
// exactly: a local link-local address always has one.
func peerIsLocal(peer, local netip.Addr) bool {
	return peer == local || (peer.Zone() == "" && peer.IsLinkLocalUnicast() && peer == local.WithZone(""))
}

// abandonDial releases a socket whose association never reached
// ESTABLISHED, as policy says: AbandonAbort sends an ABORT (RFC 9260 §9.1)
// through the abortive close, which clears the setup at the peer at once
// if it has already answered; AbandonQuiet releases it plainly, which
// makes Linux discard the setup without a word (the SHUTDOWN primitive in
// COOKIE-WAIT or COOKIE-ECHOED: net/sctp/sm_statefuns.c,
// sctp_sf_cookie_wait_prm_shutdown). Either way the descriptor is closed
// once, through its *os.File. The error is the release's, which Dial
// does not report over the setup's own.
func abandonDial(ops closeOps, policy AbandonPolicy) error {
	if policy == AbandonQuiet {
		return ops.release()
	}
	return ops.abortive()
}

// connectSocket configures and binds a new socket, starts the association
// setup and waits for it.
func connectSocket(ctx context.Context, s *socket, address string, control func(string, string, syscall.RawConn) error, ops []configOp, bind, peer []byte) error {
	if err := setupSocket(s, address, control, ops); err != nil {
		return err
	}
	if bind != nil {
		if err := s.bindx(optSockoptBindxAdd, bind); err != nil {
			return os.NewSyscallError("sctp_bindx", err)
		}
	}
	if testHookDialConnecting != nil {
		if err := testHookDialConnecting(s); err != nil {
			return err
		}
	}
	// The socket is non-blocking, so the setup is started and EINPROGRESS
	// comes straight back (net/sctp/socket.c: sctp_wait_for_connect with a
	// zero timeout). EALREADY would say a setup with this peer is already
	// under way, which cannot happen on a fresh socket whose Control left
	// it unconnected, as Dial requires; it is tolerated defensively, since
	// the wait below confirms establishment either way. EISCONN, for an
	// association Control started and that is already established, is an
	// error.
	if err := s.connectx(peer); err != nil && err != syscall.EINPROGRESS && err != syscall.EALREADY {
		return os.NewSyscallError("sctp_connectx", err)
	}
	if testHookDialStarted != nil {
		testHookDialStarted()
	}
	return awaitEstablished(ctx, s)
}

// testHookDialStarted, when a test sets it, runs between the start of the
// setup and the wait for it, so that a test can make the association
// change state before Dial first looks. It is nil otherwise.
var testHookDialStarted func()

// testHookDialConnecting, when a test sets it, runs on each attempt's
// socket just before the setup starts, so that a test can bind it as the
// kernel's own port choice might have, for example to the port being
// dialed. It is nil otherwise.
var testHookDialConnecting func(*socket) error

// connectx starts the association setup with the packed sockaddr array
// addrs through SCTP_SOCKOPT_CONNECTX3 (RFC 6458 §9.9's sctp_connectx),
// the only form this package uses: the older CONNECTX and CONNECTX_OLD
// return no association id. The error is the bare errno.
func (s *socket) connectx(addrs []byte) error {
	arg := connectx3Arg{addrNum: int32(len(addrs)), addrs: unsafe.Pointer(&addrs[0])}
	l := uint32(unsafe.Sizeof(arg))
	err := s.getsockopt(optSockoptConnectx3, unsafe.Pointer(&arg), &l)
	// The kernel reads addrs through the pointer in arg, which the compiler
	// cannot see as a use of addrs.
	runtime.KeepAlive(addrs)
	return err
}

// aLongTimeAgo is a deadline in the past, which ends a poller wait at once.
var aLongTimeAgo = time.Unix(1, 0)

// awaitEstablished waits, through the runtime poller, until the
// association is established, the setup fails, or ctx is done.
//
// The wait is for readability, which the SCTP_ASSOC_CHANGE subscription
// the package keeps on every socket guarantees: establishment queues
// COMM_UP, and a failed setup queues CANT_STR_ASSOC as well as setting the
// socket error (SCTP_CMD_SET_SK_ERR: ECONNREFUSED for an ABORT, ETIMEDOUT
// once the INIT or COOKIE ECHO retransmissions run out), which sctp_poll
// reports as EPOLLERR (net/sctp/sm_statefuns.c: sctp_sf_do_5_1E_ca,
// sctp_stop_t1_and_abort; net/sctp/socket.c: sctp_poll).
//
// Writability would not do. The runtime poller is edge-triggered: it
// wakes a waiter once per readiness change the kernel signals, and the
// waiter's look consumes that wake. A peer that accepts and at once ends
// the association gracefully takes the socket from ESTABLISHED to
// CLOSING (net/sctp/sm_sideeffect.c: sctp_cmd_new_state) and then frees
// the association, all before the dial may look. A look after that finds
// SCTP_STATUS answering EINVAL, exactly as it does before the association
// is established, so it cannot tell "gone" from "not yet", and it waits
// again for a writability change that never comes. The queued COMM_UP
// record, by contrast, is lasting evidence: it stays on the socket until
// something reads it.
//
// Each wake checks SO_ERROR first, then asks SCTP_STATUS, which answers
// only while the socket is ESTABLISHED or CLOSING and still holds its
// association (sctp_id2assoc). When it does not answer, a notification
// queued on the socket (read with MSG_PEEK, so that it stays for the
// connection's own reads) shows that the association was established and
// has already ended; the dial has succeeded all the same, as a TCP
// connect does when the peer's FIN arrives first, and the connection's
// reads then report the end.
//
// ctx ends the wait through the read deadline, which a context.AfterFunc
// moves into the past. The deadline is cleared before a successful return.
// A setup found complete at the moment ctx ended counts as established.
func awaitEstablished(ctx context.Context, s *socket) error {
	established := false
	var failed error
	check := func(fd int) bool {
		soerr, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
		if err != nil {
			failed = os.NewSyscallError("getsockopt", err)
			return true
		}
		if soerr != 0 {
			failed = os.NewSyscallError("sctp_connectx", syscall.Errno(soerr))
			return true
		}
		var st [sizeStatus]byte
		l := uint32(len(st))
		switch err := rawGetsockopt(fd, ipprotoSCTP, optStatus, unsafe.Pointer(&st[0]), &l); err {
		case nil:
			established = true
			return true
		case syscall.EINVAL:
		default:
			failed = os.NewSyscallError("getsockopt", err)
			return true
		}
		var b [1]byte
		n, _, flags, _, err := syscall.Recvmsg(fd, b[:], nil, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		if err == nil && (n > 0 || flags&msgNotification != 0) {
			established = true
			return true
		}
		return false
	}

	stop := func() bool { return true }
	var interrupted chan struct{}
	if ctx.Done() != nil {
		interrupted = make(chan struct{})
		stop = context.AfterFunc(ctx, func() {
			_ = s.file.SetReadDeadline(aLongTimeAgo)
			close(interrupted)
		})
	}
	err := s.raw.Read(func(fd uintptr) bool { return check(int(fd)) })
	if !stop() {
		// The AfterFunc has started: let it finish moving the deadline,
		// so that clearing it below cannot be undone afterwards.
		<-interrupted
	}

	if err != nil && errors.Is(err, os.ErrDeadlineExceeded) && ctx.Err() != nil && failed == nil {
		// The poller stopped waiting because ctx ended. The setup may have
		// completed at the same moment; a completed one is kept.
		_ = s.control(func(fd int) error {
			check(fd)
			return nil
		})
		if !established && failed == nil {
			return ctx.Err()
		}
	} else if err != nil {
		return err
	}
	if failed != nil {
		return failed
	}
	return s.file.SetReadDeadline(time.Time{})
}
