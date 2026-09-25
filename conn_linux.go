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

// conn_linux.go builds a Conn around a connected descriptor and holds the
// Conn methods that are neither sends nor receives nor typed options: the
// association id, the addresses, the deadlines, raw access and adoption
// of an inherited descriptor.

package sctp

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// newConn builds a Conn around s, a connected socket this package owns,
// with the handler, grace period and subscriptions of p. It takes s over
// on every path: when it fails, it releases s with an abortive close,
// since the association may be live.
//
// The association id is read once, here, from SCTP_STATUS (RFC 6458
// §8.2.1) and fixed for the life of the Conn. On an accepted socket whose
// association ended before Accept, SCTP_STATUS fails with EINVAL: Linux
// keeps such an association queued so that accept(2) can still return it
// (net/sctp/sm_sideeffect.c: sctp_cmd_delete_tcb), but hands it over as a
// closed socket (net/sctp/socket.c: sctp_sock_migrate marks it CLOSED and
// shut for reading, and sctp_id2assoc then finds no association; see
// socket.status for the one way it can answer again). That connection is
// still returned, because the peer's data may be queued on it, with id 0
// and address snapshots that hold no IPs, since Linux no longer knows
// them; its reads report the end. A dialed association that was
// established and ended before Dial looked (awaitEstablished) is returned
// the same way.
func newConn(s socket, kind connKind, p *prepared) (*Conn, error) {
	c := &Conn{sock: s, kind: kind, handler: p.handler, closeWait: p.closeTimeout}
	c.life.init()
	if err := c.init(p); err != nil {
		_ = c.newCloseOps().abortive()
		return nil, err
	}
	return c, nil
}

// init reads what newConn fixes for the life of the Conn.
func (c *Conn) init(p *prepared) error {
	subs := p.subscribed
	if p.adopted {
		// Whoever set the descriptor up chose its subscriptions, and the
		// kernel is the only record of them.
		s, err := kernelSubscriptions(&c.sock)
		if err != nil {
			return err
		}
		subs = s
	}
	c.subs.Store(uint32(subs))

	if c.kind == kindAccepted || c.kind == kindAdopted {
		// The package keeps SCTP_ASSOC_CHANGE subscribed on every socket
		// it uses (Config.Notifications). An association takes its own
		// copy of the endpoint's subscriptions when it is created
		// (net/sctp/associola.c: sctp_association_init), so one queued on
		// a listener before the package owned it, or on a descriptor set
		// up elsewhere, may lack it; on an established one-to-one socket
		// SCTP_EVENT reaches that copy (net/sctp/socket.c:
		// sctp_setsockopt_event).
		if err := c.sock.control(func(fd int) error { return setEvent(fd, EventAssocChange, true) }); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	}

	assoc, state, err := c.sock.status()
	switch {
	case err == nil && state != StateClosed:
		c.assoc = assoc
	case err == nil, errors.Is(err, syscall.EINVAL):
		// The association has already ended; see newConn.
		c.laddr.Store(&Addr{})
		c.raddr.Store(&Addr{})
		c.send.init(c)
		return nil
	default:
		return os.NewSyscallError("getsockopt", err)
	}

	c.refreshSnapshots()
	if ra := c.raddr.Load(); ra != nil {
		c.peerPort = ra.Port
	}
	c.send.init(c)
	return nil
}

// refreshSnapshots replaces the LocalAddr and RemoteAddr snapshots with the
// association's current address lists, each as a whole. A list that cannot
// be read, because the association ended meanwhile, leaves that snapshot
// as it was, or, on the first read, empty.
func (c *Conn) refreshSnapshots() {
	if a, err := c.sock.getAddrs(optGetLocalAddrs, c.assoc); err == nil {
		c.laddr.Store(a)
	} else if c.laddr.Load() == nil {
		c.laddr.Store(&Addr{})
	}
	if a, err := c.sock.getAddrs(optGetPeerAddrs, c.assoc); err == nil {
		c.raddr.Store(a)
	} else if c.raddr.Load() == nil {
		c.raddr.Store(&Addr{})
	}
}

// opened reports whether c is a Conn this package opened and has not yet
// released: false for a nil or zero Conn, and once Close or Abort has
// released the descriptor.
func (c *Conn) opened() bool {
	return c != nil && c.sock.raw != nil && lifeState(c.life.state.Load()) != lifeClosed
}

// network is the network name c's errors carry.
func (c *Conn) network() string {
	if c == nil || c.sock.network == "" {
		return "sctp"
	}
	return c.sock.network
}

// AssocID returns the id of the connection's association, fixed for the
// life of the Conn: the id notifications about it carry. It is 0 for a
// connection whose association ended before Accept returned it.
func (c *Conn) AssocID() AssocID {
	if c == nil {
		return 0
	}
	return c.assoc
}

// LocalAddr returns a snapshot of the association's local addresses, as an
// *Addr: the association's own list (RFC 6458 §9.5), which for a wildcard
// bind is the endpoint's addresses restricted to the scope of the peer's
// address (net/sctp/bind_addr.c: sctp_bind_addr_copy), not every address
// in the namespace. The snapshot is taken when the association is
// established and replaced as a whole after a successful BindAdd or
// BindRemove, so a concurrent caller gets the old set or the new one,
// never a mix; the returned *Addr is never modified afterwards. It stays
// readable after Close, and does not follow changes made with ASCONF by
// the peer; LocalAddrs does. It holds no IPs when the association ended
// before Accept.
func (c *Conn) LocalAddr() net.Addr {
	if c == nil {
		return nil
	}
	return netAddr(c.laddr.Load())
}

// RemoteAddr returns a snapshot of the peer's addresses, as an *Addr,
// taken and refreshed the way LocalAddr's is. PeerAddrs follows changes
// the peer makes with ASCONF; this snapshot does not.
func (c *Conn) RemoteAddr() net.Addr {
	if c == nil {
		return nil
	}
	return netAddr(c.raddr.Load())
}

// LocalAddrs returns the association's local addresses as they are now
// (RFC 6458 §9.5), asking with the connection's own association id, and
// fails once the association has ended.
func (c *Conn) LocalAddrs() (*Addr, error) {
	return c.liveAddrs(optGetLocalAddrs)
}

// PeerAddrs returns the association's peer addresses as they are now (RFC
// 6458 §9.3), asking with the connection's own association id, and fails
// once the association has ended.
func (c *Conn) PeerAddrs() (*Addr, error) {
	return c.liveAddrs(optGetPeerAddrs)
}

// liveAddrs reads one address list of c's association. For an association
// that ended before Accept (id 0) it answers EINVAL, as Linux answers every
// association query on such a socket (sctp_id2assoc), without asking:
// SCTP_GET_LOCAL_ADDRS with id 0 would report the endpoint's bound
// addresses instead of failing (net/sctp/socket.c:
// sctp_getsockopt_local_addrs).
func (c *Conn) liveAddrs(opt int) (*Addr, error) {
	if !c.opened() {
		return nil, opError("get", c.network(), nil, c.LocalAddr(), net.ErrClosed)
	}
	if c.assoc == 0 {
		return nil, optError("get", "getsockopt", c.network(), nil, c.LocalAddr(), syscall.EINVAL)
	}
	a, err := c.sock.getAddrs(opt, c.assoc)
	if err != nil {
		var errno syscall.Errno
		if errors.As(err, &errno) {
			return nil, optError("get", "getsockopt", c.network(), nil, c.LocalAddr(), errno)
		}
		return nil, opError("get", c.network(), nil, c.LocalAddr(), err)
	}
	return a, nil
}

// BindAdd adds ips to the local endpoint (RFC 6458 §9.1, sctp_bindx with
// SCTP_BINDX_ADD_ADDR), on the port the socket is bound to. When ASCONF
// (RFC 5061) was negotiated, Linux also adds the addresses to the
// association and asks the peer to add them; the call returns once the
// kernel has accepted the local change, not when the peer acknowledges it
// (RFC 5061 §5.3). IPv4 addresses are passed IPv4-mapped on an AF_INET6
// socket. The LocalAddr and RemoteAddr snapshots are refreshed afterwards.
// A zero netip.Addr, an empty list, or an address the socket's family
// cannot carry is refused with an error matching syscall.EINVAL before any
// system call.
func (c *Conn) BindAdd(ips ...netip.Addr) error {
	return c.bindx(optSockoptBindxAdd, "BindAdd", ips)
}

// BindRemove removes ips from the local endpoint (RFC 6458 §9.1, sctp_bindx
// with SCTP_BINDX_REM_ADDR), and, when ASCONF (RFC 5061) was negotiated,
// asks the peer to remove them from the association. RFC 6458 §9.1 forbids
// removing every local address, and a list that would is refused with an
// error matching syscall.EINVAL (Linux itself answers EBUSY:
// net/sctp/socket.c, sctp_bindx_rem); so is a list naming the unspecified
// address, which stands for all of them. Arguments are checked as for
// BindAdd, and the snapshots are refreshed the same way.
func (c *Conn) BindRemove(ips ...netip.Addr) error {
	return c.bindx(optSockoptBindxRemove, "BindRemove", ips)
}

// bindx is BindAdd and BindRemove. bindMu keeps each bindx and the refresh
// that follows it together, so that an older refresh never replaces the
// snapshot a newer one stored.
func (c *Conn) bindx(opt int, name string, ips []netip.Addr) error {
	if !c.opened() {
		return opError("bindx", c.network(), nil, c.LocalAddr(), net.ErrClosed)
	}
	buf, err := bindxAddrs(c.sock.family, name, ips)
	if err != nil {
		return opError("bindx", c.network(), nil, c.LocalAddr(), err)
	}

	c.bindMu.Lock()
	defer c.bindMu.Unlock()
	if opt == optSockoptBindxRemove {
		// bindx acts on the endpoint's bound addresses, which on a
		// one-to-one socket SCTP_GET_LOCAL_ADDRS reports for id 0.
		if bound, err := c.sock.getAddrs(optGetLocalAddrs, 0); err == nil && removesEveryAddress(bound.IPs, ips) {
			return opError("bindx", c.network(), nil, c.LocalAddr(), invalidArg("%s would remove every local address, which RFC 6458 §9.1 forbids", name))
		}
	}
	if err := c.sock.bindx(opt, buf); err != nil {
		return optError("bindx", "setsockopt", c.network(), nil, c.LocalAddr(), err)
	}
	if c.assoc != 0 {
		c.refreshSnapshots()
	}
	return nil
}

// bindxAddrs checks the arguments of a BindAdd or BindRemove and packs them
// for a socket of family with port 0, which Linux reads as the port the
// socket is bound to (net/sctp/socket.c: sctp_do_bind, sctp_bindx_rem).
func bindxAddrs(family int, name string, ips []netip.Addr) ([]byte, error) {
	if len(ips) == 0 {
		return nil, invalidArg("%s needs at least one address", name)
	}
	buf, err := encodeAddrs(family, ips, 0)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// removesEveryAddress reports whether removing remove from an endpoint bound
// to bound would leave it with none: every bound address is in remove, or
// remove names the unspecified address. IPv4 addresses compare in plain
// form, and zones must match exactly, so an address on another interface
// is never taken for the bound one (v1 removesEveryLocalAddress).
func removesEveryAddress(bound, remove []netip.Addr) bool {
	for _, r := range remove {
		if r.IsUnspecified() {
			return true
		}
	}
	if len(bound) == 0 {
		return false
	}
	for _, b := range bound {
		found := false
		for _, r := range remove {
			if b.Unmap() == r.Unmap() {
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

// SetDeadline sets the read and write deadlines, as net.Conn documents: a
// call waiting when the deadline passes returns an error wrapping
// os.ErrDeadlineExceeded, and a zero t means no deadline.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.setDeadline(t, (*os.File).SetDeadline)
}

// SetReadDeadline sets the deadline for reads, as net.Conn documents.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.setDeadline(t, (*os.File).SetReadDeadline)
}

// SetWriteDeadline sets the deadline for sends, as net.Conn documents.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.setDeadline(t, (*os.File).SetWriteDeadline)
}

// setDeadline hands t to the runtime poller through the descriptor's
// *os.File, which is what every wait in the package goes through.
func (c *Conn) setDeadline(t time.Time, set func(*os.File, time.Time) error) error {
	if c == nil || c.sock.file == nil {
		return opError("set", c.network(), nil, nil, net.ErrClosed)
	}
	return opError("set", c.network(), nil, c.LocalAddr(), set(c.sock.file, t))
}

// SyscallConn returns raw access to the connection's descriptor, for
// socket options the package does not type, for example. Read and Write
// wait through the runtime poller and follow the connection's deadlines;
// once the descriptor has been released, every call returns an error
// matching net.ErrClosed without running the callback.
func (c *Conn) SyscallConn() (syscall.RawConn, error) {
	if !c.opened() {
		return nil, opError("syscallconn", c.network(), nil, c.LocalAddr(), net.ErrClosed)
	}
	return &connRawConn{c: c}, nil
}

// connRawConn is the syscall.RawConn SyscallConn returns: the descriptor's
// own, with errors wrapped the way net's raw connections wrap them
// (net/rawconn.go), so that a released descriptor reports net.ErrClosed.
type connRawConn struct{ c *Conn }

func (r *connRawConn) Control(f func(fd uintptr)) error {
	return opError("raw-control", r.c.network(), nil, r.c.LocalAddr(), r.c.sock.raw.Control(f))
}

func (r *connRawConn) Read(f func(fd uintptr) bool) error {
	return opError("raw-read", r.c.network(), r.c.LocalAddr(), r.c.RemoteAddr(), r.c.sock.raw.Read(f))
}

func (r *connRawConn) Write(f func(fd uintptr) bool) error {
	return opError("raw-write", r.c.network(), r.c.LocalAddr(), r.c.RemoteAddr(), r.c.sock.raw.Write(f))
}

// FileConn returns a Conn for the SCTP association on the descriptor f
// holds, with a zero Config. See Config.FileConn.
func FileConn(f *os.File) (*Conn, error) {
	return (*Config)(nil).FileConn(f)
}

// FileConn adopts an inherited descriptor (socket activation, descriptor
// passing) that holds an established association on a one-to-one SCTP
// socket. The file is duplicated, close-on-exec, and the caller keeps
// ownership of f; the duplicate is put in non-blocking mode, which, as
// with net.FileConn, the two share.
//
// The duplicate and f are two descriptors for one socket, so what the
// Conn does to the socket, f sees too. Close's SHUTDOWN acts on the
// association whatever f does. An ABORT, from Abort or from a Close that
// runs out of time, first shuts the socket for reading, which f's reads
// then see as the end of the stream, and is sent by the socket's final
// close (net/sctp/socket.c: sctp_close), which happens only once f is
// closed as well. So, as with net.FileConn, close f once the Conn has
// the socket.
//
// Before adopting it, FileConn checks the descriptor: SO_PROTOCOL must be
// IPPROTO_SCTP, SO_TYPE must be SOCK_STREAM (one-to-one; a one-to-many
// socket or one peeled off it is SOCK_SEQPACKET), and SCTP_STATUS must find
// an established association. Anything else is refused with an error
// matching syscall.EINVAL, and a descriptor that is not a socket at all
// fails with the kernel's syscall.ENOTSOCK. Every error is a *net.OpError
// with Op "file", as net.FileConn's are.
//
// The socket is already set up, so only the package-side fields of the
// Config apply: NotificationHandler and CloseTimeout. A Config that sets any
// other field is refused with an error matching syscall.EINVAL. The package
// does enable SCTP_RECVRCVINFO and its own SCTP_ASSOC_CHANGE subscription,
// which its reads depend on, and takes the other notification types the
// descriptor already subscribes to as the caller's.
func (c *Config) FileConn(f *os.File) (*Conn, error) {
	conn, err := c.fileConn(f)
	if err != nil {
		return nil, opError("file", "sctp", nil, nil, err)
	}
	return conn, nil
}

func (c *Config) fileConn(f *os.File) (*Conn, error) {
	p, err := c.prepare(styleFile)
	if err != nil {
		return nil, err
	}
	s, err := adoptFile(f, false)
	if err != nil {
		return nil, err
	}
	if err := applyConfig(&s, p.ops); err != nil {
		_ = s.file.Close()
		return nil, err
	}
	return newConn(s, kindAdopted, p)
}
