// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"unsafe"
)

// SendBacklog reports the socket's send-buffer charge and limit with one
// SO_MEMINFO getsockopt. It needs neither a module beyond SCTP nor a
// privilege. On a Conn the charge belongs to its one association, and
// equals AssocQueues.SendCharged. See SendBacklog for what is charged.
func (c *Conn) SendBacklog() (*SendBacklog, error) {
	if !c.opened() {
		return nil, c.optionError("get", net.ErrClosed)
	}
	v, err := c.sock.sendBacklog()
	if err != nil {
		return nil, c.callError("get", "getsockopt", err)
	}
	return v, nil
}

// SendBacklog reports the whole socket's send-buffer charge and limit:
// every association together, with one SO_MEMINFO getsockopt. Under the
// default net.sctp.sndbuf_policy of 0, sends wait for Limit minus Charged
// to become positive. With policy 1, each association instead waits for
// Limit minus its own AssocQueues.SendCharged (net/sctp/socket.c:
// sctp_wspace). A send can take either charge past Limit. The query needs
// neither a module beyond SCTP nor a privilege.
func (e *Endpoint) SendBacklog() (*SendBacklog, error) {
	if !e.opened() {
		return nil, e.optionError("get", net.ErrClosed)
	}
	v, err := e.sock.sendBacklog()
	if err != nil {
		return nil, e.getError(err)
	}
	return v, nil
}

func (s *socket) sendBacklog() (*SendBacklog, error) {
	var b [sizeMeminfo]byte
	l := uint32(len(b))
	if err := s.getsockoptAt(syscall.SOL_SOCKET, optMeminfo, unsafe.Pointer(&b[0]), &l); err != nil {
		return nil, err
	}
	return decodeSendBacklog(b[:], int(l))
}

// AssocQueues reports the connection's association through SCTP sock_diag.
// It needs Linux 5.1's SO_BINDTOIFINDEX and CONFIG_INET_SCTP_DIAG, whose
// handler has existed since 4.7. The sctp_diag module normally loads on
// demand through alias net-pf-16-proto-4-type-2-132; no capability is
// needed (net_admin gates extra attributes this query does not request).
// When the handler is unavailable it returns an error naming sctp_diag
// and matching ErrUnsupported, never zero counters. Rocky Linux 9 and 10
// ship the module in kernel-modules-extra with sctp_diag-blacklist.conf: an
// administrator must load it with modprobe sctp_diag or remove the blacklist
// line. Ubuntu 24.04 and 26.10 ship it without that blacklist.
//
// The call creates a netlink socket in the calling thread's network
// namespace, checks the SCTP socket's SO_COOKIE, and closes the netlink
// socket afterwards. A query costs tens of microseconds and Linux walks
// the association's queues to count them: use it for monitoring, rather
// than per message. SendBacklog is the cheaper query.
//
// An association that has ended fails with an error matching syscall.ENOENT;
// one that dies or moves during the lookup can also report syscall.ESTALE
// (net/sctp/diag.c: sctp_sock_dump_one). Errors are *net.OpError with Op
// "get", and a closed Conn matches net.ErrClosed.
//
// On Linux 6.18, sctp_diag_dump_one does not initialize the lookup
// addresses' IPv6 scope ids, so a query for a live IPv6 link-local
// association can fail with ENOENT (net/sctp/ipv6.c: sctp_v6_cmp_addr
// compares the scope id); reported at sctp/lksctp-tools#82. Global and
// loopback associations are unaffected, and SendBacklog uses no such lookup.
func (c *Conn) AssocQueues() (*AssocQueues, error) {
	if !c.opened() {
		return nil, c.optionError("get", net.ErrClosed)
	}
	if c.assoc == 0 {
		return nil, c.callError("get", "sock_diag", syscall.ENOENT)
	}
	s, err := c.sock.queueSelector(c.assoc)
	if err != nil {
		if errors.Is(err, syscall.EINVAL) {
			err = syscall.ENOENT
		}
		return nil, c.callError("get", "getsockopt", err)
	}
	q, err := c.sock.queryQueues(s)
	if err != nil {
		return nil, c.callError("get", "sock_diag", err)
	}
	return q, nil
}

// AssocQueues reports association id's queues, with the module, privilege
// and monitoring costs described by Conn.AssocQueues. It selects the
// association by its own local and peer address lists, checks the owning
// socket's cookie, then checks that id still names an association with
// that peer address. An association that ended, was peeled off or was
// replaced during the call fails rather than returning another one's
// counters: EINVAL from an address query, ENOENT from a transport lookup,
// or ESTALE from the cookie or identity check. A reserved scope selector
// or negative id is refused as for LocalAddrs. Errors are *net.OpError
// with Op "get", and a closed Endpoint matches net.ErrClosed.
func (e *Endpoint) AssocQueues(id AssocID) (*AssocQueues, error) {
	if !e.opened() {
		return nil, e.optionError("get", net.ErrClosed)
	}
	if err := assocIDArg("AssocQueues", id); err != nil {
		return nil, e.argError("get", err)
	}
	s, err := e.sock.queueSelector(id)
	if err != nil {
		return nil, e.getError(err)
	}
	q, err := e.sock.queryQueues(s)
	if err != nil {
		return nil, optError("get", "sock_diag", e.network(), nil, e.Addr(), err)
	}
	peer, err := e.sock.getAddrs(optGetPeerAddrs, id)
	if err != nil {
		return nil, e.getError(err)
	}
	if peer.Port != s.peer.Port() || !slices.Contains(peer.IPs, s.peer.Addr()) {
		return nil, e.optionError("get", syscall.ESTALE)
	}
	return q, nil
}

// queueSelector reads the association's live addresses, preferring its
// primary peer path. A local address must have the same family: SCTP
// keeps IPv4 transports as AF_INET even on an AF_INET6 socket
// (net/sctp/diag.c: sctp_diag_dump_one).
func (s *socket) queueSelector(id AssocID) (diagSelector, error) {
	peer, err := s.getAddrs(optGetPeerAddrs, id)
	if err != nil {
		return diagSelector{}, err
	}
	local, err := s.getAddrs(optGetLocalAddrs, id)
	if err != nil {
		return diagSelector{}, err
	}
	var primary [sizePrim]byte
	binary.NativeEndian.PutUint32(primary[primAssocIDOff:], uint32(id))
	l := uint32(len(primary))
	if err := s.getsockopt(optPrimaryAddr, unsafe.Pointer(&primary[0]), &l); err != nil {
		return diagSelector{}, err
	}
	p, err := decodeAddr(primary[primAddrOff:])
	if err != nil {
		return diagSelector{}, err
	}
	// Primary first, followed by every other peer address. A multi-homed
	// association may contain both address families.
	ips := append([]netip.Addr{p.Addr()}, peer.IPs...)
	for _, rip := range ips {
		if !slices.Contains(peer.IPs, rip) {
			continue
		}
		for _, lip := range local.IPs {
			if lip.Unmap().Is4() != rip.Unmap().Is4() {
				continue
			}
			return diagSelector{local: netip.AddrPortFrom(lip, local.Port), peer: netip.AddrPortFrom(rip, peer.Port)}, nil
		}
	}
	return diagSelector{}, fmt.Errorf("sctp: sock_diag found no local and peer addresses of the same family")
}

func (s *socket) queryQueues(selector diagSelector) (*AssocQueues, error) {
	var result *AssocQueues
	// Keep the SCTP descriptor pinned across the cookie read and lookup.
	// Peel-off may still move the association: the cookie check detects it.
	err := s.control(func(fd int) error {
		var cookie [8]byte
		l := uint32(len(cookie))
		if err := rawGetsockopt(fd, syscall.SOL_SOCKET, optCookie, unsafe.Pointer(&cookie[0]), &l); err != nil {
			return err
		}
		if l != uint32(len(cookie)) {
			return fmt.Errorf("sctp: SO_COOKIE returned %d bytes, want 8", l)
		}
		selector.cookie = binary.NativeEndian.Uint64(cookie[:])
		var bound [4]byte
		l = uint32(len(bound))
		if err := rawGetsockopt(fd, syscall.SOL_SOCKET, optBindToIfindex, unsafe.Pointer(&bound[0]), &l); err != nil {
			return err
		}
		if l != uint32(len(bound)) {
			return fmt.Errorf("sctp: SO_BINDTOIFINDEX returned %d bytes, want 4", l)
		}
		selector.ifindex = binary.NativeEndian.Uint32(bound[:])
		nl, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_INET_DIAG)
		if err != nil {
			return os.NewSyscallError("socket", err)
		}
		defer func() { _ = syscall.Close(nl) }()
		result, err = queryDiag(selector, func(req []byte, probe bool) (*AssocQueues, error) {
			return exchangeDiag(nl, req, probe, selector.cookie)
		})
		return err
	})
	return result, err
}

func exchangeDiag(fd int, req []byte, probe bool, cookie uint64) (*AssocQueues, error) {
	if err := syscall.Sendto(fd, req, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, os.NewSyscallError("sendto", err)
	}
	for {
		// sctp_sock_dump_one queues its response synchronously, before
		// sendto returns. DONTWAIT turns an absent reply into an explicit
		// error. PEEK|TRUNC measures the full datagram, including large
		// INET_DIAG_LOCALS and INET_DIAG_PEERS address arrays.
		n, _, _, _, err := syscall.Recvmsg(fd, nil, nil, syscall.MSG_PEEK|syscall.MSG_TRUNC|syscall.MSG_DONTWAIT)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("sctp: sock_diag reply was not queued: %w", os.NewSyscallError("recvmsg", err))
		}
		if n < sizeNLMsgHeader {
			return nil, fmt.Errorf("sctp: sock_diag datagram has only %d bytes", n)
		}
		b := make([]byte, n)
		got, _, flags, from, err := syscall.Recvmsg(fd, b, nil, syscall.MSG_DONTWAIT)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return nil, os.NewSyscallError("recvmsg", err)
		}
		if got != n || flags&syscall.MSG_TRUNC != 0 {
			return nil, fmt.Errorf("sctp: sock_diag datagram was truncated (%d of %d bytes, flags %#x)", got, n, flags)
		}
		if sender, ok := from.(*syscall.SockaddrNetlink); !ok || sender.Pid != 0 {
			return nil, fmt.Errorf("sctp: sock_diag reply did not come from the kernel")
		}
		q, done, err := parseDiagReply(b, binary.NativeEndian.Uint32(req[8:]), cookie, probe)
		if err != nil {
			return nil, err
		}
		if done {
			return q, nil
		}
	}
}
