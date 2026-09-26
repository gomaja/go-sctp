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

// socket_linux.go owns descriptors: it creates every SCTP socket the
// package opens, wraps it in an *os.File, and runs every later system call
// on it inside a syscall.RawConn callback.
//
// One close per descriptor. A descriptor is closed exactly once: by its
// *os.File once it is wrapped, and by a raw close(2) only before that, on
// the one path that has not wrapped it yet. A raw close after wrapping
// would land on whatever the kernel had since reused the number for:
// georgeyanev/go-sctp PR #7 (merged 2026-09-04) fixed exactly that, a
// failed dial whose second, raw close took down an unrelated descriptor.
// The *os.File also pins the descriptor: raw.Control, raw.Read and
// raw.Write hold a reference for the whole callback (internal/poll: FD
// incref), and Close releases the number only once the last callback has
// returned, so no system call here can ever reach a reused number.

package sctp

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"sync"
	"syscall"
	"unsafe"
)

// newSocket creates a one-to-one SCTP socket (SOCK_STREAM, RFC 6458 §4) of
// family and wraps it. SOCK_NONBLOCK hands every wait to the runtime
// poller, and SOCK_CLOEXEC keeps the descriptor out of any child a
// concurrent fork starts: both are set atomically by socket(2), so there
// is no window between creating the descriptor and marking it.
//
// When the kernel has no SCTP, inet_create (net/ipv4/af_inet.c) answers
// EPROTONOSUPPORT, or ESOCKTNOSUPPORT, once it cannot load the module;
// that becomes unsupportedErr, which matches both ErrUnsupported and the
// errno.
func newSocket(family int, network string) (socket, error) {
	fd, err := syscall.Socket(family, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, ipprotoSCTP)
	if err != nil {
		return socket{}, socketError(err)
	}
	return wrapSocketFile(fd, family, network)
}

// socketError is the error newSocket reports for a failed socket(2).
func socketError(err error) error {
	var errno syscall.Errno
	if errors.As(err, &errno) && (errno == syscall.EPROTONOSUPPORT || errno == syscall.ESOCKTNOSUPPORT) {
		return unsupportedErr{errno: errno}
	}
	return os.NewSyscallError("socket", err)
}

// wrapSocketFile hands fd to an *os.File, which from then on is the only
// thing that closes it. fd must already be non-blocking: os.NewFile
// registers a non-blocking descriptor with the runtime poller (os/
// file_unix.go: newFile), which is what lets every wait on it be a poller
// wait that a deadline or Close can end. A descriptor that os.NewFile
// refuses is closed here, raw, since nothing else owns it yet.
func wrapSocketFile(fd, family int, network string) (socket, error) {
	f := os.NewFile(uintptr(fd), "sctp")
	if f == nil {
		// Only a negative fd is refused, and there is nothing to close.
		return socket{}, os.NewSyscallError("socket", syscall.EBADF)
	}
	raw, err := f.SyscallConn()
	if err != nil {
		_ = f.Close()
		return socket{}, err
	}
	return socket{file: f, raw: raw, family: family, network: network}, nil
}

// control runs fn with the descriptor inside raw.Control, which keeps the
// descriptor open for the whole call. It returns fn's error unchanged. The
// only way raw.Control itself fails is the descriptor having been released
// (internal/poll: FD.RawControl), which is reported as net.ErrClosed.
func (s *socket) control(fn func(fd int) error) error {
	var ferr error
	if err := s.raw.Control(func(fd uintptr) { ferr = fn(int(fd)) }); err != nil {
		return net.ErrClosed
	}
	return ferr
}

// getsockopt reads SCTP option opt (level IPPROTO_SCTP) into the l bytes
// at p, and sets l to the length the kernel reports. The error is the
// bare errno, or net.ErrClosed.
func (s *socket) getsockopt(opt int, p unsafe.Pointer, l *uint32) error {
	return s.control(func(fd int) error { return rawGetsockopt(fd, ipprotoSCTP, opt, p, l) })
}

// setsockopt writes the l bytes at p to SCTP option opt (level
// IPPROTO_SCTP). The error is the bare errno, or net.ErrClosed.
func (s *socket) setsockopt(opt int, p unsafe.Pointer, l uintptr) error {
	return s.control(func(fd int) error { return rawSetsockopt(fd, ipprotoSCTP, opt, p, l) })
}

// maxAddrsBuf bounds the buffer an address-list query may grow to. Linux
// answers ENOMEM when the list does not fit (net/sctp/socket.c:
// sctp_getsockopt_local_addrs, sctp_getsockopt_peer_addrs,
// sctp_copy_laddrs), and the query is retried with a larger buffer up to
// this size: 256 KiB holds more than 9000 IPv6 entries, far beyond any
// real interface list, while keeping the kernel's own allocation for the
// reply (a kmalloc of the whole buffer) bounded.
const maxAddrsBuf = 256 << 10

// getAddrs reads an address list with SCTP_GET_LOCAL_ADDRS or
// SCTP_GET_PEER_ADDRS (RFC 6458 §§9.3, 9.5) for association assoc. For the
// local list, assoc 0 asks for the endpoint's bound addresses (a wildcard
// bind expanded into every address in the namespace) and any other id for
// the association's own list (asoc->base.bind_addr); on a one-to-one socket
// the kernel ignores the value of a non-zero id and answers for the socket's
// one association (sctp_id2assoc).
//
// The reply is decoded from the buffer and the count the kernel wrote, never
// from the length it reports: SCTP_GET_LOCAL_ADDRS reports the length of
// the address array without the 8-byte struct sctp_getaddrs header (the
// "XXX" comment in sctp_getsockopt_local_addrs), while SCTP_GET_PEER_ADDRS
// includes it (sctp_getsockopt_peer_addrs), and decodeAddrs rejects a count
// the buffer cannot hold before it allocates.
func (s *socket) getAddrs(opt int, assoc AssocID) (*Addr, error) {
	for size := 4096; ; size *= 4 {
		buf := make([]byte, size)
		binary.NativeEndian.PutUint32(buf[getAddrsAssocIDOff:], uint32(assoc))
		l := uint32(size)
		err := s.getsockopt(opt, unsafe.Pointer(&buf[0]), &l)
		if errors.Is(err, syscall.ENOMEM) && size*4 <= maxAddrsBuf {
			continue
		}
		if err != nil {
			return nil, err
		}
		n := int(int32(binary.NativeEndian.Uint32(buf[getAddrsAddrNumOff:])))
		ips, port, err := decodeAddrs(buf[getAddrsAddrsOff:], n)
		if err != nil {
			return nil, err
		}
		return &Addr{IPs: ips, Port: port}, nil
	}
}

// status reads SCTP_STATUS (RFC 6458 §8.2.1) and returns the association
// id and state it reports. On a one-to-one or peeled socket the kernel
// answers for the socket's one association while the socket is
// ESTABLISHED or CLOSING, and fails with EINVAL when it has none
// (net/sctp/socket.c: sctp_getsockopt_sctp_status, sctp_id2assoc).
//
// One association is reported with state StateClosed: one that ended
// while it waited to be accepted, which Linux keeps on the socket so that
// accept(2) can hand it over (net/sctp/sm_sideeffect.c:
// sctp_cmd_delete_tcb). The accepted socket starts out CLOSED, and
// SCTP_STATUS fails, but a shutdown(2) on it still finds that association
// on the socket's list and moves the socket to CLOSING (sctp_shutdown),
// after which the query answers for it. It has ended all the same.
func (s *socket) status() (AssocID, AssocState, error) {
	var buf [sizeStatus]byte
	l := uint32(len(buf))
	if err := s.getsockopt(optStatus, unsafe.Pointer(&buf[0]), &l); err != nil {
		return 0, 0, err
	}
	id := AssocID(int32(binary.NativeEndian.Uint32(buf[statusAssocIDOff:])))
	state := AssocState(int32(binary.NativeEndian.Uint32(buf[statusStateOff:])))
	return id, state, nil
}

// bindx adds (optSockoptBindxAdd) or removes (optSockoptBindxRemove) the
// packed sockaddr array addrs, RFC 6458 §9.1's sctp_bindx. Linux binds each
// entry with sctp_do_bind, the same function bind(2) reaches, so one entry
// is exactly a bind(2) and several are one atomic operation that succeeds
// or fails as a whole (net/sctp/socket.c: sctp_setsockopt_bindx,
// sctp_bindx_add, sctp_bindx_rem).
func (s *socket) bindx(opt int, addrs []byte) error {
	return s.setsockopt(opt, unsafe.Pointer(&addrs[0]), uintptr(len(addrs)))
}

// setupRawConn is the syscall.RawConn Config.Control receives: the socket
// exists but is neither connected nor listening yet. Control reaches the
// descriptor; Read and Write return syscall.EINVAL, as a listener's RawConn
// does in the standard library (net/rawconn.go), since nothing can be read
// from or written to the socket at that point.
type setupRawConn struct{ raw syscall.RawConn }

func (r setupRawConn) Control(f func(fd uintptr)) error  { return r.raw.Control(f) }
func (r setupRawConn) Read(func(fd uintptr) bool) error  { return syscall.EINVAL }
func (r setupRawConn) Write(func(fd uintptr) bool) error { return syscall.EINVAL }

// setupSocket runs the part of opening a socket that every constructor
// shares, in the order Config documents: the dual-stack switch, then
// Control, then the typed settings.
//
// An AF_INET6 socket has IPV6_V6ONLY cleared before Control runs, so that
// "sctp" and "sctp6" sockets carry IPv4 peers (as IPv4-mapped addresses)
// whatever net.ipv6.bindv6only says: the kernel starts an AF_INET6 socket
// with sk_ipv6only taken from that sysctl (net/ipv6/af_inet6.c:
// inet6_create), and SCTP honours it (net/sctp/ipv6.c: sctp_v6_available,
// sctp_inet6_af_supported). The option is never set, only cleared; a
// Control that wants an IPv6-only socket sets it itself, afterwards.
func setupSocket(s *socket, address string, control func(network, address string, c syscall.RawConn) error, ops []configOp) error {
	if s.family == afInet6 {
		if err := s.control(func(fd int) error {
			return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
		}); err != nil {
			return os.NewSyscallError("setsockopt", err)
		}
	}
	if control != nil {
		if err := control(s.network, address, setupRawConn{raw: s.raw}); err != nil {
			return err
		}
	}
	return applyConfig(s, ops)
}

// ipv6Unavailable reports whether this kernel refuses AF_INET6 sockets
// (booted with ipv6.disable=1, or built without IPv6): socket(2) then
// answers EAFNOSUPPORT. It is asked once, the first time a wildcard "sctp"
// socket needs a family.
var ipv6Unavailable = sync.OnceValue(func() bool {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, ipprotoSCTP)
	if err != nil {
		return errors.Is(err, syscall.EAFNOSUPPORT)
	}
	_ = syscall.Close(fd) // a probe descriptor, never wrapped
	return false
})

// isWildcard reports whether a names no specific local address: nil, no
// IPs, or a single unspecified address (0.0.0.0 or ::).
func isWildcard(a *Addr) bool {
	return a == nil || len(a.IPs) == 0 || (len(a.IPs) == 1 && a.IPs[0].IsUnspecified())
}

// socketFamily validates network and every address given, and chooses the
// family of the socket to create. "sctp4" is AF_INET and "sctp6" AF_INET6,
// whose sockets also carry IPv4 addresses in mapped form. "sctp" (and "")
// with a wildcard local address is AF_INET6 dual-stack, so that the
// wildcard covers the host's IPv4 and IPv6 addresses alike and a
// multi-homed peer's addresses of both families can join the association
// (an AF_INET socket ignores the IPv6 addresses a peer lists in its INIT or
// INIT ACK: net/sctp/sm_make_chunk.c, sctp_process_param); it falls back to
// AF_INET on a kernel without IPv6. Otherwise "sctp" takes the family the
// addresses need: AF_INET6 as soon as one is not IPv4.
func socketFamily(network string, laddr, raddr *Addr) (int, error) {
	var ips []netip.Addr
	if laddr != nil {
		ips = append(ips, laddr.IPs...)
	}
	if raddr != nil {
		ips = append(ips, raddr.IPs...)
	}
	family, err := canonicalNetwork(network, ips)
	if err != nil {
		return 0, err
	}
	if (network == "" || network == "sctp") && isWildcard(laddr) && !ipv6Unavailable() {
		return afInet6, nil
	}
	return family, nil
}

// canonicalName is network with "" spelled "sctp": the name a socket and
// every error it produces carry.
func canonicalName(network string) string {
	if network == "" {
		return "sctp"
	}
	return network
}

// localBindAddrs packs laddr for sctp_bindx on a socket of family. A
// wildcard laddr (no IPs) binds the family's unspecified address, so that
// the port it names is kept.
func localBindAddrs(family int, laddr *Addr) ([]byte, error) {
	if len(laddr.IPs) != 0 {
		return encodeAddrs(family, laddr.IPs, laddr.Port)
	}
	wild := netip.IPv4Unspecified()
	if family == afInet6 {
		wild = netip.IPv6Unspecified()
	}
	return encodeAddrs(family, []netip.Addr{wild}, laddr.Port)
}

// netAddr turns a possibly nil *Addr into a net.Addr that is nil when a is,
// so that a *net.OpError built from it never carries a non-nil interface
// holding a nil pointer. Otherwise it returns a copy of a with IPs of its
// own: the caller may keep and change what it gets, and neither the
// snapshot a Conn or Listener holds nor an address a caller passed in
// changes with it.
func netAddr(a *Addr) net.Addr {
	if a == nil {
		return nil
	}
	return &Addr{IPs: slices.Clone(a.IPs), Port: a.Port}
}

// adoptFile duplicates the descriptor f holds, close-on-exec, checks that
// it is a one-to-one SCTP socket that is listening (listening true) or
// holds an established association (listening false), puts the
// duplicate in non-blocking mode and wraps it. The caller keeps f.
//
// The duplicate is made inside f's own raw.Control, which keeps f's
// descriptor open for the call even if the caller closes f concurrently.
// A closed f has no descriptor to duplicate, and reports EBADF, as a dup of
// a closed descriptor does. The checks run on the duplicate before it is
// wrapped, so a refused descriptor is closed with close(2), the one raw
// close it gets, and never reaches the runtime poller.
func adoptFile(f *os.File, listening bool) (socket, error) {
	if f == nil {
		return socket{}, invalidArg("the *os.File is nil")
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return socket{}, os.NewSyscallError("fcntl", syscall.EBADF)
	}
	fd := -1
	var derr error
	if err := raw.Control(func(ffd uintptr) {
		// F_DUPFD_CLOEXEC marks the duplicate close-on-exec atomically.
		r, _, errno := syscall.Syscall(syscall.SYS_FCNTL, ffd, syscall.F_DUPFD_CLOEXEC, 0)
		if errno != 0 {
			derr = errno
			return
		}
		fd = int(r)
	}); err != nil {
		return socket{}, os.NewSyscallError("fcntl", syscall.EBADF)
	}
	if derr != nil {
		return socket{}, os.NewSyscallError("fcntl", derr)
	}

	family, err := checkAdoptable(fd, listening)
	if err == nil {
		if nerr := syscall.SetNonblock(fd, true); nerr != nil {
			err = os.NewSyscallError("fcntl", nerr)
		}
	}
	if err != nil {
		_ = syscall.Close(fd)
		return socket{}, err
	}
	return wrapSocketFile(fd, family, "sctp")
}

// checkAdoptable checks, with getsockopt, that fd is a socket FileConn or
// FileListener can adopt, and returns its address family. SO_PROTOCOL must
// be IPPROTO_SCTP and SO_TYPE SOCK_STREAM (RFC 6458 §4: one-to-one; a
// one-to-many socket, and one peeled off it, is SOCK_SEQPACKET:
// net/sctp/socket.c, sctp_do_peeloff). A listener must have SO_ACCEPTCONN
// set (net/core/sock.c: sk_getsockopt reports sk_state == TCP_LISTEN, which
// is SCTP_SS_LISTENING), and a connection must have an established
// association, which SCTP_STATUS finds (sctp_id2assoc). A refusal matches
// syscall.EINVAL; a descriptor that is not a socket fails the first
// getsockopt with the kernel's ENOTSOCK.
func checkAdoptable(fd int, listening bool) (int, error) {
	proto, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_PROTOCOL)
	if err != nil {
		return 0, os.NewSyscallError("getsockopt", err)
	}
	if proto != ipprotoSCTP {
		return 0, invalidArg("the descriptor is not an SCTP socket (SO_PROTOCOL %d, not IPPROTO_SCTP)", proto)
	}
	typ, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return 0, os.NewSyscallError("getsockopt", err)
	}
	if typ != syscall.SOCK_STREAM {
		return 0, invalidArg("the descriptor is not a one-to-one SCTP socket (SO_TYPE %d, not SOCK_STREAM)", typ)
	}
	family, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_DOMAIN)
	if err != nil {
		return 0, os.NewSyscallError("getsockopt", err)
	}
	if listening {
		acc, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ACCEPTCONN)
		if err != nil {
			return 0, os.NewSyscallError("getsockopt", err)
		}
		if acc == 0 {
			return 0, invalidArg("the descriptor is not a listening socket (SO_ACCEPTCONN is 0)")
		}
		return family, nil
	}
	var st [sizeStatus]byte
	l := uint32(len(st))
	switch err := rawGetsockopt(fd, ipprotoSCTP, optStatus, unsafe.Pointer(&st[0]), &l); {
	case err == nil && AssocState(int32(binary.NativeEndian.Uint32(st[statusStateOff:]))) != StateClosed:
		return family, nil
	case err == nil, errors.Is(err, syscall.EINVAL):
		return 0, invalidArg("the descriptor holds no established association (SCTP_STATUS finds none)")
	default:
		return 0, os.NewSyscallError("getsockopt", err)
	}
}
