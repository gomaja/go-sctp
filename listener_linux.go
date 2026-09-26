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
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Listen opens a one-to-one SCTP socket bound to laddr and listening for
// associations, with a zero Config. See Config.Listen.
func Listen(network string, laddr *Addr) (*Listener, error) {
	return (*Config)(nil).Listen(network, laddr)
}

// Listen opens a one-to-one SCTP socket, applies c, binds it to laddr and
// puts it in listening state. network is "sctp", "sctp4" or "sctp6". A nil
// laddr, or one with no IPs, is the wildcard address: with a port of 0 the
// kernel chooses one, and with "sctp" the socket is AF_INET6 dual-stack, so
// that it listens on the host's IPv4 and IPv6 addresses alike. Several IPs
// make a multi-homed endpoint, bound atomically (RFC 6458 §9.1).
//
// The backlog is the kernel's own maximum, net.core.somaxconn, read at
// each Listen, rather than syscall.SOMAXCONN: the Go constant is 128,
// while Linux has defaulted to 4096 since 5.4, and a listener handed more
// INITs than its backlog answers the excess with an ABORT, so the peer
// sees its setup refused by a listener that is healthy.
//
// Errors are *net.OpError with Op "listen".
func (c *Config) Listen(network string, laddr *Addr) (*Listener, error) {
	l, err := c.listen(network, laddr)
	if err != nil {
		return nil, opError("listen", canonicalName(network), nil, netAddr(laddr), err)
	}
	return l, nil
}

func (c *Config) listen(network string, laddr *Addr) (*Listener, error) {
	family, err := socketFamily(network, laddr, nil)
	if err != nil {
		return nil, err
	}
	p, err := c.prepare(styleListen)
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

	s, err := newSocket(family, canonicalName(network))
	if err != nil {
		return nil, err
	}
	var control func(string, string, syscall.RawConn) error
	if c != nil {
		control = c.Control
	}
	if err := setupListener(&s, address, control, p.ops, bind); err != nil {
		// No association exists yet, so a plain release is all there is.
		_ = s.file.Close()
		return nil, err
	}
	return newListener(s, p), nil
}

// setupListener configures, binds and listens on a new socket.
func setupListener(s *socket, address string, control func(string, string, syscall.RawConn) error, ops []configOp, bind []byte) error {
	if err := setupSocket(s, address, control, ops); err != nil {
		return err
	}
	if bind != nil {
		if err := s.bindx(optSockoptBindxAdd, bind); err != nil {
			return os.NewSyscallError("sctp_bindx", err)
		}
	}
	backlog := syscall.SOMAXCONN
	if n, err := readSomaxconn(); err == nil && n > backlog {
		// The kernel clamps a larger value to its own maximum
		// (net/sctp/socket.c: sctp_inet_listen), so asking for exactly
		// that is safe.
		backlog = n
	}
	if err := s.control(func(fd int) error { return syscall.Listen(fd, backlog) }); err != nil {
		return os.NewSyscallError("listen", err)
	}
	return nil
}

// readSomaxconn reads net.core.somaxconn, the largest accept backlog the
// kernel grants.
func readSomaxconn() (int, error) {
	b, err := os.ReadFile("/proc/sys/net/core/somaxconn")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

// newListener builds a Listener around s, a listening socket this package
// owns, and takes the Addr snapshot.
func newListener(s socket, p *prepared) *Listener {
	l := &Listener{sock: s, prep: p}
	l.refreshAddr()
	return l
}

// refreshAddr replaces the Addr snapshot with the endpoint's bound
// addresses, SCTP_GET_LOCAL_ADDRS for association id 0 (RFC 6458 §9.5),
// which for a wildcard bind lists every address in the namespace. A list
// that cannot be read leaves the snapshot as it was, or, on the first read,
// empty.
func (l *Listener) refreshAddr() {
	if a, err := l.sock.getAddrs(optGetLocalAddrs, 0); err == nil {
		l.addr.Store(a)
	} else if l.addr.Load() == nil {
		l.addr.Store(&Addr{})
	}
}

// network is the network name l's errors carry.
func (l *Listener) network() string {
	if l == nil || l.sock.network == "" {
		return "sctp"
	}
	return l.sock.network
}

// Accept waits for the next association and returns it as a net.Conn: the
// *Conn AcceptSCTP returns, and never a non-nil net.Conn holding a nil
// *Conn. Errors are *net.OpError with Op "accept".
func (l *Listener) Accept() (net.Conn, error) {
	c, err := l.AcceptSCTP()
	if err != nil {
		return nil, err
	}
	return c, nil
}

// AcceptSCTP waits for the next association and returns it as a *Conn,
// as net.TCPListener.AcceptTCP does. The accepted socket is created
// non-blocking and close-on-exec (accept4 with SOCK_NONBLOCK and
// SOCK_CLOEXEC), and the Conn uses the NotificationHandler and
// CloseTimeout of the Config that created the listener. The wait follows
// the listener's deadline and ends when the listener is closed. Errors are
// *net.OpError with Op "accept".
func (l *Listener) AcceptSCTP() (*Conn, error) {
	c, err := l.accept()
	if err != nil {
		return nil, opError("accept", l.network(), nil, l.Addr(), err)
	}
	return c, nil
}

func (l *Listener) accept() (*Conn, error) {
	if l == nil || l.sock.raw == nil {
		return nil, net.ErrClosed
	}
	nfd := -1
	var aerr error
	if err := l.sock.raw.Read(func(fd uintptr) bool {
		for {
			nfd, _, aerr = syscall.Accept4(int(fd), syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC)
			switch aerr {
			case syscall.EINTR:
				continue
			case syscall.EAGAIN:
				// A listening socket is readable once an association
				// waits to be accepted (net/sctp/socket.c: sctp_poll).
				return false
			default:
				return true
			}
		}
	}); err != nil {
		return nil, err
	}
	if aerr != nil {
		return nil, os.NewSyscallError("accept4", aerr)
	}
	s, err := wrapSocketFile(nfd, l.sock.family, l.sock.network)
	if err != nil {
		return nil, err
	}
	return newConn(s, kindAccepted, l.prep)
}

// Addr returns an *Addr holding every address the listener is bound to: a
// snapshot, taken when it starts listening and replaced as a whole after a
// successful BindAdd or BindRemove. For a wildcard bind it lists every
// address in the network namespace. Each call returns a copy of its own,
// which the caller may keep and change. It stays readable after Close.
func (l *Listener) Addr() net.Addr {
	if l == nil {
		return nil
	}
	return netAddr(l.addr.Load())
}

// Close stops listening and releases the descriptor. An Accept waiting in
// another goroutine returns an error matching net.ErrClosed, and so does a
// second Close. Associations the kernel had queued but not yet handed to
// Accept are ended by the kernel (net/sctp/socket.c: sctp_close).
func (l *Listener) Close() error {
	if l == nil || l.sock.file == nil {
		return opError("close", l.network(), nil, nil, net.ErrClosed)
	}
	if err := l.sock.file.Close(); err != nil {
		return opError("close", l.network(), nil, l.Addr(), err)
	}
	return nil
}

// SetDeadline sets the deadline for Accept and AcceptSCTP: a call waiting
// when it passes returns an error wrapping os.ErrDeadlineExceeded, and a
// zero t means no deadline. The listener stays usable afterwards.
func (l *Listener) SetDeadline(t time.Time) error {
	if l == nil || l.sock.file == nil {
		return opError("set", l.network(), nil, nil, net.ErrClosed)
	}
	if err := l.sock.file.SetDeadline(t); err != nil {
		return opError("set", l.network(), nil, l.Addr(), err)
	}
	return nil
}

// BindAdd adds ips to the listening endpoint (RFC 6458 §9.1, sctp_bindx
// with SCTP_BINDX_ADD_ADDR), on the port it is bound to; associations
// accepted afterwards can use them. The Addr snapshot is refreshed
// afterwards. A zero netip.Addr, an empty list, or an address the socket's
// family cannot carry is refused with an error matching syscall.EINVAL
// before any system call.
func (l *Listener) BindAdd(ips ...netip.Addr) error {
	return l.bindx(optSockoptBindxAdd, "BindAdd", ips)
}

// BindRemove removes ips from the listening endpoint (RFC 6458 §9.1,
// sctp_bindx with SCTP_BINDX_REM_ADDR), so that associations accepted
// afterwards no longer use them. RFC 6458 §9.1 forbids removing every
// local address, and a list that would is refused with an error matching
// syscall.EINVAL (Linux itself answers EBUSY: net/sctp/socket.c,
// sctp_bindx_rem); so is a list naming the unspecified address.
func (l *Listener) BindRemove(ips ...netip.Addr) error {
	return l.bindx(optSockoptBindxRemove, "BindRemove", ips)
}

func (l *Listener) bindx(opt int, name string, ips []netip.Addr) error {
	if l == nil || l.sock.raw == nil {
		return opError("bindx", l.network(), nil, nil, net.ErrClosed)
	}
	buf, err := bindxAddrs(l.sock.family, name, ips)
	if err != nil {
		return opError("bindx", l.network(), nil, l.Addr(), err)
	}

	l.bindMu.Lock()
	defer l.bindMu.Unlock()
	if opt == optSockoptBindxRemove {
		if bound, err := l.sock.getAddrs(optGetLocalAddrs, 0); err == nil && removesEveryAddress(bound.IPs, ips) {
			return opError("bindx", l.network(), nil, l.Addr(), invalidArg("%s would remove every local address, which RFC 6458 §9.1 forbids", name))
		}
	}
	if err := l.sock.bindx(opt, buf); err != nil {
		return optError("bindx", "setsockopt", l.network(), nil, l.Addr(), err)
	}
	l.refreshAddr()
	return nil
}

// SyscallConn returns raw access to the listening descriptor. As with the
// standard library's listeners (net/rawconn.go), only Control is
// supported: Read and Write return syscall.EINVAL. Once the listener is
// closed, Control returns an error matching net.ErrClosed without running
// the callback.
func (l *Listener) SyscallConn() (syscall.RawConn, error) {
	if l == nil || l.sock.raw == nil {
		return nil, opError("syscallconn", l.network(), nil, nil, net.ErrClosed)
	}
	return &listenerRawConn{l: l}, nil
}

// listenerRawConn is the syscall.RawConn Listener.SyscallConn returns.
type listenerRawConn struct{ l *Listener }

func (r *listenerRawConn) Control(f func(fd uintptr)) error {
	if err := r.l.sock.raw.Control(f); err != nil {
		return opError("raw-control", r.l.network(), nil, r.l.Addr(), err)
	}
	return nil
}

func (r *listenerRawConn) Read(func(fd uintptr) bool) error  { return syscall.EINVAL }
func (r *listenerRawConn) Write(func(fd uintptr) bool) error { return syscall.EINVAL }

// FileListener returns a Listener for the listening SCTP socket f holds,
// with a zero Config. See Config.FileListener.
func FileListener(f *os.File) (*Listener, error) {
	return (*Config)(nil).FileListener(f)
}

// FileListener adopts an inherited listening descriptor (socket
// activation, descriptor passing). The file is duplicated, close-on-exec,
// and the caller keeps ownership of f; the duplicate is put in
// non-blocking mode, which the two share.
//
// Before adopting it, FileListener checks the descriptor: SO_PROTOCOL must
// be IPPROTO_SCTP, SO_TYPE must be SOCK_STREAM (one-to-one), and
// SO_ACCEPTCONN must say that it is listening. Anything else is refused
// with an error matching syscall.EINVAL, and a descriptor that is not a
// socket at all fails with the kernel's syscall.ENOTSOCK. Every error is a
// *net.OpError with Op "file".
//
// Only the package-side fields of the Config apply, NotificationHandler
// and CloseTimeout, as for Config.FileConn. The package enables
// SCTP_RECVRCVINFO and its own SCTP_ASSOC_CHANGE subscription on the
// listener, and again on every accepted socket, which also covers the
// associations already queued when the listener was adopted.
func (c *Config) FileListener(f *os.File) (*Listener, error) {
	l, err := c.fileListener(f)
	if err != nil {
		return nil, opError("file", "sctp", nil, nil, err)
	}
	return l, nil
}

func (c *Config) fileListener(f *os.File) (*Listener, error) {
	p, err := c.prepare(styleFile)
	if err != nil {
		return nil, err
	}
	s, err := adoptFile(f, true)
	if err != nil {
		return nil, err
	}
	if err := applyConfig(&s, p.ops); err != nil {
		_ = s.file.Close()
		return nil, err
	}
	return newListener(s, p), nil
}
