// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// unsupported.go stubs the package's socket-backed entry points on any
// GOOS other than linux, which this package does not support: the raw
// syscalls and SCTP socket options syscall_linux_other.go and
// syscall_linux_386.go use are Linux-specific, but that is a statement
// about this package's own implementation, not about SCTP or these
// syscalls more broadly — FreeBSD and illumos, among others, have their
// own SCTP stacks this package simply does not target. Every stubbed
// entry point returns ErrUnsupported (errors.go) instead of attempting a
// call the platform cannot honour, so code written against this package
// compiles and fails predictably on every platform, rather than only on
// Linux.
//
// unsupportedStubCases, in unsupported_test.go, lists one case per function
// or method declared in this file, and TestUnsupportedStubManifestIsComplete
// parses this file and requires the two lists to match by name exactly, so
// a stub can never be added here without also being exercised and checked
// against ErrUnsupported by TestUnsupportedEntryPointsReportTheSentinel.
// That check runs against this file's source, not against a fixed list, so
// it stays correct as this file grows.
//
// Addresses, notifications and enumerations are portable and carry no build
// tag. Value-only accessors (LocalAddr, RemoteAddr, Listener.Addr,
// AssocID) return their zero value here, since no Conn or Listener can
// exist on these platforms to hold anything else; every other stub returns
// ErrUnsupported. None of them is carried over from v1's
// sctp_unsupported.go (git show main:sctp_unsupported.go): the API they
// stand in for is new.

package sctp

import (
	"context"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// sendState is a Conn's send storage. On Linux it holds a syscall.Msghdr,
// which not every platform defines; with no send path here, it is empty.
type sendState struct{}

// recvState is a Conn's receive storage, empty here for the same reason.
type recvState struct{}

// Dial reports ErrUnsupported: SCTP sockets exist only on Linux.
func Dial(context.Context, string, *Addr, *Addr) (*Conn, error) { return nil, ErrUnsupported }

// Dial reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Config) Dial(context.Context, string, *Addr, *Addr) (*Conn, error) {
	return nil, ErrUnsupported
}

// Listen reports ErrUnsupported: SCTP sockets exist only on Linux.
func Listen(string, *Addr) (*Listener, error) { return nil, ErrUnsupported }

// Listen reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Config) Listen(string, *Addr) (*Listener, error) { return nil, ErrUnsupported }

// FileConn reports ErrUnsupported: SCTP sockets exist only on Linux.
func FileConn(*os.File) (*Conn, error) { return nil, ErrUnsupported }

// FileConn reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Config) FileConn(*os.File) (*Conn, error) { return nil, ErrUnsupported }

// FileListener reports ErrUnsupported: SCTP sockets exist only on Linux.
func FileListener(*os.File) (*Listener, error) { return nil, ErrUnsupported }

// FileListener reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Config) FileListener(*os.File) (*Listener, error) { return nil, ErrUnsupported }

// InstallAuthKey reports ErrUnsupported: SCTP sockets exist only on Linux.
func InstallAuthKey(syscall.RawConn, uint16, []byte) error { return ErrUnsupported }

// ActivateAuthKey reports ErrUnsupported: SCTP sockets exist only on Linux.
func ActivateAuthKey(syscall.RawConn, uint16) error { return ErrUnsupported }

// AcceptSCTP reports ErrUnsupported: SCTP sockets exist only on Linux.
func (l *Listener) AcceptSCTP() (*Conn, error) { return nil, ErrUnsupported }

// Addr returns nil: no Listener is ever bound here.
func (l *Listener) Addr() net.Addr { return nil }

// Close reports ErrUnsupported: SCTP sockets exist only on Linux.
func (l *Listener) Close() error { return ErrUnsupported }

// SetDeadline reports ErrUnsupported: SCTP sockets exist only on Linux.
func (l *Listener) SetDeadline(time.Time) error { return ErrUnsupported }

// BindAdd reports ErrUnsupported: SCTP sockets exist only on Linux.
func (l *Listener) BindAdd(...netip.Addr) error { return ErrUnsupported }

// BindRemove reports ErrUnsupported: SCTP sockets exist only on Linux.
func (l *Listener) BindRemove(...netip.Addr) error { return ErrUnsupported }

// SyscallConn reports ErrUnsupported: SCTP sockets exist only on Linux.
func (l *Listener) SyscallConn() (syscall.RawConn, error) { return nil, ErrUnsupported }

// AssocID returns 0: no association exists here.
func (c *Conn) AssocID() AssocID { return 0 }

// LocalAddr returns nil: no Conn is ever connected here.
func (c *Conn) LocalAddr() net.Addr { return nil }

// RemoteAddr returns nil: no Conn is ever connected here.
func (c *Conn) RemoteAddr() net.Addr { return nil }

// LocalAddrs reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) LocalAddrs() (*Addr, error) { return nil, ErrUnsupported }

// PeerAddrs reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) PeerAddrs() (*Addr, error) { return nil, ErrUnsupported }

// BindAdd reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) BindAdd(...netip.Addr) error { return ErrUnsupported }

// BindRemove reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) BindRemove(...netip.Addr) error { return ErrUnsupported }

// SetDeadline reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetDeadline(time.Time) error { return ErrUnsupported }

// SetReadDeadline reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetReadDeadline(time.Time) error { return ErrUnsupported }

// SetWriteDeadline reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetWriteDeadline(time.Time) error { return ErrUnsupported }

// SyscallConn reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SyscallConn() (syscall.RawConn, error) { return nil, ErrUnsupported }

// Close reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) Close() error { return ErrUnsupported }

// CloseWithTimeout reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) CloseWithTimeout(time.Duration) error { return ErrUnsupported }

// Shutdown reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) Shutdown() error { return ErrUnsupported }

// Abort reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) Abort() error { return ErrUnsupported }
