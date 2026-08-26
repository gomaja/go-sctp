//go:build linux
// +build linux

// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func TestDialErrorCarriesOperationAndAddresses(t *testing.T) {
	cause := errors.New("control failed")
	local := &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, Port: 0}
	remote := &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 2)}}, Port: 2905}
	wantLocal := cloneSCTPAddr(local)
	wantRemote := cloneSCTPAddr(remote)
	cfg := SocketConfig{Control: func(string, string, syscall.RawConn) error {
		return cause
	}}

	conn, err := cfg.Dial("sctp4", local, remote)
	if conn != nil {
		_ = conn.Abort()
		t.Fatal("Dial returned a connection with a failing Control hook")
	}
	opErr := requireSCTPOpError(t, err, "dial", "sctp4", wantLocal, wantRemote, cause)

	local.Port = 1
	local.IPAddrs[0].IP[len(local.IPAddrs[0].IP)-4] = 10
	remote.Port = 1
	remote.IPAddrs[0].IP[len(remote.IPAddrs[0].IP)-4] = 10
	if got := opErr.Source; !sctpAddrEqual(got, wantLocal) {
		t.Errorf("Source changed after caller mutation: got %#v, want %#v", got, wantLocal)
	}
	if got := opErr.Addr; !sctpAddrEqual(got, wantRemote) {
		t.Errorf("Addr changed after caller mutation: got %#v, want %#v", got, wantRemote)
	}
}

func TestDialWrapsForeignOperationError(t *testing.T) {
	root := errors.New("control failed")
	cause := &net.OpError{Op: "control", Net: "tcp", Err: root}
	remote := &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 2)}}, Port: 2905}
	cfg := SocketConfig{Control: func(string, string, syscall.RawConn) error {
		return cause
	}}

	_, err := cfg.Dial("sctp4", nil, remote)
	_ = requireSCTPOpError(t, err, "dial", "sctp4", nil, remote, root)
}

func TestDialPreservesMatchingOperationError(t *testing.T) {
	root := errors.New("control failed")
	callbackErr := &net.OpError{Op: "dial", Net: "sctp4", Err: root}
	remote := &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 2)}}, Port: 2905}
	cfg := SocketConfig{Control: func(string, string, syscall.RawConn) error {
		return callbackErr
	}}

	_, err := cfg.Dial("sctp4", nil, remote)
	_ = requireSCTPOpError(t, err, "dial", "sctp4", nil, remote, callbackErr)
}

func TestListenErrorCarriesOperationAndAddress(t *testing.T) {
	cause := errors.New("control failed")
	local := &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, Port: 0}
	wantLocal := cloneSCTPAddr(local)
	cfg := SocketConfig{Control: func(string, string, syscall.RawConn) error {
		return cause
	}}

	ln, err := cfg.Listen("sctp4", local)
	if ln != nil {
		_ = ln.Close()
		t.Fatal("Listen returned a listener with a failing Control hook")
	}
	opErr := requireSCTPOpError(t, err, "listen", "sctp4", nil, wantLocal, cause)

	local.Port = 1
	local.IPAddrs[0].IP[len(local.IPAddrs[0].IP)-4] = 10
	if got := opErr.Addr; !sctpAddrEqual(got, wantLocal) {
		t.Errorf("Addr changed after caller mutation: got %#v, want %#v", got, wantLocal)
	}
}

func TestDialContextErrorCarriesOperationAndAddresses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	local := &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, Port: 0}
	remote := &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 2)}}, Port: 2905}

	conn, err := DialSCTPContext(ctx, "sctp4", local, remote, InitMsg{})
	if conn != nil {
		_ = conn.Abort()
		t.Fatal("DialSCTPContext returned a connection for a cancelled context")
	}
	_ = requireSCTPOpError(t, err, "dial", "sctp4", local, remote, context.Canceled)
}

func TestAcceptErrorCarriesListenerContext(t *testing.T) {
	ln, err := ListenSCTP("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("ListenSCTP: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	local := ln.Addr().(*SCTPAddr)
	if err := ln.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}

	conn, err := ln.AcceptSCTP()
	if conn != nil {
		_ = conn.Abort()
		t.Fatal("AcceptSCTP returned a connection after its deadline")
	}
	_ = requireSCTPOpError(t, err, "accept", "sctp", nil, local, os.ErrDeadlineExceeded)
}

func TestNetConnIOErrorsCarryConnectionContext(t *testing.T) {
	client, server := eorPair(t)
	local := server.LocalAddr().(*SCTPAddr)
	remote := server.RemoteAddr().(*SCTPAddr)

	if err := server.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, err := server.Read(make([]byte, 1))
	_ = requireSCTPOpError(t, err, "read", "sctp", local, remote, os.ErrDeadlineExceeded)

	if err := client.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	local = client.LocalAddr().(*SCTPAddr)
	remote = client.RemoteAddr().(*SCTPAddr)
	_, err = client.Write([]byte{1})
	_ = requireSCTPOpError(t, err, "write", "sctp", local, remote, os.ErrDeadlineExceeded)
}

func TestClosedNetConnErrorsRetainConnectionContext(t *testing.T) {
	_, conn := eorPair(t)
	local := conn.LocalAddr().(*SCTPAddr)
	remote := conn.RemoteAddr().(*SCTPAddr)
	if err := conn.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}

	_, err := conn.Read(make([]byte, 1))
	_ = requireSCTPOpError(t, err, "read", "sctp", local, remote, net.ErrClosed)
	_, err = conn.Write([]byte{1})
	_ = requireSCTPOpError(t, err, "write", "sctp", local, remote, net.ErrClosed)
}

func TestNetConnGracefulCloseReturnsDirectEOF(t *testing.T) {
	client, server := eorPairNoCleanup(t)
	t.Cleanup(func() { _ = client.Abort() })
	t.Cleanup(func() { _ = server.Abort() })

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	_, err := server.Read(make([]byte, 1))
	if err != io.EOF {
		t.Fatalf("Read after graceful peer close = %v, want direct io.EOF", err)
	}
}

func TestClosedListenerAcceptErrorRetainsListenerContext(t *testing.T) {
	ln, err := ListenSCTP("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("ListenSCTP: %v", err)
	}
	local := ln.Addr().(*SCTPAddr)
	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err = ln.AcceptSCTP()
	_ = requireSCTPOpError(t, err, "accept", "sctp", nil, local, net.ErrClosed)
}

func TestRawConnectErrorRemainsUnwrapped(t *testing.T) {
	_, err := SCTPConnect(-1, loopbackAddr())
	if !errors.Is(err, syscall.EBADF) {
		t.Fatalf("SCTPConnect error = %v, want syscall.EBADF", err)
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		t.Fatalf("SCTPConnect error = %#v, raw descriptor helper must not return *net.OpError", opErr)
	}
}

func sctpAddrEqual(got net.Addr, want *SCTPAddr) bool {
	addr, ok := got.(*SCTPAddr)
	if !ok {
		return false
	}
	return addr.String() == want.String()
}
