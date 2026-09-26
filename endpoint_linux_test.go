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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// endpointWait bounds every wait of the Endpoint tests, so that a hang
// fails a test instead of stalling the suite.
const endpointWait = 5 * time.Second

// --- helpers ------------------------------------------------------------------

// listenEndpoint opens a listening Endpoint with cfg and aborts it on
// cleanup, which does nothing once a test has closed it itself.
func listenEndpoint(t testing.TB, cfg *Config, network string, laddr *Addr) *Endpoint {
	t.Helper()
	e, err := cfg.ListenEndpoint(network, laddr)
	if err != nil {
		t.Fatalf("ListenEndpoint(%q, %v): %v", network, laddr, err)
	}
	t.Cleanup(func() { _ = e.Abort() })
	return e
}

// openEndpoint opens a connect-only Endpoint with cfg, aborted on cleanup.
func openEndpoint(t testing.TB, cfg *Config, network string, laddr *Addr) *Endpoint {
	t.Helper()
	e, err := cfg.OpenEndpoint(network, laddr)
	if err != nil {
		t.Fatalf("OpenEndpoint(%q, %v): %v", network, laddr, err)
	}
	t.Cleanup(func() { _ = e.Abort() })
	return e
}

// endpointAddr is e's Addr snapshot as an *Addr with a port.
func endpointAddr(t testing.TB, e *Endpoint) *Addr {
	t.Helper()
	a, ok := e.Addr().(*Addr)
	if !ok || a == nil || a.Port == 0 {
		t.Fatalf("Endpoint Addr = %#v, want an *Addr with a port", e.Addr())
	}
	return a
}

// setEndpointReadDeadline sets e's read deadline d from now.
func setEndpointReadDeadline(t testing.TB, e *Endpoint, d time.Duration) {
	t.Helper()
	if err := e.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
}

// nextNote reads e, which has no NotificationHandler, until a whole
// notification arrives, and fails the test on data before it.
func nextNote(t testing.TB, e *Endpoint) Notification {
	t.Helper()
	setEndpointReadDeadline(t, e, endpointWait)
	buf := make([]byte, 1<<16)
	n, info, err := e.RecvMsg(buf)
	if err != nil {
		t.Fatalf("RecvMsg waiting for a notification: %v", err)
	}
	if !info.Notification {
		t.Fatalf("data %q (%+v) arrived before the notification", buf[:n], info.Rcv)
	}
	if !info.EOR {
		t.Fatalf("a notification in pieces with a %d-byte buffer", len(buf))
	}
	note, err := ParseNotification(buf[:n])
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	return note
}

// nextAssocChange reads e until an AssocChange arrives.
func nextAssocChange(t testing.TB, e *Endpoint) *AssocChange {
	t.Helper()
	for {
		if ac, ok := nextNote(t, e).(*AssocChange); ok {
			return ac
		}
	}
}

// awaitCommUp reads e's next AssocChange and requires it to be
// AssocCommUp for a real association.
func awaitCommUp(t testing.TB, e *Endpoint) *AssocChange {
	t.Helper()
	ac := nextAssocChange(t, e)
	if ac.State != AssocCommUp || !realAssocID(ac.AssocID) {
		t.Fatalf("association change %+v, want AssocCommUp for a real association", ac)
	}
	return ac
}

// awaitAssocState reads e until association id reports state.
func awaitAssocState(t testing.TB, e *Endpoint, id AssocID, state AssocChangeState) *AssocChange {
	t.Helper()
	for {
		if ac := nextAssocChange(t, e); ac.AssocID == id && ac.State == state {
			return ac
		}
	}
}

// endpointData reads e until a message arrives, skipping notifications,
// and returns its bytes and what RecvMsg reported about them.
func endpointData(t testing.TB, e *Endpoint) ([]byte, MsgInfo) {
	t.Helper()
	setEndpointReadDeadline(t, e, endpointWait)
	buf := make([]byte, 1<<16)
	for {
		n, info, err := e.RecvMsg(buf)
		if err != nil {
			t.Fatalf("RecvMsg: %v", err)
		}
		if !info.Notification {
			return bytes.Clone(buf[:n]), info
		}
	}
}

// endpointPair sets up one association between a listening Endpoint and a
// connect-only one and returns both with the id each side knows it by,
// both AssocCommUp records consumed.
func endpointPair(t testing.TB, serverCfg, clientCfg *Config) (server, client *Endpoint, serverID, clientID AssocID) {
	t.Helper()
	server = listenEndpoint(t, serverCfg, "sctp4", loopback4(0))
	client = openEndpoint(t, clientCfg, "sctp4", loopback4(0))
	clientID, err := client.Connect(endpointAddr(t, server))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if up := awaitCommUp(t, client); up.AssocID != clientID {
		t.Fatalf("the client's AssocCommUp names association %d; Connect returned %d", up.AssocID, clientID)
	}
	serverID = awaitCommUp(t, server).AssocID
	return server, client, serverID, clientID
}

// onlyAssoc waits until e holds exactly one association and returns its
// id, without reading anything from e.
func onlyAssoc(t testing.TB, e *Endpoint) AssocID {
	t.Helper()
	deadline := time.Now().Add(endpointWait)
	for {
		ids, err := e.AssocIDs()
		if err != nil {
			t.Fatalf("AssocIDs: %v", err)
		}
		if len(ids) == 1 {
			return ids[0]
		}
		if time.Now().After(deadline) {
			t.Fatalf("AssocIDs = %v; want exactly one association", ids)
		}
		time.Sleep(time.Millisecond)
	}
}

// peeledPair peels off the association a one-to-one connection dialed to
// a listening Endpoint opened with cfg, and returns the peeled connection
// and its peer. Both are aborted on cleanup.
func peeledPair(t testing.TB, cfg *Config) (peeled, peer *Conn) {
	t.Helper()
	e := listenEndpoint(t, cfg, "sctp4", loopback4(0))
	peer, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, endpointAddr(t, e))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = peer.Abort() })
	peeled, err = e.PeelOff(onlyAssoc(t, e))
	if err != nil {
		t.Fatalf("PeelOff: %v", err)
	}
	t.Cleanup(func() { _ = peeled.Abort() })
	return peeled, peer
}

// mustEndpointRawConn is e's SyscallConn.
func mustEndpointRawConn(t testing.TB, e *Endpoint) syscall.RawConn {
	t.Helper()
	rc, err := e.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	return rc
}

// wantOp asserts that err is a *net.OpError with Op op matching target.
func wantOp(t testing.TB, what, op string, err, target error) {
	t.Helper()
	_ = opOf(t, what, op, err, target)
}

// opOf is wantOp, returning the *net.OpError.
func opOf(t testing.TB, what, op string, err, target error) *net.OpError {
	t.Helper()
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != op {
		t.Fatalf("%s = %#v (%v), want a *net.OpError with Op %s", what, err, err, op)
	}
	if !errors.Is(err, target) {
		t.Fatalf("%s = %v, want it to match %v", what, err, target)
	}
	return opErr
}

// --- opening an Endpoint ------------------------------------------------------

// TestEndpointConfigOrderAndInvariants: Control runs on an unbound
// SOCK_SEQPACKET socket, before any typed setting, and an Endpoint's
// invariants are applied after it, so that nothing Control does can turn
// them off: SCTP_RECVRCVINFO, the SCTP_ASSOC_CHANGE subscription, and a
// fragment interleave level of 1 (RFC 6458 §8.1.20). Typed settings such
// as InitMsg reach the endpoint, an explicit FragmentInterleave is kept,
// and InterleaveStreams, which Linux cannot deliver, is refused.
func TestEndpointConfigOrderAndInvariants(t *testing.T) {
	var controlCalled bool
	cfg := &Config{
		InitMsg: InitMsg{OutStreams: 17, MaxInStreams: 19, MaxAttempts: 3, MaxInitTimeout: 800 * time.Millisecond},
		Control: func(network, address string, rc syscall.RawConn) error {
			controlCalled = true
			if network != "sctp4" || address == "" {
				return fmt.Errorf("Control got network %q address %q", network, address)
			}
			var cerr error
			if err := rc.Control(func(fd uintptr) {
				typ, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
				if err != nil || typ != syscall.SOCK_SEQPACKET {
					cerr = fmt.Errorf("SO_TYPE = %d, %v; want SOCK_SEQPACKET", typ, err)
					return
				}
				sa, err := syscall.Getsockname(int(fd))
				if err != nil {
					cerr = err
					return
				}
				if sa.(*syscall.SockaddrInet4).Port != 0 {
					cerr = errors.New("Control ran after the bind")
					return
				}
				// Try to switch the invariants off; the constructor applies
				// them after Control.
				if err := setIntOpt(int(fd), ipprotoSCTP, optRecvRcvInfo, 0); err != nil {
					cerr = err
					return
				}
				if err := setIntOpt(int(fd), ipprotoSCTP, optFragmentInterleave, 0); err != nil {
					cerr = err
					return
				}
				cerr = setEvent(int(fd), EventAssocChange, false)
			}); err != nil {
				return err
			}
			return cerr
		},
	}
	e := listenEndpoint(t, cfg, "sctp4", loopback4(0))
	if !controlCalled {
		t.Fatal("Config.Control was not called")
	}
	rc := mustEndpointRawConn(t, e)
	var init [sizeInitMsg]byte
	getRawOpt(t, rc, optInitMsg, init[:])
	if o, i, a, m := binary.NativeEndian.Uint16(init[initMsgOutStreamsOff:]), binary.NativeEndian.Uint16(init[initMsgMaxInStreamsOff:]), binary.NativeEndian.Uint16(init[initMsgMaxAttemptsOff:]), binary.NativeEndian.Uint16(init[initMsgMaxInitTimeoOff:]); o != 17 || i != 19 || a != 3 || m != 800 {
		t.Errorf("InitMsg = %d/%d/%d/%d, want 17/19/3/800", o, i, a, m)
	}
	if got := getIntOpt(t, rc, ipprotoSCTP, optRecvRcvInfo); got != 1 {
		t.Errorf("SCTP_RECVRCVINFO = %d after Control switched it off; the Endpoint must force it on", got)
	}
	if !subscribedInKernel(t, rc, EventAssocChange) {
		t.Error("SCTP_ASSOC_CHANGE is not subscribed after Control switched it off; the Endpoint must force it on")
	}
	if got := getIntOpt(t, rc, ipprotoSCTP, optFragmentInterleave); got != int(InterleaveAssocs) {
		t.Errorf("fragment interleave = %d, want %d, RFC 6458 §8.1.20's default for one-to-many sockets", got, InterleaveAssocs)
	}

	for _, level := range []FragmentInterleave{InterleaveNone, InterleaveAssocs} {
		e := openEndpoint(t, &Config{FragmentInterleave: new(level)}, "sctp4", loopback4(0))
		rc := mustEndpointRawConn(t, e)
		if got := getIntOpt(t, rc, ipprotoSCTP, optFragmentInterleave); got != int(level) {
			t.Errorf("explicit level %d: fragment interleave = %d", level, got)
		}
		if got := getIntOpt(t, rc, ipprotoSCTP, optRecvRcvInfo); got != 1 {
			t.Errorf("explicit level %d: SCTP_RECVRCVINFO = %d, want 1", level, got)
		}
	}
	e2, err := (&Config{FragmentInterleave: new(InterleaveStreams)}).OpenEndpoint("sctp4", loopback4(0))
	if e2 != nil {
		_ = e2.Abort()
	}
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("OpenEndpoint with InterleaveStreams = %v, want errors.ErrUnsupported: Linux collapses it to InterleaveAssocs", err)
	}
}

// TestEndpointConfigReachesTheSocket: settings made through Config land on
// the one-to-many socket, and so on every association it later creates,
// for example DelayedSACK (RFC 6458 §8.1.19), read back with association
// id 0, SCTP_FUTURE_ASSOC (v1 TestSocketConfigPreAssociationDelayedSACKOnEndpoints).
func TestEndpointConfigReachesTheSocket(t *testing.T) {
	cfg := &Config{DelayedSACK: &DelayedSACK{Delay: 137 * time.Millisecond, Frequency: 2}, NoDelay: new(true)}
	for name, e := range map[string]*Endpoint{
		"ListenEndpoint": listenEndpoint(t, cfg, "sctp4", loopback4(0)),
		"OpenEndpoint":   openEndpoint(t, cfg, "sctp4", loopback4(0)),
	} {
		rc := mustEndpointRawConn(t, e)
		var sack [sizeDelayedSACK]byte
		getRawOpt(t, rc, optDelayedAckTime, sack[:])
		if d, f := binary.NativeEndian.Uint32(sack[delayedSACKDelayOff:]), binary.NativeEndian.Uint32(sack[delayedSACKFrequencyOff:]); d != 137 || f != 2 {
			t.Errorf("%s: delayed SACK = %d ms/%d, want 137/2", name, d, f)
		}
		if got := getIntOpt(t, rc, ipprotoSCTP, optNoDelay); got != 1 {
			t.Errorf("%s: SCTP_NODELAY = %d, want 1", name, got)
		}
	}
}

// TestEndpointConfigRefusals: a Config field an Endpoint cannot apply, such
// as ReusePort (one-to-one sockets only, RFC 6458 §8.1.27) or an
// AbandonPolicy, is refused before any socket exists, with Op "listen".
func TestEndpointConfigRefusals(t *testing.T) {
	before := openFds(t)
	var controlCalls atomic.Int32
	control := func(string, string, syscall.RawConn) error { controlCalls.Add(1); return nil }
	for name, cfg := range map[string]*Config{
		"ReusePort":        {Control: control, ReusePort: new(true)},
		"AbandonPolicy":    {Control: control, AbandonPolicy: AbandonQuiet},
		"DelayedSACK":      {Control: control, DelayedSACK: &DelayedSACK{Delay: 501 * time.Millisecond}},
		"negative timeout": {Control: control, CloseTimeout: -time.Second},
	} {
		for ctor, open := range map[string]func() (*Endpoint, error){
			"ListenEndpoint": func() (*Endpoint, error) { return cfg.ListenEndpoint("sctp4", loopback4(0)) },
			"OpenEndpoint":   func() (*Endpoint, error) { return cfg.OpenEndpoint("sctp4", loopback4(0)) },
		} {
			e, err := open()
			if e != nil {
				_ = e.Abort()
			}
			op := opOf(t, ctor+" with "+name, "listen", err, syscall.EINVAL)
			if a, ok := op.Addr.(*Addr); !ok || a.Port != 0 || len(a.IPs) != 1 {
				t.Errorf("%s with %s: Addr = %#v, want the local address asked for", ctor, name, op.Addr)
			}
		}
	}
	if n := controlCalls.Load(); n != 0 {
		t.Errorf("Control ran %d times for Configs refused before any socket exists", n)
	}
	if after := openFds(t); after != before {
		t.Errorf("descriptor count went %d -> %d", before, after)
	}
}

// TestEndpointControlFailureReleasesDescriptor: when Control fails, the
// constructor returns its error, with Op "listen", and the descriptor
// Control saw is released.
func TestEndpointControlFailureReleasesDescriptor(t *testing.T) {
	want := errors.New("control failed")
	borrowed := -1
	cfg := &Config{Control: func(_, _ string, rc syscall.RawConn) error {
		if err := rc.Control(func(fd uintptr) { borrowed = int(fd) }); err != nil {
			return err
		}
		return want
	}}
	for name, open := range map[string]func() (*Endpoint, error){
		"ListenEndpoint": func() (*Endpoint, error) { return cfg.ListenEndpoint("sctp4", loopback4(0)) },
		"OpenEndpoint":   func() (*Endpoint, error) { return cfg.OpenEndpoint("sctp4", loopback4(0)) },
	} {
		borrowed = -1
		e, err := open()
		if e != nil {
			t.Fatalf("%s returned an Endpoint", name)
		}
		wantOp(t, name, "listen", err, want)
		if borrowed < 0 {
			t.Fatalf("%s: Control was not called", name)
		}
		if fdIsOpen(borrowed) {
			t.Errorf("%s: descriptor %d is still open after the constructor failed", name, borrowed)
		}
	}
}

// TestEndpointRefusesBadNetworks: an unknown network, and an address of
// the wrong family for the network, are refused with EINVAL.
func TestEndpointRefusesBadNetworks(t *testing.T) {
	if e, err := OpenEndpoint("udp", loopback4(0)); err == nil {
		_ = e.Abort()
		t.Error("OpenEndpoint accepted network udp")
	}
	v6 := &Addr{IPs: []netip.Addr{netip.IPv6Loopback()}}
	if e, err := ListenEndpoint("sctp4", v6); !errors.Is(err, syscall.EINVAL) {
		if e != nil {
			_ = e.Abort()
		}
		t.Errorf("ListenEndpoint sctp4 on ::1 = %v, want EINVAL", err)
	}
	e := openEndpoint(t, nil, "sctp4", loopback4(0))
	_, err := e.Connect(&Addr{IPs: []netip.Addr{netip.IPv6Loopback()}, Port: 9})
	wantOp(t, "sctp4 Connect to ::1", "dial", err, syscall.EINVAL)
}

// TestNilConfigConstructors: a nil *Config is the zero Config for every
// constructor, which then succeeds, or refuses a bad network with an
// error rather than a panic (v1 TestNilSocketConfigMethodsDoNotPanic).
func TestNilConfigConstructors(t *testing.T) {
	var cfg *Config
	for name, call := range map[string]func() error{
		"Listen": func() error { _, err := cfg.Listen("not-sctp", nil); return err },
		"Dial": func() error {
			_, err := cfg.Dial(testContext(t, time.Second), "not-sctp", nil, loopback4(9))
			return err
		},
		"ListenEndpoint": func() error { _, err := cfg.ListenEndpoint("not-sctp", nil); return err },
		"OpenEndpoint":   func() error { _, err := cfg.OpenEndpoint("not-sctp", nil); return err },
	} {
		if err := call(); err == nil {
			t.Errorf("nil Config %s on network not-sctp succeeded", name)
		}
	}
	l, err := cfg.Listen("sctp4", loopback4(0))
	if err != nil {
		t.Fatalf("nil Config Listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	c, err := cfg.Dial(testContext(t, 10*time.Second), "sctp4", nil, listenerAddr(t, l))
	if err != nil {
		t.Fatalf("nil Config Dial: %v", err)
	}
	_ = c.Abort()
	le, err := cfg.ListenEndpoint("sctp4", loopback4(0))
	if err != nil {
		t.Fatalf("nil Config ListenEndpoint: %v", err)
	}
	_ = le.Abort()
	oe, err := cfg.OpenEndpoint("sctp4", nil)
	if err != nil {
		t.Fatalf("nil Config OpenEndpoint: %v", err)
	}
	_ = oe.Abort()
}

// TestEndpointAddrAfterConnectBinds: an OpenEndpoint given no local
// address is bound by its first Connect (net/sctp/socket.c: sctp_autobind
// from __sctp_connect's path), and Addr then reports the port the kernel
// chose.
func TestEndpointAddrAfterConnectBinds(t *testing.T) {
	server := listenEndpoint(t, nil, "sctp4", loopback4(0))
	client := openEndpoint(t, nil, "sctp4", nil)
	if a := client.Addr().(*Addr); a.Port != 0 {
		t.Fatalf("an unbound endpoint reports port %d", a.Port)
	}
	if _, err := client.Connect(endpointAddr(t, server)); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	awaitCommUp(t, client)
	if a := client.Addr().(*Addr); a.Port == 0 {
		t.Errorf("Addr after Connect = %v; the port the kernel bound is missing", a)
	}
}

// TestOpenEndpointRefusesPeers: an OpenEndpoint does not listen, so a
// peer's INIT for it is answered with an ABORT (RFC 6458 §3.1.3; Linux
// enters a one-to-many socket in its endpoint table only when it starts
// listening: net/sctp/socket.c, sctp_listen_start), while a
// ListenEndpoint on the same kind of address accepts.
func TestOpenEndpointRefusesPeers(t *testing.T) {
	open := openEndpoint(t, nil, "sctp4", loopback4(0))
	if c, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, endpointAddr(t, open)); err == nil {
		_ = c.Abort()
		t.Fatal("a Dial to an OpenEndpoint succeeded")
	} else if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Errorf("a Dial to an OpenEndpoint = %v, want ECONNREFUSED", err)
	}
	if n, err := open.AssocCount(); err != nil || n != 0 {
		t.Errorf("the OpenEndpoint holds %d associations, %v", n, err)
	}
	listening := listenEndpoint(t, nil, "sctp4", loopback4(0))
	c, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, endpointAddr(t, listening))
	if err != nil {
		t.Fatalf("a Dial to a ListenEndpoint: %v", err)
	}
	_ = c.Abort()
}

// --- associations and messages -------------------------------------------------

// TestEndpointRoundTripAndPeelOff: a message's metadata crosses intact;
// the association's addresses are the endpoints'; PeelOff moves the
// association, with what is queued for it, to a close-on-exec descriptor
// of its own, after which the endpoint no longer knows the id (a send to
// it fails with EPIPE, net/sctp/socket.c: sctp_sendmsg) and closing the
// endpoint leaves the peeled connection alone (v1
// TestSCTPEndpointRoundTripAndPeelOffOwnership,
// TestPeelOffSucceedsOnAOneToManySocket).
func TestEndpointRoundTripAndPeelOff(t *testing.T) {
	server, client, serverID, clientID := endpointPair(t, nil, nil)
	for name, e := range map[string]*Endpoint{"server": server, "client": client} {
		rawFd(t, mustEndpointRawConn(t, e), func(fd int) {
			if !isCloseOnExec(fd) || !isNonblocking(fd) {
				t.Errorf("%s endpoint descriptor %d: close-on-exec %v, non-blocking %v; want both", name, fd, isCloseOnExec(fd), isNonblocking(fd))
			}
		})
	}

	clientLocal, err := client.LocalAddrs(clientID)
	if err != nil {
		t.Fatalf("client LocalAddrs: %v", err)
	}
	clientPeer, err := client.PeerAddrs(clientID)
	if err != nil {
		t.Fatalf("client PeerAddrs: %v", err)
	}
	serverLocal, err := server.LocalAddrs(serverID)
	if err != nil {
		t.Fatalf("server LocalAddrs: %v", err)
	}
	serverPeer, err := server.PeerAddrs(serverID)
	if err != nil {
		t.Fatalf("server PeerAddrs: %v", err)
	}
	if clientLocal.Port != endpointAddr(t, client).Port || clientPeer.Port != endpointAddr(t, server).Port ||
		serverLocal.Port != endpointAddr(t, server).Port || serverPeer.Port != endpointAddr(t, client).Port {
		t.Fatalf("addresses: client %v -> %v, server %v -> %v", clientLocal, clientPeer, serverLocal, serverPeer)
	}
	for _, a := range []*Addr{clientLocal, clientPeer, serverLocal, serverPeer} {
		if !equalStrings(ipStrings(a), []string{"127.0.0.1"}) {
			t.Errorf("association address %v, want 127.0.0.1", a)
		}
	}
	clientPeer.IPs[0] = netip.MustParseAddr("10.9.9.9")
	if fresh, err := client.PeerAddrs(clientID); err != nil || !equalStrings(ipStrings(fresh), []string{"127.0.0.1"}) {
		t.Errorf("PeerAddrs after the caller changed an earlier result = %v, %v", fresh, err)
	}

	request := []byte("one-to-many request")
	if n, err := client.SendMsg(clientID, request, SendOptions{Info: &SndInfo{Stream: 3, PPID: 0x11223344, Context: 0x55667788}}); err != nil || n != len(request) {
		t.Fatalf("SendMsg = %d, %v", n, err)
	}
	got, info := endpointData(t, server)
	// RcvInfo.Context is the receiver's SCTP_CONTEXT, not the sender's
	// SndInfo.Context, which comes back only in SendFailed (RFC 6458
	// §§5.3.4, 5.3.5).
	if !bytes.Equal(got, request) || !info.EOR || info.Rcv.AssocID != serverID || info.Rcv.Stream != 3 || info.Rcv.PPID != 0x11223344 || info.Rcv.Context != 0 {
		t.Fatalf("server received %q, %+v; want the request on association %d, stream 3, PPID 0x11223344, EOR", got, info, serverID)
	}

	// Something queued for the association before the peel follows it.
	queued := []byte("queued before the peel")
	if _, err := client.SendMsg(clientID, queued, SendOptions{}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	peeled, err := server.PeelOff(serverID)
	if err != nil {
		t.Fatalf("PeelOff: %v", err)
	}
	t.Cleanup(func() { _ = peeled.Abort() })
	if peeled.AssocID() != serverID {
		t.Errorf("peeled AssocID = %d, want %d", peeled.AssocID(), serverID)
	}
	rawFd(t, mustSyscallConn(t, peeled), func(fd int) {
		if fd <= 2 || !isCloseOnExec(fd) || !isNonblocking(fd) {
			t.Errorf("peeled descriptor %d: close-on-exec %v, non-blocking %v; want a package-owned, close-on-exec, non-blocking descriptor", fd, isCloseOnExec(fd), isNonblocking(fd))
		}
		if typ, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE); err != nil || typ != syscall.SOCK_SEQPACKET {
			t.Errorf("peeled SO_TYPE = %d, %v; want SOCK_SEQPACKET", typ, err)
		}
	})
	if peeled.kind != kindPeeled {
		t.Errorf("peeled connection kind %d, want kindPeeled", peeled.kind)
	}
	setReadDeadline(t, peeled, endpointWait)
	buf := make([]byte, 128)
	if n, err := peeled.Read(buf); err != nil || string(buf[:n]) != string(queued) {
		t.Fatalf("peeled Read = %q, %v; want the message queued before the peel", buf[:n], err)
	}

	_, err = server.SendMsg(serverID, []byte("stale"), SendOptions{})
	wantOp(t, "endpoint SendMsg to the peeled association", "write", err, syscall.EPIPE)

	if err := server.Close(); err != nil {
		t.Fatalf("server endpoint Close: %v", err)
	}
	after := []byte("the peeled connection outlives its endpoint")
	if _, err := client.SendMsg(clientID, after, SendOptions{}); err != nil {
		t.Fatalf("SendMsg after the endpoint closed: %v", err)
	}
	if n, err := peeled.Read(buf); err != nil || string(buf[:n]) != string(after) {
		t.Fatalf("peeled Read after the endpoint closed = %q, %v", buf[:n], err)
	}
	if _, err := peeled.Write([]byte("reply")); err != nil {
		t.Fatalf("peeled Write: %v", err)
	}
	if got, info := endpointData(t, client); string(got) != "reply" || info.Rcv.AssocID != clientID {
		t.Fatalf("client received %q on %d, want the reply on %d", got, info.Rcv.AssocID, clientID)
	}

	local, remote := peeled.LocalAddr().(*Addr), peeled.RemoteAddr().(*Addr)
	if local.Port != serverLocal.Port || remote.Port != serverPeer.Port {
		t.Errorf("peeled addresses %v -> %v, want the association's %v -> %v", local, remote, serverLocal, serverPeer)
	}
	if err := peeled.Abort(); err != nil {
		t.Fatalf("peeled Abort: %v", err)
	}
	_, err = peeled.Read(buf)
	op := opOf(t, "Read after Abort", "read", err, net.ErrClosed)
	if op.Net != "sctp4" || op.Source == nil || op.Addr == nil {
		t.Errorf("Read after Abort = %#v, want the connection's network and addresses", op)
	}
}

// TestEndpointCreatesAndRoutesMultipleAssociations: one endpoint holds
// associations with two peers at once, lists and counts them, and routes
// concurrent sends to the association each names (v1
// TestSCTPEndpointCreatesAndRoutesMultipleAssociations).
func TestEndpointCreatesAndRoutesMultipleAssociations(t *testing.T) {
	servers := []*Endpoint{
		listenEndpoint(t, nil, "sctp4", loopback4(0)),
		listenEndpoint(t, nil, "sctp4", loopback4(0)),
	}
	client := openEndpoint(t, nil, "sctp4", loopback4(0))
	clientIDs := make([]AssocID, len(servers))
	serverIDs := make([]AssocID, len(servers))
	for i, s := range servers {
		var err error
		if clientIDs[i], err = client.Connect(endpointAddr(t, s)); err != nil {
			t.Fatalf("Connect %d: %v", i, err)
		}
		serverIDs[i] = awaitCommUp(t, s).AssocID
	}
	up := map[AssocID]bool{}
	for len(up) < len(servers) {
		up[awaitCommUp(t, client).AssocID] = true
	}
	for i, id := range clientIDs {
		if !up[id] {
			t.Fatalf("Connect %d returned %d, which no AssocCommUp named (%v)", i, id, up)
		}
	}
	if clientIDs[0] == clientIDs[1] {
		t.Fatalf("both associations have id %d", clientIDs[0])
	}
	if n, err := client.AssocCount(); err != nil || n != 2 {
		t.Fatalf("AssocCount = %d, %v; want 2", n, err)
	}
	listed, err := client.AssocIDs()
	if want := slices.Sorted(slices.Values(clientIDs)); err != nil || !slices.Equal(listed, want) {
		t.Fatalf("AssocIDs = %v, %v; want %v, in ascending order", listed, err, want)
	}
	listed[0] = -1
	if fresh, err := client.AssocIDs(); err != nil || fresh[0] == -1 {
		t.Fatalf("AssocIDs after the caller changed an earlier result = %v, %v", fresh, err)
	}
	for i, s := range servers {
		if ids, err := s.AssocIDs(); err != nil || len(ids) != 1 || ids[0] != serverIDs[i] {
			t.Errorf("server %d AssocIDs = %v, %v; want [%d]", i, ids, err, serverIDs[i])
		}
	}

	var wg sync.WaitGroup
	errs := make(chan error, len(servers))
	for i, id := range clientIDs {
		wg.Go(func() {
			_, err := client.SendMsg(id, []byte{byte('A' + i)}, SendOptions{Info: &SndInfo{Stream: uint16(i + 1), PPID: uint32(0x100 + i)}})
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent SendMsg: %v", err)
		}
	}
	for i, s := range servers {
		got, info := endpointData(t, s)
		if len(got) != 1 || got[0] != byte('A'+i) || !info.EOR || info.Rcv.AssocID != serverIDs[i] || info.Rcv.Stream != uint16(i+1) || info.Rcv.PPID != uint32(0x100+i) {
			t.Errorf("server %d received %q, %+v", i, got, info)
		}
	}
}

// TestEndpointAssocIDsGrowsItsBuffer: more associations than the first
// list buffer holds make Linux refuse the first read with EINVAL
// (net/sctp/socket.c: sctp_getsockopt_assoc_ids), and AssocIDs retries
// with a larger buffer (v1 TestSCTPEndpointAssociationIDsGrowsItsBoundedBuffer).
func TestEndpointAssocIDsGrowsItsBuffer(t *testing.T) {
	const associations = assocIDsFirstBuffer + 1
	client := openEndpoint(t, nil, "sctp4", loopback4(0))
	want := map[AssocID]bool{}
	for i := range associations {
		server := listenEndpoint(t, nil, "sctp4", loopback4(0))
		id, err := client.Connect(endpointAddr(t, server))
		if err != nil {
			t.Fatalf("Connect %d: %v", i, err)
		}
		awaitCommUp(t, server)
		if up := awaitCommUp(t, client); up.AssocID != id {
			t.Fatalf("association %d: AssocCommUp names %d, Connect returned %d", i, up.AssocID, id)
		}
		want[id] = true
	}
	if n, err := client.AssocCount(); err != nil || n != associations {
		t.Fatalf("AssocCount = %d, %v; want %d", n, err, associations)
	}
	ids, err := client.AssocIDs()
	if err != nil || len(ids) != associations || !slices.IsSorted(ids) {
		t.Fatalf("AssocIDs = %v, %v; want %d ids in ascending order", ids, err, associations)
	}
	for _, id := range ids {
		if !want[id] {
			t.Errorf("AssocIDs returned %d, which Connect never did", id)
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Errorf("AssocIDs left out %v", want)
	}
}

// TestEndpointConnectReturnsTheIDWhileSetupIsInProgress: Connect returns
// the new association's id at once, with a nil error, although the
// non-blocking CONNECTX3 answers EINPROGRESS (net/sctp/socket.c:
// sctp_getsockopt_connectx3 copies the id out on EINPROGRESS too;
// erlang/otp PR #1592). Against a peer that never answers the setup stays
// in COOKIE-WAIT, and the id already names it.
func TestEndpointConnectReturnsTheIDWhileSetupIsInProgress(t *testing.T) {
	if !silentPeerAvailable(t) {
		t.Skip("SCTP to 192.0.2.1 is answered rather than dropped here, so no setup stays in progress; the Linux suite routes it to a dummy link")
	}
	e := openEndpoint(t, nil, "sctp4", nil)
	id, err := e.Connect(unreachableAddr())
	if err != nil || !realAssocID(id) {
		t.Fatalf("Connect to a silent peer = %d, %v; want a real id and nil", id, err)
	}
	var st [sizeStatus]byte
	binary.NativeEndian.PutUint32(st[statusAssocIDOff:], uint32(id))
	getRawOpt(t, mustEndpointRawConn(t, e), optStatus, st[:])
	if state := AssocState(int32(binary.NativeEndian.Uint32(st[statusStateOff:]))); state != StateCookieWait {
		t.Errorf("association %d is in %v, want StateCookieWait", id, state)
	}
	if ids, err := e.AssocIDs(); err != nil || len(ids) != 1 || ids[0] != id {
		t.Errorf("AssocIDs = %v, %v; want [%d]", ids, err, id)
	}
	if err := e.AbortAssoc(id, nil); err != nil {
		t.Errorf("AbortAssoc of the setup: %v", err)
	}
}

// TestEndpointDuplicateConnect: a second Connect to a peer the endpoint
// already has an established association with fails with EISCONN, Op
// "dial", and returns no id (net/sctp/socket.c: __sctp_connect), rather
// than reporting a new association (v1
// TestSCTPEndpointDuplicateConnectIsNotReportedAsANewAssociation).
func TestEndpointDuplicateConnect(t *testing.T) {
	server, client, _, _ := endpointPair(t, nil, nil)
	id, err := client.Connect(endpointAddr(t, server))
	if id != 0 {
		t.Errorf("duplicate Connect returned id %d, want 0", id)
	}
	op := opOf(t, "duplicate Connect", "dial", err, syscall.EISCONN)
	if a, ok := op.Addr.(*Addr); !ok || a.Port != endpointAddr(t, server).Port {
		t.Errorf("duplicate Connect error Addr = %#v, want the peer asked for", op.Addr)
	}
}

// TestEndpointSetDeadlineAppliesToReceiveAndSend: a passed deadline fails
// RecvMsg and SendMsg with os.ErrDeadlineExceeded, and clearing it lets
// them work again (v1 TestSCTPEndpointSetDeadlineAppliesToReceiveAndSend).
func TestEndpointSetDeadlineAppliesToReceiveAndSend(t *testing.T) {
	server, client, _, clientID := endpointPair(t, nil, nil)
	if err := client.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	_, _, err := client.RecvMsg(make([]byte, 1))
	wantOp(t, "RecvMsg past the deadline", "read", err, os.ErrDeadlineExceeded)
	_, err = client.SendMsg(clientID, []byte("expired"), SendOptions{})
	op := opOf(t, "SendMsg past the deadline", "write", err, os.ErrDeadlineExceeded)
	if !op.Timeout() {
		t.Error("the deadline error is not a timeout")
	}
	if err := client.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing the deadline: %v", err)
	}
	if _, err := client.SendMsg(clientID, []byte("after the deadline"), SendOptions{}); err != nil {
		t.Fatalf("SendMsg after clearing the deadline: %v", err)
	}
	if got, _ := endpointData(t, server); string(got) != "after the deadline" {
		t.Fatalf("received %q", got)
	}
	if err := client.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	_, err = client.SendMsg(clientID, []byte("x"), SendOptions{})
	wantOp(t, "SendMsg past the write deadline", "write", err, os.ErrDeadlineExceeded)
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wantOp(t, "SetDeadline after Close", "set", client.SetDeadline(time.Now()), net.ErrClosed)
}

// TestEndpointRefusesEmptyMessages: an empty message is refused before any
// system call, whatever the options, so that nothing reaches the peer:
// sendmsg with an empty payload and control data would otherwise be a
// candidate for a one-byte DATA chunk (v1
// TestSCTPEndpointRejectsZeroLengthMessagesWithAncillaryData).
func TestEndpointRefusesEmptyMessages(t *testing.T) {
	server, client, serverID, clientID := endpointPair(t, nil, nil)
	calls := countSendmsg(t)
	for _, opts := range []SendOptions{
		{},
		{Info: &SndInfo{Stream: 1}},
		{PR: &PrInfo{Policy: PRTTL, TTL: time.Second}},
		{AuthKey: new(uint16(0))},
		{Info: &SndInfo{}, PR: &PrInfo{Policy: PRTTL, TTL: time.Second}, AuthKey: new(uint16(0))},
	} {
		for _, b := range [][]byte{nil, {}} {
			n, err := client.SendMsg(clientID, b, opts)
			if n != 0 {
				t.Errorf("SendMsg of an empty message reported %d bytes", n)
			}
			wantOp(t, "SendMsg of an empty message", "write", err, syscall.EINVAL)
		}
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d sendmsg calls for refused messages, want none", n)
	}
	if _, err := client.SendMsg(clientID, []byte("sentinel"), SendOptions{}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	if got, info := endpointData(t, server); string(got) != "sentinel" || info.Rcv.AssocID != serverID {
		t.Fatalf("received %q on %d; an empty message reached the peer", got, info.Rcv.AssocID)
	}
}

// TestEndpointSendRefusals: SendOptions.Path is refused on an Endpoint,
// where the kernel would find the association by address rather than by
// the id given; a scope selector or negative id and a flag SendFlags does
// not name are refused too, all before any system call.
func TestEndpointSendRefusals(t *testing.T) {
	_, client, _, clientID := endpointPair(t, nil, nil)
	calls := countSendmsg(t)
	for name, send := range map[string]func() error{
		"Path": func() error {
			_, err := client.SendMsg(clientID, []byte("x"), SendOptions{Path: netip.MustParseAddr("127.0.0.1")})
			return err
		},
		"SCTP_EOF flag": func() error {
			_, err := client.SendMsg(clientID, []byte("x"), SendOptions{Info: &SndInfo{Flags: sndFlagEOF}})
			return err
		},
		"SCTP_ABORT flag": func() error {
			_, err := client.SendMsg(clientID, []byte("x"), SendOptions{Info: &SndInfo{Flags: sndFlagAbort}})
			return err
		},
		"PRAll": func() error {
			_, err := client.SendMsg(clientID, []byte("x"), SendOptions{PR: &PrInfo{Policy: PRAll}})
			return err
		},
	} {
		wantOp(t, name, "write", send(), syscall.EINVAL)
	}
	for _, id := range []AssocID{math.MinInt32, -1, 0, 1, 2} {
		_, err := client.SendMsg(id, []byte("x"), SendOptions{})
		wantOp(t, fmt.Sprintf("SendMsg to association %d", id), "write", err, syscall.EINVAL)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d sendmsg calls for refused sends, want none", n)
	}
}

// TestEndpointSendDefaultsAllCombinations: every Endpoint send carries
// SCTP_SNDINFO, since the association id travels there, so the package
// sends the defaults itself: a nil Info is Config.DefaultSndInfo, and a
// nil PR is Config.DefaultPrInfo, in every combination (Linux applies
// neither to a message that carries SNDINFO: net/sctp/socket.c:
// sctp_sendmsg_update_sinfo). The receiver's RcvInfo shows the stream,
// PPID and unordered bit each send should have had.
func TestEndpointSendDefaultsAllCombinations(t *testing.T) {
	defSnd := SndInfo{Stream: 1, Flags: SendUnordered, PPID: 46, Context: 7}
	defPR := PrInfo{Policy: PRTTL, TTL: time.Second}
	cfg := &Config{DefaultSndInfo: new(defSnd), DefaultPrInfo: new(defPR)}
	l := mustListen(t, nil, "sctp4", loopback4(0))
	e := openEndpoint(t, cfg, "sctp4", loopback4(0))
	id, err := e.Connect(listenerAddr(t, l))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	receiver, err := l.AcceptSCTP()
	if err != nil {
		t.Fatalf("AcceptSCTP: %v", err)
	}
	t.Cleanup(func() { _ = receiver.Abort() })
	awaitCommUp(t, e)
	if e.send.defSnd != defSnd || e.send.defPR != defPR {
		t.Fatalf("cached defaults %+v and %+v, want the Config's %+v and %+v", e.send.defSnd, e.send.defPR, defSnd, defPR)
	}

	info := &SndInfo{Stream: 2, PPID: 99, Context: 3}
	prRtx := &PrInfo{Policy: PRRtx, Value: 3}
	both := &SndInfo{Stream: 3, Flags: SendUnordered, PPID: 77}
	none := &PrInfo{Policy: PRNone}
	sent := captureSends(t)
	for _, tc := range []struct {
		name       string
		opts       SendOptions
		wantSnd    SndInfo
		wantPR     *PrInfo
		wantStream uint16
		wantPPID   uint32
		wantUnord  bool
	}{
		{name: "neither", wantSnd: defSnd, wantPR: &PrInfo{Policy: PRTTL, Value: 1000}, wantStream: 1, wantPPID: 46, wantUnord: true},
		{name: "Info only", opts: SendOptions{Info: info}, wantSnd: *info, wantPR: &PrInfo{Policy: PRTTL, Value: 1000}, wantStream: 2, wantPPID: 99},
		{name: "PR only", opts: SendOptions{PR: prRtx}, wantSnd: defSnd, wantPR: prRtx, wantStream: 1, wantPPID: 46, wantUnord: true},
		{name: "both", opts: SendOptions{Info: both, PR: none}, wantSnd: *both, wantPR: none, wantStream: 3, wantPPID: 77, wantUnord: true},
	} {
		if _, err := e.SendMsg(id, []byte(tc.name), tc.opts); err != nil {
			t.Fatalf("%s: SendMsg: %v", tc.name, err)
		}
		recs := sent()
		if len(recs) != 1 {
			t.Fatalf("%s: %d sendmsg calls, want 1", tc.name, len(recs))
		}
		r := recs[0]
		if r.snd == nil || *r.snd != tc.wantSnd || r.sndAssoc != id {
			t.Errorf("%s: SNDINFO sent = %+v for association %d, want %+v for %d", tc.name, r.snd, r.sndAssoc, tc.wantSnd, id)
		}
		if (r.pr == nil) != (tc.wantPR == nil) || (r.pr != nil && *r.pr != *tc.wantPR) {
			t.Errorf("%s: PRINFO sent = %+v, want %+v", tc.name, r.pr, tc.wantPR)
		}
		if r.name != nil {
			t.Errorf("%s: an Endpoint send carried a destination address", tc.name)
		}
		got, rinfo := recvWithin(t, receiver, endpointWait)
		if string(got) != tc.name || rinfo.Stream != tc.wantStream || rinfo.PPID != tc.wantPPID || rinfo.Unordered != tc.wantUnord {
			t.Errorf("%s: received %q on stream %d PPID %d unordered %v, want stream %d PPID %d unordered %v",
				tc.name, got, rinfo.Stream, rinfo.PPID, rinfo.Unordered, tc.wantStream, tc.wantPPID, tc.wantUnord)
		}
	}

	// With no default PR policy, a send carries SNDINFO alone.
	plain := openEndpoint(t, nil, "sctp4", loopback4(0))
	pid, err := plain.Connect(listenerAddr(t, l))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	peer, err := l.AcceptSCTP()
	if err != nil {
		t.Fatalf("AcceptSCTP: %v", err)
	}
	t.Cleanup(func() { _ = peer.Abort() })
	awaitCommUp(t, plain)
	if _, err := plain.SendMsg(pid, []byte("plain"), SendOptions{}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	if r := sent(); len(r) != 1 || r[0].snd == nil || *r[0].snd != (SndInfo{}) || r[0].sndAssoc != pid || r[0].pr != nil {
		t.Errorf("with no defaults, a send carried %+v; want an SNDINFO naming association %d and no PRINFO", r, pid)
	}
	recvWithin(t, peer, endpointWait)
}

// TestEndpointSendMsgWaitsAndNoWait: SendMsg waits for send-buffer space
// unless NoWait is set, which fails at once with EAGAIN and queues
// nothing, as on a Conn; the wait is endpoint-wide (RFC 6458 §3.2). The
// buffer is made to stay full first (fillEndpointStable): a single EAGAIN
// can come while DATA is still in flight, and the delayed SACK for it
// would free room inside the wait.
func TestEndpointSendMsgWaitsAndNoWait(t *testing.T) {
	l := mustListen(t, &Config{ReadBuffer: new(4096)}, "sctp4", loopback4(0))
	e := openEndpoint(t, &Config{WriteBuffer: new(16384)}, "sctp4", loopback4(0))
	id, err := e.Connect(listenerAddr(t, l))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	peer, err := l.AcceptSCTP()
	if err != nil {
		t.Fatalf("AcceptSCTP: %v", err)
	}
	t.Cleanup(func() { _ = peer.Abort() })
	awaitCommUp(t, e)
	payload := fill(512)
	sent := fillEndpointStable(t, e, map[AssocID]*Conn{id: peer}, payload)

	// With the buffer full for good, NoWait fails at once, and queues
	// nothing: the peer reads exactly the messages counted above.
	start := time.Now()
	_, err = e.SendMsg(id, payload, SendOptions{NoWait: true})
	wantOp(t, "NoWait on a full buffer", "write", err, syscall.EAGAIN)
	if d := time.Since(start); d > time.Second {
		t.Errorf("the NoWait refusal took %v; it must not wait", d)
	}
	if err := e.SetWriteDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	start = time.Now()
	_, err = e.SendMsg(id, payload, SendOptions{})
	wantOp(t, "a waiting SendMsg on a full buffer", "write", err, os.ErrDeadlineExceeded)
	if d := time.Since(start); d < 150*time.Millisecond {
		t.Errorf("the waiting SendMsg returned after %v; it did not wait", d)
	}
	if err := e.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := e.SendMsg(id, []byte("the last one"), SendOptions{})
		done <- err
	}()
	setReadDeadline(t, peer, endpointWait)
	buf := make([]byte, 1024)
	for i := range sent {
		if n, err := peer.Read(buf); err != nil || n != len(payload) {
			t.Fatalf("peer Read %d = %d, %v", i, n, err)
		}
	}
	if err := <-done; err != nil {
		t.Fatalf("the waiting SendMsg: %v", err)
	}
	if n, err := peer.Read(buf); err != nil || string(buf[:n]) != "the last one" {
		t.Fatalf("peer Read = %q, %v; want the last message, after exactly the %d queued before it", buf[:n], err, sent)
	}
}

// endpointStats reads SCTP_GET_ASSOC_STATS for association id of e,
// through the options layer's own layout.
func endpointStats(t testing.TB, e *Endpoint, id AssocID) AssocStats {
	t.Helper()
	layout, err := e.sock.storageLayout()
	if err != nil {
		t.Fatalf("storage layout: %v", err)
	}
	var buf [sizeAssocStatsKernel64]byte
	b := layout.assocStatsRequest(buf[:], id)
	l := uint32(len(b))
	if err := e.sock.getsockopt(optGetAssocStats, unsafe.Pointer(&b[0]), &l); err != nil {
		t.Fatalf("SCTP_GET_ASSOC_STATS for association %d: %v", id, err)
	}
	return layout.assocStats(b)
}

// fillEndpoint sends payload with NoWait to each association of peers in
// turn until every one is refused with EAGAIN, and returns how many
// messages each accepted. The peers must not be reading. The buffer is the
// endpoint's, so an EAGAIN for one association is an EAGAIN for all.
func fillEndpoint(t testing.TB, e *Endpoint, ids []AssocID, payload []byte) map[AssocID]int {
	t.Helper()
	queued := make(map[AssocID]int, len(ids))
	refused := 0
	for i := 0; refused < len(ids); i++ {
		if i >= 1<<20 {
			t.Fatal("the send buffer never filled")
		}
		id := ids[i%len(ids)]
		_, err := e.SendMsg(id, payload, SendOptions{NoWait: true})
		switch {
		case errors.Is(err, syscall.EAGAIN):
			refused++
		case err != nil:
			t.Fatalf("SendMsg to association %d: %v", id, err)
		default:
			queued[id]++
			refused = 0
		}
	}
	return queued
}

// fillEndpointStable is fillSendBufferStable for an Endpoint: it fills the
// endpoint's send buffer with messages to every association of peers, each
// peer being the one-to-one Conn at the other end of one, waits until
// every peer has closed its receive window and the endpoint has taken in
// the SACK that says so (awaitClosedWindow), and fills the room those
// SACKs freed. From then on nothing frees room until a peer reads. It
// returns how many messages were queued in all.
func fillEndpointStable(t testing.TB, e *Endpoint, peers map[AssocID]*Conn, payload []byte) int {
	t.Helper()
	ids := slices.Sorted(maps.Keys(peers))
	total := 0
	count := func(q map[AssocID]int) {
		for _, n := range q {
			total += n
		}
	}
	first := fillEndpoint(t, e, ids, payload)
	for _, id := range ids {
		if first[id] == 0 {
			t.Fatalf("the send buffer filled before association %d took a message", id)
		}
	}
	count(first)
	for _, id := range ids {
		awaitClosedWindow(t, peers[id], func() uint64 { return endpointStats(t, e, id).SACKsIn })
	}
	count(fillEndpoint(t, e, ids, payload))
	return total
}

// TestEndpointFragmentsHandlerReentryAndMissingRcvInfo: a message longer
// than the buffer arrives in pieces, each with the message's RcvInfo and
// EOR on the last; the NotificationHandler runs outside the receive lock
// and may call back into the endpoint; and data that arrives without
// SCTP_RCVINFO, here because SyscallConn switched it off, fails with
// ErrMissingRcvInfo instead of being returned as if it belonged to an
// association (v1 TestSCTPEndpointFragmentsHandlerReentryAndMissingMetadata).
func TestEndpointFragmentsHandlerReentryAndMissingRcvInfo(t *testing.T) {
	var server *Endpoint
	upID := make(chan AssocID, 1)
	cfg := &Config{NotificationHandler: func(n Notification) error {
		ac, ok := n.(*AssocChange)
		if !ok || ac.State != AssocCommUp {
			return nil
		}
		if err := server.SetWriteDeadline(time.Time{}); err != nil {
			return err
		}
		if _, err := server.AssocIDs(); err != nil {
			return err
		}
		select {
		case upID <- ac.AssocID:
		default:
		}
		return nil
	}}
	server = listenEndpoint(t, cfg, "sctp4", loopback4(0))
	client := openEndpoint(t, nil, "sctp4", loopback4(0))
	clientID, err := client.Connect(endpointAddr(t, server))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	awaitCommUp(t, client)
	want := bytes.Repeat([]byte("fragment"), 41)
	if _, err := client.SendMsg(clientID, want, SendOptions{Info: &SndInfo{Stream: 5, PPID: 0xaabbccdd}}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	setEndpointReadDeadline(t, server, endpointWait)
	var (
		got    []byte
		first  RcvInfo
		pieces int
	)
	buf := make([]byte, 31)
	for {
		n, info, err := server.RecvMsg(buf)
		if err != nil {
			t.Fatalf("RecvMsg piece %d: %v", pieces, err)
		}
		if info.Notification {
			t.Fatal("RecvMsg returned a notification although a handler is set")
		}
		if pieces == 0 {
			first = info.Rcv
		} else if info.Rcv != first {
			t.Fatalf("piece %d has RcvInfo %+v, the first had %+v", pieces, info.Rcv, first)
		}
		got = append(got, buf[:n]...)
		pieces++
		if info.EOR {
			break
		}
	}
	if pieces < 2 || !bytes.Equal(got, want) || first.Stream != 5 || first.PPID != 0xaabbccdd {
		t.Fatalf("%d pieces, %d bytes, RcvInfo %+v; want the %d-byte message in several pieces", pieces, len(got), first, len(want))
	}
	select {
	case id := <-upID:
		if id != first.AssocID {
			t.Errorf("the handler saw association %d, the message came on %d", id, first.AssocID)
		}
	case <-time.After(endpointWait):
		t.Fatal("the handler did not receive AssocCommUp")
	}

	rawFd(t, mustEndpointRawConn(t, server), func(fd int) {
		if err := setIntOpt(fd, ipprotoSCTP, optRecvRcvInfo, 0); err != nil {
			t.Fatalf("switching SCTP_RECVRCVINFO off: %v", err)
		}
	})
	missing := []byte("no receive metadata")
	if _, err := client.SendMsg(clientID, missing, SendOptions{}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	big := make([]byte, 256)
	n, info, err := server.RecvMsg(big)
	wantOp(t, "RecvMsg of data without SCTP_RCVINFO", "read", err, ErrMissingRcvInfo)
	if !bytes.Equal(big[:n], missing) || !info.EOR || info.Rcv != (RcvInfo{}) {
		t.Errorf("RecvMsg without SCTP_RCVINFO = %q, %+v; want the bytes, EOR and a zero Rcv", big[:n], info)
	}
}

// TestEndpointHandlerReassemblesNotificationWithTinyBuffer: with a one-byte
// buffer, the AssocCommUp record arrives in pieces; RecvMsg reassembles it,
// hands it to the handler once, whole, and then returns the next message
// (v1 TestSCTPEndpointHandlerReassemblesNotificationWithTinyBuffer).
func TestEndpointHandlerReassemblesNotificationWithTinyBuffer(t *testing.T) {
	type handled struct {
		id AssocID
		up bool
	}
	got := make(chan handled, 4)
	server := listenEndpoint(t, &Config{NotificationHandler: func(n Notification) error {
		if ac, ok := n.(*AssocChange); ok {
			got <- handled{ac.AssocID, ac.State == AssocCommUp}
		}
		return nil
	}}, "sctp4", loopback4(0))
	client := openEndpoint(t, nil, "sctp4", loopback4(0))
	id, err := client.Connect(endpointAddr(t, server))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	awaitCommUp(t, client)
	if _, err := client.SendMsg(id, []byte{'x'}, SendOptions{}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	setEndpointReadDeadline(t, server, endpointWait)
	buf := make([]byte, 1)
	n, info, err := server.RecvMsg(buf)
	if err != nil || n != 1 || buf[0] != 'x' || info.Notification || !info.EOR {
		t.Fatalf("RecvMsg with a one-byte buffer = %d %q, %+v, %v", n, buf[:n], info, err)
	}
	select {
	case h := <-got:
		if !h.up || h.id != info.Rcv.AssocID {
			t.Errorf("the handler got %+v, want AssocCommUp for association %d", h, info.Rcv.AssocID)
		}
	case <-time.After(endpointWait):
		t.Fatal("the handler did not receive the reassembled AssocCommUp")
	}
	select {
	case h := <-got:
		t.Errorf("the handler ran again, with %+v", h)
	default:
	}
}

// TestEndpointRecvMsgReportsScriptedRcvInfo: an SCTP_RCVINFO that names a
// scope selector is reported with ErrInvalidRcvInfo, and data with none
// with ErrMissingRcvInfo, on the receive path itself, with the bytes read
// and a zero Rcv; a good record after them is returned normally. Linux
// never sends the first, so the kernel's side is scripted.
func TestEndpointRecvMsgReportsScriptedRcvInfo(t *testing.T) {
	e := scriptEndpoint(t, nil)
	sel := &RcvInfo{AssocID: assocScopeAll, Stream: 4}
	good := &RcvInfo{AssocID: 9, Stream: 4}
	script := &recvScript{steps: []recvStep{
		{data: []byte("selector"), rcv: sel, flags: msgEOR},
		{data: []byte("bare"), flags: msgEOR},
		{data: []byte("good"), rcv: good, flags: msgEOR},
	}, done: syscall.EAGAIN}
	hookRecvmsg(t, script.recvmsg)
	setEndpointReadDeadline(t, e, endpointWait)
	buf := make([]byte, 64)
	n, info, err := e.RecvMsg(buf)
	wantOp(t, "RecvMsg with a scope selector", "read", err, ErrInvalidRcvInfo)
	if string(buf[:n]) != "selector" || info.Rcv != (RcvInfo{}) || !info.EOR {
		t.Errorf("RecvMsg with a scope selector = %q, %+v", buf[:n], info)
	}
	n, info, err = e.RecvMsg(buf)
	wantOp(t, "RecvMsg with no SCTP_RCVINFO", "read", err, ErrMissingRcvInfo)
	if string(buf[:n]) != "bare" || info.Rcv != (RcvInfo{}) {
		t.Errorf("RecvMsg with no SCTP_RCVINFO = %q, %+v", buf[:n], info)
	}
	n, info, err = e.RecvMsg(buf)
	if err != nil || string(buf[:n]) != "good" || info.Rcv.AssocID != 9 || info.Rcv.Stream != 4 {
		t.Errorf("RecvMsg of a good record = %q, %+v, %v", buf[:n], info, err)
	}
}

// TestEndpointRecvMsgHasNoAssociationEnd: an Endpoint has no latch and no
// end of stream: an AssocCommLost or AssocShutdownComplete record is
// delivered like any other and changes nothing for the reads after it,
// which go on to the next association's messages, and a failed read's
// error belongs to that read alone (Linux never sets the socket error of
// a one-to-many socket: net/sctp/sm_sideeffect.c, sctp_cmd_set_sk_err).
func TestEndpointRecvMsgHasNoAssociationEnd(t *testing.T) {
	e := scriptEndpoint(t, nil)
	script := &recvScript{steps: []recvStep{
		{data: assocChangeRecord(AssocCommLost, 7, nil), flags: msgNotification | msgEOR},
		{err: syscall.ECONNRESET},
		{data: []byte("after the loss"), rcv: &RcvInfo{AssocID: 8}, flags: msgEOR},
		{data: assocChangeRecord(AssocShutdownComplete, 8, nil), flags: msgNotification | msgEOR},
		{err: syscall.EAGAIN},
		{data: []byte("after the end"), rcv: &RcvInfo{AssocID: 9}, flags: msgEOR},
	}, done: syscall.EAGAIN}
	hookRecvmsg(t, script.recvmsg)
	setEndpointReadDeadline(t, e, endpointWait)
	buf := make([]byte, 256)
	n, info, err := e.RecvMsg(buf)
	if err != nil || !info.Notification {
		t.Fatalf("first RecvMsg = %+v, %v; want the AssocCommLost record", info, err)
	}
	if ac, err := ParseNotification(buf[:n]); err != nil || ac.(*AssocChange).State != AssocCommLost {
		t.Fatalf("first record = %v, %v", ac, err)
	}
	_, _, err = e.RecvMsg(buf)
	wantOp(t, "the read that got ECONNRESET", "read", err, syscall.ECONNRESET)
	if n, info, err = e.RecvMsg(buf); err != nil || string(buf[:n]) != "after the loss" || info.Rcv.AssocID != 8 {
		t.Fatalf("the read after the error = %q, %+v, %v; want the next message, the error being that read's alone", buf[:n], info, err)
	}
	if _, info, err = e.RecvMsg(buf); err != nil || !info.Notification {
		t.Fatalf("RecvMsg = %+v, %v; want the AssocShutdownComplete record", info, err)
	}
	done := make(chan error, 1)
	go func() {
		n, info, err := e.RecvMsg(buf)
		if err == nil && (string(buf[:n]) != "after the end" || info.Rcv.AssocID != 9) {
			err = fmt.Errorf("got %q, %+v", buf[:n], info)
		}
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("a read after AssocShutdownComplete returned %v at once; an Endpoint has no end of stream", err)
	default:
	}
	wakeScriptedEndpoint(t, e)
	if err := <-done; err != nil {
		t.Fatalf("the parked read: %v", err)
	}
}

// --- ending associations -------------------------------------------------------

// TestEndpointAssocLifecycleLeavesOthersOpen: CloseAssoc shuts one
// association down gracefully and AbortAssoc aborts another, carrying the
// caller's cause in the ABORT's User-Initiated Abort error cause (RFC 6458
// §5.3.4; RFC 9260 §3.3.10.12), each leaving every other association and
// the endpoint as they were (v1
// TestSCTPEndpointAssociationLifecycleLeavesOtherAssociationsOpen).
func TestEndpointAssocLifecycleLeavesOthersOpen(t *testing.T) {
	servers := []*Endpoint{
		listenEndpoint(t, nil, "sctp4", loopback4(0)),
		listenEndpoint(t, nil, "sctp4", loopback4(0)),
	}
	client := openEndpoint(t, nil, "sctp4", loopback4(0))
	clientIDs := make([]AssocID, 2)
	serverIDs := make([]AssocID, 2)
	for i, s := range servers {
		var err error
		if clientIDs[i], err = client.Connect(endpointAddr(t, s)); err != nil {
			t.Fatalf("Connect %d: %v", i, err)
		}
		serverIDs[i] = awaitCommUp(t, s).AssocID
	}
	awaitCommUp(t, client)
	awaitCommUp(t, client)

	if err := client.CloseAssoc(clientIDs[0]); err != nil {
		t.Fatalf("CloseAssoc: %v", err)
	}
	awaitAssocState(t, client, clientIDs[0], AssocShutdownComplete)
	awaitAssocState(t, servers[0], serverIDs[0], AssocShutdownComplete)
	// An association's end is not the endpoint's: a read with nothing
	// queued waits, rather than reporting the end of a stream.
	setEndpointReadDeadline(t, client, 100*time.Millisecond)
	_, _, err := client.RecvMsg(make([]byte, 64))
	wantOp(t, "RecvMsg after one association ended", "read", err, os.ErrDeadlineExceeded)

	if _, err := client.SendMsg(clientIDs[1], []byte("still open"), SendOptions{}); err != nil {
		t.Fatalf("SendMsg on the other association: %v", err)
	}
	if got, info := endpointData(t, servers[1]); string(got) != "still open" || info.Rcv.AssocID != serverIDs[1] {
		t.Fatalf("the other association delivered %q on %d", got, info.Rcv.AssocID)
	}

	cause := []byte{0xde, 0xad, 0xbe, 0xef, 0x01}
	if err := client.AbortAssoc(clientIDs[1], cause); err != nil {
		t.Fatalf("AbortAssoc: %v", err)
	}
	lost := awaitAssocState(t, servers[1], serverIDs[1], AssocCommLost)
	if lost.Error != CauseUserAbort {
		t.Errorf("AssocCommLost cause %v, want CauseUserAbort", lost.Error)
	}
	setEndpointReadDeadline(t, servers[1], 100*time.Millisecond)
	_, _, err = servers[1].RecvMsg(make([]byte, 64))
	wantOp(t, "RecvMsg after the association was lost", "read", err, os.ErrDeadlineExceeded)
	// Info holds the ABORT's causes: one User-Initiated Abort cause (code
	// 12) whose information is the caller's cause.
	if len(lost.Info) < 4+len(cause) || binary.BigEndian.Uint16(lost.Info) != 12 || !bytes.Equal(lost.Info[4:4+len(cause)], cause) {
		t.Errorf("AssocCommLost Info = %x, want a User-Initiated Abort cause carrying %x", lost.Info, cause)
	}
	deadline := time.Now().Add(endpointWait)
	for {
		n, err := client.AssocCount()
		if err != nil {
			t.Fatalf("AssocCount: %v", err)
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the client still has %d associations", n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	// The endpoint itself is still usable.
	id, err := client.Connect(endpointAddr(t, servers[0]))
	if err != nil {
		t.Fatalf("Connect after both associations ended: %v", err)
	}
	awaitAssocState(t, client, id, AssocCommUp)
	if _, err := client.SendMsg(id, []byte("again"), SendOptions{}); err != nil {
		t.Fatalf("SendMsg on the new association: %v", err)
	}
	if got, _ := endpointData(t, servers[0]); string(got) != "again" {
		t.Fatalf("the new association delivered %q", got)
	}
}

// TestEndpointEndAssocRefusals: CloseAssoc and AbortAssoc refuse a scope
// selector before any system call, fail with the kernel's EPIPE for an id
// the endpoint does not hold (net/sctp/socket.c: sctp_sendmsg), and
// AbortAssoc refuses a cause longer than one ABORT chunk can carry.
func TestEndpointEndAssocRefusals(t *testing.T) {
	_, client, _, clientID := endpointPair(t, nil, nil)
	calls := countSendmsg(t)
	for _, id := range []AssocID{-1, 0, 1, 2} {
		wantOp(t, "CloseAssoc of a selector", "close", client.CloseAssoc(id), syscall.EINVAL)
		wantOp(t, "AbortAssoc of a selector", "close", client.AbortAssoc(id, nil), syscall.EINVAL)
	}
	err := client.AbortAssoc(clientID, make([]byte, maxAbortCause+1))
	wantOp(t, "AbortAssoc with an oversized cause", "close", err, syscall.EINVAL)
	if !strings.Contains(err.Error(), strconv.Itoa(maxAbortCause)) {
		t.Errorf("the refusal %q does not name the limit", err)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d sendmsg calls for refused ends, want none", n)
	}
	wantOp(t, "CloseAssoc of an unknown id", "close", client.CloseAssoc(clientID+1000), syscall.EPIPE)
	wantOp(t, "AbortAssoc of an unknown id", "close", client.AbortAssoc(clientID+1000, []byte("x")), syscall.EPIPE)
	// The longest cause fits.
	if err := client.AbortAssoc(clientID, make([]byte, maxAbortCause)); err != nil {
		t.Errorf("AbortAssoc with a %d-byte cause: %v", maxAbortCause, err)
	}
}

// TestEndpointAbortAssocCauseOverSendBuffer: Linux weighs an SCTP_ABORT
// send's cause against the socket's send buffer before it looks at the
// flag (net/sctp/socket.c: sctp_sendmsg_parse), so a cause the package
// accepts but longer than the send buffer fails with EMSGSIZE, and the
// association is left as it was.
func TestEndpointAbortAssocCauseOverSendBuffer(t *testing.T) {
	server, client, _, clientID := endpointPair(t, nil, &Config{WriteBuffer: new(4096)})
	sndbuf := getIntOpt(t, mustEndpointRawConn(t, client), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if sndbuf+1 > maxAbortCause {
		t.Skipf("the send buffer is %d bytes, not below the %d-byte cause limit", sndbuf, maxAbortCause)
	}
	err := client.AbortAssoc(clientID, make([]byte, sndbuf+1))
	wantOp(t, "AbortAssoc with a cause over the send buffer", "close", err, syscall.EMSGSIZE)
	if _, err := client.SendMsg(clientID, []byte("still open"), SendOptions{}); err != nil {
		t.Fatalf("SendMsg after the refused ABORT: %v", err)
	}
	if got, _ := endpointData(t, server); string(got) != "still open" {
		t.Fatalf("received %q", got)
	}
	if err := client.AbortAssoc(clientID, make([]byte, sndbuf)); err != nil {
		t.Errorf("AbortAssoc with a %d-byte cause, the send buffer's size: %v", sndbuf, err)
	}
}

// TestEndpointCloseGracefullyEndsEveryAssociation: Close shuts down every
// association the endpoint holds and returns as soon as they are gone,
// well before its grace period, and each peer sees the graceful end (v1
// TestSCTPEndpointCloseGracefullyTerminatesEveryAssociation).
func TestEndpointCloseGracefullyEndsEveryAssociation(t *testing.T) {
	servers := []*Endpoint{
		listenEndpoint(t, nil, "sctp4", loopback4(0)),
		listenEndpoint(t, nil, "sctp4", loopback4(0)),
	}
	client := openEndpoint(t, nil, "sctp4", loopback4(0))
	serverIDs := make([]AssocID, 2)
	for i, s := range servers {
		if _, err := client.Connect(endpointAddr(t, s)); err != nil {
			t.Fatalf("Connect %d: %v", i, err)
		}
		serverIDs[i] = awaitCommUp(t, s).AssocID
	}
	awaitCommUp(t, client)
	awaitCommUp(t, client)
	start := time.Now()
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Close took %v with two peers that answer", d)
	}
	for i, s := range servers {
		awaitAssocState(t, s, serverIDs[i], AssocShutdownComplete)
	}
	wantOp(t, "a second Close", "close", client.Close(), net.ErrClosed)
	wantOp(t, "Abort after Close", "close", client.Abort(), net.ErrClosed)
}

// stalledEndpoint connects e to two one-to-one peers, opened with
// peerCfg, that do not read, and fills e's send buffer with messages to
// both for good (fillEndpointStable), so that neither SHUTDOWN can
// complete while the peers do not read: each waits behind data the peer's
// zero window will not take (RFC 9260 §9.2), and no send can find room.
// It returns the two peers and their listeners, which are closed on
// cleanup unless the test closes them first.
func stalledEndpoint(t *testing.T, e *Endpoint, peerCfg *Config) ([]*Conn, []*Listener) {
	t.Helper()
	var (
		peers     []*Conn
		listeners []*Listener
	)
	byID := map[AssocID]*Conn{}
	for range 2 {
		l := mustListen(t, peerCfg, "sctp4", loopback4(0))
		listeners = append(listeners, l)
		id, err := e.Connect(listenerAddr(t, l))
		if err != nil {
			t.Fatalf("Connect: %v", err)
		}
		c, err := l.AcceptSCTP()
		if err != nil {
			t.Fatalf("AcceptSCTP: %v", err)
		}
		t.Cleanup(func() { _ = c.Abort() })
		awaitCommUp(t, e)
		peers, byID[id] = append(peers, c), c
	}
	fillEndpointStable(t, e, byID, fill(512))
	return peers, listeners
}

// TestEndpointCloseAbortOvertakes: an Endpoint Close waiting for two
// SHUTDOWN handshakes that cannot complete is ended by an Abort from
// another goroutine: both return nil well before the grace period, and
// every peer sees the ABORT.
func TestEndpointCloseAbortOvertakes(t *testing.T) {
	e := openEndpoint(t, &Config{CloseTimeout: 10 * time.Second}, "sctp4", loopback4(0))
	peers, _ := stalledEndpoint(t, e, &Config{ReadBuffer: new(4096)})
	done := make(chan error, 1)
	go func() { done <- e.Close() }()
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-done:
		t.Fatalf("Close returned %v before the Abort, although no handshake can complete", err)
	default:
	}
	start := time.Now()
	if err := e.Abort(); err != nil {
		t.Fatalf("Abort during Close = %v, want nil", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("the overtaken Close = %v, want nil", err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("Close returned %v after the Abort", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close was still waiting 3 s after Abort")
	}
	for i, p := range peers {
		setReadDeadline(t, p, endpointWait)
		for {
			_, err := p.Read(make([]byte, 1024))
			if err == nil {
				continue // the data that did get through
			}
			if !errors.Is(err, syscall.ECONNRESET) {
				t.Errorf("peer %d ended with %v, want ECONNRESET from the ABORT", i, err)
			}
			break
		}
	}
	wantOp(t, "a second Abort", "close", e.Abort(), net.ErrClosed)
}

// TestEndpointCloseTimeoutBoundsTheWait: against peers that cannot answer,
// Close spends Config.CloseTimeout and then aborts.
func TestEndpointCloseTimeoutBoundsTheWait(t *testing.T) {
	const grace = 700 * time.Millisecond
	e := openEndpoint(t, &Config{CloseTimeout: grace}, "sctp4", loopback4(0))
	_, _ = stalledEndpoint(t, e, &Config{ReadBuffer: new(4096)})
	start := time.Now()
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if d := time.Since(start); d < grace/2 || d > 4*grace {
		t.Errorf("Close took %v against a %v grace period", d, grace)
	}
}

// TestEndpointCloseDrainsBackpressuredAssociations: with the send buffer
// full, Close still makes each association's SCTP_EOF send at once, since
// that send never waits for buffer space (net/sctp/socket.c:
// sctp_sendmsg_check_sflags starts the SHUTDOWN primitive before
// sctp_sendmsg_to_asoc, the only path that waits): both associations are
// in SHUTDOWN-PENDING before the peers read a byte. Peers that then read
// receive every queued message, then the end of the stream, and Close
// returns before its grace period.
func TestEndpointCloseDrainsBackpressuredAssociations(t *testing.T) {
	const grace = 5 * time.Second
	e := openEndpoint(t, &Config{CloseTimeout: grace, WriteBuffer: new(1 << 20)}, "sctp4", loopback4(0))
	// Peers with a receive window small enough for the messages to close
	// and large enough that reading reopens it at once
	// (closingReadBuffer), and a send buffer larger than both windows.
	peers, _ := stalledEndpoint(t, e, &Config{ReadBuffer: new(closingReadBuffer)})
	ids, err := e.AssocIDs()
	if err != nil || len(ids) != 2 {
		t.Fatalf("AssocIDs = %v, %v", ids, err)
	}
	rc := mustEndpointRawConn(t, e)
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- e.Close() }()
	for _, id := range ids {
		for {
			var st [sizeStatus]byte
			binary.NativeEndian.PutUint32(st[statusAssocIDOff:], uint32(id))
			var serr error
			if err := rc.Control(func(fd uintptr) {
				l := uint32(len(st))
				serr = rawGetsockopt(int(fd), ipprotoSCTP, optStatus, unsafe.Pointer(&st[0]), &l)
			}); err != nil {
				t.Fatalf("Control: %v", err)
			}
			if serr != nil {
				t.Fatalf("SCTP_STATUS of association %d: %v", id, serr)
			}
			if AssocState(int32(binary.NativeEndian.Uint32(st[statusStateOff:]))) == StateShutdownPending {
				break
			}
			if time.Since(start) > time.Second {
				t.Fatalf("association %d is not in SHUTDOWN-PENDING 1 s after Close started: its SCTP_EOF send waited", id)
			}
			time.Sleep(time.Millisecond)
		}
	}
	var wg sync.WaitGroup
	for i, p := range peers {
		wg.Go(func() {
			setReadDeadline(t, p, grace)
			buf := make([]byte, 1024)
			for {
				n, err := p.Read(buf)
				if err == io.EOF {
					return
				}
				if err != nil {
					t.Errorf("peer %d: %v, want the queued messages and then io.EOF", i, err)
					return
				}
				if n != 512 {
					t.Errorf("peer %d read %d bytes, want 512", i, n)
				}
			}
		})
	}
	wg.Wait()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(grace + time.Second):
		t.Fatal("Close did not return after the peers drained")
	}
	if d := time.Since(start); d >= grace {
		t.Errorf("Close took %v, its whole grace period", d)
	}
}

// TestEndpointCloseReleasesParkedCalls: Close from one goroutine while
// another is parked in RecvMsg and a third in a SendMsg on a full buffer:
// both parked calls return with net.ErrClosed within a second of Close
// returning, and the descriptor count is back where it started (v1
// TestSCTPEndpointErrorsDeadlinesAndCloseWakeup, and the Endpoint's
// version of the parked-call case every Conn has).
func TestEndpointCloseReleasesParkedCalls(t *testing.T) {
	before := openFds(t)
	func() {
		e, err := (&Config{CloseTimeout: 300 * time.Millisecond}).OpenEndpoint("sctp4", loopback4(0))
		if err != nil {
			t.Fatalf("OpenEndpoint: %v", err)
		}
		peers, listeners := stalledEndpoint(t, e, &Config{ReadBuffer: new(4096)})
		ids, err := e.AssocIDs()
		if err != nil || len(ids) != 2 {
			t.Fatalf("AssocIDs = %v, %v", ids, err)
		}
		readDone := make(chan error, 1)
		go func() {
			_, _, err := e.RecvMsg(make([]byte, 64))
			readDone <- err
		}()
		writeDone := make(chan error, 1)
		go func() {
			_, err := e.SendMsg(ids[0], fill(512), SendOptions{})
			writeDone <- err
		}()
		time.Sleep(100 * time.Millisecond)
		if err := e.Close(); err != nil {
			t.Fatalf("Close = %v, want nil", err)
		}
		closed := time.Now()
		// The parked send is for an association Close shuts down, so it
		// can end before the release, with the ESHUTDOWN any send gets
		// once a shutdown has started (net/sctp/sm_statetable.c:
		// sctp_sf_error_shutdown); otherwise the release ends it.
		for name, ch := range map[string]chan error{"RecvMsg": readDone, "SendMsg": writeDone} {
			select {
			case err := <-ch:
				var opErr *net.OpError
				released := errors.Is(err, net.ErrClosed) || (name == "SendMsg" && errors.Is(err, syscall.ESHUTDOWN))
				if !errors.As(err, &opErr) || !released {
					t.Errorf("parked %s = %v, want a *net.OpError matching net.ErrClosed", name, err)
				}
				if d := time.Since(closed); d > time.Second {
					t.Errorf("parked %s returned %v after Close", name, d)
				}
			case <-time.After(time.Second):
				t.Fatalf("parked %s was still waiting 1 s after Close returned", name)
			}
		}
		for _, p := range peers {
			_ = p.Abort()
		}
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	if after := openFds(t); after != before {
		t.Errorf("descriptor count went %d -> %d", before, after)
	}
}

// TestEndpointMethodsAfterClose: after Close every method reports a
// closed socket, as a *net.OpError matching net.ErrClosed, and a
// SyscallConn taken before runs no callback (v1
// TestSCTPEndpointErrorsDeadlinesAndCloseWakeup,
// TestSCTPEndpointRawAccessDynamicBindAndEndpointOptions).
func TestEndpointMethodsAfterClose(t *testing.T) {
	e := listenEndpoint(t, nil, "sctp4", loopback4(0))
	rc := mustEndpointRawConn(t, e)
	addr := endpointAddr(t, e)
	if err := e.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	ip := netip.MustParseAddr("127.0.0.1")
	for name, call := range endpointCalls(e, ip) {
		err := call()
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s after Close = %v, want net.ErrClosed", name, err)
			continue
		}
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr.Err != net.ErrClosed {
			t.Errorf("%s after Close = %#v, want a *net.OpError around the bare net.ErrClosed", name, err)
		}
	}
	called := false
	if err := rc.Control(func(uintptr) { called = true }); !errors.Is(err, net.ErrClosed) || called {
		t.Errorf("a SyscallConn taken before Close: Control = %v, callback ran %v; want net.ErrClosed and no call", err, called)
	}
	if a := e.Addr().(*Addr); a.Port != addr.Port {
		t.Errorf("Addr after Close = %v, want the snapshot %v", a, addr)
	}
	if e.Network() != "sctp4" {
		t.Errorf("Network after Close = %q", e.Network())
	}
}

// endpointCalls is every Endpoint method that can fail, as a call.
func endpointCalls(e *Endpoint, ip netip.Addr) map[string]func() error {
	return map[string]func() error{
		"Connect":          func() error { _, err := e.Connect(loopback4(9)); return err },
		"SendMsg":          func() error { _, err := e.SendMsg(3, []byte("x"), SendOptions{}); return err },
		"RecvMsg":          func() error { _, _, err := e.RecvMsg(make([]byte, 8)); return err },
		"PeelOff":          func() error { _, err := e.PeelOff(3); return err },
		"CloseAssoc":       func() error { return e.CloseAssoc(3) },
		"AbortAssoc":       func() error { return e.AbortAssoc(3, nil) },
		"AssocIDs":         func() error { _, err := e.AssocIDs(); return err },
		"AssocCount":       func() error { _, err := e.AssocCount(); return err },
		"LocalAddrs":       func() error { _, err := e.LocalAddrs(3); return err },
		"PeerAddrs":        func() error { _, err := e.PeerAddrs(3); return err },
		"AutoClose":        func() error { _, err := e.AutoClose(); return err },
		"SetAutoClose":     func() error { return e.SetAutoClose(time.Second) },
		"BindAdd":          func() error { return e.BindAdd(ip) },
		"BindRemove":       func() error { return e.BindRemove(ip) },
		"SetDeadline":      func() error { return e.SetDeadline(time.Now()) },
		"SetReadDeadline":  func() error { return e.SetReadDeadline(time.Now()) },
		"SetWriteDeadline": func() error { return e.SetWriteDeadline(time.Now()) },
		"Close":            e.Close,
		"Abort":            e.Abort,
		"SyscallConn":      func() error { _, err := e.SyscallConn(); return err },
	}
}

// TestNilEndpointMethodsReportClosed: a nil *Endpoint, and a zero one the
// package never opened, report a closed socket from every method instead
// of panicking (v1 TestNilSCTPEndpointMethodsReportClosed).
func TestNilEndpointMethodsReportClosed(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.1")
	for kind, e := range map[string]*Endpoint{"nil": nil, "zero": new(Endpoint)} {
		if e.Addr() != nil {
			t.Errorf("%s Endpoint Addr = %v, want nil", kind, e.Addr())
		}
		for name, call := range endpointCalls(e, ip) {
			if err := call(); !errors.Is(err, net.ErrClosed) {
				t.Errorf("%s Endpoint.%s = %v, want net.ErrClosed", kind, name, err)
			}
		}
	}
}

// TestEndpointSelectorsRefused: every method that takes an association id
// refuses a scope selector or a negative id with EINVAL before any system
// call, and PeelOff of an id the endpoint does not hold gets the kernel's
// EINVAL (net/sctp/socket.c: sctp_do_peeloff).
func TestEndpointSelectorsRefused(t *testing.T) {
	e := listenEndpoint(t, nil, "sctp4", loopback4(0))
	calls := countSockopts(t)
	for _, id := range []AssocID{math.MinInt32, -1, 0, 1, 2} {
		for name, call := range map[string]func() error{
			"PeelOff":    func() error { _, err := e.PeelOff(id); return err },
			"LocalAddrs": func() error { _, err := e.LocalAddrs(id); return err },
			"PeerAddrs":  func() error { _, err := e.PeerAddrs(id); return err },
		} {
			// The package's own refusal names the method; the kernel's
			// EINVAL, for an id it cannot find, would not.
			if err := call(); !errors.Is(err, syscall.EINVAL) || !strings.Contains(err.Error(), name+": association id") {
				t.Errorf("%s(%d) = %v, want the package's refusal matching EINVAL", name, id, err)
			}
		}
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d socket option calls for refused ids, want none", n)
	}
	c, err := e.PeelOff(999999999)
	if c != nil {
		_ = c.Abort()
	}
	op := opOf(t, "PeelOff of an unknown id", "peeloff", err, syscall.EINVAL)
	if op.Addr == nil {
		t.Error("the PeelOff error names no address")
	}
	_, err = e.LocalAddrs(999999999)
	wantOp(t, "LocalAddrs of an unknown id", "get", err, syscall.EINVAL)
	_, err = e.PeerAddrs(999999999)
	wantOp(t, "PeerAddrs of an unknown id", "get", err, syscall.EINVAL)
}

// --- options, addresses and raw access -----------------------------------------

// TestEndpointAutoClose: AutoClose starts at 0 (RFC 6458 §8.1.8), reads
// back what SetAutoClose set in whole seconds, and refuses a negative
// value, one that is not a whole second or one beyond the kernel's u32
// before any system call.
func TestEndpointAutoClose(t *testing.T) {
	e := listenEndpoint(t, nil, "sctp4", loopback4(0))
	if d, err := e.AutoClose(); err != nil || d != 0 {
		t.Fatalf("AutoClose = %v, %v; want 0", d, err)
	}
	if err := e.SetAutoClose(2 * time.Second); err != nil {
		t.Fatalf("SetAutoClose(2s): %v", err)
	}
	if d, err := e.AutoClose(); err != nil || d != 2*time.Second {
		t.Fatalf("AutoClose = %v, %v; want 2s", d, err)
	}
	if err := e.SetAutoClose(0); err != nil {
		t.Fatalf("SetAutoClose(0): %v", err)
	}
	if d, err := e.AutoClose(); err != nil || d != 0 {
		t.Fatalf("AutoClose after 0 = %v, %v", d, err)
	}
	calls := countSockopts(t)
	for _, d := range []time.Duration{-time.Second, 1500 * time.Millisecond, time.Duration(math.MaxUint32+1) * time.Second} {
		wantOp(t, fmt.Sprintf("SetAutoClose(%v)", d), "set", e.SetAutoClose(d), syscall.EINVAL)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d socket option calls for refused values, want none", n)
	}
}

// TestEndpointAutoCloseCappedByTheKernel: a value above
// net.sctp.max_autoclose is accepted, and AutoClose reports the capped
// value in force (net/sctp/socket.c: sctp_setsockopt_autoclose).
func TestEndpointAutoCloseCappedByTheKernel(t *testing.T) {
	limit, err := strconv.ParseUint(readSysctl(t, "max_autoclose"), 10, 64)
	if err != nil {
		t.Fatalf("net.sctp.max_autoclose: %v", err)
	}
	if limit >= math.MaxUint32 {
		t.Skipf("net.sctp.max_autoclose is %d, which no u32 exceeds", limit)
	}
	e := listenEndpoint(t, nil, "sctp4", loopback4(0))
	if err := e.SetAutoClose(time.Duration(limit+1) * time.Second); err != nil {
		t.Fatalf("SetAutoClose above the limit: %v", err)
	}
	if d, err := e.AutoClose(); err != nil || d != time.Duration(limit)*time.Second {
		t.Errorf("AutoClose = %v, %v; want the kernel's cap, %ds", d, err, limit)
	}
}

// TestEndpointAutoCloseEndsIdleAssociations: an association set up after
// SetAutoClose, and idle for the autoclose time, is shut down gracefully by
// the kernel (RFC 6458 §8.1.8), and the endpoint reports it with
// AssocShutdownComplete, while one set up before keeps the value it
// started with (net/sctp/associola.c: sctp_association_init).
func TestEndpointAutoCloseEndsIdleAssociations(t *testing.T) {
	server := listenEndpoint(t, nil, "sctp4", loopback4(0))
	before, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, endpointAddr(t, server))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = before.Abort() }()
	beforeID := awaitCommUp(t, server).AssocID
	if err := server.SetAutoClose(time.Second); err != nil {
		t.Fatalf("SetAutoClose: %v", err)
	}
	after, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, endpointAddr(t, server))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = after.Abort() }()
	afterID := awaitCommUp(t, server).AssocID
	start := time.Now()
	awaitAssocState(t, server, afterID, AssocShutdownComplete)
	if d := time.Since(start); d < 500*time.Millisecond {
		t.Errorf("the idle association closed after %v, before its autoclose time", d)
	}
	setReadDeadline(t, after, endpointWait)
	if _, err := after.Read(make([]byte, 16)); err != io.EOF {
		t.Errorf("the peer of the closed association read %v, want io.EOF", err)
	}
	if ids, err := server.AssocIDs(); err != nil || len(ids) != 1 || ids[0] != beforeID {
		t.Errorf("AssocIDs = %v, %v; want only the association set up before SetAutoClose", ids, err)
	}
}

// TestEndpointBindAddRemove: BindAdd and BindRemove change the endpoint's
// bound addresses on its port, and Addr follows them, as a copy the
// caller may change; the socket is SOCK_SEQPACKET and close-on-exec (v1
// TestSCTPEndpointRawAccessDynamicBindAndEndpointOptions).
func TestEndpointBindAddRemove(t *testing.T) {
	loops := requireLoopbacks(t, 2)
	e := listenEndpoint(t, nil, "sctp4", addrOf(0, loops[0]))
	if n, err := e.AssocCount(); err != nil || n != 0 {
		t.Fatalf("AssocCount of a fresh endpoint = %d, %v", n, err)
	}
	if ids, err := e.AssocIDs(); err != nil || ids == nil || len(ids) != 0 {
		t.Fatalf("AssocIDs of a fresh endpoint = %#v, %v; want a non-nil empty slice", ids, err)
	}
	rawFd(t, mustEndpointRawConn(t, e), func(fd int) {
		if typ, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE); err != nil || typ != syscall.SOCK_SEQPACKET {
			t.Errorf("SO_TYPE = %d, %v; want SOCK_SEQPACKET", typ, err)
		}
		if !isCloseOnExec(fd) {
			t.Error("the endpoint descriptor is not close-on-exec")
		}
	})
	initial := endpointAddr(t, e)
	extra := netip.MustParseAddr(loops[1])
	if err := e.BindAdd(extra); err != nil {
		t.Fatalf("BindAdd: %v", err)
	}
	bound := endpointAddr(t, e)
	if bound.Port != initial.Port || !equalStrings(ipStrings(bound), sortedCopy(loops[:2])) {
		t.Fatalf("Addr after BindAdd = %v, want %v on port %d", bound, loops[:2], initial.Port)
	}
	bound.IPs[0] = netip.MustParseAddr("10.9.9.9")
	if fresh := endpointAddr(t, e); !equalStrings(ipStrings(fresh), sortedCopy(loops[:2])) {
		t.Fatalf("Addr after the caller changed an earlier copy = %v", fresh)
	}
	if err := e.BindRemove(extra); err != nil {
		t.Fatalf("BindRemove: %v", err)
	}
	if got := endpointAddr(t, e); !equalStrings(ipStrings(got), loops[:1]) {
		t.Fatalf("Addr after BindRemove = %v, want %v", got, loops[:1])
	}
	err := e.BindRemove(netip.MustParseAddr(loops[0]))
	wantOp(t, "BindRemove of the last address", "bindx", err, syscall.EINVAL)
	wantOp(t, "BindAdd of nothing", "bindx", e.BindAdd(), syscall.EINVAL)
}

// TestEndpointBindAddMixedFamilies: an sctp6 endpoint bound to an IPv6
// address takes IPv4 addresses with BindAdd too, passed IPv4-mapped
// (lksctp-tools #32, pysctp #30); Addr reports them in plain form, and
// an IPv4 peer reaches the endpoint through one.
func TestEndpointBindAddMixedFamilies(t *testing.T) {
	loops := requireLoopbacks(t, 2)
	e := listenEndpoint(t, nil, "sctp6", &Addr{IPs: []netip.Addr{netip.IPv6Loopback()}})
	v4 := netip.MustParseAddr(loops[1])
	if err := e.BindAdd(v4, netip.MustParseAddr(loops[0])); err != nil {
		t.Fatalf("BindAdd of IPv4 addresses on an sctp6 endpoint: %v", err)
	}
	bound := endpointAddr(t, e)
	if want := sortedCopy([]string{"::1", loops[0], loops[1]}); !equalStrings(ipStrings(bound), want) {
		t.Fatalf("Addr = %v, want %v, IPv4 in plain form", bound, want)
	}
	client, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, &Addr{IPs: []netip.Addr{v4}, Port: bound.Port})
	if err != nil {
		t.Fatalf("an IPv4 peer dialing %v: %v", v4, err)
	}
	defer func() { _ = client.Abort() }()
	up := awaitCommUp(t, e)
	peer, err := e.PeerAddrs(up.AssocID)
	if err != nil || len(peer.IPs) == 0 || !peer.IPs[0].Is4() {
		t.Errorf("PeerAddrs = %v, %v; want the IPv4 peer in plain form", peer, err)
	}
	if err := e.BindRemove(v4); err != nil {
		t.Fatalf("BindRemove of an IPv4 address: %v", err)
	}
	if want := sortedCopy([]string{"::1", loops[0]}); !equalStrings(ipStrings(endpointAddr(t, e)), want) {
		t.Errorf("Addr after BindRemove = %v, want %v", endpointAddr(t, e), want)
	}
}

// mappedV4Config is a Config whose sockets report IPv4 addresses the way
// mapped asks: IPv4-mapped, which is how Linux starts every socket
// (net/sctp/socket.c: sctp_init_sock sets v4mapped), with no Control at
// all, or in plain AF_INET form, with SCTP_I_WANT_MAPPED_V4_ADDR switched
// off by Control. Accepted and peeled sockets take the option from their
// listening or one-to-many socket (sctp_sock_migrate copies the socket's
// SCTP options).
func mappedV4Config(mapped bool) *Config {
	if mapped {
		return nil
	}
	return &Config{Control: func(_, _ string, rc syscall.RawConn) error {
		var serr error
		if err := rc.Control(func(fd uintptr) {
			serr = setIntOpt(int(fd), ipprotoSCTP, optWantMappedV4Addr, 0)
		}); err != nil {
			return err
		}
		return serr
	}}
}

// wantPlainAddrs fails the test when a holds an IPv4-mapped address, or
// no IPv4 address to check.
func wantPlainAddrs(t testing.TB, what string, a *Addr) {
	t.Helper()
	v4 := false
	for _, ip := range a.IPs {
		if ip.Is4In6() {
			t.Errorf("%s reports %v in IPv4-mapped form", what, ip)
		}
		v4 = v4 || ip.Is4()
	}
	if !v4 {
		t.Errorf("%s = %v, which holds no IPv4 address to check", what, a)
	}
}

// wantPlainIPv4 fails the test unless ip is the plain IPv4 address want.
func wantPlainIPv4(t testing.TB, what string, ip, want netip.Addr) {
	t.Helper()
	if ip != want || !ip.Is4() {
		t.Errorf("%s = %v, want %v in plain IPv4 form", what, ip, want)
	}
}

// TestEndpointAddressesAreNeverMapped: an sctp6 Endpoint reports IPv4
// addresses in plain form from every call that returns an address, its
// own and an IPv4 peer's, whether SCTP_I_WANT_MAPPED_V4_ADDR is on, as
// Linux starts every socket, or switched off through Control: the option
// chooses only the form Linux reports in (net/sctp/ipv6.c:
// sctp_v6_addr_to_user), and the package decodes both.
func TestEndpointAddressesAreNeverMapped(t *testing.T) {
	for _, mapped := range []bool{true, false} {
		t.Run(fmt.Sprintf("mapped=%t", mapped), func(t *testing.T) {
			e := listenEndpoint(t, mappedV4Config(mapped), "sctp6", nil)
			if got := getIntOpt(t, mustEndpointRawConn(t, e), ipprotoSCTP, optWantMappedV4Addr); got != int(boolValue(mapped)) {
				t.Fatalf("SCTP_I_WANT_MAPPED_V4_ADDR = %d, want %t", got, mapped)
			}
			c, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, loopback4(endpointAddr(t, e).Port))
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			t.Cleanup(func() { _ = c.Abort() })
			id := awaitCommUp(t, e).AssocID
			wantPlainAddrs(t, "Addr", endpointAddr(t, e))
			local, err := e.LocalAddrs(id)
			if err != nil {
				t.Fatalf("LocalAddrs: %v", err)
			}
			wantPlainAddrs(t, "LocalAddrs", local)
			peer, err := e.PeerAddrs(id)
			if err != nil {
				t.Fatalf("PeerAddrs: %v", err)
			}
			wantPlainAddrs(t, "PeerAddrs", peer)
		})
	}
}

// mappedConn sets up an association over IPv4 whose side under test, a
// Conn "dialed", "accepted", or "peeled" off an Endpoint, is an AF_INET6
// socket opened with cfg, and returns that Conn and its sctp4 peer.
func mappedConn(t *testing.T, side string, cfg *Config) (c, peer *Conn) {
	t.Helper()
	ctx := testContext(t, 10*time.Second)
	accept := func(l *Listener) <-chan *Conn {
		ch := make(chan *Conn, 1)
		go func() {
			a, err := l.AcceptSCTP()
			if err != nil {
				close(ch)
				return
			}
			ch <- a
		}()
		return ch
	}
	var err error
	switch side {
	case "dialed":
		l := mustListen(t, nil, "sctp4", loopback4(0))
		accepted := accept(l)
		if c, err = cfg.Dial(ctx, "sctp6", nil, listenerAddr(t, l)); err != nil {
			t.Fatalf("Dial sctp6: %v", err)
		}
		peer = <-accepted
	case "accepted":
		l := mustListen(t, cfg, "sctp6", nil)
		accepted := accept(l)
		if peer, err = Dial(ctx, "sctp4", nil, loopback4(listenerAddr(t, l).Port)); err != nil {
			t.Fatalf("Dial sctp4: %v", err)
		}
		c = <-accepted
	case "peeled":
		e := listenEndpoint(t, cfg, "sctp6", nil)
		if peer, err = Dial(ctx, "sctp4", nil, loopback4(endpointAddr(t, e).Port)); err != nil {
			t.Fatalf("Dial sctp4: %v", err)
		}
		if c, err = e.PeelOff(onlyAssoc(t, e)); err != nil {
			t.Fatalf("PeelOff: %v", err)
		}
	default:
		t.Fatalf("unknown side %q", side)
	}
	if c == nil || peer == nil {
		t.Fatal("the association was not set up")
	}
	t.Cleanup(func() { _ = c.Abort(); _ = peer.Abort() })
	return c, peer
}

// TestConnAddressesAreNeverMapped: on a dialed, an accepted and a peeled
// Conn whose AF_INET6 socket carries an association over IPv4, every call
// that returns an address reports IPv4 in plain form, never ::ffff:a.b.c.d,
// whether SCTP_I_WANT_MAPPED_V4_ADDR is on, as Linux starts every socket,
// or off: LocalAddr, RemoteAddr, LocalAddrs, PeerAddrs, PrimaryAddr,
// PathInfo, Status's primary path, Stats's path of the largest observed
// RTO when there is one, and a PeerAddrChange notification. The option
// chooses only the form Linux reports in (net/sctp/ipv6.c:
// sctp_v6_addr_to_user), and the package decodes both.
func TestConnAddressesAreNeverMapped(t *testing.T) {
	loop := netip.MustParseAddr("127.0.0.1")
	for _, mapped := range []bool{true, false} {
		for _, side := range []string{"dialed", "accepted", "peeled"} {
			t.Run(fmt.Sprintf("%s/mapped=%t", side, mapped), func(t *testing.T) {
				c, peer := mappedConn(t, side, mappedV4Config(mapped))
				if c.sock.family != afInet6 {
					t.Fatalf("the %s Conn's socket has family %d, want AF_INET6", side, c.sock.family)
				}
				rc := mustSyscallConn(t, c)
				if got := getIntOpt(t, rc, ipprotoSCTP, optWantMappedV4Addr); got != int(boolValue(mapped)) {
					t.Fatalf("SCTP_I_WANT_MAPPED_V4_ADDR = %d, want %t", got, mapped)
				}
				wantPlainAddrs(t, "LocalAddr", c.LocalAddr().(*Addr))
				wantPlainAddrs(t, "RemoteAddr", c.RemoteAddr().(*Addr))
				local, err := c.LocalAddrs()
				if err != nil {
					t.Fatalf("LocalAddrs: %v", err)
				}
				wantPlainAddrs(t, "LocalAddrs", local)
				peers, err := c.PeerAddrs()
				if err != nil {
					t.Fatalf("PeerAddrs: %v", err)
				}
				wantPlainAddrs(t, "PeerAddrs", peers)
				prim, err := c.PrimaryAddr()
				if err != nil {
					t.Fatalf("PrimaryAddr: %v", err)
				}
				wantPlainIPv4(t, "PrimaryAddr", prim, loop)
				pi, err := c.PathInfo(loop)
				if err != nil {
					t.Fatalf("PathInfo: %v", err)
				}
				wantPlainIPv4(t, "PathInfo", pi.Addr.Addr(), loop)
				st, err := c.Status()
				if err != nil {
					t.Fatalf("Status: %v", err)
				}
				wantPlainIPv4(t, "Status primary path", st.Primary.Addr.Addr(), loop)

				// Round trips give the association RTT measurements, and
				// so a largest observed RTO and its path.
				setReadDeadline(t, c, endpointWait)
				setReadDeadline(t, peer, endpointWait)
				buf := make([]byte, 64)
				for i := range 5 {
					if _, err := c.Write(numbered(i)); err != nil {
						t.Fatalf("Write: %v", err)
					}
					if _, err := peer.Read(buf); err != nil {
						t.Fatalf("peer Read: %v", err)
					}
					if _, err := peer.Write(numbered(i)); err != nil {
						t.Fatalf("peer Write: %v", err)
					}
					if _, err := c.Read(buf); err != nil {
						t.Fatalf("Read: %v", err)
					}
				}
				// Linux copies this address as it keeps it, without the
				// socket's form (net/sctp/socket.c:
				// sctp_getsockopt_assoc_stats), so it is AF_INET here
				// whatever the option says.
				stats, err := c.Stats()
				if err != nil {
					t.Fatalf("Stats: %v", err)
				}
				if !stats.MaxRTOAddr.IsValid() {
					t.Error("Stats reports no path for the largest observed RTO after five round trips")
				} else {
					wantPlainIPv4(t, "Stats MaxRTOAddr", stats.MaxRTOAddr.Addr(), loop)
				}

				// Making the primary path primary again queues an
				// SCTP_ADDR_MADE_PRIM record (net/sctp/associola.c:
				// sctp_assoc_set_primary), whose address Linux reports in
				// the socket's form (net/sctp/ulpevent.c:
				// sctp_ulpevent_make_peer_addr_change).
				if err := c.Subscribe(EventPeerAddrChange, true); err != nil {
					t.Fatalf("Subscribe: %v", err)
				}
				if err := c.SetPrimaryAddr(prim); err != nil {
					t.Fatalf("SetPrimaryAddr: %v", err)
				}
				note := make([]byte, NotificationMaxSize)
				for {
					n, info, err := c.RecvMsg(note)
					if err != nil {
						t.Fatalf("RecvMsg waiting for the PeerAddrChange: %v", err)
					}
					if !info.Notification {
						continue
					}
					parsed, err := ParseNotification(note[:n])
					if err != nil {
						t.Fatalf("ParseNotification: %v", err)
					}
					pac, ok := parsed.(*PeerAddrChange)
					if !ok {
						continue
					}
					if pac.State != AddrMadePrimary {
						t.Errorf("PeerAddrChange state %v, want AddrMadePrimary", pac.State)
					}
					wantPlainIPv4(t, "PeerAddrChange", pac.Addr.Addr(), loop)
					break
				}
			})
		}
	}
}

// TestEndpointSyscallConn: SyscallConn reaches the endpoint's descriptor
// with Control, Read and Write, and Read waits in the poller and follows
// the read deadline.
func TestEndpointSyscallConn(t *testing.T) {
	server, client, _, clientID := endpointPair(t, nil, nil)
	rc := mustEndpointRawConn(t, server)
	if err := server.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	err := rc.Read(func(uintptr) bool { return false })
	wantOp(t, "a raw Read past its deadline", "raw-read", err, os.ErrDeadlineExceeded)
	if err := server.SetReadDeadline(time.Now().Add(endpointWait)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := client.SendMsg(clientID, []byte("raw"), SendOptions{}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	var got []byte
	if err := rc.Read(func(fd uintptr) bool {
		buf := make([]byte, 64)
		n, _, _, _, err := syscall.Recvmsg(int(fd), buf, nil, syscall.MSG_DONTWAIT)
		if err == syscall.EAGAIN {
			return false
		}
		got = buf[:n]
		return true
	}); err != nil || string(got) != "raw" {
		t.Fatalf("raw Read = %q, %v", got, err)
	}
	wrote := false
	if err := rc.Write(func(uintptr) bool { wrote = true; return true }); err != nil || !wrote {
		t.Errorf("raw Write = %v, ran %v", err, wrote)
	}
}

// TestEndpointErrorsCarryContext: every Endpoint error is one *net.OpError
// naming the operation and the network, with the endpoint's addresses
// where it has them, built only when there is an error.
func TestEndpointErrorsCarryContext(t *testing.T) {
	e := listenEndpoint(t, nil, "sctp4", loopback4(0))
	local := endpointAddr(t, e)
	_, err := e.SendMsg(3, nil, SendOptions{})
	op := opOf(t, "SendMsg", "write", err, syscall.EINVAL)
	if op.Net != "sctp4" || op.Source == nil || op.Source.String() != local.String() {
		t.Errorf("SendMsg error %#v, want Net sctp4 and the endpoint's address as Source", op)
	}
	_, err = e.Connect(nil)
	op = opOf(t, "Connect(nil)", "dial", err, syscall.EINVAL)
	if op.Source == nil || op.Source.String() != local.String() {
		t.Errorf("Connect error Source = %v, want %v", op.Source, local)
	}
	_, err = e.LocalAddrs(0)
	op = opOf(t, "LocalAddrs(0)", "get", err, syscall.EINVAL)
	if op.Addr == nil || op.Addr.String() != local.String() {
		t.Errorf("LocalAddrs error Addr = %v, want %v", op.Addr, local)
	}
	var inner *net.OpError
	if errors.As(op.Err, &inner) {
		t.Errorf("a *net.OpError inside a *net.OpError: %#v", op)
	}
}

// TestEndpointSendMsgZeroAllocs: an Endpoint's SendMsg makes no
// allocation, with and without each option, measured against a peer in
// another process.
func TestEndpointSendMsgZeroAllocs(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector, whose instrumentation allocates on its own account")
	}
	const (
		runs          = 1000
		mallocsMargin = 0.05
		bytesMargin   = 4.0
	)
	for name, opts := range map[string]SendOptions{
		"defaults": {},
		"Info":     {Info: &SndInfo{Stream: 1, PPID: 2}},
		"PR":       {PR: &PrInfo{Policy: PRRtx, Value: 2}},
		"More":     {More: true},
		"NoWait":   {NoWait: true},
	} {
		t.Run(name, func(t *testing.T) {
			peer := startHelperPeer(t, "sctp4", "127.0.0.1:0", false)
			// NoDelay sends each message at once (RFC 6458 §8.1.5); the
			// default PrInfo makes every send carry PRINFO as well.
			e := openEndpoint(t, &Config{NoDelay: new(true), DefaultPrInfo: &PrInfo{Policy: PRTTL, TTL: time.Minute}}, "sctp4", nil)
			id, err := e.Connect(peer)
			if err != nil {
				t.Fatalf("Connect: %v", err)
			}
			awaitCommUp(t, e)
			payload := fill(64)
			var failed error
			send := func() {
				if n, err := e.SendMsg(id, payload, opts); (err != nil || n != len(payload)) && failed == nil {
					failed = fmt.Errorf("SendMsg = %d, %v", n, err)
				}
				if name == "More" {
					// Bursts of two: a message with More set is held for
					// the next (MSG_MORE).
					opts.More = !opts.More
				}
			}
			allocs, mallocs, bytes := sendAllocs(runs, send)
			if failed != nil {
				t.Fatal(failed)
			}
			if allocs != 0 || mallocs >= mallocsMargin || bytes >= bytesMargin {
				t.Errorf("AllocsPerRun %v; %.4f allocations and %.2f bytes per send, want 0", allocs, mallocs, bytes)
			}
			_ = e.Close()
		})
	}
}

// TestEndpointRecvMsgZeroAllocs: an Endpoint's RecvMsg of data makes no
// allocation, measured against a sender in another process.
func TestEndpointRecvMsgZeroAllocs(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector, whose instrumentation allocates on its own account")
	}
	const (
		runs          = 1000
		size          = 64
		mallocsMargin = 0.05
		bytesMargin   = 4.0
	)
	peer := startHelperSender(t, "sctp4", "127.0.0.1:0", 1)
	e := openEndpoint(t, nil, "sctp4", nil)
	id, err := e.Connect(peer)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	awaitCommUp(t, e)
	if _, err := e.SendMsg(id, fmt.Appendf(nil, "%d %d", 2*runs+2, size), SendOptions{}); err != nil {
		t.Fatalf("request: %v", err)
	}
	setEndpointReadDeadline(t, e, 60*time.Second)
	buf := make([]byte, 256)
	bad := false
	read := func() {
		n, info, err := e.RecvMsg(buf)
		if err != nil || n != size || info.Rcv.AssocID != id {
			bad = true
		}
	}
	read()
	allocs, mallocs, bytes := sendAllocs(runs, read)
	if bad {
		t.Fatal("a read returned an error, the wrong length or the wrong association")
	}
	if allocs != 0 || mallocs >= mallocsMargin || bytes >= bytesMargin {
		t.Errorf("AllocsPerRun %v; %.4f allocations and %.2f bytes per read, want 0", allocs, mallocs, bytes)
	}
}

// --- PeelOff ---------------------------------------------------------------------

// TestPeeledConnIO: a peeled connection is a Conn in every respect its
// kind allows: Write and Read, SendMsg and RecvMsg with metadata, and
// ReadMsg all work; SendOptions.Path is refused before any system call,
// since Linux ignores the destination there (net/sctp/socket.c:
// sctp_sendmsg_get_daddr); and its association id is the endpoint's.
func TestPeeledConnIO(t *testing.T) {
	peeled, peer := peeledPair(t, nil)
	if !realAssocID(peeled.AssocID()) {
		t.Errorf("peeled AssocID = %d", peeled.AssocID())
	}
	if _, err := peer.Write([]byte("to the peeled side")); err != nil {
		t.Fatalf("peer Write: %v", err)
	}
	setReadDeadline(t, peeled, endpointWait)
	buf := make([]byte, 64)
	if n, err := peeled.Read(buf); err != nil || string(buf[:n]) != "to the peeled side" {
		t.Fatalf("peeled Read = %q, %v", buf[:n], err)
	}
	if _, err := peeled.SendMsg([]byte("with metadata"), SendOptions{Info: &SndInfo{Stream: 2, PPID: 77}}); err != nil {
		t.Fatalf("peeled SendMsg: %v", err)
	}
	if got, info := recvWithin(t, peer, endpointWait); string(got) != "with metadata" || info.Stream != 2 || info.PPID != 77 {
		t.Fatalf("peer received %q, %+v", got, info)
	}
	if _, err := peer.SendMsg([]byte("a whole message"), SendOptions{Info: &SndInfo{Stream: 1, PPID: 5}}); err != nil {
		t.Fatalf("peer SendMsg: %v", err)
	}
	msg, rcv, err := peeled.ReadMsg(1024)
	if err != nil || string(msg) != "a whole message" || rcv.PPID != 5 || rcv.AssocID != peeled.AssocID() {
		t.Fatalf("peeled ReadMsg = %q, %+v, %v", msg, rcv, err)
	}
	calls := countSendmsg(t)
	_, err = peeled.SendMsg([]byte("x"), SendOptions{Path: netip.MustParseAddr("127.0.0.1")})
	wantOp(t, "SendMsg with Path on a peeled connection", "write", err, syscall.EINVAL)
	if n := calls.Load(); n != 0 {
		t.Errorf("%d sendmsg calls for a refused Path", n)
	}
	if s, err := peeled.Status(); err != nil || s.State != StateEstablished {
		t.Errorf("peeled Status = %+v, %v", s, err)
	}
}

// TestPeeledConnInheritance: a peeled connection keeps every kernel
// setting its endpoint had, copied by the kernel (net/sctp/socket.c:
// sctp_sock_migrate), including the send defaults its association was
// created with, which its send path reads from it; and it takes the
// NotificationHandler, the grace period of Close and the caller's own
// subscriptions from the endpoint's Config, without the EventAssocChange
// delivery an Endpoint adds for itself.
func TestPeeledConnInheritance(t *testing.T) {
	const rbuf, wbuf = 100000, 90000
	var handled atomic.Int32
	defSnd := SndInfo{Stream: 1, PPID: 46, Context: 7, Flags: SendUnordered}
	defPR := PrInfo{Policy: PRTTL, TTL: time.Second}
	cfg := &Config{
		ReadBuffer:          new(rbuf),
		WriteBuffer:         new(wbuf),
		NoDelay:             new(true),
		DefaultSndInfo:      new(defSnd),
		DefaultPrInfo:       new(defPR),
		Notifications:       []EventType{EventSendFailed, EventShutdown},
		NotificationHandler: func(Notification) error { handled.Add(1); return nil },
		CloseTimeout:        1234 * time.Millisecond,
	}
	peeled, peer := peeledPair(t, cfg)
	rc := mustSyscallConn(t, peeled)
	if got := getIntOpt(t, rc, syscall.SOL_SOCKET, syscall.SO_RCVBUF); got < rbuf {
		t.Errorf("SO_RCVBUF = %d, want the endpoint's", got)
	}
	if got := getIntOpt(t, rc, syscall.SOL_SOCKET, syscall.SO_SNDBUF); got < wbuf {
		t.Errorf("SO_SNDBUF = %d, want the endpoint's", got)
	}
	if got := getIntOpt(t, rc, ipprotoSCTP, optNoDelay); got != 1 {
		t.Errorf("SCTP_NODELAY = %d, want 1", got)
	}
	if got, err := peeled.DefaultSndInfo(); err != nil || *got != defSnd {
		t.Errorf("DefaultSndInfo = %+v, %v; want %+v", got, err, defSnd)
	}
	if got, err := peeled.DefaultPrInfo(); err != nil || *got != defPR {
		t.Errorf("DefaultPrInfo = %+v, %v; want %+v", got, err, defPR)
	}
	if peeled.send.defSnd != defSnd || peeled.send.defPR != defPR {
		t.Errorf("cached defaults %+v, %+v; want %+v, %+v", peeled.send.defSnd, peeled.send.defPR, defSnd, defPR)
	}
	for _, typ := range []EventType{EventSendFailed, EventShutdown, EventAssocChange} {
		if !subscribedInKernel(t, rc, typ) {
			t.Errorf("%v is not subscribed on the peeled socket", typ)
		}
	}
	if subscribedInKernel(t, rc, EventPeerAddrChange) {
		t.Error("EventPeerAddrChange is subscribed on the peeled socket, though the Config did not ask for it")
	}
	if got, want := eventSet(peeled.subs.Load()), eventBit(EventSendFailed)|eventBit(EventShutdown); got != want {
		t.Errorf("logical subscriptions = %#x, want %#x: an Endpoint's own EventAssocChange delivery does not pass to a Conn", got, want)
	}
	if on, err := peeled.Subscribed(EventAssocChange); err != nil || on {
		t.Errorf("Subscribed(EventAssocChange) = %v, %v; want false", on, err)
	}
	if peeled.closeWait != cfg.CloseTimeout {
		t.Errorf("grace period = %v, want %v", peeled.closeWait, cfg.CloseTimeout)
	}
	if peeled.handler == nil {
		t.Fatal("the peeled connection has no NotificationHandler")
	}
	_ = peeled.handler(nil)
	if handled.Load() != 1 {
		t.Error("the peeled connection's handler is not the endpoint Config's")
	}
	// A send with no options carries the association's defaults.
	if _, err := peeled.Write([]byte("defaults")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got, info := recvWithin(t, peer, endpointWait); string(got) != "defaults" || info.Stream != 1 || info.PPID != 46 || !info.Unordered {
		t.Errorf("peer received %q, %+v; want stream 1, PPID 46, unordered", got, info)
	}
}

// TestPeeledConnRestoresAssocChange: an association of an Endpoint whose
// SCTP_ASSOC_CHANGE subscription was switched off through SyscallConn gets
// it back when it is peeled off, since the package sees the end of a
// Conn's association from those records (net/sctp/socket.c:
// sctp_setsockopt_event reaches the association on a peeled socket), and
// a reader of the peeled connection still ends with io.EOF.
func TestPeeledConnRestoresAssocChange(t *testing.T) {
	e := listenEndpoint(t, nil, "sctp4", loopback4(0))
	peer, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, endpointAddr(t, e))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = peer.Abort() })
	id := onlyAssoc(t, e)
	rawFd(t, mustEndpointRawConn(t, e), func(fd int) {
		var b [sizeEvent]byte
		binary.NativeEndian.PutUint32(b[eventAssocIDOff:], uint32(id))
		binary.NativeEndian.PutUint16(b[eventTypeFieldOff:], uint16(EventAssocChange))
		if err := rawSetsockopt(fd, ipprotoSCTP, optEvent, unsafe.Pointer(&b[0]), uintptr(len(b))); err != nil {
			t.Fatalf("switching SCTP_ASSOC_CHANGE off for association %d: %v", id, err)
		}
	})
	peeled, err := e.PeelOff(id)
	if err != nil {
		t.Fatalf("PeelOff: %v", err)
	}
	t.Cleanup(func() { _ = peeled.Abort() })
	if !subscribedInKernel(t, mustSyscallConn(t, peeled), EventAssocChange) {
		t.Fatal("SCTP_ASSOC_CHANGE is not subscribed on the peeled connection")
	}
	setReadDeadline(t, peeled, endpointWait)
	done := make(chan error, 1)
	go func() {
		_, err := peeled.Read(make([]byte, 64))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	if err := peer.Close(); err != nil {
		t.Fatalf("peer Close: %v", err)
	}
	if err := <-done; err != io.EOF {
		t.Errorf("the peeled connection's parked read = %v, want io.EOF", err)
	}
}

// TestPeeledConnSubscribedAssocChange: a caller who lists EventAssocChange
// in the endpoint's Config gets the records on the peeled connection too,
// and one who does not, does not, as on every Conn.
func TestPeeledConnSubscribedAssocChange(t *testing.T) {
	for _, subscribed := range []bool{false, true} {
		t.Run(fmt.Sprintf("subscribed=%t", subscribed), func(t *testing.T) {
			cfg := &Config{}
			if subscribed {
				cfg.Notifications = []EventType{EventAssocChange}
			}
			peeled, peer := peeledPair(t, cfg)
			if err := peer.Close(); err != nil {
				t.Fatalf("peer Close: %v", err)
			}
			setReadDeadline(t, peeled, endpointWait)
			buf := make([]byte, 1024)
			var states []AssocChangeState
			for {
				n, info, err := peeled.RecvMsg(buf)
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Fatalf("RecvMsg: %v", err)
				}
				if info.Notification {
					note, err := ParseNotification(buf[:n])
					if err != nil {
						t.Fatalf("ParseNotification: %v", err)
					}
					if ac, ok := note.(*AssocChange); ok {
						states = append(states, ac.State)
					}
				}
			}
			switch {
			case subscribed && (len(states) == 0 || states[len(states)-1] != AssocShutdownComplete):
				t.Errorf("records %v, want them to end with AssocShutdownComplete", states)
			case !subscribed && len(states) != 0:
				t.Errorf("records %v delivered to a caller who did not subscribe", states)
			}
		})
	}
}

// TestPeeledShutdownSendsEOF: Shutdown on a peeled connection is the
// empty SCTP_EOF send, since Linux ignores shutdown(2) on this socket
// kind (net/sctp/socket.c: sctp_shutdown); the peer's reads end with
// io.EOF, the peeled side's once the shutdown completes, and a later
// Close returns at once.
func TestPeeledShutdownSendsEOF(t *testing.T) {
	peeled, peer := peeledPair(t, nil)
	var sends, eofs atomic.Int32
	hookSendmsg(t, func(fd int, msg *syscall.Msghdr, flags int) (int, error) {
		sends.Add(1)
		if sentFlags(msg)&sndFlagEOF != 0 && msg.Iovlen == 0 {
			eofs.Add(1)
		}
		return rawSendmsg(fd, msg, flags)
	})
	if err := peeled.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if sends.Load() != 1 || eofs.Load() != 1 {
		t.Fatalf("Shutdown made %d sends, %d of them empty SCTP_EOF sends; want one", sends.Load(), eofs.Load())
	}
	setReadDeadline(t, peer, endpointWait)
	if _, err := peer.Read(make([]byte, 64)); err != io.EOF {
		t.Errorf("peer Read after Shutdown = %v, want io.EOF", err)
	}
	setReadDeadline(t, peeled, endpointWait)
	if _, err := peeled.Read(make([]byte, 64)); err != io.EOF {
		t.Errorf("peeled Read after Shutdown = %v, want io.EOF", err)
	}
	_, err := peeled.Write([]byte("x"))
	wantWriteError(t, err, syscall.EPIPE)
	start := time.Now()
	if err := peeled.Close(); err != nil {
		t.Fatalf("Close after Shutdown: %v", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("Close after a completed Shutdown took %v", d)
	}
}

// TestPeeledCloseShutsDownGracefully: Close on a peeled connection
// completes the SHUTDOWN handshake with its SCTP_EOF send and returns well
// before its grace period; the peer sees the end of the stream, not an
// ABORT (v1 TestClosingAPeeledConnectionShutsDownGracefully).
func TestPeeledCloseShutsDownGracefully(t *testing.T) {
	peeled, peer := peeledPair(t, nil)
	const grace = 2 * time.Second
	start := time.Now()
	if err := peeled.CloseWithTimeout(grace); err != nil {
		t.Fatalf("CloseWithTimeout: %v", err)
	}
	if d := time.Since(start); d >= grace/2 {
		t.Errorf("Close took %v against a %v grace period; it ran out instead of completing", d, grace)
	}
	setReadDeadline(t, peer, 3*time.Second)
	if _, err := peer.Read(make([]byte, 64)); err != io.EOF {
		t.Errorf("peer Read = %v, want io.EOF from a graceful end", err)
	}
}

// TestPeeledCloseWithFullSendBuffer: Close on a peeled connection whose
// send buffer is full makes its SCTP_EOF send at once, since that send
// never waits for buffer space (net/sctp/socket.c:
// sctp_sendmsg_check_sflags); the peer drains every queued message, then
// sees io.EOF, and Close returns before its grace period (v1
// TestClosingBackpressuredPeeledConnectionRetriesEOF).
func TestPeeledCloseWithFullSendBuffer(t *testing.T) {
	peeled, peer := peeledPair(t, nil)
	if err := peeled.SetWriteBuffer(4096); err != nil {
		t.Fatalf("SetWriteBuffer: %v", err)
	}
	payload := fill(512)
	queued := fillSendBuffer(t, peeled, payload)
	if queued == 0 {
		t.Fatal("the send buffer took nothing")
	}
	const grace = 5 * time.Second
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- peeled.CloseWithTimeout(grace) }()
	time.Sleep(50 * time.Millisecond)
	setReadDeadline(t, peer, grace)
	buf := make([]byte, 4096)
	for i := range queued {
		if n, err := peer.Read(buf); err != nil || n != len(payload) {
			t.Fatalf("peer Read %d/%d = %d, %v", i+1, queued, n, err)
		}
	}
	if _, err := peer.Read(buf); err != io.EOF {
		t.Fatalf("peer Read after the queued messages = %v, want io.EOF", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("CloseWithTimeout: %v", err)
		}
	case <-time.After(grace + time.Second):
		t.Fatal("Close did not return after the peer drained")
	}
	if d := time.Since(start); d >= grace {
		t.Errorf("Close took %v, its whole grace period", d)
	}
}

// TestPeeledCloseAbortOvertakes: on a peeled connection too, an Abort
// during a Close that cannot complete sends the ABORT at once and
// releases the Close.
func TestPeeledCloseAbortOvertakes(t *testing.T) {
	peeled, peer := peeledPair(t, &Config{CloseTimeout: 10 * time.Second})
	fillSendBuffer(t, peeled, fill(512))
	done := make(chan error, 1)
	go func() { done <- peeled.Close() }()
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	if err := peeled.Abort(); err != nil {
		t.Fatalf("Abort during Close: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("the overtaken Close = %v", err)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("Close returned %v after the Abort", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close was still waiting 3 s after Abort")
	}
	setReadDeadline(t, peer, endpointWait)
	for {
		_, err := peer.Read(make([]byte, 1024))
		if err == nil {
			continue
		}
		if !errors.Is(err, syscall.ECONNRESET) {
			t.Errorf("peer ended with %v, want ECONNRESET", err)
		}
		break
	}
}

// TestPeelOffRacesWithEndpointClose: PeelOff racing the endpoint's Close
// either returns a working connection or an error, never a descriptor it
// does not own, and nothing leaks over many rounds (v1
// TestPeelOffRacesWithClose).
func TestPeelOffRacesWithEndpointClose(t *testing.T) {
	before := openFds(t)
	for round := range 30 {
		func() {
			e, err := (&Config{CloseTimeout: 50 * time.Millisecond}).ListenEndpoint("sctp4", loopback4(0))
			if err != nil {
				t.Fatalf("ListenEndpoint: %v", err)
			}
			peer, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, endpointAddr(t, e))
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer func() { _ = peer.Abort() }()
			id := onlyAssoc(t, e)
			var wg sync.WaitGroup
			peeled := make(chan *Conn, 4)
			wg.Go(func() {
				for range 4 {
					c, err := e.PeelOff(id)
					if err != nil {
						continue
					}
					if c == nil {
						t.Error("PeelOff returned neither a connection nor an error")
						return
					}
					peeled <- c
				}
			})
			wg.Go(func() {
				time.Sleep(time.Duration(round%7) * 200 * time.Microsecond)
				_ = e.Close()
			})
			wg.Wait()
			close(peeled)
			n := 0
			for c := range peeled {
				n++
				rawFd(t, mustSyscallConn(t, c), func(fd int) {
					if fd <= 2 {
						t.Errorf("PeelOff returned descriptor %d", fd)
					}
				})
				if err := c.CloseWithTimeout(20 * time.Millisecond); err != nil {
					t.Errorf("closing a peeled connection: %v", err)
				}
			}
			if n > 1 {
				t.Errorf("round %d: one association was peeled off %d times", round, n)
			}
			_ = e.Abort()
		}()
	}
	if after := openFds(t); after != before {
		t.Errorf("descriptor count went %d -> %d over 30 rounds", before, after)
	}
}

// TestPeelOffDescriptorExhaustion: with every descriptor the process may
// have in use, PeelOff fails with an error matching EMFILE, as a
// *net.OpError with Op "peeloff", and the association stays on the
// endpoint, where it keeps working. Linux itself moves the association to
// the new socket before it looks for a descriptor, and releases both when
// it finds none (net/sctp/socket.c: sctp_getsockopt_peeloff_common), so
// PeelOff makes sure of one first. The limit is lowered in a child
// process, which the rest of the suite does not share.
func TestPeelOffDescriptorExhaustion(t *testing.T) {
	if os.Getenv("SCTP_PEELOFF_EXHAUSTION_CHILD") == "1" {
		peelOffExhaustionChild(t)
		return
	}
	out, err := runChild(t, "TestPeelOffDescriptorExhaustion", "SCTP_PEELOFF_EXHAUSTION_CHILD=1")
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	if !strings.Contains(out, "peel-off exhaustion checks done") {
		t.Fatalf("child did not run the checks:\n%s", out)
	}
}

func peelOffExhaustionChild(t *testing.T) {
	e := listenEndpoint(t, nil, "sctp4", loopback4(0))
	peer, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, endpointAddr(t, e))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = peer.Abort() }()
	id := awaitCommUp(t, e).AssocID
	baseline := openFds(t)

	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	// The next descriptor is the lowest free number, so the limit must sit
	// just above the highest number in use, and every gap below it be
	// filled.
	high := 0
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	for _, ent := range ents {
		if n, err := strconv.Atoi(ent.Name()); err == nil && n > high {
			high = n
		}
	}
	lowered := lim
	lowered.Cur = uint64(high + 1)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lowered); err != nil {
		t.Fatalf("setrlimit: %v", err)
	}
	var fillers []int
	for {
		fd, err := syscall.Dup(0)
		if err != nil {
			break
		}
		fillers = append(fillers, fd)
	}

	c, err := e.PeelOff(id)
	if c != nil {
		t.Error("PeelOff returned a connection with no descriptor to spare")
		_ = c.Abort()
	}
	op := opOf(t, "PeelOff at the descriptor limit", "peeloff", err, syscall.EMFILE)
	if op.Addr == nil {
		t.Error("the PeelOff error names no address")
	}

	for _, fd := range fillers {
		_ = syscall.Close(fd)
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatalf("restoring the limit: %v", err)
	}
	if ids, err := e.AssocIDs(); err != nil || len(ids) != 1 || ids[0] != id {
		t.Fatalf("AssocIDs after the failed PeelOff = %v, %v; the association left the endpoint", ids, err)
	}
	if _, err := peer.Write([]byte("still here")); err != nil {
		t.Fatalf("peer Write: %v", err)
	}
	if got, info := endpointData(t, e); string(got) != "still here" || info.Rcv.AssocID != id {
		t.Fatalf("the endpoint received %q on %d after the failed PeelOff", got, info.Rcv.AssocID)
	}
	if _, err := e.SendMsg(id, []byte("reply"), SendOptions{}); err != nil {
		t.Fatalf("SendMsg after the failed PeelOff: %v", err)
	}
	if got, _ := recvWithin(t, peer, endpointWait); string(got) != "reply" {
		t.Fatalf("peer received %q", got)
	}
	// With descriptors to spare again, the same association peels off.
	c, err = e.PeelOff(id)
	if err != nil {
		t.Fatalf("PeelOff with the limit restored: %v", err)
	}
	if err := c.Abort(); err != nil {
		t.Errorf("Abort: %v", err)
	}
	if after := openFds(t); after != baseline {
		t.Errorf("descriptor count went %d -> %d across the exhaustion", baseline, after)
	}
	fmt.Println("peel-off exhaustion checks done")
}

// --- one server, many peers ----------------------------------------------------

// These are v1's multi-client tests, run against both kinds of server a
// caller can build: a Listener handing each association to a Conn of its
// own, and one Endpoint holding every association. Each peer sends
// payloads unique to itself and requires exactly those back, so a server
// that crossed two peers' data or metadata fails here rather than in
// production.

// echoServer is a server that echoes every message back on the stream and
// with the PPID it arrived with, on a Listener or on an Endpoint.
type echoServer struct {
	addr *Addr
	ep   *Endpoint // the Endpoint server; nil for a Listener server

	mu     sync.Mutex
	assocs []AssocID // the association of every peer, in arrival order

	stop func()
}

// startEchoServer starts a server of kind "listener" or "endpoint". Every
// association's id is recorded as it arrives: an accepted Conn's
// AssocID, or the AssocCommUp an Endpoint delivers.
func startEchoServer(t *testing.T, kind string, cfg *Config) *echoServer {
	t.Helper()
	s := &echoServer{}
	var wg sync.WaitGroup
	switch kind {
	case "listener":
		l := mustListen(t, cfg, "sctp4", loopback4(0))
		s.addr = listenerAddr(t, l)
		wg.Go(func() {
			for {
				c, err := l.AcceptSCTP()
				if err != nil {
					return
				}
				s.mu.Lock()
				s.assocs = append(s.assocs, c.AssocID())
				s.mu.Unlock()
				wg.Go(func() {
					defer func() { _ = c.Close() }()
					buf := make([]byte, 4096)
					for {
						n, info, err := c.RecvMsg(buf)
						if err != nil {
							return
						}
						if info.Notification {
							continue
						}
						if _, err := c.SendMsg(buf[:n], SendOptions{Info: &SndInfo{Stream: info.Rcv.Stream, PPID: info.Rcv.PPID}}); err != nil {
							return
						}
					}
				})
			}
		})
		s.stop = func() { _ = l.Close(); wg.Wait() }
	case "endpoint":
		e := listenEndpoint(t, cfg, "sctp4", loopback4(0))
		s.addr, s.ep = endpointAddr(t, e), e
		wg.Go(func() {
			buf := make([]byte, 4096)
			for {
				n, info, err := e.RecvMsg(buf)
				if err != nil {
					// Only Close, when the server stops, ends the reads of
					// an Endpoint; anything else is a failure, which
					// retrying would only repeat.
					if !errors.Is(err, net.ErrClosed) {
						t.Errorf("the endpoint echo server's RecvMsg: %v", err)
					}
					return
				}
				if info.Notification {
					if note, err := ParseNotification(buf[:n]); err == nil {
						if ac, ok := note.(*AssocChange); ok && ac.State == AssocCommUp {
							s.mu.Lock()
							s.assocs = append(s.assocs, ac.AssocID)
							s.mu.Unlock()
						}
					}
					continue
				}
				// A send fails when the peer has closed its association
				// meanwhile, and the peer's own check sees a lost echo.
				_, _ = e.SendMsg(info.Rcv.AssocID, buf[:n], SendOptions{Info: &SndInfo{Stream: info.Rcv.Stream, PPID: info.Rcv.PPID}})
			}
		})
		s.stop = func() { _ = e.Close(); wg.Wait() }
	default:
		t.Fatalf("unknown server kind %q", kind)
	}
	t.Cleanup(s.stop)
	return s
}

// assocIDs returns the associations recorded so far.
func (s *echoServer) assocIDs() []AssocID {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]AssocID(nil), s.assocs...)
}

// serverKinds are the two kinds of multi-client server.
var serverKinds = []string{"listener", "endpoint"}

// roundTrip sends want on stream and requires it back, on that stream.
func roundTrip(c *Conn, want string, stream uint16) error {
	if _, err := c.SendMsg([]byte(want), SendOptions{Info: &SndInfo{Stream: stream, PPID: uint32(len(want))}}); err != nil {
		return fmt.Errorf("send %q: %w", want, err)
	}
	buf := make([]byte, 4096)
	for {
		n, info, err := c.RecvMsg(buf)
		if err != nil {
			return fmt.Errorf("receive %q: %w", want, err)
		}
		if info.Notification {
			continue
		}
		if got := string(buf[:n]); got != want || info.Rcv.Stream != stream || info.Rcv.PPID != uint32(len(want)) {
			return fmt.Errorf("sent %q on stream %d, got %q on stream %d PPID %d", want, stream, got, info.Rcv.Stream, info.Rcv.PPID)
		}
		return nil
	}
}

// dialEcho dials s with a deadline.
func dialEcho(t *testing.T, s *echoServer, cfg *Config) (*Conn, error) {
	c, err := cfg.Dial(testContext(t, 10*time.Second), "sctp4", nil, s.addr)
	if err != nil {
		return nil, err
	}
	if err := c.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		_ = c.Abort()
		return nil, err
	}
	return c, nil
}

// TestManyClientsConcurrentEcho: many peers at once, each exchanging its
// own messages, each getting back exactly its own.
func TestManyClientsConcurrentEcho(t *testing.T) {
	const clients, messages = 24, 20
	for _, kind := range serverKinds {
		t.Run(kind, func(t *testing.T) {
			s := startEchoServer(t, kind, nil)
			var wg sync.WaitGroup
			errs := make(chan error, clients)
			for id := range clients {
				wg.Go(func() {
					c, err := dialEcho(t, s, nil)
					if err != nil {
						errs <- fmt.Errorf("client %d: %w", id, err)
						return
					}
					defer func() { _ = c.Close() }()
					for j := range messages {
						if err := roundTrip(c, fmt.Sprintf("client-%d-msg-%d", id, j), 0); err != nil {
							errs <- fmt.Errorf("client %d: %w", id, err)
							return
						}
					}
				})
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
		})
	}
}

// TestManyClientsHeldOpenSimultaneously: every association is established
// before any sends, so the server must hold them all at once; the
// kernel's own count confirms it, and each still works.
func TestManyClientsHeldOpenSimultaneously(t *testing.T) {
	const clients = 16
	for _, kind := range serverKinds {
		t.Run(kind, func(t *testing.T) {
			s := startEchoServer(t, kind, nil)
			conns := make([]*Conn, clients)
			for i := range conns {
				c, err := dialEcho(t, s, nil)
				if err != nil {
					t.Fatalf("client %d: %v", i, err)
				}
				defer func() { _ = c.Close() }()
				conns[i] = c
			}
			if s.ep != nil {
				if n, err := s.ep.AssocCount(); err != nil || n != clients {
					t.Errorf("the endpoint holds %d associations, %v; want %d", n, err, clients)
				}
			}
			for i, c := range conns {
				if err := roundTrip(c, fmt.Sprintf("held-open-%d", i), 0); err != nil {
					t.Errorf("client %d: %v", i, err)
				}
			}
		})
	}
}

// TestManyClientsDistinctAssociationIDs: the server sees a distinct
// association id for every peer.
func TestManyClientsDistinctAssociationIDs(t *testing.T) {
	const clients = 12
	for _, kind := range serverKinds {
		t.Run(kind, func(t *testing.T) {
			s := startEchoServer(t, kind, nil)
			for i := range clients {
				c, err := dialEcho(t, s, nil)
				if err != nil {
					t.Fatalf("client %d: %v", i, err)
				}
				defer func() { _ = c.Close() }()
				// A round trip makes sure the server has recorded the
				// association before the next peer arrives.
				if err := roundTrip(c, "hello", 0); err != nil {
					t.Fatalf("client %d: %v", i, err)
				}
			}
			ids := s.assocIDs()
			seen := map[AssocID]bool{}
			for _, id := range ids {
				if !realAssocID(id) {
					t.Errorf("association id %d", id)
				}
				seen[id] = true
			}
			if len(ids) != clients || len(seen) != clients {
				t.Errorf("%d ids, %d distinct, for %d peers: %v", len(ids), len(seen), clients, ids)
			}
		})
	}
}

// TestManyClientsPerConnectionDeadlineIsolation: one peer's passed
// deadline expires only its own reads.
func TestManyClientsPerConnectionDeadlineIsolation(t *testing.T) {
	const clients = 8
	for _, kind := range serverKinds {
		t.Run(kind, func(t *testing.T) {
			s := startEchoServer(t, kind, nil)
			conns := make([]*Conn, clients)
			for i := range conns {
				c, err := dialEcho(t, s, nil)
				if err != nil {
					t.Fatalf("client %d: %v", i, err)
				}
				defer func() { _ = c.Close() }()
				conns[i] = c
			}
			if err := conns[0].SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			_, _, err := conns[0].RecvMsg(make([]byte, 64))
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				t.Fatalf("read on the expired connection = %v, want a timeout", err)
			}
			for i := 1; i < clients; i++ {
				if err := roundTrip(conns[i], fmt.Sprintf("isolated-%d", i), 0); err != nil {
					t.Errorf("client %d after another's deadline expired: %v", i, err)
				}
			}
		})
	}
}

// TestManyClientsStreamsStayPerAssociation: several streams on several
// peers at once; every echo comes back on the stream it went out on.
func TestManyClientsStreamsStayPerAssociation(t *testing.T) {
	const clients, streams = 8, 4
	for _, kind := range serverKinds {
		t.Run(kind, func(t *testing.T) {
			s := startEchoServer(t, kind, &Config{InitMsg: InitMsg{OutStreams: streams}})
			var wg sync.WaitGroup
			errs := make(chan error, clients)
			for id := range clients {
				wg.Go(func() {
					c, err := dialEcho(t, s, &Config{InitMsg: InitMsg{OutStreams: streams, MaxInStreams: streams}})
					if err != nil {
						errs <- fmt.Errorf("client %d: %w", id, err)
						return
					}
					defer func() { _ = c.Close() }()
					for st := range uint16(streams) {
						if err := roundTrip(c, fmt.Sprintf("client-%d-stream-%d", id, st), st); err != nil {
							errs <- fmt.Errorf("client %d: %w", id, err)
							return
						}
					}
				})
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				t.Error(err)
			}
		})
	}
}

// TestManyClientsCloseDoesNotDisturbPeers: half the peers close at once,
// and every other still completes a round trip.
func TestManyClientsCloseDoesNotDisturbPeers(t *testing.T) {
	const clients = 16
	for _, kind := range serverKinds {
		t.Run(kind, func(t *testing.T) {
			s := startEchoServer(t, kind, nil)
			conns := make([]*Conn, clients)
			for i := range conns {
				c, err := dialEcho(t, s, nil)
				if err != nil {
					t.Fatalf("client %d: %v", i, err)
				}
				defer func() { _ = c.Close() }()
				conns[i] = c
				if err := roundTrip(c, fmt.Sprintf("prime-%d", i), 0); err != nil {
					t.Fatalf("client %d: %v", i, err)
				}
			}
			var wg sync.WaitGroup
			for i := 0; i < clients; i += 2 {
				wg.Go(func() { _ = conns[i].Close() })
			}
			wg.Wait()
			for i := 1; i < clients; i += 2 {
				if err := roundTrip(conns[i], fmt.Sprintf("survivor-%d", i), 0); err != nil {
					t.Errorf("survivor %d: %v", i, err)
				}
			}
		})
	}
}

// TestManyClientsNotificationsCarryAssociationID: one NotificationHandler
// serves every association, so each notification must name its own: as
// peers abort one after another, the handler sees one AssocCommLost per
// peer, each for a different association.
func TestManyClientsNotificationsCarryAssociationID(t *testing.T) {
	const clients = 6
	for _, kind := range serverKinds {
		t.Run(kind, func(t *testing.T) {
			var (
				mu   sync.Mutex
				lost []AssocID
			)
			cfg := &Config{
				Notifications: []EventType{EventAssocChange},
				NotificationHandler: func(n Notification) error {
					if ac, ok := n.(*AssocChange); ok && ac.State == AssocCommLost {
						mu.Lock()
						lost = append(lost, ac.AssocID)
						mu.Unlock()
					}
					return nil
				},
			}
			var (
				l *Listener
				e *Endpoint
				a *Addr
			)
			if kind == "listener" {
				l = mustListen(t, cfg, "sctp4", loopback4(0))
				a = listenerAddr(t, l)
			} else {
				e = listenEndpoint(t, cfg, "sctp4", loopback4(0))
				a = endpointAddr(t, e)
			}
			buf := make([]byte, 256)
			for i := range clients {
				c, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, a)
				if err != nil {
					t.Fatalf("client %d: %v", i, err)
				}
				if _, err := c.Write(fmt.Appendf(nil, "peer-%d", i)); err != nil {
					t.Fatalf("client %d Write: %v", i, err)
				}
				if l != nil {
					sc, err := l.AcceptSCTP()
					if err != nil {
						t.Fatalf("AcceptSCTP: %v", err)
					}
					setReadDeadline(t, sc, endpointWait)
					if _, err := sc.Read(buf); err != nil {
						t.Fatalf("server Read: %v", err)
					}
					if err := c.Abort(); err != nil {
						t.Fatalf("client %d Abort: %v", i, err)
					}
					// The read that finds the ABORT hands AssocCommLost to
					// the handler, then reports the association's error.
					if _, err := sc.Read(buf); !errors.Is(err, syscall.ECONNRESET) {
						t.Errorf("server Read after the ABORT = %v, want ECONNRESET", err)
					}
					_ = sc.Close()
					continue
				}
				if got, _ := endpointData(t, e); string(got) != fmt.Sprintf("peer-%d", i) {
					t.Fatalf("endpoint received %q", got)
				}
				if err := c.Abort(); err != nil {
					t.Fatalf("client %d Abort: %v", i, err)
				}
			}
			if e != nil {
				// The endpoint delivers each AssocCommLost to the handler as
				// its reads go on; a read with nothing behind the records
				// ends at its deadline.
				deadline := time.Now().Add(endpointWait)
				for {
					mu.Lock()
					n := len(lost)
					mu.Unlock()
					if n >= clients || time.Now().After(deadline) {
						break
					}
					setEndpointReadDeadline(t, e, 100*time.Millisecond)
					_, _, _ = e.RecvMsg(buf)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			seen := map[AssocID]bool{}
			for _, id := range lost {
				seen[id] = true
			}
			if len(lost) != clients || len(seen) != clients {
				t.Errorf("the shared handler saw %d AssocCommLost records naming %d associations (%v), want %d distinct", len(lost), len(seen), lost, clients)
			}
		})
	}
}

// TestDoubleCloseDoesNotReleaseAReusedDescriptor: a second Close must not
// close the descriptor number again: the kernel hands the lowest free
// number to the next socket opened anywhere in the process, which in a
// server is another peer's connection. It runs on a Conn and on an
// Endpoint.
func TestDoubleCloseDoesNotReleaseAReusedDescriptor(t *testing.T) {
	for _, kind := range []string{"Conn", "Endpoint"} {
		t.Run(kind, func(t *testing.T) {
			var (
				fd        int
				closeOnce func() error
			)
			if kind == "Conn" {
				client, _ := connPair(t, nil, nil)
				rawFd(t, mustSyscallConn(t, client), func(f int) { fd = f })
				closeOnce = client.Close
			} else {
				e := openEndpoint(t, nil, "sctp4", loopback4(0))
				rawFd(t, mustEndpointRawConn(t, e), func(f int) { fd = f })
				closeOnce = e.Close
			}
			if err := closeOnce(); err != nil {
				t.Fatalf("first Close: %v", err)
			}
			victim, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, ipprotoSCTP)
			if err != nil {
				t.Fatalf("socket: %v", err)
			}
			defer func() { _ = syscall.Close(victim) }()
			if victim != fd {
				t.Skipf("descriptor %d was not reused (got %d), so the hazard cannot be observed", fd, victim)
			}
			if err := closeOnce(); !errors.Is(err, net.ErrClosed) {
				t.Errorf("second Close = %v, want net.ErrClosed", err)
			}
			if !fdIsOpen(victim) {
				t.Fatalf("the second Close released descriptor %d, which belonged to another socket", victim)
			}
		})
	}
}

// sentFlags is the snd_flags word of the SCTP_SNDINFO record msg carries,
// read raw, SCTP_EOF and SCTP_ABORT included, or 0 when it carries none.
func sentFlags(msg *syscall.Msghdr) uint16 {
	if msg.Control == nil {
		return 0
	}
	oob := unsafe.Slice(msg.Control, int(msg.Controllen))
	for len(oob) >= sizeCmsghdr {
		l := int(readWord(oob))
		if l < sizeCmsghdr || l > len(oob) {
			return 0
		}
		if int32(binary.NativeEndian.Uint32(oob[cmsghdrTypeOff:])) == cmsgSndInfo && l-sizeCmsghdr >= sizeSndInfo {
			return binary.NativeEndian.Uint16(oob[sizeCmsghdr+sndInfoFlagsOff:])
		}
		oob = oob[min(cmsgAlign(l), len(oob)):]
	}
	return 0
}

// --- scripted endpoint -----------------------------------------------------------

// scriptEndpoint builds an Endpoint over one end of an AF_UNIX socket
// pair whose every recvmsg is the test's hook, as scriptConn does for a
// Conn: the poller, the receive lock, reassembly, the RCVINFO check and
// the notification policy are the package's own.
func scriptEndpoint(t testing.TB, handler NotificationHandler) *Endpoint {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	s, err := wrapSocketFile(fds[0], afInet, "sctp4")
	if err != nil {
		_ = syscall.Close(fds[1])
		t.Fatalf("wrapSocketFile: %v", err)
	}
	// The constructor's own wiring; the socket options it reads fail on an
	// AF_UNIX socket and leave their zero values.
	e := newEndpoint(s, &prepared{handler: handler, subscribed: eventBit(EventAssocChange)}, 0)
	scriptPeers.Store(e, fds[1])
	t.Cleanup(func() {
		_ = e.Abort()
		scriptPeers.Delete(e)
		_ = syscall.Close(fds[1])
	})
	return e
}

// wakeScriptedEndpoint makes a scriptEndpoint's descriptor readable.
func wakeScriptedEndpoint(t testing.TB, e *Endpoint) {
	t.Helper()
	fd, ok := scriptPeers.Load(e)
	if !ok {
		t.Fatal("not a scripted endpoint")
	}
	if _, err := syscall.Write(fd.(int), []byte{0}); err != nil {
		t.Fatalf("waking the scripted endpoint: %v", err)
	}
}
