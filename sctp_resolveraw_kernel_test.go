//go:build linux
// +build linux

package sctp

import (
	"net"
	"testing"
)

// TestKernelAddrsRoundTrip decodes what the running kernel actually returns
// for a multi-homed association, rather than a reply built by hand.
//
// The hand-built cases pin the decoder to the documented layout; this one
// checks that layout is what arrives. It needs a second loopback address, so it
// skips where one is not configured rather than failing.
func TestKernelAddrsRoundTrip(t *testing.T) {
	const second = "127.0.0.2"
	if !hasLocalAddr(t, second) {
		t.Skipf("%s is not configured on this host", second)
	}

	laddr := &SCTPAddr{IPAddrs: []net.IPAddr{
		{IP: net.ParseIP("127.0.0.1")},
		{IP: net.ParseIP(second)},
	}}
	ln, err := ListenSCTP("sctp", laddr)
	if err != nil {
		t.Fatalf("listen multi-homed: %v", err)
	}
	defer func() { _ = ln.Close() }()

	srvAddr, ok := ln.Addr().(*SCTPAddr)
	if !ok {
		t.Fatal("listener has no address")
	}
	if len(srvAddr.IPAddrs) != 2 {
		t.Fatalf("listener reports %d addresses, want the 2 that were bound",
			len(srvAddr.IPAddrs))
	}

	accepted := make(chan *SCTPConn, 1)
	go func() {
		c, aerr := ln.AcceptSCTP()
		if aerr != nil {
			t.Errorf("accept: %v", aerr)
			close(accepted)
			return
		}
		accepted <- c
	}()

	conn, err := DialSCTP("sctp", nil, srvAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	srvConn, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	defer func() { _ = srvConn.Close() }()

	remote, err := conn.SCTPRemoteAddr(0)
	if err != nil {
		t.Fatalf("SCTPRemoteAddr: %v", err)
	}
	if len(remote.IPAddrs) != 2 {
		t.Errorf("remote reports %d addresses, want 2", len(remote.IPAddrs))
	}
	if remote.Port != srvAddr.Port {
		t.Errorf("remote port %d, want %d", remote.Port, srvAddr.Port)
	}
	for i, a := range remote.IPAddrs {
		// A wrong offset yields zeros rather than an error, so an unspecified
		// address here is the symptom to catch.
		if a.IP == nil || a.IP.IsUnspecified() {
			t.Errorf("remote address %d decoded as %v", i, a.IP)
		}
	}

	prim, err := srvConn.SCTPGetPrimaryPeerAddr()
	if err != nil {
		t.Fatalf("SCTPGetPrimaryPeerAddr: %v", err)
	}
	if len(prim.IPAddrs) != 1 || prim.IPAddrs[0].IP.IsUnspecified() {
		t.Errorf("primary peer decoded as %v", prim.IPAddrs)
	}
}

func hasLocalAddr(t *testing.T, want string) bool {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	target := net.ParseIP(want)
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(target) {
			return true
		}
	}
	return false
}
