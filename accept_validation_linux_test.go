// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestAcceptRetriesAbortedAssociation(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	var calls atomic.Int32
	wouldBlock := make(chan struct{})
	testHookAccept4 = func(fd, flags int) (int, syscall.Sockaddr, error) {
		switch calls.Add(1) {
		case 1:
			return -1, nil, syscall.ECONNABORTED
		case 2:
			return -1, nil, syscall.EINTR
		case 3:
			close(wouldBlock)
			return -1, nil, syscall.EAGAIN
		default:
			return syscall.Accept4(fd, flags)
		}
	}
	t.Cleanup(func() { testHookAccept4 = nil })
	type result struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan result, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := l.Accept()
		accepted <- result{c, err}
	}()
	t.Cleanup(func() {
		_ = l.Close()
		<-done
		select {
		case r := <-accepted:
			if r.conn != nil {
				_ = r.conn.(*Conn).Abort()
			}
		default:
		}
	})
	// EAGAIN must precede the real association: inventing it after the
	// readiness edge has already arrived could consume that one wake.
	select {
	case r := <-accepted:
		if r.conn != nil {
			_ = r.conn.Close()
		}
		t.Fatalf("Accept returned before the real association: %v", r.err)
	case <-wouldBlock:
	case <-time.After(3 * time.Second):
		t.Fatal("Accept did not retry the transient errors")
	}
	client, err := Dial(testContext(t, 3*time.Second), "sctp4", nil, listenerAddr(t, l))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Abort() })
	var server net.Conn
	select {
	case r := <-accepted:
		if r.err != nil {
			t.Fatalf("Accept: %v", r.err)
		}
		server = r.conn
	case <-time.After(3 * time.Second):
		t.Fatal("Accept did not return the real association")
	}
	t.Cleanup(func() { _ = server.(*Conn).Abort() })
	if calls.Load() < 4 {
		t.Fatalf("accept4 calls = %d, want retries followed by a real accept", calls.Load())
	}
	if err := server.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Write([]byte("accepted")); err != nil {
		t.Fatal(err)
	}
	var b [32]byte
	if n, err := server.Read(b[:]); err != nil || string(b[:n]) != "accepted" {
		t.Fatalf("Read = %q, %v", b[:n], err)
	}
}

// A refused setup leaves its notification queued even after another
// observer has consumed SO_ERROR. No scheduling race is needed here.
func TestAwaitEstablishedConsumedRefusal(t *testing.T) {
	s, err := newSocket(afInet, "sctp4")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.file.Close() })
	p, err := (*Config)(nil).prepare(styleDial)
	if err != nil {
		t.Fatal(err)
	}
	if err := setupSocket(&s, "", nil, p.ops); err != nil {
		t.Fatal(err)
	}
	// Bind before choosing the closed port so autobind cannot connect the
	// socket to itself (as refusedAwaitSocket does).
	if err := s.control(func(fd int) error {
		return syscall.Bind(fd, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
	}); err != nil {
		t.Fatal(err)
	}
	dead := deadPort(t)
	peer, err := encodeAddrs(afInet, dead.IPs, dead.Port)
	if err != nil {
		t.Fatal(err)
	}
	err = s.connectx(peer)
	if err != nil && !errors.Is(err, syscall.EINPROGRESS) {
		t.Fatal(err)
	}
	// SO_ERROR is consumed only once the real refusal has arrived.
	until := time.Now().Add(3 * time.Second)
	consumed := false
	for time.Now().Before(until) {
		var se int
		if err := s.control(func(fd int) error {
			var e error
			se, e = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
			return e
		}); err != nil {
			t.Fatal(err)
		}
		if se != 0 {
			if syscall.Errno(se) != syscall.ECONNREFUSED {
				t.Fatalf("SO_ERROR = %v", syscall.Errno(se))
			}
			consumed = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !consumed {
		t.Fatal("no refusal arrived")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = awaitEstablished(ctx, &s)
	var se *os.SyscallError
	if !errors.Is(err, syscall.ECONNREFUSED) || !errors.As(err, &se) || se.Syscall != "sctp_connectx" {
		t.Fatalf("awaitEstablished = %v, want sctp_connectx ECONNREFUSED", err)
	}
	// The peek must leave the head notification for the connection's reads.
	var b [64]byte
	if err := s.control(func(fd int) error {
		n, _, flags, _, e := syscall.Recvmsg(fd, b[:], nil, syscall.MSG_DONTWAIT)
		if e != nil {
			return e
		}
		if n < 12 || flags&msgNotification == 0 {
			t.Errorf("head record = %d bytes, flags %#x", n, flags)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDuplicateLocalAddresses(t *testing.T) {
	for _, ips := range [][]netip.Addr{
		{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("::ffff:127.0.0.1")},
		{netip.MustParseAddr("::1"), netip.MustParseAddr("::1")},
		{netip.IPv4Unspecified(), netip.IPv6Unspecified()},
	} {
		t.Run(ips[1].String(), func(t *testing.T) {
			var controls atomic.Int32
			cfg := &Config{Control: func(string, string, syscall.RawConn) error { controls.Add(1); return nil }}
			local := &Addr{IPs: ips}
			check := func(name string, err error) {
				t.Helper()
				if !errors.Is(err, syscall.EINVAL) || !strings.Contains(err.Error(), "address 1") || !strings.Contains(err.Error(), "address 0") {
					t.Errorf("%s = %v, want duplicate indexes 1 and 0", name, err)
				}
			}
			l, err := cfg.Listen("sctp6", local)
			if l != nil {
				_ = l.Close()
			}
			check("Listen", err)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			c, err := cfg.Dial(ctx, "sctp6", local, loopback4(9))
			if c != nil {
				_ = c.Abort()
			}
			check("Dial", err)
			for name, makeEndpoint := range map[string]func(string, *Addr) (*Endpoint, error){"OpenEndpoint": cfg.OpenEndpoint, "ListenEndpoint": cfg.ListenEndpoint} {
				e, err := makeEndpoint("sctp6", local)
				if e != nil {
					_ = e.Close()
				}
				check(name, err)
			}
			if controls.Load() != 0 {
				t.Errorf("invalid local addresses reached Control %d times", controls.Load())
			}
			for _, name := range []string{"BindAdd", "BindRemove"} {
				_, err := bindxAddrs(afInet6, name, ips)
				check(name, err)
			}
			resolved, err := ResolveAddr("sctp6", (&Addr{IPs: []netip.Addr{ips[0], ips[0]}, Port: 80}).String())
			if err != nil || len(resolved.IPs) != 2 {
				t.Fatalf("ResolveAddr must retain duplicates: %v, %v", resolved, err)
			}
		})
	}
}

type failConnControl struct {
	syscall.RawConn
	at, calls int
}

func (r *failConnControl) Control(f func(uintptr)) error {
	r.calls++
	if r.calls == r.at {
		return syscall.EIO
	}
	return r.RawConn.Control(f)
}

func TestNewConnAdoptedFailurePreservesSocket(t *testing.T) {
	for _, stage := range []struct {
		name string
		at   int
	}{{"subscriptions", 1}, {"setEvent", 2}, {"status", 3}} {
		for _, linger := range []syscall.Linger{{}, {Onoff: 1, Linger: 7}} {
			t.Run(stage.name+"/linger="+strconv.Itoa(int(linger.Linger)), func(t *testing.T) {
				client, server := connPair(t, nil, nil)
				f := connFile(t, client)
				fd := fdOf(t, f)
				if err := syscall.SetsockoptLinger(fd, syscall.SOL_SOCKET, syscall.SO_LINGER, &linger); err != nil {
					t.Fatal(err)
				}
				s, err := adoptFile(f, false)
				if err != nil {
					t.Fatal(err)
				}
				p, err := (*Config)(nil).prepare(styleFile)
				if err != nil {
					t.Fatal(err)
				}
				injected := &failConnControl{RawConn: s.raw, at: stage.at}
				s.raw = injected
				before := openFds(t)
				c, err := newConn(s, kindAdopted, p)
				if c != nil {
					_ = c.Abort()
				}
				if !errors.Is(err, net.ErrClosed) {
					t.Fatalf("newConn = %v, want the injected control failure", err)
				}
				if after := openFds(t); after != before-1 {
					t.Errorf("descriptors = %d, want %d", after, before-1)
				}
				var got syscall.Linger
				l := uint32(unsafe.Sizeof(got))
				err = rawGetsockopt(fd, syscall.SOL_SOCKET, syscall.SO_LINGER, unsafe.Pointer(&got), &l)
				if err != nil || got != linger {
					t.Errorf("caller SO_LINGER = %v, %v, want %v", got, err, linger)
				}
				if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
					t.Fatal(err)
				}
				if _, err := server.Write([]byte("still live")); err != nil {
					t.Fatal(err)
				}
				var b [32]byte
				if n, err := client.Read(b[:]); err != nil || !bytes.Equal(b[:n], []byte("still live")) {
					t.Errorf("caller socket Read = %q, %v", b[:n], err)
				}
			})
		}
	}
}

func TestWrapSocketFileRefusesUnpollableDescriptor(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "regular")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	before := openFds(t)
	for range 20 {
		fd, err := syscall.Dup(int(f.Fd()))
		if err != nil {
			t.Fatal(err)
		}
		if err := syscall.SetNonblock(fd, true); err != nil {
			_ = syscall.Close(fd)
			t.Fatal(err)
		}
		s, err := wrapSocketFile(fd, afInet, "sctp4")
		if !errors.Is(err, os.ErrNoDeadline) {
			t.Errorf("wrapSocketFile = %v, want ErrNoDeadline", err)
		}
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if errno != syscall.EBADF {
			t.Errorf("refused descriptor remains open: %v", errno)
		}
		if s.file != nil {
			_ = s.file.Close()
		} else if errno == 0 {
			_ = syscall.Close(fd)
		}
	}
	if after := openFds(t); after != before {
		t.Errorf("descriptor count = %d, want %d", after, before)
	}
}

func TestRemotePortZeroRefusedBeforeSetup(t *testing.T) {
	var calls atomic.Int32
	cfg := &Config{Control: func(string, string, syscall.RawConn) error { calls.Add(1); return nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	c, err := cfg.Dial(ctx, "sctp4", nil, loopback4(0))
	if c != nil {
		_ = c.Abort()
	}
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("Dial port 0 = %v, want EINVAL", err)
	}
	if calls.Load() != 0 {
		t.Errorf("Dial port 0 opened a socket: Control calls = %d", calls.Load())
	}
	e := openEndpoint(t, nil, "sctp4", nil)
	before := endpointAddrPort(e)
	injected := &failConnControl{RawConn: e.sock.raw, at: 1}
	e.sock.raw = injected
	id, err := e.Connect(loopback4(0))
	if id != 0 || !errors.Is(err, syscall.EINVAL) {
		t.Errorf("Connect port 0 = %d, %v, want 0, EINVAL", id, err)
	}
	if after := endpointAddrPort(e); after != before {
		t.Errorf("invalid Connect autobound port %d -> %d", before, after)
	}
	if injected.calls != 0 {
		t.Errorf("Connect port 0 made %d socket calls", injected.calls)
	}
}
func endpointAddrPort(e *Endpoint) uint16 { return e.Addr().(*Addr).Port }

func TestLocalAddressValidationBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		ips  []netip.Addr
		want bool
	}{
		{"unset", nil, false},
		{"empty", []netip.Addr{}, false},
		{"one", []netip.Addr{netip.MustParseAddr("127.0.0.1")}, false},
		{"distinct", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")}, false},
		{"different zones", []netip.Addr{netip.MustParseAddr("fe80::1%a"), netip.MustParseAddr("fe80::1%b")}, false},
		{"third repeats first", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("::ffff:127.0.0.1")}, true},
		{"third repeats second", []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("127.0.0.2")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateLocalIPs(afInet6, tc.ips)
			if errors.Is(err, syscall.EINVAL) != tc.want {
				t.Fatalf("validateLocalIPs = %v, duplicate = %v", err, tc.want)
			}
			if tc.want {
				previous := "address 0"
				if tc.name == "third repeats second" {
					previous = "address 1"
				}
				if !strings.Contains(err.Error(), "address 2") || !strings.Contains(err.Error(), previous) {
					t.Errorf("duplicate indexes missing: %v", err)
				}
			}
		})
	}
}

func TestDuplicateBindAddressesRefused(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	l := mustListen(t, nil, "sctp4", loopback4(0))
	e := openEndpoint(t, nil, "sctp4", loopback4(0))
	ips := []netip.Addr{netip.MustParseAddr("127.0.0.2"), netip.MustParseAddr("::ffff:127.0.0.2")}
	for name, fn := range map[string]func(...netip.Addr) error{
		"Conn.BindAdd": client.BindAdd, "Conn.BindRemove": client.BindRemove,
		"Listener.BindAdd": l.BindAdd, "Listener.BindRemove": l.BindRemove,
		"Endpoint.BindAdd": e.BindAdd, "Endpoint.BindRemove": e.BindRemove,
	} {
		t.Run(name, func(t *testing.T) {
			err := fn(ips...)
			if !errors.Is(err, syscall.EINVAL) || !strings.Contains(err.Error(), "address 1") || !strings.Contains(err.Error(), "address 0") {
				t.Fatalf("%s = %v, want duplicate indexes", name, err)
			}
		})
	}
}

func TestRemotePortBoundariesReachSetup(t *testing.T) {
	reached := errors.New("socket setup reached")
	for _, port := range []uint16{1, 65534, 65535} {
		t.Run(strconv.Itoa(int(port)), func(t *testing.T) {
			calls := 0
			cfg := &Config{Control: func(string, string, syscall.RawConn) error { calls++; return reached }}
			c, err := cfg.Dial(context.Background(), "sctp4", nil, loopback4(port))
			if c != nil || !errors.Is(err, reached) || calls != 1 {
				t.Fatalf("Dial port %d = %v, %v, Control calls %d", port, c, err, calls)
			}
			e := openEndpoint(t, nil, "sctp4", nil)
			injected := &failConnControl{RawConn: e.sock.raw, at: 1}
			e.sock.raw = injected
			id, err := e.Connect(loopback4(port))
			if id != 0 || !errors.Is(err, net.ErrClosed) || injected.calls != 1 {
				t.Fatalf("Connect port %d = %d, %v, Control calls %d", port, id, err, injected.calls)
			}
		})
	}
}

func TestNewConnOwnedFailureAbortsSocket(t *testing.T) {
	for _, kind := range []connKind{kindDialed, kindAccepted, kindPeeled} {
		t.Run(strconv.Itoa(int(kind)), func(t *testing.T) {
			client, _ := connPair(t, nil, nil)
			f := connFile(t, client)
			s, err := adoptFile(f, false)
			if err != nil {
				t.Fatal(err)
			}
			p, err := (*Config)(nil).prepare(styleDial)
			if err != nil {
				t.Fatal(err)
			}
			s.raw = &failConnControl{RawConn: s.raw, at: 1}
			c, err := newConn(s, kind, p)
			if c != nil {
				_ = c.Abort()
			}
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("newConn = %v", err)
			}
			var got syscall.Linger
			l := uint32(unsafe.Sizeof(got))
			if err := rawGetsockopt(fdOf(t, f), syscall.SOL_SOCKET, syscall.SO_LINGER, unsafe.Pointer(&got), &l); err != nil {
				t.Fatal(err)
			}
			if got.Onoff != 1 || got.Linger != 0 {
				t.Errorf("owned socket linger = %v, want {1 0}", got)
			}
		})
	}
}

func TestLocalAddressValidationSocketFamily(t *testing.T) {
	for _, tc := range []struct {
		name      string
		family    int
		ips       []string
		duplicate bool
	}{
		{"IPv6 wildcards", afInet6, []string{"0.0.0.0", "::"}, true},
		{"IPv6 wildcards reversed", afInet6, []string{"::", "0.0.0.0"}, true},
		{"IPv6 mapped wildcard", afInet6, []string{"::ffff:0.0.0.0", "::"}, true},
		{"IPv6 mapped wildcard reversed", afInet6, []string{"::", "::ffff:0.0.0.0"}, true},
		{"IPv6 plain and mapped IPv4 wildcard", afInet6, []string{"0.0.0.0", "::ffff:0.0.0.0"}, true},
		{"IPv6 wildcard and specific IPv4", afInet6, []string{"::", "127.0.0.1"}, false},
		{"IPv6 wildcard and specific IPv6", afInet6, []string{"0.0.0.0", "::1"}, false},
		{"IPv6 specific mapped IPv4", afInet6, []string{"127.0.0.1", "::ffff:127.0.0.1"}, true},
		{"IPv6 one IPv4 wildcard", afInet6, []string{"0.0.0.0"}, false},
		{"IPv6 one IPv6 wildcard", afInet6, []string{"::"}, false},
		{"IPv4 wildcards remain distinct", afInet, []string{"0.0.0.0", "::"}, false},
		{"IPv4 wildcards reversed remain distinct", afInet, []string{"::", "0.0.0.0"}, false},
		{"IPv4 mapped wildcard and IPv6 wildcard remain distinct", afInet, []string{"::ffff:0.0.0.0", "::"}, false},
		{"IPv4 repeated wildcard", afInet, []string{"0.0.0.0", "0.0.0.0"}, true},
		{"IPv4 plain and mapped wildcard", afInet, []string{"0.0.0.0", "::ffff:0.0.0.0"}, true},
		{"IPv4 wildcard and specific address", afInet, []string{"0.0.0.0", "127.0.0.1"}, false},
		{"IPv4 specific mapped address", afInet, []string{"127.0.0.1", "::ffff:127.0.0.1"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ips := make([]netip.Addr, len(tc.ips))
			for i, text := range tc.ips {
				ips[i] = netip.MustParseAddr(text)
			}
			err := validateLocalIPs(tc.family, ips)
			if tc.duplicate {
				if !errors.Is(err, syscall.EINVAL) || !strings.Contains(err.Error(), "address 1") || !strings.Contains(err.Error(), "address 0") {
					t.Fatalf("validateLocalIPs = %v, want duplicate indexes 1 and 0", err)
				}
			} else if err != nil {
				t.Fatalf("validateLocalIPs = %v, want no duplicate", err)
			}
		})
	}
}

// TestAcceptSkipsPeerFromPortZero runs the handshake from source port 0,
// which RFC 9260 §3.1 forbids and Linux does not refuse. accept(2) then fails
// with ECONNABORTED, because it cannot report that peer's address (net/socket.c:
// do_accept; net/ipv4/af_inet.c: inet_getname), and Accept must go on to the
// next association rather than report a failure a loop would stop on.
func TestAcceptSkipsPeerFromPortZero(t *testing.T) {
	raw, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, ipprotoSCTP)
	if errors.Is(err, syscall.EPERM) {
		t.Skip("a raw socket needs CAP_NET_RAW")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Close(raw) })
	source := &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 2}}
	if err := syscall.Bind(raw, source); err != nil {
		t.Fatal(err)
	}
	wait := syscall.NsecToTimeval(int64(3 * time.Second))
	if err := syscall.SetsockoptTimeval(raw, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &wait); err != nil {
		t.Fatal(err)
	}

	l := mustListen(t, nil, "sctp4", loopback4(0))
	port := l.Addr().(*Addr).Port
	dest := &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}

	const initTag, initialTSN = 0x5A5A0001, 1
	init := binary.BigEndian.AppendUint32([]byte{1, 0, 0, 20}, initTag)
	init = binary.BigEndian.AppendUint32(init, 1<<20) // a_rwnd
	init = append(init, 0, 10, 0, 10)                 // streams, out and in
	init = binary.BigEndian.AppendUint32(init, initialTSN)
	if err := syscall.Sendto(raw, sctpPacketFromPortZero(port, 0, init), 0, dest); err != nil {
		t.Fatal(err)
	}
	peerTag, cookie := awaitInitAck(t, raw, port, initTag)

	echo := binary.BigEndian.AppendUint16([]byte{10, 0}, uint16(4+len(cookie)))
	echo = append(echo, cookie...)
	echo = append(echo, make([]byte, -len(echo)&3)...)
	if err := syscall.Sendto(raw, sctpPacketFromPortZero(port, peerTag, echo), 0, dest); err != nil {
		t.Fatal(err)
	}
	// Whatever accept(2) did with it, end the association now rather than
	// leave it retransmitting a SHUTDOWN to a peer that will never answer.
	t.Cleanup(func() {
		_ = syscall.Sendto(raw, sctpPacketFromPortZero(port, peerTag, []byte{6, 0, 0, 4}), 0, dest)
	})
	awaitChunk(t, raw, port, initTag, 11) // COOKIE ACK: the association is queued for Accept

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	client, err := Dial(ctx, "sctp4", nil, l.Addr().(*Addr))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Abort() }()

	if err := l.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	c, err := l.AcceptSCTP()
	if err != nil {
		t.Fatalf("Accept with a port-0 association queued first: %v", err)
	}
	defer func() { _ = c.Abort() }()
	if got, want := c.RemoteAddr().(*Addr).Port, client.LocalAddr().(*Addr).Port; got != want {
		t.Fatalf("Accept returned peer port %d, want the next association's %d", got, want)
	}
}

// sctpPacketFromPortZero is an SCTP packet with source port 0 and a correct
// CRC32c (RFC 9260 §6.8, stored least significant byte first as Appendix A says).
func sctpPacketFromPortZero(dport uint16, vtag uint32, chunks []byte) []byte {
	b := binary.BigEndian.AppendUint16([]byte{0, 0}, dport)
	b = binary.BigEndian.AppendUint32(b, vtag)
	b = append(b, 0, 0, 0, 0)
	b = append(b, chunks...)
	binary.LittleEndian.PutUint32(b[8:], crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli)))
	return b
}

// awaitChunk reads the raw socket until a packet of this exchange arrives
// whose first chunk has the given type, and returns that chunk. A raw SCTP
// socket sees all of the host's SCTP traffic, so anything else is skipped.
func awaitChunk(t *testing.T, raw int, port uint16, tag uint32, chunkType byte) []byte {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	buf := make([]byte, 1<<16)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(raw, buf, 0)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			t.Fatalf("waiting for chunk type %d: %v", chunkType, err)
		}
		if n < 20 {
			continue
		}
		pkt := buf[int(buf[0]&0x0f)*4 : n] // past the IP header
		if len(pkt) < 16 || binary.BigEndian.Uint16(pkt) != port || binary.BigEndian.Uint16(pkt[2:]) != 0 ||
			binary.BigEndian.Uint32(pkt[4:]) != tag || pkt[12] != chunkType {
			continue
		}
		return slices.Clone(pkt[12:])
	}
	t.Fatalf("no chunk type %d within the wait", chunkType)
	return nil
}

// awaitInitAck returns the initiate tag and state cookie of the INIT ACK.
func awaitInitAck(t *testing.T, raw int, port uint16, tag uint32) (uint32, []byte) {
	t.Helper()
	chunk := awaitChunk(t, raw, port, tag, 2)
	if len(chunk) < 20 {
		t.Fatalf("INIT ACK of %d bytes", len(chunk))
	}
	end := min(int(binary.BigEndian.Uint16(chunk[2:])), len(chunk))
	for off := 20; off+4 <= end; {
		kind, length := binary.BigEndian.Uint16(chunk[off:]), int(binary.BigEndian.Uint16(chunk[off+2:]))
		if length < 4 || off+length > end {
			break
		}
		if kind == 7 { // State Cookie, RFC 9260 §3.3.3
			return binary.BigEndian.Uint32(chunk[4:]), slices.Clone(chunk[off+4 : off+length])
		}
		off += (length + 3) &^ 3
	}
	t.Fatal("INIT ACK carries no state cookie")
	return 0, nil
}
