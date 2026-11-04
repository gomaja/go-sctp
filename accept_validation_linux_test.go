// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
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
	testHookAccept4 = func(fd, flags int) (int, syscall.Sockaddr, error) {
		switch calls.Add(1) {
		case 1:
			return -1, nil, syscall.ECONNABORTED
		case 2:
			return -1, nil, syscall.EINTR
		case 3:
			return -1, nil, syscall.EAGAIN
		default:
			return syscall.Accept4(fd, flags)
		}
	}
	t.Cleanup(func() { testHookAccept4 = nil })
	client, server := dialAccept(t, nil, l)
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
	dead := deadPort(t)
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
			resolved, err := ResolveAddr("sctp6", ips[0].String()+"/"+ips[0].String()+":80")
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
			t.Run(stage.name+"/"+time.Duration(linger.Linger).String(), func(t *testing.T) {
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
				if !errors.Is(err, syscall.EIO) {
					t.Fatalf("newConn = %v, want injected EIO", err)
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
	id, err := e.Connect(loopback4(0))
	if id != 0 || !errors.Is(err, syscall.EINVAL) {
		t.Errorf("Connect port 0 = %d, %v, want 0, EINVAL", id, err)
	}
	if after := endpointAddrPort(e); after != before {
		t.Errorf("invalid Connect autobound port %d -> %d", before, after)
	}
}
func endpointAddrPort(e *Endpoint) uint16 { return e.Addr().(*Addr).Port }
