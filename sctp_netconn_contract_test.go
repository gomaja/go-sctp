//go:build linux
// +build linux

package sctp

import (
	"errors"
	"net"
	"os"
	"reflect"
	"testing"
	"time"
)

const (
	netConnContractParkWindow     = 150 * time.Millisecond
	netConnContractDeadlineWindow = 300 * time.Millisecond
	netConnContractReturnBound    = 3 * time.Second
)

type netConnContractIOResult struct {
	n   int
	err error
}

// TestNetConnPendingReadObservesLaterDeadline exercises the part of
// net.Conn.SetReadDeadline that cannot be proved by setting a deadline before
// Read starts: a setter in another goroutine must interrupt an already-pending
// read.
func TestNetConnPendingReadObservesLaterDeadline(t *testing.T) {
	client, server := eorPairNoCleanup(t)
	t.Cleanup(func() { _ = client.Abort() })
	t.Cleanup(func() { _ = server.Abort() })

	var conn net.Conn = server
	started := make(chan struct{})
	done := make(chan netConnContractIOResult, 1)
	go func() {
		close(started)
		n, err := conn.Read(make([]byte, 1))
		done <- netConnContractIOResult{n: n, err: err}
	}()
	<-started

	select {
	case result := <-done:
		t.Fatalf("Read returned before a deadline was set: n=%d err=%v", result.n, result.err)
	case <-time.After(netConnContractParkWindow):
	}

	deadline := time.Now().Add(netConnContractDeadlineWindow)
	if err := conn.SetReadDeadline(deadline); err != nil {
		_, _ = client.SCTPWrite([]byte{1}, nil)
		select {
		case <-done:
		case <-time.After(netConnContractReturnBound):
		}
		t.Fatalf("SetReadDeadline on an open connection: %v", err)
	}

	select {
	case result := <-done:
		if result.n != 0 {
			t.Errorf("Read returned n=%d after its deadline, want 0", result.n)
		}
		if !errors.Is(result.err, os.ErrDeadlineExceeded) {
			t.Errorf("Read error = %v, want an error wrapping os.ErrDeadlineExceeded", result.err)
		}
		if time.Now().Before(deadline.Add(-netConnContractDeadlineWindow / 3)) {
			t.Errorf("Read returned well before the deadline set on the pending call")
		}
	case <-time.After(netConnContractReturnBound):
		// A write is the reliable release for the pre-poller implementation:
		// setting another deadline cannot wake the recvmsg that is already in
		// the kernel.
		_, _ = client.SCTPWrite([]byte{1}, nil)
		select {
		case <-done:
		case <-time.After(netConnContractReturnBound):
			t.Error("Read could not be released after missing the deadline")
		}
		t.Errorf("a pending Read was not interrupted within %v of SetReadDeadline", netConnContractReturnBound)
	}
}

// TestSCTPListenerPendingAcceptObservesLaterDeadline is the listener analogue:
// SetDeadline must wake an Accept that began with no deadline at all.
func TestSCTPListenerPendingAcceptObservesLaterDeadline(t *testing.T) {
	ln, err := ListenSCTP("sctp", loopbackAddr())
	if err != nil {
		t.Fatalf("ListenSCTP: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type acceptResult struct {
		conn *SCTPConn
		err  error
	}
	started := make(chan struct{})
	done := make(chan acceptResult, 1)
	go func() {
		close(started)
		conn, acceptErr := ln.AcceptSCTP()
		done <- acceptResult{conn: conn, err: acceptErr}
	}()
	<-started

	select {
	case result := <-done:
		if result.conn != nil {
			_ = result.conn.Abort()
		}
		t.Fatalf("AcceptSCTP returned before a deadline was set: %v", result.err)
	case <-time.After(netConnContractParkWindow):
	}

	deadline := time.Now().Add(netConnContractDeadlineWindow)
	if err := ln.SetDeadline(deadline); err != nil {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(netConnContractReturnBound):
		}
		t.Fatalf("SetDeadline on an open listener: %v", err)
	}

	select {
	case result := <-done:
		if result.conn != nil {
			_ = result.conn.Abort()
			t.Errorf("AcceptSCTP returned a connection after its deadline")
		}
		if !errors.Is(result.err, os.ErrDeadlineExceeded) {
			t.Errorf("AcceptSCTP error = %v, want an error wrapping os.ErrDeadlineExceeded", result.err)
		}
		if time.Now().Before(deadline.Add(-netConnContractDeadlineWindow / 3)) {
			t.Errorf("AcceptSCTP returned well before the deadline set on the pending call")
		}
	case <-time.After(netConnContractReturnBound):
		_ = ln.Close()
		select {
		case result := <-done:
			if result.conn != nil {
				_ = result.conn.Abort()
			}
		case <-time.After(netConnContractReturnBound):
			t.Error("AcceptSCTP could not be released after missing the deadline")
		}
		t.Errorf("a pending AcceptSCTP was not interrupted within %v of SetDeadline", netConnContractReturnBound)
	}
}

// TestNetConnWriteWaitsForBufferSpace pins ordinary net.Conn.Write to
// backpressure rather than the non-blocking SCTPWrite API. Once the kernel send
// buffer is full, a later deadline or Close must interrupt the pending Write.
func TestNetConnWriteWaitsForBufferSpace(t *testing.T) {
	t.Run("deadline set while blocked", func(t *testing.T) {
		client, server := eorPairNoCleanup(t)
		t.Cleanup(func() { _ = client.Abort() })
		t.Cleanup(func() { _ = server.Abort() })

		payload := fill(2048)
		sent := fillSendBuffer(t, client, payload)
		var conn net.Conn = client

		started := make(chan struct{})
		done := make(chan netConnContractIOResult, 1)
		go func() {
			close(started)
			n, err := conn.Write(payload)
			done <- netConnContractIOResult{n: n, err: err}
		}()
		<-started

		select {
		case result := <-done:
			t.Fatalf("Write on a full send buffer returned instead of applying backpressure: n=%d err=%v", result.n, result.err)
		case <-time.After(netConnContractParkWindow):
		}

		deadline := time.Now().Add(netConnContractDeadlineWindow)
		if err := conn.SetWriteDeadline(deadline); err != nil {
			releaseNetConnContractWriter(server, sent)
			select {
			case <-done:
			case <-time.After(netConnContractReturnBound):
			}
			t.Fatalf("SetWriteDeadline on an open connection: %v", err)
		}

		select {
		case result := <-done:
			if result.n < 0 || result.n > len(payload) {
				t.Errorf("Write returned invalid count %d for a %d-byte buffer", result.n, len(payload))
			}
			if !errors.Is(result.err, os.ErrDeadlineExceeded) {
				t.Errorf("Write error = %v, want an error wrapping os.ErrDeadlineExceeded", result.err)
			}
			if time.Now().Before(deadline.Add(-netConnContractDeadlineWindow / 3)) {
				t.Errorf("Write returned well before the deadline set on the pending call")
			}
		case <-time.After(netConnContractReturnBound):
			drained := releaseNetConnContractWriter(server, sent)
			select {
			case <-done:
			case <-time.After(netConnContractReturnBound):
				t.Error("Write could not be released by draining the peer")
			}
			select {
			case <-drained:
			case <-time.After(netConnContractReturnBound):
			}
			t.Errorf("a pending Write was not interrupted within %v of SetWriteDeadline", netConnContractReturnBound)
		}
	})

	t.Run("Close", func(t *testing.T) {
		client, server := eorPairNoCleanup(t)
		t.Cleanup(func() { _ = client.Abort() })
		t.Cleanup(func() { _ = server.Abort() })

		payload := fill(2048)
		fillSendBuffer(t, client, payload)
		var conn net.Conn = client

		started := make(chan struct{})
		writeDone := make(chan netConnContractIOResult, 1)
		go func() {
			close(started)
			n, err := conn.Write(payload)
			writeDone <- netConnContractIOResult{n: n, err: err}
		}()
		<-started

		select {
		case result := <-writeDone:
			t.Fatalf("Write on a full send buffer returned before Close: n=%d err=%v", result.n, result.err)
		case <-time.After(netConnContractParkWindow):
		}

		closeDone := make(chan error, 1)
		go func() { closeDone <- conn.Close() }()

		select {
		case result := <-writeDone:
			if result.n < 0 || result.n > len(payload) {
				t.Errorf("Write returned invalid count %d for a %d-byte buffer", result.n, len(payload))
			}
			if !errors.Is(result.err, net.ErrClosed) {
				t.Errorf("Write interrupted by Close returned %v, want an error wrapping net.ErrClosed", result.err)
			}
		case <-time.After(netConnContractReturnBound + 2*time.Second):
			_ = server.Abort()
			t.Errorf("Close did not interrupt a pending Write within %v", netConnContractReturnBound+2*time.Second)
		}

		select {
		case err := <-closeDone:
			if err != nil {
				t.Errorf("Close: %v", err)
			}
		case <-time.After(netConnContractReturnBound + 2*time.Second):
			_ = server.Abort()
			t.Errorf("Close did not return within %v", netConnContractReturnBound+2*time.Second)
		}
	})
}

func releaseNetConnContractWriter(server *SCTPConn, sent int) <-chan struct{} {
	begin := make(chan struct{})
	drained := drainAfter(server, begin, sent)
	close(begin)
	return drained
}

// TestNetConnDeadlineSettersAfterClose checks every setter, including the
// listener-specific one. A caller must be able to use errors.Is(err,
// net.ErrClosed) consistently after ownership of the descriptor has ended.
func TestNetConnDeadlineSettersAfterClose(t *testing.T) {
	t.Run("connection", func(t *testing.T) {
		client, server := eorPairNoCleanup(t)
		t.Cleanup(func() { _ = client.Abort() })
		t.Cleanup(func() { _ = server.Abort() })

		if err := client.CloseWithTimeout(200 * time.Millisecond); err != nil {
			t.Fatalf("CloseWithTimeout: %v", err)
		}
		deadline := time.Now().Add(time.Second)
		for _, test := range []struct {
			name string
			set  func(time.Time) error
		}{
			{name: "SetDeadline", set: client.SetDeadline},
			{name: "SetReadDeadline", set: client.SetReadDeadline},
			{name: "SetWriteDeadline", set: client.SetWriteDeadline},
		} {
			t.Run(test.name, func(t *testing.T) {
				err := test.set(deadline)
				if !errors.Is(err, net.ErrClosed) {
					t.Errorf("%s after Close = %v, want an error wrapping net.ErrClosed", test.name, err)
				}
			})
		}
	})

	t.Run("listener", func(t *testing.T) {
		ln, err := ListenSCTP("sctp", loopbackAddr())
		if err != nil {
			t.Fatalf("ListenSCTP: %v", err)
		}
		if err := ln.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := ln.SetDeadline(time.Now().Add(time.Second)); !errors.Is(err, net.ErrClosed) {
			t.Errorf("SetDeadline after Close = %v, want an error wrapping net.ErrClosed", err)
		}
	})
}

// TestNetConnAddressesRemainStableAfterClose requires address accessors to use
// immutable snapshots. Each call after Close must retain the established
// endpoint and return storage that a caller cannot use to mutate a later call.
func TestNetConnAddressesRemainStableAfterClose(t *testing.T) {
	ln, err := ListenSCTP("sctp", loopbackAddr())
	if err != nil {
		t.Fatalf("ListenSCTP: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type acceptResult struct {
		conn *SCTPConn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		conn, acceptErr := ln.AcceptSCTP()
		accepted <- acceptResult{conn: conn, err: acceptErr}
	}()

	client, err := DialSCTP("sctp", nil, listenerAddr(t, ln))
	if err != nil {
		t.Fatalf("DialSCTP: %v", err)
	}
	t.Cleanup(func() { _ = client.Abort() })

	var server *SCTPConn
	select {
	case result := <-accepted:
		if result.err != nil {
			t.Fatalf("AcceptSCTP: %v", result.err)
		}
		server = result.conn
	case <-time.After(netConnContractReturnBound):
		t.Fatal("AcceptSCTP did not return after DialSCTP established an association")
	}
	t.Cleanup(func() { _ = server.Abort() })

	wantListener := netConnContractAddrSnapshot(t, ln.Addr())
	wantLocal := netConnContractAddrSnapshot(t, client.LocalAddr())
	wantRemote := netConnContractAddrSnapshot(t, client.RemoteAddr())

	if err := client.CloseWithTimeout(200 * time.Millisecond); err != nil {
		t.Fatalf("closing connection: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("closing listener: %v", err)
	}

	for _, test := range []struct {
		name string
		get  func() net.Addr
		want *SCTPAddr
	}{
		{name: "LocalAddr", get: client.LocalAddr, want: wantLocal},
		{name: "RemoteAddr", get: client.RemoteAddr, want: wantRemote},
		{name: "Listener.Addr", get: ln.Addr, want: wantListener},
	} {
		t.Run(test.name, func(t *testing.T) {
			first := netConnContractAddrSnapshot(t, test.get())
			if !reflect.DeepEqual(first, test.want) {
				t.Errorf("address after Close = %#v, want stable snapshot %#v", first, test.want)
			}

			netConnContractMutateAddr(first)
			second := netConnContractAddrSnapshot(t, test.get())
			if !reflect.DeepEqual(second, test.want) {
				t.Errorf("address after mutating a prior result = %#v, want independent deep copy %#v", second, test.want)
			}
		})
	}
}

func netConnContractAddrSnapshot(t *testing.T, addr net.Addr) *SCTPAddr {
	t.Helper()
	sctpAddr, ok := addr.(*SCTPAddr)
	if !ok || sctpAddr == nil {
		t.Fatalf("address = %v (%T), want non-nil *SCTPAddr", addr, addr)
	}
	return cloneNetConnContractAddr(sctpAddr)
}

func cloneNetConnContractAddr(addr *SCTPAddr) *SCTPAddr {
	clone := &SCTPAddr{Port: addr.Port}
	if len(addr.IPAddrs) != 0 {
		clone.IPAddrs = make([]net.IPAddr, len(addr.IPAddrs))
		for i, ip := range addr.IPAddrs {
			clone.IPAddrs[i] = net.IPAddr{
				IP:   append(net.IP(nil), ip.IP...),
				Zone: ip.Zone,
			}
		}
	}
	return clone
}

func netConnContractMutateAddr(addr *SCTPAddr) {
	addr.Port = (addr.Port + 1) & 0xffff
	if len(addr.IPAddrs) == 0 {
		addr.IPAddrs = append(addr.IPAddrs, net.IPAddr{IP: net.IPv4(192, 0, 2, 1), Zone: "changed"})
		return
	}
	addr.IPAddrs[0].Zone += "-changed"
	if len(addr.IPAddrs[0].IP) != 0 {
		addr.IPAddrs[0].IP[0] ^= 0xff
	}
	addr.IPAddrs = append(addr.IPAddrs, net.IPAddr{IP: net.IPv4(192, 0, 2, 1)})
}

// TestNetConnZeroLengthClosedParity prevents the empty-buffer fast paths from
// hiding that the connection is closed. Both directions must report the same
// closed-connection condition while preserving the only valid byte count.
func TestNetConnZeroLengthClosedParity(t *testing.T) {
	client, server := eorPairNoCleanup(t)
	t.Cleanup(func() { _ = client.Abort() })
	t.Cleanup(func() { _ = server.Abort() })

	if err := client.CloseWithTimeout(200 * time.Millisecond); err != nil {
		t.Fatalf("CloseWithTimeout: %v", err)
	}
	var conn net.Conn = client

	for _, test := range []struct {
		name string
		call func() (int, error)
	}{
		{name: "Read(nil)", call: func() (int, error) { return conn.Read(nil) }},
		{name: "Write(nil)", call: func() (int, error) { return conn.Write(nil) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			n, err := test.call()
			if n != 0 {
				t.Errorf("byte count = %d, want 0", n)
			}
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("error = %v, want an error wrapping net.ErrClosed", err)
			}
		})
	}
}
