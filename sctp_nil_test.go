package sctp

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestNilPublicReceiversReturnErrors(t *testing.T) {
	var conn *SCTPConn
	if conn.fd() != -1 {
		t.Fatalf("nil SCTPConn fd = %d, want -1", conn.fd())
	}
	if conn.LocalAddr() != nil || conn.RemoteAddr() != nil {
		t.Fatal("nil SCTPConn returned a non-nil address")
	}

	checks := []struct {
		name string
		call func() error
	}{
		{"Read", func() error { _, err := conn.Read(make([]byte, 1)); return err }},
		{"Write", func() error { _, err := conn.Write([]byte("x")); return err }},
		{"SCTPWrite", func() error { _, err := conn.SCTPWrite([]byte("x"), nil); return err }},
		{"SCTPWriteInfo", func() error { _, err := conn.SCTPWriteInfo([]byte("x"), nil, nil, nil); return err }},
		{"SetDeadline", func() error { return conn.SetDeadline(time.Now()) }},
		{"SCTPLocalAddr", func() error { _, err := conn.SCTPLocalAddr(0); return err }},
		{"SCTPRemoteAddr", func() error { _, err := conn.SCTPRemoteAddr(0); return err }},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil {
				t.Fatal("nil receiver returned no error")
			}
		})
	}

	var listener *SCTPListener
	if listener.fd() != -1 {
		t.Fatalf("nil SCTPListener fd = %d, want -1", listener.fd())
	}
	if listener.Addr() != nil {
		t.Fatal("nil SCTPListener returned a non-nil address")
	}
	if err := listener.SetDeadline(time.Now()); err == nil {
		t.Fatal("nil SCTPListener.SetDeadline returned no error")
	}
}

func TestNilWrappedConnDoesNotPanic(t *testing.T) {
	wrappers := []*SCTPSndRcvInfoWrappedConn{
		nil,
		NewSCTPSndRcvInfoWrappedConn(nil),
	}
	for i, wrapped := range wrappers {
		t.Run(string(rune('A'+i)), func(t *testing.T) {
			if wrapped.LocalAddr() != nil || wrapped.RemoteAddr() != nil {
				t.Fatal("nil wrapped connection returned a non-nil address")
			}
			checks := []func() error{
				func() error { _, err := wrapped.Read(make([]byte, sndRcvInfoSize)); return err },
				func() error { _, err := wrapped.Write(make([]byte, sndRcvInfoSize)); return err },
				wrapped.Close,
				func() error { return wrapped.SetDeadline(time.Now()) },
				func() error { return wrapped.SetReadDeadline(time.Now()) },
				func() error { return wrapped.SetWriteDeadline(time.Now()) },
				func() error { return wrapped.SetReadBuffer(1) },
				func() error { _, err := wrapped.GetReadBuffer(); return err },
				func() error { return wrapped.SetWriteBuffer(1) },
				func() error { _, err := wrapped.GetWriteBuffer(); return err },
			}
			for j, call := range checks {
				if err := call(); err == nil {
					t.Fatalf("operation %d returned no error", j)
				} else if !errors.Is(err, net.ErrClosed) {
					t.Errorf("operation %d error = %v, want net.ErrClosed", j, err)
				}
			}
		})
	}
}

func TestNilSocketOptionArgumentsReturnEINVAL(t *testing.T) {
	conn := &SCTPConn{_fd: -1}
	checks := []struct {
		name string
		call func() error
	}{
		{"SetRemoteUDPEncapsPort", func() error { return conn.SetRemoteUDPEncapsPort(nil) }},
		{"GetRemoteUDPEncapsPort", func() error { return conn.GetRemoteUDPEncapsPort(nil) }},
		{"SetProbeInterval", func() error { return conn.SetProbeInterval(nil) }},
		{"GetProbeInterval", func() error { return conn.GetProbeInterval(nil) }},
		{"SetDefaultSentParam", func() error { return conn.SetDefaultSentParam(nil) }},
		{"SetSackTimer", func() error { return conn.SetSackTimer(nil) }},
		{"SetRtoInfo", func() error { return conn.SetRtoInfo(nil) }},
		{"SetAssocInfo", func() error { return conn.SetAssocInfo(nil) }},
		{"SetDefaultSndInfo", func() error { return conn.SetDefaultSndInfo(nil) }},
		{"SetDefaultPrInfo", func() error { return conn.SetDefaultPrInfo(nil) }},
		{"SetPeerAddrThlds", func() error { return conn.SetPeerAddrThlds(nil) }},
		{"SetPeerAddrThldsV2", func() error { return conn.SetPeerAddrThldsV2(nil) }},
		{"SetPeerAddrParams", func() error { return conn.SetPeerAddrParams(nil) }},
		{"GetPeerAddrParams", func() error { return conn.GetPeerAddrParams(nil) }},
		{"GetPeerAddrInfo", func() error { return conn.GetPeerAddrInfo(nil) }},
	}
	for _, tc := range checks {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("error = %v, want EINVAL", err)
			}
		})
	}
}

func TestNilAddressesReturnErrors(t *testing.T) {
	if _, err := SCTPConnect(-1, nil); err == nil {
		t.Fatal("SCTPConnect accepted a nil address")
	}
	if err := SCTPBind(-1, nil, SCTP_BINDX_ADD_ADDR); err == nil {
		t.Fatal("SCTPBind accepted a nil address")
	}
}

func TestNilDialContextReturnsEINVAL(t *testing.T) {
	var nilContext context.Context
	raddr := &SCTPAddr{
		IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}},
		Port:    9,
	}
	var nilConfig *SocketConfig
	tests := []struct {
		name string
		dial func() (*SCTPConn, error)
	}{
		{
			name: "DialSCTPContext",
			dial: func() (*SCTPConn, error) {
				return DialSCTPContext(nilContext, "sctp4", nil, raddr, InitMsg{})
			},
		},
		{
			name: "SocketConfig.DialContext",
			dial: func() (*SCTPConn, error) {
				return (&SocketConfig{}).DialContext(nilContext, "sctp4", nil, raddr)
			},
		},
		{
			name: "nil SocketConfig.DialContext",
			dial: func() (*SCTPConn, error) {
				return nilConfig.DialContext(nilContext, "sctp4", nil, raddr)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := tc.dial()
			if conn != nil {
				t.Fatalf("connection = %v, want nil", conn)
			}
			if !errors.Is(err, syscall.EINVAL) {
				t.Fatalf("error = %v, want EINVAL", err)
			}
		})
	}
}
