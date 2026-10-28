// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"context"
	"io"
	"os"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// TestDialSetupRTOInitialRestoresLasting covers defaults, Control and typed
// settings. Multiples of 20 ms convert exactly at HZ 100, 250 and 1000.
func TestDialSetupRTOInitialRestoresLasting(t *testing.T) {
	controlRTO := RTOInfo{Initial: 600 * time.Millisecond, Max: 1800 * time.Millisecond, Min: 160 * time.Millisecond}
	typedRTO := RTOInfo{Initial: 400 * time.Millisecond, Max: 1600 * time.Millisecond, Min: 200 * time.Millisecond}
	for _, tc := range []struct {
		name           string
		control, typed *RTOInfo
	}{
		{"defaults", nil, nil},
		{"typed", nil, &typedRTO},
		{"Control", &controlRTO, nil},
		{"typed_after_Control", &controlRTO, &typedRTO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{SetupRTOInitial: 2400 * time.Millisecond, RTOInfo: tc.typed}
			var lasting RTOInfo
			cfg.Control = func(_, _ string, rc syscall.RawConn) error {
				var serr error
				if err := rc.Control(func(fd uintptr) {
					var b [sizeRTOInfo]byte
					if tc.control != nil {
						if serr = encodeRTOInfo(b[:], 0, tc.control, "RTOInfo"); serr != nil {
							return
						}
						if serr = rawSetsockopt(int(fd), ipprotoSCTP, optRTOInfo, unsafe.Pointer(&b[0]), uintptr(len(b))); serr != nil {
							return
						}
					}
					l := uint32(len(b))
					serr = rawGetsockopt(int(fd), ipprotoSCTP, optRTOInfo, unsafe.Pointer(&b[0]), &l)
					lasting = decodeRTOInfo(b[:])
				}); err != nil {
					return err
				}
				if tc.typed != nil {
					lasting = *tc.typed
				}
				return serr
			}
			testHookDialConnecting = func(s *socket) error {
				got := setupSocketRTO(t, s)
				want := lasting
				want.Initial = cfg.SetupRTOInitial
				if got != want {
					t.Errorf("before connect RTOInfo = %+v, want %+v", got, want)
				}
				return nil
			}
			t.Cleanup(func() { testHookDialConnecting = nil })
			client, _ := connPair(t, cfg, nil)
			got, err := client.RTOInfo()
			if err != nil {
				t.Fatal(err)
			}
			if *got != lasting {
				t.Errorf("established RTOInfo = %+v, want lasting %+v", *got, lasting)
			}
			st, err := client.Status()
			if err != nil {
				t.Fatal(err)
			}
			path, err := client.PathInfo(st.Primary.Addr.Addr())
			if err != nil {
				t.Fatal(err)
			}
			if path.RTO != cfg.SetupRTOInitial {
				t.Errorf("PathInfo.RTO = %v, want %v; this pins Linux behaviour that the docs describe: existing paths keep the setup Initial", path.RTO, cfg.SetupRTOInitial)
			}
		})
	}
}

func setupSocketRTO(t testing.TB, s *socket) RTOInfo {
	t.Helper()
	var b [sizeRTOInfo]byte
	l := uint32(len(b))
	if err := s.getsockopt(optRTOInfo, unsafe.Pointer(&b[0]), &l); err != nil {
		t.Fatal(err)
	}
	return decodeRTOInfo(b[:])
}

func TestDialSetupRTOInitialZeroNoSockopt(t *testing.T) {
	calls := 0
	hook := func(opt int) {
		if opt == optRTOInfo {
			calls++
		}
	}
	testHookSockopt.Store(&hook)
	t.Cleanup(func() { testHookSockopt.Store(nil) })
	connPair(t, &Config{}, nil)
	if calls != 0 {
		t.Errorf("zero SetupRTOInitial made %d RTOINFO calls, want none", calls)
	}
}

func TestDialSetupRTOInitialContextLeaksNothing(t *testing.T) {
	if !silentPeerAvailable(t) {
		t.Skip("needs the Linux suite's silent peer at 192.0.2.1")
	}
	baseline, before := countAssocs(t), openFds(t)
	for _, policy := range []AbandonPolicy{AbandonAbort, AbandonQuiet} {
		for range 10 {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			c, err := (&Config{SetupRTOInitial: time.Second, AbandonPolicy: policy}).Dial(ctx, "sctp4", nil, unreachableAddr())
			cancel()
			if c != nil {
				_ = c.Abort()
				t.Fatal("Dial to a silent peer returned a Conn")
			}
			wantDialError(t, err, context.DeadlineExceeded)
		}
	}
	if after := openFds(t); after > before+2 {
		t.Errorf("descriptor count went %d -> %d", before, after)
	}
	if got := waitAssocsAtMost(t, baseline); got > baseline {
		t.Errorf("%d associations remain, baseline %d", got, baseline)
	}
}

func TestDialSetupRTOInitialSelfConnectRetry(t *testing.T) {
	dead := deadPort(t)
	attempts := 0
	var l *Listener
	selfBind := bindTo(dead, &attempts, func(a int) bool { return a == 1 })
	cfg := &Config{SetupRTOInitial: 2400 * time.Millisecond, RTOInfo: &RTOInfo{Initial: 400 * time.Millisecond}}
	testHookDialConnecting = func(s *socket) error {
		if got := setupSocketRTO(t, s).Initial; got != cfg.SetupRTOInitial {
			t.Errorf("attempt %d Initial = %v, want %v", attempts+1, got, cfg.SetupRTOInitial)
		}
		if err := selfBind(s); err != nil || attempts != 2 {
			return err
		}
		var err error
		l, err = Listen("sctp4", dead)
		return err
	}
	t.Cleanup(func() { testHookDialConnecting = nil })
	c, err := cfg.Dial(testContext(t, 10*time.Second), "sctp4", nil, dead)
	if l != nil {
		t.Cleanup(func() { _ = l.Close() })
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Abort() })
	if attempts != 2 || c.selfConnected() {
		t.Fatalf("attempts = %d, selfConnected = %v, want 2/false", attempts, c.selfConnected())
	}
	if got, err := c.RTOInfo(); err != nil || got.Initial != cfg.RTOInfo.Initial {
		t.Errorf("retry RTOInfo = %+v, %v", got, err)
	}
	server, err := l.AcceptSCTP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Abort() })
}

// TestDialSetupRTOInitialAfterEnd pins both possible restore targets:
// the association while live, and the socket if it ended before Dial looked.
func TestDialSetupRTOInitialAfterEnd(t *testing.T) {
	for _, beforeLook := range []bool{false, true} {
		name := "after_return"
		if beforeLook {
			name = "before_await"
		}
		t.Run(name, func(t *testing.T) {
			l := mustListen(t, nil, "sctp4", loopback4(0))
			addr := listenerAddr(t, l)
			closePeer := make(chan struct{})
			ended := make(chan error, 1)
			go func() {
				server, err := l.AcceptSCTP()
				if err == nil {
					<-closePeer
					err = server.Close()
				}
				ended <- err
			}()
			finish := func() {
				close(closePeer)
				if err := <-ended; err != nil {
					t.Fatal(err)
				}
				waitAssocClosed(t, addr.Port)
			}
			if beforeLook {
				testHookDialStarted = finish
				t.Cleanup(func() { testHookDialStarted = nil })
			}
			cfg := &Config{SetupRTOInitial: 2400 * time.Millisecond, RTOInfo: &RTOInfo{Initial: 400 * time.Millisecond, Min: 200 * time.Millisecond, Max: 1600 * time.Millisecond}}
			c, err := cfg.Dial(testContext(t, 5*time.Second), "sctp4", nil, addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = c.Abort() })
			if !beforeLook {
				finish()
			}
			if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := c.Read(make([]byte, 64)); err != io.EOF {
				t.Fatalf("Read = %v, want EOF", err)
			}
			got, err := c.RTOInfo()
			if err != nil {
				t.Fatal(err)
			}
			want := *cfg.RTOInfo
			if !beforeLook {
				want.Initial = cfg.SetupRTOInitial
			}
			if *got != want {
				t.Errorf("ended RTOInfo = %+v, want socket %+v", *got, want)
			}
		})
	}
}

func TestSetupRTOInitialFileRefusal(t *testing.T) {
	cfg := &Config{SetupRTOInitial: time.Second}
	_, err := cfg.FileConn(os.Stdin)
	wantRefused(t, err, "Config.SetupRTOInitial")
	_, err = cfg.FileListener(os.Stdin)
	wantRefused(t, err, "Config.SetupRTOInitial")
}
