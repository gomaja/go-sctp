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
	"encoding/binary"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// --- helpers --------------------------------------------------------------------

// wantOpError asserts that err is a *net.OpError with Op op that matches
// target.
func wantOpError(t testing.TB, what, op string, err, target error) {
	t.Helper()
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != op || !errors.Is(err, target) {
		t.Errorf("%s = %v, want a *net.OpError with Op %q matching %v", what, err, op, target)
	}
}

// wantKernelError asserts that err is a *net.OpError with Op op around an
// *os.SyscallError holding errno: the kernel refused the call, not the
// package. A setter that reads before it writes, such as
// SetPathThresholds, can fail in its getsockopt as well as its
// setsockopt.
func wantKernelError(t testing.TB, what, op string, err error, errno syscall.Errno) {
	t.Helper()
	wantOpError(t, what, op, err, errno)
	var sysErr *os.SyscallError
	if !errors.As(err, &sysErr) || (sysErr.Syscall != "getsockopt" && sysErr.Syscall != "setsockopt") {
		t.Errorf("%s = %v, want it to wrap an *os.SyscallError naming getsockopt or setsockopt", what, err)
	}
}

// countSockopts counts the option system calls the package makes until the
// test ends.
func countSockopts(t testing.TB) *atomic.Int64 {
	t.Helper()
	calls := new(atomic.Int64)
	hook := func(int) { calls.Add(1) }
	testHookSockopt.Store(&hook)
	t.Cleanup(func() { testHookSockopt.Store(nil) })
	return calls
}

// primaryPath is the association's primary peer address.
func primaryPath(t testing.TB, c *Conn) netip.Addr {
	t.Helper()
	p, err := c.PrimaryAddr()
	if err != nil {
		t.Fatalf("PrimaryAddr: %v", err)
	}
	return p
}

// awaitEvent reads c until a notification of type want arrives, and
// returns it. c must be subscribed to want and have no handler.
func awaitEvent(t testing.TB, c *Conn, want EventType) Notification {
	t.Helper()
	buf := make([]byte, NotificationMaxSize)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := c.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		n, info, err := c.RecvMsg(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			t.Fatalf("RecvMsg waiting for %v: %v", want, err)
		}
		if !info.Notification {
			continue
		}
		note, err := ParseNotification(buf[:n])
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		if note.Type() == want {
			_ = c.SetReadDeadline(time.Time{})
			return note
		}
	}
	t.Fatalf("no %v arrived within 5 s", want)
	return nil
}

// reconfConfig negotiates stream reconfiguration (RFC 6525) and permits
// every request type.
func reconfConfig(notes ...EventType) *Config {
	mask := EnableResetStreamReq | EnableResetAssocReq | EnableChangeAssocReq
	return &Config{StreamReconfiguration: new(true), StreamResetMask: &mask, Notifications: notes}
}

// --- every getter and setter against a live association --------------------------

// optionRoundTrip is one setting written through a setter and read back
// through its getter.
type optionRoundTrip struct {
	name string
	set  func(*Conn) error
	get  func(*Conn) (any, error)
	want any
}

// roundTrips lists every setter with a getter, each value read back from
// the kernel after it is set. Values are chosen to differ from the
// kernel's defaults, and durations are whole multiples of 100 ms, which
// convert to kernel ticks and back exactly whatever CONFIG_HZ is.
func roundTrips() []optionRoundTrip {
	var rt []optionRoundTrip
	add := func(name string, set func(*Conn) error, get func(*Conn) (any, error), want any) {
		rt = append(rt, optionRoundTrip{name, set, get, want})
	}
	for _, on := range []bool{true, false} {
		add("NoDelay "+strconv.FormatBool(on), func(c *Conn) error { return c.SetNoDelay(on) }, func(c *Conn) (any, error) { return c.NoDelay() }, on)
		add("FragmentsDisabled "+strconv.FormatBool(on), func(c *Conn) error { return c.SetFragmentsDisabled(on) }, func(c *Conn) (any, error) { return c.FragmentsDisabled() }, on)
		add("ReceiveNxtInfo "+strconv.FormatBool(on), func(c *Conn) error { return c.SetReceiveNxtInfo(on) }, func(c *Conn) (any, error) { return c.ReceiveNxtInfo() }, on)
		add("AutoASCONF "+strconv.FormatBool(on), func(c *Conn) error { return c.SetAutoASCONF(on) }, func(c *Conn) (any, error) { return c.AutoASCONF() }, on)
	}
	for _, level := range []FragmentInterleave{InterleaveAssocs, InterleaveNone} {
		add("FragmentInterleave "+level.String(), func(c *Conn) error { return c.SetFragmentInterleave(level) }, func(c *Conn) (any, error) { return c.FragmentInterleave() }, level)
	}
	for _, e := range []PFExposure{PFExposeEnabled, PFExposeDisabled, PFExposeUnset} {
		add("PFExposure "+e.String(), func(c *Conn) error { return c.SetPFExposure(e) }, func(c *Conn) (any, error) { return c.PFExposure() }, e)
	}
	for _, n := range []int{1, 8, 0} {
		add("MaxBurst "+strconv.Itoa(n), func(c *Conn) error { return c.SetMaxBurst(n) }, func(c *Conn) (any, error) { return c.MaxBurst() }, n)
	}
	for _, n := range []int{1, 4096, 0} {
		add("PartialDeliveryPoint "+strconv.Itoa(n), func(c *Conn) error { return c.SetPartialDeliveryPoint(n) }, func(c *Conn) (any, error) { return c.PartialDeliveryPoint() }, n)
	}
	for _, v := range []uint32{1, 0x1234, math.MaxUint32, 0} {
		add("DefaultContext "+strconv.FormatUint(uint64(v), 16), func(c *Conn) error { return c.SetDefaultContext(v) }, func(c *Conn) (any, error) { return c.DefaultContext() }, v)
	}
	for _, m := range []StreamResetMask{EnableResetStreamReq, EnableResetAssocReq, EnableChangeAssocReq, EnableResetStreamReq | EnableResetAssocReq | EnableChangeAssocReq, 0} {
		add("StreamResetMask "+m.String(), func(c *Conn) error { return c.SetStreamResetMask(m) }, func(c *Conn) (any, error) { return c.StreamResetMask() }, m)
	}
	for _, s := range []Scheduler{SchedPrio, SchedRR, SchedFCFS} {
		add("StreamScheduler "+s.String(), func(c *Conn) error { return c.SetStreamScheduler(s) }, func(c *Conn) (any, error) { return c.StreamScheduler() }, s)
	}
	rto := RTOInfo{Initial: 500 * time.Millisecond, Max: 2 * time.Second, Min: 200 * time.Millisecond}
	add("RTOInfo", func(c *Conn) error { return c.SetRTOInfo(&rto) }, func(c *Conn) (any, error) {
		r, err := c.RTOInfo()
		if err != nil {
			return nil, err
		}
		return *r, nil
	}, rto)
	add("AssocInfo", func(c *Conn) error {
		return c.SetAssocInfo(&AssocInfo{MaxRetrans: 3, CookieLife: 30 * time.Second})
	}, func(c *Conn) (any, error) {
		a, err := c.AssocInfo()
		if err != nil {
			return nil, err
		}
		return [2]any{a.MaxRetrans, a.CookieLife}, nil
	}, [2]any{uint16(3), 30 * time.Second})
	sack := DelayedSACK{Delay: 300 * time.Millisecond, Frequency: 4}
	add("DelayedSACK", func(c *Conn) error { return c.SetDelayedSACK(&sack) }, func(c *Conn) (any, error) {
		d, err := c.DelayedSACK()
		if err != nil {
			return nil, err
		}
		return *d, nil
	}, sack)
	add("PathParams heartbeat", func(c *Conn) error {
		return c.SetPathParams(netip.Addr{}, &PathParams{Heartbeat: new(true), HeartbeatInterval: new(5 * time.Second), PathMaxRetrans: new(uint16(4))})
	}, func(c *Conn) (any, error) {
		p, err := c.PathParams(netip.Addr{})
		if err != nil {
			return nil, err
		}
		return [3]any{*p.Heartbeat, *p.HeartbeatInterval, *p.PathMaxRetrans}, nil
	}, [3]any{true, 5 * time.Second, uint16(4)})
	add("PathThresholds", func(c *Conn) error {
		return c.SetPathThresholds(netip.Addr{}, &PathThresholds{PathMaxRetrans: new(uint16(6)), PFThreshold: new(uint16(2)), PrimarySwitchover: new(uint16(3))})
	}, func(c *Conn) (any, error) {
		p, err := c.PathThresholds(netip.Addr{})
		if err != nil {
			return nil, err
		}
		return [3]uint16{*p.PathMaxRetrans, *p.PFThreshold, *p.PrimarySwitchover}, nil
	}, [3]uint16{6, 2, 3})
	add("RemoteUDPEncapsPort", func(c *Conn) error { return c.SetRemoteUDPEncapsPort(netip.Addr{}, 9899) },
		func(c *Conn) (any, error) { return c.RemoteUDPEncapsPort(netip.Addr{}) }, uint16(9899))
	add("PLPMTUDProbeInterval", func(c *Conn) error { return c.SetPLPMTUDProbeInterval(netip.Addr{}, 10*time.Second) },
		func(c *Conn) (any, error) { return c.PLPMTUDProbeInterval(netip.Addr{}) }, 10*time.Second)
	add("StreamSchedulerValue", func(c *Conn) error {
		if err := c.SetStreamScheduler(SchedPrio); err != nil {
			return err
		}
		return c.SetStreamSchedulerValue(1, 7)
	}, func(c *Conn) (any, error) { return c.StreamSchedulerValue(1) }, uint16(7))
	return rt
}

// TestOptionsRoundTrip sets every option with a setter on a live
// association and reads it back through its getter.
func TestOptionsRoundTrip(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	for _, rt := range roundTrips() {
		t.Run(rt.name, func(t *testing.T) {
			if err := rt.set(client); err != nil {
				t.Fatalf("set: %v", err)
			}
			got, err := rt.get(client)
			if err != nil {
				t.Fatalf("get: %v", err)
			}
			if !reflect.DeepEqual(got, rt.want) {
				t.Errorf("read back %v (%T), want %v (%T)", got, got, rt.want, rt.want)
			}
		})
	}
}

// TestReadWriteBufferReportTwiceTheValueSet: Linux doubles SO_RCVBUF and
// SO_SNDBUF to allow for its own bookkeeping (net/core/sock.c:
// __sock_set_rcvbuf, and sk_setsockopt for SO_SNDBUF), and ReadBuffer and WriteBuffer
// report the doubled size, for a value below net.core.rmem_max and
// net.core.wmem_max.
func TestReadWriteBufferReportTwiceTheValueSet(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	for _, tc := range []struct {
		name  string
		limit string
		set   func(int) error
		get   func() (int, error)
	}{
		{"ReadBuffer", "rmem_max", client.SetReadBuffer, client.ReadBuffer},
		{"WriteBuffer", "wmem_max", client.SetWriteBuffer, client.WriteBuffer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := os.ReadFile("/proc/sys/net/core/" + tc.limit)
			if err != nil {
				t.Skipf("cannot read net.core.%s: %v", tc.limit, err)
			}
			limit, err := strconv.Atoi(strings.TrimSpace(string(b)))
			if err != nil {
				t.Fatalf("net.core.%s = %q", tc.limit, b)
			}
			want := min(48*1024, limit/2)
			if err := tc.set(want); err != nil {
				t.Fatalf("Set%s(%d): %v", tc.name, want, err)
			}
			got, err := tc.get()
			if err != nil || got != 2*want {
				t.Errorf("%s = %d, %v; want %d, twice the %d set", tc.name, got, err, 2*want, want)
			}
		})
	}
	for _, n := range []int{0, -1} {
		wantOpError(t, "SetReadBuffer("+strconv.Itoa(n)+")", "set", client.SetReadBuffer(n), syscall.EINVAL)
		wantOpError(t, "SetWriteBuffer("+strconv.Itoa(n)+")", "set", client.SetWriteBuffer(n), syscall.EINVAL)
	}
}

// --- paths ---------------------------------------------------------------------------

// TestZeroPathAddrRefusedBeforeAnySyscall: PathInfo, SetPrimaryAddr and
// RequestPeerPrimary each name one address, and refuse the zero netip.Addr
// with an error matching syscall.EINVAL before any system call, where
// Linux would otherwise read it as the wildcard.
func TestZeroPathAddrRefusedBeforeAnySyscall(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	calls := countSockopts(t)
	_, err := client.PathInfo(netip.Addr{})
	wantOpError(t, "PathInfo(zero)", "get", err, syscall.EINVAL)
	wantOpError(t, "SetPrimaryAddr(zero)", "set", client.SetPrimaryAddr(netip.Addr{}), syscall.EINVAL)
	wantOpError(t, "RequestPeerPrimary(zero)", "set", client.RequestPeerPrimary(netip.Addr{}), syscall.EINVAL)
	if n := calls.Load(); n != 0 {
		t.Errorf("%d option system calls for three refused zero addresses, want 0", n)
	}
}

// TestRequestHeartbeat: with the zero address Linux sends a HEARTBEAT on
// every path of the association (net/sctp/socket.c:
// sctp_setsockopt_peer_addr_params applies SPP_HB_DEMAND to each
// transport), and with a peer address on that path alone. The
// association's control chunk count moves either way; the HEARTBEATs
// themselves are proven from a capture elsewhere.
func TestRequestHeartbeat(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	for _, path := range []netip.Addr{{}, primaryPath(t, client)} {
		before, err := client.Stats()
		if err != nil {
			t.Fatalf("Stats: %v", err)
		}
		if err := client.RequestHeartbeat(path); err != nil {
			t.Fatalf("RequestHeartbeat(%v): %v", path, err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			after, err := client.Stats()
			if err != nil {
				t.Fatalf("Stats: %v", err)
			}
			if after.ControlChunksOut > before.ControlChunksOut {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("RequestHeartbeat(%v): no control chunk sent within 2 s (%d before, %d after)", path, before.ControlChunksOut, after.ControlChunksOut)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// TestNonPeerPathErrnos: a path that is not one of the peer's addresses is
// refused by Linux with EINVAL (every sctp_addr_id2transport caller in
// net/sctp/socket.c), except by the two threshold options, which answer
// ENOENT (sctp_setsockopt_paddr_thresholds, sctp_getsockopt_paddr_thresholds).
func TestNonPeerPathErrnos(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	stranger := netip.MustParseAddr("127.0.0.9")
	cases := []struct {
		name  string
		op    string
		err   error
		errno syscall.Errno
	}{
		{"PathInfo", "get", get2(client.PathInfo(stranger)), syscall.EINVAL},
		{"PathParams", "get", get2(client.PathParams(stranger)), syscall.EINVAL},
		{"SetPathParams", "set", client.SetPathParams(stranger, &PathParams{}), syscall.EINVAL},
		{"RequestHeartbeat", "set", client.RequestHeartbeat(stranger), syscall.EINVAL},
		{"SetPrimaryAddr", "set", client.SetPrimaryAddr(stranger), syscall.EINVAL},
		{"RemoteUDPEncapsPort", "get", get2(client.RemoteUDPEncapsPort(stranger)), syscall.EINVAL},
		{"SetRemoteUDPEncapsPort", "set", client.SetRemoteUDPEncapsPort(stranger, 9899), syscall.EINVAL},
		{"PLPMTUDProbeInterval", "get", get2(client.PLPMTUDProbeInterval(stranger)), syscall.EINVAL},
		{"SetPLPMTUDProbeInterval", "set", client.SetPLPMTUDProbeInterval(stranger, 10*time.Second), syscall.EINVAL},
		{"PathThresholds", "get", get2(client.PathThresholds(stranger)), syscall.ENOENT},
		{"SetPathThresholds", "set", client.SetPathThresholds(stranger, &PathThresholds{PFThreshold: new(uint16(1))}), syscall.ENOENT},
	}
	for _, tc := range cases {
		wantKernelError(t, tc.name, tc.op, tc.err, tc.errno)
	}
}

// get2 drops a getter's value and keeps its error.
func get2[T any](_ T, err error) error { return err }

// TestPathInfoReportsThePath: PathInfo on the primary path reports it
// active, with a path MTU and an RTO, and the address the package was
// asked about, with the association's peer port.
func TestPathInfoReportsThePath(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	primary := primaryPath(t, client)
	info, err := client.PathInfo(primary)
	if err != nil {
		t.Fatalf("PathInfo(%v): %v", primary, err)
	}
	remote := client.RemoteAddr().(*Addr)
	if info.Addr != netip.AddrPortFrom(primary, remote.Port) {
		t.Errorf("PathInfo.Addr = %v, want %v", info.Addr, netip.AddrPortFrom(primary, remote.Port))
	}
	if info.State != PathActive {
		t.Errorf("State = %v, want PathActive", info.State)
	}
	if info.MTU == 0 || info.RTO == 0 || info.Cwnd == 0 {
		t.Errorf("PathInfo = %+v; an established path has an MTU, an RTO and a congestion window", info)
	}
}

// TestPathParamsThroughTheKernel: the association's defaults read back as
// the kernel keeps them, and a per-path change reaches that path.
func TestPathParamsThroughTheKernel(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	before, err := client.PathParams(netip.Addr{})
	if err != nil {
		t.Fatalf("PathParams: %v", err)
	}
	// The kernel's default heartbeat interval is 30 s (net.sctp.hb_interval):
	// a zero here would mean the field is read from the wrong offset.
	if before.HeartbeatInterval == nil || *before.HeartbeatInterval == 0 || before.Heartbeat == nil || !*before.Heartbeat {
		t.Errorf("default PathParams = %s, want heartbeats on with a non-zero interval", pathParamsString(before))
	}
	for _, f := range []any{before.Heartbeat, before.HeartbeatInterval, before.PathMaxRetrans, before.PMTUD, before.PathMTU, before.DelayedSACK, before.SACKDelay} {
		if reflect.ValueOf(f).IsNil() {
			t.Errorf("PathParams getter left a field nil: %s", pathParamsString(before))
			break
		}
	}

	primary := primaryPath(t, client)
	set := &PathParams{
		Heartbeat:         new(true),
		HeartbeatInterval: new(7*time.Second + 3*time.Millisecond),
		PathMaxRetrans:    new(uint16(9)),
		DelayedSACK:       new(true),
		SACKDelay:         new(403 * time.Millisecond),
		DSCP:              new(uint8(0xb8)),
	}
	if err := client.SetPathParams(primary, set); err != nil {
		t.Fatalf("SetPathParams(%v): %v", primary, err)
	}
	got, err := client.PathParams(primary)
	if err != nil {
		t.Fatalf("PathParams(%v): %v", primary, err)
	}
	if !kernelTickReadback(*got.HeartbeatInterval, 7*time.Second+3*time.Millisecond) || *got.PathMaxRetrans != 9 || !*got.DelayedSACK || !kernelTickReadback(*got.SACKDelay, 403*time.Millisecond) || got.DSCP == nil || *got.DSCP != 0xb8 {
		t.Errorf("PathParams(%v) = %s after setting %s", primary, pathParamsString(got), pathParamsString(set))
	}

	if err := client.SetPathParams(primary, &PathParams{Heartbeat: new(false)}); err != nil {
		t.Fatalf("SetPathParams(heartbeat off): %v", err)
	}
	if got, err := client.PathParams(primary); err != nil || *got.Heartbeat || !kernelTickReadback(*got.HeartbeatInterval, 7*time.Second+3*time.Millisecond) {
		t.Errorf("after switching heartbeats off: %v, %v; want off with the interval kept", pathParamsString(got), err)
	}
	if err := client.SetPathParams(primary, &PathParams{PMTUD: new(false), PathMTU: new(uint32(1400))}); err != nil {
		t.Fatalf("SetPathParams(fixed MTU): %v", err)
	}
	if got, err := client.PathParams(primary); err != nil || *got.PMTUD || *got.PathMTU != 1400 {
		t.Errorf("after fixing the path MTU: %v, %v; want PMTUD off at 1400", pathParamsString(got), err)
	}
}

// TestSetPrimaryAddrSelectsThePath: on a multi-homed association the
// primary moves to the address asked for (RFC 6458 §8.1.9).
func TestSetPrimaryAddrSelectsThePath(t *testing.T) {
	avail := requireLoopbacks(t, 3)
	l := mustListen(t, nil, "sctp4", addrOf(0, avail[:2]...))
	client, _ := dialAccept(t, nil, l)
	before := primaryPath(t, client)
	var other netip.Addr
	for _, ip := range client.RemoteAddr().(*Addr).IPs {
		if ip != before {
			other = ip
			break
		}
	}
	if !other.IsValid() {
		t.Skipf("the peer announced only %v; there is no other path", before)
	}
	if err := client.SetPrimaryAddr(other); err != nil {
		t.Fatalf("SetPrimaryAddr(%v): %v", other, err)
	}
	if now := primaryPath(t, client); now != other {
		t.Errorf("primary = %v after asking for %v (was %v)", now, other, before)
	}
	if st, err := client.Status(); err != nil || st.Primary.Addr.Addr() != other {
		t.Errorf("Status().Primary = %v, %v; want %v", st.Primary.Addr, err, other)
	}
}

// TestRequestPeerPrimary: without ASCONF negotiated Linux refuses the
// request with EPERM (net/sctp/socket.c: sctp_setsockopt_peer_primary_addr);
// with it, the peer moves its primary to the address named (RFC 5061
// §4.2.4).
func TestRequestPeerPrimary(t *testing.T) {
	t.Run("without ASCONF", func(t *testing.T) {
		client, _ := connPair(t, &Config{DynamicAddressReconfiguration: new(false)}, nil)
		local := client.LocalAddr().(*Addr).IPs[0]
		wantKernelError(t, "RequestPeerPrimary", "set", client.RequestPeerPrimary(local), syscall.EPERM)
	})
	t.Run("with ASCONF", func(t *testing.T) {
		avail := requireLoopbacks(t, 3)
		cfg := &Config{Authentication: new(true), DynamicAddressReconfiguration: new(true)}
		l := mustListen(t, cfg, "sctp4", addrOf(0, avail[2]))
		type result struct {
			c   *Conn
			err error
		}
		ch := make(chan result, 1)
		go func() {
			c, err := l.AcceptSCTP()
			ch <- result{c, err}
		}()
		client, err := cfg.Dial(testContext(t, 10*time.Second), "sctp4", addrOf(0, avail[0], avail[1]), listenerAddr(t, l))
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		t.Cleanup(func() { _ = client.Abort() })
		r := <-ch
		if r.err != nil {
			t.Fatalf("AcceptSCTP: %v", r.err)
		}
		server := r.c
		t.Cleanup(func() { _ = server.Abort() })
		if on, err := client.ASCONFSupported(); err != nil || !on {
			t.Skipf("ASCONF was not negotiated despite the Config: %v, %v", on, err)
		}
		target := netip.MustParseAddr(avail[1])
		if primaryPath(t, server) == target {
			target = netip.MustParseAddr(avail[0])
		}
		if err := client.RequestPeerPrimary(target); err != nil {
			t.Fatalf("RequestPeerPrimary(%v): %v", target, err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for primaryPath(t, server) != target {
			if time.Now().After(deadline) {
				t.Fatalf("the peer's primary is %v, want %v after the request", primaryPath(t, server), target)
			}
			time.Sleep(10 * time.Millisecond)
		}
		wantKernelError(t, "RequestPeerPrimary(not local)", "set", client.RequestPeerPrimary(netip.MustParseAddr("127.0.0.9")), syscall.EADDRNOTAVAIL)
	})
}

// zone0Index returns the index of the Linux suite's dummy link zone0, and
// requires it to carry fe80::1 and fe80::3, and the dummy link
// silent0 to carry fe80::9. Without zone0 the test is skipped; with zone0
// but without those addresses it fails, so that a change to the
// environment cannot turn it green by skipping.
func zone0Index(t *testing.T) uint32 {
	t.Helper()
	ifi, err := net.InterfaceByName("zone0")
	if err != nil {
		t.Skipf("no interface zone0 (the Linux suite adds a dummy link zone0 with fe80::1 and fe80::3): %v", err)
	}
	for link, want := range map[string][]string{"zone0": {"fe80::1", "fe80::3"}, "silent0": {"fe80::9"}} {
		li, err := net.InterfaceByName(link)
		if err != nil {
			t.Fatalf("zone0 exists but %s does not (the Linux suite adds both): %v", link, err)
		}
		addrs, err := li.Addrs()
		if err != nil {
			t.Fatalf("%s addresses: %v", link, err)
		}
		for _, w := range want {
			found := false
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok && n.IP.Equal(net.ParseIP(w)) {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s does not carry %s (the Linux suite adds fe80::1 and fe80::3 on zone0 and fe80::9 on silent0): %v", link, w, addrs)
			}
		}
	}
	return uint32(ifi.Index)
}

// linkLocalPair sets up an association between a listener bound to listen
// and a dialer bound to local, dialing to on the listener's port, all on
// "sctp6".
func linkLocalPair(t *testing.T, listen, local []string, to string) (client, server *Conn) {
	t.Helper()
	l := mustListen(t, nil, "sctp6", addrOf(0, listen...))
	type result struct {
		c   *Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := l.AcceptSCTP()
		ch <- result{c, err}
	}()
	client, err := Dial(testContext(t, 10*time.Second), "sctp6", addrOf(0, local...), addrOf(listenerAddr(t, l).Port, to))
	if err != nil {
		t.Fatalf("Dial from %v to %s: %v", local, to, err)
	}
	t.Cleanup(func() { _ = client.Abort() })
	r := <-ch
	if r.err != nil {
		t.Fatalf("AcceptSCTP: %v", r.err)
	}
	t.Cleanup(func() { _ = r.c.Abort() })
	return client, r.c
}

// wantZonelessPath checks that c accepts path, a peer's link-local address
// given without a zone, in a path option and in SendOptions.Path, and that
// peer receives what c sends there.
func wantZonelessPath(t *testing.T, side string, c, peer *Conn, path netip.Addr) {
	t.Helper()
	info, err := c.PathInfo(path)
	if err != nil {
		t.Fatalf("%s PathInfo(%v): %v", side, path, err)
	}
	if info.Addr.Addr().WithZone("") != path {
		t.Errorf("%s PathInfo(%v).Addr = %v", side, path, info.Addr)
	}
	if _, err := c.PathThresholds(path); err != nil {
		t.Errorf("%s PathThresholds(%v): %v", side, path, err)
	}
	msg := []byte(side + " to " + path.String())
	if _, err := c.SendMsg(msg, SendOptions{Path: path}); err != nil {
		t.Fatalf("%s SendMsg(Path: %v): %v", side, path, err)
	}
	setReadDeadline(t, peer, 5*time.Second)
	got, _, err := peer.ReadMsg(256)
	if err != nil {
		t.Fatalf("the peer of the %s side read: %v", side, err)
	}
	if string(got) != string(msg) {
		t.Errorf("the peer of the %s side read %q, want %q", side, got, msg)
	}
}

// bareLinkLocal returns the link-local address of a without a zone, one
// PeerAddrs reports without a zone when wantBare is set, and fails if a
// holds none.
func bareLinkLocal(t *testing.T, side string, a *Addr, ip string, wantBare bool) netip.Addr {
	t.Helper()
	want := netip.MustParseAddr(ip)
	for _, p := range a.IPs {
		if p.WithZone("") == want {
			if wantBare && p.Zone() != "" {
				t.Fatalf("%s PeerAddrs reports %v with a zone; this association was meant to learn it from an address parameter, without one", side, p)
			}
			return want
		}
	}
	t.Fatalf("%s PeerAddrs %v does not hold %s", side, a, ip)
	return netip.Addr{}
}

// TestLinkLocalPeerPathOptions: a link-local path given without a zone,
// the form PeerAddrs reports for a peer address learned from an INIT or
// INIT ACK parameter, is accepted by the path options and SendOptions.Path
// on the dialed and on the accepted side, when the association's
// addresses decide one zone. Each side takes the scope id from a
// different source (linkLocalPathScope): the dialed side from its own
// zoned local addresses; the accepted side, whose local addresses Linux
// rebuilds from the cookie's address list without a scope id when that
// list holds two or more (net/sctp/bind_addr.c: sctp_raw_to_bind_addrs
// passes iif 0), from the INIT's source, which carries the arrival
// interface (net/sctp/ipv6.c: sctp_v6_from_skb), or, when that source is
// not link-local, from the interface that holds its local link-local
// address.
func TestLinkLocalPeerPathOptions(t *testing.T) {
	zone0 := zone0Index(t)

	t.Run("the accepted side's INIT source", func(t *testing.T) {
		// The listener's two addresses are on two links, so that the
		// interfaces holding them name two zones and the INIT's source
		// alone decides the accepted side's.
		client, server := linkLocalPair(t, []string{"fe80::1%zone0", "fe80::9%silent0"}, []string{"fe80::3%zone0"}, "fe80::1%zone0")
		for _, ip := range server.LocalAddr().(*Addr).IPs {
			if ip.IsLinkLocalUnicast() && ip.Zone() != "" {
				t.Errorf("the accepted side's local address %v has a zone; Linux was expected to rebuild them from the cookie's two-address list without one", ip)
			}
		}
		for side, c := range map[string]*Conn{"dialed": client, "accepted": server} {
			if got := c.pathScope.Load(); got != zone0 {
				t.Errorf("%s side link-local scope = %d, want zone0's %d", side, got, zone0)
			}
		}
		peers, err := client.PeerAddrs()
		if err != nil {
			t.Fatalf("PeerAddrs: %v", err)
		}
		wantZonelessPath(t, "dialed", client, server, bareLinkLocal(t, "dialed", peers, "fe80::9", true))
		wantZonelessPath(t, "accepted", server, client, netip.MustParseAddr("fe80::3"))
	})

	t.Run("the interface holding the accepted side's address", func(t *testing.T) {
		client, server := linkLocalPair(t, []string{"::1", "fe80::1%zone0"}, []string{"::1", "fe80::3%zone0"}, "::1")
		for side, c := range map[string]*Conn{"dialed": client, "accepted": server} {
			if got := c.pathScope.Load(); got != zone0 {
				t.Errorf("%s side link-local scope = %d, want zone0's %d", side, got, zone0)
			}
		}
		clientPeers, err := client.PeerAddrs()
		if err != nil {
			t.Fatalf("PeerAddrs: %v", err)
		}
		serverPeers, err := server.PeerAddrs()
		if err != nil {
			t.Fatalf("PeerAddrs: %v", err)
		}
		wantZonelessPath(t, "dialed", client, server, bareLinkLocal(t, "dialed", clientPeers, "fe80::1", true))
		wantZonelessPath(t, "accepted", server, client, bareLinkLocal(t, "accepted", serverPeers, "fe80::3", true))
	})

	t.Run("two links", func(t *testing.T) {
		// Over a wildcard bind every link's link-local addresses join the
		// association, so no one zone can be picked, and a path without
		// one is left for Linux to refuse.
		l := mustListen(t, nil, "sctp6", nil)
		client, err := Dial(testContext(t, 10*time.Second), "sctp6", nil, addrOf(listenerAddr(t, l).Port, "::1"))
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		t.Cleanup(func() { _ = client.Abort() })
		zones := map[string]bool{}
		for _, ip := range client.LocalAddr().(*Addr).IPs {
			if ip.IsLinkLocalUnicast() && ip.Zone() != "" {
				zones[ip.Zone()] = true
			}
		}
		if len(zones) < 2 {
			t.Fatalf("the association's local link-local addresses span links %v, not two (the Linux suite puts fe80::9 on silent0 as well as fe80::1 and fe80::3 on zone0)", zones)
		}
		if got := client.pathScope.Load(); got != 0 {
			t.Errorf("link-local scope = %d over links %v, want 0", got, zones)
		}
		wantKernelError(t, "PathInfo(fe80::1) with no zone over two links", "get", get2(client.PathInfo(netip.MustParseAddr("fe80::1"))), syscall.EINVAL)
	})
}

// TestPathThresholdsReadModifyWrite: SetPathThresholds changes only the
// fields it is given, both for one path and for the association, although
// Linux applies the PF and switchover thresholds whatever their value
// (net/sctp/socket.c: sctp_setsockopt_paddr_thresholds).
func TestPathThresholdsReadModifyWrite(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	for _, path := range []netip.Addr{{}, primaryPath(t, client)} {
		name := "association"
		if path.IsValid() {
			name = "path " + path.String()
		}
		t.Run(name, func(t *testing.T) {
			get := func() [3]uint16 {
				t.Helper()
				p, err := client.PathThresholds(path)
				if err != nil {
					t.Fatalf("PathThresholds: %v", err)
				}
				if p.PathMaxRetrans == nil || p.PFThreshold == nil || p.PrimarySwitchover == nil {
					t.Fatalf("PathThresholds left a field nil: %+v", p)
				}
				return [3]uint16{*p.PathMaxRetrans, *p.PFThreshold, *p.PrimarySwitchover}
			}
			start := get()
			if path == (netip.Addr{}) && start[2] != 0xffff {
				// The kernel's default switchover threshold disables
				// switchover; anything else means the field is read from
				// the wrong offset.
				t.Errorf("default PrimarySwitchover = %#x, want 0xffff", start[2])
			}
			if err := client.SetPathThresholds(path, &PathThresholds{PFThreshold: new(uint16(2))}); err != nil {
				t.Fatalf("SetPathThresholds(PF): %v", err)
			}
			if got := get(); got != [3]uint16{start[0], 2, start[2]} {
				t.Errorf("after setting PFThreshold alone: %v, want %v", got, [3]uint16{start[0], 2, start[2]})
			}
			if err := client.SetPathThresholds(path, &PathThresholds{PrimarySwitchover: new(uint16(4))}); err != nil {
				t.Fatalf("SetPathThresholds(switchover): %v", err)
			}
			if got := get(); got != [3]uint16{start[0], 2, 4} {
				t.Errorf("after setting PrimarySwitchover alone: %v, want %v", got, [3]uint16{start[0], 2, 4})
			}
			if err := client.SetPathThresholds(path, &PathThresholds{PathMaxRetrans: new(uint16(7))}); err != nil {
				t.Fatalf("SetPathThresholds(max retrans): %v", err)
			}
			if got := get(); got != [3]uint16{7, 2, 4} {
				t.Errorf("after setting PathMaxRetrans alone: %v, want [7 2 4]", got)
			}
			if err := client.SetPathThresholds(path, &PathThresholds{}); err != nil {
				t.Fatalf("SetPathThresholds(nothing): %v", err)
			}
			if got := get(); got != [3]uint16{7, 2, 4} {
				t.Errorf("an empty PathThresholds changed them to %v", got)
			}
			// A PF threshold above the switchover threshold is Linux's to
			// refuse (sctp_setsockopt_paddr_thresholds).
			wantKernelError(t, "SetPathThresholds(PF above switchover)", "set",
				client.SetPathThresholds(path, &PathThresholds{PFThreshold: new(uint16(5))}), syscall.EINVAL)
			calls := countSockopts(t)
			wantOpError(t, "SetPathThresholds(max retrans 0)", "set",
				client.SetPathThresholds(path, &PathThresholds{PathMaxRetrans: new(uint16(0))}), syscall.EINVAL)
			wantOpError(t, "SetPathThresholds(nil)", "set", client.SetPathThresholds(path, nil), syscall.EINVAL)
			if n := calls.Load(); n != 0 {
				t.Errorf("%d option system calls for refused arguments, want 0", n)
			}
		})
	}
}

// TestUDPEncapsAndProbeIntervalPerPath: both options reach one path as well
// as the association (RFC 6951 §6.1, updated by RFC 8899; RFC 8899 for the
// probe interval).
func TestUDPEncapsAndProbeIntervalPerPath(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	primary := primaryPath(t, client)
	if err := client.SetRemoteUDPEncapsPort(primary, 9900); err != nil {
		t.Fatalf("SetRemoteUDPEncapsPort(%v): %v", primary, err)
	}
	if got, err := client.RemoteUDPEncapsPort(primary); err != nil || got != 9900 {
		t.Errorf("RemoteUDPEncapsPort(%v) = %d, %v; want 9900", primary, got, err)
	}
	if got, err := client.RemoteUDPEncapsPort(netip.Addr{}); err != nil || got != 0 {
		t.Errorf("association-wide RemoteUDPEncapsPort = %d, %v; want 0, untouched by the per-path setting", got, err)
	}

	if err := client.SetPLPMTUDProbeInterval(primary, 20*time.Second+3*time.Millisecond); err != nil {
		t.Fatalf("SetPLPMTUDProbeInterval(%v): %v", primary, err)
	}
	if got, err := client.PLPMTUDProbeInterval(primary); err != nil || !kernelTickReadback(got, 20*time.Second+3*time.Millisecond) {
		t.Errorf("PLPMTUDProbeInterval(%v) = %v, %v; want tick-rounded 20.003s", primary, got, err)
	}
	if err := client.SetPLPMTUDProbeInterval(netip.Addr{}, 0); err != nil {
		t.Fatalf("SetPLPMTUDProbeInterval(0): %v", err)
	}
	if got, err := client.PLPMTUDProbeInterval(netip.Addr{}); err != nil || got != 0 {
		t.Errorf("PLPMTUDProbeInterval after disabling = %v, %v; want 0", got, err)
	}
	calls := countSockopts(t)
	for _, d := range []time.Duration{time.Second, 4999 * time.Millisecond, -time.Second, 1500 * time.Microsecond} {
		wantOpError(t, "SetPLPMTUDProbeInterval("+d.String()+")", "set", client.SetPLPMTUDProbeInterval(netip.Addr{}, d), syscall.EINVAL)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d option system calls for refused intervals, want 0", n)
	}
}

// --- association -------------------------------------------------------------

// TestStatusReportsEstablished: an association that has carried a message
// reports StateEstablished and an active primary path with an MTU and an
// RTO (v1 TestGetStatusReportsEstablished).
func TestStatusReportsEstablished(t *testing.T) {
	client, server := connPair(t, nil, nil)
	if _, err := client.Write([]byte("status probe")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := server.Read(make([]byte, 64)); err != nil {
		t.Fatalf("Read: %v", err)
	}
	st, err := client.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.State != StateEstablished {
		t.Errorf("State = %v, want StateEstablished", st.State)
	}
	if st.Primary.State != PathActive || st.Primary.MTU == 0 || st.Primary.RTO == 0 {
		t.Errorf("Primary = %+v, want an active path with an MTU and an RTO", st.Primary)
	}
	if st.Primary.Addr.Addr() != primaryPath(t, client) || st.Primary.Addr.Port() != client.RemoteAddr().(*Addr).Port {
		t.Errorf("Primary.Addr = %v, want the primary path %v with the peer's port", st.Primary.Addr, primaryPath(t, client))
	}
	if st.InStreams == 0 || st.OutStreams == 0 || st.FragmentationPoint == 0 || st.PeerRwnd == 0 {
		t.Errorf("Status = %+v, want streams, a fragmentation point and a peer window", st)
	}
}

// TestStatusAfterShutdown: once the peer closes, the state moves off
// StateEstablished, or the association is gone and Status reports the
// kernel's EINVAL (v1 TestGetStatusAfterShutdown).
func TestStatusAfterShutdown(t *testing.T) {
	client, server := connPair(t, nil, nil)
	if err := server.Close(); err != nil {
		t.Fatalf("server Close: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		st, err := client.Status()
		if err != nil {
			wantKernelError(t, "Status after the peer closed", "get", err, syscall.EINVAL)
			return
		}
		if st.State != StateEstablished {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("state still %v 3 s after the peer closed", st.State)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestStatusReportsNegotiatedStreams: the outbound streams Status reports
// are what the peer's MaxInStreams allowed, and a send on the first stream
// past them is refused (v1 TestGetStatus, TestGetStatusUsage).
func TestStatusReportsNegotiatedStreams(t *testing.T) {
	client, _ := connPair(t, nil, &Config{InitMsg: InitMsg{OutStreams: 5, MaxInStreams: 2}})
	st, err := client.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.OutStreams != 2 {
		t.Fatalf("OutStreams = %d, want the peer's MaxInStreams 2", st.OutStreams)
	}
	for sid := uint16(0); sid < st.OutStreams; sid++ {
		if _, err := client.SendMsg([]byte("hello"), SendOptions{Info: &SndInfo{Stream: sid}}); err != nil {
			t.Errorf("SendMsg on stream %d of %d: %v", sid, st.OutStreams, err)
		}
	}
	if _, err := client.SendMsg([]byte("hello"), SendOptions{Info: &SndInfo{Stream: st.OutStreams}}); err == nil {
		t.Errorf("SendMsg on stream %d, one past the %d negotiated, succeeded", st.OutStreams, st.OutStreams)
	}
}

// TestInitMsgAndAdaptationLayerReportWhatWasAnnounced: both getters report
// what this side announced in its INIT or INIT ACK, which an accepted
// connection takes from its listener.
func TestInitMsgAndAdaptationLayerReportWhatWasAnnounced(t *testing.T) {
	adaptation := uint32(0xdeadbeef)
	cfg := &Config{
		InitMsg:         InitMsg{OutStreams: 7, MaxInStreams: 9, MaxAttempts: 3, MaxInitTimeout: 4 * time.Second},
		AdaptationLayer: &adaptation,
	}
	client, server := connPair(t, cfg, cfg)
	for name, c := range map[string]*Conn{"client": client, "server": server} {
		if got, err := c.InitMsg(); err != nil || *got != cfg.InitMsg {
			t.Errorf("%s InitMsg = %+v, %v; want %+v", name, got, err, cfg.InitMsg)
		}
		if got, err := c.AdaptationLayer(); err != nil || got != adaptation {
			t.Errorf("%s AdaptationLayer = %#x, %v; want %#x", name, got, err, adaptation)
		}
	}
}

// TestAssociationDefaults: the association's values read back as the
// kernel's defaults, non-zero where a misplaced field would read zero (v1
// TestRtoInfoRoundTrip, TestAssocInfoRoundTrip, TestMaxBurstRoundTrip,
// TestContextRoundTrip, TestStreamSchedulerRoundTrips).
func TestAssociationDefaults(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	// RFC 6458 §8.1.24 documents a default burst of 4, Linux's
	// net.sctp.max_burst.
	if n, err := client.MaxBurst(); err != nil || n != 4 {
		t.Errorf("MaxBurst = %d, %v; want the default 4", n, err)
	}
	if v, err := client.DefaultContext(); err != nil || v != 0 {
		t.Errorf("DefaultContext = %d, %v; want 0", v, err)
	}
	if s, err := client.StreamScheduler(); err != nil || s != SchedFCFS {
		t.Errorf("StreamScheduler = %v, %v; want SchedFCFS", s, err)
	}
	rto, err := client.RTOInfo()
	if err != nil || rto.Initial == 0 || rto.Max == 0 || rto.Min == 0 {
		t.Errorf("RTOInfo = %+v, %v; want the kernel's non-zero defaults", rto, err)
	}
	a, err := client.AssocInfo()
	if err != nil || a.MaxRetrans == 0 || a.LocalRwnd == 0 || a.PeerRwnd == 0 || a.PeerDestinations != 1 || a.CookieLife == 0 {
		t.Errorf("AssocInfo = %+v, %v; want non-zero values and one peer destination", a, err)
	}
	calls := countSockopts(t)
	for _, r := range []RTOInfo{{Min: 2 * time.Second, Max: time.Second}, {Initial: 1500 * time.Microsecond}} {
		wantOpError(t, "SetRTOInfo", "set", client.SetRTOInfo(&r), syscall.EINVAL)
	}
	wantOpError(t, "SetAssocInfo(fractional cookie life)", "set", client.SetAssocInfo(&AssocInfo{CookieLife: time.Microsecond}), syscall.EINVAL)
	wantOpError(t, "SetMaxBurst(-1)", "set", client.SetMaxBurst(-1), syscall.EINVAL)
	wantOpError(t, "SetStreamResetMask(0x08)", "set", client.SetStreamResetMask(EnableResetStreamReq|0x08), syscall.EINVAL)
	if n := calls.Load(); n != 0 {
		t.Errorf("%d option system calls for refused arguments, want 0", n)
	}
	if m, err := client.StreamResetMask(); err != nil || m != 0 {
		t.Errorf("StreamResetMask after a refused mask = %v, %v; want it untouched", m, err)
	}
}

// TestAssociationQueriesAfterTheEnd: once the peer has aborted and Linux
// has freed the association, the queries that need one fail with Linux's
// EINVAL (net/sctp/socket.c: sctp_id2assoc finds none; v1
// TestAssocStatsNeedsAssociation, TestPeerAuthChunksNeedsAssociation,
// TestPrStreamStatusNeedsAssociation), while the Conn stays open until
// Close.
func TestAssociationQueriesAfterTheEnd(t *testing.T) {
	client, server := connPair(t, authConfig(), authConfig())
	primary := primaryPath(t, client)
	if err := server.Abort(); err != nil {
		t.Fatalf("server Abort: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := client.Status(); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the association outlived the peer's ABORT by 5 s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for name, err := range map[string]error{
		"Status":         get2(client.Status()),
		"Stats":          get2(client.Stats()),
		"PathInfo":       get2(client.PathInfo(primary)),
		"PRAssocStatus":  get2(client.PRAssocStatus(PRTTL)),
		"PRStreamStatus": get2(client.PRStreamStatus(0, PRTTL)),
		"PeerAuthChunks": get2(client.PeerAuthChunks()),
		"PrimaryAddr":    get2(client.PrimaryAddr()),
	} {
		wantKernelError(t, name+" after the end", "get", err, syscall.EINVAL)
	}
}

// TestDelayedSACKZeroFieldsLeaveValues: a zero Delay or Frequency leaves
// that value as it is (RFC 6458 §8.1.19), except that Frequency 1 turns
// delayed SACK off and Linux then reports no delay (v1
// TestSackTimerZeroFieldMeansUnchanged).
func TestDelayedSACKZeroFieldsLeaveValues(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	get := func() DelayedSACK {
		t.Helper()
		d, err := client.DelayedSACK()
		if err != nil {
			t.Fatalf("DelayedSACK: %v", err)
		}
		return *d
	}
	set := func(d DelayedSACK) {
		t.Helper()
		if err := client.SetDelayedSACK(&d); err != nil {
			t.Fatalf("SetDelayedSACK(%+v): %v", d, err)
		}
	}
	set(DelayedSACK{Delay: 303 * time.Millisecond, Frequency: 5})
	set(DelayedSACK{Frequency: 9})
	if got := get(); !kernelTickReadback(got.Delay, 303*time.Millisecond) || got.Frequency != 9 {
		t.Errorf("after a zero Delay: %+v, want the delay kept", got)
	}
	set(DelayedSACK{Delay: 203 * time.Millisecond})
	if got := get(); !kernelTickReadback(got.Delay, 203*time.Millisecond) || got.Frequency != 9 {
		t.Errorf("after a zero Frequency: %+v, want the frequency kept", got)
	}
	set(DelayedSACK{})
	if got := get(); !kernelTickReadback(got.Delay, 203*time.Millisecond) || got.Frequency != 9 {
		t.Errorf("an empty DelayedSACK changed the values to %+v", got)
	}
	set(DelayedSACK{Frequency: 1})
	if got := get(); got != (DelayedSACK{Frequency: 1}) {
		t.Errorf("after Frequency 1: %+v, want delayed SACK off, reported as no delay and frequency 1", got)
	}
	wantOpError(t, "SetDelayedSACK(600ms)", "set", client.SetDelayedSACK(&DelayedSACK{Delay: 600 * time.Millisecond}), syscall.EINVAL)
}

// TestOptionNilArguments: every setter that takes a pointer refuses nil
// with an error matching syscall.EINVAL before any system call (v1
// TestNilSocketOptionArgumentsReturnEINVAL).
func TestOptionNilArguments(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	calls := countSockopts(t)
	for name, err := range map[string]error{
		"SetPathParams":     client.SetPathParams(netip.Addr{}, nil),
		"SetPathThresholds": client.SetPathThresholds(netip.Addr{}, nil),
		"SetAssocInfo":      client.SetAssocInfo(nil),
		"SetRTOInfo":        client.SetRTOInfo(nil),
		"SetDelayedSACK":    client.SetDelayedSACK(nil),
	} {
		wantOpError(t, name+"(nil)", "set", err, syscall.EINVAL)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d option system calls for nil arguments, want 0", n)
	}
}

// TestTickFieldsAreRawKernelValues: Stats().MaxRTOTicks and
// PathInfo().SRTTTicks are the kernel's own numbers, in ticks, compared
// with the same options read through SyscallConn. Reading
// SCTP_GET_ASSOC_STATS resets the observed maximum
// (net/sctp/socket.c: sctp_getsockopt_assoc_stats), and an RTT sample can
// move both between two reads, so each comparison is retried a few times.
func TestTickFieldsAreRawKernelValues(t *testing.T) {
	client, server := connPair(t, nil, nil)
	for i := 0; i < 5; i++ {
		if _, err := client.Write([]byte("rtt sample")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if _, err := server.Read(make([]byte, 64)); err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	rc := mustSyscallConn(t, client)
	l, err := client.sock.storageLayout()
	if err != nil {
		t.Fatal(err)
	}
	rawMaxRTO := func() uint64 {
		b := make([]byte, sizeAssocStatsKernel64)
		getRawOpt(t, rc, optGetAssocStats, l.assocStatsRequest(b, client.AssocID()))
		return binary.NativeEndian.Uint64(b[l.statsCountersOff+8*assocStatsMaxRTO:])
	}
	matched := false
	for i := 0; i < 20 && !matched; i++ {
		_ = rawMaxRTO() // start an observation period
		s, err := client.Stats()
		if err != nil {
			t.Fatalf("Stats: %v", err)
		}
		matched = s.MaxRTOTicks == rawMaxRTO() && s.MaxRTOTicks != 0
	}
	if !matched {
		t.Error("Stats().MaxRTOTicks never equalled SCTP_GET_ASSOC_STATS' sas_maxrto read through SyscallConn")
	}

	primary := primaryPath(t, client)
	rawSRTT := func() uint32 {
		var b [sizePathInfo]byte
		n, err := encodeAddr(b[pathInfoAddressOff:], client.sock.family, primary, client.RemoteAddr().(*Addr).Port)
		if err != nil || n == 0 {
			t.Fatal(err)
		}
		getRawOpt(t, rc, optGetPeerAddrInfo, b[:])
		return binary.NativeEndian.Uint32(b[pathInfoSRTTOff:])
	}
	matched = false
	for i := 0; i < 20 && !matched; i++ {
		info, err := client.PathInfo(primary)
		if err != nil {
			t.Fatalf("PathInfo: %v", err)
		}
		st, err := client.Status()
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		raw := rawSRTT()
		matched = info.SRTTTicks == raw && st.Primary.SRTTTicks == raw
	}
	if !matched {
		t.Error("PathInfo().SRTTTicks and Status().Primary.SRTTTicks never equalled spinfo_srtt read through SyscallConn")
	}
}

// TestAssocStatsCountsTraffic: the counters move with real traffic, which a
// struct decoded at the wrong offsets would not show (v1
// TestAssocStatsCountsTraffic).
func TestAssocStatsCountsTraffic(t *testing.T) {
	client, server := connPair(t, nil, nil)
	before, err := client.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if _, err := client.Write([]byte("stats")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := client.SendMsg([]byte("unordered"), SendOptions{Info: &SndInfo{Flags: SendUnordered}}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := server.Read(make([]byte, 64)); err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	after, err := client.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if after.PacketsOut <= before.PacketsOut || after.OrderedChunksOut <= before.OrderedChunksOut || after.UnorderedChunksOut <= before.UnorderedChunksOut {
		t.Errorf("counters did not move across two sends: before %+v, after %+v", before, after)
	}
	if after.OrderedChunksIn != before.OrderedChunksIn {
		t.Errorf("OrderedChunksIn moved from %d to %d, but nothing was received", before.OrderedChunksIn, after.OrderedChunksIn)
	}
}

// --- send and receive behaviour --------------------------------------------------

// TestMaxSeg: MaxSeg reports the association's fragmentation point, which
// Linux clamps to what the path carries, so it is at most the value set,
// and zero restores the default (v1 TestMaxSegSizeRoundTrip,
// TestMaxSegSizeRejectsOutOfRange).
func TestMaxSeg(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	before, err := client.MaxSeg()
	if err != nil || before <= 0 {
		t.Fatalf("MaxSeg = %d, %v", before, err)
	}
	if err := client.SetMaxSeg(1200); err != nil {
		t.Fatalf("SetMaxSeg(1200): %v", err)
	}
	if got, err := client.MaxSeg(); err != nil || got > 1200 || got < 1100 {
		t.Errorf("MaxSeg after setting 1200 = %d, %v", got, err)
	}
	if st, err := client.Status(); err != nil || st.FragmentationPoint > 1200 {
		t.Errorf("Status().FragmentationPoint = %d, %v; want at most 1200", st.FragmentationPoint, err)
	}
	if err := client.SetMaxSeg(0); err != nil {
		t.Fatalf("SetMaxSeg(0): %v", err)
	}
	if got, err := client.MaxSeg(); err != nil || got != before {
		t.Errorf("MaxSeg after restoring the default = %d, %v; want %d", got, err, before)
	}
	wantOpError(t, "SetMaxSeg(-1)", "set", client.SetMaxSeg(-1), syscall.EINVAL)
	if strconv.IntSize == 64 {
		var big int64 = 1 << 33
		wantOpError(t, "SetMaxSeg(1<<33)", "set", client.SetMaxSeg(int(big)), syscall.EINVAL)
	}
	// Linux refuses a segment smaller than it can fragment into
	// (net/sctp/socket.c: sctp_setsockopt_maxseg).
	wantKernelError(t, "SetMaxSeg(1)", "set", client.SetMaxSeg(1), syscall.EINVAL)
}

// TestPartialDeliveryPointBounds: a negative point or one beyond uint32 is
// refused by the package, and one beyond half the receive buffer by Linux
// (net/sctp/socket.c: sctp_setsockopt_partial_delivery_point).
func TestPartialDeliveryPointBounds(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	wantOpError(t, "SetPartialDeliveryPoint(-1)", "set", client.SetPartialDeliveryPoint(-1), syscall.EINVAL)
	if strconv.IntSize == 64 {
		var big int64 = math.MaxUint32
		big++
		wantOpError(t, "SetPartialDeliveryPoint(1<<32)", "set", client.SetPartialDeliveryPoint(int(big)), syscall.EINVAL)
	}
	rcvbuf, err := client.ReadBuffer()
	if err != nil {
		t.Fatalf("ReadBuffer: %v", err)
	}
	wantKernelError(t, "SetPartialDeliveryPoint(beyond the buffer)", "set", client.SetPartialDeliveryPoint(rcvbuf), syscall.EINVAL)
}

// TestFragmentInterleaveLevels: Linux keeps the option as a boolean, so
// InterleaveStreams is refused with ErrUnsupported and an unnamed level
// with EINVAL, both before any system call and leaving the level as it was.
func TestFragmentInterleaveLevels(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	if got, err := client.FragmentInterleave(); err != nil || got != InterleaveNone {
		t.Errorf("default FragmentInterleave = %v, %v; want InterleaveNone on a one-to-one socket", got, err)
	}
	if err := client.SetFragmentInterleave(InterleaveAssocs); err != nil {
		t.Fatalf("SetFragmentInterleave(InterleaveAssocs): %v", err)
	}
	calls := countSockopts(t)
	wantOpError(t, "SetFragmentInterleave(InterleaveStreams)", "set", client.SetFragmentInterleave(InterleaveStreams), ErrUnsupported)
	for _, level := range []FragmentInterleave{3, -1} {
		wantOpError(t, "SetFragmentInterleave("+level.String()+")", "set", client.SetFragmentInterleave(level), syscall.EINVAL)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d option system calls for refused levels, want 0", n)
	}
	if got, err := client.FragmentInterleave(); err != nil || got != InterleaveAssocs {
		t.Errorf("FragmentInterleave after the refusals = %v, %v; want InterleaveAssocs", got, err)
	}
}

// TestDefaultContextReachesRcvInfo: the default context is what the
// receiving side's RcvInfo.Context carries for messages from the peer
// (RFC 6458 §8.1.25; net/sctp/ulpevent.c copies asoc->default_rcv_context).
func TestDefaultContextReachesRcvInfo(t *testing.T) {
	client, server := connPair(t, nil, nil)
	if err := server.SetDefaultContext(0x5eed); err != nil {
		t.Fatalf("SetDefaultContext: %v", err)
	}
	if _, err := client.Write([]byte("x")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_, rcv, err := server.ReadMsg(64)
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	if rcv.Context != 0x5eed {
		t.Errorf("RcvInfo.Context = %#x, want 0x5eed", rcv.Context)
	}
	if rcv.TSN == 0x5eed || rcv.TSN == 0 {
		t.Errorf("RcvInfo.TSN = %#x; a TSN equal to the context, or zero, means the fields are swapped", rcv.TSN)
	}
}

// TestReceiveNxtInfoOnALiveConnection: switching ReceiveNxtInfo on after
// setup makes RecvMsg describe the next queued message.
func TestReceiveNxtInfoOnALiveConnection(t *testing.T) {
	client, server := connPair(t, nil, nil)
	if err := server.SetReceiveNxtInfo(true); err != nil {
		t.Fatalf("SetReceiveNxtInfo: %v", err)
	}
	for _, m := range []string{"first", "second message"} {
		if _, err := client.Write([]byte(m)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	buf := make([]byte, 64)
	deadline := time.Now().Add(5 * time.Second)
	for {
		// Wait until the peer has acknowledged both messages, so that both
		// are queued and the first read has a next one to describe.
		if a, err := client.Status(); err == nil && a.Unacked == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the two messages were not acknowledged within 5 s")
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, info, err := server.RecvMsg(buf)
	if err != nil {
		t.Fatalf("RecvMsg: %v", err)
	}
	if !info.HasNxt || info.Nxt.Length != uint32(len("second message")) {
		t.Errorf("MsgInfo = %+v; want NxtInfo for the %d-byte second message", info, len("second message"))
	}
}

// TestAutoASCONFNeedsAWildcardBind: Linux refuses to switch automatic
// ASCONF on for an endpoint not bound to every address (net/sctp/socket.c:
// sctp_setsockopt_auto_asconf).
func TestAutoASCONFNeedsAWildcardBind(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	type result struct {
		c   *Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := l.AcceptSCTP()
		ch <- result{c, err}
	}()
	client, err := Dial(testContext(t, 10*time.Second), "sctp4", loopback4(0), listenerAddr(t, l))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Abort() })
	if r := <-ch; r.err == nil {
		t.Cleanup(func() { _ = r.c.Abort() })
	}
	wantKernelError(t, "SetAutoASCONF(true) on a bound address", "set", client.SetAutoASCONF(true), syscall.EINVAL)
	if on, err := client.AutoASCONF(); err != nil || on {
		t.Errorf("AutoASCONF = %v, %v; want false", on, err)
	}
}

// TestPFExposureHasNoLockedState: every level can follow every other, and
// only a level Linux does not name is refused, by the package, with EINVAL
// (net/sctp/socket.c: sctp_setsockopt_pf_expose refuses nothing else; v1
// TestExposePotentiallyFailedHasNoLockedState).
func TestPFExposureHasNoLockedState(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	for _, e := range []PFExposure{PFExposeEnabled, PFExposeDisabled, PFExposeEnabled, PFExposeUnset, PFExposeEnabled, PFExposeUnset} {
		if err := client.SetPFExposure(e); err != nil {
			t.Fatalf("SetPFExposure(%v): %v", e, err)
		}
		if got, err := client.PFExposure(); err != nil || got != e {
			t.Fatalf("PFExposure = %v, %v; want %v", got, err, e)
		}
	}
	wantOpError(t, "SetPFExposure(3)", "set", client.SetPFExposure(PFExposeEnabled+1), syscall.EINVAL)
}

// --- the kernel layer ------------------------------------------------------

// TestUnknownOptionReportsENOPROTOOPT: an option the running kernel does
// not have fails with a *net.OpError around an *os.SyscallError holding
// ENOPROTOOPT (net/sctp/socket.c: the default of sctp_setsockopt and
// sctp_getsockopt), which is how a caller detects an option an older
// kernel lacks.
func TestUnknownOptionReportsENOPROTOOPT(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	const unknown = 999
	_, err := client.assocValueOption(unknown)
	wantKernelError(t, "get option 999", "get", err, syscall.ENOPROTOOPT)
	wantKernelError(t, "set option 999", "set", client.setAssocValueOption(unknown, 1), syscall.ENOPROTOOPT)
}

// TestStorageLayoutOnThisKernel: the probe's premise holds on the running
// kernel. Linux refuses SCTP_PEER_ADDR_THLDS with a buffer shorter than
// its own struct sctp_paddrthlds (net/sctp/socket.c:
// sctp_getsockopt_paddr_thresholds), so the 32-bit struct's 136 bytes are
// refused with EINVAL by a 64-bit kernel, and a build's own native size is
// accepted by a kernel of its word size. A 64-bit build picks its layout
// with no system call at all.
func TestStorageLayoutOnThisKernel(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	if wordSize == 8 {
		calls := countSockopts(t)
		l, err := client.sock.storageLayout()
		if err != nil || l != &nativeStorageLayout {
			t.Errorf("storageLayout = %p, %v; want the native layout", l, err)
		}
		if n := calls.Load(); n != 0 {
			t.Errorf("a 64-bit build made %d system calls to pick its layout, want 0", n)
		}
		if err := client.sock.probeKernelWordSize(); err != nil {
			t.Errorf("probe with the 64-bit size on a 64-bit kernel: %v, want success", err)
		}
		var b [136]byte
		l32 := uint32(len(b))
		var perr error
		rawFd(t, mustSyscallConn(t, client), func(fd int) {
			perr = rawGetsockopt(fd, ipprotoSCTP, optPathThresholdsProbe, unsafe.Pointer(&b[0]), &l32)
		})
		if perr != syscall.EINVAL {
			t.Errorf("SCTP_PEER_ADDR_THLDS with 136 bytes = %v, want EINVAL from a 64-bit kernel", perr)
		}
		return
	}
	// A 32-bit build: CI's native linux/386 job on an x86_64 runner.
	l, err := client.sock.storageLayout()
	if err != nil {
		t.Fatalf("storageLayout: %v", err)
	}
	t.Logf("a 32-bit build chose the %s layout", map[bool]string{true: "kernel64", false: "native"}[l == &kernel64StorageLayout])
}

// --- concurrency --------------------------------------------------------------

// TestDefaultsReadModifyWriteIsAtomic: SetDefaultSndInfo sets the default
// PR-SCTP policy again after the SCTP_DEFAULT_SNDINFO write that clears it
// (net/sctp/socket.c: sctp_setsockopt_default_sndinfo overwrites
// default_flags whole), and no concurrent DefaultPrInfo may observe the
// window between the two.
func TestDefaultsReadModifyWriteIsAtomic(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	pr := PrInfo{Policy: PRTTL, TTL: 1500 * time.Millisecond}
	if err := client.SetDefaultPrInfo(&pr); err != nil {
		t.Fatalf("SetDefaultPrInfo: %v", err)
	}
	var (
		wg      sync.WaitGroup
		stop    atomic.Bool
		torn    atomic.Int64
		readErr atomic.Value
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000 && !stop.Load(); i++ {
			if err := client.SetDefaultSndInfo(&SndInfo{Stream: uint16(i % 3)}); err != nil {
				readErr.Store(err)
				return
			}
		}
		stop.Store(true)
	}()
	go func() {
		defer wg.Done()
		for !stop.Load() {
			got, err := client.DefaultPrInfo()
			if err != nil {
				readErr.Store(err)
				stop.Store(true)
				return
			}
			if *got != pr {
				torn.Add(1)
			}
		}
	}()
	wg.Wait()
	if err, _ := readErr.Load().(error); err != nil {
		t.Fatalf("concurrent defaults: %v", err)
	}
	if n := torn.Load(); n != 0 {
		t.Errorf("DefaultPrInfo saw the default PR-SCTP policy cleared %d times during SetDefaultSndInfo", n)
	}
}

// TestPathMaxRetransIsNotLost: SetPathParams and SetPathThresholds both
// write the retransmission limit (spp_pathmaxrxt, spt_pathmaxrxt), and
// SetPathThresholds does it by reading the thresholds and writing them
// back (net/sctp/socket.c: sctp_setsockopt_paddr_thresholds), so the two
// take the same option lock: a limit SetPathParams set is never
// overwritten by a SetPathThresholds that had read the one before.
func TestPathMaxRetransIsNotLost(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	var (
		wg   sync.WaitGroup
		stop atomic.Bool
		lost atomic.Int64
		fail atomic.Value
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		pf := uint16(1)
		for !stop.Load() {
			if err := client.SetPathThresholds(netip.Addr{}, &PathThresholds{PFThreshold: &pf}); err != nil {
				fail.Store(err)
				stop.Store(true)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		defer stop.Store(true)
		for i := 0; i < 2000 && !stop.Load(); i++ {
			want := uint16(2 + i%50)
			if err := client.SetPathParams(netip.Addr{}, &PathParams{PathMaxRetrans: &want}); err != nil {
				fail.Store(err)
				return
			}
			got, err := client.PathParams(netip.Addr{})
			if err != nil {
				fail.Store(err)
				return
			}
			if *got.PathMaxRetrans != want {
				lost.Add(1)
			}
		}
	}()
	wg.Wait()
	if err, _ := fail.Load().(error); err != nil {
		t.Fatalf("concurrent path options: %v", err)
	}
	if n := lost.Load(); n != 0 {
		t.Errorf("SetPathThresholds wrote back an older retransmission limit over SetPathParams' %d times", n)
	}
}

// --- closed connections, and the method table ------------------------------

// optionMethod is one exported option method, called with arguments it
// would accept on an open connection.
type optionMethod struct {
	name string
	op   string
	call func(c *Conn) error
}

// optionMethods lists every Conn method options_linux.go and
// options_ext_linux.go declare; TestOptionMethodTableIsComplete keeps the
// list and the files in step.
func optionMethods() []optionMethod {
	ip := netip.MustParseAddr("127.0.0.1")
	return []optionMethod{
		{"ReadBuffer", "get", func(c *Conn) error { return get2(c.ReadBuffer()) }},
		{"SetReadBuffer", "set", func(c *Conn) error { return c.SetReadBuffer(4096) }},
		{"WriteBuffer", "get", func(c *Conn) error { return get2(c.WriteBuffer()) }},
		{"SetWriteBuffer", "set", func(c *Conn) error { return c.SetWriteBuffer(4096) }},
		{"PrimaryAddr", "get", func(c *Conn) error { return get2(c.PrimaryAddr()) }},
		{"SetPrimaryAddr", "set", func(c *Conn) error { return c.SetPrimaryAddr(ip) }},
		{"RequestPeerPrimary", "set", func(c *Conn) error { return c.RequestPeerPrimary(ip) }},
		{"PathInfo", "get", func(c *Conn) error { return get2(c.PathInfo(ip)) }},
		{"PathParams", "get", func(c *Conn) error { return get2(c.PathParams(ip)) }},
		{"SetPathParams", "set", func(c *Conn) error { return c.SetPathParams(ip, &PathParams{}) }},
		{"RequestHeartbeat", "set", func(c *Conn) error { return c.RequestHeartbeat(ip) }},
		{"PathThresholds", "get", func(c *Conn) error { return get2(c.PathThresholds(ip)) }},
		{"SetPathThresholds", "set", func(c *Conn) error { return c.SetPathThresholds(ip, &PathThresholds{}) }},
		{"PFExposure", "get", func(c *Conn) error { return get2(c.PFExposure()) }},
		{"SetPFExposure", "set", func(c *Conn) error { return c.SetPFExposure(PFExposeEnabled) }},
		{"AutoASCONF", "get", func(c *Conn) error { return get2(c.AutoASCONF()) }},
		{"SetAutoASCONF", "set", func(c *Conn) error { return c.SetAutoASCONF(false) }},
		{"RemoteUDPEncapsPort", "get", func(c *Conn) error { return get2(c.RemoteUDPEncapsPort(ip)) }},
		{"SetRemoteUDPEncapsPort", "set", func(c *Conn) error { return c.SetRemoteUDPEncapsPort(ip, 9899) }},
		{"PLPMTUDProbeInterval", "get", func(c *Conn) error { return get2(c.PLPMTUDProbeInterval(ip)) }},
		{"SetPLPMTUDProbeInterval", "set", func(c *Conn) error { return c.SetPLPMTUDProbeInterval(ip, 0) }},
		{"Status", "get", func(c *Conn) error { return get2(c.Status()) }},
		{"Stats", "get", func(c *Conn) error { return get2(c.Stats()) }},
		{"AssocInfo", "get", func(c *Conn) error { return get2(c.AssocInfo()) }},
		{"SetAssocInfo", "set", func(c *Conn) error { return c.SetAssocInfo(&AssocInfo{}) }},
		{"RTOInfo", "get", func(c *Conn) error { return get2(c.RTOInfo()) }},
		{"SetRTOInfo", "set", func(c *Conn) error { return c.SetRTOInfo(&RTOInfo{}) }},
		{"InitMsg", "get", func(c *Conn) error { return get2(c.InitMsg()) }},
		{"DelayedSACK", "get", func(c *Conn) error { return get2(c.DelayedSACK()) }},
		{"SetDelayedSACK", "set", func(c *Conn) error { return c.SetDelayedSACK(&DelayedSACK{}) }},
		{"AdaptationLayer", "get", func(c *Conn) error { return get2(c.AdaptationLayer()) }},
		{"NoDelay", "get", func(c *Conn) error { return get2(c.NoDelay()) }},
		{"SetNoDelay", "set", func(c *Conn) error { return c.SetNoDelay(true) }},
		{"MaxSeg", "get", func(c *Conn) error { return get2(c.MaxSeg()) }},
		{"SetMaxSeg", "set", func(c *Conn) error { return c.SetMaxSeg(0) }},
		{"MaxBurst", "get", func(c *Conn) error { return get2(c.MaxBurst()) }},
		{"SetMaxBurst", "set", func(c *Conn) error { return c.SetMaxBurst(4) }},
		{"FragmentsDisabled", "get", func(c *Conn) error { return get2(c.FragmentsDisabled()) }},
		{"SetFragmentsDisabled", "set", func(c *Conn) error { return c.SetFragmentsDisabled(false) }},
		{"FragmentInterleave", "get", func(c *Conn) error { return get2(c.FragmentInterleave()) }},
		{"SetFragmentInterleave", "set", func(c *Conn) error { return c.SetFragmentInterleave(InterleaveNone) }},
		{"PartialDeliveryPoint", "get", func(c *Conn) error { return get2(c.PartialDeliveryPoint()) }},
		{"SetPartialDeliveryPoint", "set", func(c *Conn) error { return c.SetPartialDeliveryPoint(0) }},
		{"ReceiveNxtInfo", "get", func(c *Conn) error { return get2(c.ReceiveNxtInfo()) }},
		{"SetReceiveNxtInfo", "set", func(c *Conn) error { return c.SetReceiveNxtInfo(false) }},
		{"DefaultContext", "get", func(c *Conn) error { return get2(c.DefaultContext()) }},
		{"SetDefaultContext", "set", func(c *Conn) error { return c.SetDefaultContext(0) }},
		{"PRSupported", "get", func(c *Conn) error { return get2(c.PRSupported()) }},
		{"ReconfigSupported", "get", func(c *Conn) error { return get2(c.ReconfigSupported()) }},
		{"ASCONFSupported", "get", func(c *Conn) error { return get2(c.ASCONFSupported()) }},
		{"AuthSupported", "get", func(c *Conn) error { return get2(c.AuthSupported()) }},
		{"InterleavingSupported", "get", func(c *Conn) error { return get2(c.InterleavingSupported()) }},
		{"ECNSupported", "get", func(c *Conn) error { return get2(c.ECNSupported()) }},
		{"SetAuthKey", "set", func(c *Conn) error { return c.SetAuthKey(1, []byte("key")) }},
		{"ActiveAuthKey", "get", func(c *Conn) error { return get2(c.ActiveAuthKey()) }},
		{"SetActiveAuthKey", "set", func(c *Conn) error { return c.SetActiveAuthKey(1) }},
		{"DeactivateAuthKey", "set", func(c *Conn) error { return c.DeactivateAuthKey(1) }},
		{"DeleteAuthKey", "set", func(c *Conn) error { return c.DeleteAuthKey(1) }},
		{"HMACIdentifiers", "get", func(c *Conn) error { return get2(c.HMACIdentifiers()) }},
		{"LocalAuthChunks", "get", func(c *Conn) error { return get2(c.LocalAuthChunks()) }},
		{"PeerAuthChunks", "get", func(c *Conn) error { return get2(c.PeerAuthChunks()) }},
		{"StreamResetMask", "get", func(c *Conn) error { return get2(c.StreamResetMask()) }},
		{"SetStreamResetMask", "set", func(c *Conn) error { return c.SetStreamResetMask(0) }},
		{"ResetStreams", "set", func(c *Conn) error { return c.ResetStreams(ResetOutgoing) }},
		{"ResetAssoc", "set", func(c *Conn) error { return c.ResetAssoc() }},
		{"AddStreams", "set", func(c *Conn) error { return c.AddStreams(0, 1) }},
		{"StreamScheduler", "get", func(c *Conn) error { return get2(c.StreamScheduler()) }},
		{"SetStreamScheduler", "set", func(c *Conn) error { return c.SetStreamScheduler(SchedFCFS) }},
		{"StreamSchedulerValue", "get", func(c *Conn) error { return get2(c.StreamSchedulerValue(0)) }},
		{"SetStreamSchedulerValue", "set", func(c *Conn) error { return c.SetStreamSchedulerValue(0, 1) }},
		{"PRStreamStatus", "get", func(c *Conn) error { return get2(c.PRStreamStatus(0, PRTTL)) }},
		{"PRAssocStatus", "get", func(c *Conn) error { return get2(c.PRAssocStatus(PRTTL)) }},
	}
}

// TestOptionMethodsOnAClosedConn: after Close every option method fails
// with a *net.OpError of its own Op matching net.ErrClosed (v1
// TestSockoptsOnClosedConn, TestMaxSegSizeRejectsClosedConn,
// TestAssocInfoRejectsClosedConn).
func TestOptionMethodsOnAClosedConn(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for _, m := range optionMethods() {
		wantOpError(t, m.name+" after Close", m.op, m.call(client), net.ErrClosed)
	}
	var zero Conn
	for _, m := range optionMethods() {
		wantOpError(t, m.name+" on a zero Conn", m.op, m.call(&zero), net.ErrClosed)
	}
}

// TestOptionMethodTableIsComplete parses the two files that declare the
// option methods and requires every exported Conn method in them to be in
// optionMethods exactly once, so that a method added there is added to
// the closed-connection test too.
func TestOptionMethodTableIsComplete(t *testing.T) {
	declared := map[string]bool{}
	for _, file := range []string{"options_linux.go", "options_ext_linux.go"} {
		f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || !fn.Name.IsExported() {
				continue
			}
			if star, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
				if id, ok := star.X.(*ast.Ident); ok && id.Name == "Conn" {
					declared[fn.Name.Name] = true
				}
			}
		}
	}
	listed := map[string]bool{}
	for _, m := range optionMethods() {
		if listed[m.name] {
			t.Errorf("optionMethods lists %s twice", m.name)
		}
		listed[m.name] = true
		if !declared[m.name] {
			t.Errorf("optionMethods lists %s, which the option files do not declare", m.name)
		}
	}
	for name := range declared {
		if !listed[name] {
			t.Errorf("Conn.%s is not in optionMethods", name)
		}
	}
}
