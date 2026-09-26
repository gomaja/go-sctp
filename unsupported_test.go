// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sctp

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A Conn is a net.Conn and a Listener a net.Listener on every platform,
// so code written against them compiles everywhere.
var (
	_ net.Conn     = (*Conn)(nil)
	_ net.Listener = (*Listener)(nil)
)

// unsupportedStubCase is one function or method stubbed in unsupported.go,
// paired with a call that exercises it.
type unsupportedStubCase struct {
	name string
	call func() error

	// value marks a stub that returns only a value (an address or an
	// association id), which cannot carry ErrUnsupported: its call checks
	// that the stub returned the zero value, and returns an error only if
	// it did not.
	value bool
}

// zeroValueErr is what a value case returns when its stub did not return
// the zero value.
func zeroValueErr(got any) error {
	return fmt.Errorf("returned %v, want the zero value", got)
}

// unsupportedStubCases lists one case per function or method declared in
// unsupported.go, by the same name TestUnsupportedStubManifestIsComplete
// reads from that file's source (a bare function's own name, or
// "Receiver.Method" for a method), so the two lists never drift apart.
func unsupportedStubCases() []unsupportedStubCase {
	var (
		cfg Config
		l   Listener
		c   Conn
		e   Endpoint
	)
	ctx := context.Background()
	raddr := &Addr{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Port: 9}
	ip := netip.MustParseAddr("127.0.0.1")
	return []unsupportedStubCase{
		{name: "Dial", call: func() error { _, err := Dial(ctx, "sctp", nil, raddr); return err }},
		{name: "Config.Dial", call: func() error { _, err := cfg.Dial(ctx, "sctp", nil, raddr); return err }},
		{name: "Listen", call: func() error { _, err := Listen("sctp", nil); return err }},
		{name: "Config.Listen", call: func() error { _, err := cfg.Listen("sctp", nil); return err }},
		{name: "FileConn", call: func() error { _, err := FileConn(os.Stdin); return err }},
		{name: "Config.FileConn", call: func() error { _, err := cfg.FileConn(os.Stdin); return err }},
		{name: "FileListener", call: func() error { _, err := FileListener(os.Stdin); return err }},
		{name: "Config.FileListener", call: func() error { _, err := cfg.FileListener(os.Stdin); return err }},
		{name: "ListenEndpoint", call: func() error { _, err := ListenEndpoint("sctp", nil); return err }},
		{name: "Config.ListenEndpoint", call: func() error { _, err := cfg.ListenEndpoint("sctp", nil); return err }},
		{name: "OpenEndpoint", call: func() error { _, err := OpenEndpoint("sctp", nil); return err }},
		{name: "Config.OpenEndpoint", call: func() error { _, err := cfg.OpenEndpoint("sctp", nil); return err }},
		{name: "InstallAuthKey", call: func() error { return InstallAuthKey(nil, 1, []byte("k")) }},
		{name: "ActivateAuthKey", call: func() error { return ActivateAuthKey(nil, 1) }},
		{name: "Listener.Accept", call: func() error { _, err := l.Accept(); return err }},
		{name: "Listener.AcceptSCTP", call: func() error { _, err := l.AcceptSCTP(); return err }},
		{name: "Listener.Addr", value: true, call: func() error {
			if a := l.Addr(); a != nil {
				return zeroValueErr(a)
			}
			return nil
		}},
		{name: "Listener.Close", call: l.Close},
		{name: "Listener.SetDeadline", call: func() error { return l.SetDeadline(time.Now()) }},
		{name: "Listener.BindAdd", call: func() error { return l.BindAdd(ip) }},
		{name: "Listener.BindRemove", call: func() error { return l.BindRemove(ip) }},
		{name: "Listener.SyscallConn", call: func() error { _, err := l.SyscallConn(); return err }},
		{name: "Conn.AssocID", value: true, call: func() error {
			if id := c.AssocID(); id != 0 {
				return zeroValueErr(id)
			}
			return nil
		}},
		{name: "Conn.LocalAddr", value: true, call: func() error {
			if a := c.LocalAddr(); a != nil {
				return zeroValueErr(a)
			}
			return nil
		}},
		{name: "Conn.RemoteAddr", value: true, call: func() error {
			if a := c.RemoteAddr(); a != nil {
				return zeroValueErr(a)
			}
			return nil
		}},
		{name: "Conn.LocalAddrs", call: func() error { _, err := c.LocalAddrs(); return err }},
		{name: "Conn.PeerAddrs", call: func() error { _, err := c.PeerAddrs(); return err }},
		{name: "Conn.BindAdd", call: func() error { return c.BindAdd(ip) }},
		{name: "Conn.BindRemove", call: func() error { return c.BindRemove(ip) }},
		{name: "Conn.SetDeadline", call: func() error { return c.SetDeadline(time.Now()) }},
		{name: "Conn.SetReadDeadline", call: func() error { return c.SetReadDeadline(time.Now()) }},
		{name: "Conn.SetWriteDeadline", call: func() error { return c.SetWriteDeadline(time.Now()) }},
		{name: "Conn.SyscallConn", call: func() error { _, err := c.SyscallConn(); return err }},
		{name: "Conn.Close", call: c.Close},
		{name: "Conn.CloseWithTimeout", call: func() error { return c.CloseWithTimeout(time.Second) }},
		{name: "Conn.Shutdown", call: c.Shutdown},
		{name: "Conn.Abort", call: c.Abort},
		{name: "Conn.SendMsg", call: func() error { _, err := c.SendMsg([]byte("x"), SendOptions{}); return err }},
		{name: "Conn.Write", call: func() error { _, err := c.Write([]byte("x")); return err }},
		{name: "Conn.DefaultSndInfo", call: func() error { _, err := c.DefaultSndInfo(); return err }},
		{name: "Conn.SetDefaultSndInfo", call: func() error { return c.SetDefaultSndInfo(&SndInfo{}) }},
		{name: "Conn.DefaultPrInfo", call: func() error { _, err := c.DefaultPrInfo(); return err }},
		{name: "Conn.SetDefaultPrInfo", call: func() error { return c.SetDefaultPrInfo(&PrInfo{}) }},
		{name: "Conn.Read", call: func() error { _, err := c.Read(make([]byte, 1)); return err }},
		{name: "Conn.RecvMsg", call: func() error { _, _, err := c.RecvMsg(make([]byte, 1)); return err }},
		{name: "Conn.ReadMsg", call: func() error { _, _, err := c.ReadMsg(1); return err }},
		{name: "Conn.Subscribe", call: func() error { return c.Subscribe(EventShutdown, true) }},
		{name: "Conn.Subscribed", call: func() error { _, err := c.Subscribed(EventShutdown); return err }},
		{name: "Conn.ReadBuffer", call: func() error { _, err := c.ReadBuffer(); return err }},
		{name: "Conn.SetReadBuffer", call: func() error { return c.SetReadBuffer(4096) }},
		{name: "Conn.WriteBuffer", call: func() error { _, err := c.WriteBuffer(); return err }},
		{name: "Conn.SetWriteBuffer", call: func() error { return c.SetWriteBuffer(4096) }},
		{name: "Conn.PrimaryAddr", call: func() error { _, err := c.PrimaryAddr(); return err }},
		{name: "Conn.SetPrimaryAddr", call: func() error { return c.SetPrimaryAddr(ip) }},
		{name: "Conn.RequestPeerPrimary", call: func() error { return c.RequestPeerPrimary(ip) }},
		{name: "Conn.PathInfo", call: func() error { _, err := c.PathInfo(ip); return err }},
		{name: "Conn.PathParams", call: func() error { _, err := c.PathParams(ip); return err }},
		{name: "Conn.SetPathParams", call: func() error { return c.SetPathParams(ip, &PathParams{}) }},
		{name: "Conn.RequestHeartbeat", call: func() error { return c.RequestHeartbeat(ip) }},
		{name: "Conn.PathThresholds", call: func() error { _, err := c.PathThresholds(ip); return err }},
		{name: "Conn.SetPathThresholds", call: func() error { return c.SetPathThresholds(ip, &PathThresholds{}) }},
		{name: "Conn.PFExposure", call: func() error { _, err := c.PFExposure(); return err }},
		{name: "Conn.SetPFExposure", call: func() error { return c.SetPFExposure(PFExposeEnabled) }},
		{name: "Conn.AutoASCONF", call: func() error { _, err := c.AutoASCONF(); return err }},
		{name: "Conn.SetAutoASCONF", call: func() error { return c.SetAutoASCONF(true) }},
		{name: "Conn.RemoteUDPEncapsPort", call: func() error { _, err := c.RemoteUDPEncapsPort(ip); return err }},
		{name: "Conn.SetRemoteUDPEncapsPort", call: func() error { return c.SetRemoteUDPEncapsPort(ip, 9899) }},
		{name: "Conn.PLPMTUDProbeInterval", call: func() error { _, err := c.PLPMTUDProbeInterval(ip); return err }},
		{name: "Conn.SetPLPMTUDProbeInterval", call: func() error { return c.SetPLPMTUDProbeInterval(ip, 10*time.Second) }},
		{name: "Conn.Status", call: func() error { _, err := c.Status(); return err }},
		{name: "Conn.Stats", call: func() error { _, err := c.Stats(); return err }},
		{name: "Conn.AssocInfo", call: func() error { _, err := c.AssocInfo(); return err }},
		{name: "Conn.SetAssocInfo", call: func() error { return c.SetAssocInfo(&AssocInfo{}) }},
		{name: "Conn.RTOInfo", call: func() error { _, err := c.RTOInfo(); return err }},
		{name: "Conn.SetRTOInfo", call: func() error { return c.SetRTOInfo(&RTOInfo{}) }},
		{name: "Conn.InitMsg", call: func() error { _, err := c.InitMsg(); return err }},
		{name: "Conn.DelayedSACK", call: func() error { _, err := c.DelayedSACK(); return err }},
		{name: "Conn.SetDelayedSACK", call: func() error { return c.SetDelayedSACK(&DelayedSACK{}) }},
		{name: "Conn.AdaptationLayer", call: func() error { _, err := c.AdaptationLayer(); return err }},
		{name: "Conn.NoDelay", call: func() error { _, err := c.NoDelay(); return err }},
		{name: "Conn.SetNoDelay", call: func() error { return c.SetNoDelay(true) }},
		{name: "Conn.MaxSeg", call: func() error { _, err := c.MaxSeg(); return err }},
		{name: "Conn.SetMaxSeg", call: func() error { return c.SetMaxSeg(1200) }},
		{name: "Conn.MaxBurst", call: func() error { _, err := c.MaxBurst(); return err }},
		{name: "Conn.SetMaxBurst", call: func() error { return c.SetMaxBurst(4) }},
		{name: "Conn.FragmentsDisabled", call: func() error { _, err := c.FragmentsDisabled(); return err }},
		{name: "Conn.SetFragmentsDisabled", call: func() error { return c.SetFragmentsDisabled(true) }},
		{name: "Conn.FragmentInterleave", call: func() error { _, err := c.FragmentInterleave(); return err }},
		{name: "Conn.SetFragmentInterleave", call: func() error { return c.SetFragmentInterleave(InterleaveAssocs) }},
		{name: "Conn.PartialDeliveryPoint", call: func() error { _, err := c.PartialDeliveryPoint(); return err }},
		{name: "Conn.SetPartialDeliveryPoint", call: func() error { return c.SetPartialDeliveryPoint(4096) }},
		{name: "Conn.ReceiveNxtInfo", call: func() error { _, err := c.ReceiveNxtInfo(); return err }},
		{name: "Conn.SetReceiveNxtInfo", call: func() error { return c.SetReceiveNxtInfo(true) }},
		{name: "Conn.DefaultContext", call: func() error { _, err := c.DefaultContext(); return err }},
		{name: "Conn.SetDefaultContext", call: func() error { return c.SetDefaultContext(1) }},
		{name: "Conn.PRSupported", call: func() error { _, err := c.PRSupported(); return err }},
		{name: "Conn.ReconfigSupported", call: func() error { _, err := c.ReconfigSupported(); return err }},
		{name: "Conn.ASCONFSupported", call: func() error { _, err := c.ASCONFSupported(); return err }},
		{name: "Conn.AuthSupported", call: func() error { _, err := c.AuthSupported(); return err }},
		{name: "Conn.InterleavingSupported", call: func() error { _, err := c.InterleavingSupported(); return err }},
		{name: "Conn.ECNSupported", call: func() error { _, err := c.ECNSupported(); return err }},
		{name: "Conn.SetAuthKey", call: func() error { return c.SetAuthKey(1, []byte("key")) }},
		{name: "Conn.ActiveAuthKey", call: func() error { _, err := c.ActiveAuthKey(); return err }},
		{name: "Conn.SetActiveAuthKey", call: func() error { return c.SetActiveAuthKey(1) }},
		{name: "Conn.DeactivateAuthKey", call: func() error { return c.DeactivateAuthKey(1) }},
		{name: "Conn.DeleteAuthKey", call: func() error { return c.DeleteAuthKey(1) }},
		{name: "Conn.HMACIdentifiers", call: func() error { _, err := c.HMACIdentifiers(); return err }},
		{name: "Conn.LocalAuthChunks", call: func() error { _, err := c.LocalAuthChunks(); return err }},
		{name: "Conn.PeerAuthChunks", call: func() error { _, err := c.PeerAuthChunks(); return err }},
		{name: "Conn.StreamResetMask", call: func() error { _, err := c.StreamResetMask(); return err }},
		{name: "Conn.SetStreamResetMask", call: func() error { return c.SetStreamResetMask(EnableResetStreamReq) }},
		{name: "Conn.ResetStreams", call: func() error { return c.ResetStreams(ResetOutgoing, 1) }},
		{name: "Conn.ResetAssoc", call: func() error { return c.ResetAssoc() }},
		{name: "Conn.AddStreams", call: func() error { return c.AddStreams(1, 1) }},
		{name: "Conn.StreamScheduler", call: func() error { _, err := c.StreamScheduler(); return err }},
		{name: "Conn.SetStreamScheduler", call: func() error { return c.SetStreamScheduler(SchedPrio) }},
		{name: "Conn.StreamSchedulerValue", call: func() error { _, err := c.StreamSchedulerValue(1); return err }},
		{name: "Conn.SetStreamSchedulerValue", call: func() error { return c.SetStreamSchedulerValue(1, 7) }},
		{name: "Conn.PRStreamStatus", call: func() error { _, err := c.PRStreamStatus(1, PRTTL); return err }},
		{name: "Conn.PRAssocStatus", call: func() error { _, err := c.PRAssocStatus(PRTTL); return err }},
		{name: "Endpoint.Connect", call: func() error { _, err := e.Connect(raddr); return err }},
		{name: "Endpoint.SendMsg", call: func() error { _, err := e.SendMsg(3, []byte("x"), SendOptions{}); return err }},
		{name: "Endpoint.RecvMsg", call: func() error { _, _, err := e.RecvMsg(make([]byte, 1)); return err }},
		{name: "Endpoint.PeelOff", call: func() error { _, err := e.PeelOff(3); return err }},
		{name: "Endpoint.CloseAssoc", call: func() error { return e.CloseAssoc(3) }},
		{name: "Endpoint.AbortAssoc", call: func() error { return e.AbortAssoc(3, nil) }},
		{name: "Endpoint.AssocIDs", call: func() error { _, err := e.AssocIDs(); return err }},
		{name: "Endpoint.AssocCount", call: func() error { _, err := e.AssocCount(); return err }},
		{name: "Endpoint.LocalAddrs", call: func() error { _, err := e.LocalAddrs(3); return err }},
		{name: "Endpoint.PeerAddrs", call: func() error { _, err := e.PeerAddrs(3); return err }},
		{name: "Endpoint.AutoClose", call: func() error { _, err := e.AutoClose(); return err }},
		{name: "Endpoint.SetAutoClose", call: func() error { return e.SetAutoClose(time.Second) }},
		{name: "Endpoint.Addr", value: true, call: func() error {
			if a := e.Addr(); a != nil {
				return zeroValueErr(a)
			}
			return nil
		}},
		{name: "Endpoint.BindAdd", call: func() error { return e.BindAdd(ip) }},
		{name: "Endpoint.BindRemove", call: func() error { return e.BindRemove(ip) }},
		{name: "Endpoint.SetDeadline", call: func() error { return e.SetDeadline(time.Now()) }},
		{name: "Endpoint.SetReadDeadline", call: func() error { return e.SetReadDeadline(time.Now()) }},
		{name: "Endpoint.SetWriteDeadline", call: func() error { return e.SetWriteDeadline(time.Now()) }},
		{name: "Endpoint.Close", call: e.Close},
		{name: "Endpoint.Abort", call: e.Abort},
		{name: "Endpoint.SyscallConn", call: func() error { _, err := e.SyscallConn(); return err }},
	}
}

// TestUnsupportedConstructorsCheckConfigFirst: every constructor that takes
// a Config checks it as it would on Linux before it reports
// ErrUnsupported, so that a mistake in a Config is reported on every
// platform, as a refusal matching syscall.EINVAL that names the field, in
// the *net.OpError Linux reports it in, with the same Op, network and
// addresses; only a Config Linux would accept reaches ErrUnsupported (v1
// TestSocketConfigPreAssociationUnsupportedParity).
func TestUnsupportedConstructorsCheckConfigFirst(t *testing.T) {
	ctx := context.Background()
	laddr := &Addr{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.2")}, Port: 7}
	raddr := &Addr{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Port: 9}
	type call struct {
		run            func() error
		op, net        string
		source, remote string // the addresses the error names, "" for none
	}
	calls := func(cfg *Config) map[string]call {
		return map[string]call{
			"Dial":           {func() error { _, err := cfg.Dial(ctx, "sctp4", laddr, raddr); return err }, "dial", "sctp4", laddr.String(), raddr.String()},
			"Listen":         {func() error { _, err := cfg.Listen("", laddr); return err }, "listen", "sctp", "", laddr.String()},
			"ListenEndpoint": {func() error { _, err := cfg.ListenEndpoint("sctp6", laddr); return err }, "listen", "sctp6", "", laddr.String()},
			"OpenEndpoint":   {func() error { _, err := cfg.OpenEndpoint("sctp", nil); return err }, "listen", "sctp", "", ""},
		}
	}
	addrString := func(a net.Addr) string {
		if a == nil {
			return ""
		}
		return a.String()
	}
	valid := &Config{
		FragmentsDisabled:  new(true),
		FragmentInterleave: new(InterleaveAssocs),
		RTOInfo:            &RTOInfo{Initial: 500 * time.Millisecond, Max: 2 * time.Second, Min: 200 * time.Millisecond},
		DelayedSACK:        &DelayedSACK{Delay: 200 * time.Millisecond, Frequency: 2},
	}
	for name, c := range calls(valid) {
		err := c.run()
		if !errors.Is(err, ErrUnsupported) || !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("%s with a valid Config = %v, want ErrUnsupported", name, err)
		}
		// A valid Config still reaches ErrUnsupported, but the error it
		// gets there is the same *net.OpError shape as an invalid one
		// below, and the one Linux itself builds when socket(2) answers
		// EPROTONOSUPPORT or ESOCKTNOSUPPORT (socket_linux.go: openSocket,
		// socketError): every constructor's error is a *net.OpError on
		// every platform, never a bare sentinel on this one and a wrapped
		// one elsewhere.
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr.Op != c.op || opErr.Net != c.net || addrString(opErr.Source) != c.source || addrString(opErr.Addr) != c.remote {
			t.Errorf("%s with a valid Config = %#v, want a *net.OpError with Op %s, Net %s, Source %q and Addr %q", name, err, c.op, c.net, c.source, c.remote)
		}
	}
	invalid := &Config{DelayedSACK: &DelayedSACK{Delay: 501 * time.Millisecond}}
	for name, c := range calls(invalid) {
		err := c.run()
		if !errors.Is(err, syscall.EINVAL) || !strings.Contains(err.Error(), "Config.DelayedSACK.Delay") {
			t.Errorf("%s with an invalid Config = %v, want the refusal naming Config.DelayedSACK.Delay", name, err)
		}
		if errors.Is(err, ErrUnsupported) {
			t.Errorf("%s with an invalid Config reached ErrUnsupported: %v", name, err)
		}
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr.Op != c.op || opErr.Net != c.net || addrString(opErr.Source) != c.source || addrString(opErr.Addr) != c.remote {
			t.Errorf("%s with an invalid Config = %#v, want a *net.OpError with Op %s, Net %s, Source %q and Addr %q", name, err, c.op, c.net, c.source, c.remote)
		}
	}
	for name, run := range map[string]func() error{
		"FileConn":     func() error { _, err := (&Config{NoDelay: new(true)}).FileConn(os.Stdin); return err },
		"FileListener": func() error { _, err := (&Config{NoDelay: new(true)}).FileListener(os.Stdin); return err },
	} {
		err := run()
		if !errors.Is(err, syscall.EINVAL) || errors.Is(err, ErrUnsupported) {
			t.Errorf("%s with a Config it cannot take = %v, want the refusal matching EINVAL", name, err)
		}
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr.Op != "file" || opErr.Net != "sctp" {
			t.Errorf("%s with a Config it cannot take = %#v, want a *net.OpError with Op file", name, err)
		}
	}
	for name, run := range map[string]func() error{
		"FileConn":     func() error { _, err := new(Config).FileConn(os.Stdin); return err },
		"FileListener": func() error { _, err := new(Config).FileListener(os.Stdin); return err },
	} {
		err := run()
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s with a valid Config = %v, want ErrUnsupported", name, err)
		}
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr.Op != "file" || opErr.Net != "sctp" {
			t.Errorf("%s with a valid Config = %#v, want a *net.OpError with Op file", name, err)
		}
	}
}

// TestUnsupportedConstructorErrorsHaveOneShapeOnEveryPlatform is
// TestUnsupportedConstructorsCheckConfigFirst's property restated for the
// package-level constructors (a zero Config, called through Dial, Listen,
// ListenEndpoint, OpenEndpoint, FileConn and FileListener directly rather
// than through a *Config): the *net.OpError every one of them reports
// here is the same one Linux itself builds when socket(2) answers
// EPROTONOSUPPORT or ESOCKTNOSUPPORT (socket_linux.go: openSocket,
// socketError), so a caller's error-handling code, which never sees this
// platform at build time, sees one shape either way.
func TestUnsupportedConstructorErrorsHaveOneShapeOnEveryPlatform(t *testing.T) {
	ctx := context.Background()
	laddr := &Addr{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.2")}, Port: 7}
	raddr := &Addr{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Port: 9}
	addrString := func(a net.Addr) string {
		if a == nil {
			return ""
		}
		return a.String()
	}
	for name, tc := range map[string]struct {
		run            func() error
		op, net        string
		source, remote string
	}{
		"Dial":           {func() error { _, err := Dial(ctx, "sctp4", laddr, raddr); return err }, "dial", "sctp4", laddr.String(), raddr.String()},
		"Listen":         {func() error { _, err := Listen("", laddr); return err }, "listen", "sctp", "", laddr.String()},
		"ListenEndpoint": {func() error { _, err := ListenEndpoint("sctp6", laddr); return err }, "listen", "sctp6", "", laddr.String()},
		"OpenEndpoint":   {func() error { _, err := OpenEndpoint("sctp", nil); return err }, "listen", "sctp", "", ""},
		"FileConn":       {func() error { _, err := FileConn(os.Stdin); return err }, "file", "sctp", "", ""},
		"FileListener":   {func() error { _, err := FileListener(os.Stdin); return err }, "file", "sctp", "", ""},
	} {
		t.Run(name, func(t *testing.T) {
			e := tc.run()
			if !errors.Is(e, ErrUnsupported) {
				t.Fatalf("%s = %v, want ErrUnsupported", name, e)
			}
			var opErr *net.OpError
			if !errors.As(e, &opErr) || opErr.Op != tc.op || opErr.Net != tc.net || addrString(opErr.Source) != tc.source || addrString(opErr.Addr) != tc.remote {
				t.Errorf("%s = %#v, want a *net.OpError with Op %s, Net %s, Source %q and Addr %q", name, e, tc.op, tc.net, tc.source, tc.remote)
			}
		})
	}
}

// TestUnsupportedEntryPointsReportTheSentinel calls every case in
// unsupportedStubCases and requires it to return an error matching both
// ErrUnsupported and the standard library's errors.ErrUnsupported, rather
// than a bare nil a caller checking err would read as success. A value
// case must instead report nothing: its stub returned the zero value.
func TestUnsupportedEntryPointsReportTheSentinel(t *testing.T) {
	for _, tc := range unsupportedStubCases() {
		err := tc.call()
		if tc.value {
			if err != nil {
				t.Errorf("%s %v", tc.name, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s returned a nil error on a platform without SCTP; "+
				"a caller checking err then uses a nil result", tc.name)
			continue
		}
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("%s err = %v, want it to wrap errors.ErrUnsupported", tc.name, err)
		}
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s err = %v, want it to wrap sctp.ErrUnsupported", tc.name, err)
		}
	}
}

// TestUnsupportedStubManifestIsComplete parses unsupported.go and requires
// every function and method it declares to appear, by exactly one name, in
// unsupportedStubCases — so a stub added to that file without a
// corresponding case here fails this test instead of silently compiling
// with no runtime check that it actually reports ErrUnsupported.
//
// It reads the source with os.ReadFile("unsupported.go") — a path relative
// to the package directory, which "go test" guarantees as the working
// directory — rather than locating the file through runtime.Caller. A
// caller-derived path is the absolute build-time location the compiler
// embedded, which a binary built with -trimpath does not carry at all and
// a binary run from anywhere other than where it was built cannot resolve,
// either way failing this test over where its own source happens to sit
// rather than over anything the test is meant to check.
func TestUnsupportedStubManifestIsComplete(t *testing.T) {
	const stubFile = "unsupported.go"
	src, err := os.ReadFile(stubFile)
	if err != nil {
		t.Fatalf("read %s: %v", stubFile, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), stubFile, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", stubFile, err)
	}

	declared := make(map[string]struct{})
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fn.Name.Name
		if fn.Recv != nil {
			name = receiverTypeName(t, fn.Recv.List[0].Type) + "." + name
		}
		declared[name] = struct{}{}
	}

	covered := make(map[string]struct{})
	for _, tc := range unsupportedStubCases() {
		if _, duplicate := covered[tc.name]; duplicate {
			t.Fatalf("unsupported stub manifest contains duplicate %q", tc.name)
		}
		covered[tc.name] = struct{}{}
	}

	var missing, stale []string
	for name := range declared {
		if _, ok := covered[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range covered {
		if _, ok := declared[name]; !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) != 0 || len(stale) != 0 {
		t.Fatalf("unsupported stub manifest drift: missing=%v stale=%v", missing, stale)
	}
}

func receiverTypeName(t *testing.T, expr ast.Expr) string {
	t.Helper()
	switch expr := expr.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.StarExpr:
		return receiverTypeName(t, expr.X)
	default:
		t.Fatalf("unsupported receiver expression %T", expr)
		return ""
	}
}
