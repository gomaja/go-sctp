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

package sctp

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
)

// TestNilAddrString checks the defensive nil-receiver case: *Addr flows into
// net.OpError.Addr, a net.Addr interface field, and a nil *Addr wrapped in
// that interface is not itself a nil interface — net.OpError.Error() still
// calls its String(), so a real dereference here would panic on the exact
// path errors.go's opError builds.
func TestNilAddrString(t *testing.T) {
	var addr *Addr
	if got := addr.String(); got != "<nil>" {
		t.Fatalf("nil Addr.String() = %q, want <nil>", got)
	}
}

// TestAddrNetworkIsSCTP pins the constant net.Addr identifies this package
// with.
func TestAddrNetworkIsSCTP(t *testing.T) {
	a := &Addr{}
	if got := a.Network(); got != "sctp" {
		t.Errorf("Network() = %q, want sctp", got)
	}
}

// TestAddrStringEmptyIPsIsJustThePort covers the wildcard's rendering: a nil
// IPs list, matching every local address.
func TestAddrStringEmptyIPsIsJustThePort(t *testing.T) {
	a := &Addr{Port: 3868}
	if got, want := a.String(), ":3868"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// TestAddrStringFormsPinsExactly checks every documented rendering,
// including that IPv4 is never bracketed and IPv6 always is, with its zone
// carried along.
func TestAddrStringFormsPinsExactly(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr *Addr
		want string
	}{
		{"one IPv4", &Addr{IPs: []netip.Addr{netip.MustParseAddr("10.0.0.1")}, Port: 80}, "10.0.0.1:80"},
		{"two IPv4", &Addr{IPs: []netip.Addr{
			netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"),
		}, Port: 3868}, "10.0.0.1/10.0.0.2:3868"},
		{"IPv6 bracketed", &Addr{IPs: []netip.Addr{netip.MustParseAddr("::1")}, Port: 80}, "[::1]:80"},
		{"IPv6 with zone", &Addr{IPs: []netip.Addr{netip.MustParseAddr("fe80::1%eth0")}, Port: 3868}, "[fe80::1%eth0]:3868"},
		{"mixed", &Addr{IPs: []netip.Addr{
			netip.MustParseAddr("fe80::1%eth0"), netip.MustParseAddr("10.0.0.2"),
		}, Port: 3868}, "[fe80::1%eth0]/10.0.0.2:3868"},
		{"IPv4-mapped prints plain", &Addr{IPs: []netip.Addr{netip.MustParseAddr("::ffff:10.0.0.1")}, Port: 80}, "10.0.0.1:80"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.addr.String(); got != tc.want {
				t.Errorf("String() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestCanonicalNetworkFamilySelection pins the family canonicalNetwork picks
// for each network name and ip list shape.
func TestCanonicalNetworkFamilySelection(t *testing.T) {
	v4 := netip.MustParseAddr("10.0.0.1")
	v6 := netip.MustParseAddr("::1")

	for _, tc := range []struct {
		name       string
		network    string
		ips        []netip.Addr
		wantFamily int
	}{
		{"empty network, no ips", "", nil, afInet},
		{"sctp, no ips", "sctp", nil, afInet},
		{"sctp, all IPv4", "sctp", []netip.Addr{v4}, afInet},
		{"sctp, all IPv6", "sctp", []netip.Addr{v6}, afInet6},
		{"sctp, mixed", "sctp", []netip.Addr{v4, v6}, afInet6},
		{"sctp4, IPv4", "sctp4", []netip.Addr{v4}, afInet},
		{"sctp4, no ips", "sctp4", nil, afInet},
		{"sctp6, IPv4", "sctp6", []netip.Addr{v4}, afInet6},
		{"sctp6, IPv6", "sctp6", []netip.Addr{v6}, afInet6},
		{"sctp6, no ips", "sctp6", nil, afInet6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			family, err := canonicalNetwork(tc.network, tc.ips)
			if err != nil {
				t.Fatalf("canonicalNetwork(%q, %v): %v", tc.network, tc.ips, err)
			}
			if family != tc.wantFamily {
				t.Errorf("family = %d, want %d", family, tc.wantFamily)
			}
		})
	}
}

// TestCanonicalNetworkRejectsUnknownNames covers the validation every caller
// of the network string relies on.
func TestCanonicalNetworkRejectsUnknownNames(t *testing.T) {
	for _, network := range []string{"tcp", "sctp5", "SCTP", " sctp", "sctp "} {
		if _, err := canonicalNetwork(network, nil); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("canonicalNetwork(%q, nil) = %v, want an error matching EINVAL", network, err)
		}
	}
}

// TestCanonicalNetworkSCTP4RefusesIPv6 covers the family restriction that
// backs ResolveAddr's "sctp4 refuses an IPv6 literal" contract.
func TestCanonicalNetworkSCTP4RefusesIPv6(t *testing.T) {
	ips := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("::1")}
	if _, err := canonicalNetwork("sctp4", ips); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("canonicalNetwork(sctp4, [v4, v6]) = %v, want an error matching EINVAL", err)
	}
}

// TestResolveAddrAcceptsTheDocumentedForms covers the forms ResolveAddr's
// documentation promises, plus the multi-homed and zoned examples it gives.
func TestResolveAddrAcceptsTheDocumentedForms(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network string
		addr    string
		ips     []string
		port    uint16
	}{
		{"bare port is the wildcard", "sctp", ":80", nil, 80},
		{"two IPv4 addresses", "sctp", "10.0.0.1/10.0.0.2:3868",
			[]string{"10.0.0.1", "10.0.0.2"}, 3868},
		{"one address", "sctp", "127.0.0.1:80", []string{"127.0.0.1"}, 80},
		{"empty network means sctp", "", "127.0.0.1:80", []string{"127.0.0.1"}, 80},
		{"three addresses", "sctp", "127.0.0.1/127.0.0.2/127.0.0.3:9",
			[]string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}, 9},
		{"ipv6", "sctp6", "[::1]:80", []string{"::1"}, 80},
		{"two ipv6 addresses", "sctp6", "[::1]/[::1]:80", []string{"::1", "::1"}, 80},
		{"sctp6 accepts an IPv4 literal, reported plain", "sctp6", "10.0.0.1:80",
			[]string{"10.0.0.1"}, 80},
		{"an IPv4-mapped literal is unmapped to plain form", "sctp6", "[::ffff:10.0.0.1]:80",
			[]string{"10.0.0.1"}, 80},
		{"port zero", "sctp", "127.0.0.1:0", []string{"127.0.0.1"}, 0},
		{"port at the top of the range", "sctp", "127.0.0.1:65535", []string{"127.0.0.1"}, 65535},
		{"zoned IPv6 with a trailing IPv4", "sctp", "[fe80::1%eth0]/10.0.0.2:3868",
			[]string{"fe80::1%eth0", "10.0.0.2"}, 3868},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := ResolveAddr(tc.network, tc.addr)
			if err != nil {
				t.Fatalf("ResolveAddr(%q, %q): %v", tc.network, tc.addr, err)
			}
			if addr == nil {
				t.Fatal("ResolveAddr returned a nil *Addr with no error")
			}
			if addr.Port != tc.port {
				t.Errorf("port = %d, want %d", addr.Port, tc.port)
			}
			if len(addr.IPs) != len(tc.ips) {
				t.Fatalf("got %d addresses (%v), want %d (%v)", len(addr.IPs), addr.IPs, len(tc.ips), tc.ips)
			}
			for i, want := range tc.ips {
				wantIP, err := netip.ParseAddr(want)
				if err != nil {
					t.Fatalf("test case IP %q: %v", want, err)
				}
				if addr.IPs[i] != wantIP {
					t.Errorf("address %d = %s, want %s", i, addr.IPs[i], wantIP)
				}
				if addr.IPs[i].Is4In6() {
					t.Errorf("address %d = %s, is IPv4-mapped; every address this package returns must be plain", i, addr.IPs[i])
				}
			}
		})
	}
}

// TestResolveAddrStringRoundTrips checks that a resolved address prints back
// to what a caller would write for it.
func TestResolveAddrStringRoundTrips(t *testing.T) {
	for _, addr := range []string{
		":3868",
		"10.0.0.1/10.0.0.2:3868",
		"[fe80::1%eth0]/10.0.0.2:3868",
		"[::1]:80",
	} {
		a, err := ResolveAddr("sctp", addr)
		if err != nil {
			t.Fatalf("ResolveAddr(%q): %v", addr, err)
		}
		if got := a.String(); got != addr {
			t.Errorf("ResolveAddr(%q).String() = %q, want %q", addr, got, addr)
		}
	}
}

// TestResolveAddrResolvesHostNames covers the one host name the test suite
// can rely on existing and answering the same on every platform: localhost.
// A host name resolves to exactly one address — "sctp" the first IPv4
// answer if there is one, "sctp4"/"sctp6" that specific family — so each
// network is checked for its own single, unmapped, loopback result.
func TestResolveAddrResolvesHostNames(t *testing.T) {
	for _, tc := range []struct {
		network  string
		wantIs4  bool
		checkIs6 bool
	}{
		{"sctp", true, false},
		{"sctp4", true, false},
		{"sctp6", false, true},
	} {
		t.Run(tc.network, func(t *testing.T) {
			addr, err := ResolveAddr(tc.network, "localhost:1234")
			if err != nil {
				if tc.network == "sctp6" {
					t.Skipf("localhost has no IPv6 entry on this host: %v", err)
				}
				t.Fatalf("ResolveAddr(%q, localhost:1234): %v", tc.network, err)
			}
			if len(addr.IPs) != 1 {
				t.Fatalf("got %d addresses, want exactly 1 (a host name resolves to one address)", len(addr.IPs))
			}
			ip := addr.IPs[0]
			if addr.Port != 1234 {
				t.Errorf("port = %d, want 1234", addr.Port)
			}
			if !ip.IsLoopback() {
				t.Errorf("localhost resolved to %s, which is not a loopback address", ip)
			}
			if ip.Is4In6() {
				t.Errorf("localhost resolved to %s, which is IPv4-mapped; it must be plain", ip)
			}
			if tc.wantIs4 && !ip.Is4() {
				t.Errorf("network %q: localhost resolved to %s, want IPv4", tc.network, ip)
			}
			if tc.checkIs6 && ip.Is4() {
				t.Errorf("network %q: localhost resolved to %s, want IPv6", tc.network, ip)
			}
		})
	}
}

// TestResolveAddrRejectsMalformedInput covers the errors the parser gives
// for malformed input, and the three that must match syscall.EINVAL
// specifically: an out-of-range port, an empty host list and an empty port.
func TestResolveAddrRejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name       string
		network    string
		addr       string
		wantEINVAL bool
	}{
		{"port out of range", "sctp", "127.0.0.1:99999", true},
		{"service name instead of a numeric port", "sctp", "127.0.0.1:http", true},
		{"empty port", "sctp", "127.0.0.1:", true},
		{"no port at all", "sctp", "127.0.0.1", true},
		{"leading separator", "sctp", "/127.0.0.1:80", true},
		{"trailing separator before the port", "sctp", "1.2.3.4/5.6.7.8/:80", true},
		{"empty element in the middle", "sctp", "1.2.3.4//5.6.7.8:80", true},
		{"trailing separator with only two addresses", "sctp", "1.2.3.4/:80", true},
		{"sctp4 refuses an IPv6 literal", "sctp4", "[::1]:80", true},
		{"unknown network", "tcp", "127.0.0.1:80", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := ResolveAddr(tc.network, tc.addr)
			if err == nil {
				t.Fatalf("ResolveAddr(%q, %q) = %v with no error; it should be refused", tc.network, tc.addr, addr)
			}
			if tc.wantEINVAL && !errors.Is(err, syscall.EINVAL) {
				t.Errorf("error = %v, want it to match syscall.EINVAL", err)
			}
		})
	}
}

// TestResolveAddrMalformedPortMessage checks the exact text of the
// SplitHostPort wrap: net.SplitHostPort's own error already names the
// offending element ("address 127.0.0.1: missing port in address"), and
// ResolveAddr's wrap must not repeat that around it.
func TestResolveAddrMalformedPortMessage(t *testing.T) {
	_, err := ResolveAddr("sctp", "127.0.0.1")
	want := "sctp: address 127.0.0.1: missing port in address"
	if got := err.Error(); got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

// TestResolveAddrRejectsAHostThatDoesNotResolve covers the "not an address"
// case without touching a real resolver: net.DefaultResolver is swapped for
// one that always fails locally, so the assertion holds regardless of
// network access.
func TestResolveAddrRejectsAHostThatDoesNotResolve(t *testing.T) {
	previousResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("resolution disabled for this test")
		},
	}
	defer func() { net.DefaultResolver = previousResolver }()

	if addr, err := ResolveAddr("sctp", "not-a-real-host.invalid:80"); err == nil {
		t.Fatalf("ResolveAddr(not-a-real-host.invalid:80) = %v with no error", addr)
	}
}

// TestResolveAddrRejectsAZoneOnAMappedLiteral covers normalizeResolvedAddr's
// guard: unmapping a mapped literal must not silently discard a zone that
// makes no sense on it.
func TestResolveAddrRejectsAZoneOnAMappedLiteral(t *testing.T) {
	if _, err := ResolveAddr("sctp6", "[::ffff:10.0.0.1%eth0]:80"); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("ResolveAddr(mapped literal with a zone) = %v, want an error matching EINVAL", err)
	}
}

// TestResolveAddrNeverReturnsANilAddress states the invariant every rejected
// input above must not violate: a nil error never comes with a nil *Addr,
// or one with a nil netip.Addr among its IPs.
func TestResolveAddrNeverReturnsANilAddress(t *testing.T) {
	inputs := []string{
		":0", "127.0.0.1:0", "127.0.0.1/127.0.0.2:0",
		"1.2.3.4/5.6.7.8/:80", "/127.0.0.1:80", "//:80", "/:0",
	}
	for _, in := range inputs {
		addr, err := ResolveAddr("sctp", in)
		if err != nil {
			continue // refused, which is a fine answer
		}
		if addr == nil {
			t.Errorf("ResolveAddr(%q) returned a nil *Addr with no error", in)
			continue
		}
		for i, ip := range addr.IPs {
			if !ip.IsValid() {
				t.Errorf("ResolveAddr(%q) produced an invalid address at index %d", in, i)
			}
		}
	}
}

// TestZonedLinkLocalRoundTrip checks that a zoned link-local address
// survives ResolveAddr, encodeAddr, decodeAddr and String with its zone
// intact, using a real interface. It is skipped where that interface does
// not exist, with the reason.
func TestZonedLinkLocalRoundTrip(t *testing.T) {
	const zone = "zone0"
	if _, err := net.InterfaceByName(zone); err != nil {
		t.Skipf("no interface named %s on this host: %v", zone, err)
	}

	addr, err := ResolveAddr("sctp6", "[fe80::1%"+zone+"]:1234")
	if err != nil {
		t.Fatalf("ResolveAddr: %v", err)
	}
	if len(addr.IPs) != 1 {
		t.Fatalf("got %d addresses, want 1", len(addr.IPs))
	}

	buf := make([]byte, sizeSockaddrIn6)
	n, err := encodeAddr(buf, afInet6, addr.IPs[0], addr.Port)
	if err != nil {
		t.Fatalf("encodeAddr: %v", err)
	}
	if n != sizeSockaddrIn6 {
		t.Fatalf("encodeAddr wrote %d bytes, want %d", n, sizeSockaddrIn6)
	}

	ap, err := decodeAddr(buf[:n])
	if err != nil {
		t.Fatalf("decodeAddr: %v", err)
	}
	if ap.Addr().Zone() != zone {
		t.Errorf("decoded zone = %q, want %q", ap.Addr().Zone(), zone)
	}

	roundTripped := &Addr{IPs: []netip.Addr{ap.Addr()}, Port: ap.Port()}
	want := "[fe80::1%" + zone + "]:1234"
	if got := roundTripped.String(); got != want {
		t.Errorf("round-tripped String() = %q, want %q", got, want)
	}
}

// TestNumericZoneRoundTripsAsDecimal covers the numeric-zone case: a scope
// id with no live interface behind it renders back as the same decimal
// string it was given as, independent of what interfaces exist on the host
// running the test.
func TestNumericZoneRoundTripsAsDecimal(t *testing.T) {
	const zone = "4000000000" // an ifindex no real host assigns
	if _, err := net.InterfaceByName(zone); err == nil {
		t.Skipf("an interface is actually named %s on this host", zone)
	}

	addr, err := ResolveAddr("sctp6", "[fe80::1%"+zone+"]:80")
	if err != nil {
		t.Fatalf("ResolveAddr: %v", err)
	}

	buf := make([]byte, sizeSockaddrIn6)
	n, err := encodeAddr(buf, afInet6, addr.IPs[0], addr.Port)
	if err != nil {
		t.Fatalf("encodeAddr: %v", err)
	}
	ap, err := decodeAddr(buf[:n])
	if err != nil {
		t.Fatalf("decodeAddr: %v", err)
	}
	if got := ap.Addr().Zone(); got != zone {
		t.Errorf("decoded zone = %q, want %q", got, zone)
	}
}

// FuzzResolveAddr exercises the parser with arbitrary input. The property
// that matters is the one v1's equivalent fuzz target existed for: a
// successful parse must not silently produce something the input did not
// describe, and nothing may panic. addr.String() always renders numeric
// IPs, never a host name, regardless of whether addr.IPs came from a
// literal or (PreferGo still resolves "localhost" and any hosts-file entry
// without dialing anything, so the stubbed resolver below does not stop a
// host name from succeeding) a name lookup; feeding that numeric string
// back through ResolveAddr therefore always takes the literal path and
// must reproduce an equal *Addr.
func FuzzResolveAddr(f *testing.F) {
	// A fuzz byte stream must never become a real DNS query.
	previousResolver := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo:     true,
		StrictErrors: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("DNS is disabled while fuzzing SCTP addresses")
		},
	}
	f.Cleanup(func() { net.DefaultResolver = previousResolver })

	for _, seed := range []string{
		":0",
		"127.0.0.1:80",
		"127.0.0.1/127.0.0.2:80",
		"1.2.3.4/5.6.7.8/:80",
		"/127.0.0.1:80",
		"[::1]:80",
		"[::1]/[fe80::1%1]:80",
		"",
		":",
		"/",
		"::::",
		strings.Repeat("1.2.3.4/", 64) + "5.6.7.8:1",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, addrs string) {
		for _, network := range []string{"sctp", "sctp4", "sctp6"} {
			addr, err := ResolveAddr(network, addrs)
			if err != nil {
				if addr != nil {
					t.Errorf("ResolveAddr(%q, %q) returned both %v and %v", network, addrs, addr, err)
				}
				continue
			}
			if addr == nil {
				t.Fatalf("ResolveAddr(%q, %q) returned nil with no error", network, addrs)
			}
			for i, ip := range addr.IPs {
				if !ip.IsValid() {
					t.Errorf("ResolveAddr(%q, %q) produced an invalid address at %d", network, addrs, i)
				}
			}
			str := addr.String()
			again, err := ResolveAddr(network, str)
			if err != nil {
				t.Fatalf("ResolveAddr(%q, %q) = %v, but re-parsing its own String() %q failed: %v",
					network, addrs, addr, str, err)
			}
			if again.Port != addr.Port || len(again.IPs) != len(addr.IPs) {
				t.Fatalf("ResolveAddr(%q, %q) = %v does not round-trip through %q: got %v",
					network, addrs, addr, str, again)
			}
			for i := range addr.IPs {
				if again.IPs[i] != addr.IPs[i] {
					t.Fatalf("ResolveAddr(%q, %q) = %v does not round-trip through %q: got %v",
						network, addrs, addr, str, again)
				}
			}
		}
	})
}

// BenchmarkResolveAddr (v1 BenchmarkResolveSCTPAddr): resolving one
// address is the common case; a multi-homed literal is the other form
// ResolveAddr's own documentation names.
func BenchmarkResolveAddr(b *testing.B) {
	b.Run("single", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := ResolveAddr("sctp", "127.0.0.1:0"); err != nil {
				b.Fatalf("resolve: %v", err)
			}
		}
	})
	b.Run("multihomed", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := ResolveAddr("sctp", "127.0.0.1/127.0.0.2/127.0.0.3:0"); err != nil {
				b.Fatalf("resolve: %v", err)
			}
		}
	})
}
