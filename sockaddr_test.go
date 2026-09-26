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
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"runtime/debug"
	"syscall"
	"testing"
	"time"
)

// rawSockaddrIn builds a sockaddr_in byte for byte, independently of
// encodeAddr, so a test comparing against it catches a byte-order or
// field-offset mistake in encodeAddr rather than just checking encodeAddr
// against itself.
func rawSockaddrIn(ip netip.Addr, port uint16) []byte {
	b := make([]byte, sizeSockaddrIn)
	binary.NativeEndian.PutUint16(b[sockaddrInFamilyOff:], uint16(afInet))
	binary.BigEndian.PutUint16(b[sockaddrInPortOff:], port)
	v4 := ip.As4()
	copy(b[sockaddrInAddrOff:sockaddrInAddrOff+4], v4[:])
	return b
}

// rawSockaddrIn6 is rawSockaddrIn's AF_INET6 counterpart. ip is written
// through As16, so a plain IPv4 netip.Addr comes out IPv4-mapped, matching
// what a real sockaddr_in6 carries for one.
func rawSockaddrIn6(ip netip.Addr, port uint16, scope uint32) []byte {
	b := make([]byte, sizeSockaddrIn6)
	binary.NativeEndian.PutUint16(b[sockaddrIn6FamilyOff:], uint16(afInet6))
	binary.BigEndian.PutUint16(b[sockaddrIn6PortOff:], port)
	b16 := ip.As16()
	copy(b[sockaddrIn6AddrOff:sockaddrIn6AddrOff+16], b16[:])
	binary.NativeEndian.PutUint32(b[sockaddrIn6ScopeIDOff:], scope)
	return b
}

// TestEncodeAddrIPv4 pins the exact bytes an AF_INET encode produces.
func TestEncodeAddrIPv4(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")
	dst := make([]byte, sizeSockaddrIn)
	n, err := encodeAddr(dst, afInet, ip, 80)
	if err != nil {
		t.Fatalf("encodeAddr: %v", err)
	}
	if n != sizeSockaddrIn {
		t.Fatalf("wrote %d bytes, want %d", n, sizeSockaddrIn)
	}
	want := rawSockaddrIn(ip, 80)
	if string(dst) != string(want) {
		t.Errorf("bytes = % x, want % x", dst, want)
	}
	// Port 80 is 0x0050; network order puts the high byte first.
	if dst[sockaddrInPortOff] != 0x00 || dst[sockaddrInPortOff+1] != 0x50 {
		t.Errorf("port bytes = % x, want 00 50", dst[sockaddrInPortOff:sockaddrInPortOff+2])
	}
}

// TestEncodeAddrsIPv4OnAFInet6IsMapped is a worked example of the mapping
// rule: encodeAddrs(afInet6, [10.0.0.1], 80) is a 28 byte sockaddr_in6
// carrying ::ffff:10.0.0.1, with port bytes 00 50.
func TestEncodeAddrsIPv4OnAFInet6IsMapped(t *testing.T) {
	buf, err := encodeAddrs(afInet6, []netip.Addr{netip.MustParseAddr("10.0.0.1")}, 80)
	if err != nil {
		t.Fatalf("encodeAddrs: %v", err)
	}
	if len(buf) != sizeSockaddrIn6 {
		t.Fatalf("len = %d, want %d", len(buf), sizeSockaddrIn6)
	}
	mapped := netip.MustParseAddr("::ffff:10.0.0.1")
	if !mapped.Is4In6() {
		t.Fatalf("test setup: %s is not recognised as IPv4-mapped", mapped)
	}
	want := rawSockaddrIn6(mapped, 80, 0)
	if string(buf) != string(want) {
		t.Errorf("bytes = % x, want % x", buf, want)
	}
	if buf[sockaddrIn6PortOff] != 0x00 || buf[sockaddrIn6PortOff+1] != 0x50 {
		t.Errorf("port bytes = % x, want 00 50", buf[sockaddrIn6PortOff:sockaddrIn6PortOff+2])
	}
}

// TestEncodeAddrAFInetRejectsIPv6 covers the family mismatch encodeAddr must
// catch itself: nothing downstream reinterprets a 16-byte address as a
// 4-byte one.
func TestEncodeAddrAFInetRejectsIPv6(t *testing.T) {
	dst := make([]byte, sizeSockaddrIn)
	_, err := encodeAddr(dst, afInet, netip.MustParseAddr("::1"), 80)
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("encodeAddr(afInet, ::1) = %v, want an error matching EINVAL", err)
	}
}

// TestEncodeAddrRejectsUnknownFamily covers the family argument itself.
func TestEncodeAddrRejectsUnknownFamily(t *testing.T) {
	dst := make([]byte, sizeSockaddrIn6)
	_, err := encodeAddr(dst, 99, netip.MustParseAddr("10.0.0.1"), 80)
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("encodeAddr(family 99, ...) = %v, want an error matching EINVAL", err)
	}
}

// TestEncodeAddrRejectsTheZeroAddr covers the invalid, unconstructed
// netip.Addr{}.
func TestEncodeAddrRejectsTheZeroAddr(t *testing.T) {
	dst := make([]byte, sizeSockaddrIn6)
	_, err := encodeAddr(dst, afInet6, netip.Addr{}, 80)
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("encodeAddr(zero Addr) = %v, want an error matching EINVAL", err)
	}
}

// TestEncodeAddrRejectsUndersizedBuffer covers both families' size checks.
func TestEncodeAddrRejectsUndersizedBuffer(t *testing.T) {
	t.Run("afInet", func(t *testing.T) {
		dst := make([]byte, sizeSockaddrIn-1)
		if _, err := encodeAddr(dst, afInet, netip.MustParseAddr("10.0.0.1"), 80); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("error = %v, want an error matching EINVAL", err)
		}
	})
	t.Run("afInet6", func(t *testing.T) {
		dst := make([]byte, sizeSockaddrIn6-1)
		if _, err := encodeAddr(dst, afInet6, netip.MustParseAddr("::1"), 80); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("error = %v, want an error matching EINVAL", err)
		}
	})
}

// TestEncodeAddrRejectsZoneOnIPv4 covers both the ordinary AF_INET path and
// the pathological case of a 4-in-6 address (still "IPv4" once unmapped)
// carrying a zone under AF_INET6: netip.Addr structurally forbids a zone on
// its 4-byte form, but WithZone accepts one on any 16-byte form, mapped or
// not, so this is reachable.
func TestEncodeAddrRejectsZoneOnIPv4(t *testing.T) {
	t.Run("AF_INET", func(t *testing.T) {
		// A plain 4-byte netip.Addr cannot itself carry a zone, so this
		// drives the same 4-in-6-with-a-zone value AF_INET6's subtest uses,
		// but for family afInet: unmapped.Is4() is true either way, and the
		// AF_INET branch's own zone check must catch it directly rather
		// than relying on AF_INET6's link-local check, which this family
		// never reaches.
		zoned := netip.MustParseAddr("::ffff:10.0.0.1").WithZone("eth0")
		if zoned.Zone() != "eth0" {
			t.Fatal("test setup: WithZone did not attach a zone")
		}
		dst := make([]byte, sizeSockaddrIn)
		_, err := encodeAddr(dst, afInet, zoned, 80)
		if !errors.Is(err, syscall.EINVAL) {
			t.Errorf("encodeAddr(afInet, zoned address) = %v, want an error matching EINVAL", err)
		}
	})
	t.Run("AF_INET6, mapped address with a zone", func(t *testing.T) {
		mapped := netip.MustParseAddr("::ffff:10.0.0.1").WithZone("eth0")
		if mapped.Zone() != "eth0" {
			t.Fatal("test setup: WithZone did not attach a zone to a mapped address")
		}
		dst := make([]byte, sizeSockaddrIn6)
		_, err := encodeAddr(dst, afInet6, mapped, 80)
		if !errors.Is(err, syscall.EINVAL) {
			t.Errorf("encodeAddr(mapped address with a zone) = %v, want an error matching EINVAL", err)
		}
	})
}

// TestEncodeAddrRejectsNonLinkLocalZone covers the scope restriction: a zone
// is only meaningful on a link-local unicast address, so one on a global
// address is refused. The zone names a real interface on the test host —
// not one guaranteed absent, like "eth0" — so this fails for the intended
// reason (not link-local) rather than incidentally succeeding to find an
// unknown-interface error that would pass even without the link-local
// check.
func TestEncodeAddrRejectsNonLinkLocalZone(t *testing.T) {
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) == 0 {
		t.Skip("no network interfaces available on this host")
	}
	name := ifs[0].Name

	dst := make([]byte, sizeSockaddrIn6)
	_, err = encodeAddr(dst, afInet6, netip.MustParseAddr("2001:db8::1%"+name), 80)
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("encodeAddr(global address with a zone) = %v, want an error matching EINVAL", err)
	}
}

// TestEncodeAddrRejectsUnknownZone covers a zone that names no interface at
// all, on an address that does clear the link-local check.
func TestEncodeAddrRejectsUnknownZone(t *testing.T) {
	const bogus = "sctp-test-interface-that-does-not-exist"
	if _, err := net.InterfaceByName(bogus); err == nil {
		t.Skipf("an interface is actually named %s on this host", bogus)
	}
	dst := make([]byte, sizeSockaddrIn6)
	_, err := encodeAddr(dst, afInet6, netip.MustParseAddr("fe80::1%"+bogus), 80)
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("encodeAddr(unknown zone) = %v, want an error matching EINVAL", err)
	}
}

// TestEncodeAddrZoneResolvesViaInterfaceByName checks the scope id encodeAddr
// writes for a named zone against net.InterfaceByName directly, using
// whatever real interface the test host happens to have.
func TestEncodeAddrZoneResolvesViaInterfaceByName(t *testing.T) {
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) == 0 {
		t.Skip("no network interfaces available on this host")
	}
	name := ifs[0].Name
	wantIdx, err := net.InterfaceByName(name)
	if err != nil {
		t.Fatalf("net.InterfaceByName(%q): %v", name, err)
	}

	dst := make([]byte, sizeSockaddrIn6)
	if _, err := encodeAddr(dst, afInet6, netip.MustParseAddr("fe80::1%"+name), 80); err != nil {
		t.Fatalf("encodeAddr: %v", err)
	}
	got := binary.NativeEndian.Uint32(dst[sockaddrIn6ScopeIDOff:])
	if got != uint32(wantIdx.Index) {
		t.Errorf("sin6_scope_id = %d, want %d (the index of %s)", got, wantIdx.Index, name)
	}
}

// TestEncodeAddrsPacksEveryEntry checks the multi-address form lays entries
// back to back with no gap and no shared state between them.
func TestEncodeAddrsPacksEveryEntry(t *testing.T) {
	ips := []netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("192.0.2.2"),
		netip.MustParseAddr("192.0.2.3"),
	}
	buf, err := encodeAddrs(afInet, ips, 3868)
	if err != nil {
		t.Fatalf("encodeAddrs: %v", err)
	}
	if len(buf) != len(ips)*sizeSockaddrIn {
		t.Fatalf("len = %d, want %d", len(buf), len(ips)*sizeSockaddrIn)
	}
	for i, ip := range ips {
		entry := buf[i*sizeSockaddrIn : (i+1)*sizeSockaddrIn]
		if want := rawSockaddrIn(ip, 3868); string(entry) != string(want) {
			t.Errorf("entry %d = % x, want % x", i, entry, want)
		}
	}
}

// TestEncodeAddrsEmptyIsEmptyBuffer covers the wildcard-bind shape: no
// addresses packs to no bytes, not an error and not a nil-vs-empty surprise.
func TestEncodeAddrsEmptyIsEmptyBuffer(t *testing.T) {
	buf, err := encodeAddrs(afInet, nil, 80)
	if err != nil {
		t.Fatalf("encodeAddrs(nil ips): %v", err)
	}
	if len(buf) != 0 {
		t.Errorf("len = %d, want 0", len(buf))
	}
}

// TestEncodeAddrsRejectsUnknownFamily covers the family check running even
// when there is nothing to pack.
func TestEncodeAddrsRejectsUnknownFamily(t *testing.T) {
	if _, err := encodeAddrs(99, nil, 80); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("encodeAddrs(family 99, nil, ...) = %v, want an error matching EINVAL", err)
	}
}

// TestEncodeAddrsStopsAtTheFirstBadEntry checks a later, invalid entry does
// not silently get skipped in favor of the valid ones before it, and that
// the error names which entry failed.
func TestEncodeAddrsStopsAtTheFirstBadEntry(t *testing.T) {
	ips := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("::1")}
	_, err := encodeAddrs(afInet, ips, 80)
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("encodeAddrs with an IPv6 entry for afInet = %v, want an error matching EINVAL", err)
	}
	// Exact message: encodeAddr's own "sctp: " prefix must not be repeated
	// inside encodeAddrs's "address %d: " wrap.
	want := "sctp: address 1: address ::1 is not IPv4 for an AF_INET socket"
	if got := err.Error(); got != want {
		t.Errorf("error = %q, want %q", got, want)
	}
}

// TestDecodeAddrDecodesBothFamilies covers decodeAddr's use on a single
// sockaddr, such as msg_name: an AF_INET entry decodes as is, and an
// IPv4-mapped AF_INET6 entry unmaps to the same plain form.
func TestDecodeAddrDecodesBothFamilies(t *testing.T) {
	t.Run("AF_INET", func(t *testing.T) {
		ip := netip.MustParseAddr("203.0.113.5")
		ap, err := decodeAddr(rawSockaddrIn(ip, 3868))
		if err != nil {
			t.Fatalf("decodeAddr: %v", err)
		}
		if ap.Addr() != ip || ap.Port() != 3868 {
			t.Errorf("decodeAddr = %s, want %s:3868", ap, ip)
		}
	})
	t.Run("AF_INET6 mapped", func(t *testing.T) {
		ip := netip.MustParseAddr("203.0.113.6")
		ap, err := decodeAddr(rawSockaddrIn6(ip, 3868, 0))
		if err != nil {
			t.Fatalf("decodeAddr: %v", err)
		}
		if ap.Addr() != ip || ap.Port() != 3868 {
			t.Errorf("decodeAddr = %s, want %s:3868 (plain, not mapped)", ap, ip)
		}
		if !ap.Addr().Is4() {
			t.Errorf("decoded address %s is not Is4() after unmapping", ap.Addr())
		}
	})
	t.Run("AF_INET6 genuine", func(t *testing.T) {
		ip := netip.MustParseAddr("2001:db8::1")
		ap, err := decodeAddr(rawSockaddrIn6(ip, 80, 0))
		if err != nil {
			t.Fatalf("decodeAddr: %v", err)
		}
		if ap.Addr() != ip || ap.Port() != 80 {
			t.Errorf("decodeAddr = %s, want %s:80", ap, ip)
		}
	})
}

// TestDecodeAddrsScopeIDIgnoredExceptOnLinkLocal is the critical case: Linux
// sets sin6_scope_id to the reporting or receiving interface's index for
// every IPv6 address SCTP_GET_LOCAL_ADDRS and SCTP_GET_PEER_ADDRS hand back,
// not only link-local ones (net/sctp/ipv6.c: sctp_v6_copy_addrlist and
// sctp_v6_from_addr_param, decodeSockaddrEntry's comment). A live kernel
// therefore returns ::1 with scope 1, and any global address with whatever
// interface last saw it — neither of which is a real zone, and attaching
// one would make the decoded address compare unequal to the same address
// with no zone, and print with a "%1" or "%eth0" that means nothing.
func TestDecodeAddrsScopeIDIgnoredExceptOnLinkLocal(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ip    netip.Addr
		scope uint32
	}{
		{"loopback with scope 1", netip.MustParseAddr("::1"), 1},
		{"global unicast with scope 5", netip.MustParseAddr("2001:db8::1"), 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ap, err := decodeAddr(rawSockaddrIn6(tc.ip, 80, tc.scope))
			if err != nil {
				t.Fatalf("decodeAddr: %v", err)
			}
			if got := ap.Addr(); got.Zone() != "" {
				t.Errorf("decoded %s from scope id %d with zone %q, want no zone",
					got, tc.scope, got.Zone())
			}
			if ap.Addr() != tc.ip {
				t.Errorf("decoded address = %s, want %s", ap.Addr(), tc.ip)
			}

			// Also through decodeAddrs, which shares decodeSockaddrEntry.
			ips, _, err := decodeAddrs(rawSockaddrIn6(tc.ip, 80, tc.scope), 1)
			if err != nil {
				t.Fatalf("decodeAddrs: %v", err)
			}
			if ips[0].Zone() != "" {
				t.Errorf("decodeAddrs: decoded %s from scope id %d with zone %q, want no zone",
					ips[0], tc.scope, ips[0].Zone())
			}
		})
	}
}

// TestDecodeThenEncodeAFInet6RoundTrips checks that whatever decodeAddr
// accepts, encodeAddr can encode straight back to the same bytes — the
// property FuzzDecodeAddrs also drives — for a spread of shapes: plain
// AF_INET6, a mapped address, a loopback with a spurious scope id, and a
// genuine link-local zone.
func TestDecodeThenEncodeAFInet6RoundTrips(t *testing.T) {
	ifs, _ := net.Interfaces()
	var ifaceName string
	for _, ifi := range ifs {
		if ifi.Index > 0 {
			ifaceName = ifi.Name
			break
		}
	}

	cases := []struct {
		name  string
		ip    netip.Addr
		scope uint32
	}{
		{"genuine IPv6", netip.MustParseAddr("2001:db8::1"), 0},
		{"mapped IPv4", netip.MustParseAddr("10.0.0.1"), 0},
		{"loopback with a spurious scope id", netip.MustParseAddr("::1"), 7},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := rawSockaddrIn6(tc.ip, 3868, tc.scope)
			ap, err := decodeAddr(original)
			if err != nil {
				t.Fatalf("decodeAddr: %v", err)
			}
			dst := make([]byte, sizeSockaddrIn6)
			n, err := encodeAddr(dst, afInet6, ap.Addr(), ap.Port())
			if err != nil {
				t.Fatalf("encodeAddr: %v", err)
			}
			// The re-encode need not reproduce a spurious, discarded scope
			// id, so compare against the same input with scope zeroed.
			want := rawSockaddrIn6(tc.ip, 3868, 0)
			if string(dst[:n]) != string(want) {
				t.Errorf("round trip: decodeAddr(% x) -> encodeAddr = % x, want % x", original, dst[:n], want)
			}
		})
	}

	if ifaceName == "" {
		t.Skip("no network interfaces available on this host for the zoned case")
	}
	t.Run("link-local with a zone", func(t *testing.T) {
		ifi, err := net.InterfaceByName(ifaceName)
		if err != nil {
			t.Fatalf("net.InterfaceByName(%q): %v", ifaceName, err)
		}
		original := rawSockaddrIn6(netip.MustParseAddr("fe80::1"), 3868, uint32(ifi.Index))
		ap, err := decodeAddr(original)
		if err != nil {
			t.Fatalf("decodeAddr: %v", err)
		}
		if ap.Addr().Zone() != ifaceName {
			t.Fatalf("decoded zone = %q, want %q", ap.Addr().Zone(), ifaceName)
		}
		dst := make([]byte, sizeSockaddrIn6)
		n, err := encodeAddr(dst, afInet6, ap.Addr(), ap.Port())
		if err != nil {
			t.Fatalf("encodeAddr: %v", err)
		}
		if string(dst[:n]) != string(original) {
			t.Errorf("round trip: decodeAddr(% x) -> encodeAddr = % x, want % x", original, dst[:n], original)
		}
	})
}

// TestEncodeZoneRefusesScopeZero covers the kernel rule encodeZone
// enforces: Linux refuses to bind to, or connect or send to, a link-local
// address with scope id 0 (sctp_inet6_bind_verify, sctp_inet6_send_verify),
// so an explicit zone of "0" must not silently become that.
func TestEncodeZoneRefusesScopeZero(t *testing.T) {
	dst := make([]byte, sizeSockaddrIn6)
	_, err := encodeAddr(dst, afInet6, netip.MustParseAddr("fe80::1%0"), 80)
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("encodeAddr(zone \"0\") = %v, want an error matching EINVAL", err)
	}
}

// TestEncodeZonePrefersInterfaceName covers the resolution order: the
// interface name is tried before the decimal form, the same order net's own
// zoneCache.index uses (net/interface.go) — the opposite of v1's zoneID,
// which tried the decimal form first. An interface literally named after a
// number is not something the test can fabricate, but a name that exists
// must still resolve correctly on the path that tries it first, so this
// pins basic correctness of that path using a name that plainly is not a
// number; TestNumericZoneRoundTripsAsDecimal (addr_test.go) already covers
// that a numeric zone still works when no such interface exists.
func TestEncodeZonePrefersInterfaceName(t *testing.T) {
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) == 0 {
		t.Skip("no network interfaces available on this host")
	}
	name := ifs[0].Name
	dst := make([]byte, sizeSockaddrIn6)
	if _, err := encodeAddr(dst, afInet6, netip.MustParseAddr("fe80::1%"+name), 80); err != nil {
		t.Fatalf("encodeAddr: %v", err)
	}
}

// TestEncodeAddrIPv4WildcardOnAFInet6IsIPv6Wildcard covers the dual-stack
// wildcard rule: 0.0.0.0 encoded for an AF_INET6 socket is ::, not
// ::ffff:0.0.0.0, matching net.ListenTCP("tcp", ...) and v1's own
// ipToSockaddr.
func TestEncodeAddrIPv4WildcardOnAFInet6IsIPv6Wildcard(t *testing.T) {
	dst := make([]byte, sizeSockaddrIn6)
	n, err := encodeAddr(dst, afInet6, netip.IPv4Unspecified(), 80)
	if err != nil {
		t.Fatalf("encodeAddr: %v", err)
	}
	ap, err := decodeAddr(dst[:n])
	if err != nil {
		t.Fatalf("decodeAddr: %v", err)
	}
	if want := netip.IPv6Unspecified(); ap.Addr() != want {
		t.Errorf("decoded address = %s, want %s (the IPv6 wildcard, not ::ffff:0.0.0.0)", ap.Addr(), want)
	}
}

// TestDecodeAddrRejectsUnknownFamily and TestDecodeAddrRejectsShortBuffer
// cover decodeAddr's use of the same bounds and family checks decodeAddrs
// uses per entry.
func TestDecodeAddrRejectsUnknownFamily(t *testing.T) {
	b := make([]byte, sizeSockaddrIn6)
	binary.NativeEndian.PutUint16(b[sockaddrIn6FamilyOff:], syscall.AF_UNIX)
	if _, err := decodeAddr(b); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("decodeAddr(AF_UNIX) = %v, want an error matching EINVAL", err)
	}
}

func TestDecodeAddrRejectsShortBuffer(t *testing.T) {
	if _, err := decodeAddr(make([]byte, 1)); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("decodeAddr(1 byte) = %v, want an error matching EINVAL", err)
	}
	// The family is readable but the full AF_INET6 entry is not.
	b := rawSockaddrIn6(netip.MustParseAddr("::1"), 80, 0)
	if _, err := decodeAddr(b[:sizeSockaddrIn6-1]); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("decodeAddr(truncated sockaddr_in6) = %v, want an error matching EINVAL", err)
	}
}

// TestDecodeAddrsMixedFamilies is the case v1's per-entry-stride fix exists
// for: a reply whose entries are not all the same size must still be walked
// correctly, whichever family comes first.
func TestDecodeAddrsMixedFamilies(t *testing.T) {
	v4 := netip.MustParseAddr("192.0.2.10")
	v6 := netip.MustParseAddr("2001:db8::1")

	t.Run("v4 first", func(t *testing.T) {
		buf := append(rawSockaddrIn(v4, 3868), rawSockaddrIn6(v6, 3868, 0)...)
		ips, port, err := decodeAddrs(buf, 2)
		if err != nil {
			t.Fatalf("decodeAddrs: %v", err)
		}
		if port != 3868 {
			t.Errorf("port = %d, want 3868", port)
		}
		if len(ips) != 2 || ips[0] != v4 || ips[1] != v6 {
			t.Errorf("ips = %v, want [%s %s]", ips, v4, v6)
		}
	})

	t.Run("v6 first", func(t *testing.T) {
		buf := append(rawSockaddrIn6(v6, 2905, 0), rawSockaddrIn(v4, 2905)...)
		ips, port, err := decodeAddrs(buf, 2)
		if err != nil {
			t.Fatalf("decodeAddrs: %v", err)
		}
		if port != 2905 {
			t.Errorf("port = %d, want 2905", port)
		}
		if len(ips) != 2 || ips[0] != v6 || ips[1] != v4 {
			t.Errorf("ips = %v, want [%s %s]", ips, v6, v4)
		}
	})
}

// TestDecodeAddrsUnmapsIPv4 covers the AF_INET6-mapped entries alongside
// plain AF_INET ones in a single reply.
func TestDecodeAddrsUnmapsIPv4(t *testing.T) {
	plain := netip.MustParseAddr("10.0.0.1")
	mapped := netip.MustParseAddr("10.0.0.2")
	buf := append(rawSockaddrIn(plain, 80), rawSockaddrIn6(mapped, 80, 0)...)

	ips, _, err := decodeAddrs(buf, 2)
	if err != nil {
		t.Fatalf("decodeAddrs: %v", err)
	}
	for i, ip := range ips {
		if !ip.Is4() {
			t.Errorf("ips[%d] = %s, want plain IPv4", i, ip)
		}
	}
	if ips[0] != plain || ips[1] != mapped {
		t.Errorf("ips = %v, want [%s %s]", ips, plain, mapped)
	}
}

// TestDecodeAddrsPortFromFirstEntryOnly covers both directions of the rule:
// the port comes from the first entry, and a different value on a later one
// is ignored rather than overriding it.
func TestDecodeAddrsPortFromFirstEntryOnly(t *testing.T) {
	buf := append(
		rawSockaddrIn(netip.MustParseAddr("192.0.2.1"), 3868),
		rawSockaddrIn(netip.MustParseAddr("192.0.2.2"), 9999)...,
	)
	_, port, err := decodeAddrs(buf, 2)
	if err != nil {
		t.Fatalf("decodeAddrs: %v", err)
	}
	if port != 3868 {
		t.Errorf("port = %d, want 3868 from the first entry", port)
	}
}

// TestDecodeAddrsZeroCount checks the empty reply: no allocation-worthy work
// and a nil, not merely empty-length, result.
func TestDecodeAddrsZeroCount(t *testing.T) {
	ips, port, err := decodeAddrs(make([]byte, 64), 0)
	if err != nil {
		t.Fatalf("decodeAddrs(n=0): %v", err)
	}
	if ips != nil {
		t.Errorf("ips = %v, want nil", ips)
	}
	if port != 0 {
		t.Errorf("port = %d, want 0", port)
	}
}

// TestDecodeAddrsNegativeCount checks a negative count is rejected rather
// than used: it can reach decodeAddrs as an int converted from a kernel
// uint32, so a reply claiming more than 2^31 addresses arrives negative.
func TestDecodeAddrsNegativeCount(t *testing.T) {
	if _, _, err := decodeAddrs(make([]byte, 64), -1); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("decodeAddrs(n=-1) = %v, want an error matching EINVAL", err)
	}
}

// TestDecodeAddrsRejectsUnknownFamily covers a family byte the package does
// not decode.
func TestDecodeAddrsRejectsUnknownFamily(t *testing.T) {
	b := make([]byte, sizeSockaddrIn)
	binary.NativeEndian.PutUint16(b[sockaddrInFamilyOff:], syscall.AF_UNIX)
	if _, _, err := decodeAddrs(b, 1); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("decodeAddrs(AF_UNIX) = %v, want an error matching EINVAL", err)
	}
}

// TestDecodeAddrsRejectsTruncatedEntries covers three ways an entry can run
// past the end of b: the family itself unreadable, an AF_INET entry cut
// short, and an AF_INET6 entry cut short.
func TestDecodeAddrsRejectsTruncatedEntries(t *testing.T) {
	t.Run("family unreadable", func(t *testing.T) {
		if _, _, err := decodeAddrs(make([]byte, 1), 1); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("error = %v, want an error matching EINVAL", err)
		}
	})
	t.Run("AF_INET entry cut short", func(t *testing.T) {
		b := rawSockaddrIn(netip.MustParseAddr("10.0.0.1"), 80)
		if _, _, err := decodeAddrs(b[:sizeSockaddrIn-1], 1); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("error = %v, want an error matching EINVAL", err)
		}
	})
	t.Run("AF_INET6 entry cut short", func(t *testing.T) {
		b := rawSockaddrIn6(netip.MustParseAddr("::1"), 80, 0)
		if _, _, err := decodeAddrs(b[:sizeSockaddrIn6-1], 1); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("error = %v, want an error matching EINVAL", err)
		}
	})
	t.Run("second entry runs past the end", func(t *testing.T) {
		one := rawSockaddrIn(netip.MustParseAddr("192.0.2.1"), 3868)
		two := rawSockaddrIn(netip.MustParseAddr("192.0.2.2"), 3868)
		buf := append(one, two...)
		// Bound the buffer one byte short of the second entry's end.
		if _, _, err := decodeAddrs(buf[:len(buf)-1], 2); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("error = %v, want an error matching EINVAL", err)
		}
	})
}

// TestDecodeAddrsRejectsImpossibleCount checks the count is bounded by what
// the buffer could hold, at the smallest possible entry size, before it is
// used to size an allocation: a corrupt or hostile n must not itself drive
// an allocation proportional to n.
func TestDecodeAddrsRejectsImpossibleCount(t *testing.T) {
	buf := make([]byte, 4096)
	// 4096 / 16 = 256; 257 cannot fit even if every entry were the smallest
	// possible (AF_INET) size.
	if _, _, err := decodeAddrs(buf, 257); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("decodeAddrs(257 addresses in 4096 bytes) = %v, want an error matching EINVAL", err)
	}
	// The honest boundary still works structurally (each entry must still be
	// real AF_INET bytes to succeed; this checks the count check alone does
	// not itself reject 256).
	ips := make([]byte, 0, 256*sizeSockaddrIn)
	for i := range 256 {
		ips = append(ips, rawSockaddrIn(netip.MustParseAddr("192.0.2.1"), uint16(i))...)
	}
	if _, _, err := decodeAddrs(ips, 256); err != nil {
		t.Errorf("decodeAddrs(256 addresses in a 256-entry buffer): %v", err)
	}
}

// TestDecodeAddrsAllocatesNothingOnError pins the hardening decodeAddrs
// documents: a truncated buffer, an unknown family and a count too large for
// the buffer must each be rejected before decodeAddrs allocates anything
// sized by n. Skipped under the race detector, whose own instrumentation
// allocates and would move every count.
func TestDecodeAddrsAllocatesNothingOnError(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector")
	}
	// A GC triggered mid-measurement allocates on its own account, which
	// testing.AllocsPerRun would count against decodeAddrs.
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	unknownFamily := make([]byte, sizeSockaddrIn)
	binary.NativeEndian.PutUint16(unknownFamily[sockaddrInFamilyOff:], syscall.AF_UNIX)

	truncated := rawSockaddrIn(netip.MustParseAddr("10.0.0.1"), 80)[:sizeSockaddrIn-1]

	tooLarge := make([]byte, 64) // 64/16 = 4 possible entries at most

	for _, tc := range []struct {
		name string
		b    []byte
		n    int
	}{
		{"unknown family", unknownFamily, 1},
		{"truncated entry", truncated, 1},
		{"count too large for the buffer", tooLarge, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			allocs := testing.AllocsPerRun(100, func() {
				if _, _, err := decodeAddrs(tc.b, tc.n); err == nil {
					t.Fatal("expected an error")
				}
			})
			if allocs != 0 {
				t.Errorf("decodeAddrs allocated %.1f times on the error path, want 0", allocs)
			}
		})
	}
}

// TestZoneNameEmptyForScopeZero covers the "no zone" case.
func TestZoneNameEmptyForScopeZero(t *testing.T) {
	if got := zoneName(0); got != "" {
		t.Errorf("zoneName(0) = %q, want empty", got)
	}
}

// TestZoneNameResolvesRealInterfaces checks zoneName against
// net.InterfaceByIndex directly, for whatever real interfaces this host
// has.
func TestZoneNameResolvesRealInterfaces(t *testing.T) {
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) == 0 {
		t.Skip("no network interfaces available on this host")
	}
	for _, ifi := range ifs {
		if ifi.Index <= 0 {
			continue
		}
		if got := zoneName(uint32(ifi.Index)); got != ifi.Name {
			t.Errorf("zoneName(%d) = %q, want %q", ifi.Index, got, ifi.Name)
		}
	}
}

// TestZoneNameFallsBackToDecimal covers an index with no interface behind
// it: an ifindex no real host assigns. The value is kept within int32's
// range (unlike the huge one addr_test.go's numeric-zone round trip uses,
// which only ever reaches zoneName as a uint32 read from the wire) because
// it is passed to net.InterfaceByIndex, an int parameter, and this test
// must still compile as a constant expression under GOARCH=386.
func TestZoneNameFallsBackToDecimal(t *testing.T) {
	const idx = 2000000000
	if _, err := net.InterfaceByIndex(idx); err == nil {
		t.Skipf("an interface is actually at index %d on this host", idx)
	}
	if got, want := zoneName(idx), "2000000000"; got != want {
		t.Errorf("zoneName(%d) = %q, want %q", idx, got, want)
	}
}

// --- zone name cache ------------------------------------------------------

// fakeZoneTable is an interface table and a clock for a zoneCache under
// test: calls counts how often the cache asked for the table, and err, when
// set, is what the next request fails with.
type fakeZoneTable struct {
	ifs   []net.Interface
	err   error
	calls int
	clock time.Time
}

func (f *fakeZoneTable) cache() *zoneCache {
	f.clock = time.Unix(1_000_000, 0)
	return &zoneCache{
		interfaces: func() ([]net.Interface, error) {
			f.calls++
			if f.err != nil {
				return nil, f.err
			}
			return append([]net.Interface(nil), f.ifs...), nil
		},
		now: func() time.Time { return f.clock },
	}
}

// TestZoneCacheHitDoesNotRefetch: once a name is in the table, looking it
// up again within zoneCacheTTL asks the host for nothing.
func TestZoneCacheHitDoesNotRefetch(t *testing.T) {
	f := &fakeZoneTable{ifs: []net.Interface{{Index: 7, Name: "zoneA"}}}
	z := f.cache()
	for i := 0; i < 3; i++ {
		if idx, ok := z.index("zoneA"); !ok || idx != 7 {
			t.Fatalf("lookup %d: index(zoneA) = %d, %v; want 7, true", i, idx, ok)
		}
		f.clock = f.clock.Add(zoneCacheTTL / 4)
	}
	if f.calls != 1 {
		t.Errorf("the interface table was read %d times for repeated hits within the TTL, want 1", f.calls)
	}
}

// TestZoneCacheRefreshesAfterTTL: a table older than zoneCacheTTL is read
// again before it answers, so an interface deleted and re-created under the
// same name, with a new index, is followed within the TTL, as net's own
// zone cache does (net/interface.go).
func TestZoneCacheRefreshesAfterTTL(t *testing.T) {
	f := &fakeZoneTable{ifs: []net.Interface{{Index: 7, Name: "zoneA"}}}
	z := f.cache()
	if idx, _ := z.index("zoneA"); idx != 7 {
		t.Fatalf("index(zoneA) = %d, want 7", idx)
	}
	f.ifs = []net.Interface{{Index: 9, Name: "zoneA"}}
	f.clock = f.clock.Add(zoneCacheTTL)
	if idx, ok := z.index("zoneA"); !ok || idx != 9 {
		t.Errorf("index(zoneA) after the TTL = %d, %v; want the new index 9", idx, ok)
	}
	if f.calls != 2 {
		t.Errorf("the interface table was read %d times, want 2", f.calls)
	}
}

// TestZoneCacheMissOnANameRefetches: a name the table does not hold is
// looked up again in a fresh table at once, so an interface created since
// the last read is found.
func TestZoneCacheMissOnANameRefetches(t *testing.T) {
	f := &fakeZoneTable{ifs: []net.Interface{{Index: 7, Name: "zoneA"}}}
	z := f.cache()
	if _, ok := z.index("zoneA"); !ok {
		t.Fatal("index(zoneA) missed")
	}
	f.ifs = append(f.ifs, net.Interface{Index: 8, Name: "zoneB"})
	if idx, ok := z.index("zoneB"); !ok || idx != 8 {
		t.Errorf("index(zoneB) = %d, %v; want 8, true from a fresh table", idx, ok)
	}
	if _, ok := z.index("nowhere"); ok {
		t.Error("index(nowhere) found an interface that does not exist")
	}
	if f.calls != 3 {
		t.Errorf("the interface table was read %d times, want 3 (the first read and one per miss)", f.calls)
	}
}

// TestZoneCacheNumericMissDoesNotRefetch: a decimal zone that names no
// interface in a fresh table is answered as a miss without reading the
// table again, so a send to a link-local address zoned by index does not
// cost an interface dump each time; encodeZone then takes the number.
func TestZoneCacheNumericMissDoesNotRefetch(t *testing.T) {
	f := &fakeZoneTable{ifs: []net.Interface{{Index: 7, Name: "zoneA"}}}
	z := f.cache()
	for i := 0; i < 3; i++ {
		if _, ok := z.index("12"); ok {
			t.Fatal("index(12) found an interface named 12")
		}
	}
	if f.calls != 1 {
		t.Errorf("the interface table was read %d times for a decimal zone, want 1", f.calls)
	}
	// An interface really named with digits is still found by name.
	f.ifs = append(f.ifs, net.Interface{Index: 30, Name: "12"})
	f.clock = f.clock.Add(zoneCacheTTL)
	if idx, ok := z.index("12"); !ok || idx != 30 {
		t.Errorf("index(12) with an interface named 12 = %d, %v; want 30, true", idx, ok)
	}
}

// TestZoneCacheKeepsTheTableWhenARefreshFails: an interface table that
// cannot be read leaves the previous one in place.
func TestZoneCacheKeepsTheTableWhenARefreshFails(t *testing.T) {
	f := &fakeZoneTable{ifs: []net.Interface{{Index: 7, Name: "zoneA"}}}
	z := f.cache()
	if _, ok := z.index("zoneA"); !ok {
		t.Fatal("index(zoneA) missed")
	}
	f.err = errors.New("netlink unavailable")
	f.clock = f.clock.Add(zoneCacheTTL)
	if idx, ok := z.index("zoneA"); !ok || idx != 7 {
		t.Errorf("index(zoneA) after a failed refresh = %d, %v; want the previous 7, true", idx, ok)
	}
}

// TestZoneCacheHitAllocatesNothing pins the property SendOptions.Path with
// a zoned link-local address relies on: resolving a zone the table holds
// allocates nothing.
func TestZoneCacheHitAllocatesNothing(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector")
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	f := &fakeZoneTable{ifs: []net.Interface{{Index: 7, Name: "zoneA"}}}
	z := f.cache()
	z.index("zoneA")
	allocs := testing.AllocsPerRun(200, func() {
		if idx, ok := z.index("zoneA"); !ok || idx != 7 {
			t.Fatalf("index(zoneA) = %d, %v", idx, ok)
		}
	})
	if allocs != 0 {
		t.Errorf("a cached zone lookup allocated %.1f times, want 0", allocs)
	}
}

// TestEncodeAddrZonedAllocatesNothing: encoding a link-local address zoned
// by a real interface's name allocates nothing once the name is cached,
// which is what keeps SendMsg with such a Path allocation-free.
func TestEncodeAddrZonedAllocatesNothing(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector")
	}
	ifs, err := net.Interfaces()
	if err != nil || len(ifs) == 0 {
		t.Skip("no network interfaces available on this host")
	}
	ip := netip.MustParseAddr("fe80::1").WithZone(ifs[0].Name)
	var dst [sizeSockaddrIn6]byte
	if _, err := encodeAddr(dst[:], afInet6, ip, 80); err != nil {
		t.Fatalf("encodeAddr(%v): %v", ip, err)
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	allocs := testing.AllocsPerRun(200, func() {
		if _, err := encodeAddr(dst[:], afInet6, ip, 80); err != nil {
			t.Fatalf("encodeAddr: %v", err)
		}
	})
	if allocs != 0 {
		t.Errorf("encodeAddr(%v) allocated %.1f times, want 0", ip, allocs)
	}
}

// BenchmarkEncodeAddrs (v1 BenchmarkToRawSockAddrBuf): marshalling a
// multi-homed address list into its raw wire form, the operation
// localBindAddrs and Dial's peer encoding both call on every multi-homed
// Listen or Dial.
func BenchmarkEncodeAddrs(b *testing.B) {
	ips := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.2")}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := encodeAddrs(afInet, ips, 9999); err != nil {
			b.Fatalf("encodeAddrs: %v", err)
		}
	}
}
