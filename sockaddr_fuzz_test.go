// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"net/netip"
	"runtime/debug"
	"testing"
)

// FuzzDecodeAddrs drives decodeAddrs with arbitrary bytes in place of a
// kernel SCTP_GET_LOCAL_ADDRS/SCTP_GET_PEER_ADDRS reply.
//
// The buffer is the kernel's, not a peer's, so this is not a remote attack
// surface; it is fuzzed because the decoder reads it at offsets driven by a
// count that arrives separately from the data (n, mirroring the kernel's own
// separate address-count and buffer-length fields), and any disagreement
// between them — from a kernel bug, a truncated reply, or memory corruption
// — must become an error rather than a read past what n or b actually
// supports. n itself is not filtered: decodeAddrs's own pre-check
// (n > len(b)/sizeSockaddrIn) rejects any count that cannot fit before it is
// used for anything, including the most extreme values int can hold, so
// nothing here needs to bound it first.
//
// What this covers: no input may crash decodeAddrs; a successful decode may
// not claim more addresses than it was asked for, or size its result
// differently, or produce one of a length netip.Addr cannot represent; the
// error path must not allocate (mirroring
// TestDecodeAddrsAllocatesNothingOnError, but over arbitrary rather than
// hand-picked inputs); and every address a successful decode returns must be
// one encodeAddr can encode back for an AF_INET6 socket without error — the
// property that catches decodeSockaddrEntry attaching a zone to an address
// it should not have (a loopback or global address with a kernel-supplied
// but meaningless scope id would otherwise decode to something encodeAddr
// then refuses, since a zone is only valid on a link-local address).
func FuzzDecodeAddrs(f *testing.F) {
	f.Add(rawSockaddrIn(netip.MustParseAddr("192.0.2.1"), 3868), 1)
	f.Add(rawSockaddrIn6(netip.MustParseAddr("2001:db8::1"), 3868, 0), 1)
	f.Add(append(
		rawSockaddrIn(netip.MustParseAddr("192.0.2.1"), 3868),
		rawSockaddrIn6(netip.MustParseAddr("2001:db8::1"), 3868, 0)...,
	), 2)
	f.Add(append(
		rawSockaddrIn6(netip.MustParseAddr("2001:db8::1"), 3868, 0),
		rawSockaddrIn(netip.MustParseAddr("192.0.2.1"), 3868)...,
	), 2)
	f.Add(rawSockaddrIn6(netip.MustParseAddr("::ffff:192.0.2.1"), 80, 0), 1)
	// A loopback and a global address, each with a non-zero scope id: the
	// shape a live kernel actually sends (C1) and the case that must not
	// grow a zone.
	f.Add(rawSockaddrIn6(netip.MustParseAddr("::1"), 80, 1), 1)
	f.Add(rawSockaddrIn6(netip.MustParseAddr("2001:db8::1"), 80, 5), 1)
	f.Add([]byte{}, 0)
	f.Add([]byte{0, 0}, 1)
	f.Add([]byte{0, 0}, -1)
	f.Add([]byte{0, 0}, 1<<30)

	f.Fuzz(func(t *testing.T, b []byte, n int) {
		ips, port, err := decodeAddrs(b, n)
		if err != nil {
			if ips != nil {
				t.Fatalf("decodeAddrs(%d bytes, n=%d) returned both an error and %d addresses",
					len(b), n, len(ips))
			}
			if !underRaceDetector {
				// Scoped to just this measurement, not the whole fuzz
				// iteration: a GC triggered mid-measurement would allocate
				// on its own account and move the count, but disabling
				// collection for the entire fuzz run would let a long
				// session's garbage pile up unbounded.
				old := debug.SetGCPercent(-1)
				allocs := testing.AllocsPerRun(5, func() {
					_, _, _ = decodeAddrs(b, n)
				})
				debug.SetGCPercent(old)
				if allocs != 0 {
					t.Fatalf("decodeAddrs(%d bytes, n=%d) allocated %.1f times on the error path, want 0",
						len(b), n, allocs)
				}
			}
			return
		}

		if n > len(b)/sizeSockaddrIn {
			t.Fatalf("decodeAddrs(%d bytes, n=%d) succeeded although n cannot fit in b", len(b), n)
		}
		if len(ips) != n {
			t.Fatalf("decodeAddrs(%d bytes, n=%d) returned %d addresses, want exactly n",
				len(b), n, len(ips))
		}
		if cap(ips) != n {
			t.Fatalf("decodeAddrs(%d bytes, n=%d) returned a slice of capacity %d, want exactly n",
				len(b), n, cap(ips))
		}
		for i, ip := range ips {
			if !ip.IsValid() {
				t.Fatalf("address %d is the invalid zero netip.Addr", i)
			}
			if !ip.Is4() && !ip.Is6() {
				t.Fatalf("address %d (%s) is neither Is4 nor Is6", i, ip)
			}
			dst := make([]byte, sizeSockaddrIn6)
			if _, err := encodeAddr(dst, afInet6, ip, port); err != nil {
				t.Fatalf("decodeAddrs(%d bytes, n=%d) produced address %d = %s, which encodeAddr(afInet6) refuses: %v",
					len(b), n, i, ip, err)
			}
		}
	})
}
