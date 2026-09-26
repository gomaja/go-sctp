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

// sockaddr.go encodes and decodes the Linux sockaddr_in and sockaddr_in6
// layouts abi.go pins (sizeSockaddrIn, sizeSockaddrIn6 and their field
// offsets), byte by byte with binary.NativeEndian for the host-order family
// and scope id and binary.BigEndian for the network-order port and address
// (abi.go's own comment on the two structs). Nothing here goes through
// syscall.RawSockaddrInet4/6 or unsafe.Pointer: those types differ on the
// BSDs and macOS (a leading length byte before an 8-bit family, where Linux
// has a 16-bit family at offset zero), so a codec built on Linux's own byte
// layout, rather than the host's struct, runs its tests on every platform
// this package builds for.

package sctp

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The three decode failures a malformed or truncated reply can produce.
// Each is a package-level value — never built with fmt — so returning it
// costs nothing: decodeAddrs must reject a truncated buffer, an unknown
// family or an impossible count before it allocates anything sized by the
// caller's count, and a formatted error would itself be that allocation.
var (
	errNegativeSockaddrCount = &invalidArgError{msg: "sctp: negative sockaddr count"}
	errTooManySockaddrs      = &invalidArgError{msg: "sctp: sockaddr count cannot fit in the buffer even at the smallest entry size"}
	errShortSockaddrEntry    = &invalidArgError{msg: "sctp: sockaddr entry runs past the end of the buffer"}
	errUnknownSockaddrFamily = &invalidArgError{msg: "sctp: sockaddr entry names an address family this package does not decode"}
)

// sockaddrSize returns the encoded size of one sockaddr for family:
// sizeSockaddrIn for afInet, sizeSockaddrIn6 for afInet6.
func sockaddrSize(family int) (int, error) {
	switch family {
	case afInet:
		return sizeSockaddrIn, nil
	case afInet6:
		return sizeSockaddrIn6, nil
	default:
		return 0, invalidArg("unknown address family %d", family)
	}
}

// encodeAddr writes one Linux sockaddr_in or sockaddr_in6 for family into
// dst, which must be at least that size, and returns the number of bytes
// written. It is the single-address form used for msg_name and path
// options; encodeAddrs below calls it once per entry.
//
// IPv4 on an AF_INET6 socket is encoded IPv4-mapped, ::ffff:a.b.c.d (RFC
// 6458 §9.1, Erratum 4921, Held for Document Update), except for the IPv4
// unspecified address 0.0.0.0, which becomes the IPv6 unspecified address
// :: — the dual-stack wildcard, matching net.ListenTCP("tcp", ...) and v1's
// own ipToSockaddr (git show main:ipsock_linux.go). Binding an AF_INET6
// socket to ::ffff:0.0.0.0 instead would restrict it to IPv4, which is what
// "sctp4" is for; "sctp"/"sctp6" get the dual-stack wildcard.
//
// ip and its zone are formatted into an error only as copies (ip.String,
// strings.Clone), so that encodeAddr leaks nothing of ip: SendMsg encodes
// SendOptions.Path with it, and a parameter that leaked would make the
// compiler move whatever a caller's SendOptions points to onto the heap
// on every send.
//
// A zone is accepted only on a link-local unicast IPv6 address — the only
// scope SCTP, a unicast transport, ever addresses with one — and refused
// with an error matching syscall.EINVAL on an IPv4 address or a
// non-link-local one (v1's zone handling, git show main:sctp.go,
// SCTPAddr.MarshalSockaddr, accepted a zone on any IPv6 address; this
// narrows it to the scope a zone is actually meaningful for). A named zone
// is resolved with net.InterfaceByName; a numeric one is parsed as decimal
// (encodeZone).
func encodeAddr(dst []byte, family int, ip netip.Addr, port uint16) (int, error) {
	if !ip.IsValid() {
		return 0, invalidArg("address is the zero netip.Addr")
	}
	zone := ip.Zone()
	unmapped := ip.Unmap()

	switch family {
	case afInet:
		if zone != "" {
			return 0, invalidArg("address %s has a zone but the socket family is AF_INET", ip.String())
		}
		if !unmapped.Is4() {
			return 0, invalidArg("address %s is not IPv4 for an AF_INET socket", ip.String())
		}
		if len(dst) < sizeSockaddrIn {
			return 0, invalidArg("a %d byte buffer is too small for a %d byte sockaddr_in", len(dst), sizeSockaddrIn)
		}
		// struct sockaddr_in { sin_family(2) sin_port(2) sin_addr(4) pad(8) },
		// include/uapi/linux/in.h — family host order, port and address
		// network order (abi.go).
		binary.NativeEndian.PutUint16(dst[sockaddrInFamilyOff:], uint16(afInet))
		binary.BigEndian.PutUint16(dst[sockaddrInPortOff:], port)
		v4 := unmapped.As4()
		copy(dst[sockaddrInAddrOff:sockaddrInAddrOff+4], v4[:])
		clear(dst[sockaddrInAddrOff+4 : sizeSockaddrIn])
		return sizeSockaddrIn, nil

	case afInet6:
		if len(dst) < sizeSockaddrIn6 {
			return 0, invalidArg("a %d byte buffer is too small for a %d byte sockaddr_in6", len(dst), sizeSockaddrIn6)
		}
		var scope uint32
		if zone != "" {
			if unmapped.Is4() {
				return 0, invalidArg("address %s has a zone but is IPv4", ip.String())
			}
			if !unmapped.IsLinkLocalUnicast() {
				return 0, invalidArg("address %s has a zone but is not link-local", ip.String())
			}
			s, err := encodeZone(zone)
			if err != nil {
				return 0, err
			}
			scope = s
		}
		// The IPv4 wildcard becomes the IPv6 wildcard on an AF_INET6 socket,
		// not the IPv4-mapped ::ffff:0.0.0.0: the caller asked for a
		// dual-stack socket by choosing this family, and only :: gives one.
		wire := unmapped
		if unmapped.Is4() && unmapped.IsUnspecified() {
			wire = netip.IPv6Unspecified()
		}
		// struct sockaddr_in6 { sin6_family(2) sin6_port(2) sin6_flowinfo(4)
		// sin6_addr(16) sin6_scope_id(4) }, include/uapi/linux/in6.h — family
		// and scope id host order (net/sctp/ipv6.c: sctp_v6_copy_addrlist
		// assigns addr->a.v6.sin6_scope_id = dev->ifindex directly, with no
		// htonl), port and address network order, flowinfo always zero.
		binary.NativeEndian.PutUint16(dst[sockaddrIn6FamilyOff:], uint16(afInet6))
		binary.BigEndian.PutUint16(dst[sockaddrIn6PortOff:], port)
		clear(dst[sockaddrIn6FlowInfoOff : sockaddrIn6FlowInfoOff+4])
		b16 := wire.As16()
		copy(dst[sockaddrIn6AddrOff:sockaddrIn6AddrOff+16], b16[:])
		binary.NativeEndian.PutUint32(dst[sockaddrIn6ScopeIDOff:], scope)
		return sizeSockaddrIn6, nil

	default:
		return 0, invalidArg("unknown address family %d", family)
	}
}

// encodeAddrs packs ips (with port) into Linux sockaddr_in/sockaddr_in6
// entries for a socket of the given family; IPv4 goes mapped on AF_INET6
// sockets (RFC 6458 §9.1, Erratum 4921, Held for Document Update). An empty
// ips packs to an empty, non-nil slice.
func encodeAddrs(family int, ips []netip.Addr, port uint16) ([]byte, error) {
	size, err := sockaddrSize(family)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, len(ips)*size)
	for i, ip := range ips {
		if _, err := encodeAddr(buf[i*size:(i+1)*size], family, ip, port); err != nil {
			// err is already a *invalidArgError, whose message already
			// starts with "sctp: "; strip that before adding the entry
			// index, so the result carries the prefix once, not twice.
			return nil, invalidArg("address %d: %s", i, strings.TrimPrefix(err.Error(), "sctp: "))
		}
	}
	return buf, nil
}

// encodeZone turns a textual zone — an interface name, or the decimal
// interface index v1's zoneID also accepted — into the numeric scope id
// sin6_scope_id carries. The interface name is tried first and the decimal
// form is the fallback, the same order net's own zoneCache.index resolves a
// zone in (net/interface.go); v1 tried the numeric form first. Names are
// resolved through zoneIndexes, so that encoding a zoned address, which
// every SendOptions.Path on a link-local address does, allocates nothing
// once the name is known. An empty zone is scope id 0; an explicit zone of
// "0" is refused, since Linux refuses to bind to, or connect or send to, a
// link-local address with scope id 0 (net/sctp/ipv6.c:
// sctp_inet6_bind_verify checks a local address being bound,
// sctp_inet6_send_verify a destination address being connected or sent to
// — both return 0 when the address is link-local and sin6_scope_id is
// zero) and encodeAddr only reaches this function for a link-local
// address.
func encodeZone(zone string) (uint32, error) {
	if zone == "" {
		return 0, nil
	}
	if index, ok := zoneIndexes.index(zone); ok {
		if index < 0 {
			return 0, invalidArg("zone %q: interface index %d is negative", strings.Clone(zone), index)
		}
		return uint32(index), nil
	}
	n, err := strconv.ParseUint(zone, 10, 32)
	if err != nil {
		return 0, invalidArg("zone %q is not an interface name or a decimal index", strings.Clone(zone))
	}
	if n == 0 {
		return 0, invalidArg("zone %q: a link-local address needs a non-zero scope id", strings.Clone(zone))
	}
	return uint32(n), nil
}

// zoneCacheTTL is how long zoneCache answers from the interface table it
// last read before it reads the table again: the interval net's own zone
// cache uses (net/interface.go: ipv6ZoneCache.update), so an interface
// deleted and created again under the same name, with a new index, is
// followed at least as promptly as net follows it.
const zoneCacheTTL = 60 * time.Second

// zoneIndexes resolves every zone name encodeZone sees.
var zoneIndexes = zoneCache{interfaces: net.Interfaces, now: time.Now}

// zoneCache maps interface names to interface indexes from a copy of the
// host's interface table, like net's ipv6ZoneCache (net/interface.go). A
// lookup the table answers costs a map read and allocates nothing, where
// net.InterfaceByName asks the kernel for the whole table every time. The
// table is read again when it is older than zoneCacheTTL, and when a name
// is missing from it, so an interface created since the last read is
// found at once; a missing name that is a decimal number is the one
// exception, answered from the table as it is, since encodeZone then
// takes the number as the index and a send to an address zoned by index
// would otherwise read the table on every call. The table holds one entry
// per interface the host had at the last read, and nothing else, so its
// size is bounded by the host's interfaces, not by the names asked for.
type zoneCache struct {
	mu      sync.RWMutex
	byName  map[string]int
	fetched time.Time // when byName was read; zero before the first read

	interfaces func() ([]net.Interface, error) // net.Interfaces; replaced by tests
	now        func() time.Time                // time.Now; replaced by tests
}

// index returns the index of the interface named name, and whether the
// host has one.
func (z *zoneCache) index(name string) (int, bool) {
	now := z.now()
	z.mu.RLock()
	idx, ok := z.byName[name]
	fresh := !z.fetched.IsZero() && now.Sub(z.fetched) < zoneCacheTTL
	z.mu.RUnlock()
	if fresh && (ok || isDecimal(name)) {
		return idx, ok
	}
	return z.refresh(now, name)
}

// refresh reads the interface table again, unless another caller has
// since read one this lookup may use, and looks name up in the result. A
// table that cannot be read leaves the previous one in place.
func (z *zoneCache) refresh(now time.Time, name string) (int, bool) {
	z.mu.Lock()
	defer z.mu.Unlock()
	if z.fetched.After(now) {
		// Read after this lookup started: as fresh as a read here would be.
		idx, ok := z.byName[name]
		return idx, ok
	}
	if ift, err := z.interfaces(); err == nil {
		byName := make(map[string]int, len(ift))
		for _, ifi := range ift {
			byName[ifi.Name] = ifi.Index
		}
		z.byName = byName
		z.fetched = now
	}
	idx, ok := z.byName[name]
	return idx, ok
}

// isDecimal reports whether s is a non-empty run of ASCII digits.
func isDecimal(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// zoneName maps a scope id back to the interface name it still names, else
// its decimal form (v1 zoneID, inverted). Scope id 0 — no zone — is the
// empty string.
func zoneName(index uint32) string {
	if index == 0 {
		return ""
	}
	if idx := int(index); idx > 0 && uint32(idx) == index {
		if ifi, err := net.InterfaceByIndex(idx); err == nil {
			return ifi.Name
		}
	}
	return strconv.FormatUint(uint64(index), 10)
}

// sockaddrEntrySize validates the sockaddr entry starting at b[at:] — that
// its family is readable and known, and that the entry the family implies
// fits before len(b) — and returns that entry's size without decoding it.
// Splitting validation from decoding is what lets decodeAddrs check every
// entry in a packed array before allocating the slice it decodes into.
func sockaddrEntrySize(b []byte, at int) (int, error) {
	// The two bytes of sa_family_t (sockaddrInFamilyOff and
	// sockaddrIn6FamilyOff agree, both 0) must be inside b before anything
	// is read: reading a size implied by a family read from past the end
	// would itself be the out-of-bounds access being guarded against.
	if at < 0 || at+2 > len(b) {
		return 0, errShortSockaddrEntry
	}
	family := binary.NativeEndian.Uint16(b[at+sockaddrInFamilyOff:])
	var size int
	switch int(family) {
	case afInet:
		size = sizeSockaddrIn
	case afInet6:
		size = sizeSockaddrIn6
	default:
		return 0, errUnknownSockaddrFamily
	}
	if at+size > len(b) {
		return 0, errShortSockaddrEntry
	}
	return size, nil
}

// decodeSockaddrEntry decodes one sockaddr already validated by
// sockaddrEntrySize (b is exactly that entry's bytes) into a netip.Addr and
// its port. An AF_INET entry, and an AF_INET6 entry whose address is
// IPv4-mapped (::ffff:0:0/96 — not the deprecated IPv4-compatible
// ::a.b.c.d, which Is4In6 does not match), both decode to a plain IPv4
// netip.Addr, never IPv4-mapped.
//
// A genuine IPv6 entry keeps its scope id as a zone only when the address
// is link-local unicast. Linux sets sin6_scope_id without regard to the
// address's kind, and differently for the two lists SCTP_GET_LOCAL_ADDRS
// and SCTP_GET_PEER_ADDRS hand back (net/sctp/ipv6.c): every local
// address carries its device's index (sctp_v6_copy_addrlist sets it from
// dev->ifindex for every address on the device's list); a peer address
// taken from a packet's source carries the receiving interface's index
// (sctp_v6_from_skb); and a peer address learned from an INIT, INIT ACK
// or ASCONF address parameter carries 0, since sctp_v6_from_addr_param
// stores its iif argument and every caller passes 0
// (net/sctp/sm_make_chunk.c: sctp_process_init, sctp_process_param,
// sctp_add_asconf_response, sctp_asconf_param_success; net/sctp/input.c:
// __sctp_rcv_init_lookup, __sctp_rcv_asconf_lookup). sctp_v6_addr_to_user,
// which builds the value userspace reads, never clears or conditions it.
// A loopback or global address decoded with its scope id would therefore
// pick up a spurious zone from whichever interface happened to report or
// receive it, and a peer's link-local address arrives with none, which is
// left as it is — no interface index can be made up for it. Linux's own
// bind and send paths apply the same restriction the other way — a scope
// id is only checked, or required to be non-zero, when the address is
// link-local (sctp_inet6_bind_verify, sctp_inet6_send_verify,
// __sctp_v6_cmp_addr).
func decodeSockaddrEntry(b []byte) (netip.Addr, uint16) {
	family := binary.NativeEndian.Uint16(b[sockaddrInFamilyOff:])
	// sockaddrInPortOff and sockaddrIn6PortOff agree (both 2), so this reads
	// the port correctly for either family.
	port := binary.BigEndian.Uint16(b[sockaddrInPortOff:])

	if int(family) == afInet {
		var a4 [4]byte
		copy(a4[:], b[sockaddrInAddrOff:sockaddrInAddrOff+4])
		return netip.AddrFrom4(a4), port
	}

	var a16 [16]byte
	copy(a16[:], b[sockaddrIn6AddrOff:sockaddrIn6AddrOff+16])
	ip := netip.AddrFrom16(a16)
	if ip.Is4In6() {
		return ip.Unmap(), port
	}
	if ip.IsLinkLocalUnicast() {
		if scope := binary.NativeEndian.Uint32(b[sockaddrIn6ScopeIDOff:]); scope != 0 {
			ip = ip.WithZone(zoneName(scope))
		}
	}
	return ip, port
}

// decodeAddr parses one sockaddr, such as msg_name or an
// SCTP_GET_PEER_ADDR_INFO reply's spinfo_address, out of a sockaddr_storage
// sized field into an AddrPort; unmaps IPv4 to plain form.
func decodeAddr(b []byte) (netip.AddrPort, error) {
	size, err := sockaddrEntrySize(b, 0)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ip, port := decodeSockaddrEntry(b[:size])
	return netip.AddrPortFrom(ip, port), nil
}

// decodeAddrs parses n sockaddrs packed back to back in b — the reply shape
// of SCTP_GET_LOCAL_ADDRS and SCTP_GET_PEER_ADDRS — bounded by len(b) before
// any allocation, and unmaps IPv4 to plain form. Every address in an association
// shares the port, so only the first entry's is returned; a later entry
// carrying a different one (a malformed or truncated reply) does not
// override it (v1 resolveFromRawAddrBuf, git show main:sctp.go).
//
// Each entry is sized by its own family — 16 bytes for an AF_INET entry, 28
// for AF_INET6 — rather than by a fixed stride taken from the first: nothing
// in the interface guarantees a uniform reply, and striding by the wrong
// size would silently decode a later entry from the wrong offset instead of
// reporting an error (the same v1 function, and its comment).
//
// b is walked twice on the way to a successful decode: once to check that
// every entry's family is known and that entry fits in b, and once to
// decode. That is what lets a truncated buffer, an unknown family and a
// count too large for b to hold be rejected before the result slice is
// allocated, sized by n — see errShortSockaddrEntry, errUnknownSockaddrFamily
// and errTooManySockaddrs above.
func decodeAddrs(b []byte, n int) ([]netip.Addr, uint16, error) {
	if n < 0 {
		return nil, 0, errNegativeSockaddrCount
	}
	if n == 0 {
		return nil, 0, nil
	}
	// Even at the smallest possible entry size, n of them must fit in b;
	// reject before anything is sized by n. (sizeSockaddrIn, the AF_INET
	// entry, is the smaller of the two.)
	if n > len(b)/sizeSockaddrIn {
		return nil, 0, errTooManySockaddrs
	}

	at := 0
	for range n {
		size, err := sockaddrEntrySize(b, at)
		if err != nil {
			return nil, 0, err
		}
		at += size
	}

	ips := make([]netip.Addr, n)
	var port uint16
	at = 0
	for i := range n {
		size, _ := sockaddrEntrySize(b, at) // already validated above
		ip, p := decodeSockaddrEntry(b[at : at+size])
		if i == 0 {
			port = p
		}
		ips[i] = ip
		at += size
	}
	return ips, port, nil
}
