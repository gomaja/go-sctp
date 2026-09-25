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
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Addr is an SCTP transport address: one port, one or more IP addresses. It
// implements net.Addr.
//
// Every address the package itself produces — from ResolveAddr, or decoded
// from a kernel reply — reports IPv4 in plain form, never IPv4-mapped, even
// when the socket that produced it is AF_INET6: that is this package's own
// convention, so that netip.Addr values compare and print alike regardless
// of which family answered. An IPv6 zone, if any, is carried in the
// netip.Addr itself.
type Addr struct {
	IPs  []netip.Addr
	Port uint16
}

// Network returns "sctp", satisfying net.Addr.
func (a *Addr) Network() string { return "sctp" }

// String renders a the same way ResolveAddr parses it: its IPs joined with "/",
// followed by ":" and the port. An IPv6 address (and any zone) is
// bracketed; a plain or IPv4-mapped one is not, since it is always printed
// in plain form.
//
// A nil IPs list is the wildcard address, matching every local address, and
// renders as just ":port".
func (a *Addr) String() string {
	if a == nil {
		return "<nil>"
	}
	var b strings.Builder
	for i, ip := range a.IPs {
		if i > 0 {
			b.WriteByte('/')
		}
		ip = ip.Unmap()
		if ip.Is4() {
			b.WriteString(ip.String())
		} else {
			b.WriteByte('[')
			b.WriteString(ip.String())
			b.WriteByte(']')
		}
	}
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(int(a.Port)))
	return b.String()
}

// canonicalNetwork validates "sctp", "sctp4" or "sctp6" ("" meaning "sctp")
// and returns the address family ips must be encoded for.
//
//   - "sctp6" always returns afInet6: it accepts IPv4 addresses (reported
//     back in plain form) but still encodes them mapped, over the AF_INET6
//     socket the name asks for.
//   - "sctp4" returns afInet once every entry is confirmed IPv4 (unmapped
//     first, so a mapped literal counts as IPv4 too), and refuses the first
//     one that is not.
//   - "sctp" and "" pick whichever family the list actually needs: afInet6
//     as soon as one entry is not IPv4, afInet otherwise — including for an
//     empty list, which is the wildcard bind address (v1 SCTPAddr.family,
//     git show main:ipsock_linux.go).
//
// ips may be nil; that only validates the network name, which every caller
// needs regardless of whether it already has addresses in hand.
func canonicalNetwork(network string, ips []netip.Addr) (family int, err error) {
	switch network {
	case "", "sctp":
		for _, ip := range ips {
			if !ip.Unmap().Is4() {
				return afInet6, nil
			}
		}
		return afInet, nil
	case "sctp4":
		for i, ip := range ips {
			if !ip.Unmap().Is4() {
				return 0, invalidArg("sctp4 address %d (%s) is not IPv4", i, ip)
			}
		}
		return afInet, nil
	case "sctp6":
		return afInet6, nil
	default:
		return 0, invalidArg("network %q must be \"sctp\", \"sctp4\" or \"sctp6\"", network)
	}
}

// ResolveAddr parses "host1/host2/...:port" for network "sctp", "sctp4" or
// "sctp6", resolving host names through net.DefaultResolver. It never opens
// a socket, so it works on every platform. The port is required and must be
// numeric — a service name such as "http" is refused with an error matching
// syscall.EINVAL, as is a port outside 0-65535.
//
// A bare ":port", with no host at all, is the wildcard address: it resolves
// to &Addr{Port: port}, an empty IPs list, matching every local address. Any
// other empty element — "/10.0.0.1:80", "10.0.0.1//10.0.0.2:80",
// "10.0.0.1/:80" — is refused instead, since a caller that named at least
// one address almost never means for the wildcard to be silently added
// alongside it.
//
// Every element but the last is a bare host; an IPv6 literal among them,
// with or without a zone, is bracketed the way the last element's is by
// SplitHostPort ("[fe80::1%eth0]/10.0.0.2:3868"). Only the last element
// carries the port.
//
// A host name resolves to exactly one address, the way net.ResolveTCPAddr
// does: "sctp" (and "") prefers the first IPv4 answer, falling back to the
// first IPv6 one; "sctp4" requires and returns an IPv4 answer, "sctp6" an
// IPv6 one. Multi-homing is expressed by listing several hosts, not by one
// host name expanding to every address it has. An IPv4 literal is still
// accepted under "sctp6" — reported back in plain form, the way every
// address this package produces is (Addr's own doc comment) — since it is
// the caller naming that address directly, not the resolver choosing it.
func ResolveAddr(network, address string) (*Addr, error) {
	if _, err := canonicalNetwork(network, nil); err != nil {
		return nil, err
	}

	elems := strings.Split(address, "/")
	lastHost, portStr, err := net.SplitHostPort(elems[len(elems)-1])
	if err != nil {
		// err is already a *net.AddrError naming the offending element
		// ("address 127.0.0.1: missing port in address"); wrap it for
		// syscall.EINVAL without repeating that.
		return nil, invalidArg("%v", err)
	}
	p, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, invalidArg("address %q: invalid port %q", address, portStr)
	}
	port := uint16(p)

	if len(elems) == 1 && lastHost == "" {
		return &Addr{Port: port}, nil
	}

	ips := make([]netip.Addr, 0, len(elems))
	for i, e := range elems {
		host := e
		if i == len(elems)-1 {
			host = lastHost
		}
		host = unbracketHost(host)
		if host == "" {
			return nil, invalidArg("address %q names no host", address)
		}
		ip, err := resolveHost(network, host)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}

	if _, err := canonicalNetwork(network, ips); err != nil {
		return nil, err
	}
	return &Addr{IPs: ips, Port: port}, nil
}

// unbracketHost strips one layer of "[...]" from a bare host. SplitHostPort
// already does this for the element carrying the port; the others in a
// multi-homed list carry no port of their own, so an IPv6 literal among
// them still needs it removed by hand.
func unbracketHost(host string) string {
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		return host[1 : len(host)-1]
	}
	return host
}

// resolveHost resolves one address-list element to a single address. A
// literal — numeric, optionally zoned — is parsed directly, without
// touching the resolver. Anything else goes to
// net.DefaultResolver.LookupNetIP: "sctp4" and "sctp6" look up and require
// that specific family; "sctp" and "" look up both and prefer the first
// IPv4 answer, falling back to the first IPv6 one, the way
// net.ResolveTCPAddr's default network does.
//
// Either path can hand back an IPv4-mapped IPv6 address — a literal
// "::ffff:10.0.0.1", or a hosts-file IPv4 entry the pure Go resolver
// represents that way — and normalizeResolvedAddr unmaps it, so every
// address ResolveAddr returns is in the plain form Addr's doc comment
// promises.
func resolveHost(network, host string) (netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return normalizeResolvedAddr(ip)
	}

	ctx := context.Background()
	switch network {
	case "sctp4":
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
		if err != nil {
			return netip.Addr{}, err
		}
		if len(ips) == 0 {
			return netip.Addr{}, invalidArg("host %q has no IPv4 address", host)
		}
		return normalizeResolvedAddr(ips[0])
	case "sctp6":
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip6", host)
		if err != nil {
			return netip.Addr{}, err
		}
		if len(ips) == 0 {
			return netip.Addr{}, invalidArg("host %q has no IPv6 address", host)
		}
		return normalizeResolvedAddr(ips[0])
	default:
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return netip.Addr{}, err
		}
		if len(ips) == 0 {
			return netip.Addr{}, invalidArg("host %q has no address", host)
		}
		for _, ip := range ips {
			if ip.Unmap().Is4() {
				return normalizeResolvedAddr(ip)
			}
		}
		return normalizeResolvedAddr(ips[0])
	}
}

// normalizeResolvedAddr unmaps ip if it is IPv4-mapped, refusing a zone on
// it first: a zone is never meaningful on an IPv4 address (encodeAddr
// enforces the same rule at the kernel boundary), and Unmap would otherwise
// silently discard that zone rather than reject it.
func normalizeResolvedAddr(ip netip.Addr) (netip.Addr, error) {
	if ip.Is4In6() {
		if ip.Zone() != "" {
			return netip.Addr{}, invalidArg("address %s has a zone but is IPv4", ip)
		}
		return ip.Unmap(), nil
	}
	return ip, nil
}
