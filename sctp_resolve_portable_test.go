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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"
)

func TestNilSCTPAddrString(t *testing.T) {
	var addr *SCTPAddr
	if got := addr.String(); got != "<nil>" {
		t.Fatalf("nil SCTPAddr.String() = %q, want <nil>", got)
	}
}

// TestDirectSCTPAddrValuesAreValidated covers addresses constructed by callers
// instead of ResolveSCTPAddr. These values cross an unsafe ABI boundary, so a
// malformed value must be rejected before it can be truncated, padded or
// mistaken for a different endpoint by the kernel.
func TestDirectSCTPAddrValuesAreValidated(t *testing.T) {
	badZone := "sctp-test-interface-that-does-not-exist"
	for _, tc := range []struct {
		name string
		addr *SCTPAddr
	}{
		{"nil address", nil},
		{"negative port", &SCTPAddr{Port: -1}},
		{"port above uint16", &SCTPAddr{Port: 1 << 16}},
		{"empty address entry", &SCTPAddr{IPAddrs: []net.IPAddr{{}}, Port: 9}},
		{"malformed IP length", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IP{1, 2, 3, 4, 5}}}, Port: 9}},
		{"zone on IPv4", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1), Zone: "lo"}}, Port: 9}},
		{"unknown IPv6 zone", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv6loopback, Zone: badZone}}, Port: 9}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.addr != nil && tc.addr.ToRawSockAddrBuf() != nil {
				t.Error("ToRawSockAddrBuf encoded an invalid address")
			}
			for _, call := range []struct {
				name string
				fn   func() error
			}{
				{"SCTPBind", func() error { return SCTPBind(-1, tc.addr, SCTP_BINDX_ADD_ADDR) }},
				{"SCTPConnect", func() error { _, err := SCTPConnect(-1, tc.addr); return err }},
				{"SetPrimaryPeerAddr", func() error {
					return (&SCTPConn{_fd: -1}).SetPrimaryPeerAddr(tc.addr)
				}},
				{"SetPeerPrimaryAddr", func() error {
					return (&SCTPConn{_fd: -1}).SetPeerPrimaryAddr(tc.addr)
				}},
			} {
				t.Run(call.name, func(t *testing.T) {
					var panicked any
					var err error
					func() {
						defer func() { panicked = recover() }()
						err = call.fn()
					}()
					if panicked != nil {
						t.Fatalf("panicked: %v", panicked)
					}
					var addrErr *net.AddrError
					if !errors.As(err, &addrErr) {
						t.Errorf("error = %v, want *net.AddrError", err)
					}
				})
			}
		})
	}
}

// TestSCTPBindRejectsUnknownFlagsBeforeTouchingTheAddress preserves the
// existing precedence: a bogus operation is invalid even when addr is nil.
func TestSCTPBindRejectsUnknownFlagsBeforeTouchingTheAddress(t *testing.T) {
	if err := SCTPBind(-1, nil, 999); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("SCTPBind error = %v, want EINVAL", err)
	}
}

// TestResolveSCTPAddrRejectsMalformedInput covers the negative paths of the
// package's main untrusted-string entry point.
//
// The existing table expected a nil error from every case, so four error
// branches had never been reached, and two inputs produced an address that was
// wrong rather than refused:
//
//   - "1.2.3.4/5.6.7.8/:80" returned an empty address list with port 80, which
//     binds the wildcard. Every address the caller explicitly named was
//     discarded, with no error — so a trailing separator in a configuration file
//     turns "listen on these two" into "listen on everything".
//   - "/127.0.0.1:80" returned a nil IP followed by the real one, which binds
//     0.0.0.0 as well as the address named.
//
// The multi-homing slash syntax is this package's own invention, so nothing else
// validates it.
func TestResolveSCTPAddrRejectsMalformedInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr string
	}{
		{"trailing separator before the port", "1.2.3.4/5.6.7.8/:80"},
		{"leading separator", "/127.0.0.1:80"},
		{"empty element in the middle", "1.2.3.4//5.6.7.8:80"},
		{"port out of range", "127.0.0.1:99999"},
		{"no port at all", "127.0.0.1"},
		{"not an address", "!!!:80"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := ResolveSCTPAddr("sctp", tc.addr)
			if err == nil {
				t.Fatalf("ResolveSCTPAddr(%q) = %v with no error; it should be "+
					"refused rather than turned into an address the caller did "+
					"not ask for", tc.addr, addr)
			}
		})
	}
}

// TestResolveSCTPAddrAcceptsTheDocumentedForms is the other half: the fix must
// not narrow what already worked.
func TestResolveSCTPAddrAcceptsTheDocumentedForms(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network string
		addr    string
		ips     []string
		port    int
	}{
		{"bare port is the wildcard", "sctp", ":80", nil, 80},
		{"one address", "sctp", "127.0.0.1:80", []string{"127.0.0.1"}, 80},
		{"two addresses", "sctp", "127.0.0.1/127.0.0.2:80",
			[]string{"127.0.0.1", "127.0.0.2"}, 80},
		{"three addresses", "sctp", "127.0.0.1/127.0.0.2/127.0.0.3:9",
			[]string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}, 9},
		{"empty network means sctp", "", "127.0.0.1:80", []string{"127.0.0.1"}, 80},
		{"ipv6", "sctp6", "[::1]:80", []string{"::1"}, 80},
		{"two ipv6 addresses", "sctp6", "[::1]/[::1]:80",
			[]string{"::1", "::1"}, 80},
		{"port zero", "sctp", "127.0.0.1:0", []string{"127.0.0.1"}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			addr, err := ResolveSCTPAddr(tc.network, tc.addr)
			if err != nil {
				t.Fatalf("ResolveSCTPAddr(%q, %q): %v", tc.network, tc.addr, err)
			}
			if addr.Port != tc.port {
				t.Errorf("port = %d, want %d", addr.Port, tc.port)
			}
			if len(addr.IPAddrs) != len(tc.ips) {
				t.Fatalf("got %d addresses (%v), want %d (%v)",
					len(addr.IPAddrs), addr.IPAddrs, len(tc.ips), tc.ips)
			}
			for i, want := range tc.ips {
				if addr.IPAddrs[i].IP == nil {
					t.Errorf("address %d is nil; binding that asks for the "+
						"wildcard alongside the addresses named", i)
					continue
				}
				if got := addr.IPAddrs[i].IP.String(); got != want {
					t.Errorf("address %d = %s, want %s", i, got, want)
				}
			}
		})
	}
}

// TestResolveSCTPAddrNeverReturnsANilAddress states the invariant the two
// defects above both broke, independent of which input reached it.
func TestResolveSCTPAddrNeverReturnsANilAddress(t *testing.T) {
	inputs := []string{
		":0", "127.0.0.1:0", "127.0.0.1/127.0.0.2:0",
		"1.2.3.4/5.6.7.8/:80", "/127.0.0.1:80", "//:80", "/:0",
	}
	for _, in := range inputs {
		addr, err := ResolveSCTPAddr("sctp", in)
		if err != nil {
			continue // refused, which is a fine answer
		}
		for i, ip := range addr.IPAddrs {
			if ip.IP == nil {
				t.Errorf("ResolveSCTPAddr(%q) returned a nil IP at index %d "+
					"(%v); it would be bound as the wildcard", in, i, addr.IPAddrs)
			}
		}
	}
}

// FuzzResolveSCTPAddr exercises the parser with arbitrary input.
//
// This is the package's main place where a caller's string becomes an address
// that gets bound, and it had no fuzz target. The property asserted is the one
// that matters and that the two defects above both violated: a successful parse
// must not silently produce something the input did not describe.
func FuzzResolveSCTPAddr(f *testing.F) {
	// ResolveSCTPAddr deliberately supports host names, but a fuzz byte stream
	// must never become an external DNS query. Keep the full parser surface and
	// make name lookups fail locally and deterministically instead of limiting
	// the corpus to numeric addresses.
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
		// A named IPv6 zone reaches net.InterfaceByName during validation.
		// Numeric zones cover scoped addresses without making fuzz results depend
		// on which interfaces happen to exist on the worker.
		if !fuzzAddressZonesAreNumeric(addrs) {
			return
		}
		for _, network := range []string{"sctp", "sctp4", "sctp6"} {
			addr, err := ResolveSCTPAddr(network, addrs)
			if err != nil {
				if addr != nil {
					t.Errorf("ResolveSCTPAddr(%q, %q) returned both %v and %v",
						network, addrs, addr, err)
				}
				continue
			}
			if addr == nil {
				t.Fatalf("ResolveSCTPAddr(%q, %q) returned nil with no error",
					network, addrs)
			}
			for i, ip := range addr.IPAddrs {
				if ip.IP == nil {
					t.Errorf("ResolveSCTPAddr(%q, %q) produced a nil IP at %d; "+
						"binding it asks for the wildcard", network, addrs, i)
				}
			}
			if addr.Port < 0 || addr.Port > 65535 {
				t.Errorf("ResolveSCTPAddr(%q, %q) produced port %d",
					network, addrs, addr.Port)
			}
			// Encoding must not panic and must produce something a decode can
			// read back, since this is what reaches the kernel.
			if buf := addr.ToRawSockAddrBuf(); len(buf) == 0 {
				t.Errorf("ResolveSCTPAddr(%q, %q) produced an address that "+
					"encodes to nothing", network, addrs)
			}
			_ = addr.String()
		}
	})
}

func fuzzAddressZonesAreNumeric(addrs string) bool {
	for offset := 0; ; {
		i := strings.IndexByte(addrs[offset:], '%')
		if i < 0 {
			return true
		}
		i += offset + 1
		start := i
		for i < len(addrs) && addrs[i] >= '0' && addrs[i] <= '9' {
			i++
		}
		if i == start || i == len(addrs) || addrs[i] != ']' {
			return false
		}
		offset = i + 1
	}
}

// FuzzSCTPAddrMarshal exercises values built directly from fields. Successful
// encodings must be stable across the checked and compatibility APIs; invalid
// values must return an error and never panic or produce bytes for the kernel.
func FuzzSCTPAddrMarshal(f *testing.F) {
	f.Add([]byte{127, 0, 0, 1}, uint32(0), false, 80)
	f.Add([]byte(net.IPv6loopback), uint32(0), false, 443)
	f.Add([]byte(net.IPv6loopback), uint32(1), true, 443)
	f.Add([]byte{1, 2, 3, 4, 5}, uint32(0), false, 9)
	f.Add([]byte{}, uint32(0), false, -1)
	f.Add([]byte(net.IPv6loopback), ^uint32(0), true, 9)

	f.Fuzz(func(t *testing.T, raw []byte, zoneID uint32, zoned bool, port int) {
		if len(raw) > 64 {
			return
		}
		zone := ""
		if zoned {
			// Numeric zones exercise the entire encoding path without passing
			// arbitrary fuzz strings to net.InterfaceByName.
			zone = strconv.FormatUint(uint64(zoneID), 10)
		}
		addr := &SCTPAddr{
			IPAddrs: []net.IPAddr{{IP: net.IP(append([]byte(nil), raw...)), Zone: zone}},
			Port:    port,
		}
		buf, err := addr.MarshalSockaddr()
		compat := addr.ToRawSockAddrBuf()
		if err != nil {
			if compat != nil {
				t.Fatalf("invalid address encoded %d bytes through compatibility API", len(compat))
			}
			return
		}
		inet4Size := int(unsafe.Sizeof(syscall.RawSockaddrInet4{}))
		inet6Size := int(unsafe.Sizeof(syscall.RawSockaddrInet6{}))
		if len(buf) != inet4Size && len(buf) != inet6Size {
			t.Fatalf("encoded length = %d, want one sockaddr", len(buf))
		}
		if string(compat) != string(buf) {
			t.Fatal("checked and compatibility encoders disagree")
		}
	})
}
