//go:build linux
// +build linux

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
// implied. See the License for the specific language governing permissions
// and limitations under the License.

package sctp

import (
	"errors"
	"net"
	"testing"
)

// TestExplicitNetworkRejectsTheOtherAddressFamily ensures directly built
// addresses cannot bypass sctp4/sctp6 selection. The generic sctp network may
// still use a dual-stack socket and a mixed address list.
func TestExplicitNetworkRejectsTheOtherAddressFamily(t *testing.T) {
	for _, tc := range []struct {
		name    string
		network string
		addr    *SCTPAddr
	}{
		{"IPv6 on sctp4", "sctp4", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv6loopback}}, Port: 9}},
		{"IPv4 on sctp6", "sctp6", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IPv4(127, 0, 0, 1)}}, Port: 9}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := ListenSCTP(tc.network, tc.addr)
			if ln != nil {
				_ = ln.Close()
			}
			var addrErr *net.AddrError
			if !errors.As(err, &addrErr) {
				t.Fatalf("ListenSCTP error = %v, want *net.AddrError", err)
			}
		})
	}
}
