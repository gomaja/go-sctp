// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"context"
	"errors"
	"net/netip"
	"syscall"
	"testing"
)

func TestResolveAddrRejectsMalformedHostsBeforeLookup(t *testing.T) {
	previous := lookupNetIP
	calls := 0
	lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		calls++
		return nil, errors.New("unexpected lookup")
	}
	t.Cleanup(func() { lookupNetIP = previous })
	for _, address := range []string{
		"127.0.0.1:80/127.0.0.2:90",
		"[::1]:80/127.0.0.2:90",
		"127.0.0.1%eth0:80",
		"[2001:db8::1%eth0]:80",
		"[::1%eth0]:80",
		"[::%eth0]:80",
		"[::ffff:127.0.0.1%eth0]:80",
	} {
		t.Run(address, func(t *testing.T) {
			calls = 0
			a, err := ResolveAddr("sctp", address)
			if a != nil || !errors.Is(err, syscall.EINVAL) {
				t.Errorf("ResolveAddr = %v, %v, want EINVAL", a, err)
			}
			if calls != 0 {
				t.Errorf("malformed host caused %d lookups", calls)
			}
		})
	}
}

func TestResolveAddrValidatesEachAddressBeforeNextLookup(t *testing.T) {
	previous := lookupNetIP
	calls := 0
	lookupNetIP = func(context.Context, string, string) ([]netip.Addr, error) {
		calls++
		return nil, errors.New("unexpected lookup")
	}
	t.Cleanup(func() { lookupNetIP = previous })
	a, err := ResolveAddr("sctp4", "[::1]/unused.invalid:80")
	if a != nil || !errors.Is(err, syscall.EINVAL) {
		t.Errorf("ResolveAddr = %v, %v, want EINVAL", a, err)
	}
	if calls != 0 {
		t.Errorf("invalid earlier literal caused %d later lookups", calls)
	}
}

func TestResolveAddrContextRejectsNil(t *testing.T) {
	for _, address := range []string{":80", "127.0.0.1:80", "unused.invalid:80"} {
		t.Run(address, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Errorf("nil context panicked: %v", p)
				}
			}()
			a, err := ResolveAddrContext(nil, "sctp", address)
			if a != nil || !errors.Is(err, syscall.EINVAL) {
				t.Errorf("ResolveAddrContext(nil) = %v, %v, want EINVAL", a, err)
			}
		})
	}
}
