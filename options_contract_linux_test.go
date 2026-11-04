// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
	"time"
)

func TestPrInfoPolicyFieldsThroughSocket(t *testing.T) {
	c, peer := connPair(t, &Config{PartialReliability: new(true)}, &Config{PartialReliability: new(true)})
	for _, tc := range invalidPolicyFields() {
		t.Run(tc.name, func(t *testing.T) {
			n, err := c.SendMsg([]byte("refused-"+tc.name), SendOptions{PR: &tc.pr})
			wantRefused(t, err, "SendOptions.PR."+tc.field)
			if n != 0 {
				t.Errorf("refused send wrote %d bytes", n)
			}
			wantRefused(t, c.SetDefaultPrInfo(&tc.pr), "SetDefaultPrInfo."+tc.field)
		})
	}
	for i, pr := range []*PrInfo{nil, {}, {Policy: PRTTL, TTL: time.Second}, {Policy: PRRtx}, {Policy: PRPrio, Value: 9}} {
		t.Run(fmt.Sprintf("roundtrip%d", i), func(t *testing.T) {
			if pr != nil {
				if err := c.SetDefaultPrInfo(pr); err != nil {
					t.Fatal(err)
				}
			}
			got, err := c.DefaultPrInfo()
			if err != nil {
				t.Fatal(err)
			}
			want := PrInfo{}
			if pr != nil {
				want = *pr
			}
			if *got != want {
				t.Fatalf("readback = %+v, want %+v", *got, want)
			}
			if err := c.SetDefaultPrInfo(got); err != nil {
				t.Fatalf("set unchanged readback: %v", err)
			}
			payload := []byte(fmt.Sprintf("accepted-policy-%d", i))
			if n, err := c.SendMsg(payload, SendOptions{}); err != nil || n != len(payload) {
				t.Fatalf("send = %d, %v", n, err)
			}
			if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			b := make([]byte, 256)
			n, err := peer.Read(b)
			if err != nil || string(b[:n]) != string(payload) {
				t.Fatalf("read = %q, %v; want %q", b[:n], err, payload)
			}
		})
	}
}

func TestPathParamsReadModifyWrite(t *testing.T) {
	c, _ := connPair(t, nil, nil)
	path := primaryPath(t, c)
	for bits := 0; bits < 8; bits++ {
		t.Run(fmt.Sprintf("switches%d", bits), func(t *testing.T) {
			hb, pmtud, sack := bits&1 != 0, bits&2 != 0, bits&4 != 0
			// Seed retained values before disabling their switches.
			if err := c.SetPathParams(path, &PathParams{Heartbeat: new(true), HeartbeatInterval: new(30 * time.Second), PMTUD: new(false), PathMTU: new(uint32(1400)), DelayedSACK: new(true), SACKDelay: new(200 * time.Millisecond)}); err != nil {
				t.Fatal(err)
			}
			if err := c.SetPathParams(path, &PathParams{Heartbeat: &hb, PMTUD: &pmtud, DelayedSACK: &sack}); err != nil {
				t.Fatal(err)
			}
			p, err := c.PathParams(path)
			if err != nil {
				t.Fatal(err)
			}
			if *p.Heartbeat != hb || *p.PMTUD != pmtud || *p.DelayedSACK != sack {
				t.Fatalf("switches = %s", pathParamsString(p))
			}
			before := pathParamsString(p)
			// PathParams reports retained timers and the current MTU even when
			// their switches make them unsuitable for SetPathParams.
			if !*p.Heartbeat {
				p.HeartbeatInterval = nil
			}
			if *p.PMTUD {
				p.PathMTU = nil
			}
			if !*p.DelayedSACK {
				p.SACKDelay = nil
			}
			if err := c.SetPathParams(path, p); err != nil {
				t.Fatalf("write after clearing inactive fields: %v", err)
			}
			got, err := c.PathParams(path)
			if err != nil {
				t.Fatal(err)
			}
			if after := pathParamsString(got); after != before {
				t.Errorf("read-modify-write: before %s, after %s", before, after)
			}
		})
	}
}

func TestSctp6PortCollisionAndIPv6OnlyControl(t *testing.T) {
	l4 := mustListen(t, nil, "sctp4", nil)
	port := listenerAddr(t, l4).Port
	l6, err := Listen("sctp6", &Addr{Port: port})
	if l6 != nil {
		l6.Close()
		t.Fatal("dual-stack listener shared an IPv4 wildcard port")
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		t.Fatalf("dual-stack collision = %v; want EADDRINUSE", err)
	}
	cfg := &Config{Control: func(_, _ string, raw syscall.RawConn) error {
		var setErr error
		err := raw.Control(func(fd uintptr) {
			setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
		})
		if err != nil {
			return err
		}
		return setErr
	}}
	l6, err = cfg.Listen("sctp6", &Addr{Port: port})
	if err != nil {
		t.Fatalf("IPv6-only listener beside IPv4: %v", err)
	}
	defer l6.Close()
	rc, err := l6.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	if got := getIntOpt(t, rc, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY); got != 1 {
		t.Errorf("IPV6_V6ONLY = %d", got)
	}
}
