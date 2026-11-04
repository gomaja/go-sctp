// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"math"
	"strings"
	"testing"
	"time"
)

func invalidPolicyFields() []struct {
	name  string
	pr    PrInfo
	field string
} {
	return []struct {
		name  string
		pr    PrInfo
		field string
	}{
		{"ttl value", PrInfo{Policy: PRTTL, TTL: time.Millisecond, Value: 1}, "Value"},
		{"ttl value without lifetime", PrInfo{Policy: PRTTL, Value: 3000}, "Value"},
		{"ttl zero", PrInfo{Policy: PRTTL}, "TTL"},
		{"ttl negative", PrInfo{Policy: PRTTL, TTL: -time.Nanosecond}, "TTL"},
		{"ttl negative whole millisecond", PrInfo{Policy: PRTTL, TTL: -time.Millisecond}, "TTL"},
		{"ttl below millisecond", PrInfo{Policy: PRTTL, TTL: time.Millisecond - time.Nanosecond}, "TTL"},
		{"ttl above millisecond", PrInfo{Policy: PRTTL, TTL: time.Millisecond + time.Nanosecond}, "TTL"},
		{"ttl overflow", PrInfo{Policy: PRTTL, TTL: (time.Duration(math.MaxUint32) + 1) * time.Millisecond}, "TTL"},
		{"rtx positive ttl", PrInfo{Policy: PRRtx, TTL: time.Nanosecond}, "TTL"},
		{"rtx negative ttl", PrInfo{Policy: PRRtx, TTL: -time.Nanosecond}, "TTL"},
		{"priority positive ttl", PrInfo{Policy: PRPrio, TTL: time.Nanosecond}, "TTL"},
		{"priority negative ttl", PrInfo{Policy: PRPrio, TTL: -time.Nanosecond}, "TTL"},
		{"none positive ttl", PrInfo{Policy: PRNone, TTL: time.Nanosecond}, "TTL"},
		{"none negative ttl", PrInfo{Policy: PRNone, TTL: -time.Nanosecond}, "TTL"},
		{"none value", PrInfo{Policy: PRNone, Value: 1}, "Value"},
	}
}

func TestPrInfoPolicyFields(t *testing.T) {
	for _, tc := range invalidPolicyFields() {
		t.Run(tc.name, func(t *testing.T) {
			wantRefused(t, validateSendOptions(&SendOptions{PR: &tc.pr}), "SendOptions.PR."+tc.field)
			_, err := (&Config{DefaultPrInfo: &tc.pr}).prepare(styleDial)
			wantRefused(t, err, "Config.DefaultPrInfo."+tc.field)
		})
	}
	err := validatePrInfo("PR", &PrInfo{Policy: PRTTL})
	if err == nil || !strings.Contains(err.Error(), "abandons every message") || !strings.Contains(err.Error(), "PRNone") {
		t.Errorf("zero TTL error = %v; want abandonment and PRNone guidance", err)
	}
}

func TestPrInfoPolicyFieldBoundaries(t *testing.T) {
	for _, pr := range []PrInfo{
		{}, {Policy: PRTTL, TTL: time.Millisecond},
		{Policy: PRTTL, TTL: time.Duration(math.MaxUint32) * time.Millisecond},
		{Policy: PRRtx}, {Policy: PRRtx, Value: 1}, {Policy: PRRtx, Value: math.MaxUint32},
		{Policy: PRPrio}, {Policy: PRPrio, Value: 1}, {Policy: PRPrio, Value: math.MaxUint32},
	} {
		if err := validateSendOptions(&SendOptions{PR: &pr}); err != nil {
			t.Errorf("send %+v: %v", pr, err)
		}
		if _, err := (&Config{DefaultPrInfo: &pr}).prepare(styleDial); err != nil {
			t.Errorf("default %+v: %v", pr, err)
		}
	}
	if err := validateSendOptions(&SendOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := (*Config)(nil).prepare(styleDial); err != nil {
		t.Fatal(err)
	}
}

func TestResetDirectionBits(t *testing.T) {
	for _, tc := range []struct {
		bits ResetDirection
		want string
	}{
		{0, "0x0"}, {ResetIncoming, "ResetIncoming"}, {ResetOutgoing, "ResetOutgoing"},
		{ResetIncoming | ResetOutgoing, "ResetIncoming|ResetOutgoing"},
		{4, "0x4"}, {5, "ResetIncoming|0x4"}, {6, "ResetOutgoing|0x4"},
		{7, "ResetIncoming|ResetOutgoing|0x4"}, {0xffff, "ResetIncoming|ResetOutgoing|0xfffc"},
	} {
		if got := tc.bits.String(); got != tc.want {
			t.Errorf("ResetDirection(%#x) = %q, want %q", uint16(tc.bits), got, tc.want)
		}
	}
}
