// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"math"
	"reflect"
	"testing"
	"time"
)

// --- zero-value semantics ------------------------------------------------

func TestInitMsgZeroValueIsKernelDefault(t *testing.T) {
	var m InitMsg
	if m != (InitMsg{}) {
		t.Fatalf("zero InitMsg is not comparable to InitMsg{}: %+v", m)
	}
}

func TestRTOInfoZeroValueLeavesEachFieldUnchanged(t *testing.T) {
	var r RTOInfo
	if r.Initial != 0 || r.Max != 0 || r.Min != 0 {
		t.Fatalf("zero RTOInfo = %+v, want every field 0", r)
	}
}

func TestDelayedSACKZeroValueLeavesBothFieldsUnchanged(t *testing.T) {
	var d DelayedSACK
	if d.Delay != 0 || d.Frequency != 0 {
		t.Fatalf("zero DelayedSACK = %+v, want both fields 0", d)
	}
}

func TestPathParamsZeroValueLeavesEverythingUnchanged(t *testing.T) {
	var p PathParams
	v := reflect.ValueOf(p)
	for i := 0; i < v.NumField(); i++ {
		if !v.Field(i).IsNil() {
			t.Fatalf("PathParams.%s is not nil in the zero value: %+v", v.Type().Field(i).Name, p)
		}
	}
}

func TestPathThresholdsZeroValueLeavesEverythingUnchanged(t *testing.T) {
	var p PathThresholds
	if p.PathMaxRetrans != nil || p.PFThreshold != nil || p.PrimarySwitchover != nil {
		t.Fatalf("zero PathThresholds = %+v, want every field nil", p)
	}
}

// --- kernel tick fields: raw integers, not durations ------------------------

func TestPathInfoSRTTTicksIsRawUint32(t *testing.T) {
	field, ok := reflect.TypeOf(PathInfo{}).FieldByName("SRTTTicks")
	if !ok {
		t.Fatal("PathInfo has no SRTTTicks field")
	}
	if field.Type.Kind() != reflect.Uint32 {
		t.Fatalf("PathInfo.SRTTTicks has kind %v, want uint32 (spinfo_srtt, __u32)", field.Type.Kind())
	}
}

func TestAssocStatsMaxRTOTicksIsRawUint64(t *testing.T) {
	field, ok := reflect.TypeOf(AssocStats{}).FieldByName("MaxRTOTicks")
	if !ok {
		t.Fatal("AssocStats has no MaxRTOTicks field")
	}
	if field.Type.Kind() != reflect.Uint64 {
		t.Fatalf("AssocStats.MaxRTOTicks has kind %v, want uint64 (sas_maxrto, __u64)", field.Type.Kind())
	}
}

// TestAssocStatsHasFifteenCounters pins the field count abi.go's
// sizeAssocStats formula assumes (sizeAssocStatsHeader + 15*8): one uint64
// per counter Linux's struct sctp_assoc_stats carries after the address,
// MaxRTOTicks included. A field added or removed here without updating that
// formula would silently desynchronize the two.
func TestAssocStatsHasFifteenCounters(t *testing.T) {
	typ := reflect.TypeOf(AssocStats{})
	count := 0
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type.Kind() == reflect.Uint64 {
			count++
		}
	}
	if count != 15 {
		t.Fatalf("AssocStats has %d uint64 fields, want 15 (abi.go: sizeAssocStatsHeader + 15*8)", count)
	}
}

// --- validatePrInfo: shared between SendOptions.PR and Config.DefaultPrInfo -

func TestValidatePrInfoAcceptsKnownPolicies(t *testing.T) {
	tests := []PrInfo{
		{Policy: PRNone},
		{Policy: PRTTL, TTL: 500 * time.Millisecond},
		{Policy: PRTTL, TTL: 0},
		{Policy: PRRtx, Value: 3},
		{Policy: PRPrio, Value: 1},
	}
	for _, pr := range tests {
		pr := pr
		if err := validatePrInfo("SendOptions.PR", &pr); err != nil {
			t.Errorf("validatePrInfo(%+v): %v", pr, err)
		}
	}
}

func TestValidatePrInfoRefusesPRAll(t *testing.T) {
	err := validatePrInfo("SendOptions.PR", &PrInfo{Policy: PRAll})
	wantRefused(t, err, "SendOptions.PR.Policy")
}

func TestValidatePrInfoRefusesUnknownPolicyBits(t *testing.T) {
	err := validatePrInfo("SendOptions.PR", &PrInfo{Policy: PRPolicy(0x0031)})
	wantRefused(t, err, "SendOptions.PR.Policy")
}

func TestValidatePrInfoRefusesNegativeTTL(t *testing.T) {
	err := validatePrInfo("SendOptions.PR", &PrInfo{Policy: PRTTL, TTL: -time.Millisecond})
	wantRefused(t, err, "SendOptions.PR.TTL")
}

func TestValidatePrInfoRefusesFractionalTTL(t *testing.T) {
	err := validatePrInfo("SendOptions.PR", &PrInfo{Policy: PRTTL, TTL: 1500 * time.Microsecond})
	wantRefused(t, err, "SendOptions.PR.TTL")
}

func TestValidatePrInfoRefusesTTLOverflow(t *testing.T) {
	huge := time.Duration(uint64(math.MaxUint32)+1) * time.Millisecond
	err := validatePrInfo("SendOptions.PR", &PrInfo{Policy: PRTTL, TTL: huge})
	wantRefused(t, err, "SendOptions.PR.TTL")
}

func TestValidatePrInfoAcceptsExactMaxTTL(t *testing.T) {
	max := time.Duration(math.MaxUint32) * time.Millisecond
	if err := validatePrInfo("SendOptions.PR", &PrInfo{Policy: PRTTL, TTL: max}); err != nil {
		t.Fatalf("validatePrInfo at exact max: %v", err)
	}
}

// TestValidatePrInfoNamesTheCallersField confirms the same function reports
// each caller's own field path, which is the point of sharing it rather
// than copying it: Config.DefaultPrInfo's validation (config.go) and
// SendOptions.PR's validation (msginfo.go's validateSendOptions) go through
// this one function and differ only in what they pass as field.
func TestValidatePrInfoNamesTheCallersField(t *testing.T) {
	err := validatePrInfo("Config.DefaultPrInfo", &PrInfo{Policy: PRAll})
	wantRefused(t, err, "Config.DefaultPrInfo.Policy")

	err = validateSendOptions(&SendOptions{PR: &PrInfo{Policy: PRAll}})
	wantRefused(t, err, "SendOptions.PR.Policy")
}

// --- resolvePrInfo: shared between appendSendCmsgs and Config.DefaultPrInfo -

func TestResolvePrInfo(t *testing.T) {
	tests := []struct {
		name       string
		pr         PrInfo
		wantPolicy uint16
		wantValue  uint32
	}{
		{"PRNone ignores TTL and Value", PrInfo{Policy: PRNone, TTL: time.Second, Value: 5}, uint16(PRNone), 0},
		{"PRTTL converts to ms", PrInfo{Policy: PRTTL, TTL: 1500 * time.Millisecond}, uint16(PRTTL), 1500},
		{"PRRtx keeps Value", PrInfo{Policy: PRRtx, Value: 4}, uint16(PRRtx), 4},
		{"PRPrio keeps Value", PrInfo{Policy: PRPrio, Value: 2}, uint16(PRPrio), 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pr := tc.pr
			policy, value := resolvePrInfo(&pr)
			if policy != tc.wantPolicy || value != tc.wantValue {
				t.Errorf("resolvePrInfo(%+v) = (%d, %d), want (%d, %d)", tc.pr, policy, value, tc.wantPolicy, tc.wantValue)
			}
		})
	}
}
