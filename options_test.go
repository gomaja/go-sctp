// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
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

// --- the word-size-dependent option structs ------------------------------

// TestStorageLayoutsPinOffsets pins both layouts the five word-size-dependent
// structs (sctp_udpencaps, sctp_probeinterval, sctp_paddrthlds_v2,
// sctp_paddrthlds for the probe, sctp_assoc_stats) can take: the native one
// follows the abi.go constants of this build, and the kernel64 one is the
// shape a 64-bit kernel always uses, the same numbers on every build.
func TestStorageLayoutsPinOffsets(t *testing.T) {
	native := nativeStorageLayout
	checkNumbers(t, []numberCase{
		{"native addr", native.addrOff, ssAddrOffset},
		{"native udpEncapsPort", native.udpEncapsPortOff, udpEncapsPortOff},
		{"native sizeUDPEncaps", native.sizeUDPEncaps, sizeUDPEncaps},
		{"native probeInterval", native.probeIntervalOff, probeIntervalIntervalOff},
		{"native sizeProbeInterval", native.sizeProbeInterval, sizeProbeInterval},
		{"native thresholdsMaxRetrans", native.thresholdsMaxRetransOff, pathThresholdsMaxRxtOff},
		{"native thresholdsPF", native.thresholdsPFOff, pathThresholdsPFThresholdOff},
		{"native thresholdsSwitchover", native.thresholdsSwitchoverOff, pathThresholdsSwitchoverOff},
		{"native sizePathThresholds", native.sizePathThresholds, sizePathThresholds},
		{"native statsCounters", native.statsCountersOff, sizeAssocStatsHeader},
		{"native sizeAssocStats", native.sizeAssocStats, sizeAssocStats},
	})
	wide := kernel64StorageLayout
	checkNumbers(t, []numberCase{
		{"kernel64 addr", wide.addrOff, 8},
		{"kernel64 udpEncapsPort", wide.udpEncapsPortOff, 136},
		{"kernel64 sizeUDPEncaps", wide.sizeUDPEncaps, 144},
		{"kernel64 probeInterval", wide.probeIntervalOff, 136},
		{"kernel64 sizeProbeInterval", wide.sizeProbeInterval, 144},
		{"kernel64 thresholdsMaxRetrans", wide.thresholdsMaxRetransOff, 136},
		{"kernel64 thresholdsPF", wide.thresholdsPFOff, 138},
		{"kernel64 thresholdsSwitchover", wide.thresholdsSwitchoverOff, 140},
		{"kernel64 sizePathThresholds", wide.sizePathThresholds, 144},
		{"kernel64 statsCounters", wide.statsCountersOff, 136},
		{"kernel64 sizeAssocStats", wide.sizeAssocStats, 256},
	})
	if wordSize == 8 && native != wide {
		t.Errorf("on a 64-bit build the native layout %+v differs from the kernel64 one %+v", native, wide)
	}
}

// storageLayouts is both layouts, each with the byte offsets a C probe over
// <linux/sctp.h> measured for it: every test below encodes and decodes
// through both on every build, whatever word size the build itself has.
func storageLayouts() []struct {
	name string
	l    *sockaddrStorageLayout
	addr int // where sockaddr_storage starts
	tail int // just past it
} {
	return []struct {
		name string
		l    *sockaddrStorageLayout
		addr int
		tail int
	}{
		{"native", &nativeStorageLayout, ssAddrOffset, ssTailOffset},
		{"kernel64", &kernel64StorageLayout, 8, 136},
	}
}

// patternedStorage is a sockaddr_storage-sized address with a distinct
// byte in every position, so that an address copied to the wrong offset
// shows.
func patternedStorage() []byte {
	b := make([]byte, sizeSockaddrStorage)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

func TestUDPEncapsBothLayouts(t *testing.T) {
	for _, tc := range storageLayouts() {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, sizeUDPEncapsKernel64)
			b := tc.l.udpEncaps(buf, 0x11223344, patternedStorage(), 9899)
			if len(b) != tc.l.sizeUDPEncaps {
				t.Fatalf("encoded %d bytes, want %d", len(b), tc.l.sizeUDPEncaps)
			}
			if got := binary.NativeEndian.Uint32(b[0:]); got != 0x11223344 {
				t.Errorf("sue_assoc_id = %#x at 0, want 0x11223344", got)
			}
			if !bytes.Equal(b[tc.addr:tc.addr+sizeSockaddrStorage], patternedStorage()) {
				t.Errorf("sue_address is not at offset %d", tc.addr)
			}
			// RFC 6951 §6.1: sue_port is in network byte order, and Linux
			// stores it as it comes (net/sctp/socket.c:
			// sctp_setsockopt_encap_port casts it to __be16). 9899 is
			// 0x26ab, which a native-order write would put as ab 26 on a
			// little-endian host.
			if b[tc.tail] != 0x26 || b[tc.tail+1] != 0xab {
				t.Errorf("sue_port at %d = % x, want 26 ab", tc.tail, b[tc.tail:tc.tail+2])
			}
			if got := tc.l.udpEncapsPort(b); got != 9899 {
				t.Errorf("decoded port = %d, want 9899", got)
			}
		})
	}
}

func TestProbeIntervalBothLayouts(t *testing.T) {
	for _, tc := range storageLayouts() {
		t.Run(tc.name, func(t *testing.T) {
			buf := make([]byte, sizeProbeIntervalKernel64)
			b := tc.l.probeInterval(buf, 0x11223344, patternedStorage(), 0x55667788)
			if len(b) != tc.l.sizeProbeInterval {
				t.Fatalf("encoded %d bytes, want %d", len(b), tc.l.sizeProbeInterval)
			}
			if got := binary.NativeEndian.Uint32(b[0:]); got != 0x11223344 {
				t.Errorf("spi_assoc_id = %#x, want 0x11223344", got)
			}
			if !bytes.Equal(b[tc.addr:tc.addr+sizeSockaddrStorage], patternedStorage()) {
				t.Errorf("spi_address is not at offset %d", tc.addr)
			}
			if got := binary.NativeEndian.Uint32(b[tc.tail:]); got != 0x55667788 {
				t.Errorf("spi_interval at %d = %#x, want 0x55667788", tc.tail, got)
			}
			if got := tc.l.probeIntervalMS(b); got != 0x55667788 {
				t.Errorf("decoded interval = %#x, want 0x55667788", got)
			}
		})
	}
}

func TestPathThresholdsBothLayouts(t *testing.T) {
	for _, tc := range storageLayouts() {
		t.Run(tc.name, func(t *testing.T) {
			want := thresholdValues{maxRetrans: 0x5566, pf: 0x7788, switchover: 0x99aa}
			buf := make([]byte, sizePathThresholdsKernel64)
			b := tc.l.pathThresholds(buf, 0x11223344, patternedStorage(), want)
			if len(b) != tc.l.sizePathThresholds {
				t.Fatalf("encoded %d bytes, want %d", len(b), tc.l.sizePathThresholds)
			}
			if got := binary.NativeEndian.Uint32(b[0:]); got != 0x11223344 {
				t.Errorf("spt_assoc_id = %#x, want 0x11223344", got)
			}
			if !bytes.Equal(b[tc.addr:tc.addr+sizeSockaddrStorage], patternedStorage()) {
				t.Errorf("spt_address is not at offset %d", tc.addr)
			}
			for _, f := range []struct {
				name string
				off  int
				want uint16
			}{
				{"spt_pathmaxrxt", tc.tail, 0x5566},
				{"spt_pathpfthld", tc.tail + 2, 0x7788},
				{"spt_pathcpthld", tc.tail + 4, 0x99aa},
			} {
				if got := binary.NativeEndian.Uint16(b[f.off:]); got != f.want {
					t.Errorf("%s at %d = %#x, want %#x", f.name, f.off, got, f.want)
				}
			}
			if got := tc.l.thresholdValues(b); got != want {
				t.Errorf("decoded %+v, want %+v", got, want)
			}
		})
	}
}

// TestAssocStatsBothLayouts decodes struct sctp_assoc_stats from buffers
// laid out as each layout puts it, with a distinct value in every counter,
// so that two swapped counters show. It is also the decoding half of v1's
// layout test, which pinned the struct's size but had no AssocStats to
// decode into.
func TestAssocStatsBothLayouts(t *testing.T) {
	for _, tc := range storageLayouts() {
		t.Run(tc.name, func(t *testing.T) {
			b := make([]byte, sizeAssocStatsKernel64)
			req := tc.l.assocStatsRequest(b, 0x11223344)
			if len(req) != tc.l.sizeAssocStats {
				t.Fatalf("request is %d bytes, want %d", len(req), tc.l.sizeAssocStats)
			}
			if got := binary.NativeEndian.Uint32(req[0:]); got != 0x11223344 {
				t.Errorf("sas_assoc_id = %#x, want 0x11223344", got)
			}
			if _, err := encodeAddr(req[tc.addr:], afInet, netip.MustParseAddr("192.0.2.7"), 5000); err != nil {
				t.Fatal(err)
			}
			header := tc.l.statsCountersOff
			for i := 0; i < assocStatsCounters; i++ {
				binary.NativeEndian.PutUint64(req[header+8*i:], uint64(i+1)<<40|uint64(i+1))
			}
			v := func(i int) uint64 { return uint64(i+1)<<40 | uint64(i+1) }
			want := AssocStats{
				MaxRTOTicks:        v(assocStatsMaxRTO),
				MaxRTOAddr:         netip.MustParseAddrPort("192.0.2.7:5000"),
				SACKsIn:            v(assocStatsISACKs),
				SACKsOut:           v(assocStatsOSACKs),
				PacketsOut:         v(assocStatsOPackets),
				PacketsIn:          v(assocStatsIPackets),
				RetransChunks:      v(assocStatsRtxChunks),
				OutOfSeqTSNs:       v(assocStatsOutOfSeqTSNs),
				DupChunksIn:        v(assocStatsIDupChunks),
				GapAcksIn:          v(assocStatsGapCount),
				UnorderedChunksOut: v(assocStatsOUODChunks),
				UnorderedChunksIn:  v(assocStatsIUODChunks),
				OrderedChunksOut:   v(assocStatsOODChunks),
				OrderedChunksIn:    v(assocStatsIODChunks),
				ControlChunksOut:   v(assocStatsOCtrlChunks),
				ControlChunksIn:    v(assocStatsICtrlChunks),
			}
			if got := tc.l.assocStats(req); got != want {
				t.Errorf("decoded\n %+v\nwant\n %+v", got, want)
			}
		})
	}
}

// TestAssocStatsWithoutObservedRTO: before any RTO update Linux leaves
// sas_obs_rto_ipaddr as whatever the association holds, zero at first
// (net/sctp/socket.c: sctp_getsockopt_assoc_stats says it "will be bogus
// in such a case"). An address no family names decodes to the zero
// AddrPort, never to an error.
func TestAssocStatsWithoutObservedRTO(t *testing.T) {
	for _, tc := range storageLayouts() {
		b := make([]byte, sizeAssocStatsKernel64)
		s := tc.l.assocStats(tc.l.assocStatsRequest(b, 3))
		if s.MaxRTOAddr.IsValid() {
			t.Errorf("%s: MaxRTOAddr = %v for a zero address, want the zero AddrPort", tc.name, s.MaxRTOAddr)
		}
	}
}

// TestSelectStorageLayout: the probe's answer picks the layout once and is
// kept; an answer that is neither leaves nothing cached and is returned, so
// the next call asks again.
func TestSelectStorageLayout(t *testing.T) {
	cases := []struct {
		name  string
		probe error
		want  *sockaddrStorageLayout
	}{
		{"a 32-bit kernel accepts the native size", nil, &nativeStorageLayout},
		{"a 64-bit kernel refuses it with EINVAL", syscall.EINVAL, &kernel64StorageLayout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cache atomic.Uint32
			calls := 0
			probe := func() error { calls++; return tc.probe }
			for i := 0; i < 3; i++ {
				l, err := selectStorageLayout(&cache, probe)
				if err != nil || l != tc.want {
					t.Fatalf("call %d: layout %p, %v; want %p, nil", i, l, err, tc.want)
				}
			}
			if calls != 1 {
				t.Errorf("the probe ran %d times, want once", calls)
			}
		})
	}

	t.Run("any other error is returned and not cached", func(t *testing.T) {
		var cache atomic.Uint32
		calls := 0
		probe := func() error { calls++; return syscall.ENOPROTOOPT }
		for i := 0; i < 2; i++ {
			l, err := selectStorageLayout(&cache, probe)
			if l != nil || !errors.Is(err, syscall.ENOPROTOOPT) {
				t.Fatalf("call %d: layout %p, %v; want nil, ENOPROTOOPT", i, l, err)
			}
		}
		if calls != 2 {
			t.Errorf("the probe ran %d times, want twice: a failed probe caches nothing", calls)
		}
		l, err := selectStorageLayout(&cache, func() error { calls++; return nil })
		if err != nil || l != &nativeStorageLayout {
			t.Errorf("after the failures: layout %p, %v; want the native one", l, err)
		}
	})
}

// --- path addresses ------------------------------------------------------------

// TestEncodePathAddr: the zero address encodes to nothing, which Linux reads
// as "the association as a whole" (net/sctp/bind_addr.c: sctp_is_any); an
// IPv4 path goes mapped on an AF_INET6 socket; and a link-local path
// without a zone gets the association's link-local scope id, when it has
// one (linkLocalPathScope), since Linux refuses a link-local path with
// scope id 0 (net/sctp/ipv6.c: sctp_inet6_send_verify) but matches a peer
// address stored with scope 0 against any scope (__sctp_v6_cmp_addr).
func TestEncodePathAddr(t *testing.T) {
	var b [sizeSockaddrIn6]byte

	n, err := encodePathAddr(b[:], afInet6, netip.Addr{}, 9, 7)
	if err != nil || n != 0 {
		t.Errorf("zero address: %d bytes, %v; want 0, nil", n, err)
	}

	n, err = encodePathAddr(b[:], afInet6, netip.MustParseAddr("fe80::2"), 9, 7)
	if err != nil || n != sizeSockaddrIn6 {
		t.Fatalf("zoneless link-local: %d bytes, %v", n, err)
	}
	if scope := binary.NativeEndian.Uint32(b[sockaddrIn6ScopeIDOff:]); scope != 7 {
		t.Errorf("zoneless link-local path got scope id %d, want 7, the association's", scope)
	}
	if port := binary.BigEndian.Uint16(b[sockaddrIn6PortOff:]); port != 9 {
		t.Errorf("port = %d, want 9", port)
	}

	n, err = encodePathAddr(b[:], afInet6, netip.MustParseAddr("fe80::2%3"), 9, 7)
	if err != nil || n != sizeSockaddrIn6 || binary.NativeEndian.Uint32(b[sockaddrIn6ScopeIDOff:]) != 3 {
		t.Errorf("zoned link-local: %d bytes, %v, scope %d; want its own scope 3", n, err, binary.NativeEndian.Uint32(b[sockaddrIn6ScopeIDOff:]))
	}

	n, err = encodePathAddr(b[:], afInet6, netip.MustParseAddr("fe80::2"), 9, 0)
	if err != nil || n != sizeSockaddrIn6 || binary.NativeEndian.Uint32(b[sockaddrIn6ScopeIDOff:]) != 0 {
		t.Errorf("no link-local scope for the association: %d bytes, %v; want the path unchanged, scope 0", n, err)
	}

	// IPv4 link-local 169.254/16, plain or IPv4-mapped, has no IPv6 scope.
	for _, ip := range []string{"2001:db8::1", "::1", "169.254.1.1", "::ffff:169.254.1.1"} {
		n, err = encodePathAddr(b[:], afInet6, netip.MustParseAddr(ip), 9, 7)
		if err != nil || n != sizeSockaddrIn6 || binary.NativeEndian.Uint32(b[sockaddrIn6ScopeIDOff:]) != 0 {
			t.Errorf("%s: %d bytes, %v, scope %d; want no scope on an address that is not link-local", ip, n, err, binary.NativeEndian.Uint32(b[sockaddrIn6ScopeIDOff:]))
		}
	}

	n, err = encodePathAddr(b[:], afInet6, netip.MustParseAddr("127.0.0.2"), 9, 7)
	if err != nil || n != sizeSockaddrIn6 || !netip.AddrFrom16([16]byte(b[sockaddrIn6AddrOff:sockaddrIn6AddrOff+16])).Is4In6() {
		t.Errorf("IPv4 on AF_INET6: %d bytes, %v; want an IPv4-mapped entry", n, err)
	}

	if _, err := encodePathAddr(b[:], afInet, netip.MustParseAddr("::1"), 9, 0); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("IPv6 on AF_INET = %v, want EINVAL", err)
	}
}

// TestLinkLocalPathScope pins the rule that picks the scope id a
// link-local path without a zone gets: the zones of the association's
// zoned local link-local addresses, else those of its zoned peer
// link-local addresses, else the interfaces that hold its zoneless local
// link-local addresses; the first of these that finds any zone decides,
// and a scope id is given only when it finds exactly one. Zones here are
// decimal interface indexes, so that no host interface is involved.
func TestLinkLocalPathScope(t *testing.T) {
	holders := map[string][]uint32{
		"fe80::1": {7}, "fe80::2": {7}, "fe80::9": {8}, "fe80::5": {7, 8},
	}
	owners := func(ip netip.Addr) []uint32 { return holders[ip.WithZone("").String()] }
	addrs := func(s ...string) []netip.Addr {
		ips := make([]netip.Addr, len(s))
		for i, a := range s {
			ips[i] = netip.MustParseAddr(a)
		}
		return ips
	}
	cases := []struct {
		name        string
		local, peer []netip.Addr
		want        uint32
	}{
		{"one zoned local link-local", addrs("::1", "fe80::1%7"), addrs("fe80::4"), 7},
		{"zoned local link-locals of one link", addrs("fe80::1%7", "fe80::2%7"), nil, 7},
		{"zoned local link-locals of two links", addrs("fe80::1%7", "fe80::9%8"), addrs("fe80::4%7"), 0},
		{"local zones decide before peer zones", addrs("fe80::1%7"), addrs("fe80::4%8"), 7},
		{"no zoned local, one zoned peer", addrs("::1", "fe80::1"), addrs("fe80::4%7", "fe80::6"), 7},
		{"no zoned local, zoned peers of two links", addrs("fe80::1"), addrs("fe80::4%7", "fe80::6%8"), 0},
		{"zoneless local link-locals of one interface", addrs("::1", "fe80::1", "fe80::2"), addrs("::1", "fe80::4"), 7},
		{"zoneless local link-locals of two interfaces", addrs("fe80::1", "fe80::9"), addrs("::1"), 0},
		{"a local link-local two interfaces hold", addrs("fe80::5"), nil, 0},
		{"a local link-local no interface holds", addrs("fe80::6"), nil, 0},
		{"no link-local address", addrs("127.0.0.1", "::1", "2001:db8::1"), addrs("::1"), 0},
		{"nothing", nil, nil, 0},
	}
	for _, tc := range cases {
		if got := linkLocalPathScope(tc.local, tc.peer, owners); got != tc.want {
			t.Errorf("%s: scope %d, want %d", tc.name, got, tc.want)
		}
	}
}

// --- PathParams ------------------------------------------------------------------

func TestEncodePathParams(t *testing.T) {
	type want struct {
		flags     uint32
		hb        uint32
		maxRetx   uint16
		mtu       uint32
		sackDelay uint32
		flowLabel uint32
		dscp      uint8
	}
	cases := []struct {
		name string
		p    PathParams
		want want
	}{
		{"nothing set changes nothing", PathParams{}, want{}},
		{"heartbeat on", PathParams{Heartbeat: ptr(true)}, want{flags: sppHBEnable}},
		{"heartbeat off", PathParams{Heartbeat: ptr(false)}, want{flags: sppHBDisable}},
		{"interval with heartbeat on", PathParams{Heartbeat: ptr(true), HeartbeatInterval: ptr(5 * time.Second)}, want{flags: sppHBEnable, hb: 5000}},
		{"zero interval", PathParams{Heartbeat: ptr(true), HeartbeatInterval: ptr(time.Duration(0))}, want{flags: sppHBEnable | sppHBTimeIsZero}},
		{"path max retrans", PathParams{PathMaxRetrans: ptr(uint16(7))}, want{maxRetx: 7}},
		{"PMTUD on", PathParams{PMTUD: ptr(true)}, want{flags: sppPMTUDEnable}},
		{"fixed path MTU", PathParams{PMTUD: ptr(false), PathMTU: ptr(uint32(1280))}, want{flags: sppPMTUDDisable, mtu: 1280}},
		{"delayed SACK off", PathParams{DelayedSACK: ptr(false)}, want{flags: sppSACKDelayDisable}},
		{"SACK delay", PathParams{DelayedSACK: ptr(true), SACKDelay: ptr(300 * time.Millisecond)}, want{flags: sppSACKDelayEnable, sackDelay: 300}},
		{"flow label", PathParams{IPv6FlowLabel: ptr(uint32(0xfffff))}, want{flags: sppIPv6FlowLabel, flowLabel: 0xfffff}},
		{"DSCP", PathParams{DSCP: ptr(uint8(0xb8))}, want{flags: sppDSCP, dscp: 0xb8}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b [sizePathParams]byte
			if err := encodePathParams(b[:], 0x11223344, patternedStorage()[:sizeSockaddrIn6], &tc.p, "PathParams"); err != nil {
				t.Fatalf("encodePathParams: %v", err)
			}
			got := want{
				flags:     binary.NativeEndian.Uint32(b[pathParamsFlagsOff:]),
				hb:        binary.NativeEndian.Uint32(b[pathParamsHBIntervalOff:]),
				maxRetx:   binary.NativeEndian.Uint16(b[pathParamsPathMaxRxtOff:]),
				mtu:       binary.NativeEndian.Uint32(b[pathParamsPathMTUOff:]),
				sackDelay: binary.NativeEndian.Uint32(b[pathParamsSackDelayOff:]),
				flowLabel: binary.NativeEndian.Uint32(b[pathParamsFlowLabelOff:]),
				dscp:      b[pathParamsDSCPOff],
			}
			if got != tc.want {
				t.Errorf("encoded %+v, want %+v", got, tc.want)
			}
			if a := binary.NativeEndian.Uint32(b[pathParamsAssocIDOff:]); a != 0x11223344 {
				t.Errorf("spp_assoc_id = %#x", a)
			}
			if !bytes.Equal(b[pathParamsAddressOff:pathParamsAddressOff+sizeSockaddrIn6], patternedStorage()[:sizeSockaddrIn6]) {
				t.Error("spp_address is not at its offset")
			}
		})
	}
}

// TestEncodePathParamsRefusals: every combination Linux would ignore or
// refuse is refused before any system call, naming the field. A zero
// PathMaxRetrans, PathMTU or SACKDelay is what Linux reads as "leave it
// alone", and a HeartbeatInterval, PathMTU or SACKDelay only takes effect
// with the matching switch in the same call (net/sctp/socket.c:
// sctp_apply_peer_addr_params).
func TestEncodePathParamsRefusals(t *testing.T) {
	cases := []struct {
		name  string
		p     PathParams
		field string
	}{
		{"interval without heartbeat", PathParams{HeartbeatInterval: ptr(time.Second)}, "PathParams.HeartbeatInterval"},
		{"interval with heartbeat off", PathParams{Heartbeat: ptr(false), HeartbeatInterval: ptr(time.Second)}, "PathParams.HeartbeatInterval"},
		{"negative interval", PathParams{Heartbeat: ptr(true), HeartbeatInterval: ptr(-time.Second)}, "PathParams.HeartbeatInterval"},
		{"fractional interval", PathParams{Heartbeat: ptr(true), HeartbeatInterval: ptr(1500 * time.Microsecond)}, "PathParams.HeartbeatInterval"},
		{"interval beyond uint32", PathParams{Heartbeat: ptr(true), HeartbeatInterval: ptr(time.Duration(math.MaxUint32+1) * time.Millisecond)}, "PathParams.HeartbeatInterval"},
		{"zero path max retrans", PathParams{PathMaxRetrans: ptr(uint16(0))}, "PathParams.PathMaxRetrans"},
		{"MTU without PMTUD off", PathParams{PathMTU: ptr(uint32(1280))}, "PathParams.PathMTU"},
		{"MTU with PMTUD on", PathParams{PMTUD: ptr(true), PathMTU: ptr(uint32(1280))}, "PathParams.PathMTU"},
		{"MTU below the minimum", PathParams{PMTUD: ptr(false), PathMTU: ptr(uint32(511))}, "PathParams.PathMTU"},
		{"zero MTU", PathParams{PMTUD: ptr(false), PathMTU: ptr(uint32(0))}, "PathParams.PathMTU"},
		{"SACK delay without delayed SACK", PathParams{SACKDelay: ptr(200 * time.Millisecond)}, "PathParams.SACKDelay"},
		{"SACK delay with delayed SACK off", PathParams{DelayedSACK: ptr(false), SACKDelay: ptr(200 * time.Millisecond)}, "PathParams.SACKDelay"},
		{"zero SACK delay", PathParams{DelayedSACK: ptr(true), SACKDelay: ptr(time.Duration(0))}, "PathParams.SACKDelay"},
		{"SACK delay over 500 ms", PathParams{DelayedSACK: ptr(true), SACKDelay: ptr(501 * time.Millisecond)}, "PathParams.SACKDelay"},
		{"fractional SACK delay", PathParams{DelayedSACK: ptr(true), SACKDelay: ptr(1500 * time.Microsecond)}, "PathParams.SACKDelay"},
		{"flow label beyond 20 bits", PathParams{IPv6FlowLabel: ptr(uint32(0x100000))}, "PathParams.IPv6FlowLabel"},
		{"DSCP in the low bits", PathParams{DSCP: ptr(uint8(46))}, "PathParams.DSCP"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b [sizePathParams]byte
			wantRefused(t, encodePathParams(b[:], 0, nil, &tc.p, "PathParams"), tc.field)
		})
	}
}

func TestDecodePathParams(t *testing.T) {
	var b [sizePathParams]byte
	binary.NativeEndian.PutUint32(b[pathParamsHBIntervalOff:], 30000)
	binary.NativeEndian.PutUint16(b[pathParamsPathMaxRxtOff:], 5)
	binary.NativeEndian.PutUint32(b[pathParamsPathMTUOff:], 65496)
	binary.NativeEndian.PutUint32(b[pathParamsSackDelayOff:], 200)
	binary.NativeEndian.PutUint32(b[pathParamsFlagsOff:], sppHBEnable|sppPMTUDDisable|sppSACKDelayEnable)
	binary.NativeEndian.PutUint32(b[pathParamsFlowLabelOff:], 0x12345)
	b[pathParamsDSCPOff] = 0xb8

	got := decodePathParams(b[:])
	want := PathParams{
		Heartbeat:         ptr(true),
		HeartbeatInterval: ptr(30 * time.Second),
		PathMaxRetrans:    ptr(uint16(5)),
		PMTUD:             ptr(false),
		PathMTU:           ptr(uint32(65496)),
		DelayedSACK:       ptr(true),
		SACKDelay:         ptr(200 * time.Millisecond),
	}
	if !reflect.DeepEqual(*got, want) {
		t.Errorf("decoded %s, want %s (the flow label and DSCP are reported only with their flags)", pathParamsString(got), pathParamsString(&want))
	}

	binary.NativeEndian.PutUint32(b[pathParamsFlagsOff:], sppHBDisable|sppPMTUDEnable|sppSACKDelayDisable|sppIPv6FlowLabel|sppDSCP)
	got = decodePathParams(b[:])
	if *got.Heartbeat || !*got.PMTUD || *got.DelayedSACK {
		t.Errorf("switches decoded as %s, want heartbeat off, PMTUD on, delayed SACK off", pathParamsString(got))
	}
	if got.IPv6FlowLabel == nil || *got.IPv6FlowLabel != 0x12345 || got.DSCP == nil || *got.DSCP != 0xb8 {
		t.Errorf("flow label and DSCP decoded as %s, want 0x12345 and 0xb8", pathParamsString(got))
	}
}

// pathParamsString prints a PathParams with its pointers followed.
func pathParamsString(p *PathParams) string {
	var s strings.Builder
	v := reflect.ValueOf(p).Elem()
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		fmt.Fprintf(&s, "%s=", v.Type().Field(i).Name)
		if f.IsNil() {
			s.WriteString("nil ")
		} else {
			fmt.Fprintf(&s, "%v ", f.Elem().Interface())
		}
	}
	return s.String()
}

func TestHeartbeatDemand(t *testing.T) {
	var b [sizePathParams]byte
	heartbeatDemand(b[:], 5, patternedStorage()[:sizeSockaddrIn])
	if f := binary.NativeEndian.Uint32(b[pathParamsFlagsOff:]); f != sppHBDemand {
		t.Errorf("spp_flags = %#x, want SPP_HB_DEMAND alone", f)
	}
	if a := binary.NativeEndian.Uint32(b[pathParamsAssocIDOff:]); a != 5 {
		t.Errorf("spp_assoc_id = %d, want 5", a)
	}
	if !bytes.Equal(b[pathParamsAddressOff:pathParamsAddressOff+sizeSockaddrIn], patternedStorage()[:sizeSockaddrIn]) {
		t.Error("spp_address is not at its offset")
	}
}

// --- thresholds ----------------------------------------------------------------

// TestMergePathThresholds: a nil field keeps the value read from the kernel,
// which is how SetPathThresholds leaves it unchanged, since Linux applies
// the PF and switchover thresholds whatever their value
// (net/sctp/socket.c: sctp_setsockopt_paddr_thresholds).
func TestMergePathThresholds(t *testing.T) {
	cur := thresholdValues{maxRetrans: 5, pf: 3, switchover: 0xffff}
	cases := []struct {
		name string
		t    PathThresholds
		want thresholdValues
	}{
		{"nothing set", PathThresholds{}, cur},
		{"PF only", PathThresholds{PFThreshold: ptr(uint16(2))}, thresholdValues{5, 2, 0xffff}},
		{"switchover only", PathThresholds{PrimarySwitchover: ptr(uint16(4))}, thresholdValues{5, 3, 4}},
		{"max retrans only", PathThresholds{PathMaxRetrans: ptr(uint16(9))}, thresholdValues{9, 3, 0xffff}},
		{"all", PathThresholds{PathMaxRetrans: ptr(uint16(8)), PFThreshold: ptr(uint16(0)), PrimarySwitchover: ptr(uint16(1))}, thresholdValues{8, 0, 1}},
	}
	for _, tc := range cases {
		got, err := mergePathThresholds(cur, &tc.t, "PathThresholds")
		if err != nil || got != tc.want {
			t.Errorf("%s: %+v, %v; want %+v", tc.name, got, err, tc.want)
		}
	}
	_, err := mergePathThresholds(cur, &PathThresholds{PathMaxRetrans: ptr(uint16(0))}, "PathThresholds")
	wantRefused(t, err, "PathThresholds.PathMaxRetrans")
}

// --- association structs ----------------------------------------------------

func TestDecodePathInfo(t *testing.T) {
	var b [sizePathInfo]byte
	binary.NativeEndian.PutUint32(b[pathInfoAssocIDOff:], 3)
	if _, err := encodeAddr(b[pathInfoAddressOff:], afInet6, netip.MustParseAddr("10.1.2.3"), 7000); err != nil {
		t.Fatal(err)
	}
	binary.NativeEndian.PutUint32(b[pathInfoStateOff:], uint32(PathActive))
	binary.NativeEndian.PutUint32(b[pathInfoCwndOff:], 0x11111111)
	binary.NativeEndian.PutUint32(b[pathInfoSRTTOff:], 0x22222222)
	binary.NativeEndian.PutUint32(b[pathInfoRTOOff:], 3000)
	binary.NativeEndian.PutUint32(b[pathInfoMTUOff:], 0x44444444)
	want := PathInfo{
		Addr:      netip.MustParseAddrPort("10.1.2.3:7000"),
		State:     PathActive,
		Cwnd:      0x11111111,
		SRTTTicks: 0x22222222, // spinfo_srtt, copied as it is
		RTO:       3 * time.Second,
		MTU:       0x44444444,
	}
	if got := decodePathInfo(b[:]); got != want {
		t.Errorf("decoded %+v, want %+v", got, want)
	}
}

func TestDecodeStatus(t *testing.T) {
	var b [sizeStatus]byte
	binary.NativeEndian.PutUint32(b[statusAssocIDOff:], 9)
	binary.NativeEndian.PutUint32(b[statusStateOff:], uint32(StateShutdownPending))
	binary.NativeEndian.PutUint32(b[statusRWNDOff:], 0x01020304)
	binary.NativeEndian.PutUint16(b[statusUnackedOff:], 0x0506)
	binary.NativeEndian.PutUint16(b[statusPendingOff:], 0x0708)
	binary.NativeEndian.PutUint16(b[statusInStreamsOff:], 0x090a)
	binary.NativeEndian.PutUint16(b[statusOutStreamsOff:], 0x0b0c)
	binary.NativeEndian.PutUint32(b[statusFragmentationPointOff:], 0x0d0e0f10)
	p := b[statusPrimaryOff:]
	if _, err := encodeAddr(p[pathInfoAddressOff:], afInet, netip.MustParseAddr("127.0.0.3"), 80); err != nil {
		t.Fatal(err)
	}
	binary.NativeEndian.PutUint32(p[pathInfoStateOff:], uint32(PathPotentiallyFailed))
	binary.NativeEndian.PutUint32(p[pathInfoSRTTOff:], 17)
	want := Status{
		State:              StateShutdownPending,
		PeerRwnd:           0x01020304,
		Unacked:            0x0506,
		Pending:            0x0708,
		InStreams:          0x090a,
		OutStreams:         0x0b0c,
		FragmentationPoint: 0x0d0e0f10,
		Primary: PathInfo{
			Addr:      netip.MustParseAddrPort("127.0.0.3:80"),
			State:     PathPotentiallyFailed,
			SRTTTicks: 17,
		},
	}
	if got := decodeStatus(b[:]); got != want {
		t.Errorf("decoded\n %+v\nwant\n %+v", got, want)
	}
}

func TestRTOInfoCodec(t *testing.T) {
	var b [sizeRTOInfo]byte
	r := RTOInfo{Initial: 500 * time.Millisecond, Max: 2 * time.Second, Min: 200 * time.Millisecond}
	if err := encodeRTOInfo(b[:], 4, &r, "RTOInfo"); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		name string
		off  int
		want uint32
	}{
		{"srto_assoc_id", rtoInfoAssocIDOff, 4},
		{"srto_initial", rtoInfoInitialOff, 500},
		{"srto_max", rtoInfoMaxOff, 2000},
		{"srto_min", rtoInfoMinOff, 200},
	} {
		if got := binary.NativeEndian.Uint32(b[f.off:]); got != f.want {
			t.Errorf("%s = %d, want %d", f.name, got, f.want)
		}
	}
	if got := decodeRTOInfo(b[:]); got != r {
		t.Errorf("decoded %+v, want %+v", got, r)
	}
	for _, tc := range []struct {
		r     RTOInfo
		field string
	}{
		{RTOInfo{Initial: -time.Millisecond}, "RTOInfo.Initial"},
		{RTOInfo{Max: 1500 * time.Microsecond}, "RTOInfo.Max"},
		{RTOInfo{Min: time.Duration(math.MaxUint32+1) * time.Millisecond}, "RTOInfo.Min"},
		{RTOInfo{Min: 2 * time.Second, Max: time.Second}, "RTOInfo.Min"},
	} {
		wantRefused(t, encodeRTOInfo(b[:], 0, &tc.r, "RTOInfo"), tc.field)
	}
}

func TestAssocInfoCodec(t *testing.T) {
	var b [sizeAssocInfo]byte
	a := AssocInfo{MaxRetrans: 7, CookieLife: 90 * time.Second, PeerDestinations: 9, PeerRwnd: 9, LocalRwnd: 9}
	if err := encodeAssocInfo(b[:], 6, &a, "AssocInfo"); err != nil {
		t.Fatal(err)
	}
	if got := binary.NativeEndian.Uint32(b[assocInfoAssocIDOff:]); got != 6 {
		t.Errorf("sasoc_assoc_id = %d, want 6", got)
	}
	if got := binary.NativeEndian.Uint16(b[assocInfoMaxRetransOff:]); got != 7 {
		t.Errorf("sasoc_asocmaxrxt = %d, want 7", got)
	}
	if got := binary.NativeEndian.Uint32(b[assocInfoCookieLifeOff:]); got != 90000 {
		t.Errorf("sasoc_cookie_life = %d, want 90000", got)
	}
	// The read-only fields never reach the kernel.
	if binary.NativeEndian.Uint16(b[assocInfoPeerDestinationsOff:]) != 0 ||
		binary.NativeEndian.Uint32(b[assocInfoPeerRwndOff:]) != 0 ||
		binary.NativeEndian.Uint32(b[assocInfoLocalRwndOff:]) != 0 {
		t.Error("a read-only AssocInfo field was encoded")
	}

	binary.NativeEndian.PutUint16(b[assocInfoPeerDestinationsOff:], 2)
	binary.NativeEndian.PutUint32(b[assocInfoPeerRwndOff:], 0x11111)
	binary.NativeEndian.PutUint32(b[assocInfoLocalRwndOff:], 0x22222)
	want := AssocInfo{MaxRetrans: 7, CookieLife: 90 * time.Second, PeerDestinations: 2, PeerRwnd: 0x11111, LocalRwnd: 0x22222}
	if got := decodeAssocInfo(b[:]); got != want {
		t.Errorf("decoded %+v, want %+v", got, want)
	}
	wantRefused(t, encodeAssocInfo(b[:], 0, &AssocInfo{CookieLife: 1500 * time.Microsecond}, "AssocInfo"), "AssocInfo.CookieLife")
	wantRefused(t, encodeAssocInfo(b[:], 0, &AssocInfo{CookieLife: -time.Second}, "AssocInfo"), "AssocInfo.CookieLife")
}

func TestDelayedSACKCodec(t *testing.T) {
	var b [sizeDelayedSACK]byte
	d := DelayedSACK{Delay: 300 * time.Millisecond, Frequency: 4}
	if err := encodeDelayedSACK(b[:], 8, &d, "DelayedSACK"); err != nil {
		t.Fatal(err)
	}
	if binary.NativeEndian.Uint32(b[delayedSACKAssocIDOff:]) != 8 ||
		binary.NativeEndian.Uint32(b[delayedSACKDelayOff:]) != 300 ||
		binary.NativeEndian.Uint32(b[delayedSACKFrequencyOff:]) != 4 {
		t.Errorf("encoded % x", b)
	}
	if got := decodeDelayedSACK(b[:]); got != d {
		t.Errorf("decoded %+v, want %+v", got, d)
	}
	wantRefused(t, encodeDelayedSACK(b[:], 0, &DelayedSACK{Delay: 501 * time.Millisecond}, "DelayedSACK"), "DelayedSACK.Delay")
	wantRefused(t, encodeDelayedSACK(b[:], 0, &DelayedSACK{Delay: 1500 * time.Microsecond}, "DelayedSACK"), "DelayedSACK.Delay")
}

func TestDecodeInitMsg(t *testing.T) {
	var b [sizeInitMsg]byte
	binary.NativeEndian.PutUint16(b[initMsgOutStreamsOff:], 11)
	binary.NativeEndian.PutUint16(b[initMsgMaxInStreamsOff:], 13)
	binary.NativeEndian.PutUint16(b[initMsgMaxAttemptsOff:], 3)
	binary.NativeEndian.PutUint16(b[initMsgMaxInitTimeoOff:], 4000)
	want := InitMsg{OutStreams: 11, MaxInStreams: 13, MaxAttempts: 3, MaxInitTimeout: 4 * time.Second}
	if got := decodeInitMsg(b[:]); got != want {
		t.Errorf("decoded %+v, want %+v", got, want)
	}
}

// --- authentication ----------------------------------------------------------

// TestDecodeHMACIdents: the count and the length the kernel reports are two
// views of the same reply, and a reply where they disagree is malformed and
// refused rather than clamped (v1 TestParseHmacIdents).
func TestDecodeHMACIdents(t *testing.T) {
	build := func(count uint32, idents ...uint16) []byte {
		b := make([]byte, sizeHMACAlgo+2*len(idents))
		binary.NativeEndian.PutUint32(b[hmacAlgoNumIdentsOff:], count)
		for i, id := range idents {
			binary.NativeEndian.PutUint16(b[hmacAlgoIdentsOff+2*i:], id)
		}
		return b
	}
	b := build(2, 3, 1)
	got, err := decodeHMACIdents(b, len(b))
	if err != nil || !reflect.DeepEqual(got, []HMACID{HMACSHA256, HMACSHA1}) {
		t.Errorf("decoded %v, %v; want [HMACSHA256 HMACSHA1] in the kernel's order", got, err)
	}
	b = build(0)
	if got, err := decodeHMACIdents(b, len(b)); err != nil || len(got) != 0 {
		t.Errorf("empty list decoded as %v, %v", got, err)
	}
	for _, tc := range []struct {
		name string
		b    []byte
		n    int
	}{
		{"count too small", build(0, 1), 6},
		{"count too large", build(8, 1), 6},
		{"half an identifier", make([]byte, 5), 5},
		{"shorter than the count", make([]byte, 8), 3},
		{"length past the buffer", make([]byte, 8), 64},
	} {
		if _, err := decodeHMACIdents(tc.b, tc.n); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

// TestDecodeAuthChunks: the count is its own field, never a chunk type,
// and must agree with the length (v1 TestParseAuthChunks).
func TestDecodeAuthChunks(t *testing.T) {
	b := make([]byte, sizeAuthChunks+4)
	binary.NativeEndian.PutUint32(b[authChunksNumChunksOff:], 4)
	copy(b[authChunksChunksOff:], []byte{0xc0, 0xc1, 0x0e, 0x0d})
	got, err := decodeAuthChunks(b, len(b))
	if err != nil || !bytes.Equal(got, []uint8{0xc0, 0xc1, 0x0e, 0x0d}) {
		t.Errorf("decoded %v, %v", got, err)
	}
	if got, err := decodeAuthChunks(make([]byte, sizeAuthChunks), sizeAuthChunks); err != nil || len(got) != 0 {
		t.Errorf("empty list decoded as %v, %v", got, err)
	}
	for _, count := range []uint32{3, 5} {
		bad := bytes.Clone(b)
		binary.NativeEndian.PutUint32(bad[authChunksNumChunksOff:], count)
		if _, err := decodeAuthChunks(bad, len(bad)); err == nil {
			t.Errorf("count %d in a four-chunk reply was accepted", count)
		}
	}
	if _, err := decodeAuthChunks(make([]byte, 8), 7); err == nil {
		t.Error("a reply shorter than its header was accepted")
	}
	if _, err := decodeAuthChunks(make([]byte, 12), 64); err == nil {
		t.Error("a length past the buffer was accepted")
	}
}

// TestEncodeAuthKey pins struct sctp_authkey (v1 TestBuildersMatchKernelLayout,
// its sctp_authkey case) and the refusals made before any system call.
func TestEncodeAuthKey(t *testing.T) {
	key := []byte("secret42")
	b, err := encodeAuthKey(7, 0x1234, key, "SetAuthKey")
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != sizeAuthKey+len(key) {
		t.Fatalf("length %d, want %d", len(b), sizeAuthKey+len(key))
	}
	if binary.NativeEndian.Uint32(b[authKeyAssocIDOff:]) != 7 ||
		binary.NativeEndian.Uint16(b[authKeyKeyNumberOff:]) != 0x1234 ||
		binary.NativeEndian.Uint16(b[authKeyKeyLengthOff:]) != uint16(len(key)) ||
		!bytes.Equal(b[authKeyKeyOff:], key) {
		t.Errorf("encoded % x", b)
	}
	_, err = encodeAuthKey(0, 1, nil, "SetAuthKey")
	wantRefused(t, err, "SetAuthKey")
	_, err = encodeAuthKey(0, 1, make([]byte, math.MaxUint16+1), "SetAuthKey")
	wantRefused(t, err, "SetAuthKey")
}

// --- stream reconfiguration -----------------------------------------------

// TestEncodeResetStreams pins struct sctp_reset_streams (v1
// TestBuildersMatchKernelLayout, its sctp_reset_streams case): with flags
// 1 and two streams, a transposed flags/count pair would read as flags 2,
// count 1, which the kernel would accept for the wrong direction.
func TestEncodeResetStreams(t *testing.T) {
	b, err := encodeResetStreams(5, ResetIncoming, []uint16{7, 9})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != sizeResetStreams+4 {
		t.Fatalf("length %d, want %d", len(b), sizeResetStreams+4)
	}
	if binary.NativeEndian.Uint32(b[resetStreamsAssocIDOff:]) != 5 ||
		binary.NativeEndian.Uint16(b[resetStreamsFlagsOff:]) != 1 ||
		binary.NativeEndian.Uint16(b[resetStreamsNumStreamsOff:]) != 2 ||
		binary.NativeEndian.Uint16(b[resetStreamsStreamListOff:]) != 7 ||
		binary.NativeEndian.Uint16(b[resetStreamsStreamListOff+2:]) != 9 {
		t.Errorf("encoded % x", b)
	}
	if b, err := encodeResetStreams(0, ResetOutgoing, nil); err != nil || len(b) != sizeResetStreams {
		t.Errorf("all streams: %d bytes, %v; want the header alone", len(b), err)
	}
	for _, tc := range []struct {
		name    string
		dir     ResetDirection
		streams []uint16
	}{
		{"no direction", 0, nil},
		{"unknown direction bit", ResetIncoming | 0x80, nil},
		{"more streams than the count holds", ResetOutgoing, make([]uint16, math.MaxUint16+1)},
	} {
		_, err := encodeResetStreams(0, tc.dir, tc.streams)
		wantRefused(t, err, "ResetStreams")
	}
}

// --- partial reliability -------------------------------------------------

func TestPRStatusCodec(t *testing.T) {
	var b [sizePRStatus]byte
	prStatusRequest(b[:], 3, 5, PRRtx)
	if binary.NativeEndian.Uint32(b[prStatusAssocIDOff:]) != 3 ||
		binary.NativeEndian.Uint16(b[prStatusStreamOff:]) != 5 ||
		binary.NativeEndian.Uint16(b[prStatusPolicyOff:]) != uint16(PRRtx) {
		t.Errorf("request % x", b)
	}
	binary.NativeEndian.PutUint64(b[prStatusAbandonedUnsentOff:], 0x1111222233334444)
	binary.NativeEndian.PutUint64(b[prStatusAbandonedSentOff:], 0x5555666677778888)
	if got := decodePRStatus(b[:]); got != (PRStatus{AbandonedUnsent: 0x1111222233334444, AbandonedSent: 0x5555666677778888}) {
		t.Errorf("decoded %+v", got)
	}
	for _, p := range []PRPolicy{PRTTL, PRRtx, PRPrio, PRAll} {
		if err := validateStatusPolicy("PRAssocStatus", p); err != nil {
			t.Errorf("%v refused: %v", p, err)
		}
	}
	for _, p := range []PRPolicy{PRNone, PRAll | PRTTL, 0x40} {
		wantRefused(t, validateStatusPolicy("PRAssocStatus", p), "PRAssocStatus")
	}
}

// --- plain arguments ----------------------------------------------------------

func TestSizeArguments(t *testing.T) {
	if v, err := uint32Arg("SetMaxBurst", 0); err != nil || v != 0 {
		t.Errorf("0: %d, %v", v, err)
	}
	wantRefused(t, func() error { _, err := uint32Arg("SetMaxBurst", -1); return err }(), "SetMaxBurst")
	if strconv.IntSize == 64 {
		// Computed at run time, so that the file still compiles for a
		// 32-bit target, where the constant would not fit an int.
		var big64 int64 = math.MaxUint32
		big64++
		big := int(big64)
		wantRefused(t, func() error { _, err := uint32Arg("SetMaxBurst", big); return err }(), "SetMaxBurst")
	}

	if v, err := bufferSizeArg("SetReadBuffer", 4096); err != nil || v != 4096 {
		t.Errorf("4096: %d, %v", v, err)
	}
	for _, n := range []int{0, -1} {
		wantRefused(t, func() error { _, err := bufferSizeArg("SetReadBuffer", n); return err }(), "SetReadBuffer")
	}
	if strconv.IntSize == 64 {
		wantRefused(t, func() error { _, err := bufferSizeArg("SetReadBuffer", oversizedBufferSize()); return err }(), "SetReadBuffer")
	}
}
