// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"encoding/binary"
	"errors"
	"math"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ptr returns a pointer to a copy of v, for building Config's many optional
// pointer fields inline.
func ptr[T any](v T) *T { return &v }

// opKinds extracts just the kind of each op, for asserting order without
// spelling out every payload field.
func opKinds(ops []configOp) []configOpKind {
	kinds := make([]configOpKind, len(ops))
	for i, op := range ops {
		kinds[i] = op.kind
	}
	return kinds
}

func wantKinds(t *testing.T, got []configOp, want []configOpKind) {
	t.Helper()
	if !reflect.DeepEqual(opKinds(got), want) {
		t.Fatalf("op kinds = %v, want %v", opKinds(got), want)
	}
}

// --- zero Config ----------------------------------------------------------

func TestPrepareZeroConfigDial(t *testing.T) {
	p, err := (&Config{}).prepare(styleDial)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	wantKinds(t, p.ops, []configOpKind{opRecvRcvInfo, opAssocChange})
	if p.closeTimeout != 3*time.Second {
		t.Errorf("closeTimeout = %v, want 3s", p.closeTimeout)
	}
	if p.fragLevel != InterleaveNone {
		t.Errorf("fragLevel = %v, want InterleaveNone", p.fragLevel)
	}
	if p.subscribed != 0 {
		t.Errorf("subscribed = %v, want 0", p.subscribed)
	}
}

func TestPrepareZeroConfigListen(t *testing.T) {
	p, err := (&Config{}).prepare(styleListen)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	wantKinds(t, p.ops, []configOpKind{opRecvRcvInfo, opAssocChange})
}

func TestPrepareZeroConfigEndpointDefaultsFragmentInterleave(t *testing.T) {
	for _, style := range []socketStyle{styleListenEndpoint, styleOpenEndpoint} {
		p, err := (&Config{}).prepare(style)
		if err != nil {
			t.Fatalf("prepare(%v): %v", style, err)
		}
		wantKinds(t, p.ops, []configOpKind{opRecvRcvInfo, opAssocChange, opFragmentInterleave})
		if got := p.ops[2].level; got != InterleaveAssocs {
			t.Errorf("prepare(%v) fragment level = %v, want InterleaveAssocs", style, got)
		}
		if p.fragLevel != InterleaveAssocs {
			t.Errorf("prepare(%v) fragLevel = %v, want InterleaveAssocs", style, p.fragLevel)
		}
		if !p.subscribed.has(EventAssocChange) {
			t.Errorf("prepare(%v) subscribed does not include EventAssocChange", style)
		}
	}
}

func TestPrepareZeroConfigFile(t *testing.T) {
	p, err := (&Config{}).prepare(styleFile)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	wantKinds(t, p.ops, []configOpKind{opRecvRcvInfo, opAssocChange})
	if p.closeTimeout != 3*time.Second {
		t.Errorf("closeTimeout = %v, want 3s", p.closeTimeout)
	}
}

// --- application order ----------------------------------------------------

func TestPrepareOrderAndValues(t *testing.T) {
	cfg := &Config{
		ReadBuffer:  ptr(4096),
		WriteBuffer: ptr(8192),
		InitMsg: InitMsg{
			OutStreams:     10,
			MaxInStreams:   10,
			MaxAttempts:    5,
			MaxInitTimeout: 60 * time.Second,
		},
		FragmentInterleave:            ptr(InterleaveAssocs),
		Authentication:                ptr(true),
		HMACIdentifiers:               []HMACID{HMACSHA256, HMACSHA1},
		AuthChunks:                    []uint8{0, 192},
		DynamicAddressReconfiguration: ptr(true),
		PartialReliability:            ptr(true),
		StreamReconfiguration:         ptr(true),
		StreamResetMask:               ptr(EnableResetStreamReq | EnableChangeAssocReq),
		MessageInterleaving:           true,
		ExperimentalECN:               ptr(true),
		AdaptationLayer:               ptr(uint32(7)),
		RTOInfo:                       &RTOInfo{Initial: 1 * time.Second, Max: 60 * time.Second, Min: 500 * time.Millisecond},
		DelayedSACK:                   &DelayedSACK{Delay: 200 * time.Millisecond, Frequency: 2},
		FragmentsDisabled:             ptr(true),
		ReusePort:                     ptr(true),
		ReceiveNxtInfo:                ptr(true),
		NoDelay:                       ptr(true),
		DefaultSndInfo:                &SndInfo{Stream: 1, Flags: SendUnordered, PPID: 42},
		DefaultPrInfo:                 &PrInfo{Policy: PRTTL, TTL: 500 * time.Millisecond},
		Notifications:                 []EventType{EventAssocChange, EventSenderDry},
	}

	p, err := cfg.prepare(styleDial)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	want := []configOpKind{
		opRecvRcvInfo, opAssocChange,
		opReadBuffer, opWriteBuffer, opInitMsg, opFragmentInterleave,
		opAuthentication, opHMACIdentifiers,
		opAuthChunk, opAuthChunk, // one per AuthChunks entry
		opDynamicAddressReconfiguration, opPartialReliability,
		opStreamReconfiguration, opStreamResetMask, opMessageInterleaving,
		opExperimentalECN, opAdaptationLayer, opRTOInfo, opDelayedSACK,
		opFragmentsDisabled, opReusePort, opReceiveNxtInfo, opNoDelay,
		opDefaultSndInfo, opDefaultPrInfo,
		opNotification, opNotification, // one per Notifications entry
	}
	wantKinds(t, p.ops, want)

	// Spot-check a few converted values, not just kinds.
	for _, op := range p.ops {
		switch op.kind {
		case opInitMsg:
			if op.maxInitTimeoutMS != 60000 {
				t.Errorf("opInitMsg.maxInitTimeoutMS = %d, want 60000", op.maxInitTimeoutMS)
			}
		case opRTOInfo:
			if op.initialMS != 1000 || op.maxMS != 60000 || op.minMS != 500 {
				t.Errorf("opRTOInfo = %+v, want 1000/60000/500", op)
			}
		case opDelayedSACK:
			if op.delayMS != 200 || op.frequency != 2 {
				t.Errorf("opDelayedSACK = %+v, want 200/2", op)
			}
		case opHMACIdentifiers:
			if !reflect.DeepEqual(op.hmacIdentifiers, []HMACID{HMACSHA256, HMACSHA1}) {
				t.Errorf("opHMACIdentifiers = %v, want [HMACSHA256 HMACSHA1]", op.hmacIdentifiers)
			}
		}
	}

	if p.fragLevel != InterleaveAssocs {
		t.Errorf("fragLevel = %v, want InterleaveAssocs", p.fragLevel)
	}
}

// --- slice copying ----------------------------------------------------------

func TestPrepareCopiesSlices(t *testing.T) {
	hmacs := []HMACID{HMACSHA1}
	chunks := []uint8{0, 192}
	notifications := []EventType{EventAssocChange}
	cfg := &Config{
		Authentication:  ptr(true),
		HMACIdentifiers: hmacs,
		AuthChunks:      chunks,
		Notifications:   notifications,
	}

	p, err := cfg.prepare(styleDial)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	// Mutate every slice-typed source field only after prepare has already
	// returned: none of this may reach the snapshot it built.
	hmacs[0] = HMACSHA256
	chunks[0], chunks[1] = 255, 254
	cfg.Notifications[0] = EventShutdown

	var gotHMACs []HMACID
	var gotChunks []uint8
	for _, op := range p.ops {
		switch op.kind {
		case opHMACIdentifiers:
			gotHMACs = op.hmacIdentifiers
		case opAuthChunk:
			gotChunks = append(gotChunks, op.chunk)
		}
	}
	if !reflect.DeepEqual(gotHMACs, []HMACID{HMACSHA1}) {
		t.Fatalf("snapshot HMACIdentifiers changed after mutating the Config: got %v", gotHMACs)
	}
	if !reflect.DeepEqual(gotChunks, []uint8{0, 192}) {
		t.Fatalf("snapshot AuthChunks changed after mutating the Config: got %v", gotChunks)
	}
	if !p.subscribed.has(EventAssocChange) {
		t.Fatalf("snapshot lost its EventAssocChange subscription after mutating the Config's Notifications")
	}
}

// --- cross-field refusals ---------------------------------------------------

func TestPrepareRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name  string
		style socketStyle
		cfg   *Config
		want  string
	}{
		{
			name: "HMACIdentifiers without Authentication",
			cfg:  &Config{HMACIdentifiers: []HMACID{HMACSHA1}},
			want: "Config.HMACIdentifiers",
		},
		{
			name: "HMACIdentifiers missing SHA1",
			cfg:  &Config{Authentication: ptr(true), HMACIdentifiers: []HMACID{HMACSHA256}},
			want: "HMACSHA1",
		},
		{
			name: "duplicate HMACIdentifiers",
			cfg:  &Config{Authentication: ptr(true), HMACIdentifiers: []HMACID{HMACSHA1, HMACSHA1}},
			want: "duplicates identifier",
		},
		{
			name: "AuthChunks without Authentication",
			cfg:  &Config{AuthChunks: []uint8{0}},
			want: "Config.AuthChunks",
		},
		{
			name: "duplicate AuthChunks",
			cfg:  &Config{Authentication: ptr(true), AuthChunks: []uint8{0, 0}},
			want: "duplicates chunk type",
		},
		{
			name: "DynamicAddressReconfiguration without Authentication",
			cfg:  &Config{DynamicAddressReconfiguration: ptr(true)},
			want: "Config.DynamicAddressReconfiguration",
		},
		{
			name: "non-zero StreamResetMask without StreamReconfiguration",
			cfg:  &Config{StreamResetMask: ptr(EnableResetStreamReq)},
			want: "Config.StreamReconfiguration",
		},
		{
			name: "unknown StreamResetMask bits",
			cfg:  &Config{StreamReconfiguration: ptr(true), StreamResetMask: ptr(StreamResetMask(0x08))},
			want: "unknown bits",
		},
		{
			name: "MessageInterleaving without FragmentInterleave on Dial",
			cfg:  &Config{MessageInterleaving: true},
			want: "Config.MessageInterleaving",
		},
		{
			name: "DelayedSACK.Delay above 500ms",
			cfg:  &Config{DelayedSACK: &DelayedSACK{Delay: 501 * time.Millisecond}},
			want: "500 ms maximum",
		},
		{
			name: "RTOInfo non-millisecond value",
			cfg:  &Config{RTOInfo: &RTOInfo{Initial: 1500 * time.Microsecond}},
			want: "Config.RTOInfo.Initial",
		},
		{
			name: "InitMsg.MaxInitTimeout overflow",
			cfg:  &Config{InitMsg: InitMsg{MaxInitTimeout: 70 * time.Second}},
			want: "Config.InitMsg.MaxInitTimeout",
		},
		{
			name: "DefaultSndInfo.Flags SendSACKImmediately",
			cfg:  &Config{DefaultSndInfo: &SndInfo{Flags: SendSACKImmediately}},
			want: "Config.DefaultSndInfo.Flags",
		},
		{
			name: "DefaultPrInfo PRAll",
			cfg:  &Config{DefaultPrInfo: &PrInfo{Policy: PRAll}},
			want: "Config.DefaultPrInfo.Policy",
		},
		{
			name: "DefaultPrInfo non-millisecond TTL",
			cfg:  &Config{DefaultPrInfo: &PrInfo{Policy: PRTTL, TTL: 1500 * time.Microsecond}},
			want: "Config.DefaultPrInfo.TTL",
		},
		{
			name: "negative CloseTimeout",
			cfg:  &Config{CloseTimeout: -time.Second},
			want: "Config.CloseTimeout",
		},
		{
			name: "unknown Notifications entry",
			cfg:  &Config{Notifications: []EventType{0x9999}},
			want: "Config.Notifications[0]",
		},
		{
			name: "ReadBuffer not positive",
			cfg:  &Config{ReadBuffer: ptr(0)},
			want: "Config.ReadBuffer",
		},
		{
			name: "WriteBuffer not positive",
			cfg:  &Config{WriteBuffer: ptr(-1)},
			want: "Config.WriteBuffer",
		},
		{
			name:  "ReusePort on ListenEndpoint",
			style: styleListenEndpoint,
			cfg:   &Config{ReusePort: ptr(true)},
			want:  "Config.ReusePort",
		},
		{
			name:  "ReusePort on OpenEndpoint",
			style: styleOpenEndpoint,
			cfg:   &Config{ReusePort: ptr(false)},
			want:  "Config.ReusePort",
		},
		{
			name:  "AbandonPolicy on Listen",
			style: styleListen,
			cfg:   &Config{AbandonPolicy: AbandonQuiet},
			want:  "Config.AbandonPolicy",
		},
		{
			name:  "AbandonPolicy on ListenEndpoint",
			style: styleListenEndpoint,
			cfg:   &Config{AbandonPolicy: AbandonQuiet},
			want:  "Config.AbandonPolicy",
		},
		{
			name:  "AbandonPolicy on OpenEndpoint",
			style: styleOpenEndpoint,
			cfg:   &Config{AbandonPolicy: AbandonQuiet},
			want:  "Config.AbandonPolicy",
		},
		{
			name: "out-of-range AbandonPolicy on Dial",
			cfg:  &Config{AbandonPolicy: AbandonPolicy(7)},
			want: "Config.AbandonPolicy",
		},
		{
			name: "unknown FragmentInterleave value",
			cfg:  &Config{FragmentInterleave: ptr(FragmentInterleave(9))},
			want: "Config.FragmentInterleave",
		},
		{
			name: "unsupported HMAC identifier",
			cfg:  &Config{Authentication: ptr(true), HMACIdentifiers: []HMACID{HMACSHA1, HMACID(2)}},
			want: "Config.HMACIdentifiers[1]",
		},
		{
			name: "empty non-nil HMACIdentifiers without Authentication",
			cfg:  &Config{HMACIdentifiers: []HMACID{}},
			want: "Config.HMACIdentifiers",
		},
		{
			name: "empty non-nil HMACIdentifiers with Authentication",
			cfg:  &Config{Authentication: ptr(true), HMACIdentifiers: []HMACID{}},
			want: "HMACSHA1",
		},
		{
			name: "AuthChunks forbidden INIT",
			cfg:  &Config{Authentication: ptr(true), AuthChunks: []uint8{1}},
			want: "INIT",
		},
		{
			name: "AuthChunks forbidden INIT-ACK",
			cfg:  &Config{Authentication: ptr(true), AuthChunks: []uint8{2}},
			want: "INIT-ACK",
		},
		{
			name: "AuthChunks forbidden SHUTDOWN-COMPLETE",
			cfg:  &Config{Authentication: ptr(true), AuthChunks: []uint8{14}},
			want: "SHUTDOWN-COMPLETE",
		},
		{
			name: "AuthChunks forbidden AUTH",
			cfg:  &Config{Authentication: ptr(true), AuthChunks: []uint8{15}},
			want: "Config.AuthChunks[0]",
		},
		{
			// 15 explicit entries plus the ASCONF/ASCONF-ACK pair Linux
			// adds automatically whenever Authentication is true — neither
			// chunk already listed, and DynamicAddressReconfiguration left
			// nil — is 17 effective entries, one past sctpAuthMaxChunks
			// (16).
			name: "AuthChunks 15 plus auto-added ASCONF pair exceeds 16, DynamicAddressReconfiguration nil",
			cfg: &Config{
				Authentication: ptr(true),
				AuthChunks:     manyAuthChunks(15),
			},
			want: "Config.AuthChunks",
		},
		{
			// Same as above, but with DynamicAddressReconfiguration set
			// explicitly to false: the auto-add does not depend on it, so
			// this still refuses. sctp_setsockopt_auth_supported adds the
			// pair whenever ep->asconf_enable is already set — which may
			// already be true from the host's net.sctp.addip_enable
			// sysctl before this package's own DynamicAddressReconfiguration
			// op ever runs (config.go has the full citations) — and a
			// later "off" never removes an already-added chunk.
			name: "AuthChunks 15 plus auto-added ASCONF pair exceeds 16, DynamicAddressReconfiguration false",
			cfg: &Config{
				Authentication:                ptr(true),
				DynamicAddressReconfiguration: ptr(false),
				AuthChunks:                    manyAuthChunks(15),
			},
			want: "Config.AuthChunks",
		},
		{
			// The caller already lists ASCONF (0xC1) itself, so only
			// ASCONF-ACK is added automatically: 16 explicit entries + 1
			// auto-added is 17, one past the cap. Exercises the message
			// naming a single auto-added chunk, not a pair.
			name: "AuthChunks 16 including caller's own ASCONF exceeds 16 with only ASCONF-ACK auto-added",
			cfg: &Config{
				Authentication: ptr(true),
				AuthChunks:     append(manyAuthChunks(15), chunkTypeASCONF),
			},
			want: "Config.AuthChunks",
		},
		{
			name: "empty non-nil AuthChunks without Authentication",
			cfg:  &Config{AuthChunks: []uint8{}},
			want: "Config.AuthChunks",
		},
		{
			name: "RTOInfo Min exceeds Max",
			cfg:  &Config{RTOInfo: &RTOInfo{Min: 2 * time.Second, Max: 1 * time.Second}},
			want: "Config.RTOInfo.Min",
		},
		{
			name: "RTOInfo.Max non-millisecond value",
			cfg:  &Config{RTOInfo: &RTOInfo{Max: 1500 * time.Microsecond}},
			want: "Config.RTOInfo.Max",
		},
		{
			name: "RTOInfo.Min non-millisecond value",
			cfg:  &Config{RTOInfo: &RTOInfo{Min: 1500 * time.Microsecond}},
			want: "Config.RTOInfo.Min",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.cfg.prepare(tc.style)
			if err == nil {
				t.Fatal("prepare unexpectedly succeeded")
			}
			wantRefused(t, err, tc.want)
		})
	}
}

// manyAuthChunks returns n distinct chunk type values starting at 20, none
// of them one of the four RFC 4895 §3.2 forbids (1, 2, 14, 15) and none of
// them ASCONF (0xC1 = 193) or ASCONF-ACK (0x80 = 128), for exercising the
// sctpAuthMaxChunks (SCTP_AUTH_MAX_CHUNKS, 16) entry-count cap
// independently of both the forbidden-type check and the ASCONF-pair
// auto-add.
func manyAuthChunks(n int) []uint8 {
	chunks := make([]uint8, n)
	for i := range chunks {
		chunks[i] = uint8(20 + i)
	}
	return chunks
}

// oversizedBufferSize returns a value one past math.MaxInt32, computed at
// runtime (not as a constant expression) so this file still type-checks
// when vetted for a 32-bit target, where math.MaxInt32+1 would not fit the
// int the constant would otherwise be given. On the 64-bit hosts this
// package's tests actually run on, int is 64 bits and the returned value is
// the intended one past math.MaxInt32.
func oversizedBufferSize() int {
	n := math.MaxInt32
	n++
	return n
}

// TestReadWriteBufferRejectsValuesBeyondInt32 exercises SO_RCVBUF/SO_SNDBUF's
// own width (net/core/sock.c's sk_setsockopt, "int val"): a *int value
// beyond math.MaxInt32 must be refused rather than silently truncated at
// the kernel boundary. Skipped when int itself is 32 bits: there,
// oversizedBufferSize's "n := math.MaxInt32; n++" simply wraps to a
// negative int at runtime (Go defines wraparound, not a panic, for
// unsigned and signed integer overflow alike) and never reaches the
// >math.MaxInt32 branch at all — the property this test pins is
// unreachable on a build where math.MaxInt32 already is int's own maximum,
// so there is nothing this test can prove there.
func TestReadWriteBufferRejectsValuesBeyondInt32(t *testing.T) {
	if strconv.IntSize == 32 {
		t.Skip("int is 32 bits on this platform: math.MaxInt32+1 cannot be represented as an int, so this property cannot be exercised here")
	}
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{"ReadBuffer", &Config{ReadBuffer: ptr(oversizedBufferSize())}, "Config.ReadBuffer"},
		{"WriteBuffer", &Config{WriteBuffer: ptr(oversizedBufferSize())}, "Config.WriteBuffer"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.cfg.prepare(styleDial)
			if err == nil {
				t.Fatal("prepare unexpectedly succeeded")
			}
			wantRefused(t, err, tc.want)
			if !strings.Contains(err.Error(), "exceeds the int32 range") {
				t.Errorf("err = %q, want it to mention the int32 range", err)
			}
		})
	}
}

func TestInterleaveStreamsUnsupported(t *testing.T) {
	for _, style := range []socketStyle{styleDial, styleListen, styleListenEndpoint, styleOpenEndpoint} {
		_, err := (&Config{FragmentInterleave: ptr(InterleaveStreams)}).prepare(style)
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("prepare(%v) = %v, want an error matching ErrUnsupported", style, err)
		}
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Fatalf("prepare(%v) = %v, want an error matching errors.ErrUnsupported too", style, err)
		}
		if !containsField(err, "Config.FragmentInterleave") {
			t.Fatalf("prepare(%v) = %q, want it to name Config.FragmentInterleave", style, err)
		}
		if errors.Is(err, syscall.EINVAL) {
			t.Fatalf("prepare(%v) = %v, want it NOT to match syscall.EINVAL (it is unsupported, not invalid)", style, err)
		}
	}
}

// TestInterleaveStreamsMessageDoesNotStutter pins the exact, non-stuttering
// message unsupportedField builds: no second "sctp: socket operation
// unsupported: " embedded inside it (invalidArg's own "sctp: " prefix
// style would otherwise double up with ErrUnsupported's own text if this
// case were built by wrapping it with fmt.Errorf("...: %w: ...",
// ErrUnsupported) instead).
func TestInterleaveStreamsMessageDoesNotStutter(t *testing.T) {
	_, err := (&Config{FragmentInterleave: ptr(InterleaveStreams)}).prepare(styleDial)
	if err == nil {
		t.Fatal("prepare unexpectedly succeeded")
	}
	const want = "sctp: Config.FragmentInterleave: Linux stores SCTP_FRAGMENT_INTERLEAVE as a boolean and collapses any nonzero value to InterleaveAssocs (net/sctp/socket.c: sctp_setsockopt_fragment_interleave), so it cannot deliver cross-stream interleaving"
	if err.Error() != want {
		t.Fatalf("err = %q, want exactly %q", err.Error(), want)
	}
	if strings.Contains(err.Error(), "unsupported: sctp:") || strings.Count(err.Error(), "sctp:") != 1 {
		t.Fatalf("err = %q, want exactly one \"sctp:\" prefix, not a stutter", err.Error())
	}
}

func containsField(err error, field string) bool {
	return err != nil && strings.Contains(err.Error(), field)
}

// --- AuthChunks / RTOInfo boundaries -----------------------------------

// TestPrepareAccepts14NonASCONFAuthChunks pins the accepted side of the
// AuthChunks entry-count boundary: whenever Authentication is true, this
// package always counts the ASCONF/ASCONF-ACK pair Linux may add
// automatically (see the AuthChunks validation's own comment in
// config.go), so 14 explicit, non-ASCONF entries plus that pair is 16
// effective entries — exactly sctpAuthMaxChunks (SCTP_AUTH_MAX_CHUNKS) —
// still accepted. DynamicAddressReconfiguration is left nil, confirming
// the count does not depend on it.
func TestPrepareAccepts14NonASCONFAuthChunks(t *testing.T) {
	p, err := (&Config{Authentication: ptr(true), AuthChunks: manyAuthChunks(14)}).prepare(styleDial)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	got := 0
	for _, op := range p.ops {
		if op.kind == opAuthChunk {
			got++
		}
	}
	if got != 14 {
		t.Fatalf("opAuthChunk count = %d, want 14", got)
	}
}

// TestPrepareAccepts14AuthChunksPlusExplicitASCONFPairDedup exercises the
// dedup half of the same boundary: the caller lists ASCONF and ASCONF-ACK
// themselves, alongside 14 other entries, for 16 explicit entries total.
// Since both are already present, nothing is added on top, so the
// effective count stays at 16 (not 18) and the Config is accepted.
func TestPrepareAccepts14AuthChunksPlusExplicitASCONFPairDedup(t *testing.T) {
	chunks := append(manyAuthChunks(14), chunkTypeASCONF, chunkTypeASCONFAck)
	p, err := (&Config{Authentication: ptr(true), AuthChunks: chunks}).prepare(styleDial)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	got := 0
	for _, op := range p.ops {
		if op.kind == opAuthChunk {
			got++
		}
	}
	if got != 16 {
		t.Fatalf("opAuthChunk count = %d, want 16", got)
	}
}

// TestPrepareAcceptsEmptyNonNilAuthChunksWithAuthentication is AuthChunks'
// counterpart to the HMACIdentifiers empty-non-nil-with-Authentication
// case: unlike HMACIdentifiers, AuthChunks has no "must include" rule, so
// an empty but non-nil list is simply accepted (zero entries, well under
// the 16-entry cap) rather than refused.
func TestPrepareAcceptsEmptyNonNilAuthChunksWithAuthentication(t *testing.T) {
	p, err := (&Config{Authentication: ptr(true), AuthChunks: []uint8{}}).prepare(styleDial)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	for _, op := range p.ops {
		if op.kind == opAuthChunk {
			t.Fatalf("unexpected opAuthChunk for an empty AuthChunks list: %+v", op)
		}
	}
}

// TestRTOInfoMinEqualsMaxAccepted pins the accepted boundary next to
// TestPrepareRejectsInvalidConfiguration's "RTOInfo Min exceeds Max" case:
// sctp_setsockopt_rtoinfo only refuses rto_min > rto_max, so Min == Max is
// fine.
func TestRTOInfoMinEqualsMaxAccepted(t *testing.T) {
	_, err := (&Config{RTOInfo: &RTOInfo{Min: time.Second, Max: time.Second}}).prepare(styleDial)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
}

// --- MessageInterleaving / FragmentInterleave interaction ------------------

func TestMessageInterleavingRequiresFragmentInterleave(t *testing.T) {
	// Explicit InterleaveAssocs is enough on any style.
	for _, style := range []socketStyle{styleDial, styleListen, styleListenEndpoint, styleOpenEndpoint} {
		p, err := (&Config{
			MessageInterleaving: true,
			FragmentInterleave:  ptr(InterleaveAssocs),
		}).prepare(style)
		if err != nil {
			t.Fatalf("prepare(%v): %v", style, err)
		}
		found := false
		for _, op := range p.ops {
			found = found || op.kind == opMessageInterleaving
		}
		if !found {
			t.Fatalf("prepare(%v): no opMessageInterleaving in %v", style, opKinds(p.ops))
		}
	}

	// nil is refused on Dial/Listen (no implicit default there).
	for _, style := range []socketStyle{styleDial, styleListen} {
		_, err := (&Config{MessageInterleaving: true}).prepare(style)
		wantRefused(t, err, "Config.MessageInterleaving")
	}

	// nil is fine on an Endpoint: it defaults to InterleaveAssocs.
	for _, style := range []socketStyle{styleListenEndpoint, styleOpenEndpoint} {
		if _, err := (&Config{MessageInterleaving: true}).prepare(style); err != nil {
			t.Fatalf("prepare(%v): %v", style, err)
		}
	}
}

// --- Notifications: dedup, unknown, endpoint auto-subscribe ----------------

func TestPrepareNotificationsDeduplicated(t *testing.T) {
	p, err := (&Config{Notifications: []EventType{EventShutdown, EventShutdown, EventSenderDry}}).prepare(styleDial)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	var events []EventType
	for _, op := range p.ops {
		if op.kind == opNotification {
			events = append(events, op.event)
		}
	}
	if !reflect.DeepEqual(events, []EventType{EventShutdown, EventSenderDry}) {
		t.Fatalf("notification ops = %v, want [EventShutdown EventSenderDry] (duplicate collapsed)", events)
	}
	if !p.subscribed.has(EventShutdown) || !p.subscribed.has(EventSenderDry) {
		t.Fatalf("subscribed = %v, want both bits set", p.subscribed)
	}
}

func TestPrepareEndpointAlwaysSubscribesAssocChangeWithoutExtraOp(t *testing.T) {
	p, err := (&Config{}).prepare(styleListenEndpoint)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if !p.subscribed.has(EventAssocChange) {
		t.Fatal("subscribed does not include EventAssocChange on an Endpoint")
	}
	for _, op := range p.ops {
		if op.kind == opNotification {
			t.Fatalf("unexpected opNotification %v: EventAssocChange is a package invariant, not a Config.Notifications entry here", op.event)
		}
	}
}

// --- styleFile ---------------------------------------------------------

func TestPrepareFileStyleAllowsOnlyHandlerAndCloseTimeout(t *testing.T) {
	cfg := &Config{
		NotificationHandler: func(Notification) error { return nil },
		CloseTimeout:        5 * time.Second,
	}
	p, err := cfg.prepare(styleFile)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if p.closeTimeout != 5*time.Second {
		t.Errorf("closeTimeout = %v, want 5s", p.closeTimeout)
	}
	if p.handler == nil {
		t.Error("handler not carried through")
	}
	wantKinds(t, p.ops, []configOpKind{opRecvRcvInfo, opAssocChange})
}

func TestPrepareFileStyleRejectsEveryOtherField(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
	}{
		{"Control", &Config{Control: func(string, string, syscall.RawConn) error { return nil }}},
		{"AbandonPolicy", &Config{AbandonPolicy: AbandonQuiet}},
		{"InitMsg", &Config{InitMsg: InitMsg{OutStreams: 1}}},
		{"AdaptationLayer", &Config{AdaptationLayer: ptr(uint32(1))}},
		{"HMACIdentifiers", &Config{HMACIdentifiers: []HMACID{}}}, // empty but non-nil
		{"AuthChunks", &Config{AuthChunks: []uint8{}}},
		{"PartialReliability", &Config{PartialReliability: ptr(true)}},
		{"StreamReconfiguration", &Config{StreamReconfiguration: ptr(true)}},
		{"DynamicAddressReconfiguration", &Config{DynamicAddressReconfiguration: ptr(true)}},
		{"Authentication", &Config{Authentication: ptr(true)}},
		{"ExperimentalECN", &Config{ExperimentalECN: ptr(true)}},
		{"MessageInterleaving", &Config{MessageInterleaving: true}},
		{"ReadBuffer", &Config{ReadBuffer: ptr(1)}},
		{"WriteBuffer", &Config{WriteBuffer: ptr(1)}},
		{"NoDelay", &Config{NoDelay: ptr(true)}},
		{"DefaultSndInfo", &Config{DefaultSndInfo: &SndInfo{}}},
		{"DefaultPrInfo", &Config{DefaultPrInfo: &PrInfo{}}},
		{"ReusePort", &Config{ReusePort: ptr(true)}},
		{"FragmentsDisabled", &Config{FragmentsDisabled: ptr(true)}},
		{"FragmentInterleave", &Config{FragmentInterleave: ptr(InterleaveNone)}},
		{"ReceiveNxtInfo", &Config{ReceiveNxtInfo: ptr(true)}},
		{"StreamResetMask", &Config{StreamResetMask: ptr(StreamResetMask(0))}},
		{"RTOInfo", &Config{RTOInfo: &RTOInfo{}}},
		{"DelayedSACK", &Config{DelayedSACK: &DelayedSACK{}}},
		{"Notifications", &Config{Notifications: []EventType{}}}, // empty but non-nil
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.cfg.prepare(styleFile)
			wantRefused(t, err, "Config."+tc.name)
		})
	}
}

// --- CloseTimeout -----------------------------------------------------------

func TestResolveCloseTimeoutZeroMeans3s(t *testing.T) {
	p, err := (&Config{}).prepare(styleDial)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if p.closeTimeout != 3*time.Second {
		t.Errorf("closeTimeout = %v, want 3s", p.closeTimeout)
	}
}

func TestResolveCloseTimeoutPositiveKept(t *testing.T) {
	p, err := (&Config{CloseTimeout: 10 * time.Second}).prepare(styleDial)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if p.closeTimeout != 10*time.Second {
		t.Errorf("closeTimeout = %v, want 10s", p.closeTimeout)
	}
}

// --- AbandonPolicy -----------------------------------------------------------

func TestAbandonPolicyDialOnly(t *testing.T) {
	p, err := (&Config{AbandonPolicy: AbandonQuiet}).prepare(styleDial)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if p.abandon != AbandonQuiet {
		t.Errorf("abandon = %v, want AbandonQuiet", p.abandon)
	}
}

// --- AdaptationLayer: any uint32 is valid ------------------------------------

func TestAdaptationLayerAcceptsAnyValue(t *testing.T) {
	for _, v := range []uint32{0, 1, math.MaxUint32} {
		p, err := (&Config{AdaptationLayer: ptr(v)}).prepare(styleDial)
		if err != nil {
			t.Fatalf("prepare(AdaptationLayer=%d): %v", v, err)
		}
		var got uint32
		found := false
		for _, op := range p.ops {
			if op.kind == opAdaptationLayer {
				got, found = op.u32, true
			}
		}
		if !found || got != v {
			t.Errorf("AdaptationLayer op = %d (found=%v), want %d", got, found, v)
		}
	}
}

// --- ReadBuffer/WriteBuffer ---------------------------------------------------

func TestReadWriteBufferPositive(t *testing.T) {
	p, err := (&Config{ReadBuffer: ptr(4096), WriteBuffer: ptr(8192)}).prepare(styleDial)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	for _, op := range p.ops {
		switch op.kind {
		case opReadBuffer:
			if op.bytes != 4096 {
				t.Errorf("ReadBuffer op = %d, want 4096", op.bytes)
			}
		case opWriteBuffer:
			if op.bytes != 8192 {
				t.Errorf("WriteBuffer op = %d, want 8192", op.bytes)
			}
		}
	}
}

// --- DefaultSndInfo / DefaultPrInfo op payloads: kernel units -------------

// TestDefaultSndInfoOpPPIDMatchesWireBytes checks that opDefaultSndInfo's
// sndInfoPPID is exactly what appendSendCmsgs (msginfo.go) itself would
// write to the wire for the same PPID: appendSendCmsgs writes snd_ppid with
// binary.BigEndian, so reading those bytes back with binary.NativeEndian
// must equal networkOrderUint32(ppid) — the whole point of pre-swapping the
// op's copy is that the code that later applies these ops can write every
// configOp field the same way, with no special case for this one.
func TestDefaultSndInfoOpPPIDMatchesWireBytes(t *testing.T) {
	const ppid = uint32(0x01020304)
	cfg := &Config{DefaultSndInfo: &SndInfo{Stream: 3, Flags: SendUnordered, PPID: ppid, Context: 9}}
	p, err := cfg.prepare(styleDial)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	var got *configOp
	for i := range p.ops {
		if p.ops[i].kind == opDefaultSndInfo {
			got = &p.ops[i]
		}
	}
	if got == nil {
		t.Fatal("no opDefaultSndInfo in the snapshot")
	}
	if got.sndInfoStream != 3 || got.sndInfoFlags != uint16(SendUnordered) || got.sndInfoContext != 9 {
		t.Fatalf("opDefaultSndInfo = %+v, want Stream=3 Flags=SendUnordered Context=9", *got)
	}

	dst := make([]byte, sndCmsgSpace)
	n := appendSendCmsgs(dst[:0], &SndInfo{PPID: ppid}, 0, nil, nil)
	wirePPID := binary.NativeEndian.Uint32(dst[:n][sizeCmsghdr+sndInfoPPIDOff:])
	if got.sndInfoPPID != wirePPID {
		t.Errorf("opDefaultSndInfo.sndInfoPPID = %#08x, want %#08x (appendSendCmsgs's own wire bytes, read back native-order)", got.sndInfoPPID, wirePPID)
	}
	if want := networkOrderUint32(ppid); got.sndInfoPPID != want {
		t.Errorf("opDefaultSndInfo.sndInfoPPID = %#08x, want networkOrderUint32(ppid) = %#08x", got.sndInfoPPID, want)
	}
}

// TestDefaultPrInfoOpResolvesKernelUnits checks that opDefaultPrInfo's
// prPolicy/prValue are the same resolution resolvePrInfo (options.go)
// documents and appendSendCmsgs's per-message PRINFO cmsg already relies
// on: pr_value is the TTL in milliseconds for PRTTL, Value for
// PRRtx/PRPrio, and 0 for PRNone regardless of what TTL or Value holds.
func TestDefaultPrInfoOpResolvesKernelUnits(t *testing.T) {
	tests := []struct {
		name       string
		pr         PrInfo
		wantPolicy uint16
		wantValue  uint32
	}{
		{"PRNone ignores TTL and Value", PrInfo{Policy: PRNone, TTL: time.Second, Value: 99}, uint16(PRNone), 0},
		{"PRTTL converts to ms", PrInfo{Policy: PRTTL, TTL: 250 * time.Millisecond}, uint16(PRTTL), 250},
		{"PRRtx keeps Value", PrInfo{Policy: PRRtx, Value: 7}, uint16(PRRtx), 7},
		{"PRPrio keeps Value", PrInfo{Policy: PRPrio, Value: 3}, uint16(PRPrio), 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pr := tc.pr
			p, err := (&Config{DefaultPrInfo: &pr}).prepare(styleDial)
			if err != nil {
				t.Fatalf("prepare: %v", err)
			}
			var got *configOp
			for i := range p.ops {
				if p.ops[i].kind == opDefaultPrInfo {
					got = &p.ops[i]
				}
			}
			if got == nil {
				t.Fatal("no opDefaultPrInfo in the snapshot")
			}
			if got.prPolicy != tc.wantPolicy || got.prValue != tc.wantValue {
				t.Errorf("opDefaultPrInfo = {prPolicy:%d prValue:%d}, want {%d %d}", got.prPolicy, got.prValue, tc.wantPolicy, tc.wantValue)
			}
		})
	}
}

// --- nil *Config -----------------------------------------------------------

// TestPrepareNilConfigMatchesZeroConfig decides and pins how prepare treats
// a nil receiver: the same as the zero Config, for every style, rather than
// panicking.
func TestPrepareNilConfigMatchesZeroConfig(t *testing.T) {
	for _, style := range []socketStyle{styleDial, styleListen, styleListenEndpoint, styleOpenEndpoint, styleFile} {
		var nilCfg *Config
		got, err := nilCfg.prepare(style)
		if err != nil {
			t.Fatalf("prepare(nil, %v): %v", style, err)
		}
		want, err := (&Config{}).prepare(style)
		if err != nil {
			t.Fatalf("prepare(&Config{}, %v): %v", style, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("prepare(nil, %v) = %+v, want %+v (same as the zero Config)", style, got, want)
		}
	}
}

// --- duration helpers ---------------------------------------------------

func TestDurationToMillisWholeRoundTrip(t *testing.T) {
	for _, d := range []time.Duration{0, time.Millisecond, 500 * time.Millisecond, 60 * time.Second} {
		ms, err := durationToMillis("field", d, math.MaxUint32)
		if err != nil {
			t.Fatalf("durationToMillis(%v): %v", d, err)
		}
		if got := millisToDuration(ms); got != d {
			t.Errorf("round trip: durationToMillis(%v) -> %d -> millisToDuration = %v, want %v", d, ms, got, d)
		}
	}
}

func TestDurationToMillisRefusesFractional(t *testing.T) {
	_, err := durationToMillis("RTOInfo.Initial", 1500*time.Microsecond, math.MaxUint32)
	wantRefused(t, err, "RTOInfo.Initial")
	if !strings.Contains(err.Error(), "whole number of milliseconds") {
		t.Errorf("err = %q, want it to mention whole milliseconds", err)
	}
}

func TestDurationToMillisRefusesNegative(t *testing.T) {
	_, err := durationToMillis("field", -time.Millisecond, math.MaxUint32)
	wantRefused(t, err, "field")
	if !strings.Contains(err.Error(), "negative") {
		t.Errorf("err = %q, want it to mention negative", err)
	}
}

// TestDurationToMillisRefusesHugeDuration checks that a huge value (1<<62
// ns) is refused without panicking or wrapping around in the conversion
// arithmetic (d/time.Millisecond, compared against limit), regardless of
// which check — fractional or over-limit — happens to catch it first; see
// TestDurationToMillisRefusesOverflowingWholeValue immediately below for a
// value guaranteed to hit the over-limit check specifically.
func TestDurationToMillisRefusesHugeDuration(t *testing.T) {
	huge := time.Duration(int64(1) << 62)
	_, err := durationToMillis("field", huge, math.MaxUint32)
	wantRefused(t, err, "field")
}

func TestDurationToMillisRefusesOverflowingWholeValue(t *testing.T) {
	huge := time.Duration(uint64(math.MaxUint32)+1) * time.Millisecond
	_, err := durationToMillis("field", huge, math.MaxUint32)
	wantRefused(t, err, "field")
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("err = %q, want it to mention exceeding the maximum", err)
	}
}

func TestDurationToMillisAcceptsExactMax(t *testing.T) {
	d := time.Duration(math.MaxUint32) * time.Millisecond
	ms, err := durationToMillis("field", d, math.MaxUint32)
	if err != nil {
		t.Fatalf("durationToMillis at exact max: %v", err)
	}
	if ms != math.MaxUint32 {
		t.Errorf("ms = %d, want %d", ms, uint32(math.MaxUint32))
	}
}

// TestDurationToMillisPanicsOnOversizedLimit checks the documented contract
// on durationToMillis's limit parameter: every real call site in this
// package passes a compile-time constant no larger than math.MaxUint32
// (the width of the value the function returns), so a larger limit is a
// programming mistake here, not a bad Config value, and the function panics
// rather than silently truncating an already-validated millisecond count.
func TestDurationToMillisPanicsOnOversizedLimit(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("durationToMillis did not panic with a limit beyond math.MaxUint32")
		}
	}()
	_, _ = durationToMillis("field", time.Millisecond, uint64(math.MaxUint32)+1)
}

// TestDurationToSecondsPanicsOnOversizedLimit is
// TestDurationToMillisPanicsOnOversizedLimit for durationToSeconds.
func TestDurationToSecondsPanicsOnOversizedLimit(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("durationToSeconds did not panic with a limit beyond math.MaxUint32")
		}
	}()
	_, _ = durationToSeconds("field", time.Second, uint64(math.MaxUint32)+1)
}

func TestDurationToSecondsWholeRoundTrip(t *testing.T) {
	for _, d := range []time.Duration{0, time.Second, 30 * time.Second} {
		s, err := durationToSeconds("field", d, math.MaxUint32)
		if err != nil {
			t.Fatalf("durationToSeconds(%v): %v", d, err)
		}
		if got := time.Duration(s) * time.Second; got != d {
			t.Errorf("round trip: durationToSeconds(%v) -> %d -> %v, want %v", d, s, got, d)
		}
	}
}

func TestDurationToSecondsRefusesFractional(t *testing.T) {
	_, err := durationToSeconds("field", 500*time.Millisecond, math.MaxUint32)
	wantRefused(t, err, "field")
	if !strings.Contains(err.Error(), "whole number of seconds") {
		t.Errorf("err = %q, want it to mention whole seconds", err)
	}
}

func TestDurationToSecondsRefusesOverflow(t *testing.T) {
	_, err := durationToSeconds("field", 10*time.Second, 5)
	wantRefused(t, err, "field")
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("err = %q, want it to mention exceeding the maximum", err)
	}
}

// --- fuzzing: prepare must never panic, and is a pure function of Config --

// fuzzConfig builds a Config deterministically from data, covering every
// field prepare reads. It never sets Control or NotificationHandler (funcs
// are not fuzzable inputs and are not compared by reflect.DeepEqual below).
func fuzzConfig(data []byte) *Config {
	at := func(i int) byte {
		if i < 0 || i >= len(data) {
			return 0
		}
		return data[i]
	}
	boolPtr := func(i int) *bool {
		if at(i)&1 == 0 {
			return nil
		}
		v := at(i)&2 != 0
		return &v
	}

	cfg := &Config{
		CloseTimeout:                  time.Duration(int8(at(0))) * time.Millisecond,
		AbandonPolicy:                 AbandonPolicy(at(1) % 4), // 0,1 valid; 2,3 out of range — enough to exercise both without spending most mutations re-discovering the same first check
		AdaptationLayer:               func() *uint32 { v := uint32(at(2)); return &v }(),
		PartialReliability:            boolPtr(3),
		StreamReconfiguration:         boolPtr(4),
		DynamicAddressReconfiguration: boolPtr(5),
		Authentication:                boolPtr(6),
		ExperimentalECN:               boolPtr(7),
		MessageInterleaving:           at(8)&1 != 0,
		NoDelay:                       boolPtr(9),
		ReusePort:                     boolPtr(10),
		FragmentsDisabled:             boolPtr(11),
		ReceiveNxtInfo:                boolPtr(12),
	}

	if at(13)&1 != 0 {
		v := FragmentInterleave(int8(at(14)) % 4)
		cfg.FragmentInterleave = &v
	}
	if at(15)&1 != 0 {
		v := int(at(16))
		cfg.ReadBuffer = &v
	}
	if at(17)&1 != 0 {
		v := int(at(18))
		cfg.WriteBuffer = &v
	}
	if at(19)&1 != 0 {
		v := StreamResetMask(at(20))
		cfg.StreamResetMask = &v
	}
	if at(21)&1 != 0 {
		cfg.RTOInfo = &RTOInfo{
			Initial: time.Duration(at(22)) * time.Millisecond,
			Max:     time.Duration(at(23)) * time.Millisecond,
			Min:     time.Duration(at(24)) * time.Millisecond,
		}
	}
	if at(25)&1 != 0 {
		cfg.DelayedSACK = &DelayedSACK{
			Delay:     time.Duration(at(26)) * time.Millisecond,
			Frequency: uint32(at(27)),
		}
	}
	if at(28)&1 != 0 {
		cfg.DefaultSndInfo = &SndInfo{
			Stream: uint16(at(29)),
			Flags:  SendFlags(at(30) & 1),
			PPID:   uint32(at(31)),
		}
	}
	if at(32)&1 != 0 {
		cfg.DefaultPrInfo = &PrInfo{
			Policy: PRPolicy(at(33)) & 0x30,
			TTL:    time.Duration(at(34)) * time.Millisecond,
			Value:  uint32(at(35)),
		}
	}
	cfg.InitMsg = InitMsg{
		OutStreams:     uint16(at(36)),
		MaxInStreams:   uint16(at(37)),
		MaxAttempts:    uint16(at(38)),
		MaxInitTimeout: time.Duration(at(39)) * time.Millisecond,
	}
	for i := 40; i < len(data) && len(cfg.HMACIdentifiers) < 8; i++ {
		cfg.HMACIdentifiers = append(cfg.HMACIdentifiers, HMACID(data[i]))
	}
	for i := 40; i < len(data) && len(cfg.AuthChunks) < 25; i++ { // past sctpNumChunkTypes (20)
		cfg.AuthChunks = append(cfg.AuthChunks, data[i])
	}
	for i := 40; i+1 < len(data) && len(cfg.Notifications) < 16; i += 2 {
		cfg.Notifications = append(cfg.Notifications, EventType(uint16(data[i])<<8|uint16(data[i+1])))
	}
	if at(13)&2 == 0 {
		cfg.HMACIdentifiers = nil
	}
	if at(13)&4 == 0 {
		cfg.AuthChunks = nil
	}
	if at(13)&8 == 0 {
		cfg.Notifications = nil
	}
	return cfg
}

func FuzzPrepareConfig(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3, 0xff})
	f.Add([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 7, 1, 2, 1, 2})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		cfg := fuzzConfig(data)
		style := socketStyle(data0(data) % 5)

		first, firstErr := cfg.prepare(style)
		second, secondErr := cfg.prepare(style)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("same input changed success: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr != nil {
			if firstErr.Error() != secondErr.Error() {
				t.Fatalf("same input changed error: first=%q second=%q", firstErr, secondErr)
			}
			// Every refusal prepare can produce is either a portable
			// validation error (invalidArg, matching syscall.EINVAL) or the
			// one ErrUnsupported case (InterleaveStreams) — never anything
			// else — and every one of them names the Config field it
			// refused.
			if !errors.Is(firstErr, syscall.EINVAL) && !errors.Is(firstErr, ErrUnsupported) {
				t.Fatalf("error %q matches neither syscall.EINVAL nor ErrUnsupported", firstErr)
			}
			if !strings.Contains(firstErr.Error(), "Config.") {
				t.Fatalf("error %q does not name a Config field", firstErr)
			}
			return
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("same input changed plan:\nfirst=%+v\nsecond=%+v", first, second)
		}
		// The op kinds prepare emits always follow Config's own documented
		// application order (config.go's configOpKind), so their kind
		// values never decrease along the slice — repeats (AuthChunks,
		// Notifications) are fine, a drop backward is not.
		for i := 1; i < len(first.ops); i++ {
			if first.ops[i].kind < first.ops[i-1].kind {
				t.Fatalf("op kinds out of order at index %d: %v", i, opKinds(first.ops))
			}
		}
	})
}

func data0(data []byte) byte {
	if len(data) == 0 {
		return 0
	}
	return data[0]
}
