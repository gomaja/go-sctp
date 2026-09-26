// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// --- test helpers -------------------------------------------------------

// checkCmsgHeader asserts that buf declares, at off, a control message of
// cmsg_level IPPROTO_SCTP, cmsg_type wantType and cmsg_len CMSG_LEN(n) —
// exactly what net/sctp/socket.c's sctp_msghdr_parse itself checks for
// every SCTP cmsg it accepts.
func checkCmsgHeader(t *testing.T, buf []byte, off, n, wantType int) {
	t.Helper()
	if got, want := readWord(buf[off+cmsghdrLenOff:]), uint64(cmsgLen(n)); got != want {
		t.Errorf("cmsg_len at offset %d = %d, want CMSG_LEN(%d) = %d", off, got, n, want)
	}
	if got := int32(binary.NativeEndian.Uint32(buf[off+cmsghdrLevelOff:])); got != ipprotoSCTP {
		t.Errorf("cmsg_level at offset %d = %d, want IPPROTO_SCTP (%d)", off, got, ipprotoSCTP)
	}
	if got := int32(binary.NativeEndian.Uint32(buf[off+cmsghdrTypeOff:])); got != int32(wantType) {
		t.Errorf("cmsg_type at offset %d = %d, want %d", off, got, wantType)
	}
}

// fullSlice recovers the whole backing array a len-0 buffer created for
// appendSendCmsgs was given, the way appendSendCmsgs itself does, so the
// caller can inspect what it wrote.
func fullSlice(buf []byte, n int) []byte { return buf[:cap(buf)][:n] }

// buildRecvCmsgLevel appends one control message of the given cmsg_level
// and cmsg_type holding payload, mirroring what a recvmsg() ancillary-data
// buffer looks like, so parseRecvCmsgs can be exercised without a socket.
func buildRecvCmsgLevel(dst []byte, level, typ int, payload []byte) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, cmsgSpace(len(payload)))...)
	putWord(dst[start+cmsghdrLenOff:], uint64(cmsgLen(len(payload))))
	binary.NativeEndian.PutUint32(dst[start+cmsghdrLevelOff:], uint32(level))
	binary.NativeEndian.PutUint32(dst[start+cmsghdrTypeOff:], uint32(typ))
	copy(dst[start+sizeCmsghdr:], payload)
	return dst
}

func buildRecvCmsg(dst []byte, typ int, payload []byte) []byte {
	return buildRecvCmsgLevel(dst, ipprotoSCTP, typ, payload)
}

func rcvInfoPayload(stream, ssn uint16, unordered bool, ppid, tsn, cumTSN, context, assoc uint32) []byte {
	b := make([]byte, sizeRcvInfo)
	binary.NativeEndian.PutUint16(b[rcvInfoStreamOff:], stream)
	binary.NativeEndian.PutUint16(b[rcvInfoSSNOff:], ssn)
	var flags uint16
	if unordered {
		flags |= sndFlagUnordered
	}
	binary.NativeEndian.PutUint16(b[rcvInfoFlagsOff:], flags)
	binary.BigEndian.PutUint32(b[rcvInfoPPIDOff:], ppid)
	binary.NativeEndian.PutUint32(b[rcvInfoTSNOff:], tsn)
	binary.NativeEndian.PutUint32(b[rcvInfoCumTSNOff:], cumTSN)
	binary.NativeEndian.PutUint32(b[rcvInfoContextOff:], context)
	binary.NativeEndian.PutUint32(b[rcvInfoAssocIDOff:], assoc)
	return b
}

func nxtInfoPayload(stream uint16, unordered, notification bool, ppid, length, assoc uint32) []byte {
	b := make([]byte, sizeNxtInfo)
	binary.NativeEndian.PutUint16(b[nxtInfoStreamOff:], stream)
	var flags uint16
	if unordered {
		flags |= sndFlagUnordered
	}
	if notification {
		flags |= msgNotification
	}
	binary.NativeEndian.PutUint16(b[nxtInfoFlagsOff:], flags)
	binary.BigEndian.PutUint32(b[nxtInfoPPIDOff:], ppid)
	binary.NativeEndian.PutUint32(b[nxtInfoLengthOff:], length)
	binary.NativeEndian.PutUint32(b[nxtInfoAssocIDOff:], assoc)
	return b
}

// --- appendSendCmsgs ------------------------------------------------------

// TestAppendSendCmsgsPanicsOnNonEmptyDst pins the enforced precondition:
// appendSendCmsgs always writes starting at index 0, so a caller passing a
// non-empty dst (as opposed to one merely appended to) would silently
// overwrite bytes at the wrong offset without this check.
func TestAppendSendCmsgsPanicsOnNonEmptyDst(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("appendSendCmsgs did not panic on a non-empty dst")
		}
	}()
	buf := make([]byte, 1, sndCmsgSpace)
	appendSendCmsgs(buf, &SndInfo{}, 0, nil, nil)
}

// TestAppendSendCmsgsEncodesSndInfo covers SNDINFO alone: every field,
// including the PPID big-endian conversion, and the exact CMSG_LEN/level/
// type triple sctp_msghdr_parse itself checks.
func TestAppendSendCmsgsEncodesSndInfo(t *testing.T) {
	snd := &SndInfo{Stream: 3, Flags: SendUnordered, PPID: 0x01020304, Context: 0x11223344}
	buf := make([]byte, sndCmsgSpace)[:0]

	n := appendSendCmsgs(buf, snd, AssocID(9), nil, nil)
	if want := cmsgSpace(sizeSndInfo); n != want {
		t.Fatalf("appendSendCmsgs (SNDINFO only) used %d bytes, want cmsgSpace(sizeSndInfo) = %d", n, want)
	}
	full := fullSlice(buf, n)

	checkCmsgHeader(t, full, 0, sizeSndInfo, cmsgSndInfo)

	p := sizeCmsghdr
	if got := binary.NativeEndian.Uint16(full[p+sndInfoStreamOff:]); got != 3 {
		t.Errorf("snd_sid = %d, want 3", got)
	}
	if got := binary.NativeEndian.Uint16(full[p+sndInfoFlagsOff:]); got != uint16(SendUnordered) {
		t.Errorf("snd_flags = %#x, want %#x", got, uint16(SendUnordered))
	}
	// PPID crosses to network order at this boundary: 0x01020304 must land
	// as the big-endian bytes 01 02 03 04, not the host-order bytes
	// binary.NativeEndian would produce on a little-endian build.
	if got, want := full[p+sndInfoPPIDOff:p+sndInfoPPIDOff+4], []byte{0x01, 0x02, 0x03, 0x04}; !bytes.Equal(got, want) {
		t.Errorf("snd_ppid bytes = % x, want % x (big-endian for 0x01020304)", got, want)
	}
	if got := binary.NativeEndian.Uint32(full[p+sndInfoContextOff:]); got != 0x11223344 {
		t.Errorf("snd_context = %#x, want %#x", got, 0x11223344)
	}
	if got := AssocID(binary.NativeEndian.Uint32(full[p+sndInfoAssocIDOff:])); got != 9 {
		t.Errorf("snd_assoc_id = %d, want 9", got)
	}
}

// TestAppendSendCmsgsWritesAssocIDEvenWhenZero pins that Conn.SendMsg's
// AssocID(0) still lands in snd_assoc_id — RFC 6458 §5.3.4 says a
// one-to-one or peeled-off socket ignores it, but the encoder does not
// special-case that; it just always writes what it is given.
func TestAppendSendCmsgsWritesAssocIDEvenWhenZero(t *testing.T) {
	buf := make([]byte, sndCmsgSpace)[:0]
	n := appendSendCmsgs(buf, &SndInfo{}, AssocID(0), nil, nil)
	full := fullSlice(buf, n)
	if got := binary.NativeEndian.Uint32(full[sizeCmsghdr+sndInfoAssocIDOff:]); got != 0 {
		t.Errorf("snd_assoc_id = %d, want 0", got)
	}
}

// TestAppendSendCmsgsEncodesPrInfoWhenSet covers PRINFO placed right after
// SNDINFO, and the PRRtx/PRPrio branch, which uses PrInfo.Value directly.
func TestAppendSendCmsgsEncodesPrInfoWhenSet(t *testing.T) {
	pr := &PrInfo{Policy: PRRtx, Value: 42}
	buf := make([]byte, sndCmsgSpace)[:0]

	n := appendSendCmsgs(buf, &SndInfo{}, 0, pr, nil)
	wantN := cmsgSpace(sizeSndInfo) + cmsgSpace(sizePrInfo)
	if n != wantN {
		t.Fatalf("appendSendCmsgs (SNDINFO+PRINFO) used %d bytes, want %d", n, wantN)
	}
	full := fullSlice(buf, n)

	prOff := cmsgSpace(sizeSndInfo)
	checkCmsgHeader(t, full, prOff, sizePrInfo, cmsgPrInfo)

	p := prOff + sizeCmsghdr
	if got := PRPolicy(binary.NativeEndian.Uint16(full[p+prInfoPolicyOff:])); got != PRRtx {
		t.Errorf("pr_policy = %v, want PRRtx", got)
	}
	if got := binary.NativeEndian.Uint32(full[p+prInfoValueOff:]); got != 42 {
		t.Errorf("pr_value = %d, want 42 (PRRtx uses PrInfo.Value directly)", got)
	}
}

// TestAppendSendCmsgsPRTTLConvertsToMilliseconds covers the PRTTL branch,
// which converts PrInfo.TTL to a millisecond count rather than using Value.
func TestAppendSendCmsgsPRTTLConvertsToMilliseconds(t *testing.T) {
	pr := &PrInfo{Policy: PRTTL, TTL: 2500 * time.Millisecond, Value: 999}
	buf := make([]byte, sndCmsgSpace)[:0]

	n := appendSendCmsgs(buf, &SndInfo{}, 0, pr, nil)
	full := fullSlice(buf, n)

	p := cmsgSpace(sizeSndInfo) + sizeCmsghdr
	if got := binary.NativeEndian.Uint32(full[p+prInfoValueOff:]); got != 2500 {
		t.Errorf("pr_value = %d, want 2500 (from a 2500ms TTL; PrInfo.Value must be ignored for PRTTL)", got)
	}
}

// TestAppendSendCmsgsPRNoneEncodesZeroValue pins the kernel's own rule
// (net/sctp/socket.c: sctp_msghdr_parse, "if (cmsgs->prinfo->pr_policy ==
// SCTP_PR_SCTP_NONE) cmsgs->prinfo->pr_value = 0;"): PRNone always encodes
// pr_value 0, whatever PrInfo.Value or PrInfo.TTL held.
func TestAppendSendCmsgsPRNoneEncodesZeroValue(t *testing.T) {
	pr := &PrInfo{Policy: PRNone, Value: 999, TTL: 5 * time.Second}
	buf := make([]byte, sndCmsgSpace)[:0]

	n := appendSendCmsgs(buf, &SndInfo{}, 0, pr, nil)
	full := fullSlice(buf, n)

	p := cmsgSpace(sizeSndInfo) + sizeCmsghdr
	if got := PRPolicy(binary.NativeEndian.Uint16(full[p+prInfoPolicyOff:])); got != PRNone {
		t.Fatalf("pr_policy = %v, want PRNone", got)
	}
	if got := binary.NativeEndian.Uint32(full[p+prInfoValueOff:]); got != 0 {
		t.Errorf("pr_value = %d, want 0 — Linux zeroes it for PRNone even though PrInfo.Value/TTL were non-zero", got)
	}
}

// TestAppendSendCmsgsEncodesAuthInfoWhenKeySet covers AUTHINFO placed
// directly after SNDINFO when no PRINFO is present, so its offset must not
// assume PRINFO always precedes it.
func TestAppendSendCmsgsEncodesAuthInfoWhenKeySet(t *testing.T) {
	key := uint16(7)
	buf := make([]byte, sndCmsgSpace)[:0]

	n := appendSendCmsgs(buf, &SndInfo{}, 0, nil, &key)
	wantN := cmsgSpace(sizeSndInfo) + cmsgSpace(sizeAuthInfo)
	if n != wantN {
		t.Fatalf("appendSendCmsgs (SNDINFO+AUTHINFO, no PRINFO) used %d bytes, want %d", n, wantN)
	}
	full := fullSlice(buf, n)

	authOff := cmsgSpace(sizeSndInfo)
	checkCmsgHeader(t, full, authOff, sizeAuthInfo, cmsgAuthInfo)

	if got := binary.NativeEndian.Uint16(full[authOff+sizeCmsghdr+authInfoKeyNumberOff:]); got != 7 {
		t.Errorf("auth_keynumber = %d, want 7", got)
	}
}

// TestAppendSendCmsgsAuthInfoAlone covers the one send that carries
// AUTHINFO and nothing else: a Conn send that sets SendOptions.AuthKey but
// neither Info nor PR, which leaves the association's defaults to the
// kernel (sctp_sendmsg_update_sinfo applies them only to a message with no
// SNDINFO) and so must not send an SNDINFO at all.
func TestAppendSendCmsgsAuthInfoAlone(t *testing.T) {
	key := uint16(5)
	buf := make([]byte, sndCmsgSpace)[:0]

	n := appendSendCmsgs(buf, nil, 0, nil, &key)
	if want := cmsgSpace(sizeAuthInfo); n != want {
		t.Fatalf("appendSendCmsgs (AUTHINFO only) used %d bytes, want cmsgSpace(sizeAuthInfo) = %d", n, want)
	}
	full := fullSlice(buf, n)
	checkCmsgHeader(t, full, 0, sizeAuthInfo, cmsgAuthInfo)
	if got := binary.NativeEndian.Uint16(full[sizeCmsghdr+authInfoKeyNumberOff:]); got != 5 {
		t.Errorf("auth_keynumber = %d, want 5", got)
	}
}

// TestAppendSendCmsgsNothingToEncode: with no record requested the encoder
// writes nothing, so a caller can pass its result straight to
// msg_controllen.
func TestAppendSendCmsgsNothingToEncode(t *testing.T) {
	buf := make([]byte, sndCmsgSpace)[:0]
	if n := appendSendCmsgs(buf, nil, 0, nil, nil); n != 0 {
		t.Errorf("appendSendCmsgs with no records used %d bytes, want 0", n)
	}
}

// TestAppendSendCmsgsAllThreeFitsSndCmsgSpaceExactly is the worst case
// SendOptions can produce: SNDINFO, PRINFO and AUTHINFO all present. The
// total must fit sndCmsgSpace exactly — a too-small buffer for this
// combination is what lksctp-tools issue #68 documents.
func TestAppendSendCmsgsAllThreeFitsSndCmsgSpaceExactly(t *testing.T) {
	snd := &SndInfo{Stream: 1, PPID: 0xabcd}
	pr := &PrInfo{Policy: PRPrio, Value: 5}
	key := uint16(2)
	buf := make([]byte, sndCmsgSpace)[:0]

	n := appendSendCmsgs(buf, snd, AssocID(3), pr, &key)
	if n != sndCmsgSpace {
		t.Fatalf("appendSendCmsgs with Info, PR and AuthKey all set used %d bytes, want sndCmsgSpace (%d)", n, sndCmsgSpace)
	}
	full := fullSlice(buf, n)

	sndOff := 0
	prOff := cmsgSpace(sizeSndInfo)
	authOff := prOff + cmsgSpace(sizePrInfo)
	if want := sndCmsgSpace; authOff+cmsgSpace(sizeAuthInfo) != want {
		t.Fatalf("computed authOff+cmsgSpace(sizeAuthInfo) = %d, want %d", authOff+cmsgSpace(sizeAuthInfo), want)
	}

	checkCmsgHeader(t, full, sndOff, sizeSndInfo, cmsgSndInfo)
	checkCmsgHeader(t, full, prOff, sizePrInfo, cmsgPrInfo)
	checkCmsgHeader(t, full, authOff, sizeAuthInfo, cmsgAuthInfo)
}

// TestAppendSendCmsgsZeroesPaddingGaps proves every gap a poisoned, reused
// buffer (sendState.cbuf, one array across every SendMsg call) could leak
// stale bytes through gets cleared: struct sctp_prinfo's own internal gap
// (pr_policy ends at offset 2, pr_value starts at prInfoValueOff, offset 4
// — abi.go's comment on why), which a field-by-field write never touches
// directly, and the CMSG_ALIGN gap after AUTHINFO's 2-byte payload. Both
// gaps are non-empty on every word size this package targets (4 and 8):
// prInfoValueOff is a fixed 4 regardless of word size, and cmsgAlign(2) is
// never 2 for either wordSize, so neither subtest below can be vacuous.
func TestAppendSendCmsgsZeroesPaddingGaps(t *testing.T) {
	poisoned := make([]byte, sndCmsgSpace)
	for i := range poisoned {
		poisoned[i] = 0xff
	}
	buf := poisoned[:0]

	key := uint16(1)
	n := appendSendCmsgs(buf, &SndInfo{}, 0, &PrInfo{Policy: PRTTL, TTL: time.Millisecond}, &key)
	full := fullSlice(buf, n)

	checkZero := func(t *testing.T, from, to int) {
		t.Helper()
		for i := from; i < to; i++ {
			if full[i] != 0 {
				t.Errorf("padding byte at offset %d = %#x, want 0 (poisoned buffer, so a non-zero byte proves the gap was not cleared)", i, full[i])
			}
		}
	}

	t.Run("PRINFO's internal gap (pr_policy padding, payload bytes 2-3)", func(t *testing.T) {
		prOff := cmsgSpace(sizeSndInfo)
		checkZero(t, prOff+sizeCmsghdr+2, prOff+sizeCmsghdr+prInfoValueOff)
	})

	t.Run("AUTHINFO's trailing CMSG_ALIGN gap", func(t *testing.T) {
		authOff := cmsgSpace(sizeSndInfo) + cmsgSpace(sizePrInfo)
		checkZero(t, authOff+sizeCmsghdr+sizeAuthInfo, authOff+cmsgSpace(sizeAuthInfo))
	})
}

// TestAppendSendCmsgsDoesNotMutateInputs covers a real v1 bug class
// (git show main:sctp_cmsgbuild_test.go, TestSCTPWriteDoesNotMutateInfo):
// the old builder byte-swapped PPID in place and restored it afterward,
// which raced with a concurrent reader of the same *SndInfo. appendSendCmsgs
// only ever reads snd, pr and *key; this pins that none of the three ever
// changes underneath the caller.
func TestAppendSendCmsgsDoesNotMutateInputs(t *testing.T) {
	snd := &SndInfo{Stream: 2, Flags: SendUnordered, PPID: 0x11223344, Context: 9}
	pr := &PrInfo{Policy: PRTTL, TTL: 250 * time.Millisecond}
	key := uint16(6)
	beforeSnd, beforePr, beforeKey := *snd, *pr, key

	buf := make([]byte, sndCmsgSpace)[:0]
	appendSendCmsgs(buf, snd, 4, pr, &key)

	if *snd != beforeSnd {
		t.Errorf("appendSendCmsgs mutated its SndInfo argument: got %+v, want %+v", *snd, beforeSnd)
	}
	if *pr != beforePr {
		t.Errorf("appendSendCmsgs mutated its PrInfo argument: got %+v, want %+v", *pr, beforePr)
	}
	if key != beforeKey {
		t.Errorf("appendSendCmsgs mutated its AuthKey argument: got %#x, want %#x", key, beforeKey)
	}
}

// TestAppendSendCmsgsConcurrentSharedInputs exercises the race the v1 bug
// above created: several goroutines encoding from one shared, logically
// read-only *SndInfo and *PrInfo at once. Meaningful only under -race,
// which the Docker suite and go test -race both run this package under.
func TestAppendSendCmsgsConcurrentSharedInputs(t *testing.T) {
	snd := &SndInfo{Stream: 1, PPID: 0x01020304}
	pr := &PrInfo{Policy: PRRtx, Value: 3}
	key := uint16(1)

	const goroutines = 8
	const perGoroutine = 200
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			var cbuf [sndCmsgSpace]byte
			for j := 0; j < perGoroutine; j++ {
				if n := appendSendCmsgs(cbuf[:0], snd, AssocID(j), pr, &key); n != sndCmsgSpace {
					t.Errorf("appendSendCmsgs used %d bytes, want %d", n, sndCmsgSpace)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestAppendSendCmsgsAllocatesNothing pins appendSendCmsgs's zero-allocation
// contract for the worst case (all three records), with the garbage
// collector paused so a collection mid-measurement cannot be miscounted
// against it, and skipped under the race detector, whose own
// instrumentation allocates on its own account.
func TestAppendSendCmsgsAllocatesNothing(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector")
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	var cbuf [sndCmsgSpace]byte

	allocs := testing.AllocsPerRun(200, func() {
		snd := SndInfo{Stream: 1, Flags: SendUnordered, PPID: 9, Context: 4}
		pr := PrInfo{Policy: PRTTL, TTL: time.Second}
		key := uint16(3)
		if n := appendSendCmsgs(cbuf[:0], &snd, 5, &pr, &key); n != sndCmsgSpace {
			t.Fatalf("appendSendCmsgs used %d bytes, want %d", n, sndCmsgSpace)
		}
	})
	if allocs != 0 {
		t.Errorf("appendSendCmsgs allocated %.1f times, want 0", allocs)
	}
}

// --- validateSendOptions --------------------------------------------------

// wantRefused asserts that err matches syscall.EINVAL and that its message
// names field (e.g. "SendOptions.PR.Policy"), so a caller reading the
// error text can tell which part of SendOptions was refused without
// needing errors.As on an internal type.
func wantRefused(t *testing.T, err error, field string) {
	t.Helper()
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("err = %v, want an error matching syscall.EINVAL", err)
	}
	if !strings.Contains(err.Error(), field) {
		t.Errorf("err = %q, want it to name %q", err.Error(), field)
	}
}

func TestValidateSendOptionsRefusesPRAll(t *testing.T) {
	err := validateSendOptions(&SendOptions{PR: &PrInfo{Policy: PRAll}})
	wantRefused(t, err, "SendOptions.PR.Policy")
}

func TestValidateSendOptionsRefusesUnknownPRPolicyBits(t *testing.T) {
	// PRPrio (0x0030) with an extra bit outside SCTP_PR_SCTP_MASK (0x0030).
	err := validateSendOptions(&SendOptions{PR: &PrInfo{Policy: PRPolicy(0x0031)}})
	wantRefused(t, err, "SendOptions.PR.Policy")
}

func TestValidateSendOptionsRefusesTTLNotWholeMilliseconds(t *testing.T) {
	err := validateSendOptions(&SendOptions{PR: &PrInfo{Policy: PRTTL, TTL: 1500 * time.Microsecond}})
	wantRefused(t, err, "SendOptions.PR.TTL")
}

func TestValidateSendOptionsRefusesTTLExceedingUint32Milliseconds(t *testing.T) {
	// Exactly one millisecond past the uint32 range struct sctp_prinfo's
	// pr_value carries — the precise boundary, paired with
	// TestValidateSendOptionsAcceptsExactUint32MillisecondTTL, which pins
	// that math.MaxUint32 ms itself is still accepted.
	huge := time.Duration(uint64(math.MaxUint32)+1) * time.Millisecond
	err := validateSendOptions(&SendOptions{PR: &PrInfo{Policy: PRTTL, TTL: huge}})
	wantRefused(t, err, "SendOptions.PR.TTL")
}

func TestValidateSendOptionsRefusesNegativeTTL(t *testing.T) {
	err := validateSendOptions(&SendOptions{PR: &PrInfo{Policy: PRTTL, TTL: -time.Millisecond}})
	wantRefused(t, err, "SendOptions.PR.TTL")
}

func TestValidateSendOptionsRefusesUnknownSendFlagsBit(t *testing.T) {
	err := validateSendOptions(&SendOptions{Info: &SndInfo{Flags: SendFlags(1 << 5)}})
	wantRefused(t, err, "SendOptions.Info.Flags")
}

func TestValidateSendOptionsAcceptsExactUint32MillisecondTTL(t *testing.T) {
	// The other side of the boundary TestValidateSendOptionsRefusesTTLExceedingUint32Milliseconds
	// pins: math.MaxUint32 ms itself fits pr_value exactly and must not be
	// refused.
	ttl := time.Duration(math.MaxUint32) * time.Millisecond
	err := validateSendOptions(&SendOptions{PR: &PrInfo{Policy: PRTTL, TTL: ttl}})
	if err != nil {
		t.Fatalf("validateSendOptions(TTL exactly math.MaxUint32 ms) = %v, want nil", err)
	}
}

func TestValidateSendOptionsAcceptsValidCombinations(t *testing.T) {
	for i, opts := range []*SendOptions{
		{},
		{Info: &SndInfo{Flags: SendUnordered}},
		{Info: &SndInfo{Flags: SendUnordered | SendSACKImmediately}},
		{PR: &PrInfo{Policy: PRNone}},
		// TTL is meaningless for PRNone, so a value that would fail the
		// whole-millisecond check for PRTTL must not be checked here.
		{PR: &PrInfo{Policy: PRNone, TTL: 1500 * time.Microsecond}},
		{PR: &PrInfo{Policy: PRTTL, TTL: 250 * time.Millisecond}},
		{PR: &PrInfo{Policy: PRTTL, TTL: 0}},
		{PR: &PrInfo{Policy: PRRtx, Value: 3}},
		{PR: &PrInfo{Policy: PRPrio, Value: 10}},
		{Info: &SndInfo{Flags: SendUnordered}, PR: &PrInfo{Policy: PRTTL, TTL: time.Second}, AuthKey: new(uint16)},
	} {
		if err := validateSendOptions(opts); err != nil {
			t.Errorf("case %d (%+v): unexpected error %v", i, opts, err)
		}
	}
}

// TestValidateSendOptionsAllocatesNothingOnSuccess pins the success-path
// zero-allocation contract, the same way TestAppendSendCmsgsAllocatesNothing
// does for the encoder.
func TestValidateSendOptionsAllocatesNothingOnSuccess(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector")
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	allocs := testing.AllocsPerRun(200, func() {
		info := SndInfo{Flags: SendUnordered}
		pr := PrInfo{Policy: PRTTL, TTL: 250 * time.Millisecond}
		opts := SendOptions{Info: &info, PR: &pr}
		if err := validateSendOptions(&opts); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Errorf("validateSendOptions allocated %.1f times on success, want 0", allocs)
	}
}

// --- validateDefaultSndInfo -------------------------------------------------

// TestValidateDefaultSndInfo covers the rule a socket-default SndInfo
// follows, whether it comes from Config.DefaultSndInfo or
// Conn.SetDefaultSndInfo: SendUnordered is the only flag it may hold.
// Linux refuses SCTP_SACK_IMMEDIATELY in a default with EINVAL
// (sctp_setsockopt_default_sndinfo), and the other bits it accepts there
// have no SendFlags value.
func TestValidateDefaultSndInfo(t *testing.T) {
	for _, ok := range []SendFlags{0, SendUnordered} {
		if err := validateDefaultSndInfo("SetDefaultSndInfo", &SndInfo{Stream: 2, Flags: ok, PPID: 9}); err != nil {
			t.Errorf("flags %v: unexpected error %v", ok, err)
		}
	}
	for _, bad := range []SendFlags{SendSACKImmediately, SendUnordered | SendSACKImmediately, SendFlags(1 << 5)} {
		err := validateDefaultSndInfo("SetDefaultSndInfo", &SndInfo{Flags: bad})
		wantRefused(t, err, "SetDefaultSndInfo.Flags")
	}
}

// BenchmarkAppendSendCmsgs measures encoding the worst-case control
// message, SNDINFO, PRINFO and AUTHINFO together, into a reused buffer (v1
// BenchmarkBuildSndRcvCmsg measured its SCTP_SNDRCV builder, which
// allocated its buffer on every call).
func BenchmarkAppendSendCmsgs(b *testing.B) {
	var cbuf [sndCmsgSpace]byte
	snd := SndInfo{Stream: 1, Flags: SendUnordered, PPID: 0x1234, Context: 4}
	pr := PrInfo{Policy: PRTTL, TTL: time.Second}
	key := uint16(3)
	b.ReportAllocs()
	for b.Loop() {
		if n := appendSendCmsgs(cbuf[:0], &snd, 0, &pr, &key); n != sndCmsgSpace {
			b.Fatalf("appendSendCmsgs used %d bytes, want %d", n, sndCmsgSpace)
		}
	}
}

// --- parseRecvCmsgs --------------------------------------------------------

func TestParseRecvCmsgsFillsRcvInfo(t *testing.T) {
	payload := rcvInfoPayload(4, 55, true, 0x01020304, 1000, 999, 42, 7)
	oob := buildRecvCmsg(nil, cmsgRcvInfo, payload)

	var info MsgInfo
	if err := parseRecvCmsgs(oob, 0, &info); err != nil {
		t.Fatalf("parseRecvCmsgs: %v", err)
	}
	want := RcvInfo{Stream: 4, SSN: 55, Unordered: true, PPID: 0x01020304, TSN: 1000, CumTSN: 999, Context: 42, AssocID: 7}
	if info.Rcv != want {
		t.Errorf("Rcv = %+v, want %+v", info.Rcv, want)
	}
}

func TestParseRecvCmsgsRcvInfoOrderedWhenUnorderedBitClear(t *testing.T) {
	oob := buildRecvCmsg(nil, cmsgRcvInfo, rcvInfoPayload(1, 0, false, 1, 1, 1, 1, 1))
	var info MsgInfo
	if err := parseRecvCmsgs(oob, 0, &info); err != nil {
		t.Fatalf("parseRecvCmsgs: %v", err)
	}
	if info.Rcv.Unordered {
		t.Error("Rcv.Unordered = true, want false when rcv_flags carries no SCTP_UNORDERED bit")
	}
}

func TestParseRecvCmsgsFillsNxtInfoAndSetsHasNxt(t *testing.T) {
	oob := buildRecvCmsg(nil, cmsgNxtInfo, nxtInfoPayload(6, true, false, 0x0a0b0c0d, 128, 3))

	var info MsgInfo
	if err := parseRecvCmsgs(oob, 0, &info); err != nil {
		t.Fatalf("parseRecvCmsgs: %v", err)
	}
	if !info.HasNxt {
		t.Fatal("HasNxt = false, want true")
	}
	want := NxtInfo{Stream: 6, Unordered: true, Notification: false, PPID: 0x0a0b0c0d, Length: 128, AssocID: 3}
	if info.Nxt != want {
		t.Errorf("Nxt = %+v, want %+v", info.Nxt, want)
	}
}

func TestParseRecvCmsgsNxtInfoNotificationBit(t *testing.T) {
	oob := buildRecvCmsg(nil, cmsgNxtInfo, nxtInfoPayload(2, false, true, 0, 100, 5))

	var info MsgInfo
	if err := parseRecvCmsgs(oob, 0, &info); err != nil {
		t.Fatalf("parseRecvCmsgs: %v", err)
	}
	if !info.HasNxt {
		t.Fatal("HasNxt = false, want true")
	}
	if !info.Nxt.Notification {
		t.Error("Nxt.Notification = false, want true when nxt_flags carries SCTP_NOTIFICATION")
	}
}

// TestParseRecvCmsgsIgnoresShortPayloads covers a RCVINFO or NXTINFO record
// whose declared payload is shorter than the struct it claims to carry: a
// cmsg_len that undershoots sizeRcvInfo/sizeNxtInfo must be skipped rather
// than decoded out of bounds or partially trusted.
func TestParseRecvCmsgsIgnoresShortPayloads(t *testing.T) {
	t.Run("RCVINFO", func(t *testing.T) {
		short := rcvInfoPayload(4, 5, true, 6, 7, 8, 9, 10)[:sizeRcvInfo-1]
		oob := buildRecvCmsg(nil, cmsgRcvInfo, short)

		var info MsgInfo
		if err := parseRecvCmsgs(oob, 0, &info); err != nil {
			t.Fatalf("parseRecvCmsgs: %v", err)
		}
		if info.Rcv != (RcvInfo{}) {
			t.Errorf("Rcv = %+v, want zero — a short RCVINFO payload must be ignored, not partially decoded", info.Rcv)
		}
	})

	t.Run("NXTINFO", func(t *testing.T) {
		short := nxtInfoPayload(4, true, false, 6, 7, 8)[:sizeNxtInfo-1]
		oob := buildRecvCmsg(nil, cmsgNxtInfo, short)

		var info MsgInfo
		if err := parseRecvCmsgs(oob, 0, &info); err != nil {
			t.Fatalf("parseRecvCmsgs: %v", err)
		}
		if info.HasNxt {
			t.Errorf("HasNxt = true, want false — a short NXTINFO payload must be ignored, not partially decoded")
		}
		if info.Nxt != (NxtInfo{}) {
			t.Errorf("Nxt = %+v, want zero", info.Nxt)
		}
	})
}

// TestParseRecvCmsgsRcvInfoThenNxtInfo exercises the walk from one record
// to the next, the case a single-record test cannot: a wrong CMSG_ALIGN gap
// would make this read NXTINFO's header at the wrong offset.
func TestParseRecvCmsgsRcvInfoThenNxtInfo(t *testing.T) {
	oob := buildRecvCmsg(nil, cmsgRcvInfo, rcvInfoPayload(1, 2, false, 10, 20, 30, 40, 50))
	oob = buildRecvCmsg(oob, cmsgNxtInfo, nxtInfoPayload(6, true, false, 60, 70, 80))

	var info MsgInfo
	if err := parseRecvCmsgs(oob, 0, &info); err != nil {
		t.Fatalf("parseRecvCmsgs: %v", err)
	}
	if info.Rcv.Stream != 1 {
		t.Errorf("Rcv.Stream = %d, want 1 — a misaligned walk would read NXTINFO's header as RCVINFO's payload", info.Rcv.Stream)
	}
	if !info.HasNxt || info.Nxt.Stream != 6 {
		t.Errorf("HasNxt=%v Nxt.Stream=%d, want true and 6", info.HasNxt, info.Nxt.Stream)
	}
}

// TestParseRecvCmsgsKernelOrderNxtInfoThenRcvInfo mirrors the order Linux
// actually emits the two records in: sctp_recvmsg (net/sctp/socket.c)
// checks sp->recvnxtinfo and calls sctp_ulpevent_read_nxtinfo before it
// checks sp->recvrcvinfo and calls sctp_ulpevent_read_rcvinfo, so a real
// oob buffer has NXTINFO first — the opposite of
// TestParseRecvCmsgsRcvInfoThenNxtInfo's order, which only proves the walk
// is order-agnostic in the abstract.
func TestParseRecvCmsgsKernelOrderNxtInfoThenRcvInfo(t *testing.T) {
	oob := buildRecvCmsg(nil, cmsgNxtInfo, nxtInfoPayload(6, true, false, 60, 70, 80))
	oob = buildRecvCmsg(oob, cmsgRcvInfo, rcvInfoPayload(1, 2, false, 10, 20, 30, 40, 50))

	var info MsgInfo
	if err := parseRecvCmsgs(oob, 0, &info); err != nil {
		t.Fatalf("parseRecvCmsgs: %v", err)
	}
	if !info.HasNxt || info.Nxt.Stream != 6 {
		t.Errorf("HasNxt=%v Nxt.Stream=%d, want true and 6", info.HasNxt, info.Nxt.Stream)
	}
	if info.Rcv.Stream != 1 {
		t.Errorf("Rcv.Stream = %d, want 1 — a misaligned walk would read RCVINFO's header at the wrong offset", info.Rcv.Stream)
	}
}

func TestParseRecvCmsgsIgnoresNonSCTPLevelRecords(t *testing.T) {
	const notIPPROTOSCTP = 6 // IPPROTO_TCP, just needs to differ from IPPROTO_SCTP
	oob := buildRecvCmsgLevel(nil, notIPPROTOSCTP, cmsgRcvInfo, rcvInfoPayload(1, 2, false, 3, 4, 5, 6, 7))

	var info MsgInfo
	if err := parseRecvCmsgs(oob, 0, &info); err != nil {
		t.Fatalf("parseRecvCmsgs: %v", err)
	}
	if info.Rcv != (RcvInfo{}) {
		t.Errorf("Rcv = %+v, want zero — a cmsg_level other than IPPROTO_SCTP must be ignored", info.Rcv)
	}
}

func TestParseRecvCmsgsEOR(t *testing.T) {
	var info MsgInfo
	if err := parseRecvCmsgs(nil, msgEOR, &info); err != nil {
		t.Fatalf("parseRecvCmsgs: %v", err)
	}
	if !info.EOR {
		t.Error("EOR = false, want true when flags carries MSG_EOR")
	}
}

func TestParseRecvCmsgsNotificationZeroesRcvEvenWithRcvInfoPresent(t *testing.T) {
	oob := buildRecvCmsg(nil, cmsgRcvInfo, rcvInfoPayload(9, 1, false, 123, 1, 1, 1, 1))

	var info MsgInfo
	if err := parseRecvCmsgs(oob, msgNotification, &info); err != nil {
		t.Fatalf("parseRecvCmsgs: %v", err)
	}
	if !info.Notification {
		t.Fatal("Notification = false, want true")
	}
	if info.Rcv != (RcvInfo{}) {
		t.Errorf("Rcv = %+v, want zero — MsgInfo.Notification true means Rcv is zero even when a RCVINFO record is present", info.Rcv)
	}
}

func TestParseRecvCmsgsCtruncReturnsError(t *testing.T) {
	var info MsgInfo
	err := parseRecvCmsgs(nil, msgCtrunc, &info)
	if !errors.Is(err, ErrControlTruncated) {
		t.Fatalf("parseRecvCmsgs err = %v, want ErrControlTruncated", err)
	}
}

func TestParseRecvCmsgsCtruncKeepsWhatParsedBeforeIt(t *testing.T) {
	oob := buildRecvCmsg(nil, cmsgRcvInfo, rcvInfoPayload(3, 0, false, 1, 2, 3, 4, 5))

	var info MsgInfo
	err := parseRecvCmsgs(oob, msgCtrunc, &info)
	if !errors.Is(err, ErrControlTruncated) {
		t.Fatalf("parseRecvCmsgs err = %v, want ErrControlTruncated", err)
	}
	if info.Rcv.Stream != 3 {
		t.Errorf("Rcv.Stream = %d, want 3 — MSG_CTRUNC must not discard a record already parsed", info.Rcv.Stream)
	}
}

// TestParseRecvCmsgsHandlesPutCmsgTruncation builds an oob buffer in the
// exact shape put_cmsg (net/core/scm.c) leaves when msg_controllen runs out
// partway through a record, rather than before the record starts: it sets
// cmsg_len to whatever room was actually left ("if (msg->msg_controllen <
// cmlen) { msg->msg_flags |= MSG_CTRUNC; cmlen = msg->msg_controllen; }"),
// not the record's true length, and copies only that many payload bytes.
// This is a torn RCVINFO, not the "nothing written at all" case
// TestParseRecvCmsgsCtruncKeepsWhatParsedBeforeIt already covers.
func TestParseRecvCmsgsHandlesPutCmsgTruncation(t *testing.T) {
	full := rcvInfoPayload(9, 1, false, 123, 1, 1, 1, 1)
	room := sizeCmsghdr + 5 // enough for the header plus a few payload bytes, short of sizeRcvInfo
	oob := make([]byte, room)
	putWord(oob[cmsghdrLenOff:], uint64(room)) // put_cmsg: cmlen = msg->msg_controllen
	binary.NativeEndian.PutUint32(oob[cmsghdrLevelOff:], uint32(ipprotoSCTP))
	binary.NativeEndian.PutUint32(oob[cmsghdrTypeOff:], uint32(cmsgRcvInfo))
	copy(oob[sizeCmsghdr:], full[:5])

	var info MsgInfo
	err := parseRecvCmsgs(oob, msgCtrunc, &info)
	if !errors.Is(err, ErrControlTruncated) {
		t.Fatalf("parseRecvCmsgs err = %v, want ErrControlTruncated", err)
	}
	if info.Rcv != (RcvInfo{}) {
		t.Errorf("Rcv = %+v, want zero — a torn RCVINFO record must not be partially decoded", info.Rcv)
	}
}

func TestParseRecvCmsgsResetsInfoEachCall(t *testing.T) {
	oob := buildRecvCmsg(nil, cmsgRcvInfo, rcvInfoPayload(1, 0, false, 1, 1, 1, 1, 1))
	info := MsgInfo{EOR: true, Notification: true, HasNxt: true, Nxt: NxtInfo{Stream: 99}}

	if err := parseRecvCmsgs(oob, 0, &info); err != nil {
		t.Fatalf("parseRecvCmsgs: %v", err)
	}
	if info.EOR || info.Notification || info.HasNxt {
		t.Errorf("stale MsgInfo fields survived: EOR=%v Notification=%v HasNxt=%v, want all false", info.EOR, info.Notification, info.HasNxt)
	}
	if info.Nxt != (NxtInfo{}) {
		t.Errorf("Nxt = %+v, want zero — a call with no NXTINFO record must clear a previous call's Nxt", info.Nxt)
	}
}

// TestParseRecvCmsgsAllocatesNothing pins parseRecvCmsgs's zero-allocation
// contract: the receive path calls it on every RecvMsg.
func TestParseRecvCmsgsAllocatesNothing(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector")
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	oob := buildRecvCmsg(nil, cmsgRcvInfo, rcvInfoPayload(1, 2, true, 3, 4, 5, 6, 7))
	oob = buildRecvCmsg(oob, cmsgNxtInfo, nxtInfoPayload(8, false, true, 9, 10, 11))

	allocs := testing.AllocsPerRun(200, func() {
		var info MsgInfo
		if err := parseRecvCmsgs(oob, msgEOR, &info); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Errorf("parseRecvCmsgs allocated %.1f times, want 0", allocs)
	}
}

// FuzzParseRecvCmsgs exercises the hostile side of the boundary: oob is
// whatever bytes a caller driving recvmsg() through SyscallConn might hand
// in, truncated, spliced or otherwise altered. parseRecvCmsgs must never
// panic, whatever flags and oob contain.
func FuzzParseRecvCmsgs(f *testing.F) {
	f.Add([]byte{}, 0)
	f.Add(buildRecvCmsg(nil, cmsgRcvInfo, rcvInfoPayload(1, 2, true, 3, 4, 5, 6, 7)), 0)
	f.Add(buildRecvCmsg(nil, cmsgNxtInfo, nxtInfoPayload(1, false, true, 2, 3, 4)), int(msgEOR))
	f.Add([]byte{0x01}, int(msgCtrunc))

	f.Fuzz(func(t *testing.T, oob []byte, flags int) {
		if len(oob) > 4096 {
			t.Skip()
		}
		var info MsgInfo
		err := parseRecvCmsgs(oob, flags, &info)

		if info.Notification && info.Rcv != (RcvInfo{}) {
			t.Errorf("Notification=true but Rcv=%+v, want zero", info.Rcv)
		}
		if !info.HasNxt && info.Nxt != (NxtInfo{}) {
			t.Errorf("HasNxt=false but Nxt=%+v, want zero", info.Nxt)
		}
		if want := flags&msgEOR != 0; info.EOR != want {
			t.Errorf("EOR=%v, want %v (flags&msgEOR != 0)", info.EOR, want)
		}
		wantErr := flags&msgCtrunc != 0
		if gotErr := err != nil; gotErr != wantErr {
			t.Errorf("err=%v (non-nil=%v), want non-nil iff flags&msgCtrunc != 0 (%v)", err, gotErr, wantErr)
		}
		if err != nil && !errors.Is(err, ErrControlTruncated) {
			t.Errorf("err=%v, want ErrControlTruncated", err)
		}
	})
}

// --- splitDefaultFlags ------------------------------------------------------

func TestSplitDefaultFlags(t *testing.T) {
	for _, tc := range []struct {
		raw        uint16
		wantFlags  SendFlags
		wantPolicy PRPolicy
		reason     string
	}{
		{raw: 0x0000, wantFlags: 0, wantPolicy: PRNone,
			reason: "zero word"},
		{raw: 0x0031, wantFlags: SendUnordered, wantPolicy: PRPrio,
			reason: "SendUnordered | PRPrio"},
		{raw: 0x0011, wantFlags: SendUnordered, wantPolicy: PRTTL,
			reason: "SendUnordered | PRTTL"},
		// sctp_setsockopt_default_sndinfo and sctp_setsockopt_default_send_param
		// (net/sctp/socket.c) both accept SCTP_ADDR_OVER (0x02), SCTP_ABORT
		// (0x04) and SCTP_EOF (0x200) in this word — not SCTP_SACK_IMMEDIATELY
		// (0x08), which the kernel itself already refuses there — so a
		// default set through Control could legitimately carry any of the
		// three. None has a SendFlags bit, and none may leak into the
		// SendFlags value a default send reapplies.
		{raw: 0x0003, wantFlags: SendUnordered, wantPolicy: PRNone,
			reason: "SendUnordered | SCTP_ADDR_OVER: the ADDR_OVER bit must not leak through"},
		{raw: 0x0005, wantFlags: SendUnordered, wantPolicy: PRNone,
			reason: "SendUnordered | SCTP_ABORT: the ABORT bit must not leak through"},
		{raw: 0x0201, wantFlags: SendUnordered, wantPolicy: PRNone,
			reason: "SendUnordered | SCTP_EOF: the EOF bit must not leak through"},
		{raw: 0x0206, wantFlags: 0, wantPolicy: PRNone,
			reason: "SCTP_ADDR_OVER | SCTP_ABORT | SCTP_EOF with no SendUnordered at all: none of the three is SendUnordered"},
	} {
		gotFlags, gotPolicy := splitDefaultFlags(tc.raw)
		if gotFlags != tc.wantFlags || gotPolicy != tc.wantPolicy {
			t.Errorf("splitDefaultFlags(%#04x) = (%v, %v), want (%v, %v) [%s]",
				tc.raw, gotFlags, gotPolicy, tc.wantFlags, tc.wantPolicy, tc.reason)
		}
	}
}

// --- cmsg layout formulas ---------------------------------------------------

func TestSndCmsgSpaceMatchesCmsgSpace(t *testing.T) {
	want := cmsgSpace(sizeSndInfo) + cmsgSpace(sizePrInfo) + cmsgSpace(sizeAuthInfo)
	if sndCmsgSpace != want {
		t.Errorf("sndCmsgSpace = %d, want cmsgSpace(SNDINFO)+cmsgSpace(PRINFO)+cmsgSpace(AUTHINFO) = %d", sndCmsgSpace, want)
	}
}

func TestRcvCmsgSpaceMatchesCmsgSpace(t *testing.T) {
	want := cmsgSpace(sizeRcvInfo) + cmsgSpace(sizeNxtInfo)
	if rcvCmsgSpace != want {
		t.Errorf("rcvCmsgSpace = %d, want cmsgSpace(RCVINFO)+cmsgSpace(NXTINFO) = %d", rcvCmsgSpace, want)
	}
}

// TestCmsgFormulaAcrossWordSizes recomputes CMSG_ALIGN/CMSG_SPACE for both
// word sizes at once (mirrors abi_test.go's TestSockaddrStorageLayoutFormula),
// so a mistake in the formula itself is caught even when this test runs on
// the word size that happens to match the current build. The 64-bit row's
// RCVINFO and NXTINFO totals (48, 32) match v1's own kernel-measured
// comment (git show main:sctp_oobpool_test.go).
func TestCmsgFormulaAcrossWordSizes(t *testing.T) {
	for _, tc := range []struct {
		align                                            int
		hdrLen                                           int
		sndSpace, prSpace, authSpace, rcvSpace, nxtSpace int
	}{
		{align: 4, hdrLen: 12, sndSpace: 28, prSpace: 20, authSpace: 16, rcvSpace: 40, nxtSpace: 28},
		{align: 8, hdrLen: 16, sndSpace: 32, prSpace: 24, authSpace: 24, rcvSpace: 48, nxtSpace: 32},
	} {
		round := func(n int) int { return (n + tc.align - 1) &^ (tc.align - 1) }
		space := func(n int) int { return tc.hdrLen + round(n) }

		for _, c := range []struct {
			name      string
			got, want int
		}{
			{"cmsghdr size", tc.align + 8, tc.hdrLen},
			{"SNDINFO CMSG_SPACE", space(sizeSndInfo), tc.sndSpace},
			{"PRINFO CMSG_SPACE", space(sizePrInfo), tc.prSpace},
			{"AUTHINFO CMSG_SPACE", space(sizeAuthInfo), tc.authSpace},
			{"RCVINFO CMSG_SPACE", space(sizeRcvInfo), tc.rcvSpace},
			{"NXTINFO CMSG_SPACE", space(sizeNxtInfo), tc.nxtSpace},
		} {
			if c.got != c.want {
				t.Errorf("align %d: %s = %d, want %d", tc.align, c.name, c.got, c.want)
			}
		}

		if tc.align != wordSize {
			continue
		}
		if sizeCmsghdr != tc.hdrLen {
			t.Errorf("sizeCmsghdr = %d, want %d for this build's word size", sizeCmsghdr, tc.hdrLen)
		}
		for _, c := range []struct {
			name      string
			got, want int
		}{
			{"cmsgSpace(sizeSndInfo)", cmsgSpace(sizeSndInfo), tc.sndSpace},
			{"cmsgSpace(sizePrInfo)", cmsgSpace(sizePrInfo), tc.prSpace},
			{"cmsgSpace(sizeAuthInfo)", cmsgSpace(sizeAuthInfo), tc.authSpace},
			{"cmsgSpace(sizeRcvInfo)", cmsgSpace(sizeRcvInfo), tc.rcvSpace},
			{"cmsgSpace(sizeNxtInfo)", cmsgSpace(sizeNxtInfo), tc.nxtSpace},
			{"sndCmsgSpace", sndCmsgSpace, tc.sndSpace + tc.prSpace + tc.authSpace},
			{"rcvCmsgSpace", rcvCmsgSpace, tc.rcvSpace + tc.nxtSpace},
		} {
			if c.got != c.want {
				t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
			}
		}
	}
}

// TestCmsgLenIsExactNotAligned uses sizeAuthInfo (2), the one payload size
// in this file whose CMSG_LEN and CMSG_SPACE differ on every word size this
// package targets (cmsgAlign(2) is 4 on a 32-bit build and 8 on a 64-bit
// one, never 2), so it is the case that catches cmsgLen accidentally
// rounding like cmsgSpace does.
func TestCmsgLenIsExactNotAligned(t *testing.T) {
	if got, want := cmsgLen(sizeAuthInfo), sizeCmsghdr+sizeAuthInfo; got != want {
		t.Errorf("cmsgLen(sizeAuthInfo) = %d, want %d (unaligned)", got, want)
	}
	if got := cmsgLen(sizeAuthInfo); got == cmsgSpace(sizeAuthInfo) {
		t.Fatalf("cmsgLen(sizeAuthInfo) == cmsgSpace(sizeAuthInfo) (%d): this build's word size makes the two coincide, which should not happen for either wordSize this package targets", got)
	}
}
