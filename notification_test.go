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
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
	"runtime/debug"
	"syscall"
	"testing"
)

// notif builds a notification buffer of the given type and size, with the
// header's declared length set to size. Fields below the header stay zero.
func notif(typ EventType, size int) []byte {
	b := make([]byte, size)
	if size >= notificationTypeOff+2 {
		binary.NativeEndian.PutUint16(b[notificationTypeOff:], uint16(typ))
	}
	if size >= notificationLengthOff+4 {
		binary.NativeEndian.PutUint32(b[notificationLengthOff:], uint32(size))
	}
	return b
}

// notifFlags is notif with the header's flags field also set.
func notifFlags(typ EventType, flags uint16, size int) []byte {
	b := notif(typ, size)
	if size >= notificationFlagsOff+2 {
		binary.NativeEndian.PutUint16(b[notificationFlagsOff:], flags)
	}
	return b
}

// notifSized builds a notification whose header declares one length while
// the buffer it arrived in is another (at least notificationHeaderSize),
// filling everything past the header with a recognisable byte.
func notifSized(typ EventType, declared, bufSize int, fill byte) []byte {
	b := make([]byte, bufSize)
	for i := range b {
		b[i] = fill
	}
	binary.NativeEndian.PutUint16(b[notificationTypeOff:], uint16(typ))
	binary.NativeEndian.PutUint16(b[notificationFlagsOff:], 0)
	binary.NativeEndian.PutUint32(b[notificationLengthOff:], uint32(declared))
	return b
}

// TestNotificationMaxSizeHoldsEveryFixedNotification pins NotificationMaxSize
// against every notification's own fixed size, so a caller sizing a read
// buffer as documented can hold any of them whole.
func TestNotificationMaxSizeHoldsEveryFixedNotification(t *testing.T) {
	for _, tc := range []struct {
		name string
		size int
	}{
		{"sctp_assoc_change", sizeAssocChange},
		{"sctp_paddr_change", sizePAddrChange},
		{"sctp_remote_error", sizeRemoteError},
		{"sctp_shutdown_event", sizeShutdownEvent},
		{"sctp_adaptation_event", sizeAdaptationEvent},
		{"sctp_pdapi_event", sizePDAPIEvent},
		{"sctp_sender_dry_event", sizeSenderDryEvent},
		{"sctp_authkey_event", sizeAuthKeyEvent},
		{"sctp_stream_reset_event", sizeStreamResetEvent},
		{"sctp_assoc_reset_event", sizeAssocResetEvent},
		{"sctp_stream_change_event", sizeStreamChangeEvent},
		{"sctp_send_failed_event", sizeSendFailedEvent},
	} {
		if tc.size > NotificationMaxSize {
			t.Errorf("%s is %d bytes but NotificationMaxSize is %d; a caller "+
				"sizing their buffer as documented cannot read this event whole",
				tc.name, tc.size, NotificationMaxSize)
		}
	}
	if NotificationMaxSize <= sizePAddrChange {
		t.Errorf("NotificationMaxSize = %d, which does not exceed the largest "+
			"fixed notification (%d)", NotificationMaxSize, sizePAddrChange)
	}
}

// TestParseNotificationRejectsTruncated checks every length from empty to
// one short of each type's fixed part is refused, and the exact size parses.
// A parser that reads past the end of a truncated notification panics in
// the read path, so each minimum below is load-bearing (the free5gc defect
// this parser exists to avoid).
func TestParseNotificationRejectsTruncated(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  EventType
		full int
	}{
		{"assoc_change", EventAssocChange, sizeAssocChange},
		{"peer_addr_change", EventPeerAddrChange, sizePAddrChange},
		{"remote_error", EventRemoteError, sizeRemoteError},
		{"shutdown", EventShutdown, sizeShutdownEvent},
		{"adaptation", EventAdaptationIndication, sizeAdaptationEvent},
		{"partial_delivery", EventPartialDelivery, sizePDAPIEvent},
		{"sender_dry", EventSenderDry, sizeSenderDryEvent},
		{"authentication", EventAuthentication, sizeAuthKeyEvent},
		{"stream_reset", EventStreamReset, sizeStreamResetEvent},
		{"assoc_reset", EventAssocReset, sizeAssocResetEvent},
		{"stream_change", EventStreamChange, sizeStreamChangeEvent},
		{"send_failed", EventSendFailed, sizeSendFailedEvent},
	} {
		for size := 0; size < tc.full; size++ {
			n, err := ParseNotification(notif(tc.typ, size))
			if !errors.Is(err, ErrShortNotification) {
				t.Errorf("%s at %d bytes: err = %v, want ErrShortNotification",
					tc.name, size, err)
			}
			if n != nil {
				t.Errorf("%s at %d bytes: returned a notification from a truncated buffer",
					tc.name, size)
			}
		}
		// peer_addr_change embeds a sockaddr whose family field must name a
		// family decodeAddr recognises; every other type is all zero fields.
		full := notif(tc.typ, tc.full)
		if tc.typ == EventPeerAddrChange {
			full = paddrChangeFixture(t, afInet, netip.MustParseAddr("192.0.2.1"), 1, AddrAvailable, 0, 1)
		}
		n, err := ParseNotification(full)
		if err != nil {
			t.Errorf("%s at its full %d bytes: %v", tc.name, tc.full, err)
		}
		if n == nil {
			t.Errorf("%s at its full %d bytes: nil notification", tc.name, tc.full)
		}
	}
}

// TestParseNotificationZeroAndUnderHeaderLength covers the hostile lengths a
// declared field can hold below any type's fixed part, including zero
// (JDK-8067846): every one is ErrShortNotification, never a decoded value.
func TestParseNotificationZeroAndUnderHeaderLength(t *testing.T) {
	for _, declared := range []int{0, 1, 4, 7} {
		b := notifSized(EventAssocChange, declared, 64, 0xFF)
		n, err := ParseNotification(b)
		if !errors.Is(err, ErrShortNotification) {
			t.Errorf("declared %d: err = %v, want ErrShortNotification", declared, err)
		}
		if n != nil {
			t.Errorf("declared %d: returned %T", declared, n)
		}
	}
}

// TestParseNotificationBoundsByDeclaredLength checks that the length in the
// header is the authoritative extent of the event, not merely an upper
// bound checked against the buffer: the kernel sets it to the whole size of
// the event and delivers exactly that many bytes, so a buffer longer than
// the declared length holds bytes — usually a previous read's leftovers —
// that are not part of this event.
func TestParseNotificationBoundsByDeclaredLength(t *testing.T) {
	t.Run("tail past the declared length is not returned", func(t *testing.T) {
		b := notifSized(EventAssocChange, sizeAssocChange, 64, 0xAA)
		binary.NativeEndian.PutUint16(b[assocChangeStateOff:], uint16(AssocCommUp))
		n, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		ac, ok := n.(*AssocChange)
		if !ok {
			t.Fatalf("got %T, want *AssocChange", n)
		}
		if len(ac.Info) != 0 {
			t.Errorf("Info = % x (%d bytes), want empty: the event declares no "+
				"tail and the rest of the buffer is not part of it", ac.Info, len(ac.Info))
		}
	})

	t.Run("a declared tail is still returned, exactly", func(t *testing.T) {
		b := notifSized(EventAssocChange, sizeAssocChange+4, 64, 0xAA)
		copy(b[sizeAssocChange:], []byte{0xDE, 0xAD, 0xBE, 0xEF})
		n, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		ac := n.(*AssocChange)
		if want := []byte{0xDE, 0xAD, 0xBE, 0xEF}; string(ac.Info) != string(want) {
			t.Errorf("Info = % x, want % x", ac.Info, want)
		}
	})

	t.Run("under-declared events are refused", func(t *testing.T) {
		b := notifSized(EventAssocChange, notificationHeaderSize, 24, 0xFF)
		n, err := ParseNotification(b)
		if !errors.Is(err, ErrShortNotification) {
			t.Errorf("err = %v, want ErrShortNotification", err)
		}
		if n != nil {
			t.Errorf("returned %T from an under-declared event", n)
		}
	})

	t.Run("one byte over the buffer is refused, not panicked on", func(t *testing.T) {
		const buf = 64
		for _, declared := range []int{buf + 1, buf + 2, buf + 8, 65516} {
			b := notifSized(EventAssocChange, declared, buf, 0xFF)
			n, err := ParseNotification(b)
			if !errors.Is(err, ErrShortNotification) {
				t.Errorf("declared %d with %d present: err = %v, want ErrShortNotification",
					declared, buf, err)
			}
			if n != nil {
				t.Errorf("declared %d with %d present: returned %T", declared, buf, n)
			}
		}
		b := notifSized(EventAssocChange, buf, buf, 0)
		if _, err := ParseNotification(b); err != nil {
			t.Errorf("declared %d with %d present: %v, want it to parse", buf, buf, err)
		}
	})

	t.Run("declared above the reassembly limit is refused as too long", func(t *testing.T) {
		b := notifSized(EventAssocChange, NotificationReassemblyLimit+1, 64, 0)
		n, err := ParseNotification(b)
		if !errors.Is(err, ErrNotificationTooLong) {
			t.Errorf("err = %v, want ErrNotificationTooLong", err)
		}
		if n != nil {
			t.Errorf("returned %T alongside the error", n)
		}
	})

	t.Run("the stream list stops at the declared length", func(t *testing.T) {
		b := notifSized(EventStreamReset, sizeStreamResetEvent+2, 24, 0xEE)
		binary.NativeEndian.PutUint32(b[streamResetEventAssocIDOff:], 3)
		binary.NativeEndian.PutUint16(b[streamResetEventStreamsOff:], 1)

		n, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		sr := n.(*StreamReset)
		if len(sr.Streams) != 1 || sr.Streams[0] != 1 {
			t.Errorf("Streams = %v, want [1]: the event declares one stream id "+
				"and the remaining buffer bytes are not part of it", sr.Streams)
		}
	})

	t.Run("an odd stream-list tail is refused", func(t *testing.T) {
		for _, tc := range []struct {
			length  int
			wantErr bool
			streams int
		}{
			{sizeStreamResetEvent, false, 0},
			{sizeStreamResetEvent + 1, true, 0},
			{sizeStreamResetEvent + 2, false, 1},
		} {
			b := notif(EventStreamReset, tc.length)
			n, err := ParseNotification(b)
			if tc.wantErr {
				if !errors.Is(err, ErrShortNotification) || n != nil {
					t.Errorf("length %d = (%T, %v), want nil ErrShortNotification",
						tc.length, n, err)
				}
				continue
			}
			if err != nil {
				t.Errorf("length %d: %v", tc.length, err)
				continue
			}
			sr, ok := n.(*StreamReset)
			if !ok {
				t.Errorf("length %d returned %T, want *StreamReset", tc.length, n)
				continue
			}
			if len(sr.Streams) != tc.streams {
				t.Errorf("length %d streams = %v, want %d stream ids",
					tc.length, sr.Streams, tc.streams)
			}
		}
	})

	t.Run("every variable tail is bounded", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			typ  EventType
			size int
			tail func(Notification) int
		}{
			{"assoc_change", EventAssocChange, sizeAssocChange,
				func(n Notification) int { return len(n.(*AssocChange).Info) }},
			{"remote_error", EventRemoteError, sizeRemoteError,
				func(n Notification) int { return len(n.(*RemoteError).Data) }},
			{"send_failed", EventSendFailed, sizeSendFailedEvent,
				func(n Notification) int { return len(n.(*SendFailed).Data) }},
		} {
			b := notifSized(tc.typ, tc.size, tc.size+40, 0xAA)
			n, err := ParseNotification(b)
			if err != nil {
				t.Errorf("%s: ParseNotification: %v", tc.name, err)
				continue
			}
			if got := tc.tail(n); got != 0 {
				t.Errorf("%s: tail = %d bytes, want 0: the event declares %d bytes "+
					"and the buffer holds %d", tc.name, got, tc.size, tc.size+40)
			}
		}
	})
}

// TestParseNotificationAssocChange checks every field lands in its own
// place; each value is distinct so a wrong offset reads a neighbouring
// field and is caught rather than looking plausible.
func TestParseNotificationAssocChange(t *testing.T) {
	b := notif(EventAssocChange, sizeAssocChange+4)
	binary.NativeEndian.PutUint16(b[assocChangeStateOff:], uint16(AssocCommLost))
	binary.BigEndian.PutUint16(b[assocChangeErrorOff:], uint16(CauseProtocolViolation))
	binary.NativeEndian.PutUint16(b[assocChangeOutStreamsOff:], 0x3333)
	binary.NativeEndian.PutUint16(b[assocChangeInStreamsOff:], 0x4444)
	binary.NativeEndian.PutUint32(b[assocChangeAssocIDOff:], 0x55555555)
	copy(b[sizeAssocChange:], []byte{0xAA, 0xBB, 0xCC, 0xDD})

	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	ac, ok := n.(*AssocChange)
	if !ok {
		t.Fatalf("got %T, want *AssocChange", n)
	}
	if ac.Type() != EventAssocChange {
		t.Errorf("Type = %v, want EventAssocChange", ac.Type())
	}
	if ac.State != AssocCommLost {
		t.Errorf("State = %v, want AssocCommLost", ac.State)
	}
	if ac.Error != CauseProtocolViolation {
		t.Errorf("Error = %v, want CauseProtocolViolation", ac.Error)
	}
	if ac.OutStreams != 0x3333 {
		t.Errorf("OutStreams = %#x, want 0x3333", ac.OutStreams)
	}
	if ac.InStreams != 0x4444 {
		t.Errorf("InStreams = %#x, want 0x4444", ac.InStreams)
	}
	if ac.AssocID != AssocID(0x55555555) {
		t.Errorf("AssocID = %#x, want 0x55555555", ac.AssocID)
	}
	if string(ac.Info) != string([]byte{0xAA, 0xBB, 0xCC, 0xDD}) {
		t.Errorf("Info = % x, want aa bb cc dd", ac.Info)
	}
}

// TestParseNotificationAssocChangeAssocIDZero checks an association id of
// zero parses like any other (erlang/otp #4334): it is a real, if unusual,
// value the pool can hand out, not a sentinel this decoder should refuse.
func TestParseNotificationAssocChangeAssocIDZero(t *testing.T) {
	b := notif(EventAssocChange, sizeAssocChange)
	binary.NativeEndian.PutUint16(b[assocChangeStateOff:], uint16(AssocCommUp))
	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	ac, ok := n.(*AssocChange)
	if !ok {
		t.Fatalf("got %T, want *AssocChange", n)
	}
	if ac.AssocID != 0 {
		t.Errorf("AssocID = %d, want 0", ac.AssocID)
	}
}

// TestParseNotificationPartialDeliveryFieldOrder pins the field order the
// kernel actually uses: struct sctp_pdapi_event places assoc_id at offset
// 12 and stream at 16, the opposite of RFC 6458 §6.1.7's declared order.
// Following the RFC ordering here reads the two transposed — a wrong value,
// not an error.
func TestParseNotificationPartialDeliveryFieldOrder(t *testing.T) {
	b := notif(EventPartialDelivery, sizePDAPIEvent)
	binary.NativeEndian.PutUint32(b[pdapiEventIndicationOff:], 0x11111111)
	binary.NativeEndian.PutUint32(b[pdapiEventAssocIDOff:], 0x22222222)
	binary.NativeEndian.PutUint32(b[pdapiEventStreamOff:], 0x33333333)
	binary.NativeEndian.PutUint32(b[pdapiEventSeqOff:], 0x44444444)

	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	pd := n.(*PartialDelivery)
	if pd.AssocID != AssocID(0x22222222) {
		t.Errorf("AssocID = %#x, want 0x22222222 (kernel puts assoc_id at offset 12)", pd.AssocID)
	}
	if pd.Stream != 0x33333333 {
		t.Errorf("Stream = %#x, want 0x33333333 (kernel puts stream at offset 16)", pd.Stream)
	}
	if pd.SeqNum != 0x44444444 {
		t.Errorf("SeqNum = %#x, want 0x44444444", pd.SeqNum)
	}
}

// TestParseNotificationPartialDeliveryUnordered checks Unordered decodes
// from pdapi_flags's bit 0, the flag net/sctp/stream_interleave.c's
// sctp_intl_abort_pd and sctp_intl_skip set for an aborted unordered I-DATA
// partial delivery and clear otherwise.
func TestParseNotificationPartialDeliveryUnordered(t *testing.T) {
	for _, tc := range []struct {
		name      string
		flags     uint16
		unordered bool
	}{
		{"ordered", 0, false},
		{"unordered", pdapiFlagUnordered, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := notifFlags(EventPartialDelivery, tc.flags, sizePDAPIEvent)
			n, err := ParseNotification(b)
			if err != nil {
				t.Fatalf("ParseNotification: %v", err)
			}
			pd := n.(*PartialDelivery)
			if pd.Unordered != tc.unordered {
				t.Errorf("Unordered = %v, want %v", pd.Unordered, tc.unordered)
			}
		})
	}
}

// paddrChangeFixture builds a complete SCTP_PEER_ADDR_CHANGE record with the
// given embedded address, state, raw spc_error and association id.
func paddrChangeFixture(t *testing.T, family int, ip netip.Addr, port uint16, state AddrChangeState, spcError int32, assocID AssocID) []byte {
	t.Helper()
	b := notif(EventPeerAddrChange, sizePAddrChange)
	if _, err := encodeAddr(b[paddrChangeAddrOff:paddrChangeStateOff], family, ip, port); err != nil {
		t.Fatalf("encodeAddr: %v", err)
	}
	binary.NativeEndian.PutUint32(b[paddrChangeStateOff:], uint32(int32(state)))
	binary.NativeEndian.PutUint32(b[paddrChangeErrorOff:], uint32(spcError))
	binary.NativeEndian.PutUint32(b[paddrChangeAssocIDOff:], uint32(assocID))
	return b
}

// TestParseNotificationPeerAddrChange covers the notification that reports a
// path going unreachable, decoding both AF_INET and mapped AF_INET6
// addresses to plain IPv4 through sockaddr.go's decodeAddr.
func TestParseNotificationPeerAddrChange(t *testing.T) {
	t.Run("AF_INET", func(t *testing.T) {
		ip := netip.MustParseAddr("192.0.2.7")
		b := paddrChangeFixture(t, afInet, ip, 3868, AddrUnreachable, 0, 0x77777777)
		n, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		pac := n.(*PeerAddrChange)
		if pac.Addr.Addr() != ip || pac.Addr.Port() != 3868 {
			t.Errorf("Addr = %v, want %s:3868", pac.Addr, ip)
		}
		if pac.State != AddrUnreachable {
			t.Errorf("State = %v, want AddrUnreachable", pac.State)
		}
		if pac.AssocID != AssocID(0x77777777) {
			t.Errorf("AssocID = %#x, want 0x77777777", pac.AssocID)
		}
	})

	t.Run("mapped AF_INET6 decodes to plain IPv4", func(t *testing.T) {
		mapped := netip.MustParseAddr("::ffff:192.0.2.7")
		b := paddrChangeFixture(t, afInet6, mapped, 80, AddrAvailable, 0, 1)
		n, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		pac := n.(*PeerAddrChange)
		if !pac.Addr.Addr().Is4() || pac.Addr.Addr().String() != "192.0.2.7" {
			t.Errorf("Addr = %v, want plain 192.0.2.7", pac.Addr.Addr())
		}
	})

	t.Run("genuine AF_INET6", func(t *testing.T) {
		ip := netip.MustParseAddr("2001:db8::1")
		b := paddrChangeFixture(t, afInet6, ip, 443, AddrConfirmed, 0, 9)
		n, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		pac := n.(*PeerAddrChange)
		if pac.Addr.Addr() != ip {
			t.Errorf("Addr = %v, want %v", pac.Addr.Addr(), ip)
		}
	})

	t.Run("a malformed embedded address returns decodeAddr's own error", func(t *testing.T) {
		// A complete, correctly-declared record whose embedded sockaddr
		// names a family decodeAddr does not recognise (AF_UNIX): the
		// record itself is not short, so this must not read as
		// ErrShortNotification, only as the address decode's own error.
		b := notif(EventPeerAddrChange, sizePAddrChange)
		const afUnix = 1
		binary.NativeEndian.PutUint16(b[paddrChangeAddrOff:], afUnix)

		n, err := ParseNotification(b)
		if n != nil {
			t.Errorf("returned %T alongside the error", n)
		}
		if err == nil {
			t.Fatal("err = nil, want decodeAddr's unknown-family error")
		}
		if errors.Is(err, ErrShortNotification) {
			t.Errorf("err = %v matches ErrShortNotification, but the record is complete "+
				"and long enough — only the embedded address is malformed", err)
		}
		if !errors.Is(err, syscall.EINVAL) {
			t.Errorf("err = %v, want it to match syscall.EINVAL (decodeAddr's own contract)", err)
		}
	})
}

// TestAddrChangeReasonDecoding pins the raw spc_error → AddrChangeReason
// mapping: a raw 0 means SCTP_FAILED_THRESHOLD only when State is
// AddrUnreachable — the only state Linux actually reports it for — and
// means no reason at all otherwise; every raw value from 1 to 6 decodes to
// AddrChangeReason(raw+1); a raw value the kernel's own enum could never
// produce (negative, or already math.MaxInt32) decodes to
// AddrChangeReason(raw) unshifted, so it neither collides with a name this
// function assigns to a different raw (raw == -1 must not read as
// ReasonNone) nor overflows int32 (raw == math.MaxInt32 has no raw+1).
func TestAddrChangeReasonDecoding(t *testing.T) {
	for _, tc := range []struct {
		name  string
		raw   int32
		state AddrChangeState
		want  AddrChangeReason
	}{
		{"0 with AddrUnreachable is the failed threshold", 0, AddrUnreachable, ReasonFailedThreshold},
		{"0 with AddrAvailable is no reason", 0, AddrAvailable, ReasonNone},
		{"0 with AddrConfirmed is no reason", 0, AddrConfirmed, ReasonNone},
		{"1 is received SACK", 1, AddrUnreachable, ReasonReceivedSACK},
		{"2 is heartbeat success", 2, AddrConfirmed, ReasonHeartbeatSuccess},
		{"3 is response to user request", 3, AddrAvailable, ReasonResponseToUserReq},
		{"4 is internal error", 4, AddrAvailable, ReasonInternalError},
		{"5 is shutdown guard expires", 5, AddrAvailable, ReasonShutdownGuardExpires},
		{"6 is peer faulty", 6, AddrAvailable, ReasonPeerFaulty},
		{"an unknown positive raw value renders numerically", 99, AddrAvailable, AddrChangeReason(100)},
		{"-1 does not read as ReasonNone", -1, AddrAvailable, AddrChangeReason(-1)},
		{"-1 does not read as ReasonNone, even with AddrUnreachable", -1, AddrUnreachable, AddrChangeReason(-1)},
		{"MaxInt32 does not wrap", math.MaxInt32, AddrAvailable, AddrChangeReason(math.MaxInt32)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := paddrChangeFixture(t, afInet, netip.MustParseAddr("192.0.2.1"), 1, tc.state, tc.raw, 1)
			n, err := ParseNotification(b)
			if err != nil {
				t.Fatalf("ParseNotification: %v", err)
			}
			pac := n.(*PeerAddrChange)
			if pac.Reason != tc.want {
				t.Errorf("Reason = %v, want %v", pac.Reason, tc.want)
			}
		})
	}
}

// TestParseNotificationRemoteError checks the cause and the cause
// information: the bytes after the 4-byte cause header, padding included
// (Linux emits one RemoteError per cause).
func TestParseNotificationRemoteError(t *testing.T) {
	b := notif(EventRemoteError, sizeRemoteError+4)
	binary.BigEndian.PutUint16(b[remoteErrorErrorOff:], uint16(CauseInvalidStream))
	binary.NativeEndian.PutUint32(b[remoteErrorAssocIDOff:], 7)
	copy(b[sizeRemoteError:], []byte{0x01, 0x02, 0x00, 0x00}) // includes a pad byte

	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	re, ok := n.(*RemoteError)
	if !ok {
		t.Fatalf("got %T, want *RemoteError", n)
	}
	if re.Error != CauseInvalidStream {
		t.Errorf("Error = %v, want CauseInvalidStream", re.Error)
	}
	if re.AssocID != 7 {
		t.Errorf("AssocID = %d, want 7", re.AssocID)
	}
	if want := []byte{0x01, 0x02, 0x00, 0x00}; string(re.Data) != string(want) {
		t.Errorf("Data = % x, want % x", re.Data, want)
	}
}

// TestParseNotificationRemoteErrorUnassignedCause checks an unassigned
// cause code still parses (pion #470) and renders as ErrorCause(n).
func TestParseNotificationRemoteErrorUnassignedCause(t *testing.T) {
	const unassigned = 0x2710 // 10000, unassigned by IANA
	b := notif(EventRemoteError, sizeRemoteError)
	binary.BigEndian.PutUint16(b[remoteErrorErrorOff:], unassigned)

	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	re := n.(*RemoteError)
	if re.Error != ErrorCause(unassigned) {
		t.Errorf("Error = %v, want %d", re.Error, unassigned)
	}
	if got, want := re.Error.String(), "ErrorCause(10000)"; got != want {
		t.Errorf("Error.String() = %q, want %q", got, want)
	}
}

// TestParseNotificationSendFailed checks every SendFailed field: Sent from
// ssf_flags, the DATA-chunk bits out of ssfe_info.snd_flags, PPID converted
// to host order, and Data bounded by ssf_length.
func TestParseNotificationSendFailed(t *testing.T) {
	b := notifFlags(EventSendFailed, sendFailedFlagSent, sizeSendFailedEvent+3)
	binary.NativeEndian.PutUint32(b[sendFailedEventErrorOff:], uint32(htonsForTest(uint16(CauseNoUserData))))
	binary.NativeEndian.PutUint16(b[sendFailedEventInfoOff+sndInfoStreamOff:], 5)
	sndFlags := dataChunkFlagUnordered | dataChunkFlagFirstFragment
	binary.NativeEndian.PutUint16(b[sendFailedEventInfoOff+sndInfoFlagsOff:], uint16(sndFlags))
	binary.BigEndian.PutUint32(b[sendFailedEventInfoOff+sndInfoPPIDOff:], 0x01020304)
	binary.NativeEndian.PutUint32(b[sendFailedEventInfoOff+sndInfoContextOff:], 99)
	binary.NativeEndian.PutUint32(b[sendFailedEventAssocIDOff:], 13)
	copy(b[sendFailedEventDataOff:], "abc")

	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	sf, ok := n.(*SendFailed)
	if !ok {
		t.Fatalf("got %T, want *SendFailed", n)
	}
	if sf.Error != CauseNoUserData {
		t.Errorf("Error = %v, want CauseNoUserData", sf.Error)
	}
	if !sf.Sent {
		t.Error("Sent = false, want true (ssf_flags carried SCTP_DATA_SENT)")
	}
	if sf.Stream != 5 {
		t.Errorf("Stream = %d, want 5", sf.Stream)
	}
	if sf.PPID != 0x01020304 {
		t.Errorf("PPID = %#x, want 0x01020304", sf.PPID)
	}
	if sf.Context != 99 {
		t.Errorf("Context = %d, want 99", sf.Context)
	}
	if !sf.Unordered {
		t.Error("Unordered = false, want true (U bit set)")
	}
	if !sf.FirstFragment {
		t.Error("FirstFragment = false, want true (B bit set)")
	}
	if sf.LastFragment {
		t.Error("LastFragment = true, want false (E bit clear)")
	}
	if sf.AssocID != 13 {
		t.Errorf("AssocID = %d, want 13", sf.AssocID)
	}
	if string(sf.Data) != "abc" {
		t.Errorf("Data = %q, want %q", sf.Data, "abc")
	}
}

// TestParseNotificationSendFailedUnsent checks the unset case: ssf_flags
// carrying SCTP_DATA_UNSENT (0) decodes to Sent == false.
func TestParseNotificationSendFailedUnsent(t *testing.T) {
	b := notif(EventSendFailed, sizeSendFailedEvent)
	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	sf := n.(*SendFailed)
	if sf.Sent {
		t.Error("Sent = true, want false (ssf_flags carried SCTP_DATA_UNSENT)")
	}
}

// TestParseNotificationStreamReset checks the flag bits and the flexible
// stream-id array, and that an empty array means all streams.
func TestParseNotificationStreamReset(t *testing.T) {
	t.Run("with stream ids and the denied flag", func(t *testing.T) {
		b := notifFlags(EventStreamReset, streamResetFlagDenied|streamResetFlagIncoming, sizeStreamResetEvent+4)
		binary.NativeEndian.PutUint32(b[streamResetEventAssocIDOff:], 11)
		binary.NativeEndian.PutUint16(b[streamResetEventStreamsOff:], 3)
		binary.NativeEndian.PutUint16(b[streamResetEventStreamsOff+2:], 5)

		n, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		sr, ok := n.(*StreamReset)
		if !ok {
			t.Fatalf("got %T, want *StreamReset", n)
		}
		if sr.AssocID != 11 || len(sr.Streams) != 2 || sr.Streams[0] != 3 || sr.Streams[1] != 5 {
			t.Errorf("decoded id=%d streams=%v, want id=11 streams=[3 5]", sr.AssocID, sr.Streams)
		}
		if !sr.Denied {
			t.Error("Denied = false, want true")
		}
		if !sr.Incoming {
			t.Error("Incoming = false, want true")
		}
		if sr.Outgoing || sr.Failed {
			t.Errorf("Outgoing=%v Failed=%v, want both false", sr.Outgoing, sr.Failed)
		}
	})

	t.Run("empty stream list means all streams", func(t *testing.T) {
		b := notif(EventStreamReset, sizeStreamResetEvent)
		n, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		sr := n.(*StreamReset)
		if len(sr.Streams) != 0 {
			t.Errorf("Streams = %v, want empty", sr.Streams)
		}
	})
}

// TestParseNotificationAssocReset checks the TSNs and flag bits.
func TestParseNotificationAssocReset(t *testing.T) {
	b := notifFlags(EventAssocReset, assocResetFlagFailed, sizeAssocResetEvent)
	binary.NativeEndian.PutUint32(b[assocResetEventAssocIDOff:], 4)
	binary.NativeEndian.PutUint32(b[assocResetEventLocalTSNOff:], 0x11223344)
	binary.NativeEndian.PutUint32(b[assocResetEventRemoteTSNOff:], 0x55667788)

	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	ar, ok := n.(*AssocReset)
	if !ok {
		t.Fatalf("got %T, want *AssocReset", n)
	}
	if ar.AssocID != 4 || ar.LocalTSN != 0x11223344 || ar.RemoteTSN != 0x55667788 {
		t.Errorf("decoded %+v", ar)
	}
	if !ar.Failed || ar.Denied {
		t.Errorf("Failed=%v Denied=%v, want Failed only", ar.Failed, ar.Denied)
	}
}

// TestParseNotificationStreamChange checks the added-stream counts and flag
// bits.
func TestParseNotificationStreamChange(t *testing.T) {
	b := notifFlags(EventStreamChange, streamChangeFlagFailed, sizeStreamChangeEvent)
	binary.NativeEndian.PutUint32(b[streamChangeEventAssocIDOff:], 6)
	binary.NativeEndian.PutUint16(b[streamChangeEventInStreamsOff:], 20)
	binary.NativeEndian.PutUint16(b[streamChangeEventOutStreamsOff:], 30)

	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	sc, ok := n.(*StreamChange)
	if !ok {
		t.Fatalf("got %T, want *StreamChange", n)
	}
	if sc.AssocID != 6 || sc.InStreams != 20 || sc.OutStreams != 30 {
		t.Errorf("decoded %+v", sc)
	}
	if !sc.Failed {
		t.Error("Failed = false, want true")
	}
}

// TestParseNotificationAuthEvent checks the key numbers and indication.
func TestParseNotificationAuthEvent(t *testing.T) {
	b := notif(EventAuthentication, sizeAuthKeyEvent)
	binary.NativeEndian.PutUint16(b[authKeyEventKeyNumberOff:], 5)
	binary.NativeEndian.PutUint16(b[authKeyEventAltKeyNumberOff:], 6)
	binary.NativeEndian.PutUint32(b[authKeyEventIndicationOff:], uint32(AuthFreeKey))
	binary.NativeEndian.PutUint32(b[authKeyEventAssocIDOff:], 14)

	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	ae, ok := n.(*AuthEvent)
	if !ok {
		t.Fatalf("got %T, want *AuthEvent", n)
	}
	if ae.Key != 5 || ae.AltKey != 6 || ae.Indication != AuthFreeKey || ae.AssocID != 14 {
		t.Errorf("decoded %+v", ae)
	}
}

// TestParseNotificationTrivialEvents covers the three notifications that
// carry nothing but an association id.
func TestParseNotificationTrivialEvents(t *testing.T) {
	t.Run("shutdown", func(t *testing.T) {
		b := notif(EventShutdown, sizeShutdownEvent)
		binary.NativeEndian.PutUint32(b[shutdownEventAssocIDOff:], 21)
		n, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		s, ok := n.(*Shutdown)
		if !ok || s.AssocID != 21 {
			t.Errorf("got (%T, id=%v), want (*Shutdown, 21)", n, s)
		}
		if s.Type() != EventShutdown {
			t.Errorf("Type = %v, want EventShutdown", s.Type())
		}
	})

	t.Run("sender dry", func(t *testing.T) {
		b := notif(EventSenderDry, sizeSenderDryEvent)
		binary.NativeEndian.PutUint32(b[senderDryEventAssocIDOff:], 22)
		n, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		s, ok := n.(*SenderDry)
		if !ok || s.AssocID != 22 {
			t.Errorf("got (%T, id=%v), want (*SenderDry, 22)", n, s)
		}
		if s.Type() != EventSenderDry {
			t.Errorf("Type = %v, want EventSenderDry", s.Type())
		}
	})

	t.Run("adaptation indication", func(t *testing.T) {
		b := notif(EventAdaptationIndication, sizeAdaptationEvent)
		binary.NativeEndian.PutUint32(b[adaptationEventIndicationOff:], 0xCAFEF00D)
		binary.NativeEndian.PutUint32(b[adaptationEventAssocIDOff:], 23)
		n, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		a, ok := n.(*AdaptationIndication)
		if !ok || a.Indication != 0xCAFEF00D || a.AssocID != 23 {
			t.Errorf("got %T %+v", n, a)
		}
		if a.Type() != EventAdaptationIndication {
			t.Errorf("Type = %v, want EventAdaptationIndication", a.Type())
		}
	})
}

// TestParseNotificationUnknownType checks an event this package does not
// model decodes to *UnknownNotification, carrying the whole record and
// reporting its type from the header, rather than being dropped: the
// kernel may add notification types this package predates.
func TestParseNotificationUnknownType(t *testing.T) {
	const unknown = EventType(0x7FFF)

	for declared := 0; declared < notificationHeaderSize; declared++ {
		b := notifSized(unknown, declared, notificationHeaderSize, 0)
		n, err := ParseNotification(b)
		if !errors.Is(err, ErrShortNotification) || n != nil {
			t.Errorf("declared %d = (%T, %v), want nil ErrShortNotification", declared, n, err)
		}
	}

	b := notif(unknown, notificationHeaderSize+4)
	copy(b[notificationHeaderSize:], []byte{1, 2, 3, 4})
	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	un, ok := n.(*UnknownNotification)
	if !ok {
		t.Fatalf("got %T, want *UnknownNotification", n)
	}
	if un.Type() != unknown {
		t.Errorf("Type() = %v, want %v", un.Type(), unknown)
	}
	if !bytes.Equal(un.Data, b) {
		t.Errorf("Data = % x, want the whole record % x", un.Data, b)
	}

	// Data mutated after the fact must not change Type(): it reads the
	// header out of its own copy, not out of the original buffer.
	orig := append([]byte(nil), b...)
	for i := range b {
		b[i] = 0xFF
	}
	if !bytes.Equal(un.Data, orig) {
		t.Error("UnknownNotification.Data aliased the caller's buffer")
	}
}

// TestParseNotificationUnknownTypeZeroLengthType reports EventType(0) rather
// than panicking when Data itself is too short to carry a header — this can
// only happen if a caller builds one by hand, since ParseNotification never
// returns a *UnknownNotification with less than notificationHeaderSize
// bytes of Data.
func TestParseNotificationUnknownTypeZeroLengthType(t *testing.T) {
	un := &UnknownNotification{Data: []byte{1, 2, 3}}
	if got := un.Type(); got != 0 {
		t.Errorf("Type() = %v, want 0", got)
	}
}

// TestUnknownNotificationTypeNilReceiver checks a nil *UnknownNotification's
// Type does not panic, consistent with every other notification type's
// Type method (none of which dereference their receiver at all).
// UnknownNotification is the one type that must read its own receiver —
// Type has nothing else to compute it from — so it is the one that needs
// an explicit guard rather than getting nil-safety for free.
func TestUnknownNotificationTypeNilReceiver(t *testing.T) {
	var un *UnknownNotification
	if got := un.Type(); got != 0 {
		t.Errorf("Type() = %v, want 0", got)
	}
}

// TestParseNotificationCopies is the ownership guarantee every decoded
// value makes: mutating the input after ParseNotification returns must not
// change any byte field of the result, for every type that carries one.
func TestParseNotificationCopies(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func() []byte
		bytes func(Notification) [][]byte
	}{
		{"AssocChange.Info", func() []byte {
			b := notif(EventAssocChange, sizeAssocChange+4)
			copy(b[sizeAssocChange:], []byte{1, 2, 3, 4})
			return b
		}, func(n Notification) [][]byte { return [][]byte{n.(*AssocChange).Info} }},
		{"RemoteError.Data", func() []byte {
			b := notif(EventRemoteError, sizeRemoteError+4)
			copy(b[sizeRemoteError:], []byte{5, 6, 7, 8})
			return b
		}, func(n Notification) [][]byte { return [][]byte{n.(*RemoteError).Data} }},
		{"SendFailed.Data", func() []byte {
			b := notif(EventSendFailed, sizeSendFailedEvent+4)
			copy(b[sendFailedEventDataOff:], []byte{9, 10, 11, 12})
			return b
		}, func(n Notification) [][]byte { return [][]byte{n.(*SendFailed).Data} }},
		{"UnknownNotification.Data", func() []byte {
			return notif(EventType(0x7FFF), notificationHeaderSize+4)
		}, func(n Notification) [][]byte { return [][]byte{n.(*UnknownNotification).Data} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.build()
			n, err := ParseNotification(b)
			if err != nil {
				t.Fatalf("ParseNotification: %v", err)
			}
			before := tc.bytes(n)
			want := make([][]byte, len(before))
			for i, bs := range before {
				want[i] = append([]byte(nil), bs...)
			}

			// Simulate the input buffer being reused for the next read.
			for i := range b {
				b[i] = 0xFF
			}

			after := tc.bytes(n)
			for i := range after {
				if !bytes.Equal(after[i], want[i]) {
					t.Errorf("field %d changed after the input buffer was reused: "+
						"got % x, want % x (the parser aliased the caller's buffer)",
						i, after[i], want[i])
				}
			}
		})
	}

	// StreamReset.Streams is decoded into a fresh []uint16, not a reslice of
	// b, so it also needs no aliasing of the original bytes at all: check it
	// separately since its element type differs.
	t.Run("StreamReset.Streams", func(t *testing.T) {
		b := notif(EventStreamReset, sizeStreamResetEvent+2)
		binary.NativeEndian.PutUint16(b[streamResetEventStreamsOff:], 42)
		n, err := ParseNotification(b)
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		sr := n.(*StreamReset)
		for i := range b {
			b[i] = 0xFF
		}
		if len(sr.Streams) != 1 || sr.Streams[0] != 42 {
			t.Errorf("Streams = %v, want [42]", sr.Streams)
		}
	})
}

// TestAssocChangeErrorIsDecodedFromNetworkOrder pins the byte order of the
// error cause an SCTP_ASSOC_CHANGE carries. The kernel declares its cause
// constants cpu_to_be16 and assigns them into a host-typed __u16 without
// converting, so the two bytes in the buffer are the network
// representation. Every value here is deliberately byte-asymmetric: a
// symmetric one (such as 0x2222) is identical under a byte swap and so
// cannot falsify a decoder that reads natively instead of big-endian.
func TestAssocChangeErrorIsDecodedFromNetworkOrder(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause ErrorCause
	}{
		{"user abort", CauseUserAbort},
		{"invalid stream", CauseInvalidStream},
		{"protocol violation", CauseProtocolViolation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := notif(EventAssocChange, sizeAssocChange)
			binary.NativeEndian.PutUint16(b[assocChangeStateOff:], uint16(AssocCommLost))
			binary.BigEndian.PutUint16(b[assocChangeErrorOff:], uint16(tc.cause))
			binary.NativeEndian.PutUint16(b[assocChangeOutStreamsOff:], 7)
			binary.NativeEndian.PutUint16(b[assocChangeInStreamsOff:], 9)
			binary.NativeEndian.PutUint32(b[assocChangeAssocIDOff:], 42)

			n, err := ParseNotification(b)
			if err != nil {
				t.Fatalf("ParseNotification: %v", err)
			}
			ac := n.(*AssocChange)
			if ac.Error != tc.cause {
				t.Errorf("Error = %v, want %v; the cause is being read in the "+
					"wrong byte order", ac.Error, tc.cause)
			}
			if ac.State != AssocCommLost || ac.OutStreams != 7 || ac.InStreams != 9 || ac.AssocID != 42 {
				t.Errorf("host-order fields decoded wrong: state=%v out=%d in=%d id=%d",
					ac.State, ac.OutStreams, ac.InStreams, ac.AssocID)
			}
		})
	}
}

// TestRemoteErrorErrorIsDecodedFromNetworkOrder is the same property for
// SCTP_REMOTE_ERROR, whose sre_error is the __be16 copied straight off the
// peer's ERROR chunk.
func TestRemoteErrorErrorIsDecodedFromNetworkOrder(t *testing.T) {
	b := notif(EventRemoteError, sizeRemoteError)
	binary.BigEndian.PutUint16(b[remoteErrorErrorOff:], uint16(CauseInvalidStream))
	binary.NativeEndian.PutUint32(b[remoteErrorAssocIDOff:], 7)

	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	re := n.(*RemoteError)
	if re.Error != CauseInvalidStream {
		t.Errorf("Error = %v, want CauseInvalidStream", re.Error)
	}
}

// htonsForTest reproduces the C-level cpu_to_be16 conversion the kernel
// applies to a cause constant before it lands in ssf_error: byte-swapped if
// this host is little-endian, unchanged if it is big-endian. It is the
// fixture-building half of causeFromU32's own conversion, kept separate so
// the test does not exercise the code under test to build its own input.
func htonsForTest(h uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], h)
	return binary.NativeEndian.Uint16(buf[:])
}

// TestSendFailedErrorIsDecodedFromNetworkOrder covers the cause field that
// needs a different rule from the other two: ssf_error is a __u32 holding
// the same be16 constant, widened by an ordinary C integer promotion. The
// promotion is host arithmetic, so unlike the __u16 fields the raw bytes
// are not simply the network form — on a little-endian host the swapped
// value sits in the low half of the word, which is what htonsForTest
// reproduces here and causeFromU32 must undo.
func TestSendFailedErrorIsDecodedFromNetworkOrder(t *testing.T) {
	b := notif(EventSendFailed, sizeSendFailedEvent)
	binary.NativeEndian.PutUint32(b[sendFailedEventErrorOff:], uint32(htonsForTest(uint16(CauseUserAbort))))

	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	sf := n.(*SendFailed)
	if sf.Error != CauseUserAbort {
		t.Errorf("Error = %v, want CauseUserAbort", sf.Error)
	}
}

// TestCauseDecodingBothKernelByteOrders exercises the package's own
// byte-order-parameterised decoders directly against explicit byte arrays
// laid out the way a little-endian kernel and a big-endian kernel each
// actually produce them, rather than against fixtures this host's own
// NativeEndian built (which only ever proves a decoder agrees with itself
// on whichever order this test happens to run on). causeFromU16 needs no
// order parameter — sac_error's bytes are always the network form, on any
// host — but causeFromU32Order, assocChangeInfoOrder and
// decodePeerAddrChangeOrder each take one explicitly, so every subtest
// below calls one of those three package functions, never
// encoding/binary's LittleEndian/BigEndian directly: the property under
// test is that this package's own decoding is correct for either order,
// not that the standard library is.
func TestCauseDecodingBothKernelByteOrders(t *testing.T) {
	t.Run("sac_error 00 0c is CauseUserAbort on any host", func(t *testing.T) {
		if got := ErrorCause(causeFromU16([]byte{0x00, 0x0c})); got != CauseUserAbort {
			t.Errorf("causeFromU16(00 0c) = %v, want CauseUserAbort", got)
		}
	})

	t.Run("ssf_error as a little-endian kernel lays it out", func(t *testing.T) {
		// The be16 constant 0x0c00 (cpu_to_be16(0x0c) on a little-endian
		// host), zero-extended to 32 bits and stored in that host's own
		// little-endian order: low byte first.
		b := []byte{0x00, 0x0c, 0x00, 0x00}
		if got := ErrorCause(causeFromU32Order(b, binary.LittleEndian)); got != CauseUserAbort {
			t.Errorf("causeFromU32Order(%x, LittleEndian) = %v, want CauseUserAbort", b, got)
		}
	})

	t.Run("ssf_error as a big-endian kernel lays it out", func(t *testing.T) {
		// The be16 constant 0x000c (cpu_to_be16(0x0c) is the identity on a
		// big-endian host), zero-extended to 32 bits and stored high byte
		// first.
		b := []byte{0x00, 0x00, 0x00, 0x0c}
		if got := ErrorCause(causeFromU32Order(b, binary.BigEndian)); got != CauseUserAbort {
			t.Errorf("causeFromU32Order(%x, BigEndian) = %v, want CauseUserAbort", b, got)
		}
	})

	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		t.Run("sac_state through assocChangeInfoOrder, "+order.String(), func(t *testing.T) {
			b := make([]byte, sizeAssocChange)
			order.PutUint16(b[assocChangeStateOff:], uint16(AssocCommLost))
			order.PutUint32(b[assocChangeAssocIDOff:], 7)
			state, id, ok := assocChangeInfoOrder(b, order)
			if !ok || state != AssocCommLost || id != 7 {
				t.Errorf("assocChangeInfoOrder(..., %v) = (%v, %v, %v), want (AssocCommLost, 7, true)",
					order, state, id, ok)
			}
		})

		t.Run("spc_state/spc_error through decodePeerAddrChangeOrder, "+order.String(), func(t *testing.T) {
			// Values wider than 16 bits: a decoder that mistakenly read
			// spc_state or spc_error as a 16-bit field, rather than the
			// 32-bit C int it actually is, would truncate these and fail
			// the check below regardless of which order laid them out —
			// unlike a value that happens to fit in 16 bits, which a
			// Uint16 misread can still get right by chance for one order.
			const state = AddrChangeState(0x10000)
			const spcError = int32(0x10001)
			b := notif(EventPeerAddrChange, sizePAddrChange)
			if _, err := encodeAddr(b[paddrChangeAddrOff:paddrChangeStateOff], afInet,
				netip.MustParseAddr("192.0.2.1"), 1); err != nil {
				t.Fatalf("encodeAddr: %v", err)
			}
			order.PutUint32(b[paddrChangeStateOff:], uint32(state))
			order.PutUint32(b[paddrChangeErrorOff:], uint32(spcError))
			order.PutUint32(b[paddrChangeAssocIDOff:], 9)

			n, err := decodePeerAddrChangeOrder(b, order)
			if err != nil {
				t.Fatalf("decodePeerAddrChangeOrder(..., %v): %v", order, err)
			}
			pac := n.(*PeerAddrChange)
			if pac.State != state {
				t.Errorf("State = %v, want %v", pac.State, state)
			}
			if want := decodeAddrChangeReason(spcError, state); pac.Reason != want {
				t.Errorf("Reason = %v, want %v", pac.Reason, want)
			}
			if pac.AssocID != 9 {
				t.Errorf("AssocID = %v, want 9", pac.AssocID)
			}
		})
	}
}

// TestNotificationPPIDIsConvertedToHostOrder pins the same host-order
// convention SndInfo and RcvInfo use, for SendFailed.PPID.
func TestNotificationPPIDIsConvertedToHostOrder(t *testing.T) {
	const ppid = 0x11223344
	b := notif(EventSendFailed, sizeSendFailedEvent)
	// The kernel copies the network-order wire field through untouched
	// (struct sctp_datahdr's ppid is a plain __u32, not __be32 — Linux never
	// byte-swaps it, so the package's own convention is the only place the
	// conversion happens).
	binary.BigEndian.PutUint32(b[sendFailedEventInfoOff+sndInfoPPIDOff:], ppid)

	n, err := ParseNotification(b)
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	got := n.(*SendFailed).PPID
	if got != ppid {
		t.Errorf("PPID = %#x, want host-order %#x", got, ppid)
	}
}

// TestAssocChangeInfoAllocations pins assocChangeInfo's zero-allocation
// promise, both when it has enough bytes to decode (sizeAssocChange, where
// ok is true) and when it does not (a 12-byte prefix, where ok is false):
// neither path may allocate, since the receive path calls this on every
// notification fragment.
func TestAssocChangeInfoAllocations(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector")
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	full := notif(EventAssocChange, sizeAssocChange)
	binary.NativeEndian.PutUint16(full[assocChangeStateOff:], uint16(AssocCommLost))
	binary.NativeEndian.PutUint32(full[assocChangeAssocIDOff:], 99)

	t.Run("complete prefix", func(t *testing.T) {
		var state AssocChangeState
		var id AssocID
		var ok bool
		allocs := testing.AllocsPerRun(100, func() {
			state, id, ok = assocChangeInfo(full)
		})
		if allocs != 0 {
			t.Errorf("assocChangeInfo allocated %.1f times, want 0", allocs)
		}
		if !ok || state != AssocCommLost || id != 99 {
			t.Errorf("assocChangeInfo(full) = (%v, %v, %v), want (AssocCommLost, 99, true)", state, id, ok)
		}
	})

	t.Run("12-byte prefix", func(t *testing.T) {
		partial := full[:12]
		var ok bool
		allocs := testing.AllocsPerRun(100, func() {
			_, _, ok = assocChangeInfo(partial)
		})
		if allocs != 0 {
			t.Errorf("assocChangeInfo allocated %.1f times, want 0", allocs)
		}
		// 12 bytes reaches sac_state (ends at offset 10) but not
		// sac_assoc_id (offset 16-20, struct sctp_assoc_change,
		// include/uapi/linux/sctp.h): ok is false until the id itself has
		// arrived, so a caller never receives a zero id it should not trust.
		if ok {
			t.Error("ok = true from a 12-byte prefix, which does not reach sac_assoc_id")
		}
	})
}

// TestNotificationHeaderShortBuffer checks notificationHeader reports ok ==
// false rather than panicking on a buffer shorter than the header.
func TestNotificationHeaderShortBuffer(t *testing.T) {
	for size := 0; size < notificationHeaderSize; size++ {
		if _, _, _, ok := notificationHeader(make([]byte, size)); ok {
			t.Errorf("size %d: ok = true, want false", size)
		}
	}
	typ, flags, length, ok := notificationHeader(notifFlags(EventShutdown, 0x1234, notificationHeaderSize))
	if !ok || typ != EventShutdown || flags != 0x1234 || length != notificationHeaderSize {
		t.Errorf("notificationHeader = (%v, %#x, %d, %v), want (EventShutdown, 0x1234, %d, true)",
			typ, flags, length, ok, notificationHeaderSize)
	}
}

// TestNotificationAccumulator ports v1's reassembly and validation tests.
func TestNotificationAccumulator(t *testing.T) {
	t.Run("fragmented exact record", func(t *testing.T) {
		want := notif(EventAssocChange, sizeAssocChange)
		accumulator := notificationAccumulator{retain: true}
		for _, fragment := range [][]byte{want[:3], want[3:8], want[8:17], want[17:]} {
			accumulator.add(fragment)
		}
		got, err := accumulator.finish()
		if err != nil {
			t.Fatalf("finish: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("reassembled = % x, want % x", got, want)
		}
	})

	t.Run("byte-at-a-time fragmentation", func(t *testing.T) {
		want := notif(EventPeerAddrChange, sizePAddrChange)
		accumulator := notificationAccumulator{retain: true}
		for i := range want {
			accumulator.add(want[i : i+1])
		}
		got, err := accumulator.finish()
		if err != nil {
			t.Fatalf("finish: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("reassembled = % x, want % x", got, want)
		}
	})

	t.Run("validation without retention", func(t *testing.T) {
		whole := notif(EventAssocChange, sizeAssocChange)
		accumulator := notificationAccumulator{}
		accumulator.add(whole)
		got, err := accumulator.finish()
		if err != nil {
			t.Fatalf("finish: %v", err)
		}
		if got != nil {
			t.Fatalf("non-retaining accumulator returned %d bytes", len(got))
		}
	})

	t.Run("short header", func(t *testing.T) {
		accumulator := notificationAccumulator{retain: true}
		accumulator.add(make([]byte, notificationHeaderSize-1))
		if _, err := accumulator.finish(); !errors.Is(err, ErrShortNotification) {
			t.Fatalf("finish = %v, want ErrShortNotification", err)
		}
	})

	t.Run("declared below header", func(t *testing.T) {
		whole := notifSized(EventAssocChange, notificationHeaderSize-1, notificationHeaderSize, 0)
		accumulator := notificationAccumulator{retain: true}
		accumulator.add(whole)
		if _, err := accumulator.finish(); !errors.Is(err, ErrShortNotification) {
			t.Fatalf("finish = %v, want ErrShortNotification", err)
		}
	})

	t.Run("declared above limit", func(t *testing.T) {
		header := notifSized(EventAssocChange, NotificationReassemblyLimit+1, notificationHeaderSize, 0)
		accumulator := notificationAccumulator{retain: true}
		accumulator.add(header)
		accumulator.add(make([]byte, 32))
		if _, err := accumulator.finish(); !errors.Is(err, ErrNotificationTooLong) {
			t.Fatalf("finish = %v, want ErrNotificationTooLong", err)
		}
		if accumulator.data != nil {
			t.Fatalf("oversized accumulator retained %d bytes", len(accumulator.data))
		}
		// Draining: further fragments after the failure must not panic,
		// allocate unboundedly, or change the reported error.
		accumulator.add(make([]byte, 1<<16))
		if _, err := accumulator.finish(); !errors.Is(err, ErrNotificationTooLong) {
			t.Fatalf("finish after draining = %v, want ErrNotificationTooLong", err)
		}
		if err := accumulator.interrupted(); !errors.Is(err, ErrNotificationTooLong) ||
			!errors.Is(err, ErrShortNotification) {
			t.Fatalf("interrupted = %v, want it to match both ErrNotificationTooLong and ErrShortNotification", err)
		}
	})

	t.Run("actual bytes above limit", func(t *testing.T) {
		header := notifSized(EventAssocChange, NotificationReassemblyLimit, notificationHeaderSize, 0)
		accumulator := notificationAccumulator{retain: true}
		accumulator.add(header)
		accumulator.add(make([]byte, NotificationReassemblyLimit-notificationHeaderSize+1))
		if _, err := accumulator.finish(); !errors.Is(err, ErrNotificationTooLong) {
			t.Fatalf("finish = %v, want ErrNotificationTooLong", err)
		}
	})

	t.Run("actual bytes exceed declaration", func(t *testing.T) {
		header := notifSized(EventAssocChange, notificationHeaderSize, notificationHeaderSize, 0)
		accumulator := notificationAccumulator{retain: true}
		accumulator.add(header)
		accumulator.add([]byte{0})
		if _, err := accumulator.finish(); !errors.Is(err, ErrShortNotification) {
			t.Fatalf("finish = %v, want ErrShortNotification", err)
		}
	})

	t.Run("missing EOR after exact bytes", func(t *testing.T) {
		whole := notif(EventAssocChange, sizeAssocChange)
		accumulator := notificationAccumulator{retain: true}
		accumulator.add(whole)
		if err := accumulator.interrupted(); !errors.Is(err, ErrShortNotification) {
			t.Fatalf("interrupted = %v, want ErrShortNotification", err)
		}
	})

	t.Run("limit is inclusive", func(t *testing.T) {
		header := notifSized(EventAssocChange, NotificationReassemblyLimit, notificationHeaderSize, 0)
		accumulator := notificationAccumulator{}
		accumulator.add(header)
		accumulator.add(make([]byte, NotificationReassemblyLimit-notificationHeaderSize))
		if _, err := accumulator.finish(); err != nil {
			t.Fatalf("finish at exact limit: %v", err)
		}
	})

	t.Run("reset drops a buffer larger than the drop cap instead of keeping it", func(t *testing.T) {
		big := notif(EventAssocChange, sizeAssocChange+notificationDataDropCap+1)
		var acc notificationAccumulator
		acc.retain = true
		acc.add(big)
		if _, err := acc.finish(); err != nil {
			t.Fatalf("finish: %v", err)
		}
		if cap(acc.data) <= notificationDataDropCap {
			t.Fatalf("test setup: cap(data) = %d, want > %d (notificationDataDropCap)",
				cap(acc.data), notificationDataDropCap)
		}

		acc.reset()
		if acc.data != nil {
			t.Errorf("data = a slice of length %d, want nil: reset must drop a buffer "+
				"this large rather than keep it alive for the rest of the connection's life",
				len(acc.data))
		}

		// The reused accumulator must still decode correctly afterward.
		acc.retain = true
		small := notif(EventShutdown, sizeShutdownEvent)
		acc.add(small)
		got, err := acc.finish()
		if err != nil {
			t.Fatalf("finish after drop: %v", err)
		}
		if !bytes.Equal(got, small) {
			t.Fatalf("reassembly after drop = % x, want % x", got, small)
		}
	})

	t.Run("reset reuses storage across records without leaking stale bytes", func(t *testing.T) {
		// JDK-8261601: a per-connection accumulator reused for the next
		// record must not let the new, shorter record read back any trace
		// of the old, longer one. Unlike replacing the value outright,
		// reset must also keep data's capacity, which the allocation check
		// below pins.
		// Poisoned from right after the 8-byte header onward — through
		// sac_state/sac_error/sac_outbound_streams/sac_inbound_streams/
		// sac_assoc_id and into sac_info — so a leak is detectable in the
		// prefix array as well as in data: notif alone would leave that
		// fixed part zero, indistinguishable from what reset should itself
		// produce.
		long := notif(EventAssocChange, sizeAssocChange+80)
		for i := notificationHeaderSize; i < len(long); i++ {
			long[i] = 0xEE
		}
		short := notif(EventShutdown, sizeShutdownEvent)

		var acc notificationAccumulator
		acc.retain = true
		acc.add(long)
		gotLong, err := acc.finish()
		if err != nil {
			t.Fatalf("finish (long): %v", err)
		}
		if !bytes.Equal(gotLong, long) {
			t.Fatalf("first reassembly = % x, want % x", gotLong, long)
		}
		capBefore := cap(acc.data)

		acc.reset()
		if acc.retain || acc.total != 0 || acc.haveDeclared || acc.err != nil || acc.prefixBytes != 0 {
			t.Fatalf("reset left state behind: %+v", acc)
		}
		if cap(acc.data) != capBefore {
			t.Errorf("reset did not keep data's capacity: had %d, now %d", capBefore, cap(acc.data))
		}

		acc.retain = true
		acc.add(short)
		gotShort, err := acc.finish()
		if err != nil {
			t.Fatalf("finish (short): %v", err)
		}
		if !bytes.Equal(gotShort, short) {
			t.Fatalf("second reassembly = % x, want % x", gotShort, short)
		}
		if bytes.Contains(gotShort, []byte{0xEE}) {
			t.Fatalf("second reassembly % x carries a byte from the first record", gotShort)
		}
		// short is only sizeShutdownEvent bytes, so it never writes
		// prefix[sizeShutdownEvent:]; those bytes must be reset's zeroing,
		// not the first record's poison surviving underneath.
		if tail := acc.prefix[sizeShutdownEvent:]; !bytes.Equal(tail, make([]byte, len(tail))) {
			t.Fatalf("prefix tail past the second record's own bytes = % x, want all zero "+
				"(reset must clear the prefix array, not just prefixBytes)", tail)
		}

		t.Run("zero allocations when capacity already suffices", func(t *testing.T) {
			if underRaceDetector {
				t.Skip("allocation counts are unreliable under the race detector")
			}
			defer debug.SetGCPercent(debug.SetGCPercent(-1))

			var got []byte
			var ferr error
			allocs := testing.AllocsPerRun(50, func() {
				acc.reset()
				acc.retain = true
				acc.add(short)
				got, ferr = acc.finish()
			})
			if ferr != nil {
				t.Fatalf("finish: %v", ferr)
			}
			if !bytes.Equal(got, short) {
				t.Fatalf("reassembly = % x, want % x", got, short)
			}
			if allocs != 0 {
				t.Errorf("reassembling a record within already-allocated capacity "+
					"allocated %.1f times, want 0", allocs)
			}
		})
	})

	t.Run("assocChangeInfo can read the prefix as it grows, without retaining", func(t *testing.T) {
		if underRaceDetector {
			t.Skip("allocation counts are unreliable under the race detector")
		}
		defer debug.SetGCPercent(debug.SetGCPercent(-1))

		want := notif(EventAssocChange, sizeAssocChange)
		binary.NativeEndian.PutUint16(want[assocChangeStateOff:], uint16(AssocCommLost))
		binary.NativeEndian.PutUint32(want[assocChangeAssocIDOff:], 77)

		var acc notificationAccumulator // retain stays false: nothing wants the whole record
		var lastState AssocChangeState
		var lastID AssocID
		var lastOK bool
		var sawPremature bool
		allocs := testing.AllocsPerRun(20, func() {
			acc.reset()
			for i := range want {
				acc.add(want[i : i+1])
				state, id, ok := assocChangeInfo(acc.prefix[:acc.prefixBytes])
				if i+1 < sizeAssocChange && ok {
					sawPremature = true
				}
				lastState, lastID, lastOK = state, id, ok
			}
		})
		if sawPremature {
			t.Error("assocChangeInfo returned ok before sac_assoc_id had fully arrived")
		}
		if !lastOK || lastState != AssocCommLost || lastID != 77 {
			t.Fatalf("assocChangeInfo = (%v, %v, %v), want (AssocCommLost, 77, true)", lastState, lastID, lastOK)
		}
		if acc.data != nil {
			t.Errorf("data = %v, want nil: retain was never set", acc.data)
		}
		if allocs != 0 {
			t.Errorf("feeding a record byte-by-byte and peeking with assocChangeInfo "+
				"allocated %.1f times, want 0", allocs)
		}
	})
}

// FuzzNotificationAccumulator checks add/finish never panics and never
// retains more than NotificationReassemblyLimit bytes, for any split of any
// input into fragments.
func FuzzNotificationAccumulator(f *testing.F) {
	f.Add(notif(EventAssocChange, sizeAssocChange), uint8(3), true)
	f.Add([]byte{1, 2, 3}, uint8(1), false)
	f.Add(notifSized(EventAssocChange, NotificationReassemblyLimit+1, notificationHeaderSize, 0), uint8(8), true)

	f.Fuzz(func(t *testing.T, record []byte, stride uint8, retain bool) {
		accumulator := notificationAccumulator{retain: retain}
		step := int(stride) + 1
		for off := 0; off < len(record); off += step {
			end := off + step
			if end > len(record) {
				end = len(record)
			}
			accumulator.add(record[off:end])
		}
		got, err := accumulator.finish()
		if len(got) > NotificationReassemblyLimit {
			t.Fatalf("retained %d bytes, limit %d", len(got), NotificationReassemblyLimit)
		}
		if err != nil {
			return
		}
		if len(record) < notificationHeaderSize {
			t.Fatalf("accepted a %d-byte record", len(record))
		}
		if declared := binary.NativeEndian.Uint32(record[notificationLengthOff:]); declared != uint32(len(record)) {
			t.Fatalf("accepted %d bytes declaring %d", len(record), declared)
		}
		if retain && !bytes.Equal(got, record) {
			t.Fatal("retained notification differs from input")
		}
		if !retain && got != nil {
			t.Fatalf("non-retaining accumulator returned %d bytes", len(got))
		}
	})
}
