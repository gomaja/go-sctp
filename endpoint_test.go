// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"syscall"
	"testing"
)

// assocIDsPayload lays out struct sctp_assoc_ids (RFC 6458 §8.2.6) as
// SCTP_GET_ASSOC_ID_LIST writes it.
func assocIDsPayload(ids ...AssocID) []byte {
	b := make([]byte, sizeAssocIDs+len(ids)*sizeAssocID)
	binary.NativeEndian.PutUint32(b[assocIDsNumIDsOff:], uint32(len(ids)))
	for i, id := range ids {
		binary.NativeEndian.PutUint32(b[assocIDsIDsOff+i*sizeAssocID:], uint32(id))
	}
	return b
}

// rcvInfoFor is an SCTP_RCVINFO record naming association id, as a
// recvmsg's ancillary data carries it.
func rcvInfoFor(id AssocID) []byte {
	return buildRecvCmsg(nil, cmsgRcvInfo, rcvInfoPayload(7, 3, false, 0x11223344, 100, 99, 5, uint32(id)))
}

// TestRealAssocID: only ids above SCTP_ALL_ASSOC name an association; the
// three scope selectors and every negative id do not.
func TestRealAssocID(t *testing.T) {
	for _, tc := range []struct {
		id   AssocID
		want bool
	}{
		{math.MinInt32, false},
		{-1, false},
		{assocScopeFuture, false},
		{assocScopeCurrent, false},
		{assocScopeAll, false},
		{assocScopeAll + 1, true},
		{math.MaxInt32, true},
	} {
		if got := realAssocID(tc.id); got != tc.want {
			t.Errorf("realAssocID(%d) = %v, want %v", tc.id, got, tc.want)
		}
	}
}

// TestAssocIDArgNamesTheRefusal: a refused id matches syscall.EINVAL, and
// the message names the method and, for a selector, which selector it is.
func TestAssocIDArgNamesTheRefusal(t *testing.T) {
	for _, tc := range []struct {
		id   AssocID
		want string
	}{
		{0, "SCTP_FUTURE_ASSOC"},
		{1, "SCTP_CURRENT_ASSOC"},
		{2, "SCTP_ALL_ASSOC"},
		{-5, "negative"},
	} {
		err := assocIDArg("PeelOff", tc.id)
		if !errors.Is(err, syscall.EINVAL) || !strings.Contains(err.Error(), "PeelOff") || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("assocIDArg(%d) = %v, want EINVAL naming PeelOff and %s", tc.id, err, tc.want)
		}
	}
	if err := assocIDArg("PeelOff", 3); err != nil {
		t.Errorf("assocIDArg(3) = %v, want nil", err)
	}
}

// TestEndpointNetwork: Network reports the network the Endpoint was opened
// on, and "" for a nil or never-opened Endpoint.
func TestEndpointNetwork(t *testing.T) {
	if got := (*Endpoint)(nil).Network(); got != "" {
		t.Errorf("nil Endpoint Network = %q, want empty", got)
	}
	if got := new(Endpoint).Network(); got != "" {
		t.Errorf("zero Endpoint Network = %q, want empty", got)
	}
	for _, network := range []string{"sctp", "sctp4", "sctp6"} {
		e := &Endpoint{sock: socket{network: network}}
		if got := e.Network(); got != network {
			t.Errorf("Network = %q, want %q", got, network)
		}
	}
}

// TestDecodeAssocIDs: the ids come back in ascending order, as a slice of
// their own that later changes to the buffer leave alone, and an empty
// list is a non-nil empty slice.
func TestDecodeAssocIDs(t *testing.T) {
	want := []AssocID{3, 0x01020304, math.MaxInt32}
	b := assocIDsPayload(math.MaxInt32, 3, 0x01020304)
	got, err := decodeAssocIDs(b)
	if err != nil {
		t.Fatalf("decodeAssocIDs: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("decoded %v, want %v", got, want)
	}
	clear(b)
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("id[%d] = %d after the buffer was cleared, want %d", i, got[i], want[i])
		}
	}
	empty, err := decodeAssocIDs(assocIDsPayload())
	if err != nil || empty == nil || len(empty) != 0 {
		t.Errorf("empty list = (%v, %v), want a non-nil empty slice", empty, err)
	}
}

// TestDecodeAssocIDsRefusesMalformedLists: a list that cannot be trusted
// whole is refused whole, never returned in part.
func TestDecodeAssocIDsRefusesMalformedLists(t *testing.T) {
	tooMany := make([]byte, sizeAssocIDs)
	binary.NativeEndian.PutUint32(tooMany, assocIDListLimit+1)
	for _, tc := range []struct {
		name string
		b    []byte
		want error
	}{
		{"empty", nil, ErrInvalidAssocList},
		{"short header", make([]byte, 3), ErrInvalidAssocList},
		{"truncated ids", assocIDsPayload(3)[:4], ErrInvalidAssocList},
		{"trailing bytes", append(assocIDsPayload(3), 0), ErrInvalidAssocList},
		{"future selector", assocIDsPayload(assocScopeFuture), ErrInvalidAssocList},
		{"current selector", assocIDsPayload(assocScopeCurrent), ErrInvalidAssocList},
		{"all selector", assocIDsPayload(assocScopeAll), ErrInvalidAssocList},
		{"negative id", assocIDsPayload(-1), ErrInvalidAssocList},
		{"duplicate id", assocIDsPayload(3, 3), ErrInvalidAssocList},
		{"duplicate id apart", assocIDsPayload(9, 4, 7, 4), ErrInvalidAssocList},
		{"over the bound", tooMany, ErrAssocListTooLarge},
	} {
		ids, err := decodeAssocIDs(tc.b)
		if ids != nil || !errors.Is(err, tc.want) {
			t.Errorf("%s: decodeAssocIDs = (%v, %v), want (nil, %v)", tc.name, ids, err, tc.want)
		}
	}
}

// FuzzDecodeAssocIDs: whatever the kernel wrote, a list that decodes holds
// no more than the bound, only real ids, and none twice.
func FuzzDecodeAssocIDs(f *testing.F) {
	f.Add([]byte{})
	f.Add(assocIDsPayload())
	f.Add(assocIDsPayload(3, 4, 5))
	tooMany := make([]byte, sizeAssocIDs)
	binary.NativeEndian.PutUint32(tooMany, assocIDListLimit+1)
	f.Add(tooMany)
	f.Fuzz(func(t *testing.T, b []byte) {
		ids, err := decodeAssocIDs(b)
		if err != nil {
			if ids != nil {
				t.Fatalf("an error with ids %v", ids)
			}
			return
		}
		if len(ids) > assocIDListLimit {
			t.Fatalf("decoded %d ids, more than the bound", len(ids))
		}
		seen := make(map[AssocID]bool, len(ids))
		for i, id := range ids {
			if !realAssocID(id) || seen[id] {
				t.Fatalf("decoded id %d, not a real id or seen twice", id)
			}
			if i > 0 && ids[i-1] > id {
				t.Fatalf("decoded ids out of order: %v", ids)
			}
			seen[id] = true
		}
	})
}

// TestEndpointRcvInfoCopiesEveryField: a message's SCTP_RCVINFO fills Rcv
// field by field, PPID in host order, as a value that later changes to
// the ancillary data leave alone.
func TestEndpointRcvInfoCopiesEveryField(t *testing.T) {
	oob := buildRecvCmsg(nil, cmsgRcvInfo, rcvInfoPayload(0x1122, 0x3344, true, 0x55667788, 0x99aabbcc, 0xddeeff00, 0x12345678, 0x01020304))
	var info MsgInfo
	if err := parseEndpointRecvCmsgs(oob, int(msgEOR), &info); err != nil {
		t.Fatalf("parseEndpointRecvCmsgs: %v", err)
	}
	want := RcvInfo{Stream: 0x1122, SSN: 0x3344, Unordered: true, PPID: 0x55667788, TSN: 0x99aabbcc, CumTSN: 0xddeeff00, Context: 0x12345678, AssocID: 0x01020304}
	if info.Rcv != want || !info.EOR {
		t.Fatalf("info = %+v, want Rcv %+v and EOR", info, want)
	}
	clear(oob)
	if info.Rcv != want {
		t.Errorf("Rcv changed with the ancillary data: %+v", info.Rcv)
	}
}

// TestEndpointRcvInfoPayloadBoundaries: a record shorter than struct
// sctp_rcvinfo is refused with ErrInvalidRcvInfo, and one with trailing
// bytes, as a later kernel's longer struct would be, is accepted.
func TestEndpointRcvInfoPayloadBoundaries(t *testing.T) {
	full := rcvInfoPayload(1, 2, false, 3, 4, 5, 6, 99)
	for _, size := range []int{0, 1, sizeRcvInfo - 2, sizeRcvInfo - 1} {
		var info MsgInfo
		err := parseEndpointRecvCmsgs(buildRecvCmsg(nil, cmsgRcvInfo, full[:size]), 0, &info)
		if !errors.Is(err, ErrInvalidRcvInfo) || info.Rcv != (RcvInfo{}) {
			t.Errorf("a %d-byte record: %v, Rcv %+v; want ErrInvalidRcvInfo and a zero Rcv", size, err, info.Rcv)
		}
	}
	for _, extra := range []int{0, 1} {
		var info MsgInfo
		payload := append(full[:sizeRcvInfo:sizeRcvInfo], make([]byte, extra)...)
		if err := parseEndpointRecvCmsgs(buildRecvCmsg(nil, cmsgRcvInfo, payload), 0, &info); err != nil || info.Rcv.AssocID != 99 {
			t.Errorf("a record with %d trailing bytes: %v, Rcv %+v; want association 99", extra, err, info.Rcv)
		}
	}
}

// TestEndpointRcvInfoEnvelope: data with no SCTP_RCVINFO fails with
// ErrMissingRcvInfo, whatever else the ancillary data holds; a control
// message header that declares more bytes than there are fails with
// ErrInvalidRcvInfo; a notification needs no record at all.
func TestEndpointRcvInfoEnvelope(t *testing.T) {
	malformed := buildRecvCmsg(nil, cmsgRcvInfo, rcvInfoPayload(1, 2, false, 3, 4, 5, 6, 99))
	putWord(malformed[cmsghdrLenOff:], uint64(len(malformed)+64))
	for _, tc := range []struct {
		name  string
		oob   []byte
		flags int
		want  error
	}{
		{"no ancillary data", nil, 0, ErrMissingRcvInfo},
		{"only NXTINFO", buildRecvCmsg(nil, cmsgNxtInfo, nxtInfoPayload(1, false, false, 2, 3, 99)), 0, ErrMissingRcvInfo},
		{"RCVINFO at another level", buildRecvCmsgLevel(nil, syscall.SOL_SOCKET, cmsgRcvInfo, rcvInfoPayload(1, 2, false, 3, 4, 5, 6, 99)), 0, ErrMissingRcvInfo},
		{"malformed header", malformed, 0, ErrInvalidRcvInfo},
		{"notification", nil, int(msgNotification), nil},
	} {
		var info MsgInfo
		err := parseEndpointRecvCmsgs(tc.oob, tc.flags, &info)
		if !errors.Is(err, tc.want) || (tc.want == nil && err != nil) || info.Rcv != (RcvInfo{}) {
			t.Errorf("%s: %v, Rcv %+v; want %v and a zero Rcv", tc.name, err, info.Rcv, tc.want)
		}
	}
	// NXTINFO and RCVINFO together, in the order Linux writes them.
	oob := buildRecvCmsg(nil, cmsgNxtInfo, nxtInfoPayload(4, false, false, 5, 6, 77))
	oob = append(oob, rcvInfoFor(77)...)
	var info MsgInfo
	if err := parseEndpointRecvCmsgs(oob, 0, &info); err != nil || info.Rcv.AssocID != 77 || !info.HasNxt {
		t.Errorf("NXTINFO then RCVINFO: %v, %+v; want association 77 and the next message", err, info)
	}
}

// TestEndpointRcvInfoRefusesDuplicates: two SCTP_RCVINFO records on one
// message, alike or not, make its association ambiguous.
func TestEndpointRcvInfoRefusesDuplicates(t *testing.T) {
	for name, second := range map[string]AssocID{"identical": 101, "conflicting": 202} {
		oob := append(rcvInfoFor(101), rcvInfoFor(second)...)
		var info MsgInfo
		err := parseEndpointRecvCmsgs(oob, 0, &info)
		if !errors.Is(err, ErrInvalidRcvInfo) || info.Rcv != (RcvInfo{}) {
			t.Errorf("%s duplicate: %v, Rcv %+v; want ErrInvalidRcvInfo and a zero Rcv", name, err, info.Rcv)
		}
	}
}

// TestEndpointRcvInfoRefusesScopeSelectors: an SCTP_RCVINFO naming a scope
// selector, or a negative id, names no association.
func TestEndpointRcvInfoRefusesScopeSelectors(t *testing.T) {
	for _, tc := range []struct {
		id      AssocID
		wantErr bool
	}{
		{-1, true},
		{assocScopeFuture, true},
		{assocScopeCurrent, true},
		{assocScopeAll, true},
		{assocScopeAll + 1, false},
		{99, false},
	} {
		var info MsgInfo
		err := parseEndpointRecvCmsgs(rcvInfoFor(tc.id), 0, &info)
		if tc.wantErr {
			if !errors.Is(err, ErrInvalidRcvInfo) || info.Rcv != (RcvInfo{}) {
				t.Errorf("association %d: %v, Rcv %+v; want ErrInvalidRcvInfo and a zero Rcv", tc.id, err, info.Rcv)
			}
			continue
		}
		if err != nil || info.Rcv.AssocID != tc.id {
			t.Errorf("association %d: %v, Rcv %+v", tc.id, err, info.Rcv)
		}
	}
}

// TestEndpointRcvInfoTruncation: MSG_CTRUNC is reported as
// ErrControlTruncated, ahead of a missing or short record, which the
// truncation explains; a record that arrived whole is kept.
func TestEndpointRcvInfoTruncation(t *testing.T) {
	var info MsgInfo
	if err := parseEndpointRecvCmsgs(nil, int(msgCtrunc), &info); !errors.Is(err, ErrControlTruncated) || info.Rcv != (RcvInfo{}) {
		t.Errorf("truncated with no record: %v, %+v; want ErrControlTruncated and a zero Rcv", err, info.Rcv)
	}
	if err := parseEndpointRecvCmsgs(rcvInfoFor(55), int(msgCtrunc), &info); !errors.Is(err, ErrControlTruncated) || info.Rcv.AssocID != 55 {
		t.Errorf("truncated after a whole record: %v, %+v; want ErrControlTruncated and association 55", err, info.Rcv)
	}
}

// FuzzEndpointRcvInfo: whatever the ancillary data holds, a message
// reported without an error names a real association, and one reported
// with ErrMissingRcvInfo or ErrInvalidRcvInfo names none.
func FuzzEndpointRcvInfo(f *testing.F) {
	f.Add([]byte{}, 0)
	f.Add([]byte{1, 2, 3}, 0)
	f.Add(rcvInfoFor(99), int(msgEOR))
	f.Add(buildRecvCmsg(nil, cmsgRcvInfo, make([]byte, sizeRcvInfo-1)), 0)
	f.Add(append(rcvInfoFor(3), rcvInfoFor(4)...), int(msgCtrunc))
	f.Fuzz(func(t *testing.T, oob []byte, flags int) {
		if len(oob) > 4096 {
			t.Skip()
		}
		var info MsgInfo
		err := parseEndpointRecvCmsgs(oob, flags, &info)
		if info.Notification {
			return
		}
		if err == nil && !realAssocID(info.Rcv.AssocID) {
			t.Fatalf("no error, but Rcv names association %d", info.Rcv.AssocID)
		}
		if (errors.Is(err, ErrMissingRcvInfo) || errors.Is(err, ErrInvalidRcvInfo)) && info.Rcv != (RcvInfo{}) {
			t.Fatalf("%v with Rcv %+v", err, info.Rcv)
		}
	})
}
