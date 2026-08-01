//go:build linux
// +build linux

package sctp

import (
	"errors"
	"syscall"
	"testing"
	"unsafe"
)

func TestParseRcvInfoEnvelopeAndPayloadBoundaries(t *testing.T) {
	t.Parallel()

	short := sctpCmsg(SCTP_CMSG_RCVINFO,
		make([]byte, int(unsafe.Sizeof(RcvInfo{}))-1))
	unrelated := sctpCmsg(SCTP_CMSG_SNDINFO, toBuf(SndInfo{}))
	malformed := make([]byte, syscall.CmsgSpace(0))
	hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&malformed[0]))
	hdr.Level = syscall.IPPROTO_SCTP
	hdr.Type = SCTP_CMSG_RCVINFO
	hdr.SetLen(syscall.CmsgLen(128)) // declares bytes beyond the envelope

	for _, tc := range []struct {
		name    string
		input   []byte
		wantNil bool
		wantErr bool
	}{
		{"empty", nil, true, false},
		{"short payload", short, true, true},
		{"unrelated SCTP cmsg", unrelated, true, false},
		{"malformed envelope", malformed, true, true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseRcvInfo(tc.input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
			if (got == nil) != tc.wantNil {
				t.Fatalf("result = %+v, wantNil %v", got, tc.wantNil)
			}
		})
	}
}

func TestParseRcvInfoRejectsDuplicateItems(t *testing.T) {
	t.Parallel()

	one := RcvInfo{SID: 1, PPID: htonl(0x11111111), AssocID: 101}
	two := RcvInfo{SID: 2, PPID: htonl(0x22222222), AssocID: 202}
	for _, tc := range []struct {
		name   string
		second RcvInfo
	}{
		{"identical", one},
		{"conflicting", two},
	} {
		oob := append(sctpCmsg(SCTP_CMSG_RCVINFO, toBuf(one)),
			sctpCmsg(SCTP_CMSG_RCVINFO, toBuf(tc.second))...)
		got, err := parseRcvInfo(oob)
		if !errors.Is(err, ErrInvalidReceiveInfo) || got != nil {
			t.Errorf("%s duplicate = (%+v, %v), want nil ErrInvalidReceiveInfo",
				tc.name, got, err)
		}
	}
}

func TestParseRcvInfoRejectsReservedAssociationIDs(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		id      SCTPAssocID
		wantErr bool
	}{
		{"negative", -1, true},
		{"future", SCTP_FUTURE_ASSOC, true},
		{"current", SCTP_CURRENT_ASSOC, true},
		{"all", SCTP_ALL_ASSOC, true},
		{"first routable", SCTP_ALL_ASSOC + 1, false},
		{"ordinary", 99, false},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			oob := sctpCmsg(SCTP_CMSG_RCVINFO, toBuf(RcvInfo{AssocID: tc.id}))
			got, err := parseRcvInfo(oob)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidReceiveInfo) || got != nil {
					t.Fatalf("parseRcvInfo = (%+v, %v), want nil ErrInvalidReceiveInfo", got, err)
				}
				return
			}
			if err != nil || got == nil || got.AssocID != tc.id {
				t.Fatalf("parseRcvInfo = (%+v, %v), want association %d", got, err, tc.id)
			}
		})
	}
}

func FuzzParseRcvInfo(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3})
	f.Add(sctpCmsg(SCTP_CMSG_RCVINFO, toBuf(RcvInfo{
		SID: 7, PPID: htonl(0x11223344), AssocID: 99,
	})))
	f.Add(sctpCmsg(SCTP_CMSG_RCVINFO,
		make([]byte, int(unsafe.Sizeof(RcvInfo{}))-1)))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		info, err := parseRcvInfo(data)
		if info != nil && !validEndpointAssociationID(SCTPAssocID(info.AssocID)) {
			t.Fatalf("returned reserved association id %d with error %v", info.AssocID, err)
		}
		if errors.Is(err, ErrInvalidReceiveInfo) && info != nil {
			t.Fatalf("returned invalid info %+v with %v", info, err)
		}
	})
}
