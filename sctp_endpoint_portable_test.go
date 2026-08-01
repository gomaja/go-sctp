package sctp

import (
	"errors"
	"math"
	"strconv"
	"syscall"
	"testing"
)

// TestErrUnsupportedWrapsStdlibSentinel is deliberately in a platform-neutral
// file: the package-specific sentinel is part of the portable API even on
// Linux, where socket operations do not normally return it.
func TestErrUnsupportedWrapsStdlibSentinel(t *testing.T) {
	t.Parallel()

	if !errors.Is(ErrUnsupported, errors.ErrUnsupported) {
		t.Error("errors.Is(ErrUnsupported, errors.ErrUnsupported) = false")
	}
	if !errors.Is(ErrUnsupported, ErrUnsupported) {
		t.Error("ErrUnsupported does not match itself")
	}
}

func TestAssociationIDFromIntRejectsWidthAliasing(t *testing.T) {
	t.Parallel()

	for _, value := range []int{math.MinInt32, -1, SCTP_FUTURE_ASSOC,
		SCTP_CURRENT_ASSOC, SCTP_ALL_ASSOC, SCTP_ALL_ASSOC + 1, math.MaxInt32} {
		got, err := associationIDFromInt(value)
		if err != nil || int(got) != value {
			t.Errorf("associationIDFromInt(%d) = (%d, %v)", value, got, err)
		}
	}
	if strconv.IntSize == 64 {
		for _, wide := range []int64{math.MinInt32 - 1, math.MaxInt32 + 1, 1 << 32} {
			value := int(wide)
			if got, err := associationIDFromInt(value); !errors.Is(err, syscall.EINVAL) {
				t.Errorf("associationIDFromInt(%d) = (%d, %v), want EINVAL",
					value, got, err)
			}
		}
	}
}

func TestValidEndpointAssociationID(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		id   SCTPAssocID
		want bool
	}{
		{"minimum", SCTPAssocID(math.MinInt32), false},
		{"negative", -1, false},
		{"future", SCTP_FUTURE_ASSOC, false},
		{"current", SCTP_CURRENT_ASSOC, false},
		{"all", SCTP_ALL_ASSOC, false},
		{"first kernel id", SCTP_ALL_ASSOC + 1, true},
		{"maximum", SCTPAssocID(math.MaxInt32), true},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := validEndpointAssociationID(tc.id); got != tc.want {
				t.Errorf("validEndpointAssociationID(%d) = %v, want %v",
					tc.id, got, tc.want)
			}
		})
	}
}

func TestSCTPEndpointNetwork(t *testing.T) {
	t.Parallel()

	if got := (*SCTPEndpoint)(nil).Network(); got != "" {
		t.Errorf("nil endpoint Network = %q, want empty", got)
	}
	for _, network := range []string{"sctp", "sctp4", "sctp6"} {
		ep := &SCTPEndpoint{network: network}
		if got := ep.Network(); got != network {
			t.Errorf("Network = %q, want %q", got, network)
		}
	}
}

func TestDecodeRcvInfoPayloadCopiesAndConvertsEveryField(t *testing.T) {
	t.Parallel()

	want := RcvInfo{
		SID:     0x1122,
		SSN:     0x3344,
		Flags:   SCTP_UNORDERED,
		PPID:    0x55667788,
		TSN:     0x99aabbcc,
		CumTSN:  0xddeeff00,
		Context: 0x12345678,
		AssocID: SCTPAssocID(0x01020304),
	}
	raw := want
	raw.PPID = htonl(raw.PPID)
	payload := toBuf(raw)

	first := decodeRcvInfoPayload(payload)
	if first == nil || *first != want {
		t.Fatalf("decodeRcvInfoPayload = %+v, want %+v", first, want)
	}
	second := decodeRcvInfoPayload(payload)
	if second == first {
		t.Fatal("two decodes returned the same pointer; results must not alias input storage")
	}
	if second == nil || *second != want {
		t.Fatalf("second decodeRcvInfoPayload = %+v, want %+v", second, want)
	}

	for i := range payload {
		payload[i] = 0xff
	}
	if *first != want {
		t.Fatalf("result changed after source overwrite: got %+v, want %+v", *first, want)
	}
}

func TestDecodeRcvInfoPayloadBoundaries(t *testing.T) {
	t.Parallel()

	for _, size := range []int{0, 1, 26, 27} {
		if got := decodeRcvInfoPayload(make([]byte, size)); got != nil {
			t.Errorf("size %d decoded as %+v, want nil", size, got)
		}
	}
	if got := decodeRcvInfoPayload(make([]byte, 28)); got == nil {
		t.Fatal("exact 28-byte payload did not decode")
	}
	if got := decodeRcvInfoPayload(make([]byte, 29)); got == nil {
		t.Fatal("payload with trailing extension byte did not decode")
	}
}

func FuzzDecodeRcvInfoPayload(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 27))
	f.Add(toBuf(RcvInfo{SID: 7, PPID: htonl(0x11223344), AssocID: 99}))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		_ = decodeRcvInfoPayload(data)
	})
}

func associationIDsPayload(ids ...SCTPAssocID) []byte {
	b := make([]byte, 4+len(ids)*4)
	nativeEndian.PutUint32(b[:4], uint32(len(ids)))
	for i, id := range ids {
		nativeEndian.PutUint32(b[4+i*4:], uint32(id))
	}
	return b
}

func TestDecodeAssociationIDsPayload(t *testing.T) {
	t.Parallel()

	want := []SCTPAssocID{3, 0x01020304, SCTPAssocID(math.MaxInt32)}
	payload := associationIDsPayload(want...)
	got, err := decodeAssociationIDsPayload(payload)
	if err != nil {
		t.Fatalf("decodeAssociationIDsPayload: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("decoded %d ids, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("id[%d] = %d, want %d", i, got[i], want[i])
		}
	}
	for i := range payload {
		payload[i] = 0
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("id[%d] changed after source overwrite: got %d, want %d",
				i, got[i], want[i])
		}
	}

	empty, err := decodeAssociationIDsPayload(associationIDsPayload())
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty list = (%v, %v), want non-nil empty slice", empty, err)
	}
}

func TestDecodeAssociationIDsPayloadRejectsMalformedLists(t *testing.T) {
	t.Parallel()

	tooMany := make([]byte, 4)
	nativeEndian.PutUint32(tooMany, associationIDListLimit+1)
	for _, tc := range []struct {
		name string
		data []byte
		want error
	}{
		{"empty header", nil, ErrInvalidAssociationList},
		{"short header", make([]byte, 3), ErrInvalidAssociationList},
		{"truncated ids", associationIDsPayload(3)[:4], ErrInvalidAssociationList},
		{"trailing bytes", append(associationIDsPayload(3), 0), ErrInvalidAssociationList},
		{"future selector", associationIDsPayload(SCTP_FUTURE_ASSOC), ErrInvalidAssociationList},
		{"current selector", associationIDsPayload(SCTP_CURRENT_ASSOC), ErrInvalidAssociationList},
		{"all selector", associationIDsPayload(SCTP_ALL_ASSOC), ErrInvalidAssociationList},
		{"negative id", associationIDsPayload(-1), ErrInvalidAssociationList},
		{"duplicate id", associationIDsPayload(3, 3), ErrInvalidAssociationList},
		{"over safety limit", tooMany, ErrAssociationListTooLarge},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ids, err := decodeAssociationIDsPayload(tc.data)
			if ids != nil || !errors.Is(err, tc.want) {
				t.Errorf("decode = (%v, %v), want (nil, %v)", ids, err, tc.want)
			}
		})
	}
}

func FuzzDecodeAssociationIDsPayload(f *testing.F) {
	f.Add([]byte{})
	f.Add(associationIDsPayload())
	f.Add(associationIDsPayload(3, 4, 5))
	tooMany := make([]byte, 4)
	nativeEndian.PutUint32(tooMany, associationIDListLimit+1)
	f.Add(tooMany)
	f.Fuzz(func(t *testing.T, data []byte) {
		ids, err := decodeAssociationIDsPayload(data)
		if err != nil {
			return
		}
		if len(ids) > associationIDListLimit {
			t.Fatalf("decoded %d ids beyond safety limit", len(ids))
		}
		seen := make(map[SCTPAssocID]struct{}, len(ids))
		for _, id := range ids {
			if !validEndpointAssociationID(id) {
				t.Fatalf("decoded reserved id %d", id)
			}
			if _, duplicate := seen[id]; duplicate {
				t.Fatalf("decoded duplicate id %d", id)
			}
			seen[id] = struct{}{}
		}
	})
}
