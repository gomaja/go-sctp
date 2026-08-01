package sctp

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestWithPreAssociationSnapshotsAllMutableInputs(t *testing.T) {
	t.Parallel()

	delayed := &DelayedSACKConfig{Delay: 120, Frequency: 2}
	rto := &RtoInfo{Initial: 111, Max: 2222, Min: 333}
	hmacs := []uint16{SCTPAuthHmacIDSHA256, SCTPAuthHmacIDSHA1}
	chunks := []uint8{0, 192}
	notifications := []NotificationSubscription{{
		Type: SCTP_ASSOC_CHANGE, State: SocketOptionEnable,
	}}
	pre := PreAssociationConfig{
		Authentication:      SocketOptionEnable,
		DelayedSACK:         delayed,
		RTOInfo:             rto,
		HMACIdentifiers:     hmacs,
		AuthenticatedChunks: chunks,
		Notifications:       notifications,
	}
	socket := &SocketConfig{InitMsg: InitMsg{NumOstreams: 17}}
	configured := socket.WithPreAssociation(pre)

	socket.InitMsg.NumOstreams = 99
	delayed.Delay = 499
	rto.Initial = 999
	hmacs[0] = SCTPAuthHmacIDSHA1
	chunks[0] = 7
	notifications[0].State = SocketOptionDisable
	pre.DelayedSACK = nil
	pre.RTOInfo = nil
	pre.HMACIdentifiers = nil
	pre.AuthenticatedChunks = nil
	pre.Notifications = nil

	gotSocket, gotPre := configured.snapshot()
	if gotSocket.InitMsg.NumOstreams != 17 {
		t.Fatalf("snapshotted InitMsg.NumOstreams = %d, want 17",
			gotSocket.InitMsg.NumOstreams)
	}
	if gotPre.DelayedSACK == delayed || *gotPre.DelayedSACK != (DelayedSACKConfig{Delay: 120, Frequency: 2}) {
		t.Fatalf("snapshotted DelayedSACK = %+v, want independent 120/2", gotPre.DelayedSACK)
	}
	if gotPre.RTOInfo == rto || *gotPre.RTOInfo != (RtoInfo{Initial: 111, Max: 2222, Min: 333}) {
		t.Fatalf("snapshotted RTOInfo = %+v, want independent 111/2222/333", gotPre.RTOInfo)
	}
	if !reflect.DeepEqual(gotPre.HMACIdentifiers,
		[]uint16{SCTPAuthHmacIDSHA256, SCTPAuthHmacIDSHA1}) {
		t.Fatalf("snapshotted HMAC identifiers = %v", gotPre.HMACIdentifiers)
	}
	if !reflect.DeepEqual(gotPre.AuthenticatedChunks, []uint8{0, 192}) {
		t.Fatalf("snapshotted authenticated chunks = %v", gotPre.AuthenticatedChunks)
	}
	if !reflect.DeepEqual(gotPre.Notifications, []NotificationSubscription{{
		Type: SCTP_ASSOC_CHANGE, State: SocketOptionEnable,
	}}) {
		t.Fatalf("snapshotted notifications = %v", gotPre.Notifications)
	}
}

func TestWithPreAssociationPreservesNilAndEmptySlices(t *testing.T) {
	t.Parallel()

	_, nilPre := (*SocketConfig)(nil).WithPreAssociation(PreAssociationConfig{}).snapshot()
	if nilPre.HMACIdentifiers != nil || nilPre.AuthenticatedChunks != nil ||
		nilPre.Notifications != nil {
		t.Fatalf("nil slices changed shape: %+v", nilPre)
	}

	_, emptyPre := new(SocketConfig).WithPreAssociation(PreAssociationConfig{
		HMACIdentifiers:     []uint16{},
		AuthenticatedChunks: []uint8{},
		Notifications:       []NotificationSubscription{},
	}).snapshot()
	if emptyPre.HMACIdentifiers == nil || emptyPre.AuthenticatedChunks == nil ||
		emptyPre.Notifications == nil {
		t.Fatalf("non-nil empty slices changed to nil: %+v", emptyPre)
	}
}

func TestPreparePreAssociationZeroValue(t *testing.T) {
	t.Parallel()

	oneToOne, err := preparePreAssociationConfig(PreAssociationConfig{}, preAssociationOneToOne)
	if err != nil {
		t.Fatalf("prepare one-to-one zero value: %v", err)
	}
	if len(oneToOne.operations) != 0 {
		t.Fatalf("one-to-one zero value produced %d operations, want none: %+v",
			len(oneToOne.operations), oneToOne.operations)
	}

	endpoint, err := preparePreAssociationConfig(PreAssociationConfig{}, preAssociationOneToMany)
	if err != nil {
		t.Fatalf("prepare one-to-many zero value: %v", err)
	}
	want := []preAssociationOperation{{
		kind: preAssociationReceiveRcvInfo, value: 1,
	}, {
		kind: preAssociationFragmentInterleave, value: SCTPFragmentInterleaveOther,
	}}
	if !reflect.DeepEqual(endpoint.operations, want) {
		t.Fatalf("one-to-many zero-value operations = %+v, want %+v",
			endpoint.operations, want)
	}
}

func TestPreparePreAssociationExplicitFragmentInterleaveWins(t *testing.T) {
	t.Parallel()

	for _, style := range []preAssociationSocketStyle{
		preAssociationOneToOne,
		preAssociationOneToMany,
	} {
		style := style
		for _, level := range []int{
			SCTPFragmentInterleaveNone,
			SCTPFragmentInterleaveOther,
			SCTPFragmentInterleaveStreams,
		} {
			level := level
			t.Run(style.String()+"/level="+string(rune('0'+level)), func(t *testing.T) {
				t.Parallel()
				cfg := PreAssociationConfig{
					FragmentInterleave: OptionalInt{Set: true, Value: level},
				}
				if style == preAssociationOneToOne && level == SCTPFragmentInterleaveStreams {
					cfg.ReceiveRcvInfo = SocketOptionEnable
				}
				prepared, err := preparePreAssociationConfig(cfg, style)
				if err != nil {
					t.Fatalf("prepare: %v", err)
				}
				want := []preAssociationOperation{}
				if cfg.ReceiveRcvInfo == SocketOptionEnable || style == preAssociationOneToMany {
					want = append(want, preAssociationOperation{
						kind: preAssociationReceiveRcvInfo, value: 1,
					})
				}
				want = append(want, preAssociationOperation{
					kind:  preAssociationFragmentInterleave,
					value: uint32(level),
				})
				if !reflect.DeepEqual(prepared.operations, want) {
					t.Fatalf("operations = %+v, want %+v", prepared.operations, want)
				}
			})
		}
	}
}

func TestPreparePreAssociationOrderAndValues(t *testing.T) {
	t.Parallel()

	resetMask := uint32(SCTPEnableResetStreamReq | SCTPEnableChangeAssocReq)
	cfg := PreAssociationConfig{
		PartialReliability:            SocketOptionDisable,
		StreamReconfiguration:         SocketOptionEnable,
		DynamicAddressReconfiguration: SocketOptionEnable,
		Authentication:                SocketOptionEnable,
		MessageInterleaving:           SocketOptionEnable,
		ExperimentalECN:               SocketOptionDisable,
		ReusePort:                     SocketOptionEnable,
		MappedV4Address:               SocketOptionDisable,
		DisableFragments:              SocketOptionEnable,
		ReceiveRcvInfo:                SocketOptionEnable,
		ReceiveNxtInfo:                SocketOptionDisable,
		AdaptationLayer:               OptionalUint32{Set: true, Value: 0},
		FragmentInterleave:            OptionalInt{Set: true, Value: SCTPFragmentInterleaveStreams},
		StreamResetMask:               OptionalUint32{Set: true, Value: resetMask},
		RTOInfo:                       &RtoInfo{Initial: 111, Max: 2222, Min: 333},
		DelayedSACK:                   &DelayedSACKConfig{Delay: 250, Frequency: 4},
		HMACIdentifiers: []uint16{
			SCTPAuthHmacIDSHA256,
			SCTPAuthHmacIDSHA1,
		},
		AuthenticatedChunks: []uint8{0, 192},
		Notifications: []NotificationSubscription{
			{Type: SCTP_ASSOC_CHANGE, State: SocketOptionEnable},
			{Type: SCTP_SENDER_DRY_EVENT, State: SocketOptionDisable},
		},
	}

	prepared, err := preparePreAssociationConfig(cfg, preAssociationOneToOne)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	want := []preAssociationOperation{
		{kind: preAssociationReceiveRcvInfo, value: 1},
		{kind: preAssociationFragmentInterleave, value: SCTPFragmentInterleaveStreams},
		{kind: preAssociationAuthentication, value: 1},
		{kind: preAssociationHMACIdentifiers, hmacIdentifiers: []uint16{SCTPAuthHmacIDSHA256, SCTPAuthHmacIDSHA1}},
		{kind: preAssociationAuthenticatedChunk, value: 0},
		{kind: preAssociationAuthenticatedChunk, value: 192},
		{kind: preAssociationDynamicAddressReconfiguration, value: 1},
		{kind: preAssociationPartialReliability, value: 0},
		{kind: preAssociationStreamReconfiguration, value: 1},
		{kind: preAssociationStreamResetMask, value: resetMask},
		{kind: preAssociationMessageInterleaving, value: 1},
		{kind: preAssociationExperimentalECN, value: 0},
		{kind: preAssociationAdaptationLayer, value: 0},
		{kind: preAssociationRTOInfo, rtoInfo: RtoInfo{
			AssocID: SCTPAssocID(SCTP_FUTURE_ASSOC),
			Initial: 111,
			Max:     2222,
			Min:     333,
		}},
		{kind: preAssociationDelayedSACK, value: 250, secondaryValue: 4},
		{kind: preAssociationMappedV4Address, value: 0},
		{kind: preAssociationDisableFragments, value: 1},
		{kind: preAssociationReusePort, value: 1},
		{kind: preAssociationReceiveNxtInfo, value: 0},
		{kind: preAssociationNotification, value: 1, notificationType: SCTP_ASSOC_CHANGE},
		{kind: preAssociationNotification, value: 0, notificationType: SCTP_SENDER_DRY_EVENT},
	}
	if !reflect.DeepEqual(prepared.operations, want) {
		t.Fatalf("operations:\n got: %+v\nwant: %+v", prepared.operations, want)
	}
}

func TestPreparePreAssociationRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	allResetBits := uint32(SCTPEnableResetStreamReq | SCTPEnableResetAssocReq |
		SCTPEnableChangeAssocReq)
	tests := []struct {
		name  string
		style preAssociationSocketStyle
		cfg   PreAssociationConfig
		want  string
	}{
		{
			name: "invalid state",
			cfg: PreAssociationConfig{
				PartialReliability: SocketOptionState(3),
			},
			want: "PartialReliability",
		},
		{
			name: "negative fragment level",
			cfg: PreAssociationConfig{
				FragmentInterleave: OptionalInt{Set: true, Value: -1},
			},
			want: "FragmentInterleave",
		},
		{
			name: "high fragment level",
			cfg: PreAssociationConfig{
				FragmentInterleave: OptionalInt{Set: true, Value: 3},
			},
			want: "FragmentInterleave",
		},
		{
			name: "ignored fragment value",
			cfg: PreAssociationConfig{
				FragmentInterleave: OptionalInt{Value: 1},
			},
			want: "FragmentInterleave",
		},
		{
			name: "ignored adaptation value",
			cfg: PreAssociationConfig{
				AdaptationLayer: OptionalUint32{Value: 1},
			},
			want: "AdaptationLayer",
		},
		{
			name: "ignored reset mask",
			cfg: PreAssociationConfig{
				StreamResetMask: OptionalUint32{Value: 1},
			},
			want: "StreamResetMask",
		},
		{
			name: "unknown reset mask bit",
			cfg: PreAssociationConfig{
				StreamResetMask: OptionalUint32{Set: true, Value: allResetBits | 8},
			},
			want: "unknown bits",
		},
		{
			name: "SACK delay above protocol maximum",
			cfg: PreAssociationConfig{
				DelayedSACK: &DelayedSACKConfig{Delay: 501, Frequency: 2},
			},
			want: "500 ms maximum",
		},
		{
			name: "RTOInfo current association selector",
			cfg: PreAssociationConfig{
				RTOInfo: &RtoInfo{AssocID: SCTPAssocID(SCTP_CURRENT_ASSOC)},
			},
			want: "RTOInfo.AssocID",
		},
		{
			name: "RTOInfo all associations selector",
			cfg: PreAssociationConfig{
				RTOInfo: &RtoInfo{AssocID: SCTPAssocID(SCTP_ALL_ASSOC)},
			},
			want: "RTOInfo.AssocID",
		},
		{
			name: "RTOInfo existing association selector",
			cfg: PreAssociationConfig{
				RTOInfo: &RtoInfo{AssocID: SCTPAssocID(3)},
			},
			want: "RTOInfo.AssocID",
		},
		{
			name: "ASCONF without AUTH",
			cfg: PreAssociationConfig{
				DynamicAddressReconfiguration: SocketOptionEnable,
			},
			want: "Authentication",
		},
		{
			name: "reset without reconfiguration",
			cfg: PreAssociationConfig{
				StreamResetMask: OptionalUint32{Set: true, Value: 1},
			},
			want: "StreamReconfiguration",
		},
		{
			name: "one-to-one interleaving without fragment level",
			cfg: PreAssociationConfig{
				MessageInterleaving: SocketOptionEnable,
			},
			want: "FragmentInterleave",
		},
		{
			name: "one-to-one interleaving with level zero",
			cfg: PreAssociationConfig{
				MessageInterleaving: SocketOptionEnable,
				FragmentInterleave:  OptionalInt{Set: true, Value: 0},
			},
			want: "non-zero",
		},
		{
			name: "one-to-one level two without receive metadata",
			cfg: PreAssociationConfig{
				FragmentInterleave: OptionalInt{
					Set: true, Value: SCTPFragmentInterleaveStreams,
				},
			},
			want: "SCTP_DATA_IO_EVENT",
		},
		{
			name:  "endpoint reuse-port enable",
			style: preAssociationOneToMany,
			cfg: PreAssociationConfig{
				ReusePort: SocketOptionEnable,
			},
			want: "ReusePort",
		},
		{
			name:  "endpoint reuse-port disable",
			style: preAssociationOneToMany,
			cfg: PreAssociationConfig{
				ReusePort: SocketOptionDisable,
			},
			want: "ReusePort",
		},
		{
			name:  "endpoint RCVINFO disable",
			style: preAssociationOneToMany,
			cfg: PreAssociationConfig{
				ReceiveRcvInfo: SocketOptionDisable,
			},
			want: "ReceiveRcvInfo",
		},
		{
			name: "event default state",
			cfg: PreAssociationConfig{
				Notifications: []NotificationSubscription{{Type: SCTP_ASSOC_CHANGE}},
			},
			want: "state",
		},
		{
			name: "unknown event",
			cfg: PreAssociationConfig{
				Notifications: []NotificationSubscription{{Type: 0x9999, State: SocketOptionEnable}},
			},
			want: "notification type",
		},
		{
			name: "duplicate event",
			cfg: PreAssociationConfig{
				Notifications: []NotificationSubscription{
					{Type: SCTP_ASSOC_CHANGE, State: SocketOptionEnable},
					{Type: SCTP_ASSOC_CHANGE, State: SocketOptionDisable},
				},
			},
			want: "duplicate",
		},
		{
			name:  "endpoint mandatory event disabled",
			style: preAssociationOneToMany,
			cfg: PreAssociationConfig{
				Notifications: []NotificationSubscription{{
					Type: SCTP_ASSOC_CHANGE, State: SocketOptionDisable,
				}},
			},
			want: "SCTP_ASSOC_CHANGE",
		},
		{
			name: "empty HMAC list",
			cfg: PreAssociationConfig{
				Authentication:  SocketOptionEnable,
				HMACIdentifiers: []uint16{},
			},
			want: "HMACIdentifiers",
		},
		{
			name: "HMAC list without AUTH",
			cfg: PreAssociationConfig{
				HMACIdentifiers: []uint16{SCTPAuthHmacIDSHA1},
			},
			want: "Authentication",
		},
		{
			name: "HMAC list omits mandatory SHA-1",
			cfg: PreAssociationConfig{
				Authentication:  SocketOptionEnable,
				HMACIdentifiers: []uint16{SCTPAuthHmacIDSHA256},
			},
			want: "SHA-1",
		},
		{
			name: "unassigned HMAC identifier",
			cfg: PreAssociationConfig{
				Authentication:  SocketOptionEnable,
				HMACIdentifiers: []uint16{SCTPAuthHmacIDSHA1, 2},
			},
			want: "identifier 2",
		},
		{
			name: "duplicate HMAC identifier",
			cfg: PreAssociationConfig{
				Authentication:  SocketOptionEnable,
				HMACIdentifiers: []uint16{SCTPAuthHmacIDSHA1, SCTPAuthHmacIDSHA1},
			},
			want: "duplicate",
		},
		{
			name: "empty authenticated chunks",
			cfg: PreAssociationConfig{
				Authentication:      SocketOptionEnable,
				AuthenticatedChunks: []uint8{},
			},
			want: "AuthenticatedChunks",
		},
		{
			name: "authenticated chunks without AUTH",
			cfg: PreAssociationConfig{
				AuthenticatedChunks: []uint8{0},
			},
			want: "Authentication",
		},
		{
			name: "forbidden INIT auth chunk",
			cfg: PreAssociationConfig{
				Authentication:      SocketOptionEnable,
				AuthenticatedChunks: []uint8{1},
			},
			want: "INIT",
		},
		{
			name: "duplicate authenticated chunk",
			cfg: PreAssociationConfig{
				Authentication:      SocketOptionEnable,
				AuthenticatedChunks: []uint8{0, 0},
			},
			want: "duplicate",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := preparePreAssociationConfig(tc.cfg, tc.style)
			if err == nil {
				t.Fatal("prepare unexpectedly succeeded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestPreparePreAssociationEndpointInterleavingUsesRFCDefault(t *testing.T) {
	t.Parallel()

	prepared, err := preparePreAssociationConfig(PreAssociationConfig{
		MessageInterleaving: SocketOptionEnable,
	}, preAssociationOneToMany)
	if err != nil {
		t.Fatalf("prepare endpoint interleaving: %v", err)
	}
	want := []preAssociationOperation{
		{kind: preAssociationReceiveRcvInfo, value: 1},
		{kind: preAssociationFragmentInterleave, value: SCTPFragmentInterleaveOther},
		{kind: preAssociationMessageInterleaving, value: 1},
	}
	if !reflect.DeepEqual(prepared.operations, want) {
		t.Fatalf("operations = %+v, want %+v", prepared.operations, want)
	}
}

func TestPreparePreAssociationEndpointLevelTwoEnablesRcvInfoFirst(t *testing.T) {
	t.Parallel()

	prepared, err := preparePreAssociationConfig(PreAssociationConfig{
		FragmentInterleave: OptionalInt{
			Set: true, Value: SCTPFragmentInterleaveStreams,
		},
	}, preAssociationOneToMany)
	if err != nil {
		t.Fatalf("prepare endpoint level 2: %v", err)
	}
	want := []preAssociationOperation{
		{kind: preAssociationReceiveRcvInfo, value: 1},
		{kind: preAssociationFragmentInterleave, value: SCTPFragmentInterleaveStreams},
	}
	if !reflect.DeepEqual(prepared.operations, want) {
		t.Fatalf("operations = %+v, want RCVINFO before fragment level 2: %+v",
			prepared.operations, want)
	}
}

func TestPreparePreAssociationLevelTwoAcceptsDataIOEventFirst(t *testing.T) {
	t.Parallel()

	prepared, err := preparePreAssociationConfig(PreAssociationConfig{
		FragmentInterleave: OptionalInt{
			Set: true, Value: SCTPFragmentInterleaveStreams,
		},
		Notifications: []NotificationSubscription{{
			Type: SCTP_DATA_IO_EVENT, State: SocketOptionEnable,
		}},
	}, preAssociationOneToOne)
	if err != nil {
		t.Fatalf("prepare one-to-one level 2 with data-I/O metadata: %v", err)
	}
	want := []preAssociationOperation{
		{kind: preAssociationNotification, value: 1, notificationType: SCTP_DATA_IO_EVENT},
		{kind: preAssociationFragmentInterleave, value: SCTPFragmentInterleaveStreams},
	}
	if !reflect.DeepEqual(prepared.operations, want) {
		t.Fatalf("operations = %+v, want data-I/O event before fragment level 2: %+v",
			prepared.operations, want)
	}
}

func TestPreparePreAssociationDelayedSACKBoundaries(t *testing.T) {
	t.Parallel()

	for _, timer := range []DelayedSACKConfig{
		{},
		{Delay: 200, Frequency: 2},
		{Delay: 201, Frequency: 3}, // Explicit, permitted departure from SHOULD.
		{Delay: 500, Frequency: ^uint32(0)},
	} {
		timer := timer
		prepared, err := preparePreAssociationConfig(PreAssociationConfig{
			DelayedSACK: &timer,
		}, preAssociationOneToOne)
		if err != nil {
			t.Fatalf("prepare delayed SACK %+v: %v", timer, err)
		}
		want := []preAssociationOperation{{
			kind:           preAssociationDelayedSACK,
			value:          timer.Delay,
			secondaryValue: timer.Frequency,
		}}
		if !reflect.DeepEqual(prepared.operations, want) {
			t.Fatalf("delayed SACK %+v operations = %+v, want %+v",
				timer, prepared.operations, want)
		}
	}
}

func TestPreparePreAssociationRTOInfoBoundaries(t *testing.T) {
	t.Parallel()

	for _, info := range []RtoInfo{
		{},
		{AssocID: SCTPAssocID(SCTP_FUTURE_ASSOC), Initial: 1, Max: 2, Min: 3},
		{AssocID: SCTPAssocID(SCTP_FUTURE_ASSOC), Initial: ^uint32(0), Max: ^uint32(0), Min: ^uint32(0)},
	} {
		info := info
		prepared, err := preparePreAssociationConfig(PreAssociationConfig{
			RTOInfo: &info,
		}, preAssociationOneToOne)
		if err != nil {
			t.Fatalf("prepare RTOInfo %+v: %v", info, err)
		}
		wantInfo := info
		wantInfo.AssocID = SCTPAssocID(SCTP_FUTURE_ASSOC)
		want := []preAssociationOperation{{
			kind:    preAssociationRTOInfo,
			rtoInfo: wantInfo,
		}}
		if !reflect.DeepEqual(prepared.operations, want) {
			t.Fatalf("RTOInfo %+v operations = %+v, want %+v",
				info, prepared.operations, want)
		}
	}
}

func TestSetSackTimerPrevalidatesProtocolMaximum(t *testing.T) {
	t.Parallel()

	var conn *SCTPConn
	if err := conn.SetSackTimer(nil); err == nil {
		t.Fatal("SetSackTimer accepted nil")
	}
	if err := conn.SetSackTimer(&SackTimer{SackDelay: 501}); err == nil {
		t.Fatal("SetSackTimer accepted RFC-forbidden 501 ms delay")
	}
}

func TestPreparePreAssociationSnapshotsSlices(t *testing.T) {
	t.Parallel()

	cfg := PreAssociationConfig{
		Authentication:      SocketOptionEnable,
		HMACIdentifiers:     []uint16{SCTPAuthHmacIDSHA256, SCTPAuthHmacIDSHA1},
		AuthenticatedChunks: []uint8{0},
		Notifications: []NotificationSubscription{{
			Type: SCTP_ASSOC_CHANGE, State: SocketOptionEnable,
		}},
		DelayedSACK: &DelayedSACKConfig{Delay: 321, Frequency: 7},
		RTOInfo:     &RtoInfo{Initial: 321, Max: 4321, Min: 123},
	}
	prepared, err := preparePreAssociationConfig(cfg, preAssociationOneToOne)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	cfg.HMACIdentifiers[0] = 2
	cfg.AuthenticatedChunks[0] = 1
	cfg.Notifications[0] = NotificationSubscription{
		Type: SCTP_SENDER_DRY_EVENT, State: SocketOptionDisable,
	}
	cfg.DelayedSACK.Delay = 500
	cfg.DelayedSACK.Frequency = 2
	cfg.RTOInfo.Initial = 999
	cfg.RTOInfo.Max = 999
	cfg.RTOInfo.Min = 999

	want := []preAssociationOperation{
		{kind: preAssociationAuthentication, value: 1},
		{kind: preAssociationHMACIdentifiers, hmacIdentifiers: []uint16{SCTPAuthHmacIDSHA256, SCTPAuthHmacIDSHA1}},
		{kind: preAssociationAuthenticatedChunk, value: 0},
		{kind: preAssociationRTOInfo, rtoInfo: RtoInfo{
			AssocID: SCTPAssocID(SCTP_FUTURE_ASSOC),
			Initial: 321,
			Max:     4321,
			Min:     123,
		}},
		{kind: preAssociationDelayedSACK, value: 321, secondaryValue: 7},
		{kind: preAssociationNotification, value: 1, notificationType: SCTP_ASSOC_CHANGE},
	}
	if !reflect.DeepEqual(prepared.operations, want) {
		t.Fatalf("prepared plan changed after source mutation:\n got: %+v\nwant: %+v",
			prepared.operations, want)
	}
}

func TestNilSocketConfigMethodsDoNotPanic(t *testing.T) {
	t.Parallel()

	var cfg *SocketConfig
	calls := []struct {
		name string
		call func() error
	}{
		{"Listen", func() error {
			_, err := cfg.Listen("not-sctp", nil)
			return err
		}},
		{"Dial", func() error {
			_, err := cfg.Dial("not-sctp", nil, nil)
			return err
		}},
		{"DialContext", func() error {
			_, err := cfg.DialContext(context.Background(), "not-sctp", nil, nil)
			return err
		}},
		{"OpenEndpoint", func() error {
			_, err := cfg.OpenEndpoint("not-sctp", nil)
			return err
		}},
		{"ListenEndpoint", func() error {
			_, err := cfg.ListenEndpoint("not-sctp", nil)
			return err
		}},
	}

	for _, tc := range calls {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.call(); err == nil {
				t.Fatal("nil *SocketConfig call unexpectedly succeeded")
			}
		})
	}
}

func FuzzPreparePreAssociationConfig(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3, 0xff})
	f.Add([]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 7, 1, 2})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 4096 {
			t.Skip()
		}
		at := func(i int) byte {
			if i >= len(data) {
				return 0
			}
			return data[i]
		}
		state := func(i int) SocketOptionState { return SocketOptionState(at(i) & 3) }
		cfg := PreAssociationConfig{
			PartialReliability:            state(0),
			StreamReconfiguration:         state(1),
			DynamicAddressReconfiguration: state(2),
			Authentication:                state(3),
			MessageInterleaving:           state(4),
			ExperimentalECN:               state(5),
			ReusePort:                     state(6),
			MappedV4Address:               state(7),
			DisableFragments:              state(8),
			ReceiveRcvInfo:                state(9),
			ReceiveNxtInfo:                state(10),
			AdaptationLayer: OptionalUint32{
				Set: at(11)&1 != 0, Value: uint32(at(12)),
			},
			FragmentInterleave: OptionalInt{
				Set: at(13)&1 != 0, Value: int(int8(at(14))),
			},
			StreamResetMask: OptionalUint32{
				Set: at(15)&1 != 0, Value: uint32(at(16)),
			},
		}
		if at(17)&1 != 0 {
			cfg.DelayedSACK = &DelayedSACKConfig{
				Delay:     uint32(at(18))<<8 | uint32(at(19)),
				Frequency: uint32(at(20)),
			}
		}
		if at(21)&1 != 0 {
			cfg.RTOInfo = &RtoInfo{
				AssocID: SCTPAssocID(int32(at(22) % 4)),
				Initial: uint32(at(23))<<8 | uint32(at(24)),
				Max:     uint32(at(25))<<8 | uint32(at(26)),
				Min:     uint32(at(27))<<8 | uint32(at(28)),
			}
		}
		for i := 29; i+1 < len(data) && len(cfg.Notifications) < 64; i += 2 {
			cfg.Notifications = append(cfg.Notifications, NotificationSubscription{
				Type:  SCTPNotificationType(uint16(data[i])<<8 | uint16(data[i+1])),
				State: state(i),
			})
		}

		style := preAssociationSocketStyle(at(0) & 1)
		first, firstErr := preparePreAssociationConfig(cfg, style)
		second, secondErr := preparePreAssociationConfig(cfg, style)
		if (firstErr == nil) != (secondErr == nil) {
			t.Fatalf("same input changed success: first=%v second=%v", firstErr, secondErr)
		}
		if firstErr != nil {
			if firstErr.Error() != secondErr.Error() {
				t.Fatalf("same input changed error: first=%q second=%q", firstErr, secondErr)
			}
			return
		}
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("same input changed plan:\nfirst=%+v\nsecond=%+v", first, second)
		}
	})
}
