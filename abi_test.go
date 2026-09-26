// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"math/bits"
	"runtime"
	"testing"
	"unsafe"
)

// numberCase is one named constant checked against a number written out by
// hand from the kernel header, not computed from any other constant in this
// package.
type numberCase struct {
	name string
	got  int
	want int
}

func checkNumbers(t *testing.T, cases []numberCase) {
	t.Helper()
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// TestAddressFamilies pins afInet and afInet6 against
// include/linux/socket.h, v6.12, lines 193 and 201.
func TestAddressFamilies(t *testing.T) {
	checkNumbers(t, []numberCase{
		{"afInet", afInet, 2},
		{"afInet6", afInet6, 10},
	})
}

// TestAssocScopeSelectors pins the reserved sctp_assoc_t scope selectors
// against include/uapi/linux/sctp.h, v6.12, lines 62-64. Ledger:
// TestAssocIDAndSinfoConstantsMatchHeader's SCTP_FUTURE_ASSOC/
// SCTP_CURRENT_ASSOC/SCTP_ALL_ASSOC rows (git show
// main:sctp_extensions_test.go) -> ported -> TestAssocScopeSelectors; its
// SCTP_NOTIFICATION == MSG_NOTIFICATION row has no v2 counterpart: abi.go
// keeps that identity as a single constant (msgNotification), not two
// names that could drift apart.
func TestAssocScopeSelectors(t *testing.T) {
	checkNumbers(t, []numberCase{
		{"assocScopeFuture", assocScopeFuture, 0},
		{"assocScopeCurrent", assocScopeCurrent, 1},
		{"assocScopeAll", assocScopeAll, 2},
	})
}

// TestOptionNumbers pins every getsockopt/setsockopt option number against
// include/uapi/linux/sctp.h, v6.12, lines 69-108 (the primary block, 0-37)
// and 113-144 (the "internal options" block, 100+).
func TestOptionNumbers(t *testing.T) {
	checkNumbers(t, []numberCase{
		{"optRTOInfo", optRTOInfo, 0},
		{"optAssocInfo", optAssocInfo, 1},
		{"optInitMsg", optInitMsg, 2},
		{"optNoDelay", optNoDelay, 3},
		{"optAutoClose", optAutoClose, 4},
		{"optSetPeerPrimaryAddr", optSetPeerPrimaryAddr, 5},
		{"optPrimaryAddr", optPrimaryAddr, 6},
		{"optAdaptationLayer", optAdaptationLayer, 7},
		{"optDisableFragments", optDisableFragments, 8},
		{"optPeerAddrParams", optPeerAddrParams, 9},
		{"optWantMappedV4Addr", optWantMappedV4Addr, 12},
		{"optMaxSeg", optMaxSeg, 13},
		{"optStatus", optStatus, 14},
		{"optGetPeerAddrInfo", optGetPeerAddrInfo, 15},
		{"optDelayedAckTime", optDelayedAckTime, 16},
		{"optContext", optContext, 17},
		{"optFragmentInterleave", optFragmentInterleave, 18},
		{"optPartialDeliveryPoint", optPartialDeliveryPoint, 19},
		{"optMaxBurst", optMaxBurst, 20},
		{"optAuthChunk", optAuthChunk, 21},
		{"optHMACIdent", optHMACIdent, 22},
		{"optAuthKey", optAuthKey, 23},
		{"optAuthActiveKey", optAuthActiveKey, 24},
		{"optAuthDeleteKey", optAuthDeleteKey, 25},
		{"optPeerAuthChunks", optPeerAuthChunks, 26},
		{"optLocalAuthChunks", optLocalAuthChunks, 27},
		{"optGetAssocNumber", optGetAssocNumber, 28},
		{"optGetAssocIDList", optGetAssocIDList, 29},
		{"optAutoAsconf", optAutoAsconf, 30},
		{"optRecvRcvInfo", optRecvRcvInfo, 32},
		{"optRecvNxtInfo", optRecvNxtInfo, 33},
		{"optDefaultSndInfo", optDefaultSndInfo, 34},
		{"optAuthDeactivateKey", optAuthDeactivateKey, 35},
		{"optReusePort", optReusePort, 36},
		{"optPathThresholds", optPathThresholds, 37},           // SCTP_PEER_ADDR_THLDS_V2
		{"optPathThresholdsProbe", optPathThresholdsProbe, 31}, // SCTP_PEER_ADDR_THLDS

		{"optSockoptBindxAdd", optSockoptBindxAdd, 100},
		{"optSockoptBindxRemove", optSockoptBindxRemove, 101},
		{"optGetPeerAddrs", optGetPeerAddrs, 108},
		{"optGetLocalAddrs", optGetLocalAddrs, 109},
		{"optSockoptConnectx3", optSockoptConnectx3, 111},
		{"optGetAssocStats", optGetAssocStats, 112},
		{"optPRSupported", optPRSupported, 113},
		{"optDefaultPRInfo", optDefaultPRInfo, 114},
		{"optPRAssocStatus", optPRAssocStatus, 115},
		{"optPRStreamStatus", optPRStreamStatus, 116},
		{"optReconfigSupported", optReconfigSupported, 117},
		{"optEnableStreamReset", optEnableStreamReset, 118},
		{"optResetStreams", optResetStreams, 119},
		{"optResetAssoc", optResetAssoc, 120},
		{"optAddStreams", optAddStreams, 121},
		{"optSockoptPeeloffFlags", optSockoptPeeloffFlags, 122},
		{"optStreamScheduler", optStreamScheduler, 123},
		{"optStreamSchedulerValue", optStreamSchedulerValue, 124},
		{"optInterleavingSupported", optInterleavingSupported, 125},
		{"optEvent", optEvent, 127},
		{"optASCONFSupported", optASCONFSupported, 128},
		{"optAuthSupported", optAuthSupported, 129},
		{"optECNSupported", optECNSupported, 130},
		{"optExposePotentiallyFailedState", optExposePotentiallyFailedState, 131},
		{"optRemoteUDPEncapsPort", optRemoteUDPEncapsPort, 132},
		{"optPLPMTUDProbeInterval", optPLPMTUDProbeInterval, 133},
	})
}

// TestCmsgTypes pins the cmsg_type values this package uses against
// include/uapi/linux/sctp.h, v6.12, lines 329-348 (typedef enum
// sctp_cmsg_type, a plain 0-based sequence: SCTP_SNDINFO is 2, not 0, since
// SCTP_INIT and the deprecated SCTP_SNDRCV precede it and this package does
// not define constants for either).
func TestCmsgTypes(t *testing.T) {
	checkNumbers(t, []numberCase{
		{"cmsgSndInfo", cmsgSndInfo, 2},
		{"cmsgRcvInfo", cmsgRcvInfo, 3},
		{"cmsgNxtInfo", cmsgNxtInfo, 4},
		{"cmsgPrInfo", cmsgPrInfo, 5},
		{"cmsgAuthInfo", cmsgAuthInfo, 6},
	})
}

// TestSendFlagBits pins the raw kernel send-flag bits against
// include/uapi/linux/sctp.h, v6.12, lines 310-320 (enum sctp_sinfo_flags)
// and 146-152 (SCTP_PR_SCTP_MASK), and sndFlagEOF against
// include/linux/socket.h, v6.12, line 314 (MSG_FIN, which SCTP_EOF
// aliases). Ledger: the value-pinning half of TestSendFlagsMatchTheKernel
// (git show main:sctp_options_test.go) -> split and ported ->
// TestSendFlagBits + TestPRPolicyBitsDoNotOverlapSendFlags, below.
func TestSendFlagBits(t *testing.T) {
	checkNumbers(t, []numberCase{
		{"sndFlagUnordered", sndFlagUnordered, 0x1},
		{"sndFlagAddrOver", sndFlagAddrOver, 0x2},
		{"sndFlagAbort", sndFlagAbort, 0x4},
		{"sndFlagSackImmediately", sndFlagSackImmediately, 0x8},
		{"sndFlagPRAll", sndFlagPRAll, 0x80},
		{"msgNotification", msgNotification, 0x8000},
		{"sndFlagEOF", sndFlagEOF, 0x200},
		{"prPolicyMask", prPolicyMask, 0x30},
	})
}

// TestPRPolicyBitsDoNotOverlapSendFlags ports the second half of v1's
// TestSendFlagsMatchTheKernel and the overlap checks of
// TestAssocIDAndSinfoConstantsMatchHeader (git show
// main:sctp_options_test.go and sctp_extensions_test.go): every raw
// send-flag bit and PRPolicy value must stay clear of the other's bits,
// since Linux packs both into the same 16-bit snd_flags/sinfo_flags word
// (SCTP_PR_SCTP_MASK, include/uapi/linux/sctp.h lines 146-152), and none of
// them may collide with msgNotification (0x8000), the same word's
// SCTP_NOTIFICATION/MSG_NOTIFICATION bit. SCTP_PR_POLICY masks the policy
// bits out with prPolicyMask. The first half — pinning each flag's numeric
// value — is TestSendFlagBits, above. Ledger: TestSendFlagsMatchTheKernel
// -> split and ported -> TestSendFlagBits + this test;
// TestAssocIDAndSinfoConstantsMatchHeader's overlap-with-SCTP_NOTIFICATION
// loop -> folded into this test's msgNotification check.
func TestPRPolicyBitsDoNotOverlapSendFlags(t *testing.T) {
	flags := []numberCase{
		{"sndFlagUnordered", sndFlagUnordered, sndFlagUnordered},
		{"sndFlagAddrOver", sndFlagAddrOver, sndFlagAddrOver},
		{"sndFlagAbort", sndFlagAbort, sndFlagAbort},
		{"sndFlagSackImmediately", sndFlagSackImmediately, sndFlagSackImmediately},
		{"sndFlagPRAll", sndFlagPRAll, sndFlagPRAll},
		{"sndFlagEOF", sndFlagEOF, sndFlagEOF},
	}
	for _, f := range flags {
		if f.got&prPolicyMask != 0 {
			t.Errorf("%s (%#x) overlaps prPolicyMask (%#x); setting it would "+
				"also select a partial reliability policy", f.name, f.got, prPolicyMask)
		}
		if f.got&msgNotification != 0 {
			t.Errorf("%s (%#x) overlaps msgNotification (%#x) in the same flags word",
				f.name, f.got, msgNotification)
		}
	}
	for _, p := range []PRPolicy{PRNone, PRTTL, PRRtx, PRPrio} {
		if int(p)&^prPolicyMask != 0 {
			t.Errorf("PRPolicy %s (%#x) has bits outside prPolicyMask (%#x)",
				p, uint16(p), prPolicyMask)
		}
	}
}

// TestPathParamsFlagBits pins spp_flags' bits against
// include/uapi/linux/sctp.h, v6.12, lines 791-803 (enum sctp_spp_flags).
// A bit swapped between two switches would round-trip through the kernel
// unnoticed and change the wrong setting.
func TestPathParamsFlagBits(t *testing.T) {
	checkNumbers(t, []numberCase{
		{"sppHBEnable", sppHBEnable, 0x001},
		{"sppHBDisable", sppHBDisable, 0x002},
		{"sppHBDemand", sppHBDemand, 0x004},
		{"sppPMTUDEnable", sppPMTUDEnable, 0x008},
		{"sppPMTUDDisable", sppPMTUDDisable, 0x010},
		{"sppSACKDelayEnable", sppSACKDelayEnable, 0x020},
		{"sppSACKDelayDisable", sppSACKDelayDisable, 0x040},
		{"sppHBTimeIsZero", sppHBTimeIsZero, 0x080},
		{"sppIPv6FlowLabel", sppIPv6FlowLabel, 0x100},
		{"sppDSCP", sppDSCP, 0x200},
	})
}

// TestKernelLimits pins the kernel limits the option methods check before
// any system call: include/linux/sctp.h, v6.12, lines 800 and 802
// (SCTP_DSCP_VAL_MASK, SCTP_FLOWLABEL_VAL_MASK), include/net/sctp/
// constants.h, v6.12, lines 297 and 443 (SCTP_DEFAULT_MINSEGMENT,
// SCTP_PROBE_TIMER_MIN), the 500 ms net/sctp/socket.c compares SACK delays
// with, and the two reply bounds derived in abi.go.
func TestKernelLimits(t *testing.T) {
	checkNumbers(t, []numberCase{
		{"dscpMask", dscpMask, 0xfc},
		{"flowLabelMask", flowLabelMask, 0xfffff},
		{"minPathMTU", minPathMTU, 512},
		{"maxSACKDelayMS", maxSACKDelayMS, 500},
		{"minProbeIntervalMS", minProbeIntervalMS, 5000},
		{"maxHMACIdents", maxHMACIdents, 16},
		{"maxAuthChunkList", maxAuthChunkList, 256},
		{"sizeAssocID", sizeAssocID, 4},
	})
}

// TestAssocStatsCounterOrder pins the order of struct sctp_assoc_stats'
// counters, include/uapi/linux/sctp.h, v6.12, lines 1044-1058: each
// counter's index times 8 is its offset after the header.
func TestAssocStatsCounterOrder(t *testing.T) {
	checkNumbers(t, []numberCase{
		{"assocStatsMaxRTO", assocStatsMaxRTO, 0},
		{"assocStatsISACKs", assocStatsISACKs, 1},
		{"assocStatsOSACKs", assocStatsOSACKs, 2},
		{"assocStatsOPackets", assocStatsOPackets, 3},
		{"assocStatsIPackets", assocStatsIPackets, 4},
		{"assocStatsRtxChunks", assocStatsRtxChunks, 5},
		{"assocStatsOutOfSeqTSNs", assocStatsOutOfSeqTSNs, 6},
		{"assocStatsIDupChunks", assocStatsIDupChunks, 7},
		{"assocStatsGapCount", assocStatsGapCount, 8},
		{"assocStatsOUODChunks", assocStatsOUODChunks, 9},
		{"assocStatsIUODChunks", assocStatsIUODChunks, 10},
		{"assocStatsOODChunks", assocStatsOODChunks, 11},
		{"assocStatsIODChunks", assocStatsIODChunks, 12},
		{"assocStatsOCtrlChunks", assocStatsOCtrlChunks, 13},
		{"assocStatsICtrlChunks", assocStatsICtrlChunks, 14},
		{"assocStatsCounters", assocStatsCounters, 15},
		{"sizeAssocStats - sizeAssocStatsHeader", sizeAssocStats - sizeAssocStatsHeader, 8 * assocStatsCounters},
	})
}

// TestSockaddrLayouts pins sockaddr_in (include/uapi/linux/in.h, v6.12, from
// line 258) and sockaddr_in6 (include/uapi/linux/in6.h, v6.12, from line
// 50), fetched at tag v6.12 since neither header is in the flattened kernel
// source set.
func TestSockaddrLayouts(t *testing.T) {
	checkNumbers(t, []numberCase{
		{"sizeSockaddrIn", sizeSockaddrIn, 16},
		{"sockaddrInFamilyOff", sockaddrInFamilyOff, 0},
		{"sockaddrInPortOff", sockaddrInPortOff, 2},
		{"sockaddrInAddrOff", sockaddrInAddrOff, 4},

		{"sizeSockaddrIn6", sizeSockaddrIn6, 28},
		{"sockaddrIn6FamilyOff", sockaddrIn6FamilyOff, 0},
		{"sockaddrIn6PortOff", sockaddrIn6PortOff, 2},
		{"sockaddrIn6FlowInfoOff", sockaddrIn6FlowInfoOff, 4},
		{"sockaddrIn6AddrOff", sockaddrIn6AddrOff, 8},
		{"sockaddrIn6ScopeIDOff", sockaddrIn6ScopeIDOff, 24},

		{"sizeSockaddrStorage", sizeSockaddrStorage, 128},
	})
}

// TestCmsgStructLayouts pins struct sctp_sndinfo (include/uapi/linux/sctp.h
// lines 232-238), struct sctp_prinfo (287-290), struct sctp_authinfo
// (300-302), struct sctp_rcvinfo (249-258) and struct sctp_nxtinfo
// (271-277). Ledger: portions of TestStructLayoutsMatchKernel/RcvInfo and
// /SndInfo (git show main:sctp_layout_test.go) -> ported ->
// TestCmsgStructLayouts.
func TestCmsgStructLayouts(t *testing.T) {
	checkNumbers(t, []numberCase{
		{"sizeSndInfo", sizeSndInfo, 16},
		{"sndInfoStreamOff", sndInfoStreamOff, 0},
		{"sndInfoFlagsOff", sndInfoFlagsOff, 2},
		{"sndInfoPPIDOff", sndInfoPPIDOff, 4},
		{"sndInfoContextOff", sndInfoContextOff, 8},
		{"sndInfoAssocIDOff", sndInfoAssocIDOff, 12},

		{"sizePrInfo", sizePrInfo, 8},
		{"prInfoPolicyOff", prInfoPolicyOff, 0},
		{"prInfoValueOff", prInfoValueOff, 4},

		{"sizeAuthInfo", sizeAuthInfo, 2},
		{"authInfoKeyNumberOff", authInfoKeyNumberOff, 0},

		{"sizeRcvInfo", sizeRcvInfo, 28},
		{"rcvInfoStreamOff", rcvInfoStreamOff, 0},
		{"rcvInfoSSNOff", rcvInfoSSNOff, 2},
		{"rcvInfoFlagsOff", rcvInfoFlagsOff, 4},
		{"rcvInfoPPIDOff", rcvInfoPPIDOff, 8},
		{"rcvInfoTSNOff", rcvInfoTSNOff, 12},
		{"rcvInfoCumTSNOff", rcvInfoCumTSNOff, 16},
		{"rcvInfoContextOff", rcvInfoContextOff, 20},
		{"rcvInfoAssocIDOff", rcvInfoAssocIDOff, 24},

		{"sizeNxtInfo", sizeNxtInfo, 16},
		{"nxtInfoStreamOff", nxtInfoStreamOff, 0},
		{"nxtInfoFlagsOff", nxtInfoFlagsOff, 2},
		{"nxtInfoPPIDOff", nxtInfoPPIDOff, 4},
		{"nxtInfoLengthOff", nxtInfoLengthOff, 8},
		{"nxtInfoAssocIDOff", nxtInfoAssocIDOff, 12},
	})
}

// TestNotificationStructLayouts pins the twelve notification structs this
// package decodes (include/uapi/linux/sctp.h §§5.3.1.1-5.3.1.9, the line
// ranges cited on each case below) plus struct sctp_send_failed_event
// (§5.3.1.4's modern form). The legacy struct sctp_send_failed (also
// §5.3.1.4, __SCTP_SNDRCV-based) is not decoded — SendFailedEvent (RFC
// 6458 §6.1.11) replaces it. Ledger:
// TestPeerAddrChangeDecoding and related v1 notification-decoding tests
// (git show main:sctp_notification_test.go) exercised these same offsets
// indirectly; the notification decoder that replaces them keeps that
// behaviour, so no v1 row is retired by this one — this test only pins the
// raw layout abi.go now owns.
func TestNotificationStructLayouts(t *testing.T) {
	checkNumbers(t, []numberCase{
		// struct sctp_assoc_change, lines 359-369.
		{"sizeAssocChange", sizeAssocChange, 20},
		{"assocChangeTypeOff", assocChangeTypeOff, 0},
		{"assocChangeFlagsOff", assocChangeFlagsOff, 2},
		{"assocChangeLengthOff", assocChangeLengthOff, 4},
		{"assocChangeStateOff", assocChangeStateOff, 8},
		{"assocChangeErrorOff", assocChangeErrorOff, 10},
		{"assocChangeOutStreamsOff", assocChangeOutStreamsOff, 12},
		{"assocChangeInStreamsOff", assocChangeInStreamsOff, 14},
		{"assocChangeAssocIDOff", assocChangeAssocIDOff, 16},
		{"assocChangeInfoOff", assocChangeInfoOff, 20},

		// struct sctp_paddr_change, lines 395-403 (packed, aligned(4)).
		{"sizePAddrChange", sizePAddrChange, 148},
		{"paddrChangeTypeOff", paddrChangeTypeOff, 0},
		{"paddrChangeFlagsOff", paddrChangeFlagsOff, 2},
		{"paddrChangeLengthOff", paddrChangeLengthOff, 4},
		{"paddrChangeAddrOff", paddrChangeAddrOff, 8},
		{"paddrChangeStateOff", paddrChangeStateOff, 136},
		{"paddrChangeErrorOff", paddrChangeErrorOff, 140},
		{"paddrChangeAssocIDOff", paddrChangeAssocIDOff, 144},

		// struct sctp_remote_error, lines 433-440.
		{"sizeRemoteError", sizeRemoteError, 16},
		{"remoteErrorTypeOff", remoteErrorTypeOff, 0},
		{"remoteErrorFlagsOff", remoteErrorFlagsOff, 2},
		{"remoteErrorLengthOff", remoteErrorLengthOff, 4},
		{"remoteErrorErrorOff", remoteErrorErrorOff, 8},
		{"remoteErrorAssocIDOff", remoteErrorAssocIDOff, 12},
		{"remoteErrorDataOff", remoteErrorDataOff, 16},

		// struct sctp_shutdown_event, lines 492-497.
		{"sizeShutdownEvent", sizeShutdownEvent, 12},
		{"shutdownEventTypeOff", shutdownEventTypeOff, 0},
		{"shutdownEventFlagsOff", shutdownEventFlagsOff, 2},
		{"shutdownEventLengthOff", shutdownEventLengthOff, 4},
		{"shutdownEventAssocIDOff", shutdownEventAssocIDOff, 8},

		// struct sctp_adaptation_event, lines 506-512.
		{"sizeAdaptationEvent", sizeAdaptationEvent, 16},
		{"adaptationEventTypeOff", adaptationEventTypeOff, 0},
		{"adaptationEventFlagsOff", adaptationEventFlagsOff, 2},
		{"adaptationEventLengthOff", adaptationEventLengthOff, 4},
		{"adaptationEventIndicationOff", adaptationEventIndicationOff, 8},
		{"adaptationEventAssocIDOff", adaptationEventAssocIDOff, 12},

		// struct sctp_pdapi_event, lines 521-529. The association id
		// precedes the stream and sequence fields.
		{"sizePDAPIEvent", sizePDAPIEvent, 24},
		{"pdapiEventTypeOff", pdapiEventTypeOff, 0},
		{"pdapiEventFlagsOff", pdapiEventFlagsOff, 2},
		{"pdapiEventLengthOff", pdapiEventLengthOff, 4},
		{"pdapiEventIndicationOff", pdapiEventIndicationOff, 8},
		{"pdapiEventAssocIDOff", pdapiEventAssocIDOff, 12},
		{"pdapiEventStreamOff", pdapiEventStreamOff, 16},
		{"pdapiEventSeqOff", pdapiEventSeqOff, 20},

		// struct sctp_authkey_event, lines 539-547.
		{"sizeAuthKeyEvent", sizeAuthKeyEvent, 20},
		{"authKeyEventTypeOff", authKeyEventTypeOff, 0},
		{"authKeyEventFlagsOff", authKeyEventFlagsOff, 2},
		{"authKeyEventLengthOff", authKeyEventLengthOff, 4},
		{"authKeyEventKeyNumberOff", authKeyEventKeyNumberOff, 8},
		{"authKeyEventAltKeyNumberOff", authKeyEventAltKeyNumberOff, 10},
		{"authKeyEventIndicationOff", authKeyEventIndicationOff, 12},
		{"authKeyEventAssocIDOff", authKeyEventAssocIDOff, 16},

		// struct sctp_sender_dry_event, lines 564-569.
		{"sizeSenderDryEvent", sizeSenderDryEvent, 12},
		{"senderDryEventTypeOff", senderDryEventTypeOff, 0},
		{"senderDryEventFlagsOff", senderDryEventFlagsOff, 2},
		{"senderDryEventLengthOff", senderDryEventLengthOff, 4},
		{"senderDryEventAssocIDOff", senderDryEventAssocIDOff, 8},

		// struct sctp_stream_reset_event, lines 575-581.
		{"sizeStreamResetEvent", sizeStreamResetEvent, 12},
		{"streamResetEventTypeOff", streamResetEventTypeOff, 0},
		{"streamResetEventFlagsOff", streamResetEventFlagsOff, 2},
		{"streamResetEventLengthOff", streamResetEventLengthOff, 4},
		{"streamResetEventAssocIDOff", streamResetEventAssocIDOff, 8},
		{"streamResetEventStreamsOff", streamResetEventStreamsOff, 12},

		// struct sctp_assoc_reset_event, lines 585-592.
		{"sizeAssocResetEvent", sizeAssocResetEvent, 20},
		{"assocResetEventTypeOff", assocResetEventTypeOff, 0},
		{"assocResetEventFlagsOff", assocResetEventFlagsOff, 2},
		{"assocResetEventLengthOff", assocResetEventLengthOff, 4},
		{"assocResetEventAssocIDOff", assocResetEventAssocIDOff, 8},
		{"assocResetEventLocalTSNOff", assocResetEventLocalTSNOff, 12},
		{"assocResetEventRemoteTSNOff", assocResetEventRemoteTSNOff, 16},

		// struct sctp_stream_change_event, lines 598-605.
		{"sizeStreamChangeEvent", sizeStreamChangeEvent, 16},
		{"streamChangeEventTypeOff", streamChangeEventTypeOff, 0},
		{"streamChangeEventFlagsOff", streamChangeEventFlagsOff, 2},
		{"streamChangeEventLengthOff", streamChangeEventLengthOff, 4},
		{"streamChangeEventAssocIDOff", streamChangeEventAssocIDOff, 8},
		{"streamChangeEventInStreamsOff", streamChangeEventInStreamsOff, 12},
		{"streamChangeEventOutStreamsOff", streamChangeEventOutStreamsOff, 14},

		// struct sctp_send_failed_event, lines 459-467.
		{"sizeSendFailedEvent", sizeSendFailedEvent, 32},
		{"sendFailedEventTypeOff", sendFailedEventTypeOff, 0},
		{"sendFailedEventFlagsOff", sendFailedEventFlagsOff, 2},
		{"sendFailedEventLengthOff", sendFailedEventLengthOff, 4},
		{"sendFailedEventErrorOff", sendFailedEventErrorOff, 8},
		{"sendFailedEventInfoOff", sendFailedEventInfoOff, 12},
		{"sendFailedEventAssocIDOff", sendFailedEventAssocIDOff, 28},
		{"sendFailedEventDataOff", sendFailedEventDataOff, 32},
	})
}

// TestOptionStructLayouts pins the option-value structs whose layout does
// not depend on word size. Ledger: TestStructLayoutsMatchKernel's
// PeerAddrinfo, RtoInfo, AssocInfo, InitMsg, AssocValue, SndInfo,
// EventSubscribe, RcvInfo, Event, DefaultPrInfo, PrStatus, AddStreamsReq,
// PrInfo, AuthInfo and AuthKeyID subtests (git show
// main:sctp_layout_test.go) -> ported -> TestOptionStructLayouts and
// TestCmsgStructLayouts (the five cmsg structs); EventSubscribe -> retired:
// this package does not implement SCTP_EVENTS, the deprecated RFC 6458
// mechanism it configures, so it has no v2 counterpart.
func TestOptionStructLayouts(t *testing.T) {
	checkNumbers(t, []numberCase{
		// struct sctp_initmsg, lines 195-200.
		{"sizeInitMsg", sizeInitMsg, 8},
		{"initMsgOutStreamsOff", initMsgOutStreamsOff, 0},
		{"initMsgMaxInStreamsOff", initMsgMaxInStreamsOff, 2},
		{"initMsgMaxAttemptsOff", initMsgMaxAttemptsOff, 4},
		{"initMsgMaxInitTimeoOff", initMsgMaxInitTimeoOff, 6},

		// struct sctp_rtoinfo, lines 719-724.
		{"sizeRTOInfo", sizeRTOInfo, 16},
		{"rtoInfoAssocIDOff", rtoInfoAssocIDOff, 0},
		{"rtoInfoInitialOff", rtoInfoInitialOff, 4},
		{"rtoInfoMaxOff", rtoInfoMaxOff, 8},
		{"rtoInfoMinOff", rtoInfoMinOff, 12},

		// struct sctp_assocparams, lines 732-739.
		{"sizeAssocInfo", sizeAssocInfo, 20},
		{"assocInfoAssocIDOff", assocInfoAssocIDOff, 0},
		{"assocInfoMaxRetransOff", assocInfoMaxRetransOff, 4},
		{"assocInfoPeerDestinationsOff", assocInfoPeerDestinationsOff, 6},
		{"assocInfoPeerRwndOff", assocInfoPeerRwndOff, 8},
		{"assocInfoLocalRwndOff", assocInfoLocalRwndOff, 12},
		{"assocInfoCookieLifeOff", assocInfoCookieLifeOff, 16},

		// struct sctp_sack_info, lines 895-899.
		{"sizeDelayedSACK", sizeDelayedSACK, 12},
		{"delayedSACKAssocIDOff", delayedSACKAssocIDOff, 0},
		{"delayedSACKDelayOff", delayedSACKDelayOff, 4},
		{"delayedSACKFrequencyOff", delayedSACKFrequencyOff, 8},

		// struct sctp_paddrparams, lines 806-816 (packed, aligned(4)).
		// Cross-checked against v1's own kernel-measured offsets (git show
		// main:sctp.go, PeerAddrParams's pppAssocID..pppDSCP constants).
		{"sizePathParams", sizePathParams, 156},
		{"pathParamsAssocIDOff", pathParamsAssocIDOff, 0},
		{"pathParamsAddressOff", pathParamsAddressOff, 4},
		{"pathParamsHBIntervalOff", pathParamsHBIntervalOff, 132},
		{"pathParamsPathMaxRxtOff", pathParamsPathMaxRxtOff, 136},
		{"pathParamsPathMTUOff", pathParamsPathMTUOff, 138},
		{"pathParamsSackDelayOff", pathParamsSackDelayOff, 142},
		{"pathParamsFlagsOff", pathParamsFlagsOff, 146},
		{"pathParamsFlowLabelOff", pathParamsFlowLabelOff, 150},
		{"pathParamsDSCPOff", pathParamsDSCPOff, 154},

		// struct sctp_paddrinfo, lines 921-929 (packed, aligned(4)).
		// Cross-checked against v1's kernel-measured PeerAddrinfo.
		{"sizePathInfo", sizePathInfo, 152},
		{"pathInfoAssocIDOff", pathInfoAssocIDOff, 0},
		{"pathInfoAddressOff", pathInfoAddressOff, 4},
		{"pathInfoStateOff", pathInfoStateOff, 132},
		{"pathInfoCwndOff", pathInfoCwndOff, 136},
		{"pathInfoSRTTOff", pathInfoSRTTOff, 140},
		{"pathInfoRTOOff", pathInfoRTOOff, 144},
		{"pathInfoMTUOff", pathInfoMTUOff, 148},

		// struct sctp_status, lines 958-968. Cross-checked against v1's
		// kernel-measured Status (176 total).
		{"sizeStatus", sizeStatus, 176},
		{"statusAssocIDOff", statusAssocIDOff, 0},
		{"statusStateOff", statusStateOff, 4},
		{"statusRWNDOff", statusRWNDOff, 8},
		{"statusUnackedOff", statusUnackedOff, 12},
		{"statusPendingOff", statusPendingOff, 14},
		{"statusInStreamsOff", statusInStreamsOff, 16},
		{"statusOutStreamsOff", statusOutStreamsOff, 18},
		{"statusFragmentationPointOff", statusFragmentationPointOff, 20},
		{"statusPrimaryOff", statusPrimaryOff, 24},

		// struct sctp_prstatus, lines 1105-1111.
		{"sizePRStatus", sizePRStatus, 24},
		{"prStatusAssocIDOff", prStatusAssocIDOff, 0},
		{"prStatusStreamOff", prStatusStreamOff, 4},
		{"prStatusPolicyOff", prStatusPolicyOff, 6},
		{"prStatusAbandonedUnsentOff", prStatusAbandonedUnsentOff, 8},
		{"prStatusAbandonedSentOff", prStatusAbandonedSentOff, 16},

		// struct sctp_default_prinfo, lines 1113-1117.
		{"sizeDefaultPRInfo", sizeDefaultPRInfo, 12},
		{"defaultPRInfoAssocIDOff", defaultPRInfoAssocIDOff, 0},
		{"defaultPRInfoValueOff", defaultPRInfoValueOff, 4},
		{"defaultPRInfoPolicyOff", defaultPRInfoPolicyOff, 8},

		// struct sctp_authkey, lines 861-866 (fixed header only).
		{"sizeAuthKey", sizeAuthKey, 8},
		{"authKeyAssocIDOff", authKeyAssocIDOff, 0},
		{"authKeyKeyNumberOff", authKeyKeyNumberOff, 4},
		{"authKeyKeyLengthOff", authKeyKeyLengthOff, 6},
		{"authKeyKeyOff", authKeyKeyOff, 8},

		// struct sctp_authkeyid, lines 875-878.
		{"sizeAuthKeyID", sizeAuthKeyID, 8},
		{"authKeyIDAssocIDOff", authKeyIDAssocIDOff, 0},
		{"authKeyIDKeyNumberOff", authKeyIDKeyNumberOff, 4},

		// struct sctp_hmacalgo, lines 845-848 (fixed header only).
		{"sizeHMACAlgo", sizeHMACAlgo, 4},
		{"hmacAlgoNumIdentsOff", hmacAlgoNumIdentsOff, 0},
		{"hmacAlgoIdentsOff", hmacAlgoIdentsOff, 4},

		// struct sctp_authchunks, lines 977-981 (fixed header only).
		{"sizeAuthChunks", sizeAuthChunks, 8},
		{"authChunksAssocIDOff", authChunksAssocIDOff, 0},
		{"authChunksNumChunksOff", authChunksNumChunksOff, 4},
		{"authChunksChunksOff", authChunksChunksOff, 8},

		// struct sctp_assoc_ids, lines 1008-1011 (fixed header only).
		{"sizeAssocIDs", sizeAssocIDs, 4},
		{"assocIDsNumIDsOff", assocIDsNumIDsOff, 0},
		{"assocIDsIDsOff", assocIDsIDsOff, 4},

		// struct sctp_getaddrs, lines 1029-1033 (fixed header only).
		{"sizeGetAddrs", sizeGetAddrs, 8},
		{"getAddrsAssocIDOff", getAddrsAssocIDOff, 0},
		{"getAddrsAddrNumOff", getAddrsAddrNumOff, 4},
		{"getAddrsAddrsOff", getAddrsAddrsOff, 8},

		// struct sctp_reset_streams, lines 1183-1188 (fixed header only).
		{"sizeResetStreams", sizeResetStreams, 8},
		{"resetStreamsAssocIDOff", resetStreamsAssocIDOff, 0},
		{"resetStreamsFlagsOff", resetStreamsFlagsOff, 4},
		{"resetStreamsNumStreamsOff", resetStreamsNumStreamsOff, 6},
		{"resetStreamsStreamListOff", resetStreamsStreamListOff, 8},

		// struct sctp_add_streams, lines 1190-1194.
		{"sizeAddStreams", sizeAddStreams, 8},
		{"addStreamsAssocIDOff", addStreamsAssocIDOff, 0},
		{"addStreamsInStreamsOff", addStreamsInStreamsOff, 4},
		{"addStreamsOutStreamsOff", addStreamsOutStreamsOff, 6},

		// struct sctp_stream_value, lines 906-910.
		{"sizeStreamValue", sizeStreamValue, 8},
		{"streamValueAssocIDOff", streamValueAssocIDOff, 0},
		{"streamValueStreamIDOff", streamValueStreamIDOff, 4},
		{"streamValueValueOff", streamValueValueOff, 6},

		// struct sctp_event, lines 1196-1200.
		{"sizeEvent", sizeEvent, 8},
		{"eventAssocIDOff", eventAssocIDOff, 0},
		{"eventTypeFieldOff", eventTypeFieldOff, 4},
		{"eventOnOff", eventOnOff, 6},

		// struct sctp_assoc_value, lines 901-904.
		{"sizeAssocValue", sizeAssocValue, 8},
		{"assocValueAssocIDOff", assocValueAssocIDOff, 0},
		{"assocValueValueOff", assocValueValueOff, 4},

		// sctp_peeloff_flags_arg_t, lines 1073-1081.
		{"sizePeeloffFlagsArg", sizePeeloffFlagsArg, 12},
		{"peeloffFlagsArgAssocIDOff", peeloffFlagsArgAssocIDOff, 0},
		{"peeloffFlagsArgSDOff", peeloffFlagsArgSDOff, 4},
		{"peeloffFlagsArgFlagsOff", peeloffFlagsArgFlagsOff, 8},

		// struct sctp_prim, lines 762-765 (packed, aligned(4)).
		{"sizePrim", sizePrim, 132},
		{"primAssocIDOff", primAssocIDOff, 0},
		{"primAddrOff", primAddrOff, 4},

		// struct sctp_setpeerprim, lines 749-752 (packed, aligned(4)).
		{"sizeSetPeerPrim", sizeSetPeerPrim, 132},
		{"setPeerPrimAssocIDOff", setPeerPrimAssocIDOff, 0},
		{"setPeerPrimAddrOff", setPeerPrimAddrOff, 4},

		// struct sctp_authchunk, lines 825-827.
		{"sizeAuthChunk", sizeAuthChunk, 1},

		// struct sctp_setadaptation, lines 776-778.
		{"sizeSetAdaptation", sizeSetAdaptation, 4},

		// A plain C int on every Linux ABI the package builds for.
		{"sizeInt", sizeInt, 4},
	})
}

// TestConnectx3ArgLayout pins connectx3Arg against struct
// sctp_getaddrs_old (include/uapi/linux/sctp.h, lines 1019-1027): assoc_id
// at 0, addr_num at 4 and the address pointer at 8, one word wide, so the
// struct is 16 bytes on a 64-bit build and 12 on a 32-bit one — also the
// size of struct compat_sctp_getaddrs_old, which a 64-bit kernel reads from
// a 32-bit process (net/sctp/socket.c: sctp_getsockopt_connectx3).
func TestConnectx3ArgLayout(t *testing.T) {
	var a connectx3Arg
	checkNumbers(t, []numberCase{
		{"offsetof(assocID)", int(unsafe.Offsetof(a.assocID)), 0},
		{"offsetof(addrNum)", int(unsafe.Offsetof(a.addrNum)), 4},
		{"offsetof(addrs)", int(unsafe.Offsetof(a.addrs)), 8},
		{"sizeof(connectx3Arg)", int(unsafe.Sizeof(a)), 8 + bits.UintSize/8},
	})
}

// TestSockaddrStorageOptionLayouts pins the four option structs whose
// layout depends on word size — struct sctp_udpencaps (lines 1202-1206),
// struct sctp_probeinterval (1220-1224) and struct sctp_paddrthlds_v2
// (1094-1100) are none of them declared packed, so their embedded
// sockaddr_storage keeps its natural, pointer-sized alignment; struct
// sctp_assoc_stats (1040-1059) likewise, plus its __u64 counters' own
// alignment, which on 386 disagrees with every other architecture (see
// u64Align, abi_u64align_386.go). Measured with a C probe over
// <linux/sctp.h> for every word size (comment on ssAlign, abi.go); the two
// non-386 rows are the same numbers v1 measured (git show
// main:sctp_options_test.go, TestSockaddrStorageOptionLayouts) — ported
// here since the properties moved from Go-struct unsafe.Sizeof/Offsetof
// assertions to abi.go's formula constants; the 386 numbers are new, since
// v1 never ran on that architecture with these structs checked. Ledger:
// TestSockaddrStorageOptionLayouts -> ported -> TestSockaddrStorageOptionLayouts
// (same name, new home, and a third, 386-specific row this test adds).
func TestSockaddrStorageOptionLayouts(t *testing.T) {
	// wantAddr and wantTail describe every one of the four structs' embedded
	// sockaddr_storage — its own alignment (ssAlign) follows the pointer
	// size uniformly on every 32-bit architecture, 386 included. wantStats*
	// describe sctp_assoc_stats specifically, where 386's u64Align=4 (not
	// arm/mips' or amd64/arm64's 8) changes where the __u64 counters land.
	wantAddr, wantTail := 8, 136
	wantUDP, wantProbe, wantThlds, wantProbeThlds := 144, 144, 144, 144
	wantStatsHeader, wantStatsSize := 136, 256
	switch {
	case bits.UintSize == 32 && runtime.GOARCH == "386":
		wantAddr, wantTail = 4, 132
		wantUDP, wantProbe, wantThlds, wantProbeThlds = 136, 136, 140, 136
		wantStatsHeader, wantStatsSize = 132, 252
	case bits.UintSize == 32:
		wantAddr, wantTail = 4, 132
		wantUDP, wantProbe, wantThlds, wantProbeThlds = 136, 136, 140, 136
		wantStatsHeader, wantStatsSize = 136, 256
	}

	checkNumbers(t, []numberCase{
		{"ssAddrOffset", ssAddrOffset, wantAddr},
		{"ssTailOffset", ssTailOffset, wantTail},

		{"udpEncapsAddressOff", udpEncapsAddressOff, wantAddr},
		{"udpEncapsPortOff", udpEncapsPortOff, wantTail},
		{"sizeUDPEncaps", sizeUDPEncaps, wantUDP},

		{"probeIntervalAddressOff", probeIntervalAddressOff, wantAddr},
		{"probeIntervalIntervalOff", probeIntervalIntervalOff, wantTail},
		{"sizeProbeInterval", sizeProbeInterval, wantProbe},

		{"pathThresholdsAddressOff", pathThresholdsAddressOff, wantAddr},
		{"pathThresholdsMaxRxtOff", pathThresholdsMaxRxtOff, wantTail},
		{"pathThresholdsPFThresholdOff", pathThresholdsPFThresholdOff, wantTail + 2},
		{"pathThresholdsSwitchoverOff", pathThresholdsSwitchoverOff, wantTail + 4},
		{"sizePathThresholds", sizePathThresholds, wantThlds},

		// struct sctp_paddrthlds, the two-field form the layout probe
		// asks for: 136 bytes on a 32-bit target, 144 on a 64-bit one.
		{"sizePathThresholdsProbe", sizePathThresholdsProbe, wantProbeThlds},

		{"assocStatsAddrOff", assocStatsAddrOff, wantAddr},
		{"sizeAssocStatsHeader", sizeAssocStatsHeader, wantStatsHeader},
		{"sizeAssocStats", sizeAssocStats, wantStatsSize},

		{"udpEncapsAssocIDOff", udpEncapsAssocIDOff, 0},
		{"probeIntervalAssocIDOff", probeIntervalAssocIDOff, 0},
		{"pathThresholdsAssocIDOff", pathThresholdsAssocIDOff, 0},
		{"assocStatsAssocIDOff", assocStatsAssocIDOff, 0},
	})
}

// TestKernel64Layouts pins the fixed, always-64-bit-shaped constants a
// 32-bit build falls back to for these same four structs, since Linux SCTP
// hands a 32-bit process the kernel's own 64-bit bytes for them on a
// 64-bit kernel rather than translating (abi.go's comment on the
// word-size-dependent option structs explains why). Every number here is
// the same regardless of runtime.GOARCH — that is the point of the
// Kernel64 constants — so this test needs no per-architecture branch.
func TestKernel64Layouts(t *testing.T) {
	checkNumbers(t, []numberCase{
		{"ssAddrOffsetKernel64", ssAddrOffsetKernel64, 8},
		{"ssTailOffsetKernel64", ssTailOffsetKernel64, 136},

		{"udpEncapsAddressOffKernel64", udpEncapsAddressOffKernel64, 8},
		{"sizeUDPEncapsKernel64", sizeUDPEncapsKernel64, 144},

		{"probeIntervalAddressOffKernel64", probeIntervalAddressOffKernel64, 8},
		{"sizeProbeIntervalKernel64", sizeProbeIntervalKernel64, 144},

		{"pathThresholdsAddressOffKernel64", pathThresholdsAddressOffKernel64, 8},
		{"sizePathThresholdsKernel64", sizePathThresholdsKernel64, 144},

		{"udpEncapsPortOffKernel64", udpEncapsPortOffKernel64, 136},
		{"probeIntervalIntervalOffKernel64", probeIntervalIntervalOffKernel64, 136},
		{"pathThresholdsMaxRxtOffKernel64", pathThresholdsMaxRxtOffKernel64, 136},
		{"pathThresholdsPFThresholdOffKernel64", pathThresholdsPFThresholdOffKernel64, 138},
		{"pathThresholdsSwitchoverOffKernel64", pathThresholdsSwitchoverOffKernel64, 140},

		{"assocStatsAddrOffKernel64", assocStatsAddrOffKernel64, 8},
		{"sizeAssocStatsHeaderKernel64", sizeAssocStatsHeaderKernel64, 136},
		{"sizeAssocStatsKernel64", sizeAssocStatsKernel64, 256},
	})
}

// TestSockaddrStorageLayoutFormula recomputes the ssAddrOffset/ssTailOffset
// formula for every word-size row at once, the same measurements as
// TestSockaddrStorageOptionLayouts, so that a mistake in the formula itself
// is caught even when this test runs on the word size that happens to match
// the current build (mirrors v1's TestSockaddrStorageLayoutFormula, git
// show main:sctp_options_test.go, extended with the 386 row v1 never had).
// Ledger: TestSockaddrStorageLayoutFormula -> ported ->
// TestSockaddrStorageLayoutFormula.
func TestSockaddrStorageLayoutFormula(t *testing.T) {
	for _, tc := range []struct {
		align, addr, tail int
		udp, probe, thlds int
	}{
		{align: 4, addr: 4, tail: 132, udp: 136, probe: 136, thlds: 140},
		{align: 8, addr: 8, tail: 136, udp: 144, probe: 144, thlds: 144},
	} {
		round := func(n int) int { return (n + tc.align - 1) &^ (tc.align - 1) }
		addr := round(4)
		tail := addr + sizeSockaddrStorage
		cases := []struct {
			name      string
			got, want int
		}{
			{"address offset", addr, tc.addr},
			{"tail offset", tail, tc.tail},
			{"sctp_udpencaps", round(tail + 2), tc.udp},
			{"sctp_probeinterval", round(tail + 4), tc.probe},
			{"sctp_paddrthlds_v2", round(tail + 6), tc.thlds},
		}
		for _, c := range cases {
			if c.got != c.want {
				t.Errorf("align %d: %s = %d, kernel has %d", tc.align, c.name, c.got, c.want)
			}
		}

		if tc.align != ssAlign {
			continue
		}
		checkNumbers(t, []numberCase{
			{"ssAddrOffset", ssAddrOffset, tc.addr},
			{"sizeUDPEncaps", sizeUDPEncaps, tc.udp},
			{"sizePathThresholds", sizePathThresholds, tc.thlds},
		})
	}

	// sctp_assoc_stats needs its own table: its counters round up to
	// u64Align, not ssAlign, and the two disagree exactly on 386 (ssAlign 4,
	// u64Align 4) versus every other 32-bit architecture this package
	// builds for (ssAlign 4, u64Align 8) — see u64Align's own comment.
	for _, tc := range []struct {
		ssAlign, u64Align int
		header, size      int
	}{
		{ssAlign: 4, u64Align: 4, header: 132, size: 252}, // 386
		{ssAlign: 4, u64Align: 8, header: 136, size: 256}, // arm, mips, ...
		{ssAlign: 8, u64Align: 8, header: 136, size: 256}, // amd64, arm64, ...
	} {
		roundSS := func(n int) int { return (n + tc.ssAlign - 1) &^ (tc.ssAlign - 1) }
		roundU64 := func(n int) int { return (n + tc.u64Align - 1) &^ (tc.u64Align - 1) }
		tail := roundSS(4) + sizeSockaddrStorage
		header := roundU64(tail)
		size := header + 15*8
		if header != tc.header {
			t.Errorf("ssAlign %d u64Align %d: assoc_stats header = %d, kernel has %d",
				tc.ssAlign, tc.u64Align, header, tc.header)
		}
		if size != tc.size {
			t.Errorf("ssAlign %d u64Align %d: assoc_stats size = %d, kernel has %d",
				tc.ssAlign, tc.u64Align, size, tc.size)
		}

		if tc.ssAlign != ssAlign || tc.u64Align != u64Align {
			continue
		}
		checkNumbers(t, []numberCase{
			{"sizeAssocStatsHeader", sizeAssocStatsHeader, tc.header},
			{"sizeAssocStats", sizeAssocStats, tc.size},
		})
	}

	// The row selection above trusts the package's own u64Align constant to
	// find the matching row, so it cannot by itself catch u64Align holding
	// the wrong value for this GOARCH (a mutated u64Align silently makes a
	// different row "match" instead). runtime.GOARCH is independent of
	// anything in this package, so check u64Align itself against it
	// directly, and sizeAssocStatsHeader/sizeAssocStats too, so a formula
	// bug unrelated to u64Align's own value — one this GOARCH-based
	// expectation still catches but the row-selection loop above might
	// not — is caught here as well.
	wantU64Align, wantHeader, wantSize := 8, 136, 256
	if runtime.GOARCH == "386" {
		wantU64Align, wantHeader, wantSize = 4, 132, 252
	}
	checkNumbers(t, []numberCase{
		{"u64Align", u64Align, wantU64Align},
		{"sizeAssocStatsHeader", sizeAssocStatsHeader, wantHeader},
		{"sizeAssocStats", sizeAssocStats, wantSize},
	})
}
