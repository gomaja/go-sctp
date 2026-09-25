// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"reflect"
	"testing"
)

// stringerCase is one enumeration value's expected String() text.
type stringerCase struct {
	name string
	got  string
	want string
}

func checkStrings(t *testing.T, cases []stringerCase) {
	t.Helper()
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}
}

// TestConstantNameString covers the ordinary rule every enumeration in this
// file follows except ErrorCause, SendFlags and StreamResetMask (their own
// tests are below): a named value's String is its exported constant name,
// and an unnamed value renders as its type and number.
func TestConstantNameString(t *testing.T) {
	checkStrings(t, []stringerCase{
		{"StateEstablished", StateEstablished.String(), "StateEstablished"},
		{"AssocState(9)", AssocState(9).String(), "AssocState(9)"},

		{"PathActive", PathActive.String(), "PathActive"},
		{"PathUnknown", PathUnknown.String(), "PathUnknown"},
		{"PathState(9)", PathState(9).String(), "PathState(9)"},

		{"PRTTL", PRTTL.String(), "PRTTL"},
		{"PRAll", PRAll.String(), "PRAll"},
		{"PRPolicy(1)", PRPolicy(1).String(), "PRPolicy(1)"}, // 1 is not a policy bit pattern

		{"SchedRR", SchedRR.String(), "SchedRR"},
		{"Scheduler(9)", Scheduler(9).String(), "Scheduler(9)"},

		{"InterleaveAssocs", InterleaveAssocs.String(), "InterleaveAssocs"},
		{"FragmentInterleave(9)", FragmentInterleave(9).String(), "FragmentInterleave(9)"},

		{"PFExposeEnabled", PFExposeEnabled.String(), "PFExposeEnabled"},
		{"PFExposure(9)", PFExposure(9).String(), "PFExposure(9)"},

		{"ResetIncoming", ResetIncoming.String(), "ResetIncoming"},
		{"ResetOutgoing", ResetOutgoing.String(), "ResetOutgoing"},
		{"ResetDirection(9)", ResetDirection(9).String(), "ResetDirection(9)"},

		{"HMACSHA256", HMACSHA256.String(), "HMACSHA256"},
		{"HMACID(2)", HMACID(2).String(), "HMACID(2)"}, // 2 is unassigned by IANA

		{"AbandonQuiet", AbandonQuiet.String(), "AbandonQuiet"},
		{"AbandonPolicy(9)", AbandonPolicy(9).String(), "AbandonPolicy(9)"},

		{"EventSendFailed", EventSendFailed.String(), "EventSendFailed"},
		// 0x8003 is SCTP_SEND_FAILED, the notification RFC 6458 §6.1.11's
		// SCTP_SEND_FAILED_EVENT (EventSendFailed, 0x800d) replaces; this
		// package does not name it.
		{"EventType(0x8003)", EventType(0x8003).String(), "EventType(32771)"},

		{"AssocCantStart", AssocCantStart.String(), "AssocCantStart"},
		{"AssocChangeState(9)", AssocChangeState(9).String(), "AssocChangeState(9)"},

		{"AddrPotentiallyFailed", AddrPotentiallyFailed.String(), "AddrPotentiallyFailed"},
		{"AddrChangeState(9)", AddrChangeState(9).String(), "AddrChangeState(9)"},

		{"AuthNoAuth", AuthNoAuth.String(), "AuthNoAuth"},
		{"AuthIndication(9)", AuthIndication(9).String(), "AuthIndication(9)"},

		{"ReasonPeerFaulty", ReasonPeerFaulty.String(), "ReasonPeerFaulty"},
		{"ReasonNone", ReasonNone.String(), "ReasonNone"},
		{"AddrChangeReason(9)", AddrChangeReason(9).String(), "AddrChangeReason(9)"},
	})
}

// TestErrorCauseIANANames covers ErrorCause's exception to the constant-name
// rule: String returns the name errorCauseIANANames gives the cause (the
// IANA registry name for the codes IANA defines, Linux's own name for the
// two it does not — see ErrorCause's doc comment), and a cause the package
// does not name renders as ErrorCause(n).
func TestErrorCauseIANANames(t *testing.T) {
	checkStrings(t, []stringerCase{
		{"CauseNone", CauseNone.String(), "No Error"},
		{"CauseInvalidStream", CauseInvalidStream.String(), "Invalid Stream Identifier"},
		{"CauseMissingParam", CauseMissingParam.String(), "Missing Mandatory Parameter"},
		{"CauseStaleCookie", CauseStaleCookie.String(), "Stale Cookie"},
		{"CauseOutOfResource", CauseOutOfResource.String(), "Out of Resource"},
		{"CauseUnresolvableAddr", CauseUnresolvableAddr.String(), "Unresolvable Address"},
		{"CauseUnrecognizedChunk", CauseUnrecognizedChunk.String(), "Unrecognized Chunk Type"},
		{"CauseInvalidParam", CauseInvalidParam.String(), "Invalid Mandatory Parameter"},
		{"CauseUnrecognizedParams", CauseUnrecognizedParams.String(), "Unrecognized Parameters"},
		{"CauseNoUserData", CauseNoUserData.String(), "No User Data"},
		{"CauseCookieInShutdown", CauseCookieInShutdown.String(), "Cookie Received While Shutting Down"},
		{"CauseRestartNewAddrs", CauseRestartNewAddrs.String(), "Restart of an Association with New Addresses"},
		{"CauseUserAbort", CauseUserAbort.String(), "User-Initiated Abort"},
		{"CauseProtocolViolation", CauseProtocolViolation.String(), "Protocol Violation"},
		{"CauseRestartNewEncapPort", CauseRestartNewEncapPort.String(),
			"Restart of an Association with New Encapsulation Port"},
		{"CauseDeleteLastAddr", CauseDeleteLastAddr.String(), "Request to Delete Last Remaining IP Address"},
		{"CauseResourceShortage", CauseResourceShortage.String(), "Operation Refused Due to Resource Shortage"},
		{"CauseDeleteSourceAddr", CauseDeleteSourceAddr.String(), "Request to Delete Source IP Address"},
		{"CauseIllegalASCONFAck", CauseIllegalASCONFAck.String(), "Association Aborted due to illegal ASCONF-ACK"},
		{"CauseRequestRefused", CauseRequestRefused.String(), "Request refused - no authorization"},
		{"CauseUnsupportedHMAC", CauseUnsupportedHMAC.String(), "Unsupported HMAC Identifier"},
		{"ErrorCause(1000)", ErrorCause(1000).String(), "ErrorCause(1000)"},
	})
}

// TestBitSetString covers SendFlags and StreamResetMask's exception to the
// constant-name rule: String joins the names of set bits with "|" and
// renders bits it does not name as a trailing hexadecimal literal, e.g.
// SendFlags(0x21).String() == "SendUnordered|0x20".
func TestBitSetString(t *testing.T) {
	checkStrings(t, []stringerCase{
		{"SendFlags(0x21)", SendFlags(0x21).String(), "SendUnordered|0x20"},
		{"SendFlags(0)", SendFlags(0).String(), "0x0"},
		{"SendUnordered|SendSACKImmediately",
			(SendUnordered | SendSACKImmediately).String(), "SendUnordered|SendSACKImmediately"},
		{"SendFlags(0x8) alone", SendFlags(0x8).String(), "SendSACKImmediately"},

		{"EnableResetStreamReq|EnableChangeAssocReq",
			(EnableResetStreamReq | EnableChangeAssocReq).String(),
			"EnableResetStreamReq|EnableChangeAssocReq"},
		{"StreamResetMask(0x8) unknown bit", StreamResetMask(0x8).String(), "0x8"},
		{"EnableResetAssocReq|StreamResetMask(0x10)",
			(EnableResetAssocReq | StreamResetMask(0x10)).String(), "EnableResetAssocReq|0x10"},
		{"StreamResetMask(0)", StreamResetMask(0).String(), "0x0"},
	})
}

// enumValueCase is one enumeration constant's expected wire value.
type enumValueCase struct {
	name string
	got  int
	want int
}

func checkEnumValues(t *testing.T, cases []enumValueCase) {
	t.Helper()
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %#x, want %#x", c.name, c.got, c.want)
		}
	}
}

// TestEnumerationValues pins every enumeration constant's numeric value in
// this file against the kernel enum it names (include/uapi/linux/sctp.h,
// v6.12; line ranges cited per group), independently of the String-name
// tests above — a value can print the right name and still carry the wrong
// number if only the map key, not the constant itself, were ever checked.
//
// Ledger: TestPrPolicyConstantValues (git show main:sctp_extensions_test.go,
// its PR-policy and stream-reset-mask rows; its HMAC rows are covered by
// TestConstantNameString's HMACSHA256 case, which round-trips the same
// values through String) and TestNotificationTypeNumbersMatchTheKernel (git
// show main:sctp_cause_test.go) -> ported -> TestEnumerationValues.
func TestEnumerationValues(t *testing.T) {
	checkEnumValues(t, []enumValueCase{
		// enum sctp_sstat_state, lines 989-999.
		{"StateEmpty", int(StateEmpty), 0},
		{"StateClosed", int(StateClosed), 1},
		{"StateCookieWait", int(StateCookieWait), 2},
		{"StateCookieEchoed", int(StateCookieEchoed), 3},
		{"StateEstablished", int(StateEstablished), 4},
		{"StateShutdownPending", int(StateShutdownPending), 5},
		{"StateShutdownSent", int(StateShutdownSent), 6},
		{"StateShutdownReceived", int(StateShutdownReceived), 7},
		{"StateShutdownAckSent", int(StateShutdownAckSent), 8},

		// enum sctp_spinfo_state, lines 940-947.
		{"PathInactive", int(PathInactive), 0},
		{"PathPotentiallyFailed", int(PathPotentiallyFailed), 1},
		{"PathActive", int(PathActive), 2},
		{"PathUnconfirmed", int(PathUnconfirmed), 3},
		{"PathUnknown", int(PathUnknown), 0xffff},

		// PR-SCTP policies, lines 147-152 (SCTP_PR_SCTP_*).
		{"PRNone", int(PRNone), 0x0000},
		{"PRTTL", int(PRTTL), 0x0010},
		{"PRRtx", int(PRRtx), 0x0020},
		{"PRPrio", int(PRPrio), 0x0030},

		// enum sctp_sched_type, lines 1209-1217.
		{"SchedFCFS", int(SchedFCFS), 0},
		{"SchedPrio", int(SchedPrio), 1},
		{"SchedRR", int(SchedRR), 2},
		{"SchedFC", int(SchedFC), 3},
		{"SchedWFQ", int(SchedWFQ), 4},

		// PFExposure, include/net/sctp/constants.h (not the UAPI header),
		// v6.12 lines 312-317 (anonymous enum, SCTP_PF_EXPOSE_*).
		{"PFExposeUnset", int(PFExposeUnset), 0},
		{"PFExposeDisabled", int(PFExposeDisabled), 1},
		{"PFExposeEnabled", int(PFExposeEnabled), 2},

		// FragmentInterleave (SCTP_FRAGMENT_INTERLEAVE's value, RFC 6458
		// §8.1.20): InterleaveNone/Assocs/Streams are the option's own
		// levels (0, 1, 2), not separately named in the UAPI header.
		{"InterleaveNone", int(InterleaveNone), 0},
		{"InterleaveAssocs", int(InterleaveAssocs), 1},
		{"InterleaveStreams", int(InterleaveStreams), 2},

		// SendFlags, enum sctp_sinfo_flags, lines 310-320 — the two bits
		// this package exposes on SendOptions.Info.Flags. abi_test.go's
		// TestSendFlagBits pins the same numbers again from the raw
		// sndFlag* constants these must equal.
		{"SendUnordered", int(SendUnordered), 0x1},
		{"SendSACKImmediately", int(SendSACKImmediately), 0x8},

		// Stream-reset enable mask, lines 169-172 (SCTP_ENABLE_*_REQ).
		{"EnableResetStreamReq", int(EnableResetStreamReq), 0x01},
		{"EnableResetAssocReq", int(EnableResetAssocReq), 0x02},
		{"EnableChangeAssocReq", int(EnableChangeAssocReq), 0x04},

		// Stream-reset direction, lines 174-175 (SCTP_STREAM_RESET_*).
		{"ResetIncoming", int(ResetIncoming), 0x01},
		{"ResetOutgoing", int(ResetOutgoing), 0x02},

		// HMAC identifiers, lines 839-842 (only used by userspace; the
		// registry skips 2).
		{"HMACSHA1", int(HMACSHA1), 1},
		{"HMACSHA256", int(HMACSHA256), 3},

		// enum sctp_sn_type, lines 661-693 (sn_type values).
		{"EventAssocChange", int(EventAssocChange), 0x8001},
		{"EventPeerAddrChange", int(EventPeerAddrChange), 0x8002},
		{"EventRemoteError", int(EventRemoteError), 0x8004},
		{"EventShutdown", int(EventShutdown), 0x8005},
		{"EventPartialDelivery", int(EventPartialDelivery), 0x8006},
		{"EventAdaptationIndication", int(EventAdaptationIndication), 0x8007},
		{"EventAuthentication", int(EventAuthentication), 0x8008},
		{"EventSenderDry", int(EventSenderDry), 0x8009},
		{"EventStreamReset", int(EventStreamReset), 0x800a},
		{"EventAssocReset", int(EventAssocReset), 0x800b},
		{"EventStreamChange", int(EventStreamChange), 0x800c},
		{"EventSendFailed", int(EventSendFailed), 0x800d},

		// enum sctp_sac_state, lines 380-386.
		{"AssocCommUp", int(AssocCommUp), 0},
		{"AssocCommLost", int(AssocCommLost), 1},
		{"AssocRestart", int(AssocRestart), 2},
		{"AssocShutdownComplete", int(AssocShutdownComplete), 3},
		{"AssocCantStart", int(AssocCantStart), 4},

		// enum sctp_spc_state, lines 411-419.
		{"AddrAvailable", int(AddrAvailable), 0},
		{"AddrUnreachable", int(AddrUnreachable), 1},
		{"AddrRemoved", int(AddrRemoved), 2},
		{"AddrAdded", int(AddrAdded), 3},
		{"AddrMadePrimary", int(AddrMadePrimary), 4},
		{"AddrConfirmed", int(AddrConfirmed), 5},
		{"AddrPotentiallyFailed", int(AddrPotentiallyFailed), 6},

		// Anonymous auth-indication enum, lines 549-554.
		{"AuthNewKey", int(AuthNewKey), 0},
		{"AuthFreeKey", int(AuthFreeKey), 1},
		{"AuthNoAuth", int(AuthNoAuth), 2},
	})

	// AddrChangeReason does not number its constants exactly as the kernel
	// does (see its doc comment in enums.go): Linux's enum sctp_sn_error
	// (spc_error, lines 702-710) starts at SCTP_FAILED_THRESHOLD = 0, but
	// this package inserts ReasonNone ahead of it at 0, so every named
	// reason sits one past its raw kernel value — ReasonFailedThreshold is
	// 1, not the kernel's 0. That is deliberate, not a mismatch to pin here:
	// a notification decoder reads the host-order spc_error field and
	// produces ReasonNone for a raw 0 outside AddrUnreachable and
	// ReasonFailedThreshold for a raw 0 in it — Linux sends 0 for both "no
	// reason" and for its own first reason, and that state check is how the
	// two are told apart. What this test checks instead is the one property
	// that does have to hold for that decoder to be able to do that at all:
	// iota gives the Reason constants themselves a strictly increasing,
	// gap-free sequence starting at ReasonNone = 0.
	reasons := []AddrChangeReason{
		ReasonNone, ReasonFailedThreshold, ReasonReceivedSACK, ReasonHeartbeatSuccess,
		ReasonResponseToUserReq, ReasonInternalError, ReasonShutdownGuardExpires, ReasonPeerFaulty,
	}
	for i, r := range reasons {
		if int(r) != i {
			t.Errorf("AddrChangeReason sequence: value %d is %d, want %d", i, int(r), i)
		}
	}
}

// TestErrorCauseValues pins every ErrorCause constant's numeric value
// against RFC 9260 §3.3.10 and IANA's "SCTP Error Cause Codes" registry
// (codes 1-13), RFC 5061 (0xa0-0xa4), RFC 4895 (0x105) and, for
// CauseRestartNewEncapPort, Linux's own net/sctp/protocol.c use of the
// value IANA leaves unassigned — independently of the IANA *names*
// TestErrorCauseIANANames checks.
func TestErrorCauseValues(t *testing.T) {
	checkEnumValues(t, []enumValueCase{
		{"CauseNone", int(CauseNone), 0},
		{"CauseInvalidStream", int(CauseInvalidStream), 1},
		{"CauseMissingParam", int(CauseMissingParam), 2},
		{"CauseStaleCookie", int(CauseStaleCookie), 3},
		{"CauseOutOfResource", int(CauseOutOfResource), 4},
		{"CauseUnresolvableAddr", int(CauseUnresolvableAddr), 5},
		{"CauseUnrecognizedChunk", int(CauseUnrecognizedChunk), 6},
		{"CauseInvalidParam", int(CauseInvalidParam), 7},
		{"CauseUnrecognizedParams", int(CauseUnrecognizedParams), 8},
		{"CauseNoUserData", int(CauseNoUserData), 9},
		{"CauseCookieInShutdown", int(CauseCookieInShutdown), 10},
		{"CauseRestartNewAddrs", int(CauseRestartNewAddrs), 11},
		{"CauseUserAbort", int(CauseUserAbort), 12},
		{"CauseProtocolViolation", int(CauseProtocolViolation), 13},
		{"CauseRestartNewEncapPort", int(CauseRestartNewEncapPort), 14},
		{"CauseDeleteLastAddr", int(CauseDeleteLastAddr), 0xa0},
		{"CauseResourceShortage", int(CauseResourceShortage), 0xa1},
		{"CauseDeleteSourceAddr", int(CauseDeleteSourceAddr), 0xa2},
		{"CauseIllegalASCONFAck", int(CauseIllegalASCONFAck), 0xa3},
		{"CauseRequestRefused", int(CauseRequestRefused), 0xa4},
		{"CauseUnsupportedHMAC", int(CauseUnsupportedHMAC), 0x105},
	})
}

// TestSendFlagsMatchRawKernelBits pins that the exported bits sharing the
// kernel's snd_flags/sinfo_flags word with the internal raw sndFlag*
// constants (abi.go) equal the same kernel bit under both names, so
// encoding never has to choose between them for the same value: SendFlags'
// two public bits, and PRPolicy's PRAll, which is also SCTP_PR_SCTP_ALL
// (enum sctp_sinfo_flags, include/uapi/linux/sctp.h).
func TestSendFlagsMatchRawKernelBits(t *testing.T) {
	checkEnumValues(t, []enumValueCase{
		{"SendUnordered vs sndFlagUnordered", int(SendUnordered), sndFlagUnordered},
		{"SendSACKImmediately vs sndFlagSackImmediately", int(SendSACKImmediately), sndFlagSackImmediately},
		{"PRAll vs sndFlagPRAll", int(PRAll), sndFlagPRAll},
	})
}

// TestEnumerationWidths checks that every enumeration in this file has the
// size and signedness of the kernel field it travels in, so a value
// converts without loss in either direction, plus AssocID, declared in this
// file for the same reason.
func TestEnumerationWidths(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  reflect.Type
		kind reflect.Kind
	}{
		{"AssocState", reflect.TypeOf(AssocState(0)), reflect.Int32},
		{"PathState", reflect.TypeOf(PathState(0)), reflect.Int32},
		{"PRPolicy", reflect.TypeOf(PRPolicy(0)), reflect.Uint16},
		{"Scheduler", reflect.TypeOf(Scheduler(0)), reflect.Uint32},
		{"FragmentInterleave", reflect.TypeOf(FragmentInterleave(0)), reflect.Int32},
		{"PFExposure", reflect.TypeOf(PFExposure(0)), reflect.Uint32},
		{"StreamResetMask", reflect.TypeOf(StreamResetMask(0)), reflect.Uint32},
		{"ResetDirection", reflect.TypeOf(ResetDirection(0)), reflect.Uint16},
		{"HMACID", reflect.TypeOf(HMACID(0)), reflect.Uint16},
		{"ErrorCause", reflect.TypeOf(ErrorCause(0)), reflect.Uint16},
		{"AbandonPolicy", reflect.TypeOf(AbandonPolicy(0)), reflect.Uint8},
		{"SendFlags", reflect.TypeOf(SendFlags(0)), reflect.Uint16},
		{"EventType", reflect.TypeOf(EventType(0)), reflect.Uint16},
		{"AssocChangeState", reflect.TypeOf(AssocChangeState(0)), reflect.Uint16},
		{"AddrChangeState", reflect.TypeOf(AddrChangeState(0)), reflect.Int32},
		{"AuthIndication", reflect.TypeOf(AuthIndication(0)), reflect.Uint32},
		{"AddrChangeReason", reflect.TypeOf(AddrChangeReason(0)), reflect.Int32},
		{"AssocID", reflect.TypeOf(AssocID(0)), reflect.Int32},
	} {
		if tc.typ.Kind() != tc.kind {
			t.Errorf("%s underlying kind = %s, want %s", tc.name, tc.typ.Kind(), tc.kind)
		}
	}
}
