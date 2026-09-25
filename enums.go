// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"fmt"
	"strings"
)

// AssocID identifies one association: the one an Endpoint's SendMsg, RecvMsg,
// PeelOff, CloseAssoc and AbortAssoc name explicitly, or the one a Conn holds
// for its life.
//
// Association ids come from one system-wide cyclic pool (idr_alloc_cyclic,
// net/sctp/associola.c), so an id is reused after its association ends.
// Retire an id when EventAssocChange reports the end (AssocChange), and
// never treat it as a lasting peer identity.
type AssocID int32

// AssocState is Status.State, the Linux enum sctp_sstat_state
// (include/uapi/linux/sctp.h, RFC 6458 §8.2.1's sstat_state).
type AssocState int32

const (
	StateEmpty AssocState = iota
	StateClosed
	StateCookieWait
	StateCookieEchoed
	StateEstablished
	StateShutdownPending
	StateShutdownSent
	StateShutdownReceived
	StateShutdownAckSent
)

var assocStateNames = map[AssocState]string{
	StateEmpty:            "StateEmpty",
	StateClosed:           "StateClosed",
	StateCookieWait:       "StateCookieWait",
	StateCookieEchoed:     "StateCookieEchoed",
	StateEstablished:      "StateEstablished",
	StateShutdownPending:  "StateShutdownPending",
	StateShutdownSent:     "StateShutdownSent",
	StateShutdownReceived: "StateShutdownReceived",
	StateShutdownAckSent:  "StateShutdownAckSent",
}

// String returns the exported constant name, e.g. "StateEstablished". A value
// the kernel has not defined renders as its type and number, e.g.
// "AssocState(9)".
func (s AssocState) String() string {
	if name, ok := assocStateNames[s]; ok {
		return name
	}
	return fmt.Sprintf("AssocState(%d)", int32(s))
}

// PathState is PathInfo.State, the Linux enum sctp_spinfo_state
// (include/uapi/linux/sctp.h, RFC 6458 §8.2.2's spinfo_state).
type PathState int32

const (
	PathInactive PathState = iota
	PathPotentiallyFailed
	PathActive
	PathUnconfirmed
	PathUnknown PathState = 0xffff
)

var pathStateNames = map[PathState]string{
	PathInactive:          "PathInactive",
	PathPotentiallyFailed: "PathPotentiallyFailed",
	PathActive:            "PathActive",
	PathUnconfirmed:       "PathUnconfirmed",
	PathUnknown:           "PathUnknown",
}

func (s PathState) String() string {
	if name, ok := pathStateNames[s]; ok {
		return name
	}
	return fmt.Sprintf("PathState(%d)", int32(s))
}

// PRPolicy is a PR-SCTP policy, RFC 7496 §4 (RFC 3758's SCTP_PR_SCTP_MASK
// bits, include/uapi/linux/sctp.h).
type PRPolicy uint16

const (
	PRNone PRPolicy = 0x0000
	PRTTL  PRPolicy = 0x0010
	PRRtx  PRPolicy = 0x0020
	PRPrio PRPolicy = 0x0030
	PRAll  PRPolicy = 0x0080 // status queries only: totals across policies
)

var prPolicyNames = map[PRPolicy]string{
	PRNone: "PRNone",
	PRTTL:  "PRTTL",
	PRRtx:  "PRRtx",
	PRPrio: "PRPrio",
	PRAll:  "PRAll",
}

func (p PRPolicy) String() string {
	if name, ok := prPolicyNames[p]; ok {
		return name
	}
	return fmt.Sprintf("PRPolicy(%d)", uint16(p))
}

// Scheduler is a stream scheduler, RFC 8260 §3. Linux implements five
// (enum sctp_sched_type, include/uapi/linux/sctp.h).
type Scheduler uint32

const (
	SchedFCFS Scheduler = iota // default
	SchedPrio
	SchedRR
	SchedFC
	SchedWFQ
)

var schedulerNames = map[Scheduler]string{
	SchedFCFS: "SchedFCFS",
	SchedPrio: "SchedPrio",
	SchedRR:   "SchedRR",
	SchedFC:   "SchedFC",
	SchedWFQ:  "SchedWFQ",
}

func (s Scheduler) String() string {
	if name, ok := schedulerNames[s]; ok {
		return name
	}
	return fmt.Sprintf("Scheduler(%d)", uint32(s))
}

// FragmentInterleave is SCTP_FRAGMENT_INTERLEAVE (RFC 6458 §8.1.20); the
// kernel option is a plain C int.
type FragmentInterleave int32

const (
	InterleaveNone    FragmentInterleave = iota
	InterleaveAssocs                     // across associations
	InterleaveStreams                    // across streams: Linux cannot, returns ErrUnsupported
)

var fragmentInterleaveNames = map[FragmentInterleave]string{
	InterleaveNone:    "InterleaveNone",
	InterleaveAssocs:  "InterleaveAssocs",
	InterleaveStreams: "InterleaveStreams",
}

func (l FragmentInterleave) String() string {
	if name, ok := fragmentInterleaveNames[l]; ok {
		return name
	}
	return fmt.Sprintf("FragmentInterleave(%d)", int32(l))
}

// PFExposure controls whether a Potentially Failed path (RFC 7829) is
// reported through PathInfo and PeerAddrChange. The values are Linux's own
// (include/net/sctp/constants.h's SCTP_PF_EXPOSE_*), not in the UAPI header.
type PFExposure uint32

const (
	PFExposeUnset    PFExposure = iota // follow net.sctp.pf_expose
	PFExposeDisabled                   // PathInfo on a PF path fails with EACCES
	PFExposeEnabled                    // PF reported by PathInfo and by PeerAddrChange
)

var pfExposureNames = map[PFExposure]string{
	PFExposeUnset:    "PFExposeUnset",
	PFExposeDisabled: "PFExposeDisabled",
	PFExposeEnabled:  "PFExposeEnabled",
}

func (e PFExposure) String() string {
	if name, ok := pfExposureNames[e]; ok {
		return name
	}
	return fmt.Sprintf("PFExposure(%d)", uint32(e))
}

// StreamResetMask enables stream-reconfiguration request kinds, RFC 6525
// §6.3 (SCTP_ENABLE_STREAM_RESET, include/uapi/linux/sctp.h). Its String
// joins the names of its set bits with "|" and renders any bits it does not
// name as a trailing hexadecimal literal, the same rule SendFlags uses
// below.
type StreamResetMask uint32

const (
	EnableResetStreamReq StreamResetMask = 0x01
	EnableResetAssocReq  StreamResetMask = 0x02
	EnableChangeAssocReq StreamResetMask = 0x04
)

var streamResetMaskBits = []struct {
	bit  StreamResetMask
	name string
}{
	{EnableResetStreamReq, "EnableResetStreamReq"},
	{EnableResetAssocReq, "EnableResetAssocReq"},
	{EnableChangeAssocReq, "EnableChangeAssocReq"},
}

func (m StreamResetMask) String() string {
	return joinBits(m, streamResetMaskBits)
}

// ResetDirection selects which of an association's stream directions a
// StreamReset request covers, RFC 6525 §6.3.2 (strreset_flags,
// include/uapi/linux/sctp.h). Unlike StreamResetMask it is a plain
// enumeration in this API — ResetStreams takes one value, never a
// combination — so it follows the ordinary constant-name rule.
type ResetDirection uint16

const (
	ResetIncoming ResetDirection = 0x01
	ResetOutgoing ResetDirection = 0x02
)

var resetDirectionNames = map[ResetDirection]string{
	ResetIncoming: "ResetIncoming",
	ResetOutgoing: "ResetOutgoing",
}

func (d ResetDirection) String() string {
	if name, ok := resetDirectionNames[d]; ok {
		return name
	}
	return fmt.Sprintf("ResetDirection(%d)", uint16(d))
}

// HMACID is an RFC 4895 §3.3 HMAC algorithm identifier, from its IANA
// registry ("Hash Function Identifiers" of RFC 4895's SCTP-AUTH registry).
type HMACID uint16

const (
	HMACSHA1   HMACID = 1 // mandatory to implement
	HMACSHA256 HMACID = 3
)

var hmacidNames = map[HMACID]string{
	HMACSHA1:   "HMACSHA1",
	HMACSHA256: "HMACSHA256",
}

func (h HMACID) String() string {
	if name, ok := hmacidNames[h]; ok {
		return name
	}
	return fmt.Sprintf("HMACID(%d)", uint16(h))
}

// ErrorCause is an RFC 9260 §3.3.10 error cause, from IANA's "SCTP Error
// Cause Codes" registry (https://www.iana.org/assignments/sctp-parameters).
//
// CauseRestartNewEncapPort (14) is unassigned by IANA, which lists 14-99 as
// Unassigned: its code and name come from
// draft-tuexen-tsvwg-sctp-udp-encaps-cons-10 §4, an Internet-Draft that
// expired without becoming an RFC and so is not a normative source — only
// what Linux actually implements from it. include/linux/sctp.h defines
// SCTP_ERROR_NEW_ENCAP_PORT as 14, and net/sctp/sm_statefuns.c's
// sctp_sf_new_encap_port sends it in an ABORT's cause when an INIT arrives
// for an existing association over the wrong UDP encapsulation port (RFC
// 6951, updated by RFC 8899).
//
// CauseNone (0) is not a wire value at all: it is this package's own
// sentinel for an association failure that carried no cause (see
// AssocChange.Error). IANA has no entry for 0 either; the name CauseNone
// renders is Linux's own SCTP_ERROR_NO_ERROR (include/linux/sctp.h).
type ErrorCause uint16

const (
	CauseNone                ErrorCause = 0
	CauseInvalidStream       ErrorCause = 1
	CauseMissingParam        ErrorCause = 2
	CauseStaleCookie         ErrorCause = 3
	CauseOutOfResource       ErrorCause = 4
	CauseUnresolvableAddr    ErrorCause = 5
	CauseUnrecognizedChunk   ErrorCause = 6
	CauseInvalidParam        ErrorCause = 7
	CauseUnrecognizedParams  ErrorCause = 8
	CauseNoUserData          ErrorCause = 9
	CauseCookieInShutdown    ErrorCause = 10
	CauseRestartNewAddrs     ErrorCause = 11
	CauseUserAbort           ErrorCause = 12
	CauseProtocolViolation   ErrorCause = 13
	CauseRestartNewEncapPort ErrorCause = 14    // Linux only; unassigned by IANA
	CauseDeleteLastAddr      ErrorCause = 0xa0  // RFC 5061
	CauseResourceShortage    ErrorCause = 0xa1  // RFC 5061
	CauseDeleteSourceAddr    ErrorCause = 0xa2  // RFC 5061
	CauseIllegalASCONFAck    ErrorCause = 0xa3  // RFC 5061
	CauseRequestRefused      ErrorCause = 0xa4  // RFC 5061
	CauseUnsupportedHMAC     ErrorCause = 0x105 // RFC 4895
)

// errorCauseIANANames holds the name ErrorCause.String prints for every
// cause this package names: the IANA "SCTP Error Cause Codes" registry name
// for the codes IANA defines, and Linux's own constant name, in prose form,
// for the two it does not (CauseNone and CauseRestartNewEncapPort — see
// ErrorCause's doc comment for both).
var errorCauseIANANames = map[ErrorCause]string{
	CauseNone:                "No Error",
	CauseInvalidStream:       "Invalid Stream Identifier",
	CauseMissingParam:        "Missing Mandatory Parameter",
	CauseStaleCookie:         "Stale Cookie",
	CauseOutOfResource:       "Out of Resource",
	CauseUnresolvableAddr:    "Unresolvable Address",
	CauseUnrecognizedChunk:   "Unrecognized Chunk Type",
	CauseInvalidParam:        "Invalid Mandatory Parameter",
	CauseUnrecognizedParams:  "Unrecognized Parameters",
	CauseNoUserData:          "No User Data",
	CauseCookieInShutdown:    "Cookie Received While Shutting Down",
	CauseRestartNewAddrs:     "Restart of an Association with New Addresses",
	CauseUserAbort:           "User-Initiated Abort",
	CauseProtocolViolation:   "Protocol Violation",
	CauseRestartNewEncapPort: "Restart of an Association with New Encapsulation Port",
	CauseDeleteLastAddr:      "Request to Delete Last Remaining IP Address",
	CauseResourceShortage:    "Operation Refused Due to Resource Shortage",
	CauseDeleteSourceAddr:    "Request to Delete Source IP Address",
	CauseIllegalASCONFAck:    "Association Aborted due to illegal ASCONF-ACK",
	CauseRequestRefused:      "Request refused - no authorization",
	CauseUnsupportedHMAC:     "Unsupported HMAC Identifier",
}

// String returns the name errorCauseIANANames gives the cause, e.g.
// "Stale Cookie" or "No Error". A cause the package does not name renders
// as ErrorCause(n), e.g. ErrorCause(1000).
func (c ErrorCause) String() string {
	if name, ok := errorCauseIANANames[c]; ok {
		return name
	}
	return fmt.Sprintf("ErrorCause(%d)", uint16(c))
}

// AbandonPolicy says how Dial releases an association that has not reached
// ESTABLISHED when ctx ends or setup fails. It never reaches the kernel, so
// it has no UAPI counterpart.
type AbandonPolicy uint8

const (
	AbandonAbort AbandonPolicy = iota // default: abortive release (RFC 9260 §9.1)
	AbandonQuiet                      // close without arming an ABORT
)

var abandonPolicyNames = map[AbandonPolicy]string{
	AbandonAbort: "AbandonAbort",
	AbandonQuiet: "AbandonQuiet",
}

func (p AbandonPolicy) String() string {
	if name, ok := abandonPolicyNames[p]; ok {
		return name
	}
	return fmt.Sprintf("AbandonPolicy(%d)", uint8(p))
}

// SendFlags are SendOptions.Info.Flags bits (struct sctp_sndinfo's
// snd_flags, include/uapi/linux/sctp.h's enum sctp_sinfo_flags). String
// joins the names of its set bits with "|" and renders any bits it does not
// name as a trailing hexadecimal literal, e.g.
// SendFlags(0x21).String() == "SendUnordered|0x20".
type SendFlags uint16

const (
	SendUnordered       SendFlags = 1 << 0 // SCTP_UNORDERED
	SendSACKImmediately SendFlags = 1 << 3 // SCTP_SACK_IMMEDIATELY: the I bit, RFC 9260 §§3.3.1, 11.1.5
)

var sendFlagsBits = []struct {
	bit  SendFlags
	name string
}{
	{SendUnordered, "SendUnordered"},
	{SendSACKImmediately, "SendSACKImmediately"},
}

func (f SendFlags) String() string {
	return joinBits(f, sendFlagsBits)
}

// joinBits implements the SendFlags and StreamResetMask String rule: the
// ordered names of bits set in v, joined by "|", with any bits none of names
// cover appended as one trailing hexadecimal literal. A zero v with nothing
// to report still prints as "0x0", consistent with "unnamed bits render as
// hex". One generic function serves both bit widths since the logic does
// not depend on which of the two v is.
func joinBits[T ~uint16 | ~uint32](v T, names []struct {
	bit  T
	name string
}) string {
	var b strings.Builder
	rem := v
	for _, e := range names {
		if e.bit != 0 && rem&e.bit == e.bit {
			if b.Len() > 0 {
				b.WriteByte('|')
			}
			b.WriteString(e.name)
			rem &^= e.bit
		}
	}
	if rem != 0 || b.Len() == 0 {
		if b.Len() > 0 {
			b.WriteByte('|')
		}
		// uint64(rem), not rem itself: T's String method (this one) is what
		// %x would otherwise call first — fmt tries Stringer before numeric
		// formatting for any verb, %x included — recursing forever. uint64
		// has no String method and is wide enough for both T's instances.
		fmt.Fprintf(&b, "0x%x", uint64(rem))
	}
	return b.String()
}

// EventType names a notification kind, the Linux enum sctp_sn_type's sn_type
// values (include/uapi/linux/sctp.h; RFC 6458 §6). It also names the
// subscription passed to Config.Notifications and Conn.Subscribe.
type EventType uint16

const (
	EventAssocChange          EventType = 0x8001
	EventPeerAddrChange       EventType = 0x8002
	EventRemoteError          EventType = 0x8004
	EventShutdown             EventType = 0x8005
	EventPartialDelivery      EventType = 0x8006
	EventAdaptationIndication EventType = 0x8007
	EventAuthentication       EventType = 0x8008
	EventSenderDry            EventType = 0x8009
	EventStreamReset          EventType = 0x800a
	EventAssocReset           EventType = 0x800b
	EventStreamChange         EventType = 0x800c
	EventSendFailed           EventType = 0x800d // SCTP_SEND_FAILED_EVENT (RFC 6458 §6.1.11)
)

var eventTypeNames = map[EventType]string{
	EventAssocChange:          "EventAssocChange",
	EventPeerAddrChange:       "EventPeerAddrChange",
	EventRemoteError:          "EventRemoteError",
	EventShutdown:             "EventShutdown",
	EventPartialDelivery:      "EventPartialDelivery",
	EventAdaptationIndication: "EventAdaptationIndication",
	EventAuthentication:       "EventAuthentication",
	EventSenderDry:            "EventSenderDry",
	EventStreamReset:          "EventStreamReset",
	EventAssocReset:           "EventAssocReset",
	EventStreamChange:         "EventStreamChange",
	EventSendFailed:           "EventSendFailed",
}

func (t EventType) String() string {
	if name, ok := eventTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("EventType(%d)", uint16(t))
}

// AssocChangeState is AssocChange.State, the Linux enum sctp_sac_state
// (sac_state, include/uapi/linux/sctp.h; RFC 6458 §6.1.1).
type AssocChangeState uint16

const (
	AssocCommUp AssocChangeState = iota
	AssocCommLost
	AssocRestart
	AssocShutdownComplete
	AssocCantStart
)

var assocChangeStateNames = map[AssocChangeState]string{
	AssocCommUp:           "AssocCommUp",
	AssocCommLost:         "AssocCommLost",
	AssocRestart:          "AssocRestart",
	AssocShutdownComplete: "AssocShutdownComplete",
	AssocCantStart:        "AssocCantStart",
}

func (s AssocChangeState) String() string {
	if name, ok := assocChangeStateNames[s]; ok {
		return name
	}
	return fmt.Sprintf("AssocChangeState(%d)", uint16(s))
}

// AddrChangeState is PeerAddrChange.State, the Linux enum sctp_spc_state
// (spc_state, a C int, include/uapi/linux/sctp.h; RFC 6458 §6.1.2).
type AddrChangeState int32

const (
	AddrAvailable AddrChangeState = iota
	AddrUnreachable
	AddrRemoved
	AddrAdded
	AddrMadePrimary
	AddrConfirmed
	AddrPotentiallyFailed // only with PFExposeEnabled
)

var addrChangeStateNames = map[AddrChangeState]string{
	AddrAvailable:         "AddrAvailable",
	AddrUnreachable:       "AddrUnreachable",
	AddrRemoved:           "AddrRemoved",
	AddrAdded:             "AddrAdded",
	AddrMadePrimary:       "AddrMadePrimary",
	AddrConfirmed:         "AddrConfirmed",
	AddrPotentiallyFailed: "AddrPotentiallyFailed",
}

func (s AddrChangeState) String() string {
	if name, ok := addrChangeStateNames[s]; ok {
		return name
	}
	return fmt.Sprintf("AddrChangeState(%d)", int32(s))
}

// AuthIndication is AuthEvent.Indication, Linux's anonymous enum for
// auth_indication (include/uapi/linux/sctp.h; RFC 6458 §6.1.8).
type AuthIndication uint32

const (
	AuthNewKey AuthIndication = iota
	AuthFreeKey
	AuthNoAuth
)

var authIndicationNames = map[AuthIndication]string{
	AuthNewKey:  "AuthNewKey",
	AuthFreeKey: "AuthFreeKey",
	AuthNoAuth:  "AuthNoAuth",
}

func (i AuthIndication) String() string {
	if name, ok := authIndicationNames[i]; ok {
		return name
	}
	return fmt.Sprintf("AuthIndication(%d)", uint32(i))
}

// AddrChangeReason is PeerAddrChange.Reason, decoded from Linux's enum
// sctp_sn_error (spc_error, a C int, include/uapi/linux/sctp.h). Unlike
// this package's other kernel-sourced enumerations, its constants are not
// numbered exactly as the kernel's: Linux sends a raw spc_error of 0 for
// both "no reason" and its own first member, SCTP_FAILED_THRESHOLD, so
// ReasonNone is inserted ahead of the kernel's sequence here, and every
// named reason after it — ReasonFailedThreshold on — sits one past its raw
// kernel value. ParseNotification resolves which of the two a raw 0 means
// by state (AddrUnreachable or not) when it decodes spc_error into one of
// these constants; that resolution is why the constants have this shape.
//
// A raw value the kernel's own enum never produces renders as
// AddrChangeReason(n): a positive raw n (other than the six the kernel
// defines) as AddrChangeReason(n+1), same as any named reason; a negative
// raw n, or the largest value a C int holds, as AddrChangeReason(n)
// unshifted, since shifting either would either land on a number this type
// already assigns to some other raw (raw -1 shifted would read as
// ReasonNone's own 0) or have no int32 representation to shift to at all.
type AddrChangeReason int32

const (
	ReasonNone             AddrChangeReason = iota
	ReasonFailedThreshold                   // path exceeded its retransmission threshold
	ReasonReceivedSACK                      // path returned because a SACK arrived on it
	ReasonHeartbeatSuccess                  // path confirmed or recovered by a HEARTBEAT-ACK
	ReasonResponseToUserReq
	ReasonInternalError
	ReasonShutdownGuardExpires
	ReasonPeerFaulty
)

var addrChangeReasonNames = map[AddrChangeReason]string{
	ReasonNone:                 "ReasonNone",
	ReasonFailedThreshold:      "ReasonFailedThreshold",
	ReasonReceivedSACK:         "ReasonReceivedSACK",
	ReasonHeartbeatSuccess:     "ReasonHeartbeatSuccess",
	ReasonResponseToUserReq:    "ReasonResponseToUserReq",
	ReasonInternalError:        "ReasonInternalError",
	ReasonShutdownGuardExpires: "ReasonShutdownGuardExpires",
	ReasonPeerFaulty:           "ReasonPeerFaulty",
}

func (r AddrChangeReason) String() string {
	if name, ok := addrChangeReasonNames[r]; ok {
		return name
	}
	return fmt.Sprintf("AddrChangeReason(%d)", int32(r))
}
