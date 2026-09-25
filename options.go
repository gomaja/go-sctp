// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// options.go declares the value types the typed socket options (Config's
// InitMsg, RTOInfo and DelayedSACK, and the Conn and Endpoint getters and
// setters added later) read and write, plus validatePrInfo, the PR-SCTP
// check config.go's DefaultPrInfo handling shares with msginfo.go's
// per-message validateSendOptions rather than duplicating.
//
// Every type here is portable: it carries no kernel offset or byte layout
// of its own (abi.go has those) and no build tag. Marshalling a value to or
// from the kernel's own struct shape is a platform concern for later.

package sctp

import (
	"math"
	"net/netip"
	"time"
)

// InitMsg is struct sctp_initmsg (RFC 6458 §8.1.3). The zero value leaves
// every field at the kernel default.
type InitMsg struct {
	OutStreams     uint16
	MaxInStreams   uint16
	MaxAttempts    uint16
	MaxInitTimeout time.Duration
}

// RTOInfo is struct sctp_rtoinfo (RFC 6458 §8.1.1). Each field is settable
// independently: a zero field leaves that value unchanged
// (net/sctp/socket.c: sctp_setsockopt_rtoinfo checks each of
// srto_initial/srto_max/srto_min against zero before applying it).
type RTOInfo struct {
	Initial, Max, Min time.Duration
}

// AssocInfo is struct sctp_assocparams (RFC 6458 §8.1.2). MaxRetrans and
// CookieLife are settable, and a zero value leaves the current one unchanged
// (net/sctp/socket.c: sctp_setsockopt_associnfo); PeerDestinations,
// PeerRwnd and LocalRwnd are read only, filled by a get and ignored by a
// set.
type AssocInfo struct {
	MaxRetrans       uint16        // settable; zero = unchanged
	CookieLife       time.Duration // settable; zero = unchanged
	PeerDestinations uint16        // read-only
	PeerRwnd         uint32        // read-only
	LocalRwnd        uint32        // read-only
}

// DelayedSACK is struct sctp_sack_info (RFC 6458 §8.1.19). The zero value
// leaves both fields unchanged. Delay is at most 500 ms
// (RFC 9260 §6.2's MUST NOT; net/sctp/socket.c:
// __sctp_setsockopt_delayed_ack refuses more outright). Frequency of 1
// disables delayed SACK.
type DelayedSACK struct {
	Delay     time.Duration
	Frequency uint32
}

// PathParams is struct sctp_paddrparams (RFC 6458 §8.1.12). A nil field
// leaves that setting unchanged; PathMTU only takes effect with PMTUD set
// to false. DelayedSACK and SACKDelay are a Linux extension to the RFC's
// struct, the per-path counterpart of Config.DelayedSACK.
type PathParams struct {
	Heartbeat         *bool
	HeartbeatInterval *time.Duration // 0 = SPP_HB_TIME_IS_ZERO
	PathMaxRetrans    *uint16
	PMTUD             *bool
	PathMTU           *uint32        // only with PMTUD false
	DelayedSACK       *bool          // Linux extension
	SACKDelay         *time.Duration // Linux extension
	IPv6FlowLabel     *uint32
	DSCP              *uint8
}

// PathThresholds is struct sctp_paddrthlds_v2 (RFC 7829 §7.2). A nil field
// leaves that threshold unchanged.
type PathThresholds struct {
	PathMaxRetrans    *uint16 // path declared inactive when exceeded
	PFThreshold       *uint16 // path enters Potentially Failed when exceeded
	PrimarySwitchover *uint16 // primary path switchover (RFC 7829 §5); 0xffff disables
}

// PathInfo is struct sctp_paddrinfo (RFC 6458 §8.2.2).
type PathInfo struct {
	Addr  netip.AddrPort
	State PathState
	Cwnd  uint32

	// SRTTTicks is spinfo_srtt, copied from the association's transport
	// straight off (net/sctp/socket.c: "pinfo.spinfo_srtt =
	// transport->srtt"), in kernel ticks (jiffies), not the milliseconds
	// RFC 6458 §8.2.2 specifies. A tick's length depends on the kernel's
	// CONFIG_HZ, which no socket or libc call reports — sysconf(_SC_CLK_TCK)
	// gives USER_HZ, a fixed userspace-facing constant, not the kernel's own
	// HZ — so this field is a plain integer, useful only for comparison.
	SRTTTicks uint32

	RTO time.Duration
	MTU uint32
}

// Status is struct sctp_status (RFC 6458 §8.2.1).
type Status struct {
	State              AssocState
	PeerRwnd           uint32
	Unacked            uint16
	Pending            uint16
	InStreams          uint16
	OutStreams         uint16
	FragmentationPoint uint32
	Primary            PathInfo
}

// AssocStats is Linux's struct sctp_assoc_stats, not part of RFC 6458.
type AssocStats struct {
	// MaxRTOTicks is sas_maxrto, copied from the association's own observed
	// maximum (net/sctp/socket.c: "sas.sas_maxrto =
	// asoc->stats.max_obs_rto"), in kernel ticks like PathInfo.SRTTTicks
	// above, and reset by this read.
	MaxRTOTicks uint64
	MaxRTOAddr  netip.AddrPort

	SACKsIn, SACKsOut                     uint64
	PacketsIn, PacketsOut                 uint64
	RetransChunks                         uint64
	OutOfSeqTSNs                          uint64
	DupChunksIn                           uint64
	GapAcksIn                             uint64
	UnorderedChunksIn, UnorderedChunksOut uint64
	OrderedChunksIn, OrderedChunksOut     uint64
	ControlChunksIn, ControlChunksOut     uint64
}

// PRStatus is struct sctp_prstatus (RFC 7496 §§4.3-4.4): the abandoned
// message counts for one stream and PR-SCTP policy, or a totals query
// across every stream or policy (PRAll).
type PRStatus struct {
	AbandonedUnsent uint64
	AbandonedSent   uint64
}

// validatePrInfo checks pr's Policy and TTL, matching the mask
// net/sctp/socket.c's sctp_msghdr_parse applies to a per-message PRINFO
// (msginfo.go's validateSendOptions, which calls this with "SendOptions.PR")
// and Config.DefaultPrInfo (config.go, which calls this with
// "Config.DefaultPrInfo"). field is the caller's own field path, used to
// name what was refused; a refusal matches syscall.EINVAL and touches no
// system call.
//
// The policy check mirrors sctp_msghdr_parse's own mask test: "if
// (cmsgs->prinfo->pr_policy & ~SCTP_PR_SCTP_MASK) return -EINVAL;". PRAll
// (0x0080, RFC 7496 §§4.3-4.4's SCTP_PR_ASSOC_STATUS/SCTP_PR_STREAM_STATUS
// aggregate-query value) and any bit outside the two-bit policy field both
// fail that one mask test — PRAll is never a valid policy to set, only a
// query answer. The TTL checks have no kernel counterpart to mirror: they
// exist because this package converts a time.Duration to the uint32
// millisecond count struct sctp_prinfo's pr_value carries, a conversion the
// kernel itself never performs.
func validatePrInfo(field string, pr *PrInfo) error {
	if pr.Policy&^PRPolicy(prPolicyMask) != 0 {
		if pr.Policy == PRAll {
			return invalidArg("%s.Policy is PRAll, which RFC 7496 §§4.3-4.4 define only for a status query, not a per-message send", field)
		}
		return invalidArg("%s.Policy %#04x is not a known PR-SCTP policy", field, uint16(pr.Policy))
	}

	if pr.Policy == PRTTL {
		if pr.TTL < 0 {
			return invalidArg("%s.TTL %s is negative", field, pr.TTL)
		}
		if pr.TTL%time.Millisecond != 0 {
			return invalidArg("%s.TTL %s is not a whole number of milliseconds", field, pr.TTL)
		}
		if pr.TTL/time.Millisecond > math.MaxUint32 {
			return invalidArg("%s.TTL %s exceeds the uint32 millisecond range struct sctp_prinfo's pr_value carries", field, pr.TTL)
		}
	}

	return nil
}

// resolvePrInfo converts a validated pr to the kernel's own two-field
// encoding: pr_policy, a plain copy of Policy, and pr_value, which RFC 6458
// §5.3.7 and RFC 7496 §4.2's table define per policy — the TTL in whole
// milliseconds for PRTTL, the retransmission count or priority for
// PRRtx/PRPrio. An explicit PRNone always resolves to a pr_value of 0,
// whatever pr.TTL or pr.Value holds, matching net/sctp/socket.c's own
// handling of an explicit SCTP_PR_SCTP_NONE cmsg ("if
// (cmsgs->prinfo->pr_policy == SCTP_PR_SCTP_NONE) cmsgs->prinfo->pr_value =
// 0;"). pr must already have passed validatePrInfo, so the TTL-to-ms
// division below cannot lose precision or overflow.
//
// Shared by msginfo.go's appendSendCmsgs (the per-message PRINFO cmsg) and
// config.go's DefaultPrInfo handling (SCTP_DEFAULT_PRINFO): struct
// sctp_prinfo and struct sctp_default_prinfo give pr_value the same
// per-policy meaning, at the same offset (4) in both (abi.go:
// prInfoValueOff, defaultPRInfoValueOff) — only pr_policy's offset differs
// between the two (0 vs. 8), because sctp_default_prinfo's leading
// pr_assoc_id has no counterpart in the per-message cmsg.
func resolvePrInfo(pr *PrInfo) (policy uint16, value uint32) {
	switch pr.Policy {
	case PRNone:
		return uint16(pr.Policy), 0
	case PRTTL:
		return uint16(pr.Policy), uint32(pr.TTL / time.Millisecond)
	default: // PRRtx, PRPrio
		return uint16(pr.Policy), pr.Value
	}
}
