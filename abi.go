// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// abi.go is the single home for the kernel numbers and struct layouts the
// package uses: option numbers, control-message types, send-flag bits,
// and the field offsets used to encode and decode kernel structures
// byte-wise with binary.NativeEndian (host-order fields) and
// binary.BigEndian (network-order fields), rather than through Go structs
// laid out by the compiler. That is what lets the layout tests in
// abi_test.go exercise the Linux ABI on every platform this package builds
// for — nothing here depends on GOOS, so the file carries no build tag.
//
// Every number cites the UAPI symbol it names and the kernel source it was
// checked against: include/uapi/linux/sctp.h (option numbers, cmsg types,
// send-flag bits, struct sizes and offsets; notification type values are
// instead the EventType constants of enums.go, which already are the wire
// values), include/linux/socket.h (AF_INET, AF_INET6, and MSG_FIN, which
// SCTP_EOF aliases) and include/uapi/linux/socket.h (struct
// __kernel_sockaddr_storage). All were read from the flattened Linux 6.12
// sources at go-sctp-kernel-6.12-sources/, except include/linux/socket.h
// and include/uapi/linux/socket.h, which are not in that flattened set and
// were fetched at tag v6.12 from
// https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/.
//
// What is deliberately not here: the deprecated RFC 6458 mechanisms
// (SCTP_SNDRCV, SCTP_EVENTS, SCTP_DEFAULT_SEND_PARAM, the legacy
// SCTP_SEND_FAILED) and the superseded kernel option variants this package
// does not use (the old CONNECTX and CONNECTX_OLD in favor of CONNECTX3
// alone, the original SCTP_SOCKOPT_PEELOFF in favor of its _FLAGS form,
// and the two-field SCTP_PEER_ADDR_THLDS in favor of _V2) — none of their
// numbers or layouts are defined below. SO_RCVBUF, SO_SNDBUF, SO_PROTOCOL,
// SO_TYPE and SO_ACCEPTCONN are SOL_SOCKET options with no SCTP-specific
// meaning; the package uses the constants the standard syscall package
// already exports for those (syscall.SO_RCVBUF and so on) instead of
// duplicating them here.

package sctp

import "math/bits"

// ---------------------------------------------------------------------
// Address families (include/linux/socket.h, v6.12, lines 193 and 201).
// ---------------------------------------------------------------------

const (
	afInet  = 2  // AF_INET
	afInet6 = 10 // AF_INET6
)

// ---------------------------------------------------------------------
// Reserved association-scope selectors, RFC 6458 §7.2
// (include/uapi/linux/sctp.h, v6.12, lines 62-64). They are values an
// sctp_assoc_t field may carry to mean "every future association", "the
// association in progress" or "every association", never a real
// association id. Endpoint.SendMsg and the AssocID-taking calls reject
// them, as v1 did.
// ---------------------------------------------------------------------

const (
	assocScopeFuture  = 0 // SCTP_FUTURE_ASSOC
	assocScopeCurrent = 1 // SCTP_CURRENT_ASSOC
	assocScopeAll     = 2 // SCTP_ALL_ASSOC
)

// ---------------------------------------------------------------------
// getsockopt/setsockopt option numbers, level IPPROTO_SCTP
// (include/uapi/linux/sctp.h).
// ---------------------------------------------------------------------

const (
	optRTOInfo              = 0  // SCTP_RTOINFO
	optAssocInfo            = 1  // SCTP_ASSOCINFO
	optInitMsg              = 2  // SCTP_INITMSG
	optNoDelay              = 3  // SCTP_NODELAY
	optAutoClose            = 4  // SCTP_AUTOCLOSE
	optSetPeerPrimaryAddr   = 5  // SCTP_SET_PEER_PRIMARY_ADDR
	optPrimaryAddr          = 6  // SCTP_PRIMARY_ADDR
	optAdaptationLayer      = 7  // SCTP_ADAPTATION_LAYER
	optDisableFragments     = 8  // SCTP_DISABLE_FRAGMENTS
	optPeerAddrParams       = 9  // SCTP_PEER_ADDR_PARAMS
	optWantMappedV4Addr     = 12 // SCTP_I_WANT_MAPPED_V4_ADDR
	optMaxSeg               = 13 // SCTP_MAXSEG
	optStatus               = 14 // SCTP_STATUS
	optGetPeerAddrInfo      = 15 // SCTP_GET_PEER_ADDR_INFO
	optDelayedAckTime       = 16 // SCTP_DELAYED_ACK_TIME (aka SCTP_DELAYED_SACK)
	optContext              = 17 // SCTP_CONTEXT
	optFragmentInterleave   = 18 // SCTP_FRAGMENT_INTERLEAVE
	optPartialDeliveryPoint = 19 // SCTP_PARTIAL_DELIVERY_POINT
	optMaxBurst             = 20 // SCTP_MAX_BURST
	optAuthChunk            = 21 // SCTP_AUTH_CHUNK
	optHMACIdent            = 22 // SCTP_HMAC_IDENT
	optAuthKey              = 23 // SCTP_AUTH_KEY
	optAuthActiveKey        = 24 // SCTP_AUTH_ACTIVE_KEY
	optAuthDeleteKey        = 25 // SCTP_AUTH_DELETE_KEY
	optPeerAuthChunks       = 26 // SCTP_PEER_AUTH_CHUNKS (read only)
	optLocalAuthChunks      = 27 // SCTP_LOCAL_AUTH_CHUNKS (read only)
	optGetAssocNumber       = 28 // SCTP_GET_ASSOC_NUMBER (read only)
	optGetAssocIDList       = 29 // SCTP_GET_ASSOC_ID_LIST (read only)
	optAutoAsconf           = 30 // SCTP_AUTO_ASCONF
	optRecvRcvInfo          = 32 // SCTP_RECVRCVINFO
	optRecvNxtInfo          = 33 // SCTP_RECVNXTINFO
	optDefaultSndInfo       = 34 // SCTP_DEFAULT_SNDINFO
	optAuthDeactivateKey    = 35 // SCTP_AUTH_DEACTIVATE_KEY
	optReusePort            = 36 // SCTP_REUSE_PORT
	optPathThresholds       = 37 // SCTP_PEER_ADDR_THLDS_V2

	optSockoptBindxAdd              = 100 // SCTP_SOCKOPT_BINDX_ADD
	optSockoptBindxRemove           = 101 // SCTP_SOCKOPT_BINDX_REM
	optGetPeerAddrs                 = 108 // SCTP_GET_PEER_ADDRS
	optGetLocalAddrs                = 109 // SCTP_GET_LOCAL_ADDRS
	optSockoptConnectx3             = 111 // SCTP_SOCKOPT_CONNECTX3
	optGetAssocStats                = 112 // SCTP_GET_ASSOC_STATS (read only)
	optPRSupported                  = 113 // SCTP_PR_SUPPORTED
	optDefaultPRInfo                = 114 // SCTP_DEFAULT_PRINFO
	optPRAssocStatus                = 115 // SCTP_PR_ASSOC_STATUS
	optPRStreamStatus               = 116 // SCTP_PR_STREAM_STATUS
	optReconfigSupported            = 117 // SCTP_RECONFIG_SUPPORTED
	optEnableStreamReset            = 118 // SCTP_ENABLE_STREAM_RESET
	optResetStreams                 = 119 // SCTP_RESET_STREAMS
	optResetAssoc                   = 120 // SCTP_RESET_ASSOC
	optAddStreams                   = 121 // SCTP_ADD_STREAMS
	optSockoptPeeloffFlags          = 122 // SCTP_SOCKOPT_PEELOFF_FLAGS
	optStreamScheduler              = 123 // SCTP_STREAM_SCHEDULER
	optStreamSchedulerValue         = 124 // SCTP_STREAM_SCHEDULER_VALUE
	optInterleavingSupported        = 125 // SCTP_INTERLEAVING_SUPPORTED
	optEvent                        = 127 // SCTP_EVENT
	optASCONFSupported              = 128 // SCTP_ASCONF_SUPPORTED
	optAuthSupported                = 129 // SCTP_AUTH_SUPPORTED
	optECNSupported                 = 130 // SCTP_ECN_SUPPORTED
	optExposePotentiallyFailedState = 131 // SCTP_EXPOSE_POTENTIALLY_FAILED_STATE (aka SCTP_EXPOSE_PF_STATE)
	optRemoteUDPEncapsPort          = 132 // SCTP_REMOTE_UDP_ENCAPS_PORT
	optPLPMTUDProbeInterval         = 133 // SCTP_PLPMTUD_PROBE_INTERVAL
)

// ---------------------------------------------------------------------
// cmsg_type values (typedef enum sctp_cmsg_type, include/uapi/linux/sctp.h).
// SCTP_INIT (0) is a control-message type only: sctp_msghdr_parse
// (net/sctp/socket.c) accepts it solely as sendmsg() ancillary data, an
// alternative to the separate SCTP_INITMSG socket option (optInitMsg, 2,
// above) for the one sendmsg() call that starts an association — the two
// happen to share struct sctp_initmsg's shape but are otherwise unrelated,
// and Linux never delivers SCTP_INIT to recvmsg(). This package sends init
// parameters through Config.InitMsg (the option), never as this cmsg, so
// no constant for it is defined below. SCTP_SNDRCV (1, deprecated),
// SCTP_DSTADDRV4 (7) and SCTP_DSTADDRV6 (8) are likewise not used by this
// package and are not defined below.
// ---------------------------------------------------------------------

const (
	cmsgSndInfo  = 2 // SCTP_SNDINFO
	cmsgRcvInfo  = 3 // SCTP_RCVINFO
	cmsgNxtInfo  = 4 // SCTP_NXTINFO
	cmsgPrInfo   = 5 // SCTP_PRINFO
	cmsgAuthInfo = 6 // SCTP_AUTHINFO
)

// ---------------------------------------------------------------------
// Raw send-flag bits, enum sctp_sinfo_flags (include/uapi/linux/sctp.h).
// These are the kernel's own bit values for struct sctp_sndinfo's
// snd_flags / struct sctp_sndrcvinfo's sinfo_flags field. SendUnordered and
// SendSACKImmediately (enums.go) already equal sndFlagUnordered and
// sndFlagSackImmediately — those two are exported on SendOptions.Info.Flags;
// the rest are internal-only, used to build CloseAssoc's and AbortAssoc's
// empty sends and SendOptions.Path selection. SCTP_SENDALL (send to every
// association on a one-to-many socket at once) has no constant here: this
// package's Endpoint.SendMsg always names one association, so nothing ever
// builds that bit.
// ---------------------------------------------------------------------

const (
	sndFlagUnordered       = 1 << 0 // SCTP_UNORDERED
	sndFlagAddrOver        = 1 << 1 // SCTP_ADDR_OVER: send to SendOptions.Path instead of the primary
	sndFlagAbort           = 1 << 2 // SCTP_ABORT: AbortAssoc's empty send
	sndFlagSackImmediately = 1 << 3 // SCTP_SACK_IMMEDIATELY
	sndFlagPRAll           = 1 << 7 // SCTP_PR_SCTP_ALL
	msgNotification        = 0x8000 // MSG_NOTIFICATION (include/uapi/linux/sctp.h:180), aliased by
	// SCTP_NOTIFICATION in the same header's enum sctp_sinfo_flags.
	sndFlagEOF = 0x200 // MSG_FIN (include/linux/socket.h, v6.12 line 314), aliased by
	// SCTP_EOF: CloseAssoc's and a peeled-off Conn.Close's empty send.

	// prPolicyMask isolates the PR-SCTP policy bits (PRNone, PRTTL, PRRtx,
	// PRPrio — enums.go) from the flag bits above, all of which share the
	// same 16-bit snd_flags/sinfo_flags word (SCTP_PR_SCTP_MASK).
	prPolicyMask = 0x0030
)

// ---------------------------------------------------------------------
// sockaddr_in, sockaddr_in6 (include/uapi/linux/in.h and in6.h, v6.12) and
// sockaddr_storage (include/uapi/linux/socket.h, v6.12): sizes and field
// offsets, host order for the family field, network order for the port and
// address fields.
// ---------------------------------------------------------------------

const (
	// struct sockaddr_in { sin_family(2) sin_port(2) sin_addr(4) pad(8) }.
	sizeSockaddrIn      = 16
	sockaddrInFamilyOff = 0
	sockaddrInPortOff   = 2
	sockaddrInAddrOff   = 4

	// struct sockaddr_in6 { sin6_family(2) sin6_port(2) sin6_flowinfo(4)
	// sin6_addr(16) sin6_scope_id(4) }.
	sizeSockaddrIn6        = 28
	sockaddrIn6FamilyOff   = 0
	sockaddrIn6PortOff     = 2
	sockaddrIn6FlowInfoOff = 4
	sockaddrIn6AddrOff     = 8
	sockaddrIn6ScopeIDOff  = 24

	// sizeSockaddrStorage is sizeof(struct __kernel_sockaddr_storage): a
	// 128-byte union of { sa_family_t ss_family; char __data[126]; } and
	// void *__align, so its alignment follows the pointer size (ssAlign,
	// below) rather than the 2-byte alignment ss_family alone would need.
	sizeSockaddrStorage = 128
)

// wordSize is 4 on a 32-bit target and 8 on a 64-bit one. bits.UintSize is a
// compile-time constant (32 << (^uint(0) >> 63)), so every constant derived
// from it below is itself a constant — no build tag or init-time
// computation is needed, and GOARCH=386 still type-checks and computes the
// 32-bit numbers correctly even when cross-compiled from a 64-bit host.
const wordSize = bits.UintSize / 8

// ssAlign is sockaddr_storage's alignment on this word size: 4 on 32-bit,
// 8 on 64-bit (its trailing void *__align member). ssAddrOffset and
// ssTailOffset are the offset an embedded sockaddr_storage starts at, and
// the offset just past it, in any *non-packed* struct that places it right
// after one sctp_assoc_t (a 4-byte field) — sctp_udpencaps,
// sctp_probeinterval and sctp_paddrthlds_v2, below. Measured with a C probe
// over <linux/sctp.h> for both word sizes (ssAlign 4: addr 4, tail 132;
// ssAlign 8: addr 8, tail 136); TestSockaddrStorageLayoutFormula in
// abi_test.go recomputes the same formula against both rows at once.
const (
	ssAlign      = wordSize
	ssAddrOffset = (4 + ssAlign - 1) &^ (ssAlign - 1)
	ssTailOffset = ssAddrOffset + sizeSockaddrStorage
)

// ---------------------------------------------------------------------
// struct sctp_sndinfo, struct sctp_prinfo, struct sctp_authinfo,
// struct sctp_rcvinfo, struct sctp_nxtinfo (include/uapi/linux/sctp.h,
// §§5.3.4-5.3.8): the ancillary-data structures a sendmsg() call attaches
// to set per-message send parameters, and a recvmsg() call attaches to
// report per-message receive parameters. The constants below give each
// one's size and field offsets, for encoding and decoding these control
// messages byte-wise. None of the five structs is declared packed, but
// only two of the five need a compiler-inserted gap to keep every field on
// its own natural alignment:
//   - sctp_sndinfo (snd_sid, snd_flags) and sctp_nxtinfo (nxt_sid,
//     nxt_flags) each have their leading __u16 fields land on a multiple of
//     4 bytes total — two of them, 4 bytes — so the __u32 that follows
//     (snd_ppid, nxt_ppid) already lands on a 4-byte boundary with no gap.
//   - sctp_prinfo's single leading __u16 (pr_policy) is 2 bytes, and
//     sctp_rcvinfo's three (rcv_sid, rcv_ssn, rcv_flags) are 6 — neither a
//     multiple of 4 — so a 2-byte gap precedes the __u32 that follows in
//     each (pr_value, rcv_ppid; prInfoValueOff and rcvInfoPPIDOff, below,
//     are the offsets on the far side of each gap).
//   - sctp_authinfo has only its one __u16 field and needs no padding at
//     all.
// ---------------------------------------------------------------------

const (
	// struct sctp_sndinfo { snd_sid(2) snd_flags(2) snd_ppid(4) snd_context(4)
	// snd_assoc_id(4) }.
	sizeSndInfo       = 16
	sndInfoStreamOff  = 0
	sndInfoFlagsOff   = 2
	sndInfoPPIDOff    = 4
	sndInfoContextOff = 8
	sndInfoAssocIDOff = 12

	// struct sctp_prinfo { pr_policy(2) pad(2) pr_value(4) }.
	sizePrInfo      = 8
	prInfoPolicyOff = 0
	prInfoValueOff  = 4

	// struct sctp_authinfo { auth_keynumber(2) }.
	sizeAuthInfo         = 2
	authInfoKeyNumberOff = 0

	// struct sctp_rcvinfo { rcv_sid(2) rcv_ssn(2) rcv_flags(2) pad(2)
	// rcv_ppid(4) rcv_tsn(4) rcv_cumtsn(4) rcv_context(4) rcv_assoc_id(4) }.
	sizeRcvInfo       = 28
	rcvInfoStreamOff  = 0
	rcvInfoSSNOff     = 2
	rcvInfoFlagsOff   = 4
	rcvInfoPPIDOff    = 8
	rcvInfoTSNOff     = 12
	rcvInfoCumTSNOff  = 16
	rcvInfoContextOff = 20
	rcvInfoAssocIDOff = 24

	// struct sctp_nxtinfo { nxt_sid(2) nxt_flags(2) nxt_ppid(4) nxt_length(4)
	// nxt_assoc_id(4) }.
	sizeNxtInfo       = 16
	nxtInfoStreamOff  = 0
	nxtInfoFlagsOff   = 2
	nxtInfoPPIDOff    = 4
	nxtInfoLengthOff  = 8
	nxtInfoAssocIDOff = 12
)

// ---------------------------------------------------------------------
// Notification structs (include/uapi/linux/sctp.h §§5.3.1.1-5.3.1.9; RFC
// 6458 §6). Every one starts with the 8-byte header { type(2) flags(2)
// length(4) }; sizeXxx below is the fixed portion up to and including the
// last fixed field, the minimum a ParseNotification read must find before
// it trusts the type-specific fields. Flexible trailers (sac_info,
// sre_data, strreset_stream_list, ssf_data) start right at sizeXxx.
//
// struct sctp_paddr_change is "packed, aligned(4)": no padding at all
// between fields, and sizeXxx is the exact sum of the field sizes rounded
// up to 4, so its layout is identical on every architecture. The other
// eleven are not packed, but every field in each already falls on its own
// natural alignment (a 4-byte sctp_assoc_t never immediately follows a
// 2-byte field without an intervening pad byte count also captured here),
// so no build-dependent rounding is needed for them either.
// ---------------------------------------------------------------------

const (
	// notificationHeaderSize is sizeof the 8-byte prefix every one of the
	// twelve structs below starts with: { type(2) flags(2) length(4) }.
	// notificationTypeOff, notificationFlagsOff and notificationLengthOff
	// read it before the type is known, since every struct places the
	// three fields at the same offsets (RFC 6458 §6).
	notificationHeaderSize = 8
	notificationTypeOff    = 0
	notificationFlagsOff   = 2
	notificationLengthOff  = 4
)

const (
	// struct sctp_assoc_change { sac_type(2) sac_flags(2) sac_length(4)
	// sac_state(2) sac_error(2) sac_outbound_streams(2) sac_inbound_streams(2)
	// sac_assoc_id(4) sac_info[] }.
	sizeAssocChange          = 20
	assocChangeTypeOff       = 0
	assocChangeFlagsOff      = 2
	assocChangeLengthOff     = 4
	assocChangeStateOff      = 8
	assocChangeErrorOff      = 10
	assocChangeOutStreamsOff = 12
	assocChangeInStreamsOff  = 14
	assocChangeAssocIDOff    = 16
	assocChangeInfoOff       = 20

	// struct sctp_paddr_change { spc_type(2) spc_flags(2) spc_length(4)
	// spc_aaddr(128) spc_state(4) spc_error(4) spc_assoc_id(4) }
	// __attribute__((packed, aligned(4))). Verified against a live
	// association in v1 (git show main:sctp_notification.go): a
	// SCTP_PEER_ADDR_CHANGE arrived declaring length 148.
	sizePAddrChange       = 148
	paddrChangeTypeOff    = 0
	paddrChangeFlagsOff   = 2
	paddrChangeLengthOff  = 4
	paddrChangeAddrOff    = 8
	paddrChangeStateOff   = 136
	paddrChangeErrorOff   = 140
	paddrChangeAssocIDOff = 144

	// struct sctp_remote_error { sre_type(2) sre_flags(2) sre_length(4)
	// sre_error(2) pad(2) sre_assoc_id(4) sre_data[] }. The kernel pads
	// sre_assoc_id to a 4-byte boundary after the __be16 sre_error.
	sizeRemoteError       = 16
	remoteErrorTypeOff    = 0
	remoteErrorFlagsOff   = 2
	remoteErrorLengthOff  = 4
	remoteErrorErrorOff   = 8
	remoteErrorAssocIDOff = 12
	remoteErrorDataOff    = 16

	// struct sctp_shutdown_event { sse_type(2) sse_flags(2) sse_length(4)
	// sse_assoc_id(4) }.
	sizeShutdownEvent       = 12
	shutdownEventTypeOff    = 0
	shutdownEventFlagsOff   = 2
	shutdownEventLengthOff  = 4
	shutdownEventAssocIDOff = 8

	// struct sctp_adaptation_event { sai_type(2) sai_flags(2) sai_length(4)
	// sai_adaptation_ind(4) sai_assoc_id(4) }.
	sizeAdaptationEvent          = 16
	adaptationEventTypeOff       = 0
	adaptationEventFlagsOff      = 2
	adaptationEventLengthOff     = 4
	adaptationEventIndicationOff = 8
	adaptationEventAssocIDOff    = 12

	// struct sctp_pdapi_event { pdapi_type(2) pdapi_flags(2) pdapi_length(4)
	// pdapi_indication(4) pdapi_assoc_id(4) pdapi_stream(4) pdapi_seq(4) }.
	// The association id precedes the stream and sequence fields — the
	// opposite of RFC 6458 §6.1.7's declared field order. v1 decodes this
	// struct with the same, correct kernel order (git show
	// main:sctp_notification.go), noting the same RFC mismatch; these
	// offsets agree with it.
	sizePDAPIEvent          = 24
	pdapiEventTypeOff       = 0
	pdapiEventFlagsOff      = 2
	pdapiEventLengthOff     = 4
	pdapiEventIndicationOff = 8
	pdapiEventAssocIDOff    = 12
	pdapiEventStreamOff     = 16
	pdapiEventSeqOff        = 20

	// struct sctp_authkey_event { auth_type(2) auth_flags(2) auth_length(4)
	// auth_keynumber(2) auth_altkeynumber(2) auth_indication(4)
	// auth_assoc_id(4) }.
	sizeAuthKeyEvent            = 20
	authKeyEventTypeOff         = 0
	authKeyEventFlagsOff        = 2
	authKeyEventLengthOff       = 4
	authKeyEventKeyNumberOff    = 8
	authKeyEventAltKeyNumberOff = 10
	authKeyEventIndicationOff   = 12
	authKeyEventAssocIDOff      = 16

	// struct sctp_sender_dry_event { sender_dry_type(2) sender_dry_flags(2)
	// sender_dry_length(4) sender_dry_assoc_id(4) }.
	sizeSenderDryEvent       = 12
	senderDryEventTypeOff    = 0
	senderDryEventFlagsOff   = 2
	senderDryEventLengthOff  = 4
	senderDryEventAssocIDOff = 8

	// struct sctp_stream_reset_event { strreset_type(2) strreset_flags(2)
	// strreset_length(4) strreset_assoc_id(4) strreset_stream_list[] }.
	sizeStreamResetEvent       = 12
	streamResetEventTypeOff    = 0
	streamResetEventFlagsOff   = 2
	streamResetEventLengthOff  = 4
	streamResetEventAssocIDOff = 8
	streamResetEventStreamsOff = 12

	// struct sctp_assoc_reset_event { assocreset_type(2) assocreset_flags(2)
	// assocreset_length(4) assocreset_assoc_id(4) assocreset_local_tsn(4)
	// assocreset_remote_tsn(4) }.
	sizeAssocResetEvent         = 20
	assocResetEventTypeOff      = 0
	assocResetEventFlagsOff     = 2
	assocResetEventLengthOff    = 4
	assocResetEventAssocIDOff   = 8
	assocResetEventLocalTSNOff  = 12
	assocResetEventRemoteTSNOff = 16

	// struct sctp_stream_change_event { strchange_type(2) strchange_flags(2)
	// strchange_length(4) strchange_assoc_id(4) strchange_instrms(2)
	// strchange_outstrms(2) }.
	sizeStreamChangeEvent          = 16
	streamChangeEventTypeOff       = 0
	streamChangeEventFlagsOff      = 2
	streamChangeEventLengthOff     = 4
	streamChangeEventAssocIDOff    = 8
	streamChangeEventInStreamsOff  = 12
	streamChangeEventOutStreamsOff = 14

	// struct sctp_send_failed_event { ssf_type(2) ssf_flags(2) ssf_length(4)
	// ssf_error(4) ssfe_info(sizeSndInfo=16) ssf_assoc_id(4) ssf_data[] }.
	// SCTP_SEND_FAILED_EVENT, RFC 6458 §6.1.11 — the replacement for the
	// deprecated SCTP_SEND_FAILED, which this package does not implement.
	sizeSendFailedEvent       = 32
	sendFailedEventTypeOff    = 0
	sendFailedEventFlagsOff   = 2
	sendFailedEventLengthOff  = 4
	sendFailedEventErrorOff   = 8
	sendFailedEventInfoOff    = 12
	sendFailedEventAssocIDOff = 28
	sendFailedEventDataOff    = 32
)

// ---------------------------------------------------------------------
// Notification flag bits: the 8-byte header's flags field (notificationFlagsOff,
// above) carries type-specific meaning for five of the twelve notification
// structs, and is not always 0 for any of the five — every value below is a
// mask to test against that field with &, not a separate struct member;
// the other seven structs' flags fields carry no meaning this package
// decodes.
// ---------------------------------------------------------------------

const (
	// pdapi_flags (struct sctp_pdapi_event, above). RFC 6458 §6.1.7 calls
	// this field unused, and net/sctp/ulpevent.c's sctp_ulpevent_make_pdapi
	// still quotes that description in its own comment ("Currently
	// unused") — not the UAPI header, which has none at all — but
	// net/sctp/stream_interleave.c (sctp_intl_abort_pd, sctp_intl_skip)
	// sets it when the partial delivery it is aborting was an unordered
	// message under I-DATA (RFC 8260), and clears it otherwise.
	pdapiFlagUnordered = 0x1

	// ssf_flags (struct sctp_send_failed_event, above): the anonymous enum
	// { SCTP_DATA_UNSENT, SCTP_DATA_SENT } (include/uapi/linux/sctp.h,
	// v6.12, lines 482-483).
	sendFailedFlagSent = 1 // SCTP_DATA_SENT

	// strreset_flags (struct sctp_stream_reset_event, above), RFC 6525
	// §6.1.1 (include/uapi/linux/sctp.h, v6.12, lines 571-574).
	streamResetFlagIncoming = 0x0001 // SCTP_STREAM_RESET_INCOMING_SSN
	streamResetFlagOutgoing = 0x0002 // SCTP_STREAM_RESET_OUTGOING_SSN
	streamResetFlagDenied   = 0x0004 // SCTP_STREAM_RESET_DENIED
	streamResetFlagFailed   = 0x0008 // SCTP_STREAM_RESET_FAILED

	// assocreset_flags (struct sctp_assoc_reset_event, above), RFC 6525
	// §6.1.2 (include/uapi/linux/sctp.h, v6.12, lines 583-584).
	assocResetFlagDenied = 0x0004 // SCTP_ASSOC_RESET_DENIED
	assocResetFlagFailed = 0x0008 // SCTP_ASSOC_RESET_FAILED

	// strchange_flags (struct sctp_stream_change_event, above), RFC 6525
	// §6.1.3. The header #defines these as aliases of
	// SCTP_ASSOC_CHANGE_DENIED/_FAILED rather than giving them their own
	// values (include/uapi/linux/sctp.h, v6.12, lines 594-597).
	streamChangeFlagDenied = 0x0004 // SCTP_STREAM_CHANGE_DENIED
	streamChangeFlagFailed = 0x0008 // SCTP_STREAM_CHANGE_FAILED
)

// ---------------------------------------------------------------------
// DATA chunk header flags, RFC 9260 §3.3.1, as SendFailed decodes them out
// of ssfe_info.snd_flags: Linux copies the failed DATA chunk's own header
// byte there verbatim (net/sctp/ulpevent.c,
// sctp_ulpevent_make_send_failed_event: "ssf->ssfe_info.snd_flags =
// chunk->chunk_hdr->flags"). This is a different bit position in a
// different field from sndFlagUnordered above, which is the socket API's
// own sinfo_flags/snd_flags bit for an outgoing send, not the wire chunk
// header's. The kernel's names for these bits are internal
// (include/linux/sctp.h, v6.12, lines 251-258), not part of the UAPI.
// ---------------------------------------------------------------------

const (
	dataChunkFlagLastFragment  = 0x01 // E bit: SCTP_DATA_LAST_FRAG
	dataChunkFlagFirstFragment = 0x02 // B bit: SCTP_DATA_FIRST_FRAG
	dataChunkFlagUnordered     = 0x04 // U bit: SCTP_DATA_UNORDERED
)

// ---------------------------------------------------------------------
// Option-value structs (include/uapi/linux/sctp.h). Sizes and offsets for
// the ones with a fixed, non-word-size-dependent layout.
// ---------------------------------------------------------------------

const (
	// struct sctp_initmsg { sinit_num_ostreams(2) sinit_max_instreams(2)
	// sinit_max_attempts(2) sinit_max_init_timeo(2) }.
	sizeInitMsg            = 8
	initMsgOutStreamsOff   = 0
	initMsgMaxInStreamsOff = 2
	initMsgMaxAttemptsOff  = 4
	initMsgMaxInitTimeoOff = 6

	// struct sctp_rtoinfo { srto_assoc_id(4) srto_initial(4) srto_max(4)
	// srto_min(4) }.
	sizeRTOInfo       = 16
	rtoInfoAssocIDOff = 0
	rtoInfoInitialOff = 4
	rtoInfoMaxOff     = 8
	rtoInfoMinOff     = 12

	// struct sctp_assocparams { sasoc_assoc_id(4) sasoc_asocmaxrxt(2)
	// sasoc_number_peer_destinations(2) sasoc_peer_rwnd(4)
	// sasoc_local_rwnd(4) sasoc_cookie_life(4) }.
	sizeAssocInfo                = 20
	assocInfoAssocIDOff          = 0
	assocInfoMaxRetransOff       = 4
	assocInfoPeerDestinationsOff = 6
	assocInfoPeerRwndOff         = 8
	assocInfoLocalRwndOff        = 12
	assocInfoCookieLifeOff       = 16

	// struct sctp_sack_info { sack_assoc_id(4) sack_delay(4) sack_freq(4) }.
	sizeDelayedSACK         = 12
	delayedSACKAssocIDOff   = 0
	delayedSACKDelayOff     = 4
	delayedSACKFrequencyOff = 8

	// struct sctp_paddrparams { spp_assoc_id(4) spp_address(128)
	// spp_hbinterval(4) spp_pathmaxrxt(2) spp_pathmtu(4) spp_sackdelay(4)
	// spp_flags(4) spp_ipv6_flowlabel(4) spp_dscp(1) }
	// __attribute__((packed, aligned(4))). Cross-checked against v1's own
	// kernel-measured offsets (git show main:sctp.go, PeerAddrParams).
	// Packed, with no __u64 field: this layout does not depend on word size
	// at all, unlike the four structs at the end of this file that embed a
	// non-packed sockaddr_storage.
	sizePathParams          = 156
	pathParamsAssocIDOff    = 0
	pathParamsAddressOff    = 4
	pathParamsHBIntervalOff = 132
	pathParamsPathMaxRxtOff = 136
	pathParamsPathMTUOff    = 138
	pathParamsSackDelayOff  = 142
	pathParamsFlagsOff      = 146
	pathParamsFlowLabelOff  = 150
	pathParamsDSCPOff       = 154

	// struct sctp_paddrinfo { spinfo_assoc_id(4) spinfo_address(128)
	// spinfo_state(4) spinfo_cwnd(4) spinfo_srtt(4) spinfo_rto(4)
	// spinfo_mtu(4) } __attribute__((packed, aligned(4))). Cross-checked
	// against v1's kernel-measured PeerAddrinfo. Packed, with no __u64
	// field, so this layout is identical on every target: a 32-bit build
	// talking to a 32-bit kernel and a 32-bit build talking to a 64-bit
	// kernel (which SCTP does not translate for these getsockopts — see the
	// word-size-dependent structs below) see the same bytes.
	sizePathInfo       = 152
	pathInfoAssocIDOff = 0
	pathInfoAddressOff = 4
	pathInfoStateOff   = 132
	pathInfoCwndOff    = 136
	pathInfoSRTTOff    = 140
	pathInfoRTOOff     = 144
	pathInfoMTUOff     = 148

	// struct sctp_status { sstat_assoc_id(4) sstat_state(4) sstat_rwnd(4)
	// sstat_unackdata(2) sstat_penddata(2) sstat_instrms(2) sstat_outstrms(2)
	// sstat_fragmentation_point(4) sstat_primary(sizePathInfo=152) }. Not
	// packed itself, but sstat_primary is a "packed, aligned(4)" struct, so
	// it keeps its own 4-byte alignment as a member rather than
	// sockaddr_storage's natural one — cross-checked against v1's
	// kernel-measured Status (176 total). No __u64 field and no raw
	// sockaddr_storage, so this layout does not depend on word size either.
	sizeStatus                  = 176
	statusAssocIDOff            = 0
	statusStateOff              = 4
	statusRWNDOff               = 8
	statusUnackedOff            = 12
	statusPendingOff            = 14
	statusInStreamsOff          = 16
	statusOutStreamsOff         = 18
	statusFragmentationPointOff = 20
	statusPrimaryOff            = 24

	// struct sctp_prstatus { sprstat_assoc_id(4) sprstat_sid(2)
	// sprstat_policy(2) sprstat_abandoned_unsent(8)
	// sprstat_abandoned_sent(8) }. It has two __u64 fields, but they land at
	// offset 8 regardless: 4 (assoc_id) + 2 (sid) + 2 (policy) is already a
	// multiple of both u64Align values (4 on 386, 8 elsewhere), so no
	// padding is ever inserted and this layout is identical on every
	// target.
	sizePRStatus               = 24
	prStatusAssocIDOff         = 0
	prStatusStreamOff          = 4
	prStatusPolicyOff          = 6
	prStatusAbandonedUnsentOff = 8
	prStatusAbandonedSentOff   = 16

	// struct sctp_default_prinfo { pr_assoc_id(4) pr_value(4) pr_policy(2)
	// pad(2) }. Distinct from struct sctp_prinfo (sizePrInfo, above): the
	// per-message cmsg has no assoc id and a different field order.
	sizeDefaultPRInfo       = 12
	defaultPRInfoAssocIDOff = 0
	defaultPRInfoValueOff   = 4
	defaultPRInfoPolicyOff  = 8

	// struct sctp_authkey { sca_assoc_id(4) sca_keynumber(2)
	// sca_keylength(2) sca_key[] }. sizeAuthKey is the fixed header; the key
	// bytes follow at that offset.
	sizeAuthKey         = 8
	authKeyAssocIDOff   = 0
	authKeyKeyNumberOff = 4
	authKeyKeyLengthOff = 6
	authKeyKeyOff       = 8

	// struct sctp_authkeyid { scact_assoc_id(4) scact_keynumber(2) }, padded
	// to 8 by the struct's own 4-byte alignment.
	sizeAuthKeyID         = 8
	authKeyIDAssocIDOff   = 0
	authKeyIDKeyNumberOff = 4

	// struct sctp_hmacalgo { shmac_num_idents(4) shmac_idents[] }.
	sizeHMACAlgo         = 4
	hmacAlgoNumIdentsOff = 0
	hmacAlgoIdentsOff    = 4

	// struct sctp_authchunks { gauth_assoc_id(4) gauth_number_of_chunks(4)
	// gauth_chunks[] }.
	sizeAuthChunks         = 8
	authChunksAssocIDOff   = 0
	authChunksNumChunksOff = 4
	authChunksChunksOff    = 8

	// struct sctp_assoc_ids { gaids_number_of_ids(4) gaids_assoc_id[] }.
	sizeAssocIDs      = 4
	assocIDsNumIDsOff = 0
	assocIDsIDsOff    = 4

	// struct sctp_getaddrs { assoc_id(4) addr_num(4) addrs[] }. The fixed
	// header has no __u64 field and no raw sockaddr_storage (addrs[] is a
	// packed run of sockaddr_in/sockaddr_in6 entries, each already
	// word-size-independent), so this layout does not depend on word size.
	sizeGetAddrs       = 8
	getAddrsAssocIDOff = 0
	getAddrsAddrNumOff = 4
	getAddrsAddrsOff   = 8

	// struct sctp_reset_streams { srs_assoc_id(4) srs_flags(2)
	// srs_number_streams(2) srs_stream_list[] }.
	sizeResetStreams          = 8
	resetStreamsAssocIDOff    = 0
	resetStreamsFlagsOff      = 4
	resetStreamsNumStreamsOff = 6
	resetStreamsStreamListOff = 8

	// struct sctp_add_streams { sas_assoc_id(4) sas_instrms(2)
	// sas_outstrms(2) }.
	sizeAddStreams          = 8
	addStreamsAssocIDOff    = 0
	addStreamsInStreamsOff  = 4
	addStreamsOutStreamsOff = 6

	// struct sctp_stream_value { assoc_id(4) stream_id(2) stream_value(2) }.
	sizeStreamValue        = 8
	streamValueAssocIDOff  = 0
	streamValueStreamIDOff = 4
	streamValueValueOff    = 6

	// struct sctp_event { se_assoc_id(4) se_type(2) se_on(1) }, padded to 8
	// by the struct's own 4-byte alignment.
	sizeEvent         = 8
	eventAssocIDOff   = 0
	eventTypeFieldOff = 4
	eventOnOff        = 6

	// struct sctp_assoc_value { assoc_id(4) assoc_value(4) }.
	sizeAssocValue       = 8
	assocValueAssocIDOff = 0
	assocValueValueOff   = 4

	// sctp_peeloff_flags_arg_t { sctp_peeloff_arg_t { associd(4) sd(4) }
	// flags(4) }.
	sizePeeloffFlagsArg       = 12
	peeloffFlagsArgAssocIDOff = 0
	peeloffFlagsArgSDOff      = 4
	peeloffFlagsArgFlagsOff   = 8

	// struct sctp_prim / struct sctp_setpeerprim { ssp_assoc_id(4) /
	// sspp_assoc_id(4), ssp_addr(128) / sspp_addr(128) }
	// __attribute__((packed, aligned(4))): identical layout under different
	// field names, one for SCTP_PRIMARY_ADDR (SetPrimaryAddr, PrimaryAddr)
	// and one for SCTP_SET_PEER_PRIMARY_ADDR (RequestPeerPrimary). Packed,
	// so — like sctp_paddrparams and sctp_paddrinfo above — this layout
	// does not depend on word size.
	sizePrim       = 132
	primAssocIDOff = 0
	primAddrOff    = 4

	sizeSetPeerPrim       = 132
	setPeerPrimAssocIDOff = 0
	setPeerPrimAddrOff    = 4
)

// ---------------------------------------------------------------------
// Word-size-dependent option structs: each embeds a sockaddr_storage right
// after one sctp_assoc_t, and none is declared packed, so the address
// starts at ssAddrOffset and every field after it moves with the pointer
// size. sctp_assoc_stats additionally has __u64 counters after that address,
// whose own alignment (u64Align, the abi_u64align_*.go pair) can disagree
// with sockaddr_storage's (ssAlign) on a 32-bit target — see u64Align's own
// comment. Measured with a C probe for every word size (see ssAlign,
// above); TestSockaddrStorageOptionLayouts in abi_test.go pins the target
// this build was compiled for, and TestSockaddrStorageLayoutFormula
// recomputes every row from the formula at once.
//
// Each also gets a second, fixed set of constants (the Kernel64 suffix)
// for the layout Linux's own struct always has on a 64-bit kernel, address
// at 8 and (for sctp_assoc_stats) counters at 136 — 64-bit numbers,
// regardless of what GOARCH this package itself was built for. They matter
// because Linux SCTP has no compat translation for these particular
// getsockopts: a 32-bit process asking a 64-bit kernel for one of these
// four options is handed the kernel's own, 64-bit-shaped bytes, not bytes
// reshaped to the 32-bit layout the same process would see from a real
// 32-bit kernel. A 32-bit build's decoder therefore needs both a native
// layout to try and this kernel-shaped one to fall back to; which one to
// try, and when, is not decided here — these are only the two shapes it
// can choose between.
// ---------------------------------------------------------------------

// ssAddrOffsetKernel64 and ssTailOffsetKernel64 are ssAddrOffset and
// ssTailOffset fixed at the 64-bit shape (align 8): where sockaddr_storage
// always sits in the kernel's own, 64-bit-native struct, regardless of
// what word size this package itself was compiled for. The Kernel64
// constants below are built from these two.
const (
	ssAddrOffsetKernel64 = (4 + 8 - 1) &^ (8 - 1)
	ssTailOffsetKernel64 = ssAddrOffsetKernel64 + sizeSockaddrStorage
)

const (
	// struct sctp_udpencaps { sue_assoc_id(4) sue_address(128)
	// sue_port(2) }.
	udpEncapsAssocIDOff = 0
	udpEncapsAddressOff = ssAddrOffset
	udpEncapsPortOff    = ssTailOffset
	sizeUDPEncaps       = (ssTailOffset + 2 + ssAlign - 1) &^ (ssAlign - 1)

	udpEncapsAddressOffKernel64 = ssAddrOffsetKernel64
	sizeUDPEncapsKernel64       = (ssTailOffsetKernel64 + 2 + 8 - 1) &^ (8 - 1)

	// struct sctp_probeinterval { spi_assoc_id(4) spi_address(128)
	// spi_interval(4) }.
	probeIntervalAssocIDOff  = 0
	probeIntervalAddressOff  = ssAddrOffset
	probeIntervalIntervalOff = ssTailOffset
	sizeProbeInterval        = (ssTailOffset + 4 + ssAlign - 1) &^ (ssAlign - 1)

	probeIntervalAddressOffKernel64 = ssAddrOffsetKernel64
	sizeProbeIntervalKernel64       = (ssTailOffsetKernel64 + 4 + 8 - 1) &^ (8 - 1)

	// struct sctp_paddrthlds_v2 { spt_assoc_id(4) spt_address(128)
	// spt_pathmaxrxt(2) spt_pathpfthld(2) spt_pathcpthld(2) }. Not declared
	// packed in the 6.12 UAPI header — unlike sctp_paddrparams and
	// sctp_paddrinfo, which are — so, like sctp_udpencaps and
	// sctp_probeinterval above, its embedded sockaddr_storage keeps its
	// natural, word-size-dependent alignment.
	pathThresholdsAssocIDOff     = 0
	pathThresholdsAddressOff     = ssAddrOffset
	pathThresholdsMaxRxtOff      = ssTailOffset
	pathThresholdsPFThresholdOff = ssTailOffset + 2
	pathThresholdsSwitchoverOff  = ssTailOffset + 4
	sizePathThresholds           = (ssTailOffset + 6 + ssAlign - 1) &^ (ssAlign - 1)

	pathThresholdsAddressOffKernel64 = ssAddrOffsetKernel64
	sizePathThresholdsKernel64       = (ssTailOffsetKernel64 + 6 + 8 - 1) &^ (8 - 1)

	// sizeAssocStatsHeader is where struct sctp_assoc_stats's __u64 counters
	// begin: sas_assoc_id(4), then sas_obs_rto_ipaddr at ssAddrOffset,
	// rounded up to u64Align. On a 64-bit target (ssAlign 8, u64Align 8)
	// that rounds 136 up to itself: 136. On arm/mips-class 32-bit targets
	// (ssAlign 4, u64Align 8) it rounds the 132 the address alone would
	// give up to 136 too, so sizeAssocStats is 256 there as well — both of
	// those match v1's own kernel-measured constants (assocStatsCounters=136,
	// assocStatsSize=256; git show main:sctp_layout_test.go), which never
	// distinguished the two 32-bit cases. Only on 386 (ssAlign 4, u64Align 4
	// — see abi_u64align_386.go) does nothing need to round: 132 already
	// satisfies a 4-byte alignment, so the counters sit at 132 and
	// sizeAssocStats is 252, not 256 — a number v1 never measured, since it
	// never ran on 386 with this struct checked; it follows from the i386
	// SysV ABI's u64Align=4 alone.
	assocStatsAssocIDOff = 0
	assocStatsAddrOff    = ssAddrOffset
	sizeAssocStatsHeader = (ssTailOffset + u64Align - 1) &^ (u64Align - 1)
	sizeAssocStats       = sizeAssocStatsHeader + 15*8

	assocStatsAddrOffKernel64    = ssAddrOffsetKernel64
	sizeAssocStatsHeaderKernel64 = (ssTailOffsetKernel64 + 8 - 1) &^ (8 - 1)
	sizeAssocStatsKernel64       = sizeAssocStatsHeaderKernel64 + 15*8
)
