// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// msginfo.go declares the per-message send and receive metadata RFC 6458
// §5.3 carries as sendmsg(2)/recvmsg(2) ancillary data — SendOptions and its
// SndInfo, PrInfo and AuthKey records; MsgInfo and its RcvInfo and NxtInfo
// records — plus the functions that encode and parse them: appendSendCmsgs,
// parseRecvCmsgs, splitDefaultFlags and the part of SendMsg's validation
// that needs no socket. Every encode and decode is byte-wise against
// abi.go's struct cmsghdr and sctp_sndinfo/sctp_prinfo/sctp_authinfo/
// sctp_rcvinfo/sctp_nxtinfo layouts, in host order (binary.NativeEndian)
// except PPID, which crosses in network order (binary.BigEndian). RFC 6458
// §§5.3.4-5.3.6 each say the SCTP stack performs no byte order modification
// of snd_ppid/rcv_ppid/nxt_ppid at all — the user has to call
// htonl()/ntohl() to get a network-order value — and Linux holds to that
// literally: the wire DATA chunk header's ppid field is copied straight
// from sinfo_ppid with no conversion of its own
// (net/sctp/sm_make_chunk.c: sctp_make_datafrag_empty, "dp.ppid =
// sinfo->sinfo_ppid"; net/sctp/stream_interleave.c: sctp_chunk_assign_mid
// does the same for an I-DATA chunk's first fragment, "hdr->ppid =
// lchunk->sinfo.sinfo_ppid"), and the receive side copies the wire value
// back out just as directly (net/sctp/ulpqueue.c: sctp_ulpq_tail_data sets
// event->ppid straight from chunk->subh.data_hdr->ppid;
// net/sctp/ulpevent.c: sctp_ulpevent_read_rcvinfo, sctp_ulpevent_read_nxtinfo
// copy it again into rcv_ppid/nxt_ppid). appendSendCmsgs and parseRecvCmsgs
// are where this package performs the htonl/ntohl the RFC leaves to the
// user. Nothing here calls sendmsg or recvmsg itself, so the file carries
// no build tag and is exercised on every platform the package builds for.

package sctp

import (
	"encoding/binary"
	"net/netip"
	"time"
)

// SendOptions are per-message send parameters, after RFC 6458 §9.12's
// sctp_sendv_spa. It is passed by value.
//
// A nil Info or PR means the socket's default: the SndInfo from
// Config.DefaultSndInfo or SetDefaultSndInfo, and the PrInfo from
// Config.DefaultPrInfo or SetDefaultPrInfo. That holds in every combination, on a Conn and on an
// Endpoint. Linux by itself applies the defaults only to a message that
// carries no SNDINFO, and the default flags only when there is no PRINFO
// either (sctp_sendmsg_update_sinfo in net/sctp/socket.c). So when only one
// of Info and PR is set, and on every Endpoint send (which carries the
// association id in SNDINFO), the package sends the default explicitly. It
// reads the defaults from the socket when the Conn or Endpoint is created,
// which includes anything Control set, and keeps them current through the
// setters. A default changed through SyscallConn is not seen.
type SendOptions struct {
	Info    *SndInfo // SCTP_SNDINFO, RFC 6458 §5.3.4
	PR      *PrInfo  // SCTP_PRINFO, RFC 6458 §5.3.7; needs PR-SCTP negotiated
	AuthKey *uint16  // SCTP_AUTHINFO, RFC 6458 §5.3.8

	// Path sends this message to one peer address instead of letting the
	// kernel choose (RFC 6458 §5.3.4's SCTP_ADDR_OVER use; on a one-to-one
	// socket Linux honours the destination address alone). The zero value
	// means the kernel's choice, normally the primary path. The address must
	// be one of PeerAddrs; Linux refuses any other with EADDRNOTAVAIL
	// (sctp_sendmsg_new_asoc). Path is accepted on connections from Dial and
	// Accept only. SendMsg refuses it on an Endpoint (where the kernel would
	// look the association up by address, not by id) and on a connection from
	// Endpoint.PeelOff (where Linux silently ignores the destination).
	Path netip.Addr

	// More says more messages follow at once, so the kernel may hold this
	// one briefly to bundle it with them (MSG_MORE, Linux 4.11). The last
	// message of a burst must leave More false, or it can sit until the next
	// send.
	More bool

	// NoWait makes a single attempt (MSG_DONTWAIT) instead of waiting for
	// send-buffer space. A refusal returns an error matching syscall.EAGAIN,
	// and guarantees that nothing of the message was queued: Linux waits for
	// or refuses buffer space before it builds the message, so it queues a
	// message whole or not at all. The message may therefore be resent without
	// risk of duplication. It affects only this call, not other writers on the
	// socket. The attempt is made through the runtime poller, so a write
	// deadline that has already passed fails it before the attempt, as for any
	// write.
	//
	// NoWait never waits for send-buffer space, but like any send it first
	// takes the connection's send lock. A send that is waiting for space
	// holds that lock, so a NoWait send issued meanwhile waits until that send
	// completes, reaches its deadline, or the socket is closed. With no write
	// deadline set, nothing bounds that wait. If the deadline is what ends it,
	// the NoWait send then fails with the same deadline error.
	//
	// "Nothing queued" is about this message only. When this message does not
	// fit in the free send-buffer space and PR-SCTP is negotiated, Linux first
	// abandons queued or in-flight PRPrio messages whose priority value is
	// higher than this message's, and only then decides whether to wait or
	// refuse. For a message with no PR policy of its own
	// and no socket default, that is any PRPrio message whose value is above
	// zero.
	// Those abandonments stand even when the attempt is refused, and they
	// happen the same way for a send that waits.
	NoWait bool
}

type SndInfo struct { // struct sctp_sndinfo
	Stream  uint16
	Flags   SendFlags // as a default (DefaultSndInfo), SendUnordered only; see below
	PPID    uint32
	Context uint32 // returned in SendFailed if the message is not delivered
}

// As a socket default (Config.DefaultSndInfo, Conn.SetDefaultSndInfo),
// Flags may hold only SendUnordered. Linux refuses SendSACKImmediately there
// with EINVAL (sctp_setsockopt_default_sndinfo), so the package refuses it
// first. Linux also keeps the default PR-SCTP policy in the same word as the
// default flags, and setting SCTP_DEFAULT_SNDINFO overwrites it. The package
// restores the default PrInfo after every default SndInfo it sets, so the
// two defaults stay independent, as their two setters suggest.

type PrInfo struct { // struct sctp_prinfo, RFC 7496
	Policy PRPolicy
	TTL    time.Duration // PRTTL: lifetime
	Value  uint32        // PRRtx: retransmission limit; PRPrio: priority
}

// MsgInfo describes one RecvMsg call (RFC 6458 §9.13, sctp_recvv).
type MsgInfo struct {
	EOR          bool    // b received the end of the message (MSG_EOR)
	Notification bool    // the bytes are a notification; only when no NotificationHandler is set
	Rcv          RcvInfo // zero for notifications
	Nxt          NxtInfo // valid only when HasNxt; a value, so RecvMsg never allocates
	HasNxt       bool    // ReceiveNxtInfo is on and another message is queued
}

type RcvInfo struct { // struct sctp_rcvinfo, RFC 6458 §5.3.5
	Stream    uint16
	SSN       uint16
	Unordered bool
	PPID      uint32
	TSN       uint32
	CumTSN    uint32
	Context   uint32
	AssocID   AssocID
}

type NxtInfo struct { // struct sctp_nxtinfo, RFC 6458 §5.3.6
	Stream       uint16
	Unordered    bool
	Notification bool
	PPID         uint32
	Length       uint32 // size of the whole next message
	AssocID      AssocID
}

// validateSendOptions checks the parts of opts that need no socket:
// SendOptions.PR's policy and TTL, and SendOptions.Info's flags. Everything
// else a send validates — the empty-message check, SendOptions.Path and an
// Endpoint's association id — needs the connection's family or association
// table, so the send path checks those itself once it has one. A refusal
// here matches syscall.EINVAL, names the field, and touches no system call.
// The policy and flags checks each mirror a mask net/sctp/socket.c's
// sctp_msghdr_parse already applies per-message, so refusing here saves a
// syscall that would only come back with the kernel's own EINVAL; the TTL
// checks have no kernel counterpart to mirror — they exist because this
// package converts a time.Duration to the uint32 millisecond count
// struct sctp_prinfo's pr_value carries, a conversion the kernel itself
// never performs (it is only ever handed the already-converted uint32).
//
// Zero allocations on success.
func validateSendOptions(opts *SendOptions) error {
	if opts.Info != nil {
		if f := opts.Info.Flags &^ (SendUnordered | SendSACKImmediately); f != 0 {
			return invalidArg("SendOptions.Info.Flags %#04x sets bits outside SendUnordered|SendSACKImmediately", uint16(opts.Info.Flags))
		}
	}

	// The policy and TTL checks themselves live in validatePrInfo
	// (options.go), shared with Config.DefaultPrInfo's validation: RFC
	// 6458 §5.3.7's "In the case of SCTP_PR_SCTP_TTL, the lifetime is
	// provided in pr_value" and RFC 7496 §4.2's table ("SCTP_PR_SCTP_TTL |
	// Lifetime in ms") apply the same way to a default as to a per-message
	// send.
	if pr := opts.PR; pr != nil {
		if err := validatePrInfo("SendOptions.PR", pr); err != nil {
			return err
		}
	}

	return nil
}

// appendSendCmsgs encodes SNDINFO (from snd and assoc), then PRINFO when
// pr is non-nil, then AUTHINFO when key is non-nil, into dst and returns
// the number of bytes used. dst must have length 0 and capacity at least
// sndCmsgSpace — appendSendCmsgs always writes starting at index 0, the
// same as append(dst, ...) would from an empty dst, so it panics if dst is
// not empty rather than silently writing over a caller's existing bytes at
// the wrong offset. It never allocates and never decides defaults or
// validates: the caller (the send path) has already resolved snd and pr to
// whatever SendOptions and the cached socket defaults mean together
// (SendOptions's own default rule), and already validated them with
// validateSendOptions.
//
// assoc is written into every SNDINFO regardless of whether snd came from
// SendOptions.Info or a default: it is what lets an Endpoint's SendMsg name
// its association while still sharing this one encoder with Conn.SendMsg,
// which passes AssocID(0) — a value RFC 6458 §5.3.4 says a one-to-one or
// peeled-off socket ignores.
//
// A non-nil pr is always encoded, even with Policy PRNone: that lets a
// caller send an explicit "no policy" PRINFO, overriding an association's
// own default. That overriding is Linux's own behaviour, not something
// RFC 6458 specifies: sctp_sendmsg_parse (net/sctp/socket.c) sets
// srinfo->sinfo_flags's PR-policy bits from cmsgs->prinfo->pr_policy
// whenever a PRINFO cmsg is present at all — "if (cmsgs->prinfo) { ...
// SCTP_PR_SET_POLICY(srinfo->sinfo_flags, cmsgs->prinfo->pr_policy); }" —
// including PRNone, and sctp_sendmsg_update_sinfo, called afterward, only
// applies the association's own default_flags when no PRINFO cmsg was
// given at all ("if (!cmsgs->prinfo) sinfo->sinfo_flags =
// asoc->default_flags"), so an explicit PRNone is never replaced by it.
// Separately, following sctp_msghdr_parse's own handling of the SCTP_PRINFO
// cmsg ("if (cmsgs->prinfo->pr_policy == SCTP_PR_SCTP_NONE)
// cmsgs->prinfo->pr_value = 0;"), the encoded pr_value is 0 whenever Policy
// is PRNone, whatever pr.Value or pr.TTL holds.
func appendSendCmsgs(dst []byte, snd *SndInfo, assoc AssocID, pr *PrInfo, key *uint16) int {
	if len(dst) != 0 {
		panic("sctp: appendSendCmsgs requires a zero-length destination")
	}

	total := cmsgSpace(sizeSndInfo)
	if pr != nil {
		total += cmsgSpace(sizePrInfo)
	}
	if key != nil {
		total += cmsgSpace(sizeAuthInfo)
	}

	// Clearing the whole used range up front, once, covers every gap a
	// caller's reused buffer (sendState.cbuf, one array across every
	// SendMsg call) could otherwise leak into the message: not just the
	// CMSG_ALIGN padding between one record and the next, but also
	// struct sctp_prinfo's own internal gap (pr_policy ends at offset 2,
	// pr_value starts at prInfoValueOff, offset 4 — abi.go's comment on
	// why) that a field-by-field write below never touches directly. The
	// kernel never reads either kind of gap — cmsg_len, not cmsgSpace,
	// bounds what sctp_msghdr_parse decodes — so this is hygiene, not a
	// correctness requirement CMSG_ALIGN or the struct layout itself
	// imposes.
	dst = dst[:cap(dst)]
	clear(dst[:total])

	off := 0

	putCmsgHeader(dst, off, sizeSndInfo, cmsgSndInfo)
	p := off + sizeCmsghdr
	binary.NativeEndian.PutUint16(dst[p+sndInfoStreamOff:], snd.Stream)
	binary.NativeEndian.PutUint16(dst[p+sndInfoFlagsOff:], uint16(snd.Flags))
	binary.BigEndian.PutUint32(dst[p+sndInfoPPIDOff:], snd.PPID)
	binary.NativeEndian.PutUint32(dst[p+sndInfoContextOff:], snd.Context)
	binary.NativeEndian.PutUint32(dst[p+sndInfoAssocIDOff:], uint32(assoc))
	off += cmsgSpace(sizeSndInfo)

	if pr != nil {
		start := off
		putCmsgHeader(dst, start, sizePrInfo, cmsgPrInfo)
		p := start + sizeCmsghdr
		// resolvePrInfo (options.go) is the shared policy/value resolution
		// this comment block describes; config.go's DefaultPrInfo handling
		// calls the same function for SCTP_DEFAULT_PRINFO.
		policy, value := resolvePrInfo(pr)
		binary.NativeEndian.PutUint16(dst[p+prInfoPolicyOff:], policy)
		binary.NativeEndian.PutUint32(dst[p+prInfoValueOff:], value)
		off = start + cmsgSpace(sizePrInfo)
	}

	if key != nil {
		start := off
		putCmsgHeader(dst, start, sizeAuthInfo, cmsgAuthInfo)
		p := start + sizeCmsghdr
		binary.NativeEndian.PutUint16(dst[p+authInfoKeyNumberOff:], *key)
		off = start + cmsgSpace(sizeAuthInfo)
	}

	return off
}

// parseRecvCmsgs fills info from one recvmsg() result: oob is the ancillary
// data recvmsg() returned (kernel order, whatever mix of records it chose
// to attach) and flags is the msg_flags it returned alongside it. It walks
// oob structurally the way for_each_cmsghdr/__cmsg_nxthdr do
// (include/linux/socket.h, v6.12, lines 132-164), but a header whose
// declared length does not fit the remaining bytes simply ends the walk
// here, rather than failing it. That is deliberately different from the
// send side: sctp_msghdr_parse (net/sctp/socket.c) treats the same CMSG_OK
// failure as -EINVAL, because there it is validating a buffer a caller
// built by hand. Here oob is what the kernel's own put_cmsg
// (net/core/scm.c) produced from a real recvmsg(), and put_cmsg's own
// truncation already sets MSG_CTRUNC, checked below, when it runs out of
// room; a short trailing record is exactly what that produces, not a sign
// the buffer is malformed.
//
// EOR comes from MSG_EOR and Notification from MSG_NOTIFICATION. RCVINFO
// fills Rcv, unless Notification is set, in which case Rcv stays zero even
// if a RCVINFO record is present (Linux does not attach one to a
// notification: sctp_ulpevent_read_rcvinfo (net/sctp/ulpevent.c) is called
// unconditionally whenever SCTP_RECVRCVINFO is on, but returns before
// calling put_cmsg when sctp_ulpevent_is_notification(event) is true — a
// value already read from oob is never trusted over the flag regardless).
// NXTINFO fills Nxt and sets HasNxt. PPID crosses from network to host
// order here, matching appendSendCmsgs on the send side (see this file's
// own doc comment). MSG_CTRUNC makes it return ErrControlTruncated once
// info holds whatever the walk above did parse ahead of the truncation
// point: put_cmsg (net/core/scm.c) sets MSG_CTRUNC and truncates or drops
// the one record it is currently writing when msg_controllen runs out, but
// never undoes an earlier, already-written record; sctp_recvmsg
// (net/sctp/socket.c, around its "Check if we allow SCTP_NXTINFO"/
// "SCTP_RCVINFO" comments) calls it once each for NXTINFO, RCVINFO and the
// deprecated SNDRCV in that order — a straight-line sequence of independent
// calls, not a loop.
func parseRecvCmsgs(oob []byte, flags int, info *MsgInfo) error {
	*info = MsgInfo{}

	info.EOR = flags&msgEOR != 0
	info.Notification = flags&msgNotification != 0

	for len(oob) >= sizeCmsghdr {
		length := readWord(oob)
		if length < sizeCmsghdr || length > uint64(len(oob)) {
			break
		}
		level := int32(binary.NativeEndian.Uint32(oob[cmsghdrLevelOff:]))
		typ := int32(binary.NativeEndian.Uint32(oob[cmsghdrTypeOff:]))
		payload := oob[sizeCmsghdr:length]

		if level == ipprotoSCTP {
			switch typ {
			case cmsgRcvInfo:
				if !info.Notification && len(payload) >= sizeRcvInfo {
					info.Rcv = decodeRcvInfo(payload)
				}
			case cmsgNxtInfo:
				if len(payload) >= sizeNxtInfo {
					info.Nxt = decodeNxtInfo(payload)
					info.HasNxt = true
				}
			}
		}

		adv := cmsgAlign(int(length))
		if adv > len(oob) {
			break
		}
		oob = oob[adv:]
	}

	if flags&msgCtrunc != 0 {
		return ErrControlTruncated
	}
	return nil
}

func decodeRcvInfo(b []byte) RcvInfo {
	return RcvInfo{
		Stream:    binary.NativeEndian.Uint16(b[rcvInfoStreamOff:]),
		SSN:       binary.NativeEndian.Uint16(b[rcvInfoSSNOff:]),
		Unordered: binary.NativeEndian.Uint16(b[rcvInfoFlagsOff:])&sndFlagUnordered != 0,
		PPID:      binary.BigEndian.Uint32(b[rcvInfoPPIDOff:]),
		TSN:       binary.NativeEndian.Uint32(b[rcvInfoTSNOff:]),
		CumTSN:    binary.NativeEndian.Uint32(b[rcvInfoCumTSNOff:]),
		Context:   binary.NativeEndian.Uint32(b[rcvInfoContextOff:]),
		AssocID:   AssocID(binary.NativeEndian.Uint32(b[rcvInfoAssocIDOff:])),
	}
}

func decodeNxtInfo(b []byte) NxtInfo {
	flags := binary.NativeEndian.Uint16(b[nxtInfoFlagsOff:])
	return NxtInfo{
		Stream:       binary.NativeEndian.Uint16(b[nxtInfoStreamOff:]),
		Unordered:    flags&sndFlagUnordered != 0,
		Notification: flags&msgNotification != 0,
		PPID:         binary.BigEndian.Uint32(b[nxtInfoPPIDOff:]),
		Length:       binary.NativeEndian.Uint32(b[nxtInfoLengthOff:]),
		AssocID:      AssocID(binary.NativeEndian.Uint32(b[nxtInfoAssocIDOff:])),
	}
}

// splitDefaultFlags separates a socket's default_flags word (SCTP_DEFAULT_SNDINFO's
// snd_flags on read, or SCTP_DEFAULT_PRINFO's own word — net/sctp/socket.c
// keeps both the default send flags and the default PR-SCTP policy packed
// into this one word, SCTP_PR_SET_POLICY/SCTP_PR_POLICY in
// include/uapi/linux/sctp.h) into the two independent values the package
// exposes: SendUnordered, and the PRPolicy bits inside prPolicyMask.
//
// sctp_setsockopt_default_sndinfo and sctp_setsockopt_default_send_param
// (net/sctp/socket.c) both accept SCTP_UNORDERED | SCTP_ADDR_OVER |
// SCTP_ABORT | SCTP_EOF in this word (not SCTP_SACK_IMMEDIATELY, which
// SndInfo's own doc comment already says the package refuses first), so a
// default set through Control, bypassing SetDefaultSndInfo's narrower
// validation, could legitimately carry SCTP_ADDR_OVER, SCTP_ABORT or
// SCTP_EOF. None of the three has a SendFlags bit to be returned as
// (SendFlags is only SendUnordered and SendSACKImmediately), and none is a
// value a default send should ever reapply: SCTP_ADDR_OVER is
// SendOptions.Path's own field, never a flag on a default; SCTP_ABORT and
// SCTP_EOF are AbortAssoc's and CloseAssoc's own empty sends and are
// refused outright on an ordinary per-message send on a one-to-one socket
// (sctp_sendmsg_parse: "if (sctp_style(sk, TCP) && (sflags & (SCTP_EOF |
// SCTP_ABORT))) return -EINVAL;"). splitDefaultFlags therefore masks the
// flags half down to SendUnordered alone, not merely to "outside the PR
// policy bits", so none of the three ever reaches a caller as a SendFlags
// value it cannot represent and must not carry into an unrelated send.
func splitDefaultFlags(raw uint16) (SendFlags, PRPolicy) {
	return SendFlags(raw & sndFlagUnordered), PRPolicy(raw & prPolicyMask)
}

// --- struct cmsghdr encoding/decoding helpers -------------------------

// cmsgAlign is CMSG_ALIGN(len) (include/linux/socket.h, v6.12, line 119:
// "#define CMSG_ALIGN(len) ( ((len)+sizeof(long)-1) & ~(sizeof(long)-1) )"):
// len rounded up to the next multiple of sizeof(long), which is wordSize on
// both the Linux/amd64 and Linux/386 ABIs.
func cmsgAlign(n int) int { return (n + wordSize - 1) &^ (wordSize - 1) }

// cmsgSpace is CMSG_SPACE(len) (include/linux/socket.h, v6.12, line 125:
// "#define CMSG_SPACE(len) (sizeof(struct cmsghdr) + CMSG_ALIGN(len))"):
// the bytes one control message of payload length n occupies in a control
// buffer, header, payload and trailing alignment padding included.
func cmsgSpace(n int) int { return sizeCmsghdr + cmsgAlign(n) }

// cmsgLen is CMSG_LEN(len) (include/linux/socket.h, v6.12, line 126:
// "#define CMSG_LEN(len) (sizeof(struct cmsghdr) + (len))"): the exact
// cmsg_len a control message of payload length n declares. Unlike
// cmsgSpace it is not rounded up — cmsg_len covers only the header and the
// real payload — and sctp_msghdr_parse (net/sctp/socket.c) rejects any
// other value for every SCTP cmsg type it checks the length of, which is
// every one this package sends or parses. The two exceptions,
// SCTP_DSTADDRV4 and SCTP_DSTADDRV6, accept any cmsg_len at all
// (sctp_msghdr_parse's own case for them sets cmsgs->addrs_msg with no
// length check); this package does not use either, so that exception never
// applies to anything cmsgLen is called for here (abi.go's own comment on
// why they are unused).
func cmsgLen(n int) int { return sizeCmsghdr + n }

// sndCmsgSpace is the worst case for one send's SNDINFO, PRINFO and
// AUTHINFO together: cmsgSpace(sizeSndInfo) + cmsgSpace(sizePrInfo) +
// cmsgSpace(sizeAuthInfo). A const cannot call cmsgSpace, a function, so the
// three terms are written out from the same CMSG_ALIGN formula cmsgSpace
// itself uses; TestSndCmsgSpaceMatchesCmsgSpace and
// TestRcvCmsgSpaceMatchesCmsgSpace in msginfo_test.go cross-check the two
// against each other. This exact total — the buffer a caller needs to set
// all three records on one message — is what lksctp-tools issue #68
// documents a too-small default cmsg buffer failing to hold.
//
// rcvCmsgSpace is the worst case for RCVINFO and NXTINFO together, the
// records ReceiveNxtInfo being on can add to one recvmsg().
const (
	sndCmsgSpace = sizeCmsghdr + (sizeSndInfo+wordSize-1)&^(wordSize-1) +
		sizeCmsghdr + (sizePrInfo+wordSize-1)&^(wordSize-1) +
		sizeCmsghdr + (sizeAuthInfo+wordSize-1)&^(wordSize-1)
	rcvCmsgSpace = sizeCmsghdr + (sizeRcvInfo+wordSize-1)&^(wordSize-1) +
		sizeCmsghdr + (sizeNxtInfo+wordSize-1)&^(wordSize-1)
)

// putCmsgHeader writes cmsg_len (CMSG_LEN(n)), cmsg_level (IPPROTO_SCTP) and
// cmsg_type at dst[off:], ready for n bytes of payload at
// dst[off+sizeCmsghdr:].
func putCmsgHeader(dst []byte, off, n, typ int) {
	putWord(dst[off+cmsghdrLenOff:], uint64(cmsgLen(n)))
	binary.NativeEndian.PutUint32(dst[off+cmsghdrLevelOff:], uint32(ipprotoSCTP))
	binary.NativeEndian.PutUint32(dst[off+cmsghdrTypeOff:], uint32(typ))
}

// readWord reads b[0:wordSize] as a host-order, word-sized unsigned integer:
// struct cmsghdr's cmsg_len is a __kernel_size_t, 4 bytes on a 32-bit build
// and 8 on a 64-bit one (abi.go's sizeCmsghdr comment).
func readWord(b []byte) uint64 {
	if wordSize == 8 {
		return binary.NativeEndian.Uint64(b)
	}
	return uint64(binary.NativeEndian.Uint32(b))
}

// putWord is readWord's write side.
func putWord(b []byte, v uint64) {
	if wordSize == 8 {
		binary.NativeEndian.PutUint64(b, v)
		return
	}
	binary.NativeEndian.PutUint32(b, uint32(v))
}
