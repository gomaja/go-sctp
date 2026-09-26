// Copyright 2019 Wataru Ishida. All rights reserved.
// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// This file includes modifications by gomaja.

//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// notification.go decodes the RFC 6458 §6 notifications Linux delivers with
// MSG_NOTIFICATION set. ParseNotification turns one complete record into a
// typed value using abi.go's layout constants, copying every byte field it
// keeps so the result never aliases its input. notificationAccumulator
// reassembles a record that arrives split across reads, and
// notificationHeader / assocChangeInfo let a caller peek at a record's type,
// or at an SCTP_ASSOC_CHANGE's state and association id, without allocating.

package sctp

import (
	"encoding/binary"
	"errors"
	"math"
	"net/netip"
)

// NotificationHandler receives each notification, already reassembled and
// parsed, before the read that consumed it returns. A returned error is
// returned by that read. The value, including its byte slices, belongs to
// the handler: the package keeps no reference to it and never reuses its
// memory. Handlers may run concurrently and may call back into the
// connection.
type NotificationHandler func(Notification) error

// Notification is one parsed notification: a *AssocChange,
// *PeerAddrChange, *RemoteError, *Shutdown, *AdaptationIndication,
// *PartialDelivery, *AuthEvent, *SenderDry, *StreamReset, *AssocReset,
// *StreamChange or *SendFailed, or an *UnknownNotification for a type the
// package does not decode. Type reports which; a type switch reaches the
// fields. The package returns no other type.
type Notification interface{ Type() EventType }

// NotificationMaxSize is a read buffer size that holds any fixed-size
// notification this package parses: the largest of the twelve is
// sctp_paddr_change at 148 bytes. It is not a bound on every notification:
// SCTP_ASSOC_CHANGE (sac_info), SCTP_REMOTE_ERROR (sre_data),
// SCTP_STREAM_RESET_EVENT (strreset_stream_list) and SCTP_SEND_FAILED_EVENT
// (ssf_data) each carry a variable tail, so their whole size follows the
// data they carry rather than the struct.
const NotificationMaxSize = 1024

// NotificationReassemblyLimit bounds the memory a connection holds while it
// reassembles one notification, and is the largest declared length
// ParseNotification decodes: a header declaring more is refused with
// ErrNotificationTooLong before anything is allocated to hold it. Between
// notifications a connection keeps at most 64 KiB of reassembly storage,
// so one large notification does not keep a buffer of up to this size
// alive for the rest of the connection's life.
const NotificationReassemblyLimit = 1 << 20

// notificationDataDropCap is the cap above which reset drops data's
// backing array instead of reusing it (see reset's own comment).
const notificationDataDropCap = 64 * 1024

// AssocChange is SCTP_ASSOC_CHANGE (RFC 6458 §6.1.1), reporting that an
// association has come up, come down, restarted, or failed to start. State
// says which.
//
// Error is the first cause of the peer's ABORT, or the cause Linux assigned
// (CauseUserAbort, CauseProtocolViolation, CauseStaleCookie, ...), and
// CauseNone when the association failed without one, for example when
// retransmissions ran out. Linux stores it in network byte order in a
// host-order field (its cause constants are cpu_to_be16), and the package
// converts it. The same holds for RemoteError.Error and SendFailed.Error.
// Error is meaningful only when State is AssocCommLost or AssocCantStart.
//
// Info holds the peer's ABORT chunk without its 4-byte header, that is, its
// error causes, when an ABORT ended an established association
// (sctp_ulpevent_make_assoc_change in net/sctp/ulpevent.c). RFC 6458
// §6.1.1 describes the complete chunk. Held Erratum 6113 would also attach
// it to AssocCantStart, which Linux does not do. Info is empty in every
// other case.
//
// Linux never fills in RFC 6458 §6.1.1's list of supported features
// (SCTP_ASSOC_SUPPORTS_*) on AssocCommUp; its UAPI does not define them.
// Use the capability getters (PRSupported, AuthSupported, ...) instead.
type AssocChange struct {
	State      AssocChangeState
	Error      ErrorCause
	OutStreams uint16
	InStreams  uint16
	AssocID    AssocID
	Info       []byte
}

// Type reports EventAssocChange.
func (n *AssocChange) Type() EventType { return EventAssocChange }

// PeerAddrChange is SCTP_PEER_ADDR_CHANGE (RFC 6458 §6.1.2), reporting that
// one of the peer's addresses has changed reachability.
type PeerAddrChange struct {
	Addr    netip.AddrPort
	State   AddrChangeState
	Reason  AddrChangeReason // Linux's enum sctp_sn_error, decoded per AddrChangeReason's own rule
	AssocID AssocID
}

// Type reports EventPeerAddrChange.
func (n *PeerAddrChange) Type() EventType { return EventPeerAddrChange }

// SendFailed reports one DATA chunk that was not delivered. Linux sends one
// event per chunk, not per message (net/sctp/chunk.c), so a fragmented
// message produces one event per fragment, in order, from FirstFragment to
// LastFragment. Their Data values concatenate to the message. The flag
// fields are the DATA chunk header's own bits (RFC 9260 §3.3.1), which is
// what Linux copies into snd_flags. They are not the sender's SendFlags.
//
// Error is CauseNone when a PR-SCTP policy abandoned the message before it
// was sent, CauseInvalidStream when the message's stream stopped existing
// because the peer allowed fewer outbound streams (net/sctp/stream.c), and
// otherwise the cause that ended the association, decoded the same way as
// AssocChange.Error.
type SendFailed struct { // SCTP_SEND_FAILED_EVENT, RFC 6458 §6.1.11
	Error         ErrorCause
	Sent          bool // transmitted but unacknowledged (SCTP_DATA_SENT), else never sent
	Stream        uint16
	PPID          uint32 // host byte order
	Context       uint32 // SndInfo.Context of the failed message
	Unordered     bool   // U bit
	FirstFragment bool   // B bit
	LastFragment  bool   // E bit
	AssocID       AssocID
	Data          []byte // this fragment's payload
}

// Type reports EventSendFailed.
func (n *SendFailed) Type() EventType { return EventSendFailed }

// RemoteError reports one error cause from an ERROR chunk the peer sent.
// Linux sends one event per cause, in order, when the chunk carries several
// (sctp_cmd_process_operr in net/sctp/sm_sideeffect.c).
type RemoteError struct { // RFC 6458 §6.1.3
	Error   ErrorCause
	AssocID AssocID
	Data    []byte // this cause's information, without its 4-byte header; padded to a multiple of 4
}

// Type reports EventRemoteError.
func (n *RemoteError) Type() EventType { return EventRemoteError }

// Shutdown is SCTP_SHUTDOWN_EVENT (RFC 6458 §6.1.5): the peer has shut the
// association down and will accept no further data.
type Shutdown struct{ AssocID AssocID }

// Type reports EventShutdown.
func (n *Shutdown) Type() EventType { return EventShutdown }

// SenderDry is SCTP_SENDER_DRY_EVENT (RFC 6458 §6.1.9): the stack has no
// more user data to send and none outstanding.
type SenderDry struct{ AssocID AssocID }

// Type reports EventSenderDry.
func (n *SenderDry) Type() EventType { return EventSenderDry }

// PartialDelivery is SCTP_PARTIAL_DELIVERY_EVENT (RFC 6458 §6.1.7): a
// partial delivery was aborted. It is the only indication the kernel
// defines for this event (enum { SCTP_PARTIAL_DELIVERY_ABORTED = 0 },
// include/uapi/linux/sctp.h), so this struct carries no separate
// Indication field.
//
// Stream and SeqNum are filled in only when I-DATA (RFC 8260) is in use;
// net/sctp/ulpqueue.c's sctp_ulpq_abort_pd, the classic (non-I-DATA) path,
// always passes zero for both. With I-DATA, Stream is the stream of the
// aborted delivery, and SeqNum is the MID Linux reports: the aborted
// message's own when the association's receive queue is flushed
// (net/sctp/stream_interleave.c: sctp_intl_abort_pd), or the MID of the
// I-FORWARD-TSN skip entry that ended the delivery (sctp_intl_skip, RFC
// 8260 §2.3.1), which can be past the aborted message's.
//
// Unordered is pdapi_flags's bit 0. RFC 6458 §6.1.7 calls the field
// unused, and net/sctp/ulpevent.c's sctp_ulpevent_make_pdapi still quotes
// that description, but net/sctp/stream_interleave.c (sctp_intl_abort_pd,
// sctp_intl_skip) sets this bit when the aborted partial delivery was an
// unordered message under I-DATA, and leaves it clear otherwise —
// including on the classic path, which never sets it either.
type PartialDelivery struct {
	Stream    uint32 // with I-DATA (RFC 8260) only; Linux reports 0 otherwise
	SeqNum    uint32 // with I-DATA only: the MID Linux reports (see above); 0 otherwise
	Unordered bool
	AssocID   AssocID
}

// Type reports EventPartialDelivery.
func (n *PartialDelivery) Type() EventType { return EventPartialDelivery }

// AdaptationIndication is SCTP_ADAPTATION_INDICATION (RFC 6458 §6.1.6),
// carrying the peer's adaptation layer indication.
type AdaptationIndication struct {
	Indication uint32
	AssocID    AssocID
}

// Type reports EventAdaptationIndication.
func (n *AdaptationIndication) Type() EventType { return EventAdaptationIndication }

// AuthEvent is SCTP_AUTHENTICATION_EVENT (RFC 6458 §6.1.8), reporting a
// change in the AUTH shared keys in force.
type AuthEvent struct {
	Key, AltKey uint16
	Indication  AuthIndication
	AssocID     AssocID
}

// Type reports EventAuthentication.
func (n *AuthEvent) Type() EventType { return EventAuthentication }

// StreamReset is SCTP_STREAM_RESET_EVENT (RFC 6525 §6.1.1), reporting the
// outcome of a stream reset — this side's or the peer's.
type StreamReset struct {
	Incoming, Outgoing bool
	Denied, Failed     bool
	Streams            []uint16 // empty = all streams
	AssocID            AssocID
}

// Type reports EventStreamReset.
func (n *StreamReset) Type() EventType { return EventStreamReset }

// AssocReset is SCTP_ASSOC_RESET_EVENT (RFC 6525 §6.1.2), reporting the
// outcome of an association reset and the TSNs the two sides restarted
// from.
type AssocReset struct {
	Denied, Failed      bool
	LocalTSN, RemoteTSN uint32
	AssocID             AssocID
}

// Type reports EventAssocReset.
func (n *AssocReset) Type() EventType { return EventAssocReset }

// StreamChange is SCTP_STREAM_CHANGE_EVENT (RFC 6525 §6.1.3), reporting the
// outcome of an AddStreams request.
type StreamChange struct {
	Denied, Failed        bool
	InStreams, OutStreams uint16 // streams the request added, not the new totals
	AssocID               AssocID
}

// Type reports EventStreamChange.
func (n *StreamChange) Type() EventType { return EventStreamChange }

// UnknownNotification carries a notification type this package does not
// decode, so a kernel addition is never dropped silently.
type UnknownNotification struct{ Data []byte }

// Type reads the notification type straight out of Data's own header,
// rather than from a stored field: an unknown type has no named constant to
// hold. It returns 0 on a nil receiver, or if Data is too short to carry
// one, consistent with every other notification type's Type method.
func (n *UnknownNotification) Type() EventType {
	if n == nil || len(n.Data) < notificationHeaderSize {
		return 0
	}
	return EventType(binary.NativeEndian.Uint16(n.Data[notificationTypeOff:]))
}

// ParseNotification decodes one complete notification. The result copies
// what it needs and never aliases b.
//
// The header's own length field, not len(b) and not the size of any fixed
// struct, is the event's extent: Linux sets it to the whole size of the
// event and delivers exactly that many bytes, so anything in b past it
// belongs to a different read (a caller that passed its whole read buffer
// rather than b[:n], for one), and a b shorter than it is refused with
// ErrShortNotification. An event with a variable tail may be larger than
// NotificationMaxSize: an SCTP_SEND_FAILED_EVENT carries the undelivered
// payload. Bounding an event by a fixed struct size instead is the defect
// JDK-8067846 reports, where a send-failed notification longer than the
// 148-byte union sctp_notification was rejected as impossible.
//
// A malformed embedded address in an SCTP_PEER_ADDR_CHANGE record — an
// address family this package does not recognise, or one that does not fit
// the record — returns that decode's own error, which matches
// syscall.EINVAL. That is not ErrShortNotification: the record itself is
// complete and long enough, only the address inside it is malformed.
func ParseNotification(b []byte) (Notification, error) {
	typ, flags, length, ok := notificationHeader(b)
	if !ok {
		return nil, ErrShortNotification
	}
	if length < notificationHeaderSize {
		return nil, ErrShortNotification
	}
	if length > NotificationReassemblyLimit {
		return nil, ErrNotificationTooLong
	}
	if length > uint32(len(b)) {
		return nil, ErrShortNotification
	}
	b = b[:length]

	switch typ {
	case EventAssocChange:
		if len(b) < sizeAssocChange {
			return nil, ErrShortNotification
		}
		n := &AssocChange{
			State:      AssocChangeState(binary.NativeEndian.Uint16(b[assocChangeStateOff:])),
			Error:      ErrorCause(causeFromU16(b[assocChangeErrorOff:])),
			OutStreams: binary.NativeEndian.Uint16(b[assocChangeOutStreamsOff:]),
			InStreams:  binary.NativeEndian.Uint16(b[assocChangeInStreamsOff:]),
			AssocID:    AssocID(binary.NativeEndian.Uint32(b[assocChangeAssocIDOff:])),
		}
		if len(b) > sizeAssocChange {
			n.Info = append([]byte(nil), b[sizeAssocChange:]...)
		}
		return n, nil

	case EventPeerAddrChange:
		return decodePeerAddrChangeOrder(b, binary.NativeEndian)

	case EventRemoteError:
		if len(b) < sizeRemoteError {
			return nil, ErrShortNotification
		}
		n := &RemoteError{
			Error:   ErrorCause(causeFromU16(b[remoteErrorErrorOff:])),
			AssocID: AssocID(binary.NativeEndian.Uint32(b[remoteErrorAssocIDOff:])),
		}
		if len(b) > sizeRemoteError {
			n.Data = append([]byte(nil), b[remoteErrorDataOff:]...)
		}
		return n, nil

	case EventShutdown:
		if len(b) < sizeShutdownEvent {
			return nil, ErrShortNotification
		}
		return &Shutdown{
			AssocID: AssocID(binary.NativeEndian.Uint32(b[shutdownEventAssocIDOff:])),
		}, nil

	case EventPartialDelivery:
		if len(b) < sizePDAPIEvent {
			return nil, ErrShortNotification
		}
		return &PartialDelivery{
			Stream:    binary.NativeEndian.Uint32(b[pdapiEventStreamOff:]),
			SeqNum:    binary.NativeEndian.Uint32(b[pdapiEventSeqOff:]),
			Unordered: flags&pdapiFlagUnordered != 0,
			AssocID:   AssocID(binary.NativeEndian.Uint32(b[pdapiEventAssocIDOff:])),
		}, nil

	case EventAdaptationIndication:
		if len(b) < sizeAdaptationEvent {
			return nil, ErrShortNotification
		}
		return &AdaptationIndication{
			Indication: binary.NativeEndian.Uint32(b[adaptationEventIndicationOff:]),
			AssocID:    AssocID(binary.NativeEndian.Uint32(b[adaptationEventAssocIDOff:])),
		}, nil

	case EventAuthentication:
		if len(b) < sizeAuthKeyEvent {
			return nil, ErrShortNotification
		}
		return &AuthEvent{
			Key:        binary.NativeEndian.Uint16(b[authKeyEventKeyNumberOff:]),
			AltKey:     binary.NativeEndian.Uint16(b[authKeyEventAltKeyNumberOff:]),
			Indication: AuthIndication(binary.NativeEndian.Uint32(b[authKeyEventIndicationOff:])),
			AssocID:    AssocID(binary.NativeEndian.Uint32(b[authKeyEventAssocIDOff:])),
		}, nil

	case EventSenderDry:
		if len(b) < sizeSenderDryEvent {
			return nil, ErrShortNotification
		}
		return &SenderDry{
			AssocID: AssocID(binary.NativeEndian.Uint32(b[senderDryEventAssocIDOff:])),
		}, nil

	case EventStreamReset:
		if len(b) < sizeStreamResetEvent {
			return nil, ErrShortNotification
		}
		tail := b[streamResetEventStreamsOff:]
		if len(tail)%2 != 0 {
			// strreset_stream_list is a flexible array of uint16 stream ids;
			// an odd tail cannot be one and is rejected rather than
			// silently dropping its last byte.
			return nil, ErrShortNotification
		}
		var streams []uint16
		if len(tail) > 0 {
			streams = make([]uint16, len(tail)/2)
			for i := range streams {
				streams[i] = binary.NativeEndian.Uint16(tail[i*2:])
			}
		}
		return &StreamReset{
			Incoming: flags&streamResetFlagIncoming != 0,
			Outgoing: flags&streamResetFlagOutgoing != 0,
			Denied:   flags&streamResetFlagDenied != 0,
			Failed:   flags&streamResetFlagFailed != 0,
			Streams:  streams,
			AssocID:  AssocID(binary.NativeEndian.Uint32(b[streamResetEventAssocIDOff:])),
		}, nil

	case EventAssocReset:
		if len(b) < sizeAssocResetEvent {
			return nil, ErrShortNotification
		}
		return &AssocReset{
			Denied:    flags&assocResetFlagDenied != 0,
			Failed:    flags&assocResetFlagFailed != 0,
			LocalTSN:  binary.NativeEndian.Uint32(b[assocResetEventLocalTSNOff:]),
			RemoteTSN: binary.NativeEndian.Uint32(b[assocResetEventRemoteTSNOff:]),
			AssocID:   AssocID(binary.NativeEndian.Uint32(b[assocResetEventAssocIDOff:])),
		}, nil

	case EventStreamChange:
		if len(b) < sizeStreamChangeEvent {
			return nil, ErrShortNotification
		}
		return &StreamChange{
			Denied:     flags&streamChangeFlagDenied != 0,
			Failed:     flags&streamChangeFlagFailed != 0,
			InStreams:  binary.NativeEndian.Uint16(b[streamChangeEventInStreamsOff:]),
			OutStreams: binary.NativeEndian.Uint16(b[streamChangeEventOutStreamsOff:]),
			AssocID:    AssocID(binary.NativeEndian.Uint32(b[streamChangeEventAssocIDOff:])),
		}, nil

	case EventSendFailed:
		if len(b) < sizeSendFailedEvent {
			return nil, ErrShortNotification
		}
		sndFlags := binary.NativeEndian.Uint16(b[sendFailedEventInfoOff+sndInfoFlagsOff:])
		n := &SendFailed{
			Error:         ErrorCause(causeFromU32(b[sendFailedEventErrorOff:])),
			Sent:          flags&sendFailedFlagSent != 0,
			Stream:        binary.NativeEndian.Uint16(b[sendFailedEventInfoOff+sndInfoStreamOff:]),
			PPID:          binary.BigEndian.Uint32(b[sendFailedEventInfoOff+sndInfoPPIDOff:]),
			Context:       binary.NativeEndian.Uint32(b[sendFailedEventInfoOff+sndInfoContextOff:]),
			Unordered:     sndFlags&dataChunkFlagUnordered != 0,
			FirstFragment: sndFlags&dataChunkFlagFirstFragment != 0,
			LastFragment:  sndFlags&dataChunkFlagLastFragment != 0,
			AssocID:       AssocID(binary.NativeEndian.Uint32(b[sendFailedEventAssocIDOff:])),
		}
		if len(b) > sizeSendFailedEvent {
			n.Data = append([]byte(nil), b[sendFailedEventDataOff:]...)
		}
		return n, nil

	default:
		// A notification type this package does not model, either because
		// the kernel added one or because b is not a notification at all.
		// UnknownNotification carries the whole record rather than
		// dropping it, so a kernel addition is never silently lost.
		return &UnknownNotification{Data: append([]byte(nil), b...)}, nil
	}
}

// causeFromU16 decodes an RFC 9260 §3.3.10 error cause the kernel stored in
// sac_error or sre_error, both __u16 (sre_error additionally declared
// __be16 in the UAPI header). The kernel's own cause constants are
// cpu_to_be16 (include/linux/sctp.h), and every path that fills these two
// fields assigns one of them, or the raw __be16 straight off a received
// ABORT or ERROR chunk, into the host-typed field without converting
// (net/sctp/ulpevent.c: sctp_ulpevent_make_assoc_change,
// sctp_ulpevent_make_remote_error). So the two bytes in the buffer are
// always the network representation, and reading them big-endian is right
// on every host.
func causeFromU16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

// causeFromU32 decodes the same kind of cause from ssf_error, which the
// kernel widens into a __u32 by an ordinary C integer promotion when a
// cpu_to_be16 constant (or a received cause) is passed to
// sctp_ulpevent_make_send_failed_event's __u32 parameter
// (net/sctp/ulpevent.c). The promotion zero-extends the numeric value, so
// unlike causeFromU16 the raw bytes are not simply the network form: their
// position within the 4-byte field depends on host byte order. It always
// decodes against this host's own order (binary.NativeEndian) — see
// causeFromU32Order for the parameterised form this delegates to, which
// lets a test exercise the other order's layout as well.
func causeFromU32(b []byte) uint16 {
	return causeFromU32Order(b, binary.NativeEndian)
}

// causeFromU32Order is causeFromU32 with the byte order the 4-byte field
// was laid out in made explicit, rather than fixed to this host's own.
// Re-encoding the reconstructed low 16 bits with order and reading the
// result back BigEndian undoes exactly the promotion causeFromU32
// documents, for either order: order.Uint32 recovers the numeric value a
// kernel using that order stored, uint16 truncates it to the promoted
// cause's own low half, and order.PutUint16 followed by a BigEndian read
// reproduces the network-order two bytes regardless of which order did the
// widening.
func causeFromU32Order(b []byte, order binary.ByteOrder) uint16 {
	v := uint16(order.Uint32(b))
	var tmp [2]byte
	order.PutUint16(tmp[:], v)
	return binary.BigEndian.Uint16(tmp[:])
}

// decodeAddrChangeReason maps a raw spc_error (Linux's enum sctp_sn_error)
// and the record's decoded State to an AddrChangeReason.
//
// Linux sends spc_error 0 both for its own first member,
// SCTP_FAILED_THRESHOLD, and for "no reason at all", for example on
// entering the Potentially Failed state (net/sctp/sm_sideeffect.c). The
// package resolves the clash by State: 0 decodes to ReasonFailedThreshold
// only when State is AddrUnreachable — the state SCTP_FAILED_THRESHOLD is
// actually reported for — and to ReasonNone otherwise. Every raw value from
// 1 to 6 decodes to AddrChangeReason(raw+1): AddrChangeReason's own
// constants are numbered one past the kernel's enum sctp_sn_error precisely
// so that this rule recovers every named reason (raw 1 decodes to
// ReasonReceivedSACK=2, ... raw 6 to ReasonPeerFaulty=7) with no per-value
// table.
//
// A raw value the kernel's own (unsigned, in its numbering) enum could
// never produce — negative, or already the largest int32 — renders as
// AddrChangeReason(raw) instead of AddrChangeReason(raw+1): shifting it
// would either land on a name this function assigns to a different raw
// (raw == -1 would give 0, ReasonNone's own number, despite raw not being
// 0) or overflow int32 outright (raw+1 has no int32 representation when raw
// is already math.MaxInt32). Both renderings still print as
// AddrChangeReason(n) through the type's own String method; they are just
// not shifted, so a value spc_error can never actually carry can never be
// mistaken for one it can.
func decodeAddrChangeReason(raw int32, state AddrChangeState) AddrChangeReason {
	if raw == 0 {
		if state == AddrUnreachable {
			return ReasonFailedThreshold
		}
		return ReasonNone
	}
	if raw < 0 || raw == math.MaxInt32 {
		return AddrChangeReason(raw)
	}
	return AddrChangeReason(raw + 1)
}

// decodePeerAddrChangeOrder decodes a complete SCTP_PEER_ADDR_CHANGE record
// (b already truncated to its declared length by ParseNotification) with
// the given byte order for its two plain host-order C ints, spc_state and
// spc_error. ParseNotification's EventPeerAddrChange case calls this with
// binary.NativeEndian; a test can call it with an explicit order to decode
// a record built the way a kernel using that order would lay it out,
// independent of which order this host actually is.
//
// The embedded address is not part of that parameterisation: decodeAddr
// reads sockaddr_in/sockaddr_in6's family field with this host's own
// NativeEndian regardless, because a real kernel using some other order
// would also encode its family field in that same order — an address
// decoded on this host only ever comes from this host's own kernel, so
// there is no "other order" for it to be tested against the way there is
// for spc_state and spc_error.
func decodePeerAddrChangeOrder(b []byte, order binary.ByteOrder) (Notification, error) {
	if len(b) < sizePAddrChange {
		return nil, ErrShortNotification
	}
	addr, err := decodeAddr(b[paddrChangeAddrOff:paddrChangeStateOff])
	if err != nil {
		return nil, err
	}
	state := AddrChangeState(int32(order.Uint32(b[paddrChangeStateOff:])))
	reason := int32(order.Uint32(b[paddrChangeErrorOff:]))
	return &PeerAddrChange{
		Addr:    addr,
		State:   state,
		Reason:  decodeAddrChangeReason(reason, state),
		AssocID: AssocID(order.Uint32(b[paddrChangeAssocIDOff:])),
	}, nil
}

// notificationHeader reads type, flags, length from the first 8 bytes.
func notificationHeader(b []byte) (typ EventType, flags uint16, length uint32, ok bool) {
	if len(b) < notificationHeaderSize {
		return 0, 0, 0, false
	}
	typ = EventType(binary.NativeEndian.Uint16(b[notificationTypeOff:]))
	flags = binary.NativeEndian.Uint16(b[notificationFlagsOff:])
	length = binary.NativeEndian.Uint32(b[notificationLengthOff:])
	return typ, flags, length, true
}

// assocChangeInfo reads sac_state and sac_assoc_id from a complete or
// partial SCTP_ASSOC_CHANGE record without allocating. It is the receive
// path's internal-subscription fast path: recognising AssocCommLost or
// AssocShutdownComplete, and the id they name, needs no full
// ParseNotification and no copy of the record's bytes. ok is false when b
// does not yet reach sac_assoc_id (fewer than sizeAssocChange bytes), which
// happens while a record is still arriving in fragments. It always decodes
// against this host's own order; see assocChangeInfoOrder for the
// parameterised form this delegates to.
func assocChangeInfo(b []byte) (state AssocChangeState, id AssocID, ok bool) {
	return assocChangeInfoOrder(b, binary.NativeEndian)
}

// assocChangeInfoOrder is assocChangeInfo with the byte order sac_state and
// sac_assoc_id were laid out in made explicit, the same shape as
// causeFromU32Order and decodePeerAddrChangeOrder: it lets a test decode a
// record built the way a kernel using some other order would lay it out,
// independent of which order this host actually is.
func assocChangeInfoOrder(b []byte, order binary.ByteOrder) (state AssocChangeState, id AssocID, ok bool) {
	if len(b) < sizeAssocChange {
		return 0, 0, false
	}
	state = AssocChangeState(order.Uint16(b[assocChangeStateOff:]))
	id = AssocID(order.Uint32(b[assocChangeAssocIDOff:]))
	return state, id, true
}

// notificationAccumulator reassembles a notification split across reads,
// bounded by NotificationReassemblyLimit. Storage is per connection and
// reused across records: reset trims data to zero length and keeps its
// backing array, so a connection that keeps receiving similarly-sized
// notifications does not reallocate for each one, unless that array has
// grown past notificationDataDropCap, which reset drops instead.
//
// The first sizeAssocChange bytes of every record are collected into a
// fixed-size, struct-resident prefix regardless of retain, so a caller can
// pass prefix[:prefixBytes] to assocChangeInfo as soon as an
// SCTP_ASSOC_CHANGE's sac_state and sac_assoc_id have arrived, without
// allocating — even one not retaining the full record (no
// NotificationHandler, say) still gets this peek, which is what lets the
// receive path recognise AssocCommLost/AssocShutdownComplete without
// waiting for the handler path.
//
// Even when retain is false, add still validates the declared length, so a
// malformed notification is never silently consumed: add becomes
// allocation-free once an error is recorded, and callers keep reading
// through the record's end (MSG_EOR) to resynchronise, without retaining
// anything further.
type notificationAccumulator struct {
	data         []byte
	prefix       [sizeAssocChange]byte
	prefixBytes  int
	total        int
	declared     uint32
	haveDeclared bool
	retain       bool
	err          error
}

// add appends one fragment (everything read from one recvmsg call flagged
// MSG_NOTIFICATION) to the record in progress, validating the declared
// length as soon as the header is complete and refusing to grow past
// NotificationReassemblyLimit.
func (a *notificationAccumulator) add(fragment []byte) {
	if a.err != nil || len(fragment) == 0 {
		return
	}
	if len(fragment) > NotificationReassemblyLimit-a.total {
		a.fail(ErrNotificationTooLong)
		return
	}

	if a.prefixBytes < len(a.prefix) {
		a.prefixBytes += copy(a.prefix[a.prefixBytes:], fragment)
	}
	a.total += len(fragment)

	if a.prefixBytes >= notificationHeaderSize && !a.haveDeclared {
		a.declared = binary.NativeEndian.Uint32(a.prefix[notificationLengthOff : notificationLengthOff+4])
		a.haveDeclared = true
		if a.declared < notificationHeaderSize {
			a.fail(ErrShortNotification)
			return
		}
		if a.declared > NotificationReassemblyLimit {
			a.fail(ErrNotificationTooLong)
			return
		}
	}
	if a.haveDeclared && uint32(a.total) > a.declared {
		a.fail(ErrShortNotification)
		return
	}
	if a.retain {
		a.data = append(a.data, fragment...)
	}
}

// peekType returns the type of the record in progress once its header is
// complete, counting next, a fragment add has not seen yet, and reports
// false while the header is still incomplete. It lets a caller decide
// whether to retain a record before the fragment that completes its
// header is added, without allocating.
func (a *notificationAccumulator) peekType(next []byte) (EventType, bool) {
	if a.total+len(next) < notificationHeaderSize {
		return 0, false
	}
	var hdr [notificationHeaderSize]byte
	k := copy(hdr[:], a.prefix[:a.prefixBytes])
	copy(hdr[k:], next)
	return EventType(binary.NativeEndian.Uint16(hdr[notificationTypeOff:])), true
}

// keep switches retention on for the record in progress, starting data
// with the bytes add has already seen, which are all still in prefix while
// the record has not outgrown it. It reports whether the record is
// retained: false when the record has outgrown prefix, so that bytes seen
// earlier are lost, or when an error has already stopped it.
func (a *notificationAccumulator) keep() bool {
	if a.retain {
		return true
	}
	if a.err != nil || a.total > a.prefixBytes {
		return false
	}
	a.retain = true
	a.data = append(a.data, a.prefix[:a.prefixBytes]...)
	return true
}

// head returns the start of the record in progress: its first
// sizeAssocChange bytes, or as many as have arrived, which is what
// assocChangeInfo reads. It aliases the accumulator.
func (a *notificationAccumulator) head() []byte {
	return a.prefix[:a.prefixBytes]
}

// finish returns the reassembled record once add has seen exactly its
// declared length, or the error that stopped it short. The returned slice
// aliases data: it is valid only until the next add or reset, either of
// which may overwrite or replace data's backing array. A caller that keeps
// the bytes past that point must copy them. ParseNotification does, so the
// value it builds from them, which a NotificationHandler receives, never
// aliases data.
func (a *notificationAccumulator) finish() ([]byte, error) {
	if a.err != nil {
		return nil, a.err
	}
	if !a.haveDeclared || uint32(a.total) != a.declared {
		return nil, ErrShortNotification
	}
	return a.data, nil
}

// interrupted reports a missing record delimiter even when the bytes
// received so far happen to equal the header's declared length: the
// delimiter, not the length field alone, is what proves delivery completed
// (a poller wakeup or a closed connection can end a read early without one).
// Its result always matches ErrShortNotification, joined with any more
// specific error finish already recorded (ErrNotificationTooLong, say), so
// a caller can test for either the general or the specific condition.
func (a *notificationAccumulator) interrupted() error {
	_, err := a.finish()
	if err == nil {
		return ErrShortNotification
	}
	if errors.Is(err, ErrShortNotification) {
		return err
	}
	return errors.Join(err, ErrShortNotification)
}

// fail records err and drops any bytes retained so far: nothing collected
// under an error is ever handed back by finish.
func (a *notificationAccumulator) fail(err error) {
	a.err = err
	a.data = nil
}

// reset prepares the accumulator for the next record. data keeps its
// underlying array (a.data = a.data[:0]) so that a connection reusing one
// accumulator across many similarly-sized notifications does not
// reallocate — unless that array is larger than notificationDataDropCap,
// in which case reset drops it instead (a.data = nil): a connection that
// happened to decode one huge notification, up to NotificationReassemblyLimit,
// must not keep that buffer alive for the rest of its life merely because
// the accumulator that decoded it gets reused for every ordinary one after
// it. Every other field returns to its zero value, retain included — the
// caller sets retain afresh for the record about to start, the same
// per-record decision v1 made by building a new value outright.
func (a *notificationAccumulator) reset() {
	if cap(a.data) > notificationDataDropCap {
		a.data = nil
	} else {
		a.data = a.data[:0]
	}
	a.prefix = [sizeAssocChange]byte{}
	a.prefixBytes = 0
	a.total = 0
	a.declared = 0
	a.haveDeclared = false
	a.retain = false
	a.err = nil
}
