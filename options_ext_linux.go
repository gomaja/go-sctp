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

//go:build linux

// options_ext_linux.go holds the typed socket options of a Conn for the
// extensions an association negotiates: which ones it has, authentication
// (RFC 4895), stream reconfiguration (RFC 6525), stream scheduling (RFC
// 8260) and partial reliability (RFC 7496). options_linux.go describes
// the errors they return and holds the option layer they share.

package sctp

import (
	"encoding/binary"
	"net"
)

// --- negotiated extensions -----------------------------------------------------

// negotiated reports whether the association negotiated an extension:
// the peer's capability Linux recorded from the INIT or INIT ACK, or, once
// the association has ended, the endpoint's own setting (net/sctp/socket.c:
// sctp_getsockopt_pr_supported and the other _supported getters).
func (c *Conn) negotiated(opt int) (bool, error) {
	v, err := c.assocValueOption(opt)
	return v != 0, err
}

// PRSupported reports whether the association negotiated partial
// reliability (PR-SCTP, RFC 3758; SCTP_PR_SUPPORTED, RFC 7496 §4.5). Set
// it with Config.PartialReliability before connecting; Linux offers it
// whenever net.sctp.prsctp_enable is on, and either end can decline it.
func (c *Conn) PRSupported() (bool, error) {
	return c.negotiated(optPRSupported)
}

// ReconfigSupported reports whether the association negotiated stream
// reconfiguration (RFC 6525; SCTP_RECONFIG_SUPPORTED). Set it with
// Config.StreamReconfiguration before connecting: a later change does not
// reach the association.
func (c *Conn) ReconfigSupported() (bool, error) {
	return c.negotiated(optReconfigSupported)
}

// ASCONFSupported reports whether the association negotiated dynamic
// address reconfiguration (ASCONF, RFC 5061; SCTP_ASCONF_SUPPORTED). Set it
// with Config.DynamicAddressReconfiguration before connecting.
func (c *Conn) ASCONFSupported() (bool, error) {
	return c.negotiated(optASCONFSupported)
}

// AuthSupported reports whether the association negotiated authenticated
// chunks (AUTH, RFC 4895; SCTP_AUTH_SUPPORTED). Set it with
// Config.Authentication before connecting.
func (c *Conn) AuthSupported() (bool, error) {
	return c.negotiated(optAuthSupported)
}

// InterleavingSupported reports whether the association negotiated message
// interleaving (I-DATA; SCTP_INTERLEAVING_SUPPORTED, RFC 8260 §4.3.1). Set it
// with Config.MessageInterleaving before connecting.
func (c *Conn) InterleavingSupported() (bool, error) {
	return c.negotiated(optInterleavingSupported)
}

// ECNSupported reports whether the association negotiated explicit
// congestion notification (SCTP_ECN_SUPPORTED, a Linux option). Set it
// with Config.ExperimentalECN before connecting.
func (c *Conn) ECNSupported() (bool, error) {
	return c.negotiated(optECNSupported)
}

// --- authentication ----------------------------------------------------------

// SetAuthKey installs shared key number key with secret for the
// association (SCTP_AUTH_KEY, RFC 6458 §8.3.3; RFC 4895 §6.1), replacing
// a key of that number. The secret is copied into the system call's
// argument, which is cleared before SetAuthKey returns. Linux refuses
// every AUTH option with EACCES on an association that did not negotiate
// AUTH (net/sctp/auth.c: sctp_auth_set_key). An empty secret, which Linux
// refuses, and one longer than the 65535 bytes the key length field can
// describe are refused with an error matching syscall.EINVAL before any
// system call; DeleteAuthKey removes a key.
func (c *Conn) SetAuthKey(key uint16, secret []byte) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	b, err := encodeAuthKey(c.AssocID(), key, secret, "SetAuthKey")
	if err != nil {
		return c.argError("set", err)
	}
	defer clear(b)
	return c.setOpt(optAuthKey, b)
}

// authKeyID lays out struct sctp_authkeyid for key number key: the
// association id and the key number, padded to the 8 bytes Linux requires
// (net/sctp/socket.c: sctp_setsockopt_active_key and its siblings refuse
// any other length).
func (c *Conn) authKeyID(key uint16) [sizeAuthKeyID]byte {
	var b [sizeAuthKeyID]byte
	binary.NativeEndian.PutUint32(b[authKeyIDAssocIDOff:], uint32(c.AssocID()))
	binary.NativeEndian.PutUint16(b[authKeyIDKeyNumberOff:], key)
	return b
}

// ActiveAuthKey reports the number of the key the association
// authenticates what it sends with (SCTP_AUTH_ACTIVE_KEY, RFC 6458
// §8.1.18; RFC 4895 §6.1). Key 0 is the null key every association starts
// with.
func (c *Conn) ActiveAuthKey() (uint16, error) {
	b := c.authKeyID(0)
	if _, err := c.getOpt(optAuthActiveKey, b[:]); err != nil {
		return 0, err
	}
	return binary.NativeEndian.Uint16(b[authKeyIDKeyNumberOff:]), nil
}

// SetActiveAuthKey makes key number key, already installed, the one the
// association authenticates what it sends with (SCTP_AUTH_ACTIVE_KEY, RFC
// 6458 §8.1.18). Linux refuses a number with no key with EINVAL
// (net/sctp/auth.c: sctp_auth_set_active_key).
func (c *Conn) SetActiveAuthKey(key uint16) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	b := c.authKeyID(key)
	return c.setOpt(optAuthActiveKey, b[:])
}

// DeactivateAuthKey stops the association sending with key number key,
// while still accepting what arrives authenticated with it, so that a
// rollover can wait for the peer before deleting the key
// (SCTP_AUTH_DEACTIVATE_KEY, RFC 6458 §8.3.4). Linux refuses the active
// key with EINVAL (net/sctp/auth.c: sctp_auth_deact_key_id): make another
// key active first.
func (c *Conn) DeactivateAuthKey(key uint16) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	b := c.authKeyID(key)
	return c.setOpt(optAuthDeactivateKey, b[:])
}

// DeleteAuthKey removes key number key from the association
// (SCTP_AUTH_DELETE_KEY, RFC 6458 §8.3.5). Linux refuses the active key,
// and a number with no key, with EINVAL (net/sctp/auth.c:
// sctp_auth_del_key_id).
func (c *Conn) DeleteAuthKey(key uint16) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	b := c.authKeyID(key)
	return c.setOpt(optAuthDeleteKey, b[:])
}

// HMACIdentifiers reports the HMAC algorithms this endpoint asks the peer
// to use, in its order of preference (SCTP_HMAC_IDENT, RFC 6458 §8.1.17;
// RFC 4895 §3.3). Set them with Config.HMACIdentifiers. Linux refuses the
// query with EACCES while AUTH is off for the endpoint
// (net/sctp/socket.c: sctp_getsockopt_hmac_ident).
func (c *Conn) HMACIdentifiers() ([]HMACID, error) {
	var b [sizeHMACAlgo + 2*maxHMACIdents]byte
	n, err := c.getOpt(optHMACIdent, b[:])
	if err != nil {
		return nil, err
	}
	ids, err := decodeHMACIdents(b[:], n)
	if err != nil {
		return nil, c.argError("get", err)
	}
	return ids, nil
}

// LocalAuthChunks reports the chunk types this side asked the peer to
// authenticate, as the association keeps them (SCTP_LOCAL_AUTH_CHUNKS, RFC
// 6458 §8.2.4; RFC 4895 §3.2). Set them with Config.AuthChunks.
func (c *Conn) LocalAuthChunks() ([]uint8, error) {
	return c.authChunks(optLocalAuthChunks)
}

// PeerAuthChunks reports the chunk types the peer asked this side to
// authenticate (SCTP_PEER_AUTH_CHUNKS, RFC 6458 §8.2.3; RFC 4895 §3.2).
func (c *Conn) PeerAuthChunks() ([]uint8, error) {
	return c.authChunks(optPeerAuthChunks)
}

// authChunks reads one of the two chunk lists, struct sctp_authchunks. A
// list holds at most maxAuthChunkList types. The buffer is sized for the
// header and that many, and the whole buffer is offered: Linux checks a
// peer list against the length without the 8-byte header but writes it
// after the header (net/sctp/socket.c: sctp_getsockopt_peer_auth_chunks),
// so a buffer only just long enough by that check could be overrun.
func (c *Conn) authChunks(opt int) ([]uint8, error) {
	var b [sizeAuthChunks + maxAuthChunkList]byte
	binary.NativeEndian.PutUint32(b[authChunksAssocIDOff:], uint32(c.AssocID()))
	n, err := c.getOpt(opt, b[:])
	if err != nil {
		return nil, err
	}
	chunks, err := decodeAuthChunks(b[:], n)
	if err != nil {
		return nil, c.argError("get", err)
	}
	return chunks, nil
}

// --- stream reconfiguration ------------------------------------------------------

// StreamResetMask reports which reconfiguration requests the association
// accepts from the peer and may make itself (SCTP_ENABLE_STREAM_RESET, RFC
// 6525 §6.3.1).
func (c *Conn) StreamResetMask() (StreamResetMask, error) {
	v, err := c.assocValueOption(optEnableStreamReset)
	return StreamResetMask(v), err
}

// SetStreamResetMask sets which reconfiguration requests the association
// accepts from the peer and may make itself (SCTP_ENABLE_STREAM_RESET, RFC
// 6525 §6.3.1). It takes effect only where reconfiguration was negotiated
// (Config.StreamReconfiguration). A bit StreamResetMask does not name is
// refused with an error matching syscall.EINVAL before any system call.
func (c *Conn) SetStreamResetMask(m StreamResetMask) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	if m&^streamResetKnownBits != 0 {
		return c.argError("set", invalidArg("SetStreamResetMask: %#x has unknown bits %#x", uint32(m), uint32(m&^streamResetKnownBits)))
	}
	return c.setAssocValueOption(optEnableStreamReset, uint32(m))
}

// ResetStreams asks to reset the sequence numbers of streams, or of every
// stream when none are named, in direction dir: ResetOutgoing for this
// side's outgoing streams, ResetIncoming to ask the peer to reset its
// outgoing ones, or both (SCTP_RESET_STREAMS, RFC 6525 §6.3.2). It returns
// once the request is sent; an EventStreamReset reports the outcome,
// including a refusal. Reconfiguration must have been negotiated, with
// EnableResetStreamReq in the mask, or Linux refuses with ENOPROTOOPT; a
// stream the association does not have is refused with EINVAL, and
// outgoing streams with messages still queued with EAGAIN
// (net/sctp/stream.c: sctp_send_reset_streams). A direction naming neither
// ResetIncoming nor ResetOutgoing, one with any other bit, and more than
// 65535 streams are refused with an error matching syscall.EINVAL before
// any system call.
//
// Only one reconfiguration request may be outstanding (RFC 6525 §5.1.1).
// While one is, ResetStreams, ResetAssoc and AddStreams return an error
// matching syscall.EINPROGRESS (net/sctp/stream.c). Wait for
// EventStreamReset, EventAssocReset or EventStreamChange before sending the
// next.
func (c *Conn) ResetStreams(dir ResetDirection, streams ...uint16) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	b, err := encodeResetStreams(c.AssocID(), dir, streams)
	if err != nil {
		return c.argError("set", err)
	}
	return c.setOpt(optResetStreams, b)
}

// ResetAssoc asks to reset the association's TSNs and every stream's
// sequence numbers (SCTP_RESET_ASSOC, RFC 6525 §6.3.3). It returns once
// the request is sent; an EventAssocReset reports the outcome.
// Reconfiguration must have been negotiated, with EnableResetAssocReq in
// the mask, or Linux refuses with ENOPROTOOPT; with messages still queued
// Linux refuses with EAGAIN (net/sctp/stream.c: sctp_send_reset_assoc).
// While another request is outstanding it returns an error matching
// syscall.EINPROGRESS, as ResetStreams does.
func (c *Conn) ResetAssoc() error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	var b [sizeAssocID]byte
	binary.NativeEndian.PutUint32(b[:], uint32(c.AssocID()))
	return c.setOpt(optResetAssoc, b[:])
}

// AddStreams asks to add in incoming and out outgoing streams to the
// association (SCTP_ADD_STREAMS, RFC 6525 §6.3.4). It returns once the
// request is sent; an EventStreamChange reports the outcome, and the
// number of streams it added. Reconfiguration must have been negotiated,
// with EnableChangeAssocReq in the mask, or Linux refuses with ENOPROTOOPT;
// a total beyond 65535 streams is refused with EINVAL (net/sctp/stream.c:
// sctp_send_add_streams). Adding no streams is refused with an error
// matching syscall.EINVAL before any system call. While another request is
// outstanding it returns an error matching syscall.EINPROGRESS, as
// ResetStreams does.
func (c *Conn) AddStreams(in, out uint16) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	if in == 0 && out == 0 {
		return c.argError("set", invalidArg("AddStreams needs at least one stream to add"))
	}
	var b [sizeAddStreams]byte
	binary.NativeEndian.PutUint32(b[addStreamsAssocIDOff:], uint32(c.AssocID()))
	binary.NativeEndian.PutUint16(b[addStreamsInStreamsOff:], in)
	binary.NativeEndian.PutUint16(b[addStreamsOutStreamsOff:], out)
	return c.setOpt(optAddStreams, b[:])
}

// --- stream scheduling -----------------------------------------------------------

// StreamScheduler reports how the association chooses the next outgoing
// stream to send from (SCTP_STREAM_SCHEDULER, RFC 8260 §4.3.2).
func (c *Conn) StreamScheduler() (Scheduler, error) {
	v, err := c.assocValueOption(optStreamScheduler)
	return Scheduler(v), err
}

// SetStreamScheduler chooses how the association picks the next outgoing
// stream to send from (SCTP_STREAM_SCHEDULER, RFC 8260 §4.3.2; RFC 8260 §3
// describes the schedulers). Linux has SchedFC and SchedWFQ since 6.4, and
// refuses them with EINVAL before (net/sctp/stream_sched.c:
// sctp_sched_set_sched). A value Scheduler does not name is refused with
// an error matching syscall.EINVAL before any system call.
func (c *Conn) SetStreamScheduler(s Scheduler) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	if s > SchedWFQ {
		return c.argError("set", invalidArg("SetStreamScheduler: %v is not a scheduler Linux implements", s))
	}
	return c.setAssocValueOption(optStreamScheduler, uint32(s))
}

// streamValue lays out struct sctp_stream_value for stream.
func (c *Conn) streamValue(stream, value uint16) [sizeStreamValue]byte {
	var b [sizeStreamValue]byte
	binary.NativeEndian.PutUint32(b[streamValueAssocIDOff:], uint32(c.AssocID()))
	binary.NativeEndian.PutUint16(b[streamValueStreamIDOff:], stream)
	binary.NativeEndian.PutUint16(b[streamValueValueOff:], value)
	return b
}

// StreamSchedulerValue reports the scheduler's value for an outgoing
// stream (SCTP_STREAM_SCHEDULER_VALUE, RFC 8260 §4.3.3): its priority under
// SchedPrio or its weight under SchedWFQ, and 0 under the schedulers that
// keep none (net/sctp/stream_sched*.c). Linux refuses a stream the
// association does not have with EINVAL.
func (c *Conn) StreamSchedulerValue(stream uint16) (uint16, error) {
	b := c.streamValue(stream, 0)
	if _, err := c.getOpt(optStreamSchedulerValue, b[:]); err != nil {
		return 0, err
	}
	return binary.NativeEndian.Uint16(b[streamValueValueOff:]), nil
}

// SetStreamSchedulerValue sets the scheduler's value for an outgoing stream
// (SCTP_STREAM_SCHEDULER_VALUE, RFC 8260 §4.3.3): its priority under
// SchedPrio, lower sent first, or its weight under SchedWFQ, which Linux
// refuses to be 0 (net/sctp/stream_sched_fc.c: sctp_sched_wfq_set). The
// other schedulers accept the value and keep none of it. Linux refuses a
// stream the association does not have with EINVAL.
func (c *Conn) SetStreamSchedulerValue(stream, value uint16) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	b := c.streamValue(stream, value)
	return c.setOpt(optStreamSchedulerValue, b[:])
}

// --- partial reliability ---------------------------------------------------------

// PRStreamStatus reports how many messages on an outgoing stream have been
// abandoned under policy, before and after being sent
// (SCTP_PR_STREAM_STATUS, RFC 7496 §4.3); PRAll totals every policy. Linux
// refuses a stream the association does not have with EINVAL
// (net/sctp/socket.c: sctp_getsockopt_pr_streamstatus). A policy other
// than PRTTL, PRRtx, PRPrio or PRAll is refused with an error matching
// syscall.EINVAL before any system call.
func (c *Conn) PRStreamStatus(stream uint16, policy PRPolicy) (*PRStatus, error) {
	return c.prStatus(optPRStreamStatus, "PRStreamStatus", stream, policy)
}

// PRAssocStatus reports how many messages of the association have been
// abandoned under policy, before and after being sent
// (SCTP_PR_ASSOC_STATUS, RFC 7496 §4.4); PRAll totals every policy.
// Policies are checked as for PRStreamStatus.
func (c *Conn) PRAssocStatus(policy PRPolicy) (*PRStatus, error) {
	return c.prStatus(optPRAssocStatus, "PRAssocStatus", 0, policy)
}

// prStatus is PRStreamStatus and PRAssocStatus.
func (c *Conn) prStatus(opt int, name string, stream uint16, policy PRPolicy) (*PRStatus, error) {
	if !c.opened() {
		return nil, c.optionError("get", net.ErrClosed)
	}
	if err := validateStatusPolicy(name, policy); err != nil {
		return nil, c.argError("get", err)
	}
	var b [sizePRStatus]byte
	prStatusRequest(b[:], c.AssocID(), stream, policy)
	if _, err := c.getOpt(opt, b[:]); err != nil {
		return nil, err
	}
	s := decodePRStatus(b[:])
	return &s, nil
}
