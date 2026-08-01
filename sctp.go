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

// Package sctp is a binding for the Linux kernel's SCTP stack.
//
// It does not implement SCTP. Chunk handling, association setup,
// retransmission, congestion control, path management and checksums all belong
// to the kernel; what is here is the socket API around them — net.Conn and
// net.Listener implementations, the socket options of RFC 6458 and its
// extensions, ancillary data, and the notifications the kernel delivers on the
// data stream.
//
// # Platforms
//
// The socket-backed implementation is selected by Go's linux build tag, which
// also applies to Android and includes Linux/386. On other targets with a real
// syscall package the package still compiles, and entry points that need an
// SCTP socket return ErrUnsupported, which wraps errors.ErrUnsupported.
//
// Two qualifications: plan9, js/wasm and wasip1/wasm do not compile, their
// syscall packages having no RawSockaddrInet4; and ResolveSCTPAddr never touches
// the kernel, so it works normally everywhere rather than reporting
// ErrUnsupported.
//
// # Reading
//
// SCTP is message-oriented, so a read returns either a whole message or part of
// one and SCTPRead cannot say which: a message larger than the buffer is split,
// and the remainder arrives looking like a fresh message. Use ReadMsg, which
// reassembles, or SCTPReadFlags and test the flags for MSG_EOR.
//
// SCTPReadFlags also reports MSG_NOTIFICATION when no NotificationHandler is
// installed; pass those bytes to ParseNotification. A configured handler
// consumes notifications before the read returns. Read and ReadMsg always skip
// notifications. SCTPReadMsg is the raw one-recvmsg escape hatch and applies no
// notification or framing policy.
//
// # Writing
//
// Write follows net.Conn semantics: it waits for the complete SCTP message to
// be accepted, or until a deadline, Close, or another error ends the operation.
// SCTPWrite and SCTPWriteInfo retain their message-oriented non-blocking
// behaviour without a write deadline and may return EAGAIN when the send buffer
// is full; setting a write deadline makes them wait through the runtime poller.
//
// # Options announced in the INIT
//
// Several options are only meaningful before the association exists, because
// they are announced in the INIT chunk: SetInitMsg, SetAdaptationLayer, and the
// capability negotiations SetPrSupported, SetReconfigSupported,
// SetAsconfSupported, SetAuthSupported and SetEcnSupported. Setting one on an
// established association is accepted and does nothing. Several also depend on
// a net.sctp.* sysctl; each says so.
package sctp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	SOL_SCTP = 132

	SCTP_BINDX_ADD_ADDR = 0x01
	SCTP_BINDX_REM_ADDR = 0x02

	MSG_NOTIFICATION = 0x8000

	// MSG_EOR is set in the flags returned by SCTPReadFlags when the buffer
	// received the end of a message. Its absence means the message was
	// truncated to the buffer and the remainder follows on later reads.
	MSG_EOR = 0x80
)

// ErrMsgTooLong is returned by ReadMsg when a message exceeds the caller's
// limit. The bytes read up to the limit are returned with it; ReadMsg drains
// the rest of that message before returning so the next read starts at the
// next message boundary.
var ErrMsgTooLong = errors.New("sctp: message exceeds maximum length")

// ErrMessageInterrupted reports that ReadMsg consumed the beginning of an SCTP
// user message but could not reach MSG_EOR. The returned bytes are only a
// prefix. The connection is aborted before ReadMsg returns so a queued tail can
// never be mistaken for a new message on a later call.
var ErrMessageInterrupted = errors.New("sctp: message interrupted before end of record")

// ErrControlTruncated reports that the kernel could not fit all ancillary
// data for a received message in the supplied control buffer. The payload may
// still have been received, but its stream, PPID, association, or next-message
// metadata is incomplete and must not be silently treated as authoritative.
var ErrControlTruncated = errors.New("sctp: control message data truncated")

// ErrUnsupported is returned by socket-backed entry points on a platform
// without SCTP.
//
// It is declared on every platform so portable callers can use either the
// package-specific or standard-library check without a build constraint:
//
//	errors.Is(err, sctp.ErrUnsupported)
//	errors.Is(err, errors.ErrUnsupported)
var ErrUnsupported = fmt.Errorf("sctp: socket operation unsupported: %w",
	errors.ErrUnsupported)

// errNilContext is shared by every context-aware dial path so nil has the
// same non-panicking result on Linux and unsupported platforms.
var errNilContext = fmt.Errorf("sctp: nil context: %w", syscall.EINVAL)

const (
	SCTP_RTOINFO = iota
	SCTP_ASSOCINFO
	SCTP_INITMSG
	SCTP_NODELAY
	SCTP_AUTOCLOSE
	SCTP_SET_PEER_PRIMARY_ADDR
	SCTP_PRIMARY_ADDR
	SCTP_ADAPTATION_LAYER
	SCTP_DISABLE_FRAGMENTS
	SCTP_PEER_ADDR_PARAMS
	// SCTP_DEFAULT_SEND_PARAM is option 10. Both the kernel's uapi header and
	// RFC 6458 §8.1.13 spell it SEND; this package shipped it as SENT, so the
	// name below is the correct one and SCTP_DEFAULT_SENT_PARAM is kept as an
	// alias rather than renamed out from under callers.
	SCTP_DEFAULT_SEND_PARAM
	SCTP_EVENTS
	SCTP_I_WANT_MAPPED_V4_ADDR
	SCTP_MAXSEG
	SCTP_STATUS
	SCTP_GET_PEER_ADDR_INFO
	SCTP_DELAYED_ACK_TIME
	SCTP_DELAYED_ACK  = SCTP_DELAYED_ACK_TIME
	SCTP_DELAYED_SACK = SCTP_DELAYED_ACK_TIME

	// SCTP_DEFAULT_SENT_PARAM is the original misspelling of
	// SCTP_DEFAULT_SEND_PARAM. Deprecated: use SCTP_DEFAULT_SEND_PARAM.
	SCTP_DEFAULT_SENT_PARAM = SCTP_DEFAULT_SEND_PARAM

	SCTP_SOCKOPT_BINDX_ADD = 100
	SCTP_SOCKOPT_BINDX_REM = 101
	SCTP_SOCKOPT_PEELOFF   = 102
	// SCTP_SOCKOPT_PEELOFF_FLAGS is SCTP_SOCKOPT_PEELOFF with a flags word
	// appended, so the peeled descriptor can be asked for close-on-exec.
	SCTP_SOCKOPT_PEELOFF_FLAGS = 122
	SCTP_GET_PEER_ADDRS        = 108
	SCTP_GET_LOCAL_ADDRS       = 109
	SCTP_SOCKOPT_CONNECTX      = 110
	SCTP_SOCKOPT_CONNECTX3     = 111

	// SCTP_EVENT is the per-event subscription option RFC 6458 §6.2.2
	// introduced to replace SCTP_EVENTS. Its value is not part of the
	// contiguous block above, so it is spelled out.
	SCTP_EVENT = 127

	// SCTP_RECVRCVINFO makes the kernel return SCTP_RCVINFO as ancillary data
	// on recvmsg (RFC 6458 §8.1.29). It is the non-deprecated counterpart of
	// the SCTP_SNDRCV data SubscribeEvents(SCTP_EVENT_DATA_IO) asks for.
	SCTP_RECVRCVINFO = 32
	// SCTP_RECVNXTINFO makes the kernel return SCTP_NXTINFO, describing the
	// message *after* the one being read (RFC 6458 §8.1.30).
	SCTP_RECVNXTINFO = 33

	// SCTP_FRAGMENT_INTERLEAVE controls whether a partial delivery on one
	// stream blocks messages on the others (RFC 6458 §8.1.20).
	SCTP_FRAGMENT_INTERLEAVE = 18
	// SCTP_PARTIAL_DELIVERY_POINT is the message size at which the partial
	// delivery API is invoked (RFC 6458 §8.1.21).
	SCTP_PARTIAL_DELIVERY_POINT = 19
	// SCTP_MAX_BURST bounds how many packets may be emitted back to back
	// (RFC 6458 §8.1.24). The kernel default is 4.
	SCTP_MAX_BURST = 20
	// SCTP_CONTEXT is the default context reported with messages received from
	// the peer (RFC 6458 §8.1.25).
	SCTP_CONTEXT = 17
	// SCTP_REUSE_PORT allows several one-to-one endpoints to bind the same port
	// (RFC 6458 §8.1.27). Linux rejects it on SCTPEndpoint's one-to-many
	// socket style.
	SCTP_REUSE_PORT = 36

	// SCTP_DEFAULT_SNDINFO carries struct sctp_sndinfo and is the replacement
	// RFC 6458 §8.1.31 gives for SCTP_DEFAULT_SEND_PARAM, which §8.1.13 marks
	// deprecated along with the struct sctp_sndrcvinfo it takes.
	SCTP_DEFAULT_SNDINFO = 34

	// SCTP_AUTO_ASCONF makes the kernel announce local address changes to the
	// peer with ASCONF chunks (RFC 6458 §8.1.23).
	SCTP_AUTO_ASCONF = 30
	// SCTP_GET_ASSOC_NUMBER returns the current association count on a
	// one-to-many socket (RFC 6458 §8.2.5).
	SCTP_GET_ASSOC_NUMBER = 28
	// SCTP_GET_ASSOC_ID_LIST returns its current association identifiers
	// (RFC 6458 §8.2.6).
	SCTP_GET_ASSOC_ID_LIST = 29

	// SCTP_PEER_ADDR_THLDS carries struct sctp_paddrthlds and sets the
	// per-path failure and Potentially Failed thresholds (RFC 7829 §7.2).
	SCTP_PEER_ADDR_THLDS = 31
	// SCTP_PEER_ADDR_THLDS_V2 is the same option with a third threshold added:
	// the consecutive-error threshold which must be exceeded before the primary
	// path is switched (RFC 7829 §5). The option number is Linux's
	// back-compatibility device —
	// the threshold itself is RFC 7829 §7.2's spt_pathcpthld, the third member
	// of struct sctp_paddrthlds. See PeerAddrThldsV2.PathCpThld.
	SCTP_PEER_ADDR_THLDS_V2 = 37

	// SCTP_GET_ASSOC_STATS reads struct sctp_assoc_stats, the per-association
	// counters. Linux-specific; it has no RFC 6458 equivalent.
	SCTP_GET_ASSOC_STATS = 112

	// SCTP_PR_SUPPORTED negotiates PR-SCTP, the partial reliability extension
	// (RFC 7496 §4.5).
	SCTP_PR_SUPPORTED = 113
	// SCTP_DEFAULT_PRINFO carries struct sctp_default_prinfo, the default
	// partial reliability policy and its lifetime (RFC 6458 §8.1.32).
	SCTP_DEFAULT_PRINFO = 114
	// SCTP_PR_STREAM_STATUS reads struct sctp_prstatus, the count of messages
	// abandoned on one stream under the partial reliability policy
	// (RFC 7496 §4.3).
	SCTP_PR_STREAM_STATUS = 116
	// SCTP_PR_ASSOC_STATUS reads the same struct sctp_prstatus totalled across
	// every stream of the association (RFC 7496 §4.4).
	SCTP_PR_ASSOC_STATUS = 115

	// SCTP_RECONFIG_SUPPORTED negotiates the stream reconfiguration extension
	// for this socket. Linux-specific: RFC 6525 defines the extension and the
	// four socket options in its §6.3, but nothing that negotiates support,
	// and the name appears nowhere in it.
	SCTP_RECONFIG_SUPPORTED = 117
	// SCTP_ENABLE_STREAM_RESET selects which reconfiguration requests are
	// permitted (RFC 6525 §6.3).
	SCTP_ENABLE_STREAM_RESET = 118
	// SCTP_ADD_STREAMS asks the peer to widen the association's stream count
	// (RFC 6525 §6.3.4).
	SCTP_ADD_STREAMS = 121
	// SCTP_RESET_STREAMS restarts the sequence numbering of some or all
	// streams (RFC 6525 §6.3.2).
	SCTP_RESET_STREAMS = 119
	// SCTP_RESET_ASSOC restarts the whole association's sequence numbering
	// (RFC 6525 §6.3.3).
	SCTP_RESET_ASSOC = 120

	// SCTP_HMAC_IDENT carries struct sctp_hmacalgo, the ordered list of HMAC
	// algorithms this endpoint offers (RFC 6458 §8.1.17).
	SCTP_HMAC_IDENT = 22
	// SCTP_AUTH_ACTIVE_KEY carries struct sctp_authkeyid and selects the key
	// used for outbound AUTH chunks (RFC 6458 §8.1.18).
	SCTP_AUTH_ACTIVE_KEY = 24
	// SCTP_AUTH_CHUNK adds one chunk type to the CHUNKS list advertised by
	// future associations (RFC 6458 §8.3.2 and RFC 4895 §6.1). Set only.
	SCTP_AUTH_CHUNK = 21
	// SCTP_AUTH_KEY installs a shared key, carrying struct sctp_authkey with
	// the key bytes appended (RFC 6458 §8.3.3). Set only.
	SCTP_AUTH_KEY = 23
	// SCTP_AUTH_DELETE_KEY removes a shared key (RFC 6458 §8.3.5). Set only.
	SCTP_AUTH_DELETE_KEY = 25
	// SCTP_AUTH_DEACTIVATE_KEY stops a shared key being used for new packets
	// while leaving it able to verify what is already in flight
	// (RFC 6458 §8.3.4). Set only.
	SCTP_AUTH_DEACTIVATE_KEY = 35
	// SCTP_PEER_AUTH_CHUNKS reads the chunk types the peer requires to be
	// authenticated (RFC 6458 §8.2.3). Read only.
	SCTP_PEER_AUTH_CHUNKS = 26
	// SCTP_LOCAL_AUTH_CHUNKS reads the chunk types this endpoint requires to
	// be authenticated (RFC 6458 §8.2.4). Read only.
	SCTP_LOCAL_AUTH_CHUNKS = 27

	// SCTP_STREAM_SCHEDULER selects the order outbound streams are served in
	// (RFC 8260 §4).
	SCTP_STREAM_SCHEDULER = 123
	// SCTP_STREAM_SCHEDULER_VALUE sets a per-stream parameter for the
	// scheduler in force, which for SCTP_SS_PRIO is the stream's priority.
	SCTP_STREAM_SCHEDULER_VALUE = 124
	// SCTP_INTERLEAVING_SUPPORTED negotiates user message interleaving, the
	// I-DATA chunk of RFC 8260. The kernel refuses it with EPERM unless
	// net.sctp.intl_enable is on and SetFragmentInterleave has been given a
	// non-zero level.
	SCTP_INTERLEAVING_SUPPORTED = 125
	// SCTP_ASCONF_SUPPORTED negotiates dynamic address reconfiguration
	// (RFC 5061). See SetAsconfSupported: this is what makes SetAutoAsconf do
	// anything at all.
	SCTP_ASCONF_SUPPORTED = 128
	// SCTP_AUTH_SUPPORTED negotiates AUTH (RFC 4895) for this socket, without
	// net.sctp.auth_enable.
	SCTP_AUTH_SUPPORTED = 129
	// SCTP_ECN_SUPPORTED is a Linux-specific experimental capability toggle.
	// RFC 9260 §1.7 removed the former SCTP ECN specification, so this option
	// is not evidence of support for a current standards-track SCTP extension.
	SCTP_ECN_SUPPORTED = 130
	// SCTP_EXPOSE_POTENTIALLY_FAILED_STATE controls whether the PF state of
	// RFC 7829 is visible; see SetExposePotentiallyFailed.
	SCTP_EXPOSE_POTENTIALLY_FAILED_STATE = 131
	// SCTP_EXPOSE_PF_STATE is the kernel's shorter spelling of the same option.
	SCTP_EXPOSE_PF_STATE = SCTP_EXPOSE_POTENTIALLY_FAILED_STATE
	// SCTP_REMOTE_UDP_ENCAPS_PORT sets the peer's UDP encapsulation port
	// (RFC 6951, updated by RFC 8899).
	SCTP_REMOTE_UDP_ENCAPS_PORT = 132
	// SCTP_PLPMTUD_PROBE_INTERVAL is Linux's socket control for the
	// packetization-layer path MTU discovery probe interval. RFC 8899 defines
	// the DPLPMTUD procedure, not this option or its numeric ABI.
	SCTP_PLPMTUD_PROBE_INTERVAL = 133
)

// Layout of the option structs that embed a struct sockaddr_storage without
// being declared packed.
//
// Most of the SCTP option structs carrying an address are
// __attribute__((packed, aligned(4))), so their layout is the same on every
// architecture — PeerAddrParams and PeerAddrinfo are of that kind. Four are
// not: sctp_udpencaps, sctp_probeinterval, sctp_paddrthlds and
// sctp_paddrthlds_v2. There the sockaddr_storage keeps its natural alignment,
// which comes from the unsigned long inside it and so follows the word size:
//
//	                       linux/amd64        linux/386, arm, mips
//	sockaddr_storage       align 8            align 4
//	sctp_udpencaps         144, addr@8        136, addr@4
//	sctp_probeinterval     144, addr@8        136, addr@4
//	sctp_paddrthlds        144, addr@8        136, addr@4
//	sctp_paddrthlds_v2     144, addr@8        140, addr@4
//	(sctp_paddrparams)     156, addr@4        156, addr@4
//
// Measured with a C probe compiled for both word sizes. This matters on every
// 32-bit implementation target, including linux/386, linux/arm and linux/mips.
// sctp_setsockopt_encap_port and sctp_setsockopt_probe_interval both begin by
// rejecting any optlen that is not exactly sizeof, so a hard-coded 144 is
// refused outright on a 32-bit kernel — and the getters only check that the
// length is at least sizeof, so 144 is accepted there, the kernel reads the
// address from the wrong offset and writes back 136 bytes, leaving the trailing
// field holding whatever the caller passed in. That one is silent.
//
// So the offsets are derived rather than written down. Alignment of unsigned
// long equals the pointer size on every Linux ABI Go targets, which makes
// unsafe.Sizeof(uintptr(0)) the right source and keeps this a compile-time
// constant with no build tags to keep in step.
const (
	ssAlign = unsafe.Sizeof(uintptr(0))
	// ssAddrOffset is where the sockaddr_storage starts, after a uint32
	// association id rounded up to that alignment.
	ssAddrOffset = (4 + ssAlign - 1) &^ (ssAlign - 1)
	// ssTailOffset is the first byte after the address.
	ssTailOffset = ssAddrOffset + 128

	// Total sizes, each rounded up to the struct's own alignment.
	udpEncapsSize       = (ssTailOffset + 2 + ssAlign - 1) &^ (ssAlign - 1)
	probeIntervalSize   = (ssTailOffset + 4 + ssAlign - 1) &^ (ssAlign - 1)
	peerAddrThldsSize   = (ssTailOffset + 4 + ssAlign - 1) &^ (ssAlign - 1)
	peerAddrThldsV2Size = (ssTailOffset + 6 + ssAlign - 1) &^ (ssAlign - 1)

	// Linux's x86_64 compat SCTP path accepts the native 32-bit UAPI layout for
	// sctp_udpencaps and sctp_probeinterval, but rejects the peer-threshold
	// options with EINVAL unless they are supplied in the kernel's 64-bit
	// sockaddr_storage layout. Keep the native layout first: it is the correct
	// userspace ABI on real 32-bit kernels. Retry these two options with the
	// kernel layout only after that exact compat-path failure.
	kernelSSAlign             = uintptr(8)
	kernelSSAddrOffset        = (4 + kernelSSAlign - 1) &^ (kernelSSAlign - 1)
	kernelSSTailOffset        = kernelSSAddrOffset + 128
	kernelPeerAddrThldsSize   = (kernelSSTailOffset + 4 + kernelSSAlign - 1) &^ (kernelSSAlign - 1)
	kernelPeerAddrThldsV2Size = (kernelSSTailOffset + 6 + kernelSSAlign - 1) &^ (kernelSSAlign - 1)
)

// UDPEncaps mirrors struct sctp_udpencaps (RFC 6951 §6.1), naming the UDP port
// to encapsulate SCTP in when talking to one peer address.
//
// This is what lets an association traverse a middlebox that drops IP protocol
// 132 outright, which is most consumer NAT. It needs net.sctp.udp_port set for
// the local side to receive; this option is the remote half.
type UDPEncaps struct {
	AssocID SCTPAssocID
	// Address selects the peer address. RFC 6951 §6.1 specifies that a
	// wildcard applies only to future paths. Linux deliberately extends that
	// request in sctp_setsockopt_encap_port by updating every current transport
	// as well as the association default, so a zero value affects current and
	// future paths on this package's socket-backed implementation.
	Address [128]byte
	// Port is the peer's UDP port in host byte order at the Go API boundary.
	// RFC 6951 §6.1 requires sue_port in network byte order; marshal and
	// unmarshal perform that conversion. Zero disables encapsulation.
	Port uint16
}

func (e *UDPEncaps) marshal() []byte {
	b := make([]byte, udpEncapsSize)
	nativeEndian.PutUint32(b[0:], uint32(e.AssocID))
	copy(b[ssAddrOffset:ssAddrOffset+128], e.Address[:])
	binary.BigEndian.PutUint16(b[ssTailOffset:], e.Port)
	return b
}

func (e *UDPEncaps) unmarshal(b []byte) {
	e.AssocID = SCTPAssocID(nativeEndian.Uint32(b[0:]))
	copy(e.Address[:], b[ssAddrOffset:ssAddrOffset+128])
	e.Port = binary.BigEndian.Uint16(b[ssTailOffset:])
}

// SetRemoteUDPEncapsPort sets the UDP port SCTP is encapsulated in for a peer
// address (SCTP_REMOTE_UDP_ENCAPS_PORT).
func (c *SCTPConn) SetRemoteUDPEncapsPort(e *UDPEncaps) error {
	if e == nil {
		return syscall.EINVAL
	}
	b := e.marshal()
	_, _, err := c.setsockopt(SCTP_REMOTE_UDP_ENCAPS_PORT,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	return err
}

// GetRemoteUDPEncapsPort reads the peer's UDP encapsulation port. Set Address
// on the value passed in to name a path.
func (c *SCTPConn) GetRemoteUDPEncapsPort(e *UDPEncaps) error {
	if e == nil {
		return syscall.EINVAL
	}
	b := e.marshal()
	optlen := uint32(len(b))
	_, _, err := c.getsockopt(SCTP_REMOTE_UDP_ENCAPS_PORT,
		uintptr(unsafe.Pointer(&b[0])), &optlen)
	if err != nil {
		return err
	}
	e.unmarshal(b)
	return nil
}

// ProbeInterval mirrors Linux's struct sctp_probeinterval, the kernel UAPI for
// controlling the packetization-layer path MTU discovery probe period. RFC 8899
// defines the DPLPMTUD protocol procedure, but it does not define this struct or
// socket option.
//
// PLPMTUD is how a path finds its MTU without relying on ICMP, which is widely
// filtered. Zero disables it, which is the default.
type ProbeInterval struct {
	AssocID SCTPAssocID
	// Address selects the path; a zeroed address applies to the association.
	Address [128]byte
	// Interval is the probe period in milliseconds. Zero turns PLPMTUD off.
	Interval uint32
}

func (p *ProbeInterval) marshal() []byte {
	b := make([]byte, probeIntervalSize)
	nativeEndian.PutUint32(b[0:], uint32(p.AssocID))
	copy(b[ssAddrOffset:ssAddrOffset+128], p.Address[:])
	nativeEndian.PutUint32(b[ssTailOffset:], p.Interval)
	return b
}

func (p *ProbeInterval) unmarshal(b []byte) {
	p.AssocID = SCTPAssocID(nativeEndian.Uint32(b[0:]))
	copy(p.Address[:], b[ssAddrOffset:ssAddrOffset+128])
	p.Interval = nativeEndian.Uint32(b[ssTailOffset:])
}

// SetProbeInterval sets the PLPMTUD probe interval
// (SCTP_PLPMTUD_PROBE_INTERVAL).
func (c *SCTPConn) SetProbeInterval(p *ProbeInterval) error {
	if p == nil {
		return syscall.EINVAL
	}
	b := p.marshal()
	_, _, err := c.setsockopt(SCTP_PLPMTUD_PROBE_INTERVAL,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	return err
}

// GetProbeInterval reads the PLPMTUD probe interval.
func (c *SCTPConn) GetProbeInterval(p *ProbeInterval) error {
	if p == nil {
		return syscall.EINVAL
	}
	b := p.marshal()
	optlen := uint32(len(b))
	_, _, err := c.getsockopt(SCTP_PLPMTUD_PROBE_INTERVAL,
		uintptr(unsafe.Pointer(&b[0])), &optlen)
	if err != nil {
		return err
	}
	p.unmarshal(b)
	return nil
}

// Stream schedulers for SetStreamScheduler, from the kernel's
// enum sctp_sched_type. RFC 8260 §3 defines six schedulers; Linux implements
// five of them, all of the ones below.
//
// Measured on 6.12: 0 to 4 are accepted and read back unchanged, 5 and above are
// refused with EINVAL. RFC 8260 §3.3's round-robin-per-packet (SCTP_SS_RR_PKT)
// is the one with no Linux implementation and so no constant here.
//
// SetStreamScheduler does not police the value, so a caller may pass a number
// the running kernel does not know; it will fail at the setsockopt with EINVAL
// rather than silently doing something else.
const (
	// SCTPSchedFCFS sends messages in the order they were handed over,
	// regardless of stream (RFC 8260 §3.1). It is the default.
	SCTPSchedFCFS = 0
	// SCTPSchedPrio serves streams by the priority set with
	// SetStreamSchedulerValue, lowest number first (RFC 8260 §3.4).
	SCTPSchedPrio = 1
	// SCTPSchedRR serves streams round-robin, one message at a time
	// (RFC 8260 §3.2).
	SCTPSchedRR = 2
	// SCTPSchedFC distributes capacity fairly between streams, accounting for
	// message length rather than message count (RFC 8260 §3.5). It takes no
	// per-stream value.
	SCTPSchedFC = 3
	// SCTPSchedWFQ is weighted fair queueing: capacity is shared in proportion
	// to the per-stream weight set with SetStreamSchedulerValue, so a stream
	// weighted n times another gets n times the capacity (RFC 8260 §3.6).
	SCTPSchedWFQ = 4
)

// PF state exposure levels for SetExposePotentiallyFailed (RFC 7829), from the
// kernel's SCTP_PF_EXPOSE_* enum in include/net/sctp/constants.h.
//
// The values are not a boolean with an extra mode: zero means "no answer
// given", and the two explicit answers are 1 for off and 2 for on. Reading them
// as off/on/locked, which is the shape most of these options have, puts
// "exposed" on the value that disables it — a round-trip test still passes,
// because the number written is the number read back.
const (
	// SCTPPFStateUnset leaves the decision to net.sctp.pf_expose, whose own
	// default is this same value — measured, and the sysctl's floor is 0. This
	// is the state of a socket nobody has asked.
	//
	// It is not the same as SCTPPFStateDisabled: at this level GetPeerAddrInfo
	// does report SCTP_PF for a potentially-failed path. Only the notification
	// is withheld.
	SCTPPFStateUnset = 0
	// SCTPPFStateDisabled suppresses the PF state, and does so by refusing the
	// question rather than by answering it differently: GetPeerAddrInfo on a
	// path that is in the PF state returns EACCES. The SCTP_UNKNOWN to
	// SCTP_ACTIVE fixup in the kernel happens after that check and rewrites only
	// SCTP_UNKNOWN, so a PF path is never reported as active.
	//
	// That makes this the level least likely to do what a caller wants: polling
	// path health under it starts failing at exactly the moment a path degrades,
	// and GetPeerAddrInfo is the only way to see a secondary path at all.
	// GetStatus is not gated, so the primary path's state stays readable.
	SCTPPFStateDisabled = 1
	// SCTPPFStateEnabled reports the PF state through both
	// SCTP_PEER_ADDR_CHANGE and GetPeerAddrInfo. This is what a caller wants
	// if they are asking at all.
	SCTPPFStateEnabled = 2
)

// Flags for PeerAddrParams.Flags, from Linux's spp_flags. RFC 6458 §8.1.12
// defines the heartbeat (including SPP_HB_TIME_IS_ZERO), PMTUD, IPv6
// flow-label, and DSCP controls. Linux adds only the SACK-delay controls; those
// two bits and the PeerAddrParams.SackDelay field are kernel extensions.
//
// The ENABLE/DISABLE pairs are how the option distinguishes "set this" from
// "leave it alone": with neither bit set the corresponding value field is
// ignored, which is why SetPeerAddrParams cannot be used to clear a setting by
// passing zero.
const (
	SPP_HB_ENABLE         = 1 << 0
	SPP_HB_DISABLE        = 1 << 1
	SPP_HB_DEMAND         = 1 << 2 // send one heartbeat now
	SPP_PMTUD_ENABLE      = 1 << 3
	SPP_PMTUD_DISABLE     = 1 << 4
	SPP_SACKDELAY_ENABLE  = 1 << 5
	SPP_SACKDELAY_DISABLE = 1 << 6
	SPP_HB_TIME_IS_ZERO   = 1 << 7 // heartbeat immediately after each RTO
	SPP_IPV6_FLOWLABEL    = 1 << 8
	SPP_DSCP              = 1 << 9
)

// Partial reliability policies for SetDefaultPrInfo (RFC 7496 §4.2). The value
// accompanying each policy is interpreted differently, which is why they are not
// interchangeable:
//
//   - SCTPPrPolicyNone ignores the value; the message is sent reliably.
//   - SCTPPrPolicyTTL treats it as a lifetime in milliseconds.
//   - SCTPPrPolicyRtx treats it as a retransmission count.
//   - SCTPPrPolicyPrio treats it as a priority, where a larger number is
//     discarded sooner when the send buffer is under pressure.
//
// Unlike the fragment interleave levels, the kernel does police these: a policy
// outside this set is rejected with EINVAL, which was measured.
const (
	SCTPPrPolicyNone = 0x0000
	SCTPPrPolicyTTL  = 0x0010
	SCTPPrPolicyRtx  = 0x0020
	SCTPPrPolicyPrio = 0x0030
)

// Stream reconfiguration request types for SetEnableStreamReset
// (RFC 6525 §6.3). These are a bitmask; a socket may permit any combination.
const (
	// SCTPEnableResetStreamReq permits resetting the sequence numbers of
	// individual streams.
	SCTPEnableResetStreamReq = 0x01
	// SCTPEnableResetAssocReq permits resetting the whole association's
	// sequence numbers.
	SCTPEnableResetAssocReq = 0x02
	// SCTPEnableChangeAssocReq permits adding streams to a live association.
	SCTPEnableChangeAssocReq = 0x04
)

// HMAC algorithm identifiers for SetHmacIdent (RFC 4895 §3.3 Table 2 and the IANA
// registry it establishes). SHA-1 is mandatory to implement; SHA-256 is
// optional. Note that 2 is not assigned — the registry skips it — so these are
// not contiguous.
const (
	SCTPAuthHmacIDSHA1   = 1
	SCTPAuthHmacIDSHA256 = 3
)

// Fragmented interleave levels for SetFragmentInterleave (RFC 6458 §8.1.20).
//
// Linux does not store a level. It keeps a single flag, so anything non-zero
// becomes 1: setting 2 and setting 3 both read back as 1, which was measured.
// That means an out-of-range value is not rejected and not honoured either, and
// nothing tells the caller. SetFragmentInterleave rejects anything outside this
// set so the mistake fails at the call.
const (
	// SCTPFragmentInterleaveNone blocks every other message while a partial
	// delivery is in progress. This is the kernel default.
	SCTPFragmentInterleaveNone = 0
	// SCTPFragmentInterleaveOther allows messages from other associations to be
	// delivered during a partial delivery, but not from other streams of this
	// one.
	SCTPFragmentInterleaveOther = 1
	// SCTPFragmentInterleaveStreams additionally allows messages from other
	// streams of the same association.
	//
	// Current Linux keeps fragment interleave as a flag rather than a level, so
	// it stores this request as SCTPFragmentInterleaveOther. SetFragmentInterleave
	// detects that mismatch and returns an error wrapping errors.ErrUnsupported;
	// true RFC 6458 level 2 is unavailable on those kernels. RFC 8260 I-DATA
	// negotiation is a separate capability and does not turn readback level 1
	// into level 2.
	SCTPFragmentInterleaveStreams = 2
)

const (
	SCTP_EVENT_DATA_IO = 1 << iota
	SCTP_EVENT_ASSOCIATION
	SCTP_EVENT_ADDRESS
	SCTP_EVENT_SEND_FAILURE
	SCTP_EVENT_PEER_ERROR
	SCTP_EVENT_SHUTDOWN
	SCTP_EVENT_PARTIAL_DELIVERY
	SCTP_EVENT_ADAPTATION_LAYER
	SCTP_EVENT_AUTHENTICATION
	SCTP_EVENT_SENDER_DRY

	SCTP_EVENT_ALL = SCTP_EVENT_DATA_IO | SCTP_EVENT_ASSOCIATION | SCTP_EVENT_ADDRESS | SCTP_EVENT_SEND_FAILURE | SCTP_EVENT_PEER_ERROR | SCTP_EVENT_SHUTDOWN | SCTP_EVENT_PARTIAL_DELIVERY | SCTP_EVENT_ADAPTATION_LAYER | SCTP_EVENT_AUTHENTICATION | SCTP_EVENT_SENDER_DRY
)

type (
	SCTPNotificationType int
	SCTPAssocID          int32
)

const (
	SCTP_SN_TYPE_BASE = SCTPNotificationType(iota + (1 << 15))
	SCTP_ASSOC_CHANGE
	SCTP_PEER_ADDR_CHANGE
	SCTP_SEND_FAILED
	SCTP_REMOTE_ERROR
	SCTP_SHUTDOWN_EVENT
	SCTP_PARTIAL_DELIVERY_EVENT
	SCTP_ADAPTATION_INDICATION
	SCTP_AUTHENTICATION_INDICATION
	SCTP_SENDER_DRY_EVENT
	SCTP_STREAM_RESET_EVENT
	SCTP_ASSOC_RESET_EVENT
	SCTP_STREAM_CHANGE_EVENT
	SCTP_SEND_FAILED_EVENT
)

// SCTP_DATA_IO_EVENT is the modern SCTP_EVENT type that enables per-message
// receive metadata. Linux calls the same numeric value SCTP_SN_TYPE_BASE in its
// enum; the alias gives callers the RFC 6458 §§6.2.2 and 8.1.20 spelling.
const SCTP_DATA_IO_EVENT = SCTP_SN_TYPE_BASE

// SCTP_AUTHENTICATION_EVENT is the spelling RFC 6458 §6.1.8 and the kernel's
// enum sctp_sn_type use. SCTP_AUTHENTICATION_INDICATION is the name Linux gives
// the same value through its compatibility #define, and is what this package
// has always called it.
const SCTP_AUTHENTICATION_EVENT = SCTP_AUTHENTICATION_INDICATION

// NotificationHandler receives one complete SCTP notification consumed by a
// connection. Notification records are reassembled before the callback even
// when the application read buffer is smaller than the event.
// NotificationReassemblyLimit bounds automatic reassembly; an oversized event
// is drained and reported as ErrNotificationTooLong. Raw receive APIs remain
// available to applications that need a different bounded policy.
// If the poller itself fails after consuming a notification prefix but before
// MSG_EOR, the connection is aborted: leaving it open would let a later read
// misidentify the unread tail as a new event.
//
// The handler may be invoked concurrently when the same handler is installed
// on several accepted connections or when several goroutines read one
// connection. It may call methods on that connection, including another read;
// callbacks never run while the package holds the descriptor's runtime-poller
// read lock. The byte slice is valid only until the callback returns. A handler
// that retains a notification must copy it.
type NotificationHandler func([]byte) error

// EventSubscribe mirrors struct sctp_event_subscribe, the bulk subscription
// used by SCTP_EVENTS.
//
// The fields are the ten RFC 6458 §6.2.1 events. Linux appends four of its own
// (stream reset, association reset, stream change, and a second send-failure
// event), so the kernel's struct is 14 bytes against this one's 10. That is
// safe in both directions and was measured rather than assumed: setsockopt
// with a 10 byte option length is accepted and applied, and getsockopt with
// one writes only the first 10 bytes and leaves the rest of the caller's
// buffer untouched. The cost is that those four Linux-only events cannot be
// reached through this struct.
//
// RFC 6458 §6.2.2 deprecates SCTP_EVENTS for precisely this reason — the
// struct has to grow as events are added — and replaces it with SCTP_EVENT,
// which names one event per call. See SubscribeEvent.
type EventSubscribe struct {
	DataIO          uint8
	Association     uint8
	Address         uint8
	SendFailure     uint8
	PeerError       uint8
	Shutdown        uint8
	PartialDelivery uint8
	AdaptationLayer uint8
	Authentication  uint8
	SenderDry       uint8
}

// RcvInfo mirrors struct sctp_rcvinfo (RFC 6458 §5.3.5), the per-message
// receive information the kernel attaches as SCTP_RCVINFO ancillary data once
// SetRecvRcvInfo is enabled.
//
// It is the non-deprecated half of what SndRcvInfo carries: RFC 6458 §5.3.2
// titles SCTP_SNDRCV "DEPRECATED" and splits it into SCTP_SNDINFO for sending
// and this for receiving. The field order is not the same as SndRcvInfo's —
// TSN and CumTSN come before Context here and after it there — so the two are
// not interchangeable as raw memory.
//
// TestStructLayoutsMatchKernel pins the layout. Callers normally do not need
// this type: SCTPRead converts whichever form the kernel sent into SndRcvInfo.
type RcvInfo struct {
	// SID is the stream the message arrived on.
	SID uint16
	// SSN is the stream sequence number.
	SSN uint16
	// Flags carries SCTP_UNORDERED and friends.
	Flags uint16
	_     uint16
	// PPID is the payload protocol identifier in host byte order when returned
	// by SCTPEndpoint.Receive. RFC 6458 §5.3.5 labels the ancillary field network
	// byte order and says the SCTP stack leaves it untouched; the receive path
	// converts it at the kernel boundary, matching SndInfo and SndRcvInfo.
	PPID uint32
	// TSN is the transmission sequence number.
	TSN uint32
	// CumTSN is the cumulative TSN acknowledged.
	CumTSN uint32
	// Context is the value set with SetContext.
	Context uint32
	// AssocID identifies the association; ignored on one-to-one sockets.
	AssocID SCTPAssocID
}

// Event mirrors struct sctp_event (RFC 6458 §6.2.2), which subscribes to or
// unsubscribes from one notification type at a time.
//
// Both this struct and the kernel's are 8 bytes: three fields totalling 7,
// rounded up for the alignment of the leading 4 byte association id. The
// trailing field below is that padding written out. Go would insert it either
// way — removing it does not change the size, which was checked — so it is here
// to make the layout the kernel expects visible at the declaration rather than
// implied by alignment rules. TestEventStructMatchesKernel asserts the size and
// every offset.
type Event struct {
	// AssocID is ignored on the one-to-one style sockets this package creates.
	AssocID SCTPAssocID
	// Type is a notification type, e.g. SCTP_ASSOC_CHANGE.
	Type uint16
	// On is 1 to subscribe and 0 to unsubscribe.
	On uint8
	_  uint8
}

// Ancillary data types, enum sctp_cmsg_type. The values are positional in the C
// enum, so the order here is the contract — SCTP_CMSG_PRINFO must stay 5.
const (
	SCTP_CMSG_INIT = iota
	SCTP_CMSG_SNDRCV
	SCTP_CMSG_SNDINFO
	SCTP_CMSG_RCVINFO
	SCTP_CMSG_NXTINFO
	// SCTP_CMSG_PRINFO carries struct sctp_prinfo on a send, setting the
	// partial reliability policy for that one message (RFC 6458 §5.3.7).
	SCTP_CMSG_PRINFO
	// SCTP_CMSG_AUTHINFO carries struct sctp_authinfo, naming the shared key
	// to authenticate that one message with (RFC 6458 §5.3.8).
	SCTP_CMSG_AUTHINFO
	// SCTP_CMSG_DSTADDRV4 and SCTP_CMSG_DSTADDRV6 add a destination address to
	// a send on an unconnected one-to-many socket (RFC 6458 §5.3.9, §5.3.10).
	// SCTPEndpoint routes sends by an established association id and therefore
	// does not emit either destination-address item; they remain defined for
	// controlled raw-descriptor users.
	SCTP_CMSG_DSTADDRV4
	SCTP_CMSG_DSTADDRV6
)

// Direction flags for ResetStreams (RFC 6525 §6.3.2). At least one is required:
// a request with neither is rejected with EINVAL, which was measured.
const (
	// SCTPStreamResetIncoming resets the streams the peer sends on.
	SCTPStreamResetIncoming = 0x01
	// SCTPStreamResetOutgoing resets the streams this endpoint sends on.
	SCTPStreamResetOutgoing = 0x02
)

// Per-message send flags, for SndRcvInfo.Flags and SndInfo.Flags. These are the
// kernel's enum sctp_sinfo_flags (RFC 6458 §5.3.2).
//
// The sequence is not contiguous, which is what makes it worth writing out
// rather than generating with iota. Bits 4 and 5 belong to SCTP_PR_SCTP_MASK —
// the partial reliability policy travels in the same word — and SCTP_EOF is not
// an SCTP-specific bit at all but MSG_FIN, which is 0x200.
//
// SCTP_EOF used to be the fifth iota here, so 1<<4, which is exactly
// SCTP_PR_SCTP_TTL. A caller asking for a graceful shutdown on their last
// message instead selected a partial reliability policy, and got neither the
// shutdown nor an error.
const (
	// SCTP_UNORDERED sends the message without sequencing.
	SCTP_UNORDERED = 1 << 0
	// SCTP_ADDR_OVER overrides the primary destination, using the address in
	// SndRcvInfo. It applies to one-to-many sockets.
	SCTP_ADDR_OVER = 1 << 1
	// SCTP_ABORT tears the association down with an ABORT instead of sending.
	SCTP_ABORT = 1 << 2
	// SCTP_SACK_IMMEDIATELY asks the peer to acknowledge without waiting for
	// its delayed-ack timer.
	SCTP_SACK_IMMEDIATELY = 1 << 3

	// Bits 4 and 5 are SCTP_PR_SCTP_MASK, carrying the partial reliability
	// policy. Use the SCTPPrPolicy constants with SCTPWriteInfo rather than
	// setting them here.

	// SCTP_SENDALL sends the message on every association of a one-to-many
	// socket.
	SCTP_SENDALL = 1 << 6
	// SCTP_PR_SCTP_ALL is not a send flag, despite living in this word. It has
	// no effect on any send path — the kernel's only two uses of it are in
	// sctp_getsockopt_pr_streamstatus and sctp_getsockopt_pr_assocstatus, where
	// it asks for the counters aggregated over every PR policy rather than one
	// (RFC 7496 §4.3 and §4.4). Setting it in SndInfo.Flags or SndRcvInfo.Flags does
	// nothing. It is declared here because it occupies a bit in the same field;
	// pass it to GetPrStreamStatus or GetPrAssocStatus, not to a send.
	SCTP_PR_SCTP_ALL = 1 << 7

	// SCTP_NOTIFICATION is the last member of the kernel's enum, and like
	// SCTP_PR_SCTP_ALL it is not a send flag. It is MSG_NOTIFICATION, and the
	// enum lists it because the field is wide enough to hold it, not because
	// anything sets it there.
	//
	// Nothing does, on either path. Measured: with sctp_data_io_event on, a
	// data message arrives carrying an SCTP_SNDRCV cmsg whose sinfo_flags is 0,
	// and a notification arrives with no SCTP_SNDRCV cmsg at all — only
	// MSG_NOTIFICATION in the recvmsg flags. So a caller cannot learn from
	// SndRcvInfo.Flags that a message is a notification; test the flags word
	// SCTPReadFlags returns instead.
	SCTP_NOTIFICATION = 0x8000

	// SCTP_EOF starts a graceful shutdown once the message is delivered. It is
	// MSG_FIN, not a bit of its own.
	SCTP_EOF = 0x200
)

// SCTP_EOR is deliberately absent. RFC 6458 erratum 6111 adds it to the
// sinfo_flags of §5.3.2 and §5.3.4 as the flag that terminates a record built
// from several sends, and §8.1.26 defines the SCTP_EXPLICIT_EOR option that
// turns that mode on. Linux implements neither: there is no SCTP_EXPLICIT_EOR
// socket option in the uapi header, and no SCTP_EOR in enum sctp_sinfo_flags.
//
// MSG_MORE is not a substitute, which was measured rather than assumed: a
// sendmsg with MSG_MORE followed by a plain one produced two records, and the
// first was delivered with MSG_EOR already set. Every send through this package
// is therefore a complete record, and MSG_EOR is meaningful on the receive side
// only — see SCTPReadFlags.

const (
	SCTP_MAX_STREAM = 0xffff
)

type InitMsg struct {
	NumOstreams    uint16
	MaxInstreams   uint16
	MaxAttempts    uint16
	MaxInitTimeout uint16
}

// SackTimer mirrors struct sctp_sack_info (RFC 6458 §8.1.19), the delayed
// acknowledgement timer and the number of packets that force an acknowledgement
// without waiting for it.
//
// A zero field means "leave this one alone", not "set it to zero". RFC 6458
// §8.1.19 says so and Linux agrees, which makes this struct unlike most of the
// package: the two fields cannot be set independently to a known state, because
// there is no way to spell "no delay". Measured on 6.12, from a default of
// 200/2:
//
//	set 137/5 -> 137/5    both taken
//	set   0/9 -> 137/9    SackDelay ignored, previous value kept
//	set 211/0 -> 211/9    SackFrequency ignored, previous value kept
//	set   0/0 -> 211/9    accepted, and a complete no-op
//
// SackFrequency == 1 disables the delayed acknowledgement algorithm. That case
// does not follow the rule above: setting 0/1 leaves SackDelay reading back as
// 0 rather than unchanged, because disabling the algorithm clears the timer.
//
// SackDelay is policed. RFC 9260 §6.2 wants at most 500 ms; the kernel rejects
// a value it considers out of range with EINVAL — 100000 was refused — so an
// absurd delay fails at the call rather than being silently clamped.
type SackTimer struct {
	// AssocID is ignored on the one-to-one style sockets this package creates.
	AssocID SCTPAssocID
	// SackDelay is the delayed acknowledgement timer in milliseconds. Zero
	// leaves the current value in place.
	SackDelay uint32
	// SackFrequency is the number of packets that must arrive before an
	// acknowledgement is sent without waiting for SackDelay. Zero leaves the
	// current value in place; 1 disables delayed acknowledgement entirely.
	SackFrequency uint32
}

// Special association identifiers for the AssocID field of the option structs
// in this package (RFC 6458 §7.2).
//
// They exist for one-to-many sockets, where one descriptor carries many
// associations and an option has to say which ones it means. SCTPEndpoint uses
// that socket style and its typed per-association methods reject scope
// selectors where the RFC requires one real id. On the one-to-one sockets from
// Dial and Accept, the kernel ignores the field altogether — measured: reading
// SCTP_MAX_BURST with each of the three returns the same value and no error.
// RFC 6458 §7.2 says getsockopt and sctp_opt_info calls using CURRENT or ALL
// must fail with EINVAL; that requirement applies to the one-to-many scoping
// facility, not to Linux's one-to-one behavior.
//
// They are declared because zero is not self-describing. An option struct left
// zeroed is already asking for SCTP_FUTURE_ASSOC, and a reader of this package
// should not have to know that 0 is a name. RFC 6458 Held Erratum 6114 concerns
// the symbolic spelling in the separate sctp_getladdrs example in §9.5; it is
// not a normative change to these §7.2 selectors.
const (
	// SCTP_FUTURE_ASSOC affects only associations created after the call.
	SCTP_FUTURE_ASSOC = 0
	// SCTP_CURRENT_ASSOC affects only associations that already exist; future
	// ones keep the previous default.
	SCTP_CURRENT_ASSOC = 1
	// SCTP_ALL_ASSOC affects both.
	SCTP_ALL_ASSOC = 2
)

// AssocValue mirrors struct sctp_assoc_value, the association-id-and-value
// pair several socket options take.
//
// AssocID is ignored on the one-to-one style sockets this package creates.
type AssocValue struct {
	AssocID  SCTPAssocID
	AssocVal uint32
}

// DefaultPrInfo represents struct sctp_default_prinfo, the default partial
// reliability policy for messages that do not carry their own.
//
// Its field order follows the Linux UAPI: association id, value, then policy.
// RFC 6458 §8.1.32 specifies policy, value, then association id instead. The
// socket-backed methods must use the Linux order; this is an explicit ABI
// divergence rather than a byte-for-byte mirror of the RFC structure.
type DefaultPrInfo struct {
	AssocID SCTPAssocID
	// Value is a lifetime, a retransmission count or a priority depending on
	// Policy. See the SCTPPrPolicy constants.
	Value uint32
	// Policy is one of the SCTPPrPolicy constants.
	Policy uint16
	// Go's alignment rules already round the struct to 12 bytes, so this pad
	// is documentation of the C layout rather than the thing producing the
	// size. Removing it changes nothing, which was verified.
	_ uint16
}

// PrStatus mirrors struct sctp_prstatus used by RFC 7496 §4.3 for one-stream
// counters and §4.4 for association-wide counters.
type PrStatus struct {
	AssocID SCTPAssocID
	// SID selects the stream to report on. Set it before the call.
	SID uint16
	// Policy selects which policy's counters to report. Set it before the
	// call.
	Policy uint16
	// AbandonedUnsent counts messages discarded before any part was sent.
	AbandonedUnsent uint64
	// AbandonedSent counts messages discarded after at least one fragment had
	// gone out.
	AbandonedSent uint64
}

// PeerAddrThlds mirrors Linux's legacy two-field struct sctp_paddrthlds. It
// carries the per-path failure and Potentially Failed thresholds, but omits the
// primary-path switchover threshold that RFC 7829 §7.2 includes in its
// three-field struct sctp_paddrthlds. Use PeerAddrThldsV2 for the complete RFC
// field set on Linux.
type PeerAddrThlds struct {
	AssocID SCTPAssocID
	// Address selects the path. A zeroed address applies to the association as
	// a whole, which is the useful form on the single-homed sockets this
	// package usually creates.
	Address [128]byte
	// PathMaxRxt is the threshold after which a path is declared inactive: RFC
	// 7829 §7.2 acts when the path error counter exceeds this value.
	PathMaxRxt uint16
	// PathPfThld is the threshold after which a path enters the Potentially
	// Failed state. RFC 7829 §7.2 acts when the path error counter exceeds this
	// value. A value greater than or equal to PathMaxRxt is permitted, but the
	// path then becomes inactive before it can enter PF.
	PathPfThld uint16
}

func (t *PeerAddrThlds) marshal() []byte {
	return t.marshalLayout(ssAddrOffset, ssTailOffset, peerAddrThldsSize)
}

func (t *PeerAddrThlds) marshalKernelLayout() []byte {
	return t.marshalLayout(kernelSSAddrOffset, kernelSSTailOffset,
		kernelPeerAddrThldsSize)
}

func (t *PeerAddrThlds) marshalLayout(addrOffset, tailOffset, size uintptr) []byte {
	b := make([]byte, size)
	nativeEndian.PutUint32(b[0:], uint32(t.AssocID))
	copy(b[addrOffset:addrOffset+128], t.Address[:])
	nativeEndian.PutUint16(b[tailOffset:], t.PathMaxRxt)
	nativeEndian.PutUint16(b[tailOffset+2:], t.PathPfThld)
	return b
}

func (t *PeerAddrThlds) unmarshal(b []byte) {
	t.unmarshalLayout(b, ssAddrOffset, ssTailOffset)
}

func (t *PeerAddrThlds) unmarshalKernelLayout(b []byte) {
	t.unmarshalLayout(b, kernelSSAddrOffset, kernelSSTailOffset)
}

func (t *PeerAddrThlds) unmarshalLayout(b []byte, addrOffset, tailOffset uintptr) {
	t.AssocID = SCTPAssocID(nativeEndian.Uint32(b[0:]))
	copy(t.Address[:], b[addrOffset:addrOffset+128])
	t.PathMaxRxt = nativeEndian.Uint16(b[tailOffset:])
	t.PathPfThld = nativeEndian.Uint16(b[tailOffset+2:])
}

// PeerAddrThldsV2 mirrors Linux's struct sctp_paddrthlds_v2. Linux introduced
// the V2 option number for ABI compatibility, but its three fields are the
// complete struct sctp_paddrthlds specified by RFC 7829 §7.2; the older Linux
// option exposes only the first two.
type PeerAddrThldsV2 struct {
	AssocID SCTPAssocID
	// Address selects the path; a zeroed address applies to the association.
	Address [128]byte
	// PathMaxRxt is exceeded before the path is declared inactive (RFC 7829
	// §7.2).
	PathMaxRxt uint16
	// PathPfThld is exceeded before the path enters the Potentially Failed
	// state (RFC 7829 §7.2).
	PathPfThld uint16
	// PathCpThld is the consecutive-error threshold on the primary path. Once
	// the error counter exceeds it, the stack makes the current active path
	// primary instead — RFC 7829 §§5 and 7.2 Primary Path Switchover. The kernel
	// calls it ps_retrans and exposes its default as net.sctp.ps_retrans.
	//
	// It is not a probing control. The kernel reads this value in exactly one
	// place, where it calls sctp_assoc_set_primary; nothing consults it when
	// deciding whether to keep heartbeating a path. The default of 0xffff
	// therefore means switchover is disabled, not that probing is unbounded —
	// the kernel's own comment on the default reads "Disable of Primary Path
	// Switchover by default".
	//
	// Both RFC 7829 §5 and Linux test error_count > ps_retrans, so a value of 3
	// permits three consecutive errors and switches when the counter becomes 4.
	PathCpThld uint16
}

func (t *PeerAddrThldsV2) marshal() []byte {
	return t.marshalLayout(ssAddrOffset, ssTailOffset, peerAddrThldsV2Size)
}

func (t *PeerAddrThldsV2) marshalKernelLayout() []byte {
	return t.marshalLayout(kernelSSAddrOffset, kernelSSTailOffset,
		kernelPeerAddrThldsV2Size)
}

func (t *PeerAddrThldsV2) marshalLayout(addrOffset, tailOffset, size uintptr) []byte {
	b := make([]byte, size)
	nativeEndian.PutUint32(b[0:], uint32(t.AssocID))
	copy(b[addrOffset:addrOffset+128], t.Address[:])
	nativeEndian.PutUint16(b[tailOffset:], t.PathMaxRxt)
	nativeEndian.PutUint16(b[tailOffset+2:], t.PathPfThld)
	nativeEndian.PutUint16(b[tailOffset+4:], t.PathCpThld)
	return b
}

func (t *PeerAddrThldsV2) unmarshal(b []byte) {
	t.unmarshalLayout(b, ssAddrOffset, ssTailOffset)
}

func (t *PeerAddrThldsV2) unmarshalKernelLayout(b []byte) {
	t.unmarshalLayout(b, kernelSSAddrOffset, kernelSSTailOffset)
}

func (t *PeerAddrThldsV2) unmarshalLayout(b []byte, addrOffset, tailOffset uintptr) {
	t.AssocID = SCTPAssocID(nativeEndian.Uint32(b[0:]))
	copy(t.Address[:], b[addrOffset:addrOffset+128])
	t.PathMaxRxt = nativeEndian.Uint16(b[tailOffset:])
	t.PathPfThld = nativeEndian.Uint16(b[tailOffset+2:])
	t.PathCpThld = nativeEndian.Uint16(b[tailOffset+4:])
}

// AssocStats mirrors struct sctp_assoc_stats, the per-association counters
// Linux exposes through SCTP_GET_ASSOC_STATS. This has no RFC 6458 counterpart —
// the field set is the kernel's own.
type AssocStats struct {
	AssocID SCTPAssocID
	// ObsRtoIPAddr is the path on which MaxRto was observed.
	//
	// This one is worth reading carefully. struct sctp_assoc_stats is 256 bytes
	// on every architecture and its counters begin at 136 on every
	// architecture, but the sockaddr_storage in front of them does not: it sits
	// at offset 8 on a 64-bit kernel and at offset 4 on a 32-bit one, with the
	// slack absorbed by padding before the counters. So the size check every
	// getsockopt performs cannot see the difference, and neither can a test
	// that only looks at the numbers — which is why this is unmarshalled from
	// an offset rather than being read straight off a mirrored struct.
	ObsRtoIPAddr [128]byte
	// MaxRto is the largest retransmission timeout observed since the last
	// read. Reading resets it.
	MaxRto uint64
	// ISacks and OSacks count SACK chunks received and sent.
	ISacks, OSacks uint64
	// OPackets and IPackets count packets sent and received.
	OPackets, IPackets uint64
	// RtxChunks counts retransmitted data chunks.
	RtxChunks uint64
	// OutOfSeqTsns counts chunks arriving beyond the next expected TSN.
	OutOfSeqTsns uint64
	// IDupChunks counts duplicate chunks received.
	IDupChunks uint64
	// GapCnt counts gap acknowledgement blocks received.
	GapCnt uint64
	// OUodChunks and IUodChunks count unordered data chunks sent and received.
	OUodChunks, IUodChunks uint64
	// OOdChunks and IOdChunks count ordered data chunks sent and received.
	OOdChunks, IOdChunks uint64
	// OCtrlChunks and ICtrlChunks count control chunks sent and received.
	OCtrlChunks, ICtrlChunks uint64
}

// AddStreamsReq mirrors struct sctp_add_streams (RFC 6525 §6.3.4), the request to
// widen an association's stream count. The AddStreams method wraps it; this type
// is exported so the layout can be pinned by the layout test.
type AddStreamsReq struct {
	AssocID SCTPAssocID
	// InStreams is how many inbound streams to add.
	InStreams uint16
	// OutStreams is how many outbound streams to add.
	OutStreams uint16
}

// PrInfo mirrors struct sctp_prinfo (RFC 6458 §5.3.7), the per-message partial
// reliability policy carried as SCTP_CMSG_PRINFO ancillary data.
//
// Note the padding: the C struct is a __u16 followed by a __u32, so the value
// sits at offset 4 and the struct is 8 bytes rather than 6.
type PrInfo struct {
	// Policy is one of the SCTPPrPolicy constants.
	Policy uint16
	_      uint16
	// Value is a lifetime, retransmission count or priority, per Policy.
	Value uint32
}

// AuthInfo mirrors struct sctp_authinfo (RFC 6458 §5.3.8), naming the shared key
// to authenticate one message with, carried as SCTP_CMSG_AUTHINFO.
type AuthInfo struct {
	KeyNumber uint16
}

// AuthKeyID mirrors struct sctp_authkeyid (RFC 6458 §8.1.18), naming one of the
// endpoint's shared keys.
type AuthKeyID struct {
	AssocID   SCTPAssocID
	KeyNumber uint16
	// The C declaration is 6 bytes, but the kernel expects and returns 8.
	// Go's alignment already rounds this struct to 8, so as with DefaultPrInfo
	// the pad records the C layout rather than causing the size; removing it
	// changes nothing, which was verified.
	_ uint16
}

// RtoInfo mirrors struct sctp_rtoinfo (RFC 6458 §8.1.1, SCTP_RTOINFO). It
// governs the retransmission timer, and with it how quickly the stack gives up
// on an unresponsive peer.
//
// All durations are milliseconds. A zero field means "leave unchanged" on a
// set, which is how the kernel reads it.
type RtoInfo struct {
	AssocID SCTPAssocID
	// Initial is the RTO used before any round trip has been measured.
	Initial uint32
	// Max caps the exponential backoff. Combined with AssocInfo.AsocMaxRxt it
	// bounds how long a send can sit unacknowledged before the association is
	// declared failed: the retransmission intervals double up to Max, so a
	// large Max means a peer that vanishes is noticed only after minutes.
	Max uint32
	// Min floors the RTO.
	Min uint32
}

// AssocInfo mirrors struct sctp_assocparams (RFC 6458 8.1.2, SCTP_ASSOCINFO).
//
// AsocMaxRxt is the field that matters for detecting an unreachable peer: it
// is Association.Max.Retrans, RFC 9260 section 8.1 — section 8.2 is the path
// counter, not the association one. Once that many
// consecutive retransmissions to a peer go unacknowledged, the association is
// torn down and the socket becomes readable with an error. Lowering it, and
// lowering RtoInfo.Max, is what turns a silent peer into a prompt, reportable
// failure.
type AssocInfo struct {
	AssocID SCTPAssocID
	// AsocMaxRxt is the maximum retransmission attempts for the association.
	AsocMaxRxt uint16
	// NumberPeerDestinations is how many destination addresses the peer has.
	NumberPeerDestinations uint16
	// PeerRwnd is the peer's last reported receive window, minus outstanding
	// data. It stops shrinking and stays put when a peer stops acknowledging,
	// which makes it a useful companion signal to Status.Unackdata.
	PeerRwnd uint32
	// LocalRwnd is the last receive window reported to the peer.
	LocalRwnd uint32
	// CookieLife is the association's cookie lifetime, in milliseconds.
	CookieLife uint32
}

type PeerState int32

// Per-path states, from enum sctp_spinfo_state in the kernel's uapi
// linux/sctp.h. The order is load-bearing: callers compare PeerAddrinfo.State
// against these to decide whether a path is still usable, so the values must
// match what the kernel reports rather than read in a natural-looking order.
const (
	// SCTP_INACTIVE means the path has failed: it has exceeded
	// Path.Max.Retrans without a response. See RFC 9260 section 8.2.
	SCTP_INACTIVE PeerState = iota
	// SCTP_PF ("potentially failed") is an intermediate state from RFC 7829:
	// some retransmissions have failed but the path is not yet declared
	// inactive.
	SCTP_PF
	// SCTP_ACTIVE means the path is reachable and in use.
	SCTP_ACTIVE
	// SCTP_UNCONFIRMED means the path has not yet been validated by a
	// heartbeat exchange.
	SCTP_UNCONFIRMED

	// SCTP_UNKNOWN is reported when the transport state is not known.
	SCTP_UNKNOWN PeerState = 0xffff
)

// SCTP_POTENTIALLY_FAILED is the spelling RFC 7829 uses for SCTP_PF.
const SCTP_POTENTIALLY_FAILED = SCTP_PF

// PeerAddrinfo Parameters defined in RFC 6458 8.2.2 - Peer Address Information (SCTP_GET_PEER_ADDR_INFO)
type PeerAddrinfo struct {
	AssocID SCTPAssocID
	// Address holds the peer address as a raw sockaddr. Use
	// (*SCTPConn).SCTPGetPrimaryPeerAddr to obtain it decoded: the decoder
	// this package uses is unexported, and decoding the bytes by hand means
	// reproducing the per-entry family and bounds handling it does.
	Address [128]byte
	State   PeerState
	CWND    uint32
	SRTT    uint32
	RTO     uint32
	MTU     uint32
}

type StatusState int32

// Association states, from enum sctp_sstat_state in the kernel's uapi
// linux/sctp.h, as reported by GetStatus.
//
// The enum begins at SCTP_EMPTY rather than SCTP_CLOSED, and has no SCTP_BOUND
// or SCTP_LISTEN members. Numbering from SCTP_CLOSED = 0 shifts every state by
// one, so an established association compares equal to SCTP_COOKIE_ECHOED.
const (
	SCTP_EMPTY StatusState = iota
	SCTP_CLOSED
	SCTP_COOKIE_WAIT
	SCTP_COOKIE_ECHOED
	SCTP_ESTABLISHED
	SCTP_SHUTDOWN_PENDING
	SCTP_SHUTDOWN_SENT
	SCTP_SHUTDOWN_RECEIVED
	SCTP_SHUTDOWN_ACK_SENT
)

// Status Parameters defined in RFC 6458 8.2.1 - Association Status (SCTP_STATUS)
type Status struct {
	AssocID            SCTPAssocID
	State              StatusState
	RWND               uint32
	Unackdata          uint16
	Penddata           uint16
	Instreams          uint16
	Ostreams           uint16
	FragmentationPoint uint32
	PrimaryPeerAddr    PeerAddrinfo
}

type SndRcvInfo struct {
	Stream uint16
	SSN    uint16
	Flags  uint16
	_      uint16
	// PPID is expressed in host byte order. RFC 6458 §5.3.2 labels the ancillary
	// field network byte order and says the SCTP stack performs no byte-order
	// modification. This package applies htonl/ntohl at the kernel boundary so
	// every public PPID uses one host-order convention.
	PPID    uint32
	Context uint32
	TTL     uint32
	TSN     uint32
	CumTSN  uint32
	AssocID int32
}

// SndInfo mirrors struct sctp_sndinfo (RFC 6458 §5.3.4). It is the
// non-deprecated replacement for the send-side half of SndRcvInfo, and is what
// SCTP_DEFAULT_SNDINFO carries.
//
// Five fields where SndRcvInfo has ten: the deprecated struct doubled as the
// receive-side descriptor, and those fields have moved to RcvInfo.
type SndInfo struct {
	// SID is the stream to send on.
	SID uint16
	// Flags carries SCTP_UNORDERED and friends.
	Flags uint16
	// PPID is expressed in host byte order. RFC 6458 §5.3.4 labels the
	// ancillary field network byte order and says the SCTP stack does not modify
	// it; this package converts at the kernel boundary and back in notifications.
	PPID uint32
	// Context is returned with a send failure notification, letting a caller
	// identify which message failed.
	Context uint32
	AssocID int32
}

type GetAddrsOld struct {
	AssocID int32
	AddrNum int32
	Addrs   uintptr
}

type NotificationHeader struct {
	Type   uint16
	Flags  uint16
	Length uint32
}

type SCTPState uint16

const (
	SCTP_COMM_UP = SCTPState(iota)
	SCTP_COMM_LOST
	SCTP_RESTART
	SCTP_SHUTDOWN_COMP
	SCTP_CANT_STR_ASSOC
)

var nativeEndian binary.ByteOrder
var sndRcvInfoSize uintptr

func init() {
	i := uint16(1)
	if *(*byte)(unsafe.Pointer(&i)) == 0 {
		nativeEndian = binary.BigEndian
	} else {
		nativeEndian = binary.LittleEndian
	}
	sndRcvInfoSize = unsafe.Sizeof(SndRcvInfo{})
}

// toBuf serialises a fixed-size value in the host's byte order, for handing to
// the kernel as a socket address or control message.
//
// binary.Write only fails when v is not a fixed-size type, which is a mistake
// in this package rather than anything a caller can cause. Returning the empty
// buffer that failure produces would send a truncated address or control
// message to the kernel, or panic later at buf[0] in ToRawSockAddrBuf, a long
// way from the cause. Panicking here names it.
func toBuf(v interface{}) []byte {
	var buf bytes.Buffer
	if err := binary.Write(&buf, nativeEndian, v); err != nil {
		panic(fmt.Sprintf("sctp: cannot serialise %T: %v", v, err))
	}
	return buf.Bytes()
}

func htons(h uint16) uint16 {
	if nativeEndian == binary.LittleEndian {
		return (h << 8 & 0xff00) | (h >> 8 & 0xff)
	}
	return h
}

var ntohs = htons

func htonl(h uint32) uint32 {
	if nativeEndian == binary.LittleEndian {
		return (h << 24 & 0xff000000) | (h << 8 & 0x00ff0000) | (h >> 8 & 0x0000ff00) | (h >> 24 & 0x000000ff)
	}
	return h
}

var ntohl = htonl

type SCTPAddr struct {
	IPAddrs []net.IPAddr
	Port    int
}

func cloneSCTPAddr(addr *SCTPAddr) *SCTPAddr {
	if addr == nil {
		return nil
	}
	clone := &SCTPAddr{Port: addr.Port}
	if len(addr.IPAddrs) != 0 {
		clone.IPAddrs = make([]net.IPAddr, len(addr.IPAddrs))
		for i, ip := range addr.IPAddrs {
			clone.IPAddrs[i] = net.IPAddr{
				IP:   append(net.IP(nil), ip.IP...),
				Zone: ip.Zone,
			}
		}
	}
	return clone
}

// MarshalSockaddr validates and encodes the packed sockaddr array used by
// Linux SCTP connectx and bindx operations.
func (a *SCTPAddr) MarshalSockaddr() ([]byte, error) {
	if a == nil {
		return nil, &net.AddrError{Err: "nil SCTP address", Addr: "<nil>"}
	}
	if a.Port < 0 || a.Port > math.MaxUint16 {
		return nil, &net.AddrError{
			Err:  "port must be between 0 and 65535",
			Addr: a.String(),
		}
	}

	p := htons(uint16(a.Port))
	if len(a.IPAddrs) == 0 {
		s := syscall.RawSockaddrInet4{
			Family: syscall.AF_INET,
			Port:   p,
		}
		copy(s.Addr[:], net.IPv4zero)
		return toBuf(s), nil
	}

	buf := make([]byte, 0, len(a.IPAddrs)*int(unsafe.Sizeof(syscall.RawSockaddrInet6{})))
	for i, ip := range a.IPAddrs {
		if len(ip.IP) == 0 {
			return nil, &net.AddrError{
				Err:  fmt.Sprintf("address %d is empty", i),
				Addr: a.String(),
			}
		}
		if ip4 := ip.IP.To4(); ip4 != nil {
			if ip.Zone != "" {
				return nil, &net.AddrError{
					Err:  fmt.Sprintf("IPv4 address %d has a zone", i),
					Addr: a.String(),
				}
			}
			s := syscall.RawSockaddrInet4{
				Family: syscall.AF_INET,
				Port:   p,
			}
			copy(s.Addr[:], ip4)
			buf = append(buf, toBuf(s)...)
			continue
		}

		ip6 := ip.IP.To16()
		if ip6 == nil {
			return nil, &net.AddrError{
				Err:  fmt.Sprintf("address %d is not a valid IPv4 or IPv6 address", i),
				Addr: a.String(),
			}
		}
		scopeID, err := zoneID(ip.Zone)
		if err != nil {
			return nil, &net.AddrError{
				Err:  fmt.Sprintf("address %d has invalid IPv6 zone %q: %v", i, ip.Zone, err),
				Addr: a.String(),
			}
		}
		s := syscall.RawSockaddrInet6{
			Family:   syscall.AF_INET6,
			Port:     p,
			Scope_id: scopeID,
		}
		copy(s.Addr[:], ip6)
		buf = append(buf, toBuf(s)...)
	}
	return buf, nil
}

// Validate reports whether an SCTP address can be passed to the kernel without
// truncation or reinterpretation.
func (a *SCTPAddr) Validate() error {
	_, err := a.MarshalSockaddr()
	return err
}

func zoneID(zone string) (uint32, error) {
	if zone == "" {
		return 0, nil
	}
	if n, err := strconv.ParseUint(zone, 10, 32); err == nil {
		return uint32(n), nil
	}
	ifi, err := net.InterfaceByName(zone)
	if err != nil {
		return 0, err
	}
	if ifi.Index < 0 || uint64(ifi.Index) > math.MaxUint32 {
		return 0, fmt.Errorf("interface index %d is out of range", ifi.Index)
	}
	return uint32(ifi.Index), nil
}

// validateNetworkFamily applies the explicit sctp4/sctp6 promise to direct
// SCTPAddr values. The generic sctp network intentionally permits a mixed list
// on a dual-stack socket.
func (a *SCTPAddr) validateNetworkFamily(network string) error {
	if err := a.Validate(); err != nil {
		return err
	}
	for i, ip := range a.IPAddrs {
		switch network {
		case "sctp4":
			if ip.IP.To4() == nil {
				return &net.AddrError{
					Err:  fmt.Sprintf("address %d is not IPv4 for sctp4", i),
					Addr: a.String(),
				}
			}
		case "sctp6":
			if ip.IP.To4() != nil {
				return &net.AddrError{
					Err:  fmt.Sprintf("address %d is not IPv6 for sctp6", i),
					Addr: a.String(),
				}
			}
		}
	}
	return nil
}

// ToRawSockAddrBuf encodes this address for compatibility with older callers.
// It returns nil for an invalid address; new code should call MarshalSockaddr
// when it needs the validation error.
func (a *SCTPAddr) ToRawSockAddrBuf() []byte {
	buf, _ := a.MarshalSockaddr()
	return buf
}

func (a *SCTPAddr) String() string {
	if a == nil {
		return "<nil>"
	}
	var b bytes.Buffer

	for n, i := range a.IPAddrs {
		if i.IP.To4() != nil {
			b.WriteString(i.String())
		} else if i.IP.To16() != nil {
			b.WriteRune('[')
			b.WriteString(i.String())
			b.WriteRune(']')
		}
		if n < len(a.IPAddrs)-1 {
			b.WriteRune('/')
		}
	}
	b.WriteRune(':')
	b.WriteString(strconv.Itoa(a.Port))
	return b.String()
}

func (a *SCTPAddr) Network() string { return "sctp" }

// canonicalNetwork validates an SCTP network name and returns it with the empty
// string spelled out, along with the TCP network used to resolve its addresses.
//
// It is the single place that decides which names are valid, and every entry
// point that takes a network calls it. That matters for two reasons.
//
// favoriteAddrFamily, vendored from the standard library, picks an address
// family from the name's last byte. The standard library only ever calls it
// with a name its own caller has already checked; this package called it with
// whatever the caller passed. So ListenSCTP("") and DialSCTP("") panicked with
// an index out of range — the empty string has no last byte — and
// ListenSCTP("tcp") quietly created an SCTP socket, because "p" is neither '4'
// nor '6' and the default is reached. Rejecting unknown names and expanding the
// empty one here keeps the vendored function byte-identical to upstream.
//
// The empty string means "sctp", which is what ResolveSCTPAddr has always
// accepted and what net.Dial does for its own networks.
func canonicalNetwork(network string) (sctpnet, tcpnet string, err error) {
	switch network {
	case "", "sctp":
		return "sctp", "tcp", nil
	case "sctp4":
		return "sctp4", "tcp4", nil
	case "sctp6":
		return "sctp6", "tcp6", nil
	}
	return "", "", net.UnknownNetworkError(network)
}

func ResolveSCTPAddr(network, addrs string) (*SCTPAddr, error) {
	sctpnet, tcpnet, err := canonicalNetwork(network)
	if err != nil {
		return nil, err
	}
	// strings.Split never returns an empty slice, so the last element always
	// exists; the length check that used to be here could not fire.
	elems := strings.Split(addrs, "/")
	ipaddrs := make([]net.IPAddr, 0, len(elems))
	for _, e := range elems[:len(elems)-1] {
		tcpa, err := net.ResolveTCPAddr(tcpnet, e+":")
		if err != nil {
			return nil, err
		}
		if tcpa.IP == nil {
			// An empty element. "/127.0.0.1:80" used to produce a nil IP
			// followed by the real one, and binding that list asks for the
			// wildcard address as well as the one the caller named.
			return nil, &net.AddrError{
				Err:  "empty address in a multi-homed address list",
				Addr: addrs,
			}
		}
		ipaddrs = append(ipaddrs, net.IPAddr{IP: tcpa.IP, Zone: tcpa.Zone})
	}
	tcpa, err := net.ResolveTCPAddr(tcpnet, elems[len(elems)-1])
	if err != nil {
		return nil, err
	}
	if tcpa.IP != nil {
		ipaddrs = append(ipaddrs, net.IPAddr{IP: tcpa.IP, Zone: tcpa.Zone})
	} else if len(ipaddrs) > 0 {
		// The caller listed addresses and then ended with a bare port, as in
		// "1.2.3.4/5.6.7.8/:80". This used to discard every listed address and
		// return a wildcard, so a trailing separator in a configuration file
		// silently turned "listen on these two" into "listen on everything".
		return nil, &net.AddrError{
			Err:  "address list ends with a port and no address",
			Addr: addrs,
		}
	} else {
		// No addresses at all: a bare port means the wildcard, which is the
		// documented meaning of ":80".
		ipaddrs = nil
	}
	addr := &SCTPAddr{
		IPAddrs: ipaddrs,
		Port:    tcpa.Port,
	}
	if err := addr.validateNetworkFamily(sctpnet); err != nil {
		return nil, err
	}
	return addr, nil
}

// SCTPConnect establishes an association with addr on the socket fd.
//
// EISCONN is reported as success because the requested association is already
// established. EALREADY is preserved: it means the association exists but its
// handshake is still in progress. net/sctp/socket.c has, in __sctp_connect and
// again in sctp_connect_add_peer:
//
//	asoc = sctp_endpoint_lookup_assoc(ep, daddr, &transport);
//	if (asoc)
//	        return asoc->state >= SCTP_STATE_ESTABLISHED ? -EISCONN
//	                                                     : -EALREADY;
//
// Treating EALREADY as success is unsafe even on a descriptor without
// O_NONBLOCK: a second goroutine can reach this branch while the first remains
// blocked in the original connect. The early return skips sctp_wait_for_connect,
// so the socket is not yet usable. DialSCTP handles this internal state by
// waiting for SCTP_STATUS; the exported raw-descriptor operation returns
// EALREADY so its caller retains control of that policy.
//
// Two CONNECTX3 calls against an unreachable address on one non-blocking socket
// can give EINPROGRESS then EALREADY repeatably.
//
// AssocID is not filled in on either early-return path, so 0 is returned with a
// nil error for EISCONN or with EALREADY; callers needing the id read it back
// from the socket after establishment.
func SCTPConnect(fd int, addr *SCTPAddr) (int, error) {
	id, viaEALREADY, err := sctpConnect(fd, addr)
	if viaEALREADY && err == nil {
		return id, syscall.EALREADY
	}
	return id, err
}

// sctpConnect is SCTPConnect, additionally reporting whether it returned
// success through the EALREADY branch rather than from a completed connect.
//
// Only that branch leaves the handshake unfinished, so only that branch needs
// confirming before a connection is handed out. Distinguishing it keeps the
// normal path free of extra syscalls, and — more importantly — keeps a slow but
// healthy handshake from being cut short by a verification timeout, which is
// what happened when the dial path confirmed unconditionally: dials that the
// kernel would have completed were failed with ETIMEDOUT under suite load.
func sctpConnect(fd int, addr *SCTPAddr) (assocID int, viaEALREADY bool, err error) {
	buf, err := addr.MarshalSockaddr()
	if err != nil {
		return 0, false, err
	}
	param := GetAddrsOld{
		AddrNum: int32(len(buf)),
		Addrs:   uintptr(uintptr(unsafe.Pointer(&buf[0]))),
	}
	optlen := uint32(unsafe.Sizeof(param))
	_, _, err = getsockopt(fd, SCTP_SOCKOPT_CONNECTX3, uintptr(unsafe.Pointer(&param)), &optlen)
	if err == nil {
		return int(param.AssocID), false, nil
	} else if err == syscall.EISCONN {
		return 0, false, nil
	} else if err == syscall.EALREADY {
		return 0, true, nil
	} else if err != syscall.ENOPROTOOPT {
		return 0, false, err
	}
	r0, _, err := setsockopt(fd, SCTP_SOCKOPT_CONNECTX, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if err == syscall.EISCONN {
		return int(r0), false, nil
	}
	if err == syscall.EALREADY {
		return int(r0), true, nil
	}
	return int(r0), false, err
}

func SCTPBind(fd int, addr *SCTPAddr, flags int) error {
	var option uintptr
	switch flags {
	case SCTP_BINDX_ADD_ADDR:
		option = SCTP_SOCKOPT_BINDX_ADD
	case SCTP_BINDX_REM_ADDR:
		option = SCTP_SOCKOPT_BINDX_REM
	default:
		return syscall.EINVAL
	}

	buf, err := addr.MarshalSockaddr()
	if err != nil {
		return err
	}
	_, _, err = setsockopt(fd, option, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return err
}

// normalizeDynamicBindAddr prepares one sctp_bindx address list without
// changing the caller's value.
//
// RFC 6458 §9.1 permits either zero or the endpoint's bound port on an
// already-bound socket. Supplying the bound port ourselves has two useful
// properties: it makes the address cached after the call describe exactly what
// went to the kernel, and it avoids relying on platform-specific treatment of
// zero after the socket has been bound. A non-zero, different port is rejected
// before the syscall with the EINVAL required by that section.
func normalizeDynamicBindAddr(addr, current *SCTPAddr) (*SCTPAddr, error) {
	target := cloneSCTPAddr(addr)
	if err := target.Validate(); err != nil {
		return nil, err
	}
	if current == nil || current.Port == 0 {
		return target, nil
	}
	if current.Port < 0 || current.Port > math.MaxUint16 {
		return nil, &net.AddrError{
			Err:  "cached bound port must be between 0 and 65535",
			Addr: current.String(),
		}
	}
	if target.Port == 0 {
		target.Port = current.Port
		return target, nil
	}
	if target.Port != current.Port {
		return nil, &net.OpError{
			Op:   "bindx",
			Net:  "sctp",
			Addr: target,
			Err: fmt.Errorf("address port %d does not match bound port %d: %w",
				target.Port, current.Port, syscall.EINVAL),
		}
	}
	return target, nil
}

// removesEveryLocalAddress reports the RFC 6458 §9.1 case that must be
// rejected with EINVAL before reaching Linux, which reports EBUSY instead.
//
// The empty IPAddrs form encodes one wildcard sockaddr, so removing it from a
// wildcard-bound endpoint is also an attempt to remove the whole set. For
// explicit sets, net.IP.Equal deliberately treats 4-byte and 16-byte spellings
// of the same IPv4 address as equal. Zone names remain significant: if their
// equivalence is uncertain, the function returns false and leaves the decision
// to the kernel rather than rejecting a potentially valid partial removal.
func removesEveryLocalAddress(current, remove *SCTPAddr) bool {
	if current == nil || remove == nil {
		return false
	}
	if len(remove.IPAddrs) == 0 {
		return true
	}
	if len(current.IPAddrs) == 0 {
		return false
	}
	for _, bound := range current.IPAddrs {
		found := false
		for _, candidate := range remove.IPAddrs {
			if bound.Zone == candidate.Zone && bound.IP.Equal(candidate.IP) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func lastAddressRemovalError(addr *SCTPAddr) error {
	return &net.OpError{
		Op:   "bindx",
		Net:  "sctp",
		Addr: addr,
		Err:  fmt.Errorf("cannot remove every local address: %w", syscall.EINVAL),
	}
}

// dynamicBind applies one atomic RFC 6458 §9.1 sctp_bindx operation while
// the runtime keeps the descriptor alive, then reads the complete local address
// set back from the same descriptor.
//
// applied distinguishes a bind that failed from the exceptional case where the
// bind succeeded but the readback failed. Callers clear their cache in the
// latter case instead of continuing to publish an address set known to be
// stale. The returned error says explicitly that the kernel mutation happened,
// so retrying it blindly is not safe.
func dynamicBind(raw syscall.RawConn, addr *SCTPAddr, flags int) (
	local *SCTPAddr, applied bool, err error,
) {
	if raw == nil {
		return nil, false, errClosed("bindx")
	}

	var callErr error
	controlErr := raw.Control(func(fd uintptr) {
		callErr = SCTPBind(int(fd), addr, flags)
		if callErr != nil {
			return
		}
		applied = true
		local, callErr = sctpGetAddrs(int(fd), 0, SCTP_GET_LOCAL_ADDRS)
		if callErr != nil {
			callErr = fmt.Errorf(
				"sctp_bindx succeeded but refreshing the local addresses failed: %w",
				callErr)
		}
	})
	if controlErr != nil {
		return nil, applied, normalizePollError("bindx", controlErr)
	}
	return local, applied, callErr
}

type SCTPConn struct {
	// Linux delegates deadlines to the runtime poller. writeDeadline mirrors
	// whether the message-oriented send APIs wait for send-buffer readiness;
	// writeDeadlineMu makes that decision atomic with updating the poller and
	// serializes concurrent setters without being held across a send.
	writeDeadlineMu sync.Mutex
	writeDeadline   int64
	// readMu extends receive serialization past RawConn.Read's return when a
	// partial notification forces fail-closed teardown. Without it, a waiting
	// reader could acquire internal/poll's lock and consume the orphaned tail
	// before the first reader aborts the association. It is always released
	// before NotificationHandler runs, so handler re-entry remains safe.
	readMu sync.Mutex

	_fd                 int32
	notificationHandler NotificationHandler
	file                *os.File
	raw                 syscall.RawConn
	initErr             error

	// bindMu serializes dynamic address changes so that an older readback can
	// never overwrite the cache produced by a newer operation.
	bindMu     sync.Mutex
	addrMu     sync.RWMutex
	localAddr  *SCTPAddr
	remoteAddr *SCTPAddr
}

func (c *SCTPConn) fd() int {
	if c == nil {
		return -1
	}
	return int(atomic.LoadInt32(&c._fd))
}

// NewSCTPConn takes ownership of fd immediately, including when descriptor
// initialization fails. The caller must not close fd or use it after this
// call. The returned connection records initialization failures and reports
// them from subsequent operations because this compatibility signature cannot
// return an error directly.
func NewSCTPConn(fd int, handler NotificationHandler) *SCTPConn {
	conn, err := newSCTPConn(fd, handler)
	if err != nil {
		return &SCTPConn{
			_fd:                 -1,
			notificationHandler: handler,
			initErr:             err,
		}
	}
	return conn
}

func (c *SCTPConn) Write(b []byte) (int, error) {
	// net.Conn's Write reports (0, nil) for an empty buffer. The kernel refuses
	// a zero-length SCTP message with EINVAL — confirmed against it directly,
	// so it is not an artefact of this binding — which is a fine answer for
	// SCTPWrite and SCTPWriteInfo, where the caller asked for a message. It is
	// the wrong answer here, where the caller asked for the net.Conn contract.
	if c == nil || c.fd() < 0 {
		return 0, errClosed("write")
	}
	if len(b) == 0 {
		return 0, nil
	}
	return c.write(b)
}

func (c *SCTPConn) Read(b []byte) (int, error) {
	for {
		n, _, flags, err := c.SCTPReadFlags(b)
		if n < 0 {
			n = 0
		}
		if flags&MSG_NOTIFICATION == 0 {
			return n, err
		}
		// Notifications share the receive queue with application messages.
		// net.Conn.Read has no flag channel in which to identify them, so never
		// expose an event structure as bytes sent by the peer. SCTPReadFlags is
		// the API for callers that need the raw notification.
		if err != nil {
			return 0, err
		}
	}
}

// SetInitMsg sets the association initialisation parameters (SCTP_INITMSG).
//
// Every field is a uint16 in the kernel. The arguments are ints, so a value
// outside that range used to be truncated silently: 65536 streams became 0,
// which the kernel reads as "leave the default", and a caller asking for more
// streams than SCTP can carry got the default instead of an error. Read them
// back with GetInitMsg.
func (c *SCTPConn) SetInitMsg(numOstreams, maxInstreams, maxAttempts, maxInitTimeout int) error {
	for _, v := range []int{numOstreams, maxInstreams, maxAttempts, maxInitTimeout} {
		if v < 0 || v > math.MaxUint16 {
			return syscall.EINVAL
		}
	}
	return c.setInitOpts(InitMsg{
		NumOstreams:    uint16(numOstreams),
		MaxInstreams:   uint16(maxInstreams),
		MaxAttempts:    uint16(maxAttempts),
		MaxInitTimeout: uint16(maxInitTimeout),
	})
}

func (c *SCTPConn) SubscribeEvents(flags int) error {
	var d, a, ad, sf, p, sh, pa, ada, au, se uint8
	if flags&SCTP_EVENT_DATA_IO > 0 {
		d = 1
	}
	if flags&SCTP_EVENT_ASSOCIATION > 0 {
		a = 1
	}
	if flags&SCTP_EVENT_ADDRESS > 0 {
		ad = 1
	}
	if flags&SCTP_EVENT_SEND_FAILURE > 0 {
		sf = 1
	}
	if flags&SCTP_EVENT_PEER_ERROR > 0 {
		p = 1
	}
	if flags&SCTP_EVENT_SHUTDOWN > 0 {
		sh = 1
	}
	if flags&SCTP_EVENT_PARTIAL_DELIVERY > 0 {
		pa = 1
	}
	if flags&SCTP_EVENT_ADAPTATION_LAYER > 0 {
		ada = 1
	}
	if flags&SCTP_EVENT_AUTHENTICATION > 0 {
		au = 1
	}
	if flags&SCTP_EVENT_SENDER_DRY > 0 {
		se = 1
	}
	param := EventSubscribe{
		DataIO:          d,
		Association:     a,
		Address:         ad,
		SendFailure:     sf,
		PeerError:       p,
		Shutdown:        sh,
		PartialDelivery: pa,
		AdaptationLayer: ada,
		Authentication:  au,
		SenderDry:       se,
	}
	optlen := uint32(unsafe.Sizeof(param))
	_, _, err := c.setsockopt(SCTP_EVENTS, uintptr(unsafe.Pointer(&param)), uintptr(optlen))
	return err
}

// SubscribeEvent subscribes to a single notification type, or unsubscribes from
// it when on is false.
//
// This is the SCTP_EVENT option from RFC 6458 §6.2.2, which exists because
// SCTP_EVENTS — what SubscribeEvents uses — is deprecated: its struct has to
// grow every time an event is added, so a binary built against an older
// definition silently cannot reach the newer events. Naming one event per call
// has no such limit.
//
// eventType is a notification type such as SCTP_ASSOC_CHANGE. The kernel
// validates it and reports EINVAL for a type it does not know.
//
// The two options do not read the same state once an association exists, which
// was measured rather than assumed. On a socket with no association, an event
// set here reads back as set in the struct SubscribeEvents sends. On a connected
// socket it does not: AssocID 0 acts on that association, while SCTP_EVENTS
// reads the endpoint defaults, so the subscription shows as on through
// EventSubscribed and off through SCTP_EVENTS. Do not mix the two on a connected
// socket and expect either to report what the other set. Set whichever you use
// before connecting if you need one consistent view.
func (c *SCTPConn) SubscribeEvent(eventType SCTPNotificationType, on bool) error {
	param := Event{Type: uint16(eventType)}
	if on {
		param.On = 1
	}
	optlen := uint32(unsafe.Sizeof(param))
	_, _, err := c.setsockopt(SCTP_EVENT,
		uintptr(unsafe.Pointer(&param)), uintptr(optlen))
	return err
}

// EventSubscribed reports whether a single notification type is subscribed.
//
// It is the getsockopt direction of SCTP_EVENT: the type to query goes in, and
// the kernel fills in whether it is on.
func (c *SCTPConn) EventSubscribed(eventType SCTPNotificationType) (bool, error) {
	param := Event{Type: uint16(eventType)}
	optlen := uint32(unsafe.Sizeof(param))
	_, _, err := c.getsockopt(SCTP_EVENT,
		uintptr(unsafe.Pointer(&param)), &optlen)
	if err != nil {
		return false, err
	}
	return param.On != 0, nil
}

// SetRecvRcvInfo enables or disables delivery of SCTP_RCVINFO as ancillary data
// on each received message (RFC 6458 §8.1.29).
//
// This is the non-deprecated counterpart of the SCTP_SNDRCV data that
// SubscribeEvents(SCTP_EVENT_DATA_IO) asks for: RFC 6458 §5.3.2 marks
// SCTP_SNDRCV deprecated and directs callers to SCTP_SNDINFO and SCTP_RCVINFO.
// SCTPRead accepts either form and normalizes both to SndRcvInfo. SCTPReadMsg
// exposes the raw SCTP_RCVINFO control message to callers that need the modern
// ABI without normalization.
func (c *SCTPConn) SetRecvRcvInfo(on bool) error {
	return c.setsockoptInt(SCTP_RECVRCVINFO, on)
}

// SetRecvNxtInfo enables or disables delivery of SCTP_NXTINFO, which describes
// the message following the one being read (RFC 6458 §8.1.30).
//
// Read the result with SCTPReadNextInfo. SCTPRead and SCTPReadFlags ignore the
// ancillary data this enables, so enabling it and then reading with those
// discards it — which is what this package did in both directions until
// SCTPReadNextInfo existed.
func (c *SCTPConn) SetRecvNxtInfo(on bool) error {
	return c.setsockoptInt(SCTP_RECVNXTINFO, on)
}

// NxtInfo mirrors struct sctp_nxtinfo (RFC 6458 §5.3.6), describing the message
// queued behind the one just read.
//
// Length is the point of it: a caller can size the next buffer exactly instead
// of guessing, which on a message-oriented protocol is the difference between
// one read and a reassembly loop. It arrives only when SetRecvNxtInfo is on and
// only when there is a next message — an empty queue means no ancillary data,
// which SCTPReadNextInfo reports as a nil NxtInfo rather than an error.
type NxtInfo struct {
	// SID is the stream the next message arrives on.
	SID uint16
	// Flags carries SCTP_UNORDERED and, if the next message is a notification,
	// MSG_NOTIFICATION.
	Flags uint16
	// PPID is the payload protocol identifier, converted to host order as
	// SCTPRead does for SndRcvInfo.PPID.
	PPID uint32
	// Length is the size of the whole next message in bytes.
	Length  uint32
	AssocID SCTPAssocID
}

func (c *SCTPConn) SubscribedEvents() (int, error) {
	param := EventSubscribe{}
	optlen := uint32(unsafe.Sizeof(param))
	_, _, err := c.getsockopt(SCTP_EVENTS, uintptr(unsafe.Pointer(&param)), &optlen)
	if err != nil {
		return 0, err
	}
	var flags int
	if param.DataIO > 0 {
		flags |= SCTP_EVENT_DATA_IO
	}
	if param.Association > 0 {
		flags |= SCTP_EVENT_ASSOCIATION
	}
	if param.Address > 0 {
		flags |= SCTP_EVENT_ADDRESS
	}
	if param.SendFailure > 0 {
		flags |= SCTP_EVENT_SEND_FAILURE
	}
	if param.PeerError > 0 {
		flags |= SCTP_EVENT_PEER_ERROR
	}
	if param.Shutdown > 0 {
		flags |= SCTP_EVENT_SHUTDOWN
	}
	if param.PartialDelivery > 0 {
		flags |= SCTP_EVENT_PARTIAL_DELIVERY
	}
	if param.AdaptationLayer > 0 {
		flags |= SCTP_EVENT_ADAPTATION_LAYER
	}
	if param.Authentication > 0 {
		flags |= SCTP_EVENT_AUTHENTICATION
	}
	if param.SenderDry > 0 {
		flags |= SCTP_EVENT_SENDER_DRY
	}
	return flags, nil
}

// SetDefaultSentParam sets the deprecated sctp_sndrcvinfo defaults from RFC
// 6458 §8.1.13. PPID is accepted in host byte order, like SCTPWrite. RFC 6458
// §5.3.2 labels the ABI field network byte order while requiring the SCTP stack
// to leave it untouched, so the package converts a copy without modifying info.
// Prefer SetDefaultSndInfo for new code.
func (c *SCTPConn) SetDefaultSentParam(info *SndRcvInfo) error {
	if info == nil {
		return syscall.EINVAL
	}
	param := *info
	param.PPID = htonl(param.PPID)
	optlen := uint32(unsafe.Sizeof(param))
	_, _, err := c.setsockopt(SCTP_DEFAULT_SEND_PARAM,
		uintptr(unsafe.Pointer(&param)), uintptr(optlen))
	return err
}

// GetDefaultSentParam returns PPID in host byte order. Prefer
// GetDefaultSndInfo for new code (RFC 6458 §8.1.13).
func (c *SCTPConn) GetDefaultSentParam() (*SndRcvInfo, error) {
	info := &SndRcvInfo{}
	optlen := uint32(unsafe.Sizeof(*info))
	_, _, err := c.getsockopt(SCTP_DEFAULT_SEND_PARAM, uintptr(unsafe.Pointer(info)), &optlen)
	if err != nil {
		return nil, err
	}
	info.PPID = ntohl(info.PPID)
	return info, nil
}

func (c *SCTPConn) SetNoDelay(optval int) error {
	val, err := noDelayValue(optval)
	if err != nil {
		return err
	}
	_, _, err = c.setsockopt(SCTP_NODELAY, uintptr(unsafe.Pointer(&val)), unsafe.Sizeof(val))
	return err
}

func (c *SCTPConn) GetNoDelay() (int, error) {
	var optval int32
	optlen := uint32(unsafe.Sizeof(optval))
	_, _, err := c.getsockopt(
		SCTP_NODELAY,
		uintptr(unsafe.Pointer(&optval)),
		&optlen,
	)
	return int(optval), err
}

func noDelayValue(v int) (int32, error) {
	if int64(v) < math.MinInt32 || int64(v) > math.MaxInt32 {
		return 0, fmt.Errorf("sctp: SCTP_NODELAY value %d is outside Linux int range", v)
	}
	return int32(v), nil
}

// SetSackTimer configures delayed acknowledgements (RFC 6458 §8.1.19 and
// RFC 9260 §6.2). Zero fields leave the corresponding value unchanged.
//
// RFC 9260 requires implementations to reject SACK.Delay above 500 ms. It
// recommends, but does not require, a delay no greater than 200 ms and an
// acknowledgement for at least every second packet, so larger frequencies and
// delays through 500 remain available for applications that deliberately need
// them.
func (c *SCTPConn) SetSackTimer(timer *SackTimer) error {
	if timer == nil {
		return fmt.Errorf("sctp: nil SackTimer: %w", syscall.EINVAL)
	}
	if timer.SackDelay > 500 {
		return fmt.Errorf("sctp: SACK delay %d ms exceeds RFC 9260 §6.2's 500 ms maximum: %w",
			timer.SackDelay, syscall.EINVAL)
	}
	optlen := uint32(unsafe.Sizeof(*timer))
	_, _, err := c.setsockopt(SCTP_DELAYED_SACK, uintptr(unsafe.Pointer(timer)), uintptr(optlen))
	return err
}

func (c *SCTPConn) GetSackTimer() (*SackTimer, error) { // SackTimer
	timer := &SackTimer{}
	optlen := uint32(unsafe.Sizeof(*timer))
	_, _, err := c.getsockopt(
		SCTP_DELAYED_SACK,
		uintptr(unsafe.Pointer(timer)),
		&optlen,
	)
	return timer, err
}

// SetRtoInfo sets the association's retransmission timer parameters
// (SCTP_RTOINFO). Fields left zero are unchanged.
//
// Reducing Max is half of making an unreachable peer detectable promptly; see
// SetAssocInfo for the other half.
func (c *SCTPConn) SetRtoInfo(info *RtoInfo) error {
	if info == nil {
		return syscall.EINVAL
	}
	optlen := uint32(unsafe.Sizeof(*info))
	_, _, err := c.setsockopt(SCTP_RTOINFO, uintptr(unsafe.Pointer(info)), uintptr(optlen))
	return err
}

// GetRtoInfo reports the association's retransmission timer parameters.
func (c *SCTPConn) GetRtoInfo() (*RtoInfo, error) {
	info := &RtoInfo{}
	optlen := uint32(unsafe.Sizeof(*info))
	_, _, err := c.getsockopt(
		SCTP_RTOINFO,
		uintptr(unsafe.Pointer(info)),
		&optlen,
	)
	if err != nil {
		return nil, err
	}
	return info, nil
}

// SetAssocInfo sets association parameters (SCTP_ASSOCINFO). Fields left zero
// are unchanged.
//
// Setting AsocMaxRxt bounds how many unacknowledged retransmissions the stack
// tolerates before declaring the association failed, which is what converts a
// peer that has silently gone away into an error the application can see.
func (c *SCTPConn) SetAssocInfo(info *AssocInfo) error {
	if info == nil {
		return syscall.EINVAL
	}
	optlen := uint32(unsafe.Sizeof(*info))
	_, _, err := c.setsockopt(SCTP_ASSOCINFO, uintptr(unsafe.Pointer(info)), uintptr(optlen))
	return err
}

// GetAssocInfo reports association parameters, including the peer's last
// advertised receive window.
func (c *SCTPConn) GetAssocInfo() (*AssocInfo, error) {
	info := &AssocInfo{}
	optlen := uint32(unsafe.Sizeof(*info))
	_, _, err := c.getsockopt(
		SCTP_ASSOCINFO,
		uintptr(unsafe.Pointer(info)),
		&optlen,
	)
	if err != nil {
		return nil, err
	}
	return info, nil
}

// SetMaxSegSize sets the maximum fragment size the association will use
// (SCTP_MAXSEG, RFC 6458 8.1.16). Messages larger than this are fragmented
// across multiple DATA chunks rather than being sent as one.
//
// A value of zero restores the default, which is derived from the path MTU.
// The kernel clamps the request to what the path can carry, so read it back
// with GetMaxSegSize if the effective value matters.
func (c *SCTPConn) SetMaxSegSize(size int) error {
	if size < 0 || int64(size) > int64(^uint32(0)) {
		return errors.New("sctp: max segment size out of range")
	}
	val := AssocValue{AssocVal: uint32(size)}
	optlen := uint32(unsafe.Sizeof(val))
	_, _, err := c.setsockopt(
		SCTP_MAXSEG,
		uintptr(unsafe.Pointer(&val)),
		uintptr(optlen),
	)
	return err
}

// GetMaxSegSize reports the association's current maximum fragment size.
func (c *SCTPConn) GetMaxSegSize() (int, error) {
	val := AssocValue{}
	optlen := uint32(unsafe.Sizeof(val))
	_, _, err := c.getsockopt(
		SCTP_MAXSEG,
		uintptr(unsafe.Pointer(&val)),
		&optlen,
	)
	if err != nil {
		return 0, err
	}
	return int(val.AssocVal), nil
}

// SetFragmentInterleave controls whether a partial delivery on one stream
// blocks delivery of messages on the others (RFC 6458 §8.1.20).
//
// level must be one of SCTPFragmentInterleaveNone, ...Other or ...Streams.
// Linux keeps a flag rather than a level, so it stores any non-zero request as
// 1. The range check rejects undefined values before the syscall, and the
// immediate readback rejects level 2 with an error wrapping
// errors.ErrUnsupported instead of reporting false success.
//
// The default is SCTPFragmentInterleaveNone, which blocks every other message
// while a partial delivery is in progress. ...Other is the highest level that
// reads back. True level 2 is unavailable on current Linux. Negotiating the
// I-DATA chunk with SetInterleavingSupported is a separate RFC 8260 capability;
// it requires a non-zero fragment setting but does not make this option level 2.
func (c *SCTPConn) SetFragmentInterleave(level int) error {
	switch level {
	case SCTPFragmentInterleaveNone, SCTPFragmentInterleaveOther,
		SCTPFragmentInterleaveStreams:
	default:
		return fmt.Errorf("sctp: fragment interleave level %d is not one of 0, 1 or 2", level)
	}
	if err := c.setsockoptInt32(SCTP_FRAGMENT_INTERLEAVE, int32(level)); err != nil {
		return err
	}
	applied, err := c.getsockoptInt32(SCTP_FRAGMENT_INTERLEAVE)
	if err != nil {
		return err
	}
	if int(applied) != level {
		return fmt.Errorf("sctp: Linux applied fragment-interleave level %d after level %d was requested: %w",
			applied, level, errors.ErrUnsupported)
	}
	return nil
}

// GetFragmentInterleave reports the current fragmented interleave level.
func (c *SCTPConn) GetFragmentInterleave() (int, error) {
	v, err := c.getsockoptInt32(SCTP_FRAGMENT_INTERLEAVE)
	return int(v), err
}

// SetPartialDeliveryPoint sets the message size, in bytes, at which the kernel
// starts delivering a message piecewise to free receive window for the peer
// (RFC 6458 §8.1.21).
//
// A lower value makes partial delivery happen more often. RFC 6458 notes the
// call fails if the value exceeds the socket receive buffer, so a caller raising
// this should raise SO_RCVBUF first.
func (c *SCTPConn) SetPartialDeliveryPoint(bytes int) error {
	if bytes < 0 || int64(bytes) > int64(^uint32(0)) {
		return fmt.Errorf("sctp: partial delivery point %d out of range", bytes)
	}
	// Linux consumes this option as u32. The setter is named for its four-byte
	// storage, so convert through uint32 explicitly to preserve values above
	// MaxInt32 instead of letting a wider int alias an unrelated value.
	return c.setsockoptInt32(SCTP_PARTIAL_DELIVERY_POINT, int32(uint32(bytes)))
}

// GetPartialDeliveryPoint reports the current partial delivery point in bytes.
func (c *SCTPConn) GetPartialDeliveryPoint() (int, error) {
	v, err := c.getsockoptInt32(SCTP_PARTIAL_DELIVERY_POINT)
	return int(v), err
}

// SetMaxBurst bounds how many packets the association may emit back to back
// (RFC 6458 §8.1.24).
//
// Zero disables burst mitigation. The kernel default is 4, which was read back
// rather than taken from the specification.
func (c *SCTPConn) SetMaxBurst(burst int) error {
	if burst < 0 || int64(burst) > int64(^uint32(0)) {
		return fmt.Errorf("sctp: max burst %d out of range", burst)
	}
	return c.setAssocValue(SCTP_MAX_BURST, uint32(burst))
}

// GetMaxBurst reports the current maximum burst.
func (c *SCTPConn) GetMaxBurst() (int, error) {
	v, err := c.getAssocValue(SCTP_MAX_BURST)
	return int(v), err
}

// SetContext sets the context value reported with messages received from the
// peer (RFC 6458 §8.1.25).
//
// Per the RFC this affects received messages only; it does not change the
// context saved with outbound messages, which SCTPWrite carries per message in
// SndRcvInfo.Context.
func (c *SCTPConn) SetContext(context uint32) error {
	return c.setAssocValue(SCTP_CONTEXT, context)
}

// GetContext reports the current default context.
func (c *SCTPConn) GetContext() (uint32, error) {
	return c.getAssocValue(SCTP_CONTEXT)
}

// SetReusePort enables or disables binding several endpoints to one port
// (RFC 6458 §8.1.27).
//
// RFC 6458 restricts this to one-to-one style sockets, which is the only style
// this package creates, and says it has to be set before bind.
//
// Linux enforces that strictly: on a socket that is already bound or connected
// the call fails with EFAULT rather than being ignored, which was measured. A
// connection returned by DialSCTP or AcceptSCTP is therefore always too late —
// the option is only useful on a descriptor obtained before bind, for example
// inside the Control hook of a SocketConfig.
func (c *SCTPConn) SetReusePort(on bool) error {
	return c.setsockoptInt(SCTP_REUSE_PORT, on)
}

// SetDefaultSndInfo sets the send parameters applied to messages written without
// their own (RFC 6458 §8.1.31).
//
// This is the replacement for SetDefaultSentParam: RFC 6458 §8.1.13 deprecates
// SCTP_DEFAULT_SEND_PARAM along with the struct sctp_sndrcvinfo it carries.
// Prefer this for new code; the two write the same underlying defaults.
//
// PPID uses the same host-order convention as SCTPWrite and SCTPWriteInfo. RFC
// 6458 §5.3.4 labels the ABI field network byte order while requiring the SCTP
// stack to leave it untouched, so the package converts a copy at the socket
// boundary without modifying info.
//
// The kernel rejects a short option, so this is one of the places where the Go
// struct size has to be right; TestStructLayoutsMatchKernel pins it.
func (c *SCTPConn) SetDefaultSndInfo(info *SndInfo) error {
	if info == nil {
		return syscall.EINVAL
	}
	param := *info
	param.PPID = htonl(param.PPID)
	optlen := uint32(unsafe.Sizeof(param))
	_, _, err := c.setsockopt(SCTP_DEFAULT_SNDINFO,
		uintptr(unsafe.Pointer(&param)), uintptr(optlen))
	return err
}

// GetDefaultSndInfo reports the current default send parameters.
func (c *SCTPConn) GetDefaultSndInfo() (*SndInfo, error) {
	info := &SndInfo{}
	optlen := uint32(unsafe.Sizeof(*info))
	_, _, err := c.getsockopt(SCTP_DEFAULT_SNDINFO,
		uintptr(unsafe.Pointer(info)), &optlen)
	if err != nil {
		return nil, err
	}
	info.PPID = ntohl(info.PPID)
	return info, nil
}

// SetAutoAsconf enables or disables announcing local address changes to the peer
// with ASCONF chunks (RFC 6458 §8.1.23).
//
// Enabling it needs a socket bound to the wildcard address, not merely a bound
// socket. The kernel's gate is
//
//	if (!sctp_is_ep_boundall(sk) && *val)
//		return -EINVAL;
//
// so a socket bound to a specific address is refused exactly like an unbound
// one — measured as bound 127.0.0.1 set(1) → EINVAL, bound 0.0.0.0 set(1) → OK.
// Disabling it is always allowed, since the gate only guards a non-zero value.
//
// That rules out the obvious place to call it. A listener bound to named
// addresses, which is the ordinary multi-homing case, cannot enable this at
// all; it has to be a wildcard bind. Contrast SetReusePort, which must be set
// before bind.
func (c *SCTPConn) SetAutoAsconf(on bool) error {
	return c.setsockoptInt(SCTP_AUTO_ASCONF, on)
}

// AutoAsconf reports whether ASCONF announcement is enabled.
func (c *SCTPConn) AutoAsconf() (bool, error) {
	v, err := c.getsockoptInt32(SCTP_AUTO_ASCONF)
	return v != 0, err
}

// SetPrSupported enables or disables the PR-SCTP partial reliability extension
// (RFC 7496 §4.5).
//
// Set it before connecting: the extension is negotiated in the INIT handshake,
// so a later call cannot add it to a live association.
//
// On a stock kernel this option changes nothing, because net.sctp.prsctp_enable
// defaults to 1 and the extension is therefore offered whether or not it is set
// here. PrSupported consequently reports true on an association where neither
// end touched the option — measured across all four enable combinations. The
// call is still worth making for a caller that cannot assume the sysctl, and
// setting it to false is the only way to opt an individual socket out.
//
// Despite RFC 7496 describing this as an on/off value, Linux carries it in a
// struct sctp_assoc_value and rejects a plain int with EINVAL — measured, not
// inferred from the header, which declares no struct for it.
func (c *SCTPConn) SetPrSupported(on bool) error {
	var v uint32
	if on {
		v = 1
	}
	return c.setAssocValue(SCTP_PR_SUPPORTED, v)
}

// PrSupported reports whether partial reliability is available on this
// association.
//
// It reports the negotiated outcome, not what SetPrSupported requested. With
// net.sctp.prsctp_enable at its default of 1 that outcome is true regardless of
// the socket option, so a true result here does not imply anyone asked for it.
// Compare ReconfigSupported, whose sysctl defaults to 0 and which therefore does
// track the option.
func (c *SCTPConn) PrSupported() (bool, error) {
	v, err := c.getAssocValue(SCTP_PR_SUPPORTED)
	return v != 0, err
}

// SetDefaultPrInfo sets the partial reliability policy applied to messages sent
// without their own (SCTP_DEFAULT_PRINFO, RFC 6458 §8.1.32).
//
// The meaning of Value depends on Policy; see the SCTPPrPolicy constants. A
// policy outside that set is rejected by the kernel with EINVAL.
//
// This is accepted on a socket where PrSupported reports false — the policy is
// recorded and simply never takes effect, because abandoning a message requires
// the FORWARD-TSN the extension negotiates. Enable SetPrSupported before
// connecting if the policy is meant to do anything.
func (c *SCTPConn) SetDefaultPrInfo(info *DefaultPrInfo) error {
	if info == nil {
		return syscall.EINVAL
	}
	optlen := uint32(unsafe.Sizeof(*info))
	_, _, err := c.setsockopt(SCTP_DEFAULT_PRINFO,
		uintptr(unsafe.Pointer(info)), uintptr(optlen))
	return err
}

// GetDefaultPrInfo reports the current default partial reliability policy.
func (c *SCTPConn) GetDefaultPrInfo() (*DefaultPrInfo, error) {
	info := &DefaultPrInfo{}
	optlen := uint32(unsafe.Sizeof(*info))
	_, _, err := c.getsockopt(SCTP_DEFAULT_PRINFO,
		uintptr(unsafe.Pointer(info)), &optlen)
	if err != nil {
		return nil, err
	}
	return info, nil
}

// GetPrStreamStatus reports how many messages were abandoned on one stream under
// the given partial reliability policy (RFC 7496 §4.3).
//
// It needs an established association; on a socket without one the kernel
// returns EINVAL.
func (c *SCTPConn) GetPrStreamStatus(sid uint16, policy uint16) (*PrStatus, error) {
	st := &PrStatus{SID: sid, Policy: policy}
	optlen := uint32(unsafe.Sizeof(*st))
	_, _, err := c.getsockopt(SCTP_PR_STREAM_STATUS,
		uintptr(unsafe.Pointer(st)), &optlen)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// GetPrAssocStatus reports how many messages were abandoned across the whole
// association under the given partial reliability policy (RFC 7496 §4.4).
//
// This is the association-wide total; GetPrStreamStatus reports one stream. Both
// need an established association.
//
// The returned PrStatus.SID is not meaningful here — the option ignores it.
func (c *SCTPConn) GetPrAssocStatus(policy uint16) (*PrStatus, error) {
	st := &PrStatus{Policy: policy}
	optlen := uint32(unsafe.Sizeof(*st))
	_, _, err := c.getsockopt(SCTP_PR_ASSOC_STATUS,
		uintptr(unsafe.Pointer(st)), &optlen)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// SetReconfigSupported enables or disables the stream reconfiguration extension
// of RFC 6525 for this socket.
//
// The option is Linux's own. RFC 6525 defines the extension and its four socket
// options in §6.3, but nothing that negotiates whether the extension is offered
// at all — SCTP_RECONFIG_SUPPORTED appears nowhere in it.
//
// Set it before connecting. It is carried in a struct sctp_assoc_value rather
// than a plain int, as SetPrSupported is.
func (c *SCTPConn) SetReconfigSupported(on bool) error {
	var v uint32
	if on {
		v = 1
	}
	return c.setAssocValue(SCTP_RECONFIG_SUPPORTED, v)
}

// ReconfigSupported reports whether stream reconfiguration is available.
//
// The value is negotiated, and the getter changes meaning once an association
// exists — which is easy to misread as the setter having failed:
//
//   - Before connecting it echoes what SetReconfigSupported wrote.
//   - After connecting it reports whether *both* ends enabled it. Setting it on
//     only one end reads back false there, and a set issued after connect never
//     changes the answer even though it returns success.
//
// That was measured across all three combinations rather than inferred. So a
// false result on a live association means the peer did not offer the extension,
// not that the local call was rejected.
func (c *SCTPConn) ReconfigSupported() (bool, error) {
	v, err := c.getAssocValue(SCTP_RECONFIG_SUPPORTED)
	return v != 0, err
}

// SetEnableStreamReset selects which stream reconfiguration requests this
// endpoint permits (RFC 6525 §6.3). mask is a combination of the
// SCTPEnableReset constants; zero permits none.
//
// This governs what the endpoint will accept and initiate, and is independent of
// SetReconfigSupported, which decides whether the extension is negotiated at
// all. Both are needed for reconfiguration to work.
func (c *SCTPConn) SetEnableStreamReset(mask uint32) error {
	if mask&^uint32(SCTPEnableResetStreamReq|SCTPEnableResetAssocReq|
		SCTPEnableChangeAssocReq) != 0 {
		return fmt.Errorf("sctp: stream reset mask %#x has unknown bits", mask)
	}
	return c.setAssocValue(SCTP_ENABLE_STREAM_RESET, mask)
}

// EnableStreamReset reports which stream reconfiguration requests are permitted.
func (c *SCTPConn) EnableStreamReset() (uint32, error) {
	return c.getAssocValue(SCTP_ENABLE_STREAM_RESET)
}

// AddStreams asks the peer to widen the association, adding inStreams inbound
// and outStreams outbound streams (RFC 6525 §6.3.4).
//
// This needs the reconfiguration extension negotiated — SetReconfigSupported on
// both ends before connecting — and SCTPEnableChangeAssocReq present in the mask
// SetEnableStreamReset installed. Without both the kernel refuses with
// ENOPROTOOPT, which is easy to misread as the option not existing.
//
// The request goes to the peer, so success here means it was sent and accepted,
// not that the streams are usable yet. GetStatus reports the counts once the
// peer has answered.
func (c *SCTPConn) AddStreams(inStreams, outStreams uint16) error {
	as := AddStreamsReq{InStreams: inStreams, OutStreams: outStreams}
	optlen := uint32(unsafe.Sizeof(as))
	_, _, err := c.setsockopt(SCTP_ADD_STREAMS,
		uintptr(unsafe.Pointer(&as)), uintptr(optlen))
	return err
}

// ResetStreams restarts the sequence numbering of the named streams, or of every
// stream when streams is empty (RFC 6525 §6.3.2).
//
// direction is a combination of SCTPStreamResetIncoming and
// SCTPStreamResetOutgoing; at least one is required, since the kernel rejects a
// request with neither.
//
// Like AddStreams this needs the reconfiguration extension negotiated —
// SetReconfigSupported on both ends before connecting — plus
// SCTPEnableResetStreamReq in the SetEnableStreamReset mask. Without them the
// kernel answers ENOPROTOOPT, which reads like the option not existing.
//
// The option length has to cover the stream list, not just the fixed header:
// naming one stream while passing the bare struct length is rejected with
// EINVAL. That is handled here, and is the reason this takes a slice rather than
// exposing the raw struct.
func (c *SCTPConn) ResetStreams(direction uint16, streams ...uint16) error {
	if direction&^uint16(SCTPStreamResetIncoming|SCTPStreamResetOutgoing) != 0 {
		return fmt.Errorf("sctp: stream reset direction %#x has unknown bits",
			direction)
	}
	if direction == 0 {
		return fmt.Errorf("sctp: stream reset needs at least one of " +
			"SCTPStreamResetIncoming or SCTPStreamResetOutgoing")
	}
	if len(streams) > int(^uint16(0)) {
		return fmt.Errorf("sctp: %d streams exceeds the %d the request can "+
			"name", len(streams), int(^uint16(0)))
	}

	buf := buildResetStreams(direction, streams)
	_, _, err := c.setsockopt(SCTP_RESET_STREAMS,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return err
}

// buildResetStreams lays out struct sctp_reset_streams: an association id, the
// direction flags, the stream count, then the stream ids.
//
// Built as bytes rather than from a Go struct because the C struct ends in a
// flexible array, and the list has to be contiguous with the header in one
// allocation. Split out from ResetStreams so the offsets can be asserted
// directly — flags and count are adjacent uint16s, so a transposition is
// invisible to any length check.
func buildResetStreams(direction uint16, streams []uint16) []byte {
	const hdr = 8
	buf := make([]byte, hdr+2*len(streams))
	// AssocID at [0:4] stays zero: one-to-one sockets ignore it.
	nativeEndian.PutUint16(buf[4:6], direction)
	nativeEndian.PutUint16(buf[6:8], uint16(len(streams)))
	for i, sid := range streams {
		nativeEndian.PutUint16(buf[hdr+2*i:], sid)
	}
	return buf
}

// ResetAssoc restarts the association's sequence numbering as a whole
// (RFC 6525 §6.3.3).
//
// This needs the reconfiguration extension negotiated and
// SCTPEnableResetAssocReq in the SetEnableStreamReset mask.
func (c *SCTPConn) ResetAssoc() error {
	var id SCTPAssocID
	_, _, err := c.setsockopt(SCTP_RESET_ASSOC,
		uintptr(unsafe.Pointer(&id)), unsafe.Sizeof(id))
	return err
}

// SetAuthChunk adds one chunk type to the CHUNKS list this endpoint will send in
// future INIT and INIT ACK chunks (RFC 6458 §8.3.2 and RFC 4895 §6.1).
//
// The option is additive and set-only: each call adds a type, and there is no
// way to remove one or to read the set back other than LocalAuthChunks.
//
// RFC 6458 §8.3.2 specifies that changes affect only future associations. A
// call on a connected Linux socket therefore succeeds but does not retrofit the
// current association; that is the specified timing, not a missing kernel
// validation. RFC 4895 §6.1 separately defines how the CHUNKS list is advertised
// and how shared keys are established.
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) SetAuthChunk(chunkType uint8) error {
	// struct sctp_authchunk is a single __u8, so the option is one byte and
	// setsockoptInt's 32-bit value would be rejected.
	_, _, err := c.setsockopt(SCTP_AUTH_CHUNK,
		uintptr(unsafe.Pointer(&chunkType)), unsafe.Sizeof(chunkType))
	return err
}

// SetAuthKey installs a shared key for authenticating chunks (RFC 6458 §8.3.3).
//
// keyNumber names the key for SetAuthActiveKey, DeleteAuthKey and
// DeactivateAuthKey. Key 0 is the null key every association starts with;
// overwriting it is permitted.
//
// The key may not be empty: the kernel rejects a zero-length key with EINVAL
// rather than treating it as a deletion. The upper bound is what the length
// field can express — sca_keylength is a __u16, and sctp_setsockopt_auth_key
// clamps optlen to USHRT_MAX + sizeof(*authkey) for that reason — which is the
// same 65535 the guard below applies. An earlier version of this comment
// claimed 8192; no such bound exists. The kernel also validates the length
// against the option size, so a mismatch cannot make it read past the buffer.
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) SetAuthKey(keyNumber uint16, key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("sctp: auth key %d is empty; the kernel rejects a "+
			"zero-length key rather than treating it as a deletion, so use "+
			"DeleteAuthKey instead", keyNumber)
	}
	if len(key) > int(^uint16(0)) {
		return fmt.Errorf("sctp: auth key of %d bytes exceeds the %d the "+
			"length field can express", len(key), int(^uint16(0)))
	}

	buf := buildAuthKey(keyNumber, key)
	_, _, err := c.setsockopt(SCTP_AUTH_KEY,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return err
}

// buildAuthKey lays out struct sctp_authkey: an association id, the key number,
// the key length, then the key bytes.
//
// Split out from SetAuthKey for the same reason as buildResetStreams — the two
// uint16s are adjacent, so swapping them produces a buffer the kernel may still
// accept while installing a key of the wrong length under the wrong number.
func buildAuthKey(keyNumber uint16, key []byte) []byte {
	const hdr = 8
	buf := make([]byte, hdr+len(key))
	nativeEndian.PutUint16(buf[4:6], keyNumber)
	nativeEndian.PutUint16(buf[6:8], uint16(len(key)))
	copy(buf[hdr:], key)
	return buf
}

// DeleteAuthKey removes a shared key (RFC 6458 §8.3.5).
//
// The active key cannot be deleted — the kernel reports EINVAL — so select
// another with SetAuthActiveKey first, or deactivate this one. A key still needed
// to verify packets in flight should be deactivated rather than deleted.
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) DeleteAuthKey(keyNumber uint16) error {
	return c.authKeyOp(SCTP_AUTH_DELETE_KEY, keyNumber)
}

// DeactivateAuthKey stops a shared key being used for new packets while leaving
// it able to verify packets already in flight (RFC 6458 §8.3.4).
//
// This is the safe half of key rollover: deactivate, let the peer's in-flight
// packets drain, then delete.
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) DeactivateAuthKey(keyNumber uint16) error {
	return c.authKeyOp(SCTP_AUTH_DEACTIVATE_KEY, keyNumber)
}

// authKeyOp issues one of the set-only options taking a struct sctp_authkeyid.
func (c *SCTPConn) authKeyOp(optname uintptr, keyNumber uint16) error {
	id := AuthKeyID{KeyNumber: keyNumber}
	_, _, err := c.setsockopt(optname,
		uintptr(unsafe.Pointer(&id)), unsafe.Sizeof(id))
	return err
}

// SetHmacIdent sets the HMAC algorithms this endpoint offers, most preferred
// first (RFC 6458 §8.1.17).
//
// The kernel validates the identifiers and reports EOPNOTSUPP for one it does not
// implement — identifier 2 is unassigned in the IANA registry and is refused,
// which was measured. Use the SCTPAuthHmacID constants.
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) SetHmacIdent(idents ...uint16) error {
	if len(idents) == 0 {
		return fmt.Errorf("sctp: SetHmacIdent needs at least one algorithm")
	}

	buf := buildHmacAlgo(idents)
	_, _, err := c.setsockopt(SCTP_HMAC_IDENT,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return err
}

// buildHmacAlgo lays out struct sctp_hmacalgo: a __u32 count followed by that
// many __u16 identifiers.
//
// Split out from SetHmacIdent so the byte layout can be asserted without a
// kernel. That matters because the count is 32 bits: writing it as a uint16
// leaves the correct bytes on a little-endian host and the wrong ones on a
// big-endian one, so no test on amd64 can catch the mistake through behaviour.
func buildHmacAlgo(idents []uint16) []byte {
	const hdr = 4
	buf := make([]byte, hdr+2*len(idents))
	nativeEndian.PutUint32(buf[:4], uint32(len(idents)))
	for i, id := range idents {
		nativeEndian.PutUint16(buf[hdr+2*i:], id)
	}
	return buf
}

// SetPeerAddrThlds sets the per-path retransmission thresholds that drive
// failure detection (RFC 7829 §7.2).
//
// A zeroed Address applies the thresholds to every path of the association,
// which is the form to use on the single-homed sockets this package usually
// creates.
func (c *SCTPConn) SetPeerAddrThlds(th *PeerAddrThlds) error {
	if th == nil {
		return syscall.EINVAL
	}
	b := th.marshal()
	_, _, err := c.setsockopt(SCTP_PEER_ADDR_THLDS,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if shouldRetryKernelPeerThresholdLayout(err) {
		b = th.marshalKernelLayout()
		_, _, err = c.setsockopt(SCTP_PEER_ADDR_THLDS,
			uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	}
	return err
}

// GetPeerAddrThlds reports the current per-path retransmission thresholds.
func (c *SCTPConn) GetPeerAddrThlds() (*PeerAddrThlds, error) {
	th := &PeerAddrThlds{}
	b := th.marshal()
	optlen := uint32(len(b))
	_, _, err := c.getsockopt(SCTP_PEER_ADDR_THLDS,
		uintptr(unsafe.Pointer(&b[0])), &optlen)
	if err != nil {
		if shouldRetryKernelPeerThresholdLayout(err) {
			b = th.marshalKernelLayout()
			optlen = uint32(len(b))
			_, _, err = c.getsockopt(SCTP_PEER_ADDR_THLDS,
				uintptr(unsafe.Pointer(&b[0])), &optlen)
			if err == nil {
				th.unmarshalKernelLayout(b)
				return th, nil
			}
		}
		return nil, err
	}
	th.unmarshal(b)
	return th, nil
}

// SetPeerAddrThldsV2 sets the per-path thresholds including the primary path
// switchover threshold that SetPeerAddrThlds cannot reach.
//
// This is a Linux extension of the RFC 7829 option in the sense that the option
// number is Linux's back-compatibility device; the third threshold itself is
// RFC 7829 §7.2's spt_pathcpthld. See PeerAddrThldsV2.PathCpThld for what it
// does — it moves the primary path, and does not govern probing.
func (c *SCTPConn) SetPeerAddrThldsV2(th *PeerAddrThldsV2) error {
	if th == nil {
		return syscall.EINVAL
	}
	b := th.marshal()
	_, _, err := c.setsockopt(SCTP_PEER_ADDR_THLDS_V2,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	if shouldRetryKernelPeerThresholdLayout(err) {
		b = th.marshalKernelLayout()
		_, _, err = c.setsockopt(SCTP_PEER_ADDR_THLDS_V2,
			uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	}
	return err
}

// GetPeerAddrThldsV2 reports the per-path thresholds including the switchover
// threshold.
func (c *SCTPConn) GetPeerAddrThldsV2() (*PeerAddrThldsV2, error) {
	th := &PeerAddrThldsV2{}
	b := th.marshal()
	optlen := uint32(len(b))
	_, _, err := c.getsockopt(SCTP_PEER_ADDR_THLDS_V2,
		uintptr(unsafe.Pointer(&b[0])), &optlen)
	if err != nil {
		if shouldRetryKernelPeerThresholdLayout(err) {
			b = th.marshalKernelLayout()
			optlen = uint32(len(b))
			_, _, err = c.getsockopt(SCTP_PEER_ADDR_THLDS_V2,
				uintptr(unsafe.Pointer(&b[0])), &optlen)
			if err == nil {
				th.unmarshalKernelLayout(b)
				return th, nil
			}
		}
		return nil, err
	}
	th.unmarshal(b)
	return th, nil
}

func shouldRetryKernelPeerThresholdLayout(err error) bool {
	return ssAlign < kernelSSAlign && errors.Is(err, syscall.EINVAL)
}

// GetAssocStats reads the per-association counters (SCTP_GET_ASSOC_STATS).
//
// This is a Linux extension with no RFC 6458 equivalent. It needs an established
// association; on a socket without one the kernel returns EINVAL.
//
// Reading resets AssocStats.MaxRto, so the value is the maximum observed since
// the previous call rather than since the association began.
func (c *SCTPConn) GetAssocStats() (*AssocStats, error) {
	b := make([]byte, assocStatsSize)
	nativeEndian.PutUint32(b[0:], 0) // the association id is the lookup key
	optlen := uint32(len(b))
	_, _, err := c.getsockopt(SCTP_GET_ASSOC_STATS,
		uintptr(unsafe.Pointer(&b[0])), &optlen)
	if err != nil {
		return nil, err
	}
	st := &AssocStats{}
	st.unmarshal(b)
	return st, nil
}

// assocStatsSize is sizeof(struct sctp_assoc_stats), which is 256 on every
// architecture, and assocStatsCounters is where sas_maxrto begins — also fixed
// at 136 everywhere. Only the address between them moves; see
// AssocStats.ObsRtoIPAddr.
const (
	assocStatsSize     = 256
	assocStatsCounters = 136
)

func (s *AssocStats) unmarshal(b []byte) {
	s.AssocID = SCTPAssocID(nativeEndian.Uint32(b[0:]))
	copy(s.ObsRtoIPAddr[:], b[ssAddrOffset:ssAddrOffset+128])
	u := func(i int) uint64 { return nativeEndian.Uint64(b[assocStatsCounters+8*i:]) }
	s.MaxRto = u(0)
	s.ISacks, s.OSacks = u(1), u(2)
	s.OPackets, s.IPackets = u(3), u(4)
	s.RtxChunks = u(5)
	s.OutOfSeqTsns = u(6)
	s.IDupChunks = u(7)
	s.GapCnt = u(8)
	s.OUodChunks, s.IUodChunks = u(9), u(10)
	s.OOdChunks, s.IOdChunks = u(11), u(12)
	s.OCtrlChunks, s.ICtrlChunks = u(13), u(14)
}

// SetAuthActiveKey selects which shared key signs outbound AUTH chunks
// (RFC 6458 §8.1.18).
//
// The whole SCTP_AUTH_* family needs AUTH negotiated on the socket, and on a
// stock kernel it is not. With it off every one of these calls fails with
// EACCES — not EOPNOTSUPP, which is what makes it look like a permissions
// problem rather than a disabled feature. That was measured.
//
// There are two ways to turn it on, and the per-socket one is usually what a
// caller wants: SetAuthSupported before binding, which needs no privilege. The
// other is the net.sctp.auth_enable sysctl, which is system-wide and root-only;
// this comment used to name it as the only option, which is why the rest of
// this family still points here.
func (c *SCTPConn) SetAuthActiveKey(keyNumber uint16) error {
	id := AuthKeyID{KeyNumber: keyNumber}
	optlen := uint32(unsafe.Sizeof(id))
	_, _, err := c.setsockopt(SCTP_AUTH_ACTIVE_KEY,
		uintptr(unsafe.Pointer(&id)), uintptr(optlen))
	return err
}

// AuthActiveKey reports which shared key currently signs outbound AUTH chunks.
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) AuthActiveKey() (uint16, error) {
	id := AuthKeyID{}
	optlen := uint32(unsafe.Sizeof(id))
	_, _, err := c.getsockopt(SCTP_AUTH_ACTIVE_KEY,
		uintptr(unsafe.Pointer(&id)), &optlen)
	if err != nil {
		return 0, err
	}
	return id.KeyNumber, nil
}

// HmacIdent reports the HMAC algorithms this endpoint offers, in preference
// order (RFC 6458 §8.1.17).
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) HmacIdent() ([]uint16, error) {
	// struct sctp_hmacalgo is a __u32 count followed by a flexible array of
	// __u16. The kernel writes as many identifiers as fit and reduces the
	// option length to what it used, so the buffer only has to be large
	// enough; maxHmacIdents is well past the two algorithms RFC 4895 defines.
	const maxHmacIdents = 32
	var buf [4 + 2*maxHmacIdents]byte
	optlen := uint32(len(buf))
	_, _, err := c.getsockopt(SCTP_HMAC_IDENT,
		uintptr(unsafe.Pointer(&buf[0])), &optlen)
	if err != nil {
		return nil, err
	}
	return parseHmacIdents(buf[:], int(optlen))
}

// parseHmacIdents decodes a struct sctp_hmacalgo: a __u32 count followed by that
// many __u16 identifiers.
//
// Split out from HmacIdent so the bounds handling can be tested without a
// kernel, since a real one will not produce the count/length disagreement this
// has to survive.
func parseHmacIdents(buf []byte, optlen int) ([]uint16, error) {
	if optlen < 4 || optlen > len(buf) {
		return nil, fmt.Errorf("sctp: SCTP_HMAC_IDENT returned %d bytes, "+
			"which is not a struct sctp_hmacalgo in a %d byte buffer",
			optlen, len(buf))
	}
	n := nativeEndian.Uint32(buf[:4])
	if (optlen-4)%2 != 0 {
		return nil, fmt.Errorf("sctp: SCTP_HMAC_IDENT returned an odd %d-byte payload",
			optlen-4)
	}
	if available := uint32((optlen - 4) / 2); n != available {
		return nil, fmt.Errorf("sctp: SCTP_HMAC_IDENT reports %d identifiers in %d bytes",
			n, optlen)
	}
	idents := make([]uint16, n)
	for i := range idents {
		idents[i] = nativeEndian.Uint16(buf[4+2*i : 6+2*i])
	}
	return idents, nil
}

// LocalAuthChunks reports the chunk types this endpoint requires the peer to
// authenticate (RFC 6458 §8.2.4).
//
// See SetAuthActiveKey about net.sctp.auth_enable.
func (c *SCTPConn) LocalAuthChunks() ([]uint8, error) {
	return c.authChunks(SCTP_LOCAL_AUTH_CHUNKS)
}

// PeerAuthChunks reports the chunk types the peer requires this endpoint to
// authenticate (RFC 6458 §8.2.3).
//
// It needs an established association: without one the kernel returns EINVAL,
// since there is no peer to have told us anything. See SetAuthActiveKey about
// net.sctp.auth_enable.
func (c *SCTPConn) PeerAuthChunks() ([]uint8, error) {
	return c.authChunks(SCTP_PEER_AUTH_CHUNKS)
}

// authChunks reads one of the two SCTP_*_AUTH_CHUNKS options. RFC 6458
// §§8.2.3-8.2.4 and Linux struct sctp_authchunks place an association id and a
// uint32 chunk count before the flexible array; the kernel reduces the option
// length to the bytes it wrote.
func (c *SCTPConn) authChunks(optname uintptr) ([]uint8, error) {
	const maxAuthChunks = 256
	var buf [8 + maxAuthChunks]byte
	optlen := uint32(len(buf))
	_, _, err := c.getsockopt(optname,
		uintptr(unsafe.Pointer(&buf[0])), &optlen)
	if err != nil {
		return nil, err
	}
	return parseAuthChunks(buf[:], int(optlen))
}

// parseAuthChunks decodes struct sctp_authchunks. Neither its association id nor
// its chunk count is part of the returned list. The count and option length must
// agree exactly: both are kernel-provided routing/security metadata, and
// accepting whichever is smaller would silently normalise a malformed result.
func parseAuthChunks(buf []byte, optlen int) ([]uint8, error) {
	const headerSize = 8
	if optlen < headerSize || optlen > len(buf) {
		return nil, fmt.Errorf("sctp: auth chunks option returned %d bytes, "+
			"which is not a struct sctp_authchunks in a %d byte buffer",
			optlen, len(buf))
	}
	count := nativeEndian.Uint32(buf[4:8])
	if count != uint32(optlen-headerSize) {
		return nil, fmt.Errorf("sctp: auth chunks option reports %d chunks in %d bytes",
			count, optlen)
	}
	chunks := make([]uint8, int(count))
	copy(chunks, buf[headerSize:optlen])
	return chunks, nil
}

// GetReusePort reports whether port reuse is enabled.
func (c *SCTPConn) GetReusePort() (bool, error) {
	v, err := c.getsockoptInt32(SCTP_REUSE_PORT)
	return v != 0, err
}

// PeerAddrParams represents Linux's struct sctp_paddrparams, the per-path
// timers. It is a superset of RFC 6458 §8.1.12: Linux inserts spp_sackdelay and
// adds the SPP_SACKDELAY_ENABLE and SPP_SACKDELAY_DISABLE flag bits.
//
// Flags decides which of the other fields are read: each value has an
// ENABLE/DISABLE pair in the SPP_ constants, and a value with neither bit set is
// ignored. So this cannot be used to clear a setting by passing zero, and a
// caller who wants to change one thing should read the current parameters,
// modify them, and write them back.
//
// HBInterval is the one that usually matters. On an idle association nothing
// but the heartbeat detects that a path has gone silent, and its default of 30
// seconds was unreachable from this package before.
//
// Address selects the path. Leaving it zeroed addresses the association as a
// whole, which is what a one-to-one socket normally wants; to name one path,
// copy a raw sockaddr in — GetPeerAddrs returns them decoded, and
// SCTPAddr.ToRawSockAddrBuf encodes one back.
//
// This is the one struct in the package that cannot simply mirror the kernel's
// field by field. sctp_paddrparams is declared packed and aligned(4), and the
// 128-byte address leaves spp_pathmtu at offset 138 — a uint32 on a two-byte
// boundary, which Go will not lay out at any cost. So the exported form is an
// ordinary Go struct and the packed form is built on the way in and out.
// TestPeerAddrParamsLayoutMatchesKernel pins every offset.
type PeerAddrParams struct {
	AssocID SCTPAssocID
	// Address selects the path. Leaving it zeroed addresses the association as
	// a whole, which is what a one-to-one socket normally wants; to name one
	// path, copy in the bytes SCTPAddr.ToRawSockAddrBuf produces.
	Address [128]byte
	// HBInterval is the heartbeat period in milliseconds. Needs SPP_HB_ENABLE.
	HBInterval uint32
	// PathMaxRxt is the retransmission count after which this path is
	// considered inactive.
	PathMaxRxt uint16
	// PathMTU overrides path MTU discovery. Needs SPP_PMTUD_DISABLE.
	PathMTU uint32
	// SackDelay is the delayed acknowledgement timer in milliseconds. Needs
	// SPP_SACKDELAY_ENABLE.
	SackDelay uint32
	Flags     uint32
	// IPv6FlowLabel needs SPP_IPV6_FLOWLABEL.
	IPv6FlowLabel uint32
	// DSCP needs SPP_DSCP.
	DSCP uint8
}

// paddrparamsSize is sizeof(struct sctp_paddrparams): 155 bytes of fields
// rounded up to the struct's declared 4-byte alignment.
const paddrparamsSize = 156

// Field offsets within the packed struct, named so the marshalling below reads
// as the layout rather than as arithmetic.
const (
	pppAssocID    = 0
	pppAddress    = 4
	pppHBInterval = 132
	pppPathMaxRxt = 136
	pppPathMTU    = 138
	pppSackDelay  = 142
	pppFlags      = 146
	pppFlowLabel  = 150
	pppDSCP       = 154
)

func (p *PeerAddrParams) marshal() []byte {
	b := make([]byte, paddrparamsSize)
	nativeEndian.PutUint32(b[pppAssocID:], uint32(p.AssocID))
	copy(b[pppAddress:pppAddress+128], p.Address[:])
	nativeEndian.PutUint32(b[pppHBInterval:], p.HBInterval)
	nativeEndian.PutUint16(b[pppPathMaxRxt:], p.PathMaxRxt)
	nativeEndian.PutUint32(b[pppPathMTU:], p.PathMTU)
	nativeEndian.PutUint32(b[pppSackDelay:], p.SackDelay)
	nativeEndian.PutUint32(b[pppFlags:], p.Flags)
	nativeEndian.PutUint32(b[pppFlowLabel:], p.IPv6FlowLabel)
	b[pppDSCP] = p.DSCP
	return b
}

func (p *PeerAddrParams) unmarshal(b []byte) {
	p.AssocID = SCTPAssocID(nativeEndian.Uint32(b[pppAssocID:]))
	copy(p.Address[:], b[pppAddress:pppAddress+128])
	p.HBInterval = nativeEndian.Uint32(b[pppHBInterval:])
	p.PathMaxRxt = nativeEndian.Uint16(b[pppPathMaxRxt:])
	p.PathMTU = nativeEndian.Uint32(b[pppPathMTU:])
	p.SackDelay = nativeEndian.Uint32(b[pppSackDelay:])
	p.Flags = nativeEndian.Uint32(b[pppFlags:])
	p.IPv6FlowLabel = nativeEndian.Uint32(b[pppFlowLabel:])
	p.DSCP = b[pppDSCP]
}

// SetPeerAddrParams writes the per-path parameters (SCTP_PEER_ADDR_PARAMS).
//
// Set the matching SPP_ flag for each field that should take effect; see
// PeerAddrParams.
func (c *SCTPConn) SetPeerAddrParams(p *PeerAddrParams) error {
	if p == nil {
		return syscall.EINVAL
	}
	b := p.marshal()
	_, _, err := c.setsockopt(SCTP_PEER_ADDR_PARAMS,
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
	return err
}

// GetPeerAddrParams reads the per-path parameters (SCTP_PEER_ADDR_PARAMS).
//
// Zero the Address of the value passed in to ask about the association rather
// than one path.
func (c *SCTPConn) GetPeerAddrParams(p *PeerAddrParams) error {
	if p == nil {
		return syscall.EINVAL
	}
	// Only the association id and the address go in — they are the lookup key.
	// Marshalling the whole value would send the caller's own HBInterval,
	// Flags, DSCP and flow label down as well, and any field the kernel does
	// not overwrite would come back looking like a reading when it is just the
	// caller's input echoed.
	req := PeerAddrParams{AssocID: p.AssocID, Address: p.Address}
	b := req.marshal()
	optlen := uint32(len(b))
	_, _, err := c.getsockopt(SCTP_PEER_ADDR_PARAMS,
		uintptr(unsafe.Pointer(&b[0])), &optlen)
	if err != nil {
		return err
	}
	p.unmarshal(b)
	return nil
}

// GetPeerAddrInfo reads one peer address's state (SCTP_GET_PEER_ADDR_INFO,
// RFC 6458 §8.2.2).
//
// This is the only way to see a secondary path. GetStatus reports the primary
// only, so on the multi-homed associations this package exists to support,
// nothing else says whether the other paths are active, what their round-trip
// time is, or what congestion window they have.
//
// Set Address on the value passed in to name the path; the rest is filled in.
//
// It returns EACCES for a path that is in the PF state when the association's
// PF exposure level is SCTPPFStateDisabled — the kernel refuses the question
// rather than answering it. That is the one combination where this call starts
// failing precisely when a path degrades; see SCTPPFStateDisabled.
func (c *SCTPConn) GetPeerAddrInfo(info *PeerAddrinfo) error {
	if info == nil {
		return syscall.EINVAL
	}
	optlen := uint32(unsafe.Sizeof(*info))
	_, _, err := c.getsockopt(SCTP_GET_PEER_ADDR_INFO,
		uintptr(unsafe.Pointer(info)), &optlen)
	return err
}

// SetAdaptationLayer announces an adaptation layer indication to the peer
// (SCTP_ADAPTATION_LAYER, RFC 6458 §8.1.10).
//
// The value is opaque to SCTP and is carried in the INIT, so it must be set
// before the association is established to reach the peer. The other direction
// has always been available: the peer's indication arrives as an
// AdaptationIndication notification.
func (c *SCTPConn) SetAdaptationLayer(ind uint32) error {
	v := struct{ AdaptationInd uint32 }{ind}
	_, _, err := c.setsockopt(SCTP_ADAPTATION_LAYER,
		uintptr(unsafe.Pointer(&v)), unsafe.Sizeof(v))
	return err
}

// GetAdaptationLayer reports the adaptation layer indication this endpoint
// announces.
func (c *SCTPConn) GetAdaptationLayer() (uint32, error) {
	v := struct{ AdaptationInd uint32 }{}
	optlen := uint32(unsafe.Sizeof(v))
	_, _, err := c.getsockopt(SCTP_ADAPTATION_LAYER,
		uintptr(unsafe.Pointer(&v)), &optlen)
	return v.AdaptationInd, err
}

// SetDisableFragments controls whether a message larger than the path MTU is
// fragmented (SCTP_DISABLE_FRAGMENTS, RFC 6458 §8.1.11).
//
// With fragmentation off, a message that does not fit is refused with
// EMSGSIZE rather than split. That is what a caller wants when the peer is a
// device that cannot reassemble, and it turns a silent behaviour change into an
// error they can see.
func (c *SCTPConn) SetDisableFragments(on bool) error {
	return c.setSockoptBool(SCTP_DISABLE_FRAGMENTS, on)
}

// DisableFragments reports whether message fragmentation is disabled.
func (c *SCTPConn) DisableFragments() (bool, error) {
	return c.getSockoptBool(SCTP_DISABLE_FRAGMENTS)
}

// SetMappedV4Addr controls whether IPv4 addresses are reported to the caller in
// IPv4-mapped IPv6 form on an AF_INET6 socket (SCTP_I_WANT_MAPPED_V4_ADDR,
// RFC 6458 §8.1.15).
func (c *SCTPConn) SetMappedV4Addr(on bool) error {
	return c.setSockoptBool(SCTP_I_WANT_MAPPED_V4_ADDR, on)
}

// MappedV4Addr reports whether IPv4-mapped addresses are in use.
func (c *SCTPConn) MappedV4Addr() (bool, error) {
	return c.getSockoptBool(SCTP_I_WANT_MAPPED_V4_ADDR)
}

// SetAsconfSupported negotiates dynamic address reconfiguration, RFC 5061, for
// this socket.
//
// This is what makes SetAutoAsconf mean anything. net.sctp.addip_enable
// defaults to 0, and with it off the endpoint never negotiates ASCONF, so
// SetAutoAsconf succeeds and then adding a local address mid-association puts
// nothing on the wire — measured as zero ASCONF chunks, against two ASCONF and
// two ASCONF-ACK once this is on.
//
// It must be set before the socket is bound: the capability goes in the INIT.
// The kernel also requires AUTH for ASCONF, so SetAuthSupported belongs with it.
func (c *SCTPConn) SetAsconfSupported(on bool) error {
	return c.setAssocValueBool(SCTP_ASCONF_SUPPORTED, on)
}

// AsconfSupported reports the negotiated outcome for ASCONF.
func (c *SCTPConn) AsconfSupported() (bool, error) {
	v, err := c.getAssocValue(SCTP_ASCONF_SUPPORTED)
	return v != 0, err
}

// SetAuthSupported negotiates AUTH, RFC 4895, for this socket.
//
// The AUTH accessors on this type are documented as needing
// net.sctp.auth_enable, which is a system-wide sysctl only root can set. That
// is the older half of the story: this option turns AUTH on for one socket with
// the sysctl still at its default of 0, which was measured rather than assumed.
//
// Set it before binding — the capability is announced in the INIT.
func (c *SCTPConn) SetAuthSupported(on bool) error {
	return c.setAssocValueBool(SCTP_AUTH_SUPPORTED, on)
}

// AuthSupported reports the negotiated outcome for AUTH.
func (c *SCTPConn) AuthSupported() (bool, error) {
	v, err := c.getAssocValue(SCTP_AUTH_SUPPORTED)
	return v != 0, err
}

// SetEcnSupported toggles Linux's experimental SCTP ECN capability.
//
// RFC 9260 §1.7 removed the former SCTP ECN specification. This Linux UAPI
// option is therefore not a claim of compliance with a current SCTP ECN RFC and
// should be used only when both endpoints' kernel behavior is independently
// qualified.
func (c *SCTPConn) SetEcnSupported(on bool) error {
	return c.setAssocValueBool(SCTP_ECN_SUPPORTED, on)
}

// EcnSupported reports Linux's SCTP_ECN_SUPPORTED value; see SetEcnSupported.
func (c *SCTPConn) EcnSupported() (bool, error) {
	v, err := c.getAssocValue(SCTP_ECN_SUPPORTED)
	return v != 0, err
}

// SetInterleavingSupported negotiates user message interleaving, the I-DATA
// chunk of RFC 8260.
//
// Set it before binding, like the other capability negotiations here: the
// kernel stores it on the endpoint and reads it when the INIT is built, so on a
// connection returned by Dial or Accept this succeeds and changes nothing, and
// InterleavingSupported then reports false — which reads like a broken getter
// rather than a call that came too late. Use SocketConfig.Control to reach the
// descriptor beforehand.
//
// It is also refused with EPERM unless net.sctp.intl_enable is on and
// SetFragmentInterleave has been given a non-zero level, because interleaving
// without that would deliver fragments of different messages to a caller not
// expecting them.
func (c *SCTPConn) SetInterleavingSupported(on bool) error {
	return c.setAssocValueBool(SCTP_INTERLEAVING_SUPPORTED, on)
}

// InterleavingSupported reports the negotiated outcome for message
// interleaving.
func (c *SCTPConn) InterleavingSupported() (bool, error) {
	v, err := c.getAssocValue(SCTP_INTERLEAVING_SUPPORTED)
	return v != 0, err
}

// SetExposePotentiallyFailed controls whether the PF state of RFC 7829 is
// reported (SCTP_EXPOSE_POTENTIALLY_FAILED_STATE).
//
// PF is the early warning that a path has missed retransmissions but has not
// yet been declared unreachable, and it is the reason RFC 7829 exists: without
// it a caller learns about a dead path only when the retransmission budget runs
// out, which on the defaults is minutes. The kernel hides it unless asked,
// following net.sctp.pf_expose, so a caller who correctly subscribes to
// SCTP_PEER_ADDR_CHANGE and never sees SCTP_ADDR_POTENTIALLY_FAILED concludes
// the state does not exist.
//
// level is one of the SCTPPFState constants; SCTPPFStateEnabled is the one that
// turns reporting on. Unlike most of the options here it may be changed on a
// live association, and it can be changed back: sctp_setsockopt_pf_expose
// rejects only a value above SCTPPFStateEnabled, with EINVAL, and has no locked
// state. An earlier version of this comment said otherwise; that was not
// measured, and the kernel has no such path.
//
// Only SCTPPFStateEnabled delivers SCTP_ADDR_POTENTIALLY_FAILED: the kernel
// suppresses the notification at both other levels. The levels differ in what
// GetPeerAddrInfo does, not in what it reports —
//
//	SCTPPFStateUnset     GetPeerAddrInfo reports SCTP_PF, no notification
//	SCTPPFStateDisabled  GetPeerAddrInfo returns EACCES, no notification
//	SCTPPFStateEnabled   GetPeerAddrInfo reports SCTP_PF, notification delivered
func (c *SCTPConn) SetExposePotentiallyFailed(level uint32) error {
	return c.setAssocValue(SCTP_EXPOSE_POTENTIALLY_FAILED_STATE, level)
}

// ExposePotentiallyFailed reports the current PF exposure level.
func (c *SCTPConn) ExposePotentiallyFailed() (uint32, error) {
	return c.getAssocValue(SCTP_EXPOSE_POTENTIALLY_FAILED_STATE)
}

// SetStreamScheduler selects the order outbound streams are served in
// (SCTP_STREAM_SCHEDULER, RFC 8260 §4).
//
// sched is one of the SCTPSched constants. The default, SCTPSchedFCFS, ignores
// streams entirely and sends in the order messages were handed over, so a
// caller who separates traffic by stream and expects that to affect scheduling
// gets nothing until this is set.
func (c *SCTPConn) SetStreamScheduler(sched uint32) error {
	return c.setAssocValue(SCTP_STREAM_SCHEDULER, sched)
}

// StreamScheduler reports the scheduler in force.
func (c *SCTPConn) StreamScheduler() (uint32, error) {
	return c.getAssocValue(SCTP_STREAM_SCHEDULER)
}

// streamValue mirrors struct sctp_stream_value.
type streamValue struct {
	AssocID     SCTPAssocID
	StreamID    uint16
	StreamValue uint16
}

// SetStreamSchedulerValue sets a per-stream parameter for the scheduler in
// force (SCTP_STREAM_SCHEDULER_VALUE).
//
// Two schedulers use it. Under SCTPSchedPrio it is the stream's priority, lowest
// served first; under SCTPSchedWFQ it is the stream's weight, and a stream
// weighted n times another gets n times the capacity.
//
// Under SCTPSchedFCFS, SCTPSchedRR and SCTPSchedFC the call still succeeds and
// the value is discarded — measured: written as 7, it reads back as 0. So a
// caller who sets a priority without also selecting a scheduler that has one
// gets no error and no effect, which is why this says which schedulers those
// are rather than "the others ignore it".
func (c *SCTPConn) SetStreamSchedulerValue(streamID, value uint16) error {
	sv := streamValue{StreamID: streamID, StreamValue: value}
	_, _, err := c.setsockopt(SCTP_STREAM_SCHEDULER_VALUE,
		uintptr(unsafe.Pointer(&sv)), unsafe.Sizeof(sv))
	return err
}

// GetStreamSchedulerValue reads the scheduler parameter for one stream.
func (c *SCTPConn) GetStreamSchedulerValue(streamID uint16) (uint16, error) {
	sv := streamValue{StreamID: streamID}
	optlen := uint32(unsafe.Sizeof(sv))
	_, _, err := c.getsockopt(SCTP_STREAM_SCHEDULER_VALUE,
		uintptr(unsafe.Pointer(&sv)), &optlen)
	return sv.StreamValue, err
}

// GetInitMsg reads the association initialisation parameters (SCTP_INITMSG).
//
// SetInitMsg has always been available; this is the direction that was missing,
// which meant a caller could not check what the kernel actually recorded — the
// zero fields of an InitMsg mean "leave the default", so what was set and what
// is in force are different things.
func (c *SCTPConn) GetInitMsg() (*InitMsg, error) {
	options := &InitMsg{}
	optlen := uint32(unsafe.Sizeof(*options))
	_, _, err := c.getsockopt(SCTP_INITMSG,
		uintptr(unsafe.Pointer(options)), &optlen)
	if err != nil {
		return nil, err
	}
	return options, nil
}

func (c *SCTPConn) GetStatus() (*Status, error) { // Status
	sctpStatus := &Status{}
	optlen := uint32(unsafe.Sizeof(*sctpStatus))
	_, _, err := c.getsockopt(
		SCTP_STATUS,
		uintptr(unsafe.Pointer(sctpStatus)),
		&optlen,
	)
	return sctpStatus, err
}

func (c *SCTPConn) Getsockopt(optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	return c.getsockoptRaw(optname, optval, optlen)
}

func (c *SCTPConn) Setsockopt(optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	return c.setsockopt(optname, optval, optlen)
}

// resolveFromRawAddr decodes the packed sockaddr array the kernel returns for
// SCTP_GET_LOCAL_ADDRS, SCTP_GET_PEER_ADDRS and SCTP_PRIMARY_ADDR.
//
// Each entry is sized by its own family: 16 bytes for AF_INET, 28 for
// AF_INET6. The family is read per entry and the offset advanced by what that
// entry occupies, rather than reading the first entry's family and striding
// the whole array by it.
//
// On Linux the two are equivalent today. The kernel answers an AF_INET socket
// with all AF_INET entries and an AF_INET6 socket with all AF_INET6 entries,
// v4-mapping any IPv4 addresses bound to it, so the reply is uniform even for
// an association multi-homed across both families. That was measured against
// the kernel rather than assumed, including a socket explicitly bound to ::1
// and 127.0.0.1 via sctp_bindx.
//
// The per-entry walk is kept because nothing in the interface guarantees that.
// The reply is a packed array of variable-size sockaddrs, and a fixed stride
// is only correct while every entry happens to be the same size: if any kernel
// or any other platform returns a mixed reply, striding by the first family
// silently decodes every subsequent address from the wrong offset and returns
// it with no error. The cost of reading the family per entry is a load and a
// branch.
//
// limit bounds the walk to the buffer the caller actually owns. n arrives
// from the kernel and is bounded before it is used either for allocation or
// for how far to read.
// resolveFromRawAddrBuf is resolveFromRawAddr with an explicit bound on the
// readable region.
//
// A limit of 0 disables the bounds checks. Every production caller supplies a
// real bound; tests use the unbounded mode to exercise malformed counts. Prefer
// this function with the size of the buffer the kernel filled: without it, a
// count that disagrees with the data can walk off the end.
func resolveFromRawAddrBuf(ptr unsafe.Pointer, n int, limit uintptr) (*SCTPAddr, error) {
	if n < 0 {
		return nil, fmt.Errorf("negative address count: %d", n)
	}
	const maxUnboundedRawAddrs = 4096
	minEntrySize := unsafe.Sizeof(syscall.RawSockaddrInet4{})
	if limit != 0 && uint64(n) > uint64(limit/minEntrySize) {
		return nil, fmt.Errorf("%d addresses cannot fit in a %d byte reply", n, limit)
	}
	if limit == 0 && n > maxUnboundedRawAddrs {
		return nil, fmt.Errorf("unbounded address count %d exceeds safety limit %d",
			n, maxUnboundedRawAddrs)
	}
	addr := &SCTPAddr{
		IPAddrs: make([]net.IPAddr, 0, n),
	}

	var offset uintptr
	for i := 0; i < n; i++ {
		// Reading the family needs the first two bytes of this entry to be
		// inside the buffer before anything is dereferenced.
		//
		// The per-family size checks below reject the same inputs one step
		// later, so removing this one keeps every test green. It is kept
		// regardless: those checks run after the family has been read, and
		// reading the family of an entry that starts past the end is itself
		// the out-of-bounds access being guarded against.
		if limit != 0 && offset+2 > limit {
			return nil, fmt.Errorf(
				"address %d starts past the end of the %d byte reply", i, limit)
		}
		entry := unsafe.Pointer(uintptr(ptr) + offset)

		// Read the family as the two bytes it is, rather than through
		// RawSockaddrAny. That struct is 112 bytes, so converting to it to
		// reach a field in its first two claims the whole span: for the last
		// entry of a tightly sized reply that runs past the allocation, and
		// -race rejects it as a pointer straddling multiple allocations even
		// though only the family is ever read. sa_family_t is uint16 and sits
		// at offset 0 of every sockaddr.
		switch family := *(*uint16)(entry); family {
		case syscall.AF_INET:
			size := unsafe.Sizeof(syscall.RawSockaddrInet4{})
			if limit != 0 && offset+size > limit {
				return nil, fmt.Errorf(
					"IPv4 address %d extends past the end of the %d byte reply",
					i, limit)
			}
			a := (*syscall.RawSockaddrInet4)(entry)
			if i == 0 {
				addr.Port = int(ntohs(a.Port))
			}
			// Copy out of the kernel buffer: a.Addr[:] aliases memory the
			// caller is free to reuse once this returns.
			ip := make(net.IP, net.IPv4len)
			copy(ip, a.Addr[:])
			addr.IPAddrs = append(addr.IPAddrs, net.IPAddr{IP: ip})
			offset += size
		case syscall.AF_INET6:
			size := unsafe.Sizeof(syscall.RawSockaddrInet6{})
			if limit != 0 && offset+size > limit {
				return nil, fmt.Errorf(
					"IPv6 address %d extends past the end of the %d byte reply",
					i, limit)
			}
			a := (*syscall.RawSockaddrInet6)(entry)
			if i == 0 {
				addr.Port = int(ntohs(a.Port))
			}
			var zone string
			if ifi, err := net.InterfaceByIndex(int(a.Scope_id)); err == nil {
				zone = ifi.Name
			}
			ip := make(net.IP, net.IPv6len)
			copy(ip, a.Addr[:])
			addr.IPAddrs = append(addr.IPAddrs, net.IPAddr{IP: ip, Zone: zone})
			offset += size
		default:
			return nil, fmt.Errorf("unknown address family: %d", family)
		}
	}
	return addr, nil
}

// sctpGetSetPrim mirrors struct sctp_prim and struct sctp_setpeerprim, which
// are the same shape: an association id followed by a sockaddr_storage. Both
// are declared packed and aligned(4), so the address starts at offset 4 with no
// pad and the whole thing is 132 bytes.
type sctpGetSetPrim struct {
	assocID int32
	addrs   [128]byte
}

func (c *SCTPConn) SCTPGetPrimaryPeerAddr() (*SCTPAddr, error) {
	param := sctpGetSetPrim{}
	optlen := uint32(unsafe.Sizeof(param))
	_, _, err := c.getsockopt(SCTP_PRIMARY_ADDR, uintptr(unsafe.Pointer(&param)), &optlen)
	if err != nil {
		return nil, err
	}
	return resolveFromRawAddrBuf(unsafe.Pointer(&param.addrs), 1,
		unsafe.Sizeof(param.addrs))
}

// SetPrimaryPeerAddr makes addr the primary path for this association
// (SCTP_PRIMARY_ADDR, RFC 6458 §8.1.9).
//
// The primary is where data goes when every path is usable; the others carry
// retransmissions and take over on failure. Choosing it is the point of
// multi-homing, and until now only the getter existed, so an application could
// see which path was primary but not say which one should be. addr must be one
// the peer announced — GetPeerAddrs lists them — and the kernel rejects
// anything else with EINVAL.
//
// addr must name exactly one address, and this returns EINVAL otherwise. The
// option carries a single sockaddr, so a multi-address SCTPAddr used to be
// accepted and silently applied to whichever address marshalled first: measured
// on a two-homed association, passing the peer's full address returned nil and
// moved the primary to a path the caller had not asked for. That shape is easy
// to reach by accident, since RemoteAddr and SCTPRemoteAddr both return one
// *SCTPAddr carrying every address the peer has.
func (c *SCTPConn) SetPrimaryPeerAddr(addr *SCTPAddr) error {
	if addr == nil || len(addr.IPAddrs) != 1 {
		label := "<nil>"
		if addr != nil {
			label = addr.String()
		}
		return &net.AddrError{Err: "primary address must contain exactly one IP address", Addr: label}
	}
	param := sctpGetSetPrim{}
	raw, err := addr.MarshalSockaddr()
	if err != nil {
		return err
	}
	if len(raw) > len(param.addrs) {
		return syscall.EINVAL
	}
	copy(param.addrs[:], raw)
	_, _, err = c.setsockopt(SCTP_PRIMARY_ADDR,
		uintptr(unsafe.Pointer(&param)), unsafe.Sizeof(param))
	return err
}

// SetPeerPrimaryAddr asks the peer to make addr its primary destination
// (SCTP_SET_PEER_PRIMARY_ADDR, RFC 6458 §8.3.1).
//
// This is the other direction from SetPrimaryPeerAddr: that one chooses where
// this endpoint sends, while this one asks the peer to change where it sends.
// The request travels as an ASCONF parameter, so it needs RFC 5061 negotiated —
// see SetAsconfSupported, without which the kernel refuses with EPERM because
// net.sctp.addip_enable defaults to 0. addr must be one of this endpoint's own
// bound addresses.
//
// As with SetPrimaryPeerAddr, addr must name exactly one address; anything else
// returns EINVAL rather than being narrowed to the first silently.
func (c *SCTPConn) SetPeerPrimaryAddr(addr *SCTPAddr) error {
	if addr == nil || len(addr.IPAddrs) != 1 {
		label := "<nil>"
		if addr != nil {
			label = addr.String()
		}
		return &net.AddrError{Err: "peer primary address must contain exactly one IP address", Addr: label}
	}
	param := sctpGetSetPrim{}
	raw, err := addr.MarshalSockaddr()
	if err != nil {
		return err
	}
	if len(raw) > len(param.addrs) {
		return syscall.EINVAL
	}
	copy(param.addrs[:], raw)
	_, _, err = c.setsockopt(SCTP_SET_PEER_PRIMARY_ADDR,
		uintptr(unsafe.Pointer(&param)), unsafe.Sizeof(param))
	return err
}

// BindAdd atomically adds addr to this endpoint's local address set
// (sctp_bindx with SCTP_BINDX_ADD_ADDR, RFC 6458 §9.1).
//
// A zero port is replaced with the endpoint's bound port. A non-zero port must
// equal that port. The caller's SCTPAddr is never modified, and LocalAddr is
// refreshed from the kernel after a successful operation.
//
// On an established association this local socket operation may also start the
// optional RFC 5061 dynamic-address procedure. That capability must have been
// negotiated before the INIT; see SetAsconfSupported and SetAuthSupported.
// Success from BindAdd records the kernel's acceptance of the local bindx call,
// not receipt of the peer's ASCONF-ACK: RFC 5061 §5.3 rule F1 says the address
// is not fully added to the association until that acknowledgement arrives.
//
// RFC 6458 Erratum 4921 proposes different IPv4/IPv6 wording for §9.1, but is
// Held for Document Update, not Verified. This method therefore preserves the
// socket family's kernel behavior rather than treating that erratum as a new
// normative rule.
func (c *SCTPConn) BindAdd(addr *SCTPAddr) error {
	return c.bindLocalAddrs(addr, SCTP_BINDX_ADD_ADDR)
}

// BindRemove atomically removes addr from this endpoint's local address set
// (sctp_bindx with SCTP_BINDX_REM_ADDR, RFC 6458 §9.1).
//
// Port handling, input ownership, cache refresh, RFC 5061 negotiation, and the
// status of RFC 6458 Erratum 4921 are the same as for BindAdd. RFC 6458 §9.1
// forbids removing every local address. For an established association,
// RFC 5061 §5.3 rules F4 and F5 additionally govern when a removed address
// stops being valid and prohibit deleting the association's last address.
func (c *SCTPConn) BindRemove(addr *SCTPAddr) error {
	return c.bindLocalAddrs(addr, SCTP_BINDX_REM_ADDR)
}

func (c *SCTPConn) bindLocalAddrs(addr *SCTPAddr, flags int) error {
	if c == nil {
		return errClosed("bindx")
	}

	c.bindMu.Lock()
	defer c.bindMu.Unlock()

	raw, err := c.SyscallConn()
	if err != nil {
		return err
	}
	c.addrMu.RLock()
	current := cloneSCTPAddr(c.localAddr)
	c.addrMu.RUnlock()
	target, err := normalizeDynamicBindAddr(addr, current)
	if err != nil {
		return err
	}
	if flags == SCTP_BINDX_REM_ADDR && removesEveryLocalAddress(current, target) {
		return lastAddressRemovalError(target)
	}

	local, applied, err := dynamicBind(raw, target, flags)
	if applied {
		c.addrMu.Lock()
		c.localAddr = cloneSCTPAddr(local)
		c.addrMu.Unlock()
	}
	return err
}

func associationIDFromInt(id int) (SCTPAssocID, error) {
	const (
		min = -1 << 31
		max = 1<<31 - 1
	)
	if int64(id) < min || int64(id) > max {
		return 0, fmt.Errorf("sctp: association id %d is outside the signed 32-bit ABI: %w",
			id, syscall.EINVAL)
	}
	return SCTPAssocID(id), nil
}

func (c *SCTPConn) SCTPLocalAddr(id int) (*SCTPAddr, error) {
	if c == nil {
		return nil, errClosed("getsockopt")
	}
	assocID, err := associationIDFromInt(id)
	if err != nil {
		return nil, err
	}
	if id == 0 {
		// BindAdd and BindRemove also refresh this cache. Serialize the whole
		// readback so an SCTPLocalAddr call that started before a bind cannot
		// store its older result after the bind stored the new address set.
		c.bindMu.Lock()
		defer c.bindMu.Unlock()
	}
	addr, err := c.getAddrs(int(assocID), SCTP_GET_LOCAL_ADDRS)
	if err == nil && id == 0 {
		c.addrMu.Lock()
		c.localAddr = cloneSCTPAddr(addr)
		c.addrMu.Unlock()
	}
	return addr, err
}

func (c *SCTPConn) SCTPRemoteAddr(id int) (*SCTPAddr, error) {
	assocID, err := associationIDFromInt(id)
	if err != nil {
		return nil, err
	}
	addr, err := c.getAddrs(int(assocID), SCTP_GET_PEER_ADDRS)
	if err == nil && id == 0 {
		c.addrMu.Lock()
		c.remoteAddr = cloneSCTPAddr(addr)
		c.addrMu.Unlock()
	}
	return addr, err
}

func (c *SCTPConn) LocalAddr() net.Addr {
	if c == nil {
		return nil
	}
	c.addrMu.RLock()
	addr := cloneSCTPAddr(c.localAddr)
	c.addrMu.RUnlock()
	return addr
}

func (c *SCTPConn) RemoteAddr() net.Addr {
	if c == nil {
		return nil
	}
	c.addrMu.RLock()
	addr := cloneSCTPAddr(c.remoteAddr)
	c.addrMu.RUnlock()
	return addr
}

// SetDeadline sets both the read and write deadlines.
//
// A zero time.Time clears the deadline, as with net.Conn.
func (c *SCTPConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

// SetReadDeadline sets the absolute time after which reads fail.
//
// A read that exceeds the deadline returns an error satisfying
// errors.Is(err, os.ErrDeadlineExceeded). The deadline applies to each read
// as a whole: ReadMsg, which may need several recvmsg calls to reassemble a
// message, is bounded by the deadline overall rather than per call.
//
// The deadline applies to pending and future reads and can be moved or cleared
// while another goroutine is blocked in Read.
func (c *SCTPConn) SetReadDeadline(t time.Time) error {
	if c == nil {
		return errClosed("set")
	}
	if c.fd() < 0 {
		return errClosed("set")
	}
	if c.file != nil {
		if c.raw == nil {
			return syscall.EBADF
		}
		if err := normalizePollError("set", c.file.SetReadDeadline(t)); err != nil {
			return err
		}
		return nil
	}
	if c.initErr != nil {
		return c.initErr
	}
	return nil
}

func (c *SCTPConn) setWriteDeadlineState(t time.Time, apply func(time.Time) error) error {
	c.writeDeadlineMu.Lock()
	defer c.writeDeadlineMu.Unlock()

	if apply != nil {
		if err := normalizePollError("set", apply(t)); err != nil {
			return err
		}
	}
	c.writeDeadline = timeToUnixNano(t)
	return nil
}

// SetWriteDeadline sets the absolute time after which writes fail, including a
// write that is already waiting for send-buffer space.
func (c *SCTPConn) SetWriteDeadline(t time.Time) error {
	if c == nil {
		return errClosed("set")
	}
	if c.fd() < 0 {
		return errClosed("set")
	}
	if c.file != nil {
		if c.raw == nil {
			return syscall.EBADF
		}
		return c.setWriteDeadlineState(t, c.file.SetWriteDeadline)
	}
	if c.initErr != nil {
		return c.initErr
	}
	return c.setWriteDeadlineState(t, nil)
}

func timeToUnixNano(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

// errClosed is the portable error for an operation on an endpoint this package
// has closed. Callers can recognize it with errors.Is(err, net.ErrClosed).
func errClosed(op string) error {
	return &net.OpError{Op: op, Net: "sctp", Err: net.ErrClosed}
}

func normalizePollError(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrClosed) || errors.Is(err, net.ErrClosed) {
		return errClosed(op)
	}
	return err
}

type SCTPListener struct {
	// Keep the 64-bit atomic first for alignment on 32-bit architectures. Linux
	// listeners use os.File.SetReadDeadline; this mirrors the configured value.
	acceptDeadline int64

	// _fd is accessed atomically and set to -1 by Close, so a second Close
	// cannot release a descriptor number the kernel has since handed to
	// another socket. Use fd() to read it.
	_fd  int32
	file *os.File
	raw  syscall.RawConn

	// bindMu serializes BindAdd and BindRemove with their cache refresh.
	bindMu    sync.Mutex
	addrMu    sync.RWMutex
	localAddr *SCTPAddr

	notificationHandler NotificationHandler
}

// SetDeadline sets the absolute time after which Accept fails.
//
// An Accept that exceeds the deadline returns an error satisfying
// errors.Is(err, os.ErrDeadlineExceeded). A zero time.Time clears it, as with
// net.Conn. This mirrors net.TCPListener.SetDeadline, which net.Listener itself
// does not require.
//
// The deadline applies to pending and future Accept calls and can be moved or
// cleared while another goroutine is blocked in Accept.
func (ln *SCTPListener) SetDeadline(t time.Time) error {
	if ln == nil {
		return errClosed("set")
	}
	if ln.fd() < 0 {
		return errClosed("set")
	}
	if ln.file != nil {
		if ln.raw == nil {
			return syscall.EBADF
		}
		if err := normalizePollError("set", ln.file.SetReadDeadline(t)); err != nil {
			return err
		}
		atomic.StoreInt64(&ln.acceptDeadline, timeToUnixNano(t))
		return nil
	}
	atomic.StoreInt64(&ln.acceptDeadline, timeToUnixNano(t))
	return nil
}

func (ln *SCTPListener) fd() int {
	if ln == nil {
		return -1
	}
	return int(atomic.LoadInt32(&ln._fd))
}

func (ln *SCTPListener) Addr() net.Addr {
	if ln == nil {
		return nil
	}
	ln.addrMu.RLock()
	addr := cloneSCTPAddr(ln.localAddr)
	ln.addrMu.RUnlock()
	return addr
}

// BindAdd atomically adds addr to the listener's local address set
// (sctp_bindx with SCTP_BINDX_ADD_ADDR, RFC 6458 §9.1). Associations accepted
// after it succeeds inherit the enlarged set.
//
// A zero port is replaced with the listener's bound port. A non-zero port must
// equal that port. The caller's SCTPAddr is never modified, and Addr is
// refreshed from the kernel after success. This changes the listening endpoint
// itself; RFC 5061 applies only if established associations are also updated.
// RFC 6458 Erratum 4921 remains Held for Document Update, so address-family
// acceptance follows the socket and kernel rather than treating it as a
// normative correction.
func (ln *SCTPListener) BindAdd(addr *SCTPAddr) error {
	return ln.bindLocalAddrs(addr, SCTP_BINDX_ADD_ADDR)
}

// BindRemove atomically removes addr from the listener's local address set
// (sctp_bindx with SCTP_BINDX_REM_ADDR, RFC 6458 §9.1). Associations accepted
// after it succeeds no longer inherit those addresses. The port, ownership,
// cache, RFC 5061, and Held Erratum 4921 rules are the same as for BindAdd.
// Removing every address is forbidden and is rejected with EINVAL.
func (ln *SCTPListener) BindRemove(addr *SCTPAddr) error {
	return ln.bindLocalAddrs(addr, SCTP_BINDX_REM_ADDR)
}

func (ln *SCTPListener) bindLocalAddrs(addr *SCTPAddr, flags int) error {
	if ln == nil {
		return errClosed("bindx")
	}

	ln.bindMu.Lock()
	defer ln.bindMu.Unlock()

	raw, err := ln.SyscallConn()
	if err != nil {
		return err
	}
	ln.addrMu.RLock()
	current := cloneSCTPAddr(ln.localAddr)
	ln.addrMu.RUnlock()
	target, err := normalizeDynamicBindAddr(addr, current)
	if err != nil {
		return err
	}
	if flags == SCTP_BINDX_REM_ADDR && removesEveryLocalAddress(current, target) {
		return lastAddressRemovalError(target)
	}

	local, applied, err := dynamicBind(raw, target, flags)
	if applied {
		ln.addrMu.Lock()
		ln.localAddr = cloneSCTPAddr(local)
		ln.addrMu.Unlock()
	}
	return err
}

type SCTPSndRcvInfoWrappedConn struct {
	conn *SCTPConn
	// subErr records a failure to subscribe to SCTP_EVENT_DATA_IO. Reads
	// report it rather than returning messages with no ancillary data.
	subErr error
}

// NewSCTPSndRcvInfoWrappedConn wraps conn so that Read and Write carry a
// SndRcvInfo header inline, ahead of the payload.
//
// The inline header is a process-local Go representation in native byte order;
// PPID follows this package's public host-order convention. It is not a wire
// encoding and must not be persisted or exchanged between unlike architectures.
//
// The whole type depends on SCTP_EVENT_DATA_IO being subscribed, since that is
// what makes the kernel return the ancillary data the header is built from.
// The subscription used to be attempted and its error discarded, which fails
// quietly in the worst way: every Read then finds no ancillary data and writes
// a zeroed header, so the caller reads a well-formed SndRcvInfo reporting
// stream 0 and PPID 0 for every message regardless of which stream it arrived
// on.
//
// This signature cannot return an error without breaking callers, so the
// failure is kept and returned from the first Read or Write instead.
func NewSCTPSndRcvInfoWrappedConn(conn *SCTPConn) *SCTPSndRcvInfoWrappedConn {
	c := &SCTPSndRcvInfoWrappedConn{conn: conn}
	if conn == nil {
		c.subErr = errClosed("wrap")
		return c
	}
	if err := conn.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
		c.subErr = fmt.Errorf(
			"sctp: subscribing to SCTP_EVENT_DATA_IO failed, so no message can "+
				"carry its SndRcvInfo: %w", err)
	}
	return c
}

func (c *SCTPSndRcvInfoWrappedConn) checkedConn(op string) (*SCTPConn, error) {
	if c == nil || c.conn == nil {
		return nil, errClosed(op)
	}
	return c.conn, nil
}

func decodeWrappedSndRcvInfo(b []byte) (SndRcvInfo, error) {
	if len(b) < int(sndRcvInfoSize) {
		return SndRcvInfo{}, io.ErrUnexpectedEOF
	}
	return SndRcvInfo{
		Stream:  nativeEndian.Uint16(b[0:2]),
		SSN:     nativeEndian.Uint16(b[2:4]),
		Flags:   nativeEndian.Uint16(b[4:6]),
		PPID:    nativeEndian.Uint32(b[8:12]),
		Context: nativeEndian.Uint32(b[12:16]),
		TTL:     nativeEndian.Uint32(b[16:20]),
		TSN:     nativeEndian.Uint32(b[20:24]),
		CumTSN:  nativeEndian.Uint32(b[24:28]),
		AssocID: int32(nativeEndian.Uint32(b[28:32])),
	}, nil
}

func (c *SCTPSndRcvInfoWrappedConn) Write(b []byte) (int, error) {
	conn, err := c.checkedConn("write")
	if err != nil {
		return 0, err
	}
	if c.subErr != nil {
		return 0, c.subErr
	}
	if len(b) < int(sndRcvInfoSize) {
		return 0, syscall.EINVAL
	}
	info, err := decodeWrappedSndRcvInfo(b)
	if err != nil {
		return 0, err
	}
	n, err := conn.writeSndRcv(b[sndRcvInfoSize:], &info, true)
	return finishWrappedWrite(n, err)
}

func finishWrappedWrite(n int, err error) (int, error) {
	if n > 0 {
		n += int(sndRcvInfoSize)
	}
	return n, err
}

func finishWrappedRead(b []byte, n int, info *SndRcvInfo, err error) (int, error) {
	if n == 0 && err != nil {
		return 0, err
	}
	if info != nil {
		copy(b, toBuf(info))
	} else {
		// No ancillary data came back, so there is nothing to describe the
		// message. Zero the header rather than leaving whatever the caller had in
		// b, which would otherwise be read as a valid SndRcvInfo.
		hdr := b[:sndRcvInfoSize]
		for i := range hdr {
			hdr[i] = 0
		}
	}
	return n + int(sndRcvInfoSize), err
}

func (c *SCTPSndRcvInfoWrappedConn) Read(b []byte) (int, error) {
	conn, err := c.checkedConn("read")
	if err != nil {
		return 0, err
	}
	if c.subErr != nil {
		return 0, c.subErr
	}
	if len(b) < int(sndRcvInfoSize) {
		return 0, syscall.EINVAL
	}
	n, info, err := conn.SCTPRead(b[sndRcvInfoSize:])
	return finishWrappedRead(b, n, info, err)
}

func (c *SCTPSndRcvInfoWrappedConn) Close() error {
	conn, err := c.checkedConn("close")
	if err != nil {
		return err
	}
	return conn.Close()
}

func (c *SCTPSndRcvInfoWrappedConn) LocalAddr() net.Addr {
	conn, err := c.checkedConn("localaddr")
	if err != nil {
		return nil
	}
	return conn.LocalAddr()
}

func (c *SCTPSndRcvInfoWrappedConn) RemoteAddr() net.Addr {
	conn, err := c.checkedConn("remoteaddr")
	if err != nil {
		return nil
	}
	return conn.RemoteAddr()
}

func (c *SCTPSndRcvInfoWrappedConn) SetDeadline(t time.Time) error {
	conn, err := c.checkedConn("set")
	if err != nil {
		return err
	}
	return conn.SetDeadline(t)
}

func (c *SCTPSndRcvInfoWrappedConn) SetReadDeadline(t time.Time) error {
	conn, err := c.checkedConn("set")
	if err != nil {
		return err
	}
	return conn.SetReadDeadline(t)
}

func (c *SCTPSndRcvInfoWrappedConn) SetWriteDeadline(t time.Time) error {
	conn, err := c.checkedConn("set")
	if err != nil {
		return err
	}
	return conn.SetWriteDeadline(t)
}

func (c *SCTPSndRcvInfoWrappedConn) SetWriteBuffer(bytes int) error {
	conn, err := c.checkedConn("setsockopt")
	if err != nil {
		return err
	}
	return conn.SetWriteBuffer(bytes)
}

func (c *SCTPSndRcvInfoWrappedConn) GetWriteBuffer() (int, error) {
	conn, err := c.checkedConn("getsockopt")
	if err != nil {
		return 0, err
	}
	return conn.GetWriteBuffer()
}

func (c *SCTPSndRcvInfoWrappedConn) SetReadBuffer(bytes int) error {
	conn, err := c.checkedConn("setsockopt")
	if err != nil {
		return err
	}
	return conn.SetReadBuffer(bytes)
}

func (c *SCTPSndRcvInfoWrappedConn) GetReadBuffer() (int, error) {
	conn, err := c.checkedConn("getsockopt")
	if err != nil {
		return 0, err
	}
	return conn.GetReadBuffer()
}

// SocketConfig contains options for the SCTP socket.
type SocketConfig struct {
	// If Control is not nil it is called after the socket is created but before
	// it is bound or connected. Dial and DialContext pass the remote address;
	// Listen passes the local address. The RawConn is Control-only at this stage:
	// Read and Write return EINVAL. The callback must not retain the numeric file
	// descriptor after it returns.
	Control func(network, address string, c syscall.RawConn) error
	// NotificationHandler consumes notifications before SCTPReadFlags or ReadMsg
	// returns. Leave it nil to receive notification bytes and MSG_NOTIFICATION
	// through SCTPReadFlags, or use SCTPReadMsg for an always-raw receive.
	NotificationHandler NotificationHandler
	// InitMsg configures the association parameters announced in INIT.
	InitMsg InitMsg
}

// PreconfiguredSocket is an immutable SocketConfig snapshot with typed options
// that must be applied after Control and InitMsg but before bind, connect, or
// listen. Construct one with SocketConfig.WithPreAssociation.
//
// Keeping this as a wrapper preserves SocketConfig's original three-field shape
// so existing unkeyed literals remain source-compatible.
type PreconfiguredSocket struct {
	socket SocketConfig
	pre    PreAssociationConfig
}

// WithPreAssociation snapshots cfg and pre for a later Listen, Dial,
// DialContext, OpenEndpoint, or ListenEndpoint call. A nil cfg snapshots the
// zero SocketConfig. Slice and pointer fields are copied, so later caller
// mutation cannot race with socket construction or change the applied plan.
func (cfg *SocketConfig) WithPreAssociation(pre PreAssociationConfig) *PreconfiguredSocket {
	var socket SocketConfig
	if cfg != nil {
		socket = *cfg
	}
	return &PreconfiguredSocket{
		socket: socket,
		pre:    clonePreAssociationConfig(pre),
	}
}

func (cfg *PreconfiguredSocket) snapshot() (SocketConfig, PreAssociationConfig) {
	if cfg == nil {
		return SocketConfig{}, PreAssociationConfig{}
	}
	return cfg.socket, cfg.pre
}

func (cfg *SocketConfig) Listen(net string, laddr *SCTPAddr) (*SCTPListener, error) {
	if cfg == nil {
		cfg = &SocketConfig{}
	}
	return listenSCTPExtConfig(net, laddr, cfg.InitMsg, cfg.Control,
		cfg.NotificationHandler, PreAssociationConfig{})
}

func (cfg *SocketConfig) Dial(net string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	if cfg == nil {
		cfg = &SocketConfig{}
	}
	return dialSCTPExtConfig(net, laddr, raddr, cfg.InitMsg, cfg.Control,
		cfg.NotificationHandler, PreAssociationConfig{})
}

// DialContext is Dial with a context; see DialSCTPContext for what the context
// bounds and why Dial cannot offer it. A nil context is rejected with an error
// wrapping syscall.EINVAL.
func (cfg *SocketConfig) DialContext(ctx context.Context, net string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	if cfg == nil {
		cfg = &SocketConfig{}
	}
	return dialSCTPExtConfigContext(ctx, net, laddr, raddr, cfg.InitMsg,
		cfg.Control, cfg.NotificationHandler, PreAssociationConfig{})
}

// Listen is SocketConfig.Listen with the snapshotted pre-association plan.
func (cfg *PreconfiguredSocket) Listen(network string, laddr *SCTPAddr) (*SCTPListener, error) {
	socket, pre := cfg.snapshot()
	return listenSCTPExtConfig(network, laddr, socket.InitMsg, socket.Control,
		socket.NotificationHandler, pre)
}

// Dial is SocketConfig.Dial with the snapshotted pre-association plan.
func (cfg *PreconfiguredSocket) Dial(network string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	socket, pre := cfg.snapshot()
	return dialSCTPExtConfig(network, laddr, raddr, socket.InitMsg, socket.Control,
		socket.NotificationHandler, pre)
}

// DialContext is SocketConfig.DialContext with the snapshotted
// pre-association plan.
func (cfg *PreconfiguredSocket) DialContext(
	ctx context.Context, network string, laddr, raddr *SCTPAddr,
) (*SCTPConn, error) {
	socket, pre := cfg.snapshot()
	return dialSCTPExtConfigContext(ctx, network, laddr, raddr, socket.InitMsg,
		socket.Control, socket.NotificationHandler, pre)
}
