// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
)

// SendBacklog reports the socket's send-buffer memory charge and limit
// (SO_MEMINFO, Linux 4.12 and later; net/core/sock.c: sk_get_meminfo).
// The unit is bytes of memory, including overhead, rather than payload.
//
// For each DATA chunk, Linux charges skb->truesize plus sizeof(struct
// sctp_chunk), and releases the charge when the chunk is freed
// (net/sctp/socket.c: sctp_set_owner_w, sctp_wfree). It includes chunks
// unsent, in flight, awaiting retransmission, acknowledged only by a Gap
// Ack Block, or abandoned under PR-SCTP and not yet freed. A sent chunk
// is freed when the Cumulative TSN Ack covers it, or at teardown. Peel-off
// moves the charge to the new socket (net/sctp/socket.c: sctp_sock_migrate).
// Zero means no charged chunks remain. For delivered DATA the peer has
// acknowledged it, which does not mean its application has read it.
//
// A send waits while its available space is zero or negative, so one send
// can take Charged past Limit (net/sctp/socket.c: sctp_wspace,
// sctp_sendmsg_to_asoc). Linux reports no exact payload count still queued:
// net/sctp/socket.c: sctp_ioctl handles SIOCINQ only, without SIOCOUTQ,
// and the unsent queue's out_qlen is not exported. See also [AssocQueues].
type SendBacklog struct {
	// Charged is SK_MEMINFO_WMEM_QUEUED, the socket's sk_wmem_queued.
	Charged int
	// Limit is SK_MEMINFO_SNDBUF, the stored send buffer, as WriteBuffer
	// reports it, including Linux's doubling for bookkeeping.
	Limit int
}

// AssocQueues reports an association's queue accounting through SCTP
// sock_diag (net/sctp/diag.c: sctp_diag_get_info; net/sctp/socket.c:
// sctp_get_sctp_info). The counters are a snapshot, not a payload backlog.
type AssocQueues struct {
	// SendCharged is idiag_wqueue, the association's sndbuf_used: its
	// share of the memory charge described by SendBacklog.
	SendCharged int
	// RecvCharged is idiag_rqueue, the association's rmem_alloc. Linux
	// charges each owned receive event's rmem_len, including DATA and
	// notifications, and releases it with the event's ownership. This is
	// receive memory including overhead, not unread payload bytes
	// (net/sctp/ulpevent.c: sctp_ulpevent_set_owner,
	// sctp_ulpevent_release_owner).
	RecvCharged int
	// Unsent is sctpi_outqueue, the number of DATA chunks never
	// transmitted, on outqueue.out_chunk_list.
	Unsent int
	// PrimaryInFlight is sctpi_p_flight_size, payload bytes in flight
	// on the primary path only, rather than across every path.
	PrimaryInFlight int
}

func decodeSendBacklog(b []byte, n int) (*SendBacklog, error) {
	if n < (meminfoWmemQueued+1)*4 || n > len(b) {
		return nil, fmt.Errorf("sctp: SO_MEMINFO returned %d bytes in a %d-byte buffer, need at least %d", n, len(b), (meminfoWmemQueued+1)*4)
	}
	return &SendBacklog{
		Charged: int(binary.NativeEndian.Uint32(b[meminfoWmemQueued*4:])),
		Limit:   int(binary.NativeEndian.Uint32(b[meminfoSndbuf*4:])),
	}, nil
}

// diagSelector names the transport, bound interface and owning socket.
// The lookup uses the association's address family, even on a dual-stack
// socket (net/sctp/input.c: sctp_addrs_lookup_transport).
type diagSelector struct {
	local, peer netip.AddrPort
	cookie      uint64
	ifindex     uint32
}

func (s diagSelector) request(seq uint32, probe bool) []byte {
	b := make([]byte, sizeDiagRequest)
	order := binary.NativeEndian
	order.PutUint32(b, uint32(len(b)))
	order.PutUint16(b[4:], sockDiagByFamily)
	flags, states := uint16(nlmRequest), uint32(0xffffffff)
	if probe {
		flags |= nlmDump
		states = 0
	}
	order.PutUint16(b[6:], flags)
	order.PutUint32(b[8:], seq)
	p := b[sizeNLMsgHeader:]
	p[0] = afInet6
	local, peer := s.local.Addr().Unmap(), s.peer.Addr().Unmap()
	if peer.Is4() {
		p[0] = afInet
	}
	p[1], p[2] = ipprotoSCTP, 1<<(inetDiagInfo-1)
	order.PutUint32(p[4:], states)
	binary.BigEndian.PutUint16(p[8:], s.local.Port())
	binary.BigEndian.PutUint16(p[10:], s.peer.Port())
	copy(p[12:28], local.AsSlice())
	copy(p[28:44], peer.AsSlice())
	order.PutUint32(p[44:], s.ifindex)
	order.PutUint32(p[48:], uint32(s.cookie))
	order.PutUint32(p[52:], uint32(s.cookie>>32))
	return b
}

// parseDiagReply reads one complete netlink datagram. A probe may have
// entries before DONE; those are skipped, and done then remains false.
// Every length is checked before it is used as an offset or allocation.
func parseDiagReply(b []byte, seq uint32, cookie uint64, probe bool) (*AssocQueues, bool, error) {
	var result *AssocQueues
	done := false
	for len(b) > 0 {
		if len(b) < sizeNLMsgHeader {
			return nil, false, fmt.Errorf("sctp: sock_diag reply has a truncated netlink header")
		}
		length := binary.NativeEndian.Uint32(b)
		if length < sizeNLMsgHeader || uint64(length) > uint64(len(b)) {
			return nil, false, fmt.Errorf("sctp: sock_diag reply has invalid netlink length %d", length)
		}
		if binary.NativeEndian.Uint32(b[8:]) != seq {
			return nil, false, fmt.Errorf("sctp: sock_diag reply sequence does not match request")
		}
		p := b[sizeNLMsgHeader:length]
		typ := binary.NativeEndian.Uint16(b[4:])
		switch typ {
		case nlmsgError, nlmsgDone:
			if len(p) < 4 {
				return nil, false, fmt.Errorf("sctp: sock_diag reply has a truncated error or DONE")
			}
			status := int32(binary.NativeEndian.Uint32(p))
			if status < 0 {
				return nil, false, syscall.Errno(-int64(status))
			}
			if status != 0 || !probe || typ != nlmsgDone {
				return nil, false, fmt.Errorf("sctp: sock_diag returned unexpected message type %d with status %d", typ, status)
			}
			done = true
		case sockDiagByFamily:
			if !probe {
				if result != nil {
					return nil, false, fmt.Errorf("sctp: sock_diag returned more than one association")
				}
				q, err := parseDiagAssociation(p, cookie)
				if err != nil {
					return nil, false, err
				}
				result, done = q, true
			}
		default:
			return nil, false, fmt.Errorf("sctp: sock_diag returned unexpected message type %d", typ)
		}
		aligned := (uint64(length) + 3) &^ uint64(3)
		if aligned > uint64(len(b)) {
			if int(length) != len(b) {
				return nil, false, fmt.Errorf("sctp: sock_diag reply has truncated alignment")
			}
			b = nil
		} else {
			b = b[aligned:]
		}
	}
	if !probe && result == nil {
		return nil, false, fmt.Errorf("sctp: sock_diag returned no association")
	}
	return result, done, nil
}

func parseDiagAssociation(p []byte, cookie uint64) (*AssocQueues, error) {
	if len(p) < sizeInetDiagMsg {
		return nil, fmt.Errorf("sctp: sock_diag returned a truncated inet_diag_msg")
	}
	order := binary.NativeEndian
	got := uint64(order.Uint32(p[44:])) | uint64(order.Uint32(p[48:]))<<32
	if got != cookie {
		return nil, fmt.Errorf("sctp: sock_diag reply cookie does not match socket: %w", syscall.ESTALE)
	}
	q := &AssocQueues{RecvCharged: int(order.Uint32(p[56:])), SendCharged: int(order.Uint32(p[60:]))}
	info := false
	for attrs := p[sizeInetDiagMsg:]; len(attrs) > 0; {
		if len(attrs) < sizeNLAttr {
			return nil, fmt.Errorf("sctp: sock_diag returned a truncated attribute header")
		}
		n := int(order.Uint16(attrs))
		if n < sizeNLAttr || n > len(attrs) {
			return nil, fmt.Errorf("sctp: sock_diag returned invalid attribute length %d", n)
		}
		if order.Uint16(attrs[2:]) == inetDiagInfo {
			if info || n < sizeNLAttr+sctpInfoPrimaryFlightOff+4 {
				return nil, fmt.Errorf("sctp: sock_diag returned repeated or short INET_DIAG_INFO")
			}
			data := attrs[sizeNLAttr:n]
			q.Unsent = int(order.Uint32(data[sctpInfoOutqueueOff:]))
			q.PrimaryInFlight = int(order.Uint32(data[sctpInfoPrimaryFlightOff:]))
			info = true
		}
		aligned := (n + 3) &^ 3
		if aligned > len(attrs) {
			if n != len(attrs) {
				return nil, fmt.Errorf("sctp: sock_diag returned truncated attribute alignment")
			}
			attrs = nil
		} else {
			attrs = attrs[aligned:]
		}
	}
	if !info {
		return nil, fmt.Errorf("sctp: sock_diag returned no INET_DIAG_INFO")
	}
	return q, nil
}

// queryDiag probes handler availability only after an exact ENOENT. That
// errno also means the tuple no longer names an association. A zero-state
// dump distinguishes them (net/ipv4/inet_diag.c: inet_diag_cmd_exact;
// net/sctp/diag.c: sctp_diag_dump).
func queryDiag(s diagSelector, exchange func([]byte, bool) (*AssocQueues, error)) (*AssocQueues, error) {
	q, err := exchange(s.request(1, false), false)
	if !errors.Is(err, syscall.ENOENT) {
		return q, err
	}
	_, probeErr := exchange(s.request(2, true), true)
	if errors.Is(probeErr, syscall.ENOENT) {
		return nil, fmt.Errorf("sctp: sctp_diag is unavailable: %w", errors.Join(ErrUnsupported, probeErr))
	}
	if probeErr != nil {
		return nil, probeErr
	}
	return nil, err
}
