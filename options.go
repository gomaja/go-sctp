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

// options.go declares the value types the typed socket options (Config's
// InitMsg, RTOInfo and DelayedSACK, and the Conn getters and setters)
// read and write, the checks their arguments get before any system call,
// and the codecs that lay each value out in the kernel's own struct and
// read it back. validatePrInfo, the PR-SCTP check config.go's
// DefaultPrInfo handling shares with msginfo.go's per-message
// validateSendOptions, lives here too.
//
// Everything here is portable, with no build tag: the codecs write and read
// the Linux layouts byte by byte from abi.go's offsets, so the tests that
// pin them run on every platform. The system calls that carry these bytes
// are in options_linux.go and options_ext_linux.go.

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sync/atomic"
	"syscall"
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

// --- plain arguments ------------------------------------------------------------

// uint32Arg checks an int argument that travels in a __u32 kernel field:
// negative values and values beyond the field are refused, naming name,
// rather than wrapped around.
func uint32Arg(name string, v int) (uint32, error) {
	if v < 0 {
		return 0, invalidArg("%s: %d is negative", name, v)
	}
	if uint64(v) > math.MaxUint32 {
		return 0, invalidArg("%s: %d exceeds the uint32 range the kernel field holds", name, v)
	}
	return uint32(v), nil
}

// bufferSizeArg checks a SO_RCVBUF or SO_SNDBUF size: positive, and within
// the plain C int the option takes (net/core/sock.c: sk_setsockopt copies
// optval into an int), as Config.ReadBuffer and Config.WriteBuffer are.
func bufferSizeArg(name string, v int) (int32, error) {
	if v <= 0 {
		return 0, invalidArg("%s: the size must be positive, got %d", name, v)
	}
	if v > math.MaxInt32 {
		return 0, invalidArg("%s: %d exceeds the int32 range SO_RCVBUF and SO_SNDBUF take", name, v)
	}
	return int32(v), nil
}

// --- the word-size-dependent option structs ---------------------------------

// sockaddrStorageLayout is where one of the two shapes of the option
// structs that embed a non-packed struct sockaddr_storage puts its fields:
// sctp_udpencaps, sctp_probeinterval, sctp_paddrthlds_v2 and
// sctp_assoc_stats (abi.go explains why their layout follows the word
// size). Each starts with its sctp_assoc_t at offset 0.
//
// nativeStorageLayout is the shape a kernel of this build's own word size
// uses, and kernel64StorageLayout the shape a 64-bit kernel always uses.
// Linux SCTP translates none of these structs for a 32-bit process on a
// 64-bit kernel (net/sctp/socket.c has one in_compat_syscall, in
// sctp_getsockopt_connectx3), so such a process must use the 64-bit shape.
// On a 64-bit build the two are the same.
type sockaddrStorageLayout struct {
	addrOff int // the embedded sockaddr_storage

	udpEncapsPortOff, sizeUDPEncaps     int
	probeIntervalOff, sizeProbeInterval int

	thresholdsMaxRetransOff, thresholdsPFOff, thresholdsSwitchoverOff int
	sizePathThresholds                                                int

	statsCountersOff, sizeAssocStats int
}

var (
	nativeStorageLayout = sockaddrStorageLayout{
		addrOff:                 ssAddrOffset,
		udpEncapsPortOff:        udpEncapsPortOff,
		sizeUDPEncaps:           sizeUDPEncaps,
		probeIntervalOff:        probeIntervalIntervalOff,
		sizeProbeInterval:       sizeProbeInterval,
		thresholdsMaxRetransOff: pathThresholdsMaxRxtOff,
		thresholdsPFOff:         pathThresholdsPFThresholdOff,
		thresholdsSwitchoverOff: pathThresholdsSwitchoverOff,
		sizePathThresholds:      sizePathThresholds,
		statsCountersOff:        sizeAssocStatsHeader,
		sizeAssocStats:          sizeAssocStats,
	}
	kernel64StorageLayout = sockaddrStorageLayout{
		addrOff:                 ssAddrOffsetKernel64,
		udpEncapsPortOff:        udpEncapsPortOffKernel64,
		sizeUDPEncaps:           sizeUDPEncapsKernel64,
		probeIntervalOff:        probeIntervalIntervalOffKernel64,
		sizeProbeInterval:       sizeProbeIntervalKernel64,
		thresholdsMaxRetransOff: pathThresholdsMaxRxtOffKernel64,
		thresholdsPFOff:         pathThresholdsPFThresholdOffKernel64,
		thresholdsSwitchoverOff: pathThresholdsSwitchoverOffKernel64,
		sizePathThresholds:      sizePathThresholdsKernel64,
		statsCountersOff:        sizeAssocStatsHeaderKernel64,
		sizeAssocStats:          sizeAssocStatsKernel64,
	}
)

// The values a storage-layout cache holds: nothing chosen yet, or one of
// the two layouts.
const (
	storageLayoutUnknown uint32 = iota
	storageLayoutNative
	storageLayoutKernel64
)

// selectStorageLayout returns the layout cache records, or asks probe and
// records its answer. probe asks the kernel for the two-field
// SCTP_PEER_ADDR_THLDS with the native sizeof(struct sctp_paddrthlds):
// Linux refuses a buffer shorter than its own struct with EINVAL
// (net/sctp/socket.c: sctp_getsockopt_paddr_thresholds, "if (len < min)
// return -EINVAL"), so success means a kernel of this build's word size
// and EINVAL a 64-bit kernel under a 32-bit build. Any other error says
// nothing about the kernel's word size: it is returned, and nothing is
// recorded, so that the next call asks again.
func selectStorageLayout(cache *atomic.Uint32, probe func() error) (*sockaddrStorageLayout, error) {
	switch cache.Load() {
	case storageLayoutNative:
		return &nativeStorageLayout, nil
	case storageLayoutKernel64:
		return &kernel64StorageLayout, nil
	}
	switch err := probe(); {
	case err == nil:
		cache.Store(storageLayoutNative)
		return &nativeStorageLayout, nil
	case errors.Is(err, syscall.EINVAL):
		cache.Store(storageLayoutKernel64)
		return &kernel64StorageLayout, nil
	default:
		return nil, err
	}
}

// storageHeader clears b and writes the sctp_assoc_t, which all four
// structs put at offset 0 (udpEncapsAssocIDOff, probeIntervalAssocIDOff,
// pathThresholdsAssocIDOff, assocStatsAssocIDOff), and the encoded
// address, if any, into the embedded sockaddr_storage. An empty addr
// leaves the address zero, which Linux reads as the wildcard: the
// association as a whole (net/sctp/bind_addr.c: sctp_is_any).
func (l *sockaddrStorageLayout) storageHeader(b []byte, assoc AssocID, addr []byte) {
	clear(b)
	binary.NativeEndian.PutUint32(b[0:], uint32(assoc))
	copy(b[l.addrOff:l.addrOff+sizeSockaddrStorage], addr)
}

// udpEncaps lays out struct sctp_udpencaps in buf, which holds at least
// l.sizeUDPEncaps bytes, and returns that many. port is in host order;
// sue_port carries it in network byte order (RFC 6951 §6.1), and Linux
// keeps it that way (net/sctp/socket.c: sctp_setsockopt_encap_port casts
// it to __be16).
func (l *sockaddrStorageLayout) udpEncaps(buf []byte, assoc AssocID, addr []byte, port uint16) []byte {
	b := buf[:l.sizeUDPEncaps]
	l.storageHeader(b, assoc, addr)
	binary.BigEndian.PutUint16(b[l.udpEncapsPortOff:], port)
	return b
}

// udpEncapsPort reads sue_port back in host order.
func (l *sockaddrStorageLayout) udpEncapsPort(b []byte) uint16 {
	return binary.BigEndian.Uint16(b[l.udpEncapsPortOff:])
}

// probeInterval lays out struct sctp_probeinterval, the interval in whole
// milliseconds.
func (l *sockaddrStorageLayout) probeInterval(buf []byte, assoc AssocID, addr []byte, ms uint32) []byte {
	b := buf[:l.sizeProbeInterval]
	l.storageHeader(b, assoc, addr)
	binary.NativeEndian.PutUint32(b[l.probeIntervalOff:], ms)
	return b
}

// probeIntervalMS reads spi_interval.
func (l *sockaddrStorageLayout) probeIntervalMS(b []byte) uint32 {
	return binary.NativeEndian.Uint32(b[l.probeIntervalOff:])
}

// thresholdValues are the three thresholds of struct sctp_paddrthlds_v2.
type thresholdValues struct {
	maxRetrans uint16 // spt_pathmaxrxt
	pf         uint16 // spt_pathpfthld
	switchover uint16 // spt_pathcpthld
}

// pathThresholds lays out struct sctp_paddrthlds_v2.
func (l *sockaddrStorageLayout) pathThresholds(buf []byte, assoc AssocID, addr []byte, v thresholdValues) []byte {
	b := buf[:l.sizePathThresholds]
	l.storageHeader(b, assoc, addr)
	binary.NativeEndian.PutUint16(b[l.thresholdsMaxRetransOff:], v.maxRetrans)
	binary.NativeEndian.PutUint16(b[l.thresholdsPFOff:], v.pf)
	binary.NativeEndian.PutUint16(b[l.thresholdsSwitchoverOff:], v.switchover)
	return b
}

// thresholdValues reads the three thresholds back.
func (l *sockaddrStorageLayout) thresholdValues(b []byte) thresholdValues {
	return thresholdValues{
		maxRetrans: binary.NativeEndian.Uint16(b[l.thresholdsMaxRetransOff:]),
		pf:         binary.NativeEndian.Uint16(b[l.thresholdsPFOff:]),
		switchover: binary.NativeEndian.Uint16(b[l.thresholdsSwitchoverOff:]),
	}
}

// assocStatsRequest lays out the request for SCTP_GET_ASSOC_STATS: struct
// sctp_assoc_stats with only sas_assoc_id set.
func (l *sockaddrStorageLayout) assocStatsRequest(buf []byte, assoc AssocID) []byte {
	b := buf[:l.sizeAssocStats]
	l.storageHeader(b, assoc, nil)
	return b
}

// assocStats decodes struct sctp_assoc_stats. Every counter is copied as it
// is, sas_maxrto included, in kernel ticks (net/sctp/socket.c:
// sctp_getsockopt_assoc_stats copies asoc->stats.max_obs_rto without
// jiffies_to_msecs). The observed-RTO address is copied from the kernel's
// own record without addr_to_user, so it can be either family on either
// kind of socket, and before any RTO update it is whatever the association
// holds, zero at first; an address no known family names decodes to the
// zero AddrPort.
func (l *sockaddrStorageLayout) assocStats(b []byte) AssocStats {
	c := func(i int) uint64 { return binary.NativeEndian.Uint64(b[l.statsCountersOff+8*i:]) }
	var addr netip.AddrPort
	if a, err := decodeAddr(b[l.addrOff : l.addrOff+sizeSockaddrStorage]); err == nil {
		addr = a
	}
	return AssocStats{
		MaxRTOTicks:        c(assocStatsMaxRTO),
		MaxRTOAddr:         addr,
		SACKsIn:            c(assocStatsISACKs),
		SACKsOut:           c(assocStatsOSACKs),
		PacketsIn:          c(assocStatsIPackets),
		PacketsOut:         c(assocStatsOPackets),
		RetransChunks:      c(assocStatsRtxChunks),
		OutOfSeqTSNs:       c(assocStatsOutOfSeqTSNs),
		DupChunksIn:        c(assocStatsIDupChunks),
		GapAcksIn:          c(assocStatsGapCount),
		UnorderedChunksIn:  c(assocStatsIUODChunks),
		UnorderedChunksOut: c(assocStatsOUODChunks),
		OrderedChunksIn:    c(assocStatsIODChunks),
		OrderedChunksOut:   c(assocStatsOODChunks),
		ControlChunksIn:    c(assocStatsICtrlChunks),
		ControlChunksOut:   c(assocStatsOCtrlChunks),
	}
}

// --- path addresses ---------------------------------------------------------

// encodePathAddr encodes path, with the association's peer port, for a path
// option or SendOptions.Path on a socket of family, into dst, and returns
// the length written: 0 for the zero netip.Addr, which a path option then
// reads as the association as a whole. It allocates nothing.
//
// A link-local path without a zone is given scope, the association's
// link-local scope id (linkLocalPathScope), when that is not 0: Linux
// refuses a link-local path with scope id 0 (net/sctp/ipv6.c:
// sctp_inet6_send_verify, reached through sctp_verify_addr), but matches a
// peer address stored with scope id 0, as one learned from an INIT, INIT
// ACK or ASCONF parameter is, against any other (__sctp_v6_cmp_addr).
// Otherwise the path is encoded as it is, and Linux refuses it.
func encodePathAddr(dst []byte, family int, path netip.Addr, port uint16, scope uint32) (int, error) {
	if !path.IsValid() {
		return 0, nil
	}
	n, err := encodeAddr(dst, family, path, port)
	if err != nil {
		return 0, err
	}
	if scope != 0 && n == sizeSockaddrIn6 && path.Zone() == "" && isLinkLocal6(path) {
		binary.NativeEndian.PutUint32(dst[sockaddrIn6ScopeIDOff:], scope)
	}
	return n, nil
}

// linkLocalPathScope picks the scope id encodePathAddr gives a link-local
// path without a zone, from an association's local and peer addresses as
// the address snapshots hold them. owners returns the indexes of the
// interfaces that hold a local address. The candidates come from the
// first of these that finds any:
//
//  1. the zones of the zoned local link-local addresses;
//  2. the zones of the zoned peer link-local addresses: on an accepted
//     association, the INIT's source carries the interface it arrived on
//     (net/sctp/ipv6.c: sctp_v6_from_skb sets sin6_scope_id from the
//     packet's iif, and net/sctp/sm_make_chunk.c: sctp_make_temp_asoc keeps
//     it in the cookie). The local addresses carry none when the cookie
//     lists two or more, since Linux rebuilds them from that list
//     (net/sctp/bind_addr.c: sctp_raw_to_bind_addrs passes iif 0). A
//     cookie from a single-address endpoint lists none, and the local
//     address is then the COOKIE ECHO's destination, which keeps the
//     interface it arrived on (net/sctp/sm_make_chunk.c:
//     sctp_unpack_cookie; net/sctp/input.c: sctp_rcv), so rule 1 applies;
//  3. the interfaces that hold the zoneless local link-local addresses.
//
// It returns the one candidate, or 0 when there are several, as on an
// association over two links, or none: a link-local path without a zone
// then needs its zone from the caller.
func linkLocalPathScope(local, peer []netip.Addr, owners func(netip.Addr) []uint32) uint32 {
	var c scopeCandidates
	for _, ip := range local {
		if isLinkLocal6(ip) && ip.Zone() != "" {
			c.addZone(ip.Zone())
		}
	}
	if c.n == 0 {
		for _, ip := range peer {
			if isLinkLocal6(ip) && ip.Zone() != "" {
				c.addZone(ip.Zone())
			}
		}
	}
	if c.n == 0 {
		for _, ip := range local {
			if isLinkLocal6(ip) && ip.Zone() == "" {
				for _, s := range owners(ip) {
					c.add(s)
				}
			}
		}
	}
	return c.only()
}

// isLinkLocal6 reports whether ip is an IPv6 link-local unicast address,
// the only kind a scope id applies to.
func isLinkLocal6(ip netip.Addr) bool {
	return ip.Is6() && !ip.Is4In6() && ip.IsLinkLocalUnicast()
}

// scopeCandidates counts the distinct non-zero scope ids added to it, up to
// two, which is all linkLocalPathScope needs to know.
type scopeCandidates struct {
	first uint32
	n     int // 0, 1, or 2 for "several"
}

// add adds scope id s.
func (c *scopeCandidates) add(s uint32) {
	switch {
	case s == 0:
	case c.n == 0:
		c.first, c.n = s, 1
	case s != c.first:
		c.n = 2
	}
}

// addZone adds the scope id a zone names: an interface name or a decimal
// index, as the address snapshots carry them. A zone that names neither
// adds nothing.
func (c *scopeCandidates) addZone(zone string) {
	if s, err := encodeZone(zone); err == nil {
		c.add(s)
	}
}

// only returns the one scope id added, or 0 when there were none or
// several.
func (c *scopeCandidates) only() uint32 {
	if c.n == 1 {
		return c.first
	}
	return 0
}

// --- PathParams ---------------------------------------------------------------

// encodePathParams lays out struct sctp_paddrparams (RFC 6458 §8.1.12) in
// b, which holds sizePathParams bytes, from p: each nil field leaves that
// setting as it is. field names p in errors, such as "PathParams".
//
// Linux takes each switch as an ENABLE/DISABLE pair of spp_flags bits,
// neither bit leaving it alone, and reads a value only together with its
// switch, zero meaning "unchanged" (net/sctp/socket.c:
// sctp_apply_peer_addr_params). So the package refuses, before any system
// call, what Linux would silently ignore: a HeartbeatInterval without
// Heartbeat true, a PathMTU without PMTUD false, a SACKDelay without
// DelayedSACK true, and a zero PathMaxRetrans, PathMTU or SACKDelay. A
// zero HeartbeatInterval is sent with SPP_HB_TIME_IS_ZERO, which is how
// Linux takes a zero interval. It refuses what Linux itself refuses too:
// a PathMTU below SCTP_DEFAULT_MINSEGMENT and a SACKDelay above RFC 9260
// §6.2's 500 ms, as well as a flow label beyond its 20 bits and a DSCP
// outside spp_dscp's 6 most significant bits (RFC 6458 §8.1.12), which
// Linux would mask away.
func encodePathParams(b []byte, assoc AssocID, addr []byte, p *PathParams, field string) error {
	b = b[:sizePathParams]
	clear(b)
	var flags uint32
	if p.Heartbeat != nil {
		flags |= onOff(*p.Heartbeat, sppHBEnable, sppHBDisable)
	}
	if p.HeartbeatInterval != nil {
		if p.Heartbeat == nil || !*p.Heartbeat {
			return invalidArg("%s.HeartbeatInterval needs %s.Heartbeat set to true in the same call: Linux applies the interval only when heartbeats are switched on (net/sctp/socket.c: sctp_apply_peer_addr_params)", field, field)
		}
		ms, err := durationToMillis(field+".HeartbeatInterval", *p.HeartbeatInterval, math.MaxUint32)
		if err != nil {
			return err
		}
		if ms == 0 {
			flags |= sppHBTimeIsZero
		}
		binary.NativeEndian.PutUint32(b[pathParamsHBIntervalOff:], ms)
	}
	if p.PathMaxRetrans != nil {
		if *p.PathMaxRetrans == 0 {
			return invalidArg("%s.PathMaxRetrans is 0, which Linux reads as leaving the value unchanged", field)
		}
		binary.NativeEndian.PutUint16(b[pathParamsPathMaxRxtOff:], *p.PathMaxRetrans)
	}
	if p.PMTUD != nil {
		flags |= onOff(*p.PMTUD, sppPMTUDEnable, sppPMTUDDisable)
	}
	if p.PathMTU != nil {
		if p.PMTUD == nil || *p.PMTUD {
			return invalidArg("%s.PathMTU needs %s.PMTUD set to false in the same call: Linux applies a fixed path MTU only when path MTU discovery is switched off (net/sctp/socket.c: sctp_apply_peer_addr_params)", field, field)
		}
		if *p.PathMTU < minPathMTU {
			return invalidArg("%s.PathMTU %d is below the %d bytes Linux accepts (SCTP_DEFAULT_MINSEGMENT)", field, *p.PathMTU, minPathMTU)
		}
		binary.NativeEndian.PutUint32(b[pathParamsPathMTUOff:], *p.PathMTU)
	}
	if p.DelayedSACK != nil {
		flags |= onOff(*p.DelayedSACK, sppSACKDelayEnable, sppSACKDelayDisable)
	}
	if p.SACKDelay != nil {
		if p.DelayedSACK == nil || !*p.DelayedSACK {
			return invalidArg("%s.SACKDelay needs %s.DelayedSACK set to true in the same call: Linux applies the delay only when delayed SACK is switched on (net/sctp/socket.c: sctp_apply_peer_addr_params)", field, field)
		}
		ms, err := durationToMillis(field+".SACKDelay", *p.SACKDelay, math.MaxUint32)
		if err != nil {
			return err
		}
		if ms == 0 {
			return invalidArg("%s.SACKDelay is 0, which Linux reads as leaving the delay unchanged", field)
		}
		if ms > maxSACKDelayMS {
			return invalidArg("%s.SACKDelay %s exceeds RFC 9260 §6.2's 500 ms maximum", field, *p.SACKDelay)
		}
		binary.NativeEndian.PutUint32(b[pathParamsSackDelayOff:], ms)
	}
	if p.IPv6FlowLabel != nil {
		if *p.IPv6FlowLabel&^flowLabelMask != 0 {
			return invalidArg("%s.IPv6FlowLabel %#x does not fit the 20 bits of an IPv6 flow label (RFC 6458 §8.1.12)", field, *p.IPv6FlowLabel)
		}
		flags |= sppIPv6FlowLabel
		binary.NativeEndian.PutUint32(b[pathParamsFlowLabelOff:], *p.IPv6FlowLabel)
	}
	if p.DSCP != nil {
		if *p.DSCP&^dscpMask != 0 {
			return invalidArg("%s.DSCP %#02x has its low two bits set; spp_dscp carries the DSCP in its 6 most significant bits (RFC 6458 §8.1.12), so code point n is n<<2", field, *p.DSCP)
		}
		flags |= sppDSCP
		b[pathParamsDSCPOff] = *p.DSCP
	}
	binary.NativeEndian.PutUint32(b[pathParamsAssocIDOff:], uint32(assoc))
	copy(b[pathParamsAddressOff:pathParamsAddressOff+sizeSockaddrStorage], addr)
	binary.NativeEndian.PutUint32(b[pathParamsFlagsOff:], flags)
	return nil
}

// onOff picks the ENABLE or the DISABLE bit of a spp_flags pair.
func onOff(on bool, enable, disable uint32) uint32 {
	if on {
		return enable
	}
	return disable
}

// heartbeatDemand lays out the struct sctp_paddrparams that asks for a
// HEARTBEAT now (SPP_HB_DEMAND) and changes nothing else. With the zero
// address Linux sends one on every path of the association
// (net/sctp/socket.c: sctp_setsockopt_peer_addr_params applies the flags
// to each transport).
func heartbeatDemand(b []byte, assoc AssocID, addr []byte) {
	b = b[:sizePathParams]
	clear(b)
	binary.NativeEndian.PutUint32(b[pathParamsAssocIDOff:], uint32(assoc))
	copy(b[pathParamsAddressOff:pathParamsAddressOff+sizeSockaddrStorage], addr)
	binary.NativeEndian.PutUint32(b[pathParamsFlagsOff:], sppHBDemand)
}

// decodePathParams reads the struct sctp_paddrparams Linux returns, with
// every field set except IPv6FlowLabel and DSCP: Linux reports those, and
// sets SPP_IPV6_FLOWLABEL or SPP_DSCP, only once a value has been set
// through SCTP (net/sctp/socket.c: sctp_getsockopt_peer_addr_params), and
// they are nil otherwise.
func decodePathParams(b []byte) *PathParams {
	flags := binary.NativeEndian.Uint32(b[pathParamsFlagsOff:])
	hb := flags&sppHBEnable != 0
	pmtud := flags&sppPMTUDEnable != 0
	sack := flags&sppSACKDelayEnable != 0
	interval := millisToDuration(binary.NativeEndian.Uint32(b[pathParamsHBIntervalOff:]))
	retrans := binary.NativeEndian.Uint16(b[pathParamsPathMaxRxtOff:])
	mtu := binary.NativeEndian.Uint32(b[pathParamsPathMTUOff:])
	delay := millisToDuration(binary.NativeEndian.Uint32(b[pathParamsSackDelayOff:]))
	p := &PathParams{
		Heartbeat:         &hb,
		HeartbeatInterval: &interval,
		PathMaxRetrans:    &retrans,
		PMTUD:             &pmtud,
		PathMTU:           &mtu,
		DelayedSACK:       &sack,
		SACKDelay:         &delay,
	}
	if flags&sppIPv6FlowLabel != 0 {
		label := binary.NativeEndian.Uint32(b[pathParamsFlowLabelOff:])
		p.IPv6FlowLabel = &label
	}
	if flags&sppDSCP != 0 {
		dscp := b[pathParamsDSCPOff]
		p.DSCP = &dscp
	}
	return p
}

// --- thresholds ------------------------------------------------------------------

// mergePathThresholds lays t over cur, the thresholds read from the
// kernel: a nil field keeps cur's value. Linux applies spt_pathpfthld and
// spt_pathcpthld whatever they hold (net/sctp/socket.c:
// sctp_setsockopt_paddr_thresholds), so the only way to leave one alone is
// to send it back as it is. A zero PathMaxRetrans is refused, since Linux
// reads it as leaving the value unchanged.
func mergePathThresholds(cur thresholdValues, t *PathThresholds, field string) (thresholdValues, error) {
	if t.PathMaxRetrans != nil {
		if *t.PathMaxRetrans == 0 {
			return cur, invalidArg("%s.PathMaxRetrans is 0, which Linux reads as leaving the value unchanged", field)
		}
		cur.maxRetrans = *t.PathMaxRetrans
	}
	if t.PFThreshold != nil {
		cur.pf = *t.PFThreshold
	}
	if t.PrimarySwitchover != nil {
		cur.switchover = *t.PrimarySwitchover
	}
	return cur, nil
}

// --- association structs -------------------------------------------------------

// decodePathInfo reads struct sctp_paddrinfo (RFC 6458 §8.2.2) from b,
// which starts at the struct. spinfo_srtt is copied as it is, in kernel
// ticks (net/sctp/socket.c: sctp_getsockopt_peer_addr_info copies
// transport->srtt), while spinfo_rto is in milliseconds
// (jiffies_to_msecs).
func decodePathInfo(b []byte) PathInfo {
	var addr netip.AddrPort
	if a, err := decodeAddr(b[pathInfoAddressOff : pathInfoAddressOff+sizeSockaddrStorage]); err == nil {
		addr = a
	}
	return PathInfo{
		Addr:      addr,
		State:     PathState(int32(binary.NativeEndian.Uint32(b[pathInfoStateOff:]))),
		Cwnd:      binary.NativeEndian.Uint32(b[pathInfoCwndOff:]),
		SRTTTicks: binary.NativeEndian.Uint32(b[pathInfoSRTTOff:]),
		RTO:       millisToDuration(binary.NativeEndian.Uint32(b[pathInfoRTOOff:])),
		MTU:       binary.NativeEndian.Uint32(b[pathInfoMTUOff:]),
	}
}

// decodeStatus reads struct sctp_status (RFC 6458 §8.2.1).
func decodeStatus(b []byte) Status {
	return Status{
		State:              AssocState(int32(binary.NativeEndian.Uint32(b[statusStateOff:]))),
		PeerRwnd:           binary.NativeEndian.Uint32(b[statusRWNDOff:]),
		Unacked:            binary.NativeEndian.Uint16(b[statusUnackedOff:]),
		Pending:            binary.NativeEndian.Uint16(b[statusPendingOff:]),
		InStreams:          binary.NativeEndian.Uint16(b[statusInStreamsOff:]),
		OutStreams:         binary.NativeEndian.Uint16(b[statusOutStreamsOff:]),
		FragmentationPoint: binary.NativeEndian.Uint32(b[statusFragmentationPointOff:]),
		Primary:            decodePathInfo(b[statusPrimaryOff : statusPrimaryOff+sizePathInfo]),
	}
}

// encodeRTOInfo lays out struct sctp_rtoinfo (RFC 6458 §8.1.1) from r,
// checked the way Config.RTOInfo is: whole milliseconds within the __u32
// fields, and Min no larger than Max when both are set. A zero field
// leaves that value unchanged (net/sctp/socket.c: sctp_setsockopt_rtoinfo).
func encodeRTOInfo(b []byte, assoc AssocID, r *RTOInfo, field string) error {
	initial, err := durationToMillis(field+".Initial", r.Initial, math.MaxUint32)
	if err != nil {
		return err
	}
	maxMS, err := durationToMillis(field+".Max", r.Max, math.MaxUint32)
	if err != nil {
		return err
	}
	minMS, err := durationToMillis(field+".Min", r.Min, math.MaxUint32)
	if err != nil {
		return err
	}
	if minMS != 0 && maxMS != 0 && minMS > maxMS {
		return invalidArg("%s.Min %s exceeds %s.Max %s (net/sctp/socket.c: sctp_setsockopt_rtoinfo)", field, r.Min, field, r.Max)
	}
	b = b[:sizeRTOInfo]
	binary.NativeEndian.PutUint32(b[rtoInfoAssocIDOff:], uint32(assoc))
	binary.NativeEndian.PutUint32(b[rtoInfoInitialOff:], initial)
	binary.NativeEndian.PutUint32(b[rtoInfoMaxOff:], maxMS)
	binary.NativeEndian.PutUint32(b[rtoInfoMinOff:], minMS)
	return nil
}

// decodeRTOInfo reads struct sctp_rtoinfo.
func decodeRTOInfo(b []byte) RTOInfo {
	return RTOInfo{
		Initial: millisToDuration(binary.NativeEndian.Uint32(b[rtoInfoInitialOff:])),
		Max:     millisToDuration(binary.NativeEndian.Uint32(b[rtoInfoMaxOff:])),
		Min:     millisToDuration(binary.NativeEndian.Uint32(b[rtoInfoMinOff:])),
	}
}

// encodeAssocInfo lays out struct sctp_assocparams (RFC 6458 §8.1.2) from
// a's two settable fields; the read-only ones are left zero, as Linux
// ignores them (net/sctp/socket.c: sctp_setsockopt_associnfo), and a zero
// MaxRetrans or CookieLife leaves that value unchanged.
func encodeAssocInfo(b []byte, assoc AssocID, a *AssocInfo, field string) error {
	cookie, err := durationToMillis(field+".CookieLife", a.CookieLife, math.MaxUint32)
	if err != nil {
		return err
	}
	b = b[:sizeAssocInfo]
	clear(b)
	binary.NativeEndian.PutUint32(b[assocInfoAssocIDOff:], uint32(assoc))
	binary.NativeEndian.PutUint16(b[assocInfoMaxRetransOff:], a.MaxRetrans)
	binary.NativeEndian.PutUint32(b[assocInfoCookieLifeOff:], cookie)
	return nil
}

// decodeAssocInfo reads struct sctp_assocparams.
func decodeAssocInfo(b []byte) AssocInfo {
	return AssocInfo{
		MaxRetrans:       binary.NativeEndian.Uint16(b[assocInfoMaxRetransOff:]),
		CookieLife:       millisToDuration(binary.NativeEndian.Uint32(b[assocInfoCookieLifeOff:])),
		PeerDestinations: binary.NativeEndian.Uint16(b[assocInfoPeerDestinationsOff:]),
		PeerRwnd:         binary.NativeEndian.Uint32(b[assocInfoPeerRwndOff:]),
		LocalRwnd:        binary.NativeEndian.Uint32(b[assocInfoLocalRwndOff:]),
	}
}

// encodeDelayedSACK lays out struct sctp_sack_info (RFC 6458 §8.1.19) from
// d, checked the way Config.DelayedSACK is: the delay in whole
// milliseconds, at most 500 ms (RFC 9260 §6.2).
func encodeDelayedSACK(b []byte, assoc AssocID, d *DelayedSACK, field string) error {
	delay, err := durationToMillis(field+".Delay", d.Delay, math.MaxUint32)
	if err != nil {
		return err
	}
	if delay > maxSACKDelayMS {
		return invalidArg("%s.Delay %s exceeds RFC 9260 §6.2's 500 ms maximum", field, d.Delay)
	}
	b = b[:sizeDelayedSACK]
	binary.NativeEndian.PutUint32(b[delayedSACKAssocIDOff:], uint32(assoc))
	binary.NativeEndian.PutUint32(b[delayedSACKDelayOff:], delay)
	binary.NativeEndian.PutUint32(b[delayedSACKFrequencyOff:], d.Frequency)
	return nil
}

// decodeDelayedSACK reads struct sctp_sack_info. With delayed SACK off
// Linux reports a delay of 0 and a frequency of 1 (net/sctp/socket.c:
// sctp_getsockopt_delayed_ack).
func decodeDelayedSACK(b []byte) DelayedSACK {
	return DelayedSACK{
		Delay:     millisToDuration(binary.NativeEndian.Uint32(b[delayedSACKDelayOff:])),
		Frequency: binary.NativeEndian.Uint32(b[delayedSACKFrequencyOff:]),
	}
}

// decodeInitMsg reads struct sctp_initmsg (RFC 6458 §8.1.3).
func decodeInitMsg(b []byte) InitMsg {
	return InitMsg{
		OutStreams:     binary.NativeEndian.Uint16(b[initMsgOutStreamsOff:]),
		MaxInStreams:   binary.NativeEndian.Uint16(b[initMsgMaxInStreamsOff:]),
		MaxAttempts:    binary.NativeEndian.Uint16(b[initMsgMaxAttemptsOff:]),
		MaxInitTimeout: millisToDuration(uint32(binary.NativeEndian.Uint16(b[initMsgMaxInitTimeoOff:]))),
	}
}

// --- authentication ------------------------------------------------------------

// decodeHMACIdents reads struct sctp_hmacalgo (RFC 6458 §8.1.17): a __u32
// count and that many __u16 identifiers, in the endpoint's order of
// preference. n is the length the kernel reported, and the count must
// account for exactly the identifiers that length holds: a reply where the
// two disagree is malformed and refused rather than clamped (v1
// parseHmacIdents, git show main:sctp.go).
func decodeHMACIdents(b []byte, n int) ([]HMACID, error) {
	if n < sizeHMACAlgo || n > len(b) {
		return nil, fmt.Errorf("sctp: SCTP_HMAC_IDENT returned %d bytes, which is not a struct sctp_hmacalgo in a %d-byte buffer", n, len(b))
	}
	if (n-sizeHMACAlgo)%2 != 0 {
		return nil, fmt.Errorf("sctp: SCTP_HMAC_IDENT returned an odd %d-byte identifier list", n-sizeHMACAlgo)
	}
	count := binary.NativeEndian.Uint32(b[hmacAlgoNumIdentsOff:])
	if count != uint32((n-sizeHMACAlgo)/2) {
		return nil, fmt.Errorf("sctp: SCTP_HMAC_IDENT reports %d identifiers in %d bytes", count, n)
	}
	ids := make([]HMACID, count)
	for i := range ids {
		ids[i] = HMACID(binary.NativeEndian.Uint16(b[hmacAlgoIdentsOff+2*i:]))
	}
	return ids, nil
}

// decodeAuthChunks reads struct sctp_authchunks (RFC 6458 §§8.2.3-8.2.4):
// an association id, a __u32 count, and that many chunk types. Neither
// header field is part of the list, and the count must agree with the
// length the kernel reported, n (v1 parseAuthChunks, git show
// main:sctp.go).
func decodeAuthChunks(b []byte, n int) ([]uint8, error) {
	if n < sizeAuthChunks || n > len(b) {
		return nil, fmt.Errorf("sctp: the AUTH chunk list option returned %d bytes, which is not a struct sctp_authchunks in a %d-byte buffer", n, len(b))
	}
	count := binary.NativeEndian.Uint32(b[authChunksNumChunksOff:])
	if count != uint32(n-sizeAuthChunks) {
		return nil, fmt.Errorf("sctp: the AUTH chunk list option reports %d chunk types in %d bytes", count, n)
	}
	return append([]uint8{}, b[authChunksChunksOff:n]...), nil
}

// encodeAuthKey lays out struct sctp_authkey (RFC 6458 §8.3.3) for key
// number key with secret, which the caller clears once the system call has
// read it. An empty secret, which Linux refuses (net/sctp/socket.c:
// sctp_setsockopt_auth_key requires an optlen larger than the header), and
// one longer than the 65535 bytes sca_keylength can describe are refused
// here, naming name.
func encodeAuthKey(assoc AssocID, key uint16, secret []byte, name string) ([]byte, error) {
	if len(secret) == 0 {
		return nil, invalidArg("%s: the secret is empty; Linux refuses a zero-length key (net/sctp/socket.c: sctp_setsockopt_auth_key), and DeleteAuthKey removes one", name)
	}
	if len(secret) > math.MaxUint16 {
		return nil, invalidArg("%s: the secret is %d bytes, more than the 65535 sca_keylength can describe", name, len(secret))
	}
	b := make([]byte, sizeAuthKey+len(secret))
	binary.NativeEndian.PutUint32(b[authKeyAssocIDOff:], uint32(assoc))
	binary.NativeEndian.PutUint16(b[authKeyKeyNumberOff:], key)
	binary.NativeEndian.PutUint16(b[authKeyKeyLengthOff:], uint16(len(secret)))
	copy(b[authKeyKeyOff:], secret)
	return b, nil
}

// --- stream reconfiguration ---------------------------------------------------

// encodeResetStreams lays out struct sctp_reset_streams (RFC 6525
// §6.3.2): the association id, the direction flags, the stream
// count, then the stream ids, none meaning every stream. It is built as
// bytes because the C struct ends in a flexible array that must follow the
// header in one buffer. A direction naming neither ResetIncoming nor
// ResetOutgoing, one with any other bit, and more streams than the __u16
// count can name are refused.
func encodeResetStreams(assoc AssocID, dir ResetDirection, streams []uint16) ([]byte, error) {
	if dir&^(ResetIncoming|ResetOutgoing) != 0 {
		return nil, invalidArg("ResetStreams: direction %#x has unknown bits %#x", uint16(dir), uint16(dir&^(ResetIncoming|ResetOutgoing)))
	}
	if dir == 0 {
		return nil, invalidArg("ResetStreams: the direction needs at least one of ResetIncoming and ResetOutgoing")
	}
	if len(streams) > math.MaxUint16 {
		return nil, invalidArg("ResetStreams: %d streams exceeds the %d a request can name", len(streams), math.MaxUint16)
	}
	b := make([]byte, sizeResetStreams+2*len(streams))
	binary.NativeEndian.PutUint32(b[resetStreamsAssocIDOff:], uint32(assoc))
	binary.NativeEndian.PutUint16(b[resetStreamsFlagsOff:], uint16(dir))
	binary.NativeEndian.PutUint16(b[resetStreamsNumStreamsOff:], uint16(len(streams)))
	for i, sid := range streams {
		binary.NativeEndian.PutUint16(b[resetStreamsStreamListOff+2*i:], sid)
	}
	return b, nil
}

// --- partial reliability ---------------------------------------------------------

// validateStatusPolicy checks the policy of a PR-SCTP status query (RFC
// 7496 §§4.3-4.4): one of PRTTL, PRRtx and PRPrio, or PRAll for the total
// across them, as Linux accepts (net/sctp/socket.c:
// sctp_getsockopt_pr_assocstatus, sctp_getsockopt_pr_streamstatus).
func validateStatusPolicy(name string, p PRPolicy) error {
	switch p {
	case PRTTL, PRRtx, PRPrio, PRAll:
		return nil
	default:
		return invalidArg("%s: policy %v is not PRTTL, PRRtx, PRPrio or PRAll", name, p)
	}
}

// prStatusRequest lays out the struct sctp_prstatus request for stream
// and policy.
func prStatusRequest(b []byte, assoc AssocID, stream uint16, policy PRPolicy) {
	b = b[:sizePRStatus]
	clear(b)
	binary.NativeEndian.PutUint32(b[prStatusAssocIDOff:], uint32(assoc))
	binary.NativeEndian.PutUint16(b[prStatusStreamOff:], stream)
	binary.NativeEndian.PutUint16(b[prStatusPolicyOff:], uint16(policy))
}

// decodePRStatus reads the counts of struct sctp_prstatus.
func decodePRStatus(b []byte) PRStatus {
	return PRStatus{
		AbandonedUnsent: binary.NativeEndian.Uint64(b[prStatusAbandonedUnsentOff:]),
		AbandonedSent:   binary.NativeEndian.Uint64(b[prStatusAbandonedSentOff:]),
	}
}
