// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// config.go declares Config, the settings a caller chooses before a socket
// exists, and prepare, which turns one into an immutable, validated
// snapshot for a single constructor call: a prepared value. Every check
// here runs before any system call, so a mistake is reported as an error
// that matches syscall.EINVAL and names the field, never as a kernel EINVAL
// with no indication of which setting caused it.
//
// prepare's job ends at the ordered list of operations a prepared value
// carries (configOp, configOpKind): each one already holds its
// kernel-shaped value (a whole millisecond count, a raw flag word, a copied
// slice), but writing it to a descriptor — the setsockopt calls themselves
// — belongs to the platform-specific code that consumes a prepared value.

package sctp

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"syscall"
	"time"
)

// socketStyle is the shape of socket a Config is being prepared for. It
// controls which fields prepare accepts and what a nil FragmentInterleave
// or AbandonPolicy resolves to.
type socketStyle uint8

const (
	styleDial           socketStyle = iota // Config.Dial: one-to-one, connects
	styleListen                            // Config.Listen: one-to-one, accepts
	styleListenEndpoint                    // Config.ListenEndpoint: one-to-many, accepts
	styleOpenEndpoint                      // Config.OpenEndpoint: one-to-many, connect only
	styleFile                              // Config.FileConn, Config.FileListener: adopts an existing descriptor
)

// isEndpoint reports whether s is one of the two one-to-many styles, which
// RFC 6458 §8.1.20 recommends default to FragmentInterleave InterleaveAssocs
// and which never accept ReusePort (RFC 6458 §8.1.27, one-to-one only).
func (s socketStyle) isEndpoint() bool {
	return s == styleListenEndpoint || s == styleOpenEndpoint
}

// String names s for a validation error's text; a value prepare never
// produces itself still renders rather than panicking some other caller's
// %v.
func (s socketStyle) String() string {
	switch s {
	case styleDial:
		return "Dial"
	case styleListen:
		return "Listen"
	case styleListenEndpoint:
		return "ListenEndpoint"
	case styleOpenEndpoint:
		return "OpenEndpoint"
	case styleFile:
		return "FileConn or FileListener"
	default:
		return fmt.Sprintf("socketStyle(%d)", uint8(s))
	}
}

// Config holds everything that must be decided before a socket is bound or
// connected. The zero Config uses kernel defaults throughout. A Config may be
// reused; it must not be modified while a call that uses it is running.
//
// Every constructor checks the Config before it creates a socket. A field
// that is out of range, that conflicts with another field, or that the
// constructor cannot apply (such as ReusePort on an Endpoint, or an
// AbandonPolicy outside Dial) is refused with an error that matches
// syscall.EINVAL and names the field. Nothing is silently ignored.
//
// Order of application: the socket is created, then Control runs, then the
// package enables SCTP_RECVRCVINFO and applies the typed settings in this
// order, so that each finds its prerequisites in place: ReadBuffer,
// WriteBuffer, InitMsg, FragmentInterleave, Authentication, HMACIdentifiers,
// AuthChunks, DynamicAddressReconfiguration, PartialReliability,
// StreamReconfiguration, StreamResetMask, MessageInterleaving,
// ExperimentalECN, AdaptationLayer, RTOInfo, DelayedSACK, FragmentsDisabled,
// ReusePort, ReceiveNxtInfo, NoDelay, DefaultSndInfo, DefaultPrInfo,
// Notifications. Typed settings therefore win over anything Control wrote.
// Then the socket is bound, and connected or put in listening state.
type Config struct {
	// Control is called with the new socket before any typed setting is
	// applied. As for net.Dialer and net.ListenConfig, network is the
	// network the call names ("sctp" for an empty one), and address is the
	// remote address for Dial and the local one for Listen, ListenEndpoint
	// and OpenEndpoint, "" when there is none. c supports Control only: its Read and Write return
	// syscall.EINVAL, since nothing can be sent or received yet. An error
	// Control returns ends the constructor, which closes the socket.
	Control func(network, address string, c syscall.RawConn) error

	// NotificationHandler, when set, receives every notification before a read
	// returns. Every connection a Listener accepts, or an Endpoint
	// peels off, uses the handler of the Config that created it, as in v1.
	NotificationHandler NotificationHandler

	// CloseTimeout is how long Conn.Close and Endpoint.Close wait for the
	// graceful shutdown before they abort. Zero means 3 s, as in v1;
	// negative is refused. Accepted and peeled-off connections use the value
	// of the Config that created their Listener or Endpoint.
	CloseTimeout time.Duration

	// AbandonPolicy says how Dial releases an association that has not reached
	// ESTABLISHED when ctx ends or setup fails. Dial only.
	AbandonPolicy AbandonPolicy

	// "Requires X" below means X must be set to true in the same Config.
	// Linux refuses the AUTH lists with EACCES while AUTH is off
	// (net/sctp/socket.c), and RFC 5061 §4.1.1 requires ASCONF chunks to be
	// authenticated. Requiring the field, rather than relying on a
	// net.sctp.auth_enable default, keeps the outcome independent of the
	// host's sysctls, as in v1.

	// Announced in the INIT.
	InitMsg         InitMsg  // RFC 6458 §8.1.3
	AdaptationLayer *uint32  // RFC 6458 §8.1.10
	HMACIdentifiers []HMACID // RFC 4895 §§3.3, 6.1; must include HMACSHA1; requires Authentication
	AuthChunks      []uint8  // RFC 4895 §§3.2, 6.1; chunk types to require AUTH on; requires Authentication

	// Extensions negotiated in the INIT.
	PartialReliability            *bool // PR-SCTP (RFC 3758), with the policies of RFC 7496 §4.5
	StreamReconfiguration         *bool // RFC 6525 (Linux's negotiation switch)
	DynamicAddressReconfiguration *bool // ASCONF, RFC 5061; requires Authentication (RFC 5061 §§4.1.1-4.1.2)
	Authentication                *bool // AUTH, RFC 4895
	ExperimentalECN               *bool // Linux-only; RFC 9260 §1.7 removed the ECN appendix, and the chunk and parameter types stay reserved (§§3.2, 3.3.2)

	// MessageInterleaving offers I-DATA (RFC 8260). It is a plain bool
	// because Linux always starts with it off and refuses the option with
	// EPERM, even to switch it off, unless the net.sctp.intl_enable sysctl is
	// on (sctp_setsockopt_interleaving_supported). true requires a
	// FragmentInterleave of at least InterleaveAssocs, which is already the
	// default on an Endpoint, and the sysctl; without the sysctl the
	// constructor fails with an error matching syscall.EPERM.
	MessageInterleaving bool

	// Socket buffers (SO_RCVBUF, SO_SNDBUF). They are pre-association settings:
	// Linux sets an association's receive window from the receive buffer when
	// the association is created, and the INIT or INIT ACK announces it
	// (RFC 9260 §§3.3.2-3.3.3). Accepted sockets inherit the listener's sizes.
	//
	// Linux caps each value at net.core.rmem_max or net.core.wmem_max and then
	// doubles it, to allow for its own bookkeeping (net/core/sock.c), and
	// ReadBuffer and WriteBuffer report the doubled size. The association's
	// window is half the receive buffer (sctp_association_init), so it equals
	// the value set here, and it is never less than 1500 bytes
	// (SCTP_DEFAULT_MINWINDOW), the smallest a peer accepts (RFC 9260 §3.3.3,
	// Verified Erratum 7148). A message larger than the doubled send buffer is
	// refused with EMSGSIZE.
	ReadBuffer  *int
	WriteBuffer *int

	// Socket defaults. They also have setters on Conn, but set here they apply
	// before the first message and are copied to every accepted connection.
	NoDelay        *bool    // SCTP_NODELAY, RFC 6458 §8.1.5
	DefaultSndInfo *SndInfo // SCTP_DEFAULT_SNDINFO, RFC 6458 §8.1.31; used by Write and by a nil SendOptions.Info
	DefaultPrInfo  *PrInfo  // SCTP_DEFAULT_PRINFO, RFC 6458 §8.1.32; used by Write and by a nil SendOptions.PR

	// Socket behaviour.
	ReusePort          *bool               // RFC 6458 §8.1.27; one-to-one sockets only
	FragmentsDisabled  *bool               // RFC 6458 §8.1.11
	FragmentInterleave *FragmentInterleave // RFC 6458 §8.1.20; nil on an Endpoint means InterleaveAssocs
	ReceiveNxtInfo     *bool               // RFC 6458 §8.1.30
	StreamResetMask    *StreamResetMask    // RFC 6525 §6.3; non-zero requires StreamReconfiguration
	RTOInfo            *RTOInfo            // RFC 6458 §8.1.1
	DelayedSACK        *DelayedSACK        // RFC 6458 §8.1.19; Delay at most 500 ms (RFC 9260 §6.2)

	// Notifications the caller receives, subscribed at creation, before bind,
	// connect or listen (RFC 6458 §6.2.2). Linux starts every socket with
	// none. The package also keeps EventAssocChange subscribed in the kernel
	// on every socket, because it is how the package learns that an
	// association has ended. On a Conn those records are consumed by
	// the package and never delivered unless EventAssocChange is listed here
	// or subscribed later. An Endpoint always delivers them, since its callers
	// route by association id.
	Notifications []EventType
}

// configOpKind identifies one operation prepare produces, in the order
// Config's own doc comment states. opRecvRcvInfo and opAssocChange are not
// part of that order: they are the two operations prepare always emits
// first, on every style including styleFile, because the package's receive
// path depends on both regardless of what Config asked for — RCVINFO to
// read the association metadata every message carries, and ASSOC_CHANGE to
// notice an association ending at all. On a one-to-one or peeled socket,
// Linux sets the socket error once when an association fails
// (net/sctp/sm_sideeffect.c: sctp_cmd_set_sk_err — it does nothing at all
// for a one-to-many socket, "if (!sctp_style(sk, UDP)) sk->sk_err =
// error;"), and the first read or send after that consumes it; every
// descriptor this package uses is non-blocking, so once the error is
// consumed a later read finds nothing — no error, no queued data, nothing
// to report — and a reader already parked waiting for one would never
// wake. The queued ASSOC_CHANGE record this internal subscription produces
// is what wakes it.
type configOpKind uint8

const (
	opRecvRcvInfo configOpKind = iota
	opAssocChange

	opReadBuffer
	opWriteBuffer
	opInitMsg
	opFragmentInterleave
	opAuthentication
	opHMACIdentifiers
	opAuthChunk
	opDynamicAddressReconfiguration
	opPartialReliability
	opStreamReconfiguration
	opStreamResetMask
	opMessageInterleaving
	opExperimentalECN
	opAdaptationLayer
	opRTOInfo
	opDelayedSACK
	opFragmentsDisabled
	opReusePort
	opReceiveNxtInfo
	opNoDelay
	opDefaultSndInfo
	opDefaultPrInfo
	opNotification
)

// configOp is one operation a prepared value carries: applying a validated
// Config to a descriptor with a single setsockopt, or one piece of internal
// bookkeeping. Every payload field is already in the unit and width the
// kernel field takes (a whole millisecond count, a raw flag word, a copied
// slice) — never a time.Duration and never an unvalidated caller value — so
// applying an op needs no further conversion, only a switch on kind.
type configOp struct {
	kind configOpKind

	// on carries every *bool setting this package models as a single kernel
	// boolean: Authentication, PartialReliability, StreamReconfiguration,
	// DynamicAddressReconfiguration, MessageInterleaving, ExperimentalECN,
	// FragmentsDisabled, ReusePort, ReceiveNxtInfo, NoDelay.
	on bool

	// bytes is ReadBuffer/WriteBuffer, already checked to fit SO_RCVBUF and
	// SO_SNDBUF's own width: a plain C int (net/core/sock.c: sk_setsockopt
	// copies optval into "int val").
	bytes int32

	u32   uint32 // AdaptationLayer, StreamResetMask
	chunk uint8  // one AuthChunks entry
	level FragmentInterleave
	event EventType // one Notifications entry

	outStreams, maxInStreams, maxAttempts uint16
	maxInitTimeoutMS                      uint32 // InitMsg; fits a uint16 kernel field

	initialMS, maxMS, minMS uint32 // RTOInfo

	delayMS   uint32 // DelayedSACK
	frequency uint32 // DelayedSACK

	hmacIdentifiers []HMACID

	// DefaultSndInfo (opDefaultSndInfo): struct sctp_sndinfo's fields, each
	// already in the exact form a native-order write puts on the wire —
	// including sndInfoPPID, which is not snd_ppid itself but
	// networkOrderUint32(snd_ppid): the kernel never byte-swaps snd_ppid
	// (RFC 6458 §5.3.4 leaves that to the caller, and Linux holds to it
	// literally — msginfo.go's own file header), so this is the one field
	// here that does not already sit in host order. Pre-swapping it here,
	// rather than teaching the code that applies these ops which field is
	// special, means every configOp field can be written the same way:
	// binary.NativeEndian.Put*.
	sndInfoStream  uint16
	sndInfoFlags   uint16
	sndInfoPPID    uint32
	sndInfoContext uint32

	// DefaultPrInfo (opDefaultPrInfo): struct sctp_default_prinfo's
	// pr_policy and pr_value, already resolved the way the kernel resolves
	// them (resolvePrInfo, options.go) — TTL in whole milliseconds for
	// PRTTL, Value for PRRtx/PRPrio, 0 for PRNone.
	prPolicy uint16
	prValue  uint32
}

// networkOrderUint32 returns v's big-endian byte representation
// reinterpreted as a native-order uint32: the value that, written with
// binary.NativeEndian.PutUint32, lands the same bytes binary.BigEndian.
// PutUint32(v) would have written directly. It exists only to build
// configOp.sndInfoPPID (see that field's own comment) and touches no
// association or socket state.
func networkOrderUint32(v uint32) uint32 {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return binary.NativeEndian.Uint32(b[:])
}

// eventSet is the caller's logical notification subscription, one bit per
// EventType: bit i corresponds to EventType 0x8001+i (enums.go). It never
// reaches the kernel by itself — subscribed below is bookkeeping the receive
// path uses to decide whether a queued record reaches the caller, entirely
// independent of the always-on internal SCTP_ASSOC_CHANGE subscription
// (opAssocChange) that keeps the descriptor readable when an association
// ends.
type eventSet uint16

// eventBit is the single-bit eventSet value for t. It is defined only for
// the EventType constants enums.go names (EventAssocChange through
// EventSendFailed, 0x8001-0x800d), which prepare enforces before calling it.
func eventBit(t EventType) eventSet {
	return eventSet(1) << (uint16(t) - uint16(EventAssocChange))
}

// has reports whether s has t's bit set.
func (s eventSet) has(t EventType) bool { return s&eventBit(t) != 0 }

// prepared is a validated, immutable snapshot of a Config for one
// constructor call: the ordered operations Config's doc comment prescribes,
// plus the package-side fields a constructor needs but that are never
// written to the kernel through a Config-shaped setsockopt.
type prepared struct {
	ops          []configOp
	handler      NotificationHandler
	closeTimeout time.Duration // resolved: 0 → 3 * time.Second
	abandon      AbandonPolicy
	subscribed   eventSet           // caller's logical subscriptions (Notifications, plus EventAssocChange on endpoints)
	fragLevel    FragmentInterleave // the effective level: Config.FragmentInterleave, or InterleaveAssocs on an Endpoint when nil

	// adopted marks the Config form of FileConn and FileListener: the
	// descriptor was set up by someone else, so subscribed says nothing
	// about which notifications its creator asked for, and a connection
	// built from it reads them from the kernel instead.
	adopted bool
}

// streamResetKnownBits is every bit StreamResetMask names (RFC 6525 §6.3);
// prepare refuses any other bit in Config.StreamResetMask.
const streamResetKnownBits = EnableResetStreamReq | EnableResetAssocReq | EnableChangeAssocReq

// authChunkForbiddenNames names the four chunk types (abi.go's chunkType*
// constants, from include/linux/sctp.h's enum sctp_cid)
// net/sctp/socket.c's sctp_setsockopt_auth_chunk refuses outright, with
// EINVAL, before ever reaching sctp_auth_ep_add_chunkid. RFC 4895 §3.2
// says the CHUNKS parameter's chunk list "MUST NOT" include any of the
// four, and that a peer's CHUNKS parameter naming one "MUST be ignored" if
// received; the RFC gives no further reason for the restriction. Linux's
// own local socket API enforces the "MUST NOT" half more strictly than the
// RFC requires, by refusing the value outright at set time rather than
// silently ignoring it.
var authChunkForbiddenNames = map[uint8]string{
	chunkTypeInit:             "INIT",
	chunkTypeInitAck:          "INIT-ACK",
	chunkTypeShutdownComplete: "SHUTDOWN-COMPLETE",
	chunkTypeAuth:             "AUTH",
}

// unsupportedFieldError reports that a Config field's value is not wrong on
// its own terms but unreachable on this platform: it matches ErrUnsupported
// (and, through it, errors.ErrUnsupported) rather than syscall.EINVAL, and
// names the field the way invalidArg's errors do, without also carrying
// ErrUnsupported's own "socket operation unsupported" text a second time —
// wrapping it with invalidArg's "sctp: " message style would otherwise
// stutter ("sctp: Config.X: sctp: socket operation unsupported: ...").
type unsupportedFieldError struct {
	field string
	why   string
}

func (e *unsupportedFieldError) Error() string {
	return fmt.Sprintf("sctp: %s: %s", e.field, e.why)
}

func (e *unsupportedFieldError) Unwrap() error { return ErrUnsupported }

// unsupportedField builds an unsupportedFieldError naming field, with why
// explaining what Linux cannot do.
func unsupportedField(field, why string) error {
	return &unsupportedFieldError{field: field, why: why}
}

// prepare validates c for style and returns the immutable snapshot a
// constructor applies to a real socket. A nil c is treated as a zero
// Config, so that a Config method called on a nil *Config, which is how
// Dial, Listen, ListenEndpoint, OpenEndpoint, FileConn and FileListener
// reach it, never has to special-case it separately. Every
// refusal is built with invalidArg (matching syscall.EINVAL) and names the
// Config field it refused, except FragmentInterleave set to
// InterleaveStreams, which Linux cannot deliver and which prepare refuses
// with an error matching ErrUnsupported instead.
func (c *Config) prepare(style socketStyle) (*prepared, error) {
	if c == nil {
		c = &Config{}
	}

	closeTimeout, err := resolveCloseTimeout(c.CloseTimeout)
	if err != nil {
		return nil, err
	}

	if style == styleFile {
		return prepareFileStyle(c, closeTimeout)
	}

	if c.AbandonPolicy != AbandonAbort && c.AbandonPolicy != AbandonQuiet {
		return nil, invalidArg("Config.AbandonPolicy is %v, not AbandonAbort or AbandonQuiet", c.AbandonPolicy)
	}
	if c.AbandonPolicy != AbandonAbort && style != styleDial {
		return nil, invalidArg("Config.AbandonPolicy is set on a %s Config; it applies only to Dial", style)
	}

	ops := []configOp{{kind: opRecvRcvInfo}, {kind: opAssocChange}}

	if c.ReadBuffer != nil {
		if *c.ReadBuffer <= 0 {
			return nil, invalidArg("Config.ReadBuffer must be positive, got %d", *c.ReadBuffer)
		}
		if *c.ReadBuffer > math.MaxInt32 {
			return nil, invalidArg("Config.ReadBuffer %d exceeds the int32 range SO_RCVBUF takes (net/core/sock.c: sk_setsockopt copies optval into a plain int)", *c.ReadBuffer)
		}
		ops = append(ops, configOp{kind: opReadBuffer, bytes: int32(*c.ReadBuffer)})
	}
	if c.WriteBuffer != nil {
		if *c.WriteBuffer <= 0 {
			return nil, invalidArg("Config.WriteBuffer must be positive, got %d", *c.WriteBuffer)
		}
		if *c.WriteBuffer > math.MaxInt32 {
			return nil, invalidArg("Config.WriteBuffer %d exceeds the int32 range SO_SNDBUF takes (net/core/sock.c: sk_setsockopt copies optval into a plain int)", *c.WriteBuffer)
		}
		ops = append(ops, configOp{kind: opWriteBuffer, bytes: int32(*c.WriteBuffer)})
	}

	if c.InitMsg != (InitMsg{}) {
		// struct sctp_initmsg's sinit_max_init_timeo is __u16
		// (include/uapi/linux/sctp.h), applied through msecs_to_jiffies
		// (net/sctp/associola.c: sctp_association_init), so it is a whole
		// millisecond count that fits 16 bits.
		maxInitTimeoutMS, err := durationToMillis("Config.InitMsg.MaxInitTimeout", c.InitMsg.MaxInitTimeout, math.MaxUint16)
		if err != nil {
			return nil, err
		}
		ops = append(ops, configOp{
			kind:             opInitMsg,
			outStreams:       c.InitMsg.OutStreams,
			maxInStreams:     c.InitMsg.MaxInStreams,
			maxAttempts:      c.InitMsg.MaxAttempts,
			maxInitTimeoutMS: maxInitTimeoutMS,
		})
	}

	fragLevel, err := resolveFragmentInterleave(c, style)
	if err != nil {
		return nil, err
	}
	if c.FragmentInterleave != nil || style.isEndpoint() {
		ops = append(ops, configOp{kind: opFragmentInterleave, level: fragLevel})
	}

	if c.Authentication != nil {
		ops = append(ops, configOp{kind: opAuthentication, on: *c.Authentication})
	}
	authOn := c.Authentication != nil && *c.Authentication

	if c.HMACIdentifiers != nil {
		if !authOn {
			return nil, invalidArg("Config.HMACIdentifiers requires Config.Authentication=true (RFC 4895 §§3.3, 6.1)")
		}
		hasSHA1 := false
		seen := make(map[HMACID]bool, len(c.HMACIdentifiers))
		for i, id := range c.HMACIdentifiers {
			// Linux implements only these two of RFC 4895's registry
			// (net/sctp/auth.c: sctp_hmac_list has no hmac_name for any
			// other id, including the two IDs the registry itself reserves,
			// 0 and 2); sctp_auth_ep_set_hmacs refuses anything else with
			// EOPNOTSUPP, never reaching the endpoint's list.
			if id != HMACSHA1 && id != HMACSHA256 {
				return nil, invalidArg("Config.HMACIdentifiers[%d] is %v, not HMACSHA1 or HMACSHA256 — Linux implements only these two (net/sctp/auth.c: sctp_auth_ep_set_hmacs refuses any other id with EOPNOTSUPP)", i, id)
			}
			if seen[id] {
				return nil, invalidArg("Config.HMACIdentifiers[%d] duplicates identifier %v", i, id)
			}
			seen[id] = true
			if id == HMACSHA1 {
				hasSHA1 = true
			}
		}
		if !hasSHA1 {
			return nil, invalidArg("Config.HMACIdentifiers must include HMACSHA1 (RFC 4895 §§3.3, 6.1)")
		}
		ops = append(ops, configOp{kind: opHMACIdentifiers, hmacIdentifiers: append([]HMACID(nil), c.HMACIdentifiers...)})
	}

	if c.AuthChunks != nil {
		if !authOn {
			return nil, invalidArg("Config.AuthChunks requires Config.Authentication=true")
		}
		seen := make(map[uint8]bool, len(c.AuthChunks))
		for i, ct := range c.AuthChunks {
			if name, forbidden := authChunkForbiddenNames[ct]; forbidden {
				return nil, invalidArg("Config.AuthChunks[%d] is %s (%d), which RFC 4895 §3.2 says MUST NOT be listed", i, name, ct)
			}
			if seen[ct] {
				return nil, invalidArg("Config.AuthChunks[%d] duplicates chunk type %d", i, ct)
			}
			seen[ct] = true
		}

		// sctp_association_init copies the endpoint's own chunk list —
		// which sctp_auth_ep_add_chunkid alone would let grow up to
		// sctpNumChunkTypes (20) entries — into struct sctp_cookie's
		// auth_chunks field, which holds only sctpAuthMaxChunks (16); the
		// copy is a memcpy sized by the source list's own length, not
		// clamped to auth_chunks' capacity, so 17-20 entries overrun it
		// into the very next field (abi.go's sctpAuthMaxChunks comment has
		// the exact citations). This package refuses before ever reaching
		// that state.
		//
		// authOn is already established above, so ASCONF (0xC1) and
		// ASCONF-ACK (0x80) must always be counted too, not only when
		// Config.DynamicAddressReconfiguration is also true:
		// net/sctp/endpointola.c's sctp_endpoint_init seeds
		// ep->asconf_enable straight from the host's net.sctp.addip_enable
		// sysctl at endpoint creation, before any setsockopt runs, and adds
		// both chunk ids right there if ep->auth_enable came up enabled the
		// same way; independently, net/sctp/socket.c's
		// sctp_setsockopt_auth_supported adds both the moment AUTH turns on
		// if ep->asconf_enable is already set (net/sctp/socket.c:4383-4386),
		// and sctp_setsockopt_asconf_supported adds them the other way
		// round, the moment ASCONF turns on if ep->auth_enable is already
		// set (net/sctp/socket.c:4351-4354). This package's own application
		// order always applies Authentication before
		// DynamicAddressReconfiguration, so by the time
		// DynamicAddressReconfiguration would run, Authentication has
		// already had the chance to trigger the add on its own — and a
		// later Config.DynamicAddressReconfiguration=false does not remove
		// what was already added: it only clears ep->asconf_enable, and
		// sctp_auth_ep_add_chunkid has no corresponding removal call
		// anywhere in these paths. Since none of this depends on anything
		// this package's own Config asked for, only on host sysctls this
		// package cannot see, always counting the pair whenever
		// Authentication is true is the only way the outcome stays
		// independent of the host's sysctls, matching every other AUTH
		// prerequisite check above.
		effectiveCount := len(c.AuthChunks)
		var autoAdded []string
		if !seen[chunkTypeASCONF] {
			effectiveCount++
			autoAdded = append(autoAdded, "ASCONF")
		}
		if !seen[chunkTypeASCONFAck] {
			effectiveCount++
			autoAdded = append(autoAdded, "ASCONF-ACK")
		}
		if effectiveCount > sctpAuthMaxChunks {
			if len(autoAdded) > 0 {
				return nil, invalidArg("Config.AuthChunks has %d caller entries plus %s, which Linux adds automatically whenever Config.Authentication is true and they are not already listed — %d total, more than the %d entries an association's own copy of the list holds (SCTP_AUTH_MAX_CHUNKS)", len(c.AuthChunks), strings.Join(autoAdded, " and "), effectiveCount, sctpAuthMaxChunks)
			}
			return nil, invalidArg("Config.AuthChunks has %d entries, more than the %d entries an association's own copy of the list holds (SCTP_AUTH_MAX_CHUNKS)", len(c.AuthChunks), sctpAuthMaxChunks)
		}

		for _, ct := range c.AuthChunks {
			ops = append(ops, configOp{kind: opAuthChunk, chunk: ct})
		}
	}

	if c.DynamicAddressReconfiguration != nil {
		if *c.DynamicAddressReconfiguration && !authOn {
			return nil, invalidArg("Config.DynamicAddressReconfiguration=true requires Config.Authentication=true (RFC 5061 §§4.1.1-4.1.2)")
		}
		ops = append(ops, configOp{kind: opDynamicAddressReconfiguration, on: *c.DynamicAddressReconfiguration})
	}

	if c.PartialReliability != nil {
		ops = append(ops, configOp{kind: opPartialReliability, on: *c.PartialReliability})
	}

	reconfigOn := false
	if c.StreamReconfiguration != nil {
		reconfigOn = *c.StreamReconfiguration
		ops = append(ops, configOp{kind: opStreamReconfiguration, on: reconfigOn})
	}

	if c.StreamResetMask != nil {
		mask := *c.StreamResetMask
		if mask&^streamResetKnownBits != 0 {
			return nil, invalidArg("Config.StreamResetMask %#x has unknown bits %#x", uint32(mask), uint32(mask&^streamResetKnownBits))
		}
		if mask != 0 && !reconfigOn {
			return nil, invalidArg("Config.StreamResetMask is non-zero but Config.StreamReconfiguration is not true (RFC 6525 §6.3)")
		}
		ops = append(ops, configOp{kind: opStreamResetMask, u32: uint32(mask)})
	}

	if c.MessageInterleaving {
		if fragLevel < InterleaveAssocs {
			return nil, invalidArg("Config.MessageInterleaving=true requires an effective Config.FragmentInterleave of at least InterleaveAssocs (RFC 8260; net/sctp/socket.c: sctp_setsockopt_interleaving_supported)")
		}
		ops = append(ops, configOp{kind: opMessageInterleaving, on: true})
	}

	if c.ExperimentalECN != nil {
		ops = append(ops, configOp{kind: opExperimentalECN, on: *c.ExperimentalECN})
	}

	if c.AdaptationLayer != nil {
		ops = append(ops, configOp{kind: opAdaptationLayer, u32: *c.AdaptationLayer})
	}

	if c.RTOInfo != nil {
		initialMS, err := durationToMillis("Config.RTOInfo.Initial", c.RTOInfo.Initial, math.MaxUint32)
		if err != nil {
			return nil, err
		}
		maxMS, err := durationToMillis("Config.RTOInfo.Max", c.RTOInfo.Max, math.MaxUint32)
		if err != nil {
			return nil, err
		}
		minMS, err := durationToMillis("Config.RTOInfo.Min", c.RTOInfo.Min, math.MaxUint32)
		if err != nil {
			return nil, err
		}
		// sctp_setsockopt_rtoinfo (net/sctp/socket.c) computes rto_max and
		// rto_min from srto_max/srto_min when each is non-zero, or falls
		// back to the pre-association default otherwise (read from the
		// live socket), and then refuses rto_min > rto_max. This package
		// has no socket yet to read that fallback default from, so the
		// comparison is only checkable here when both fields are
		// explicitly set (non-zero); the kernel's own fallback case has no
		// portable equivalent. The same function never compares
		// srto_initial against srto_min or srto_max at all — it is applied
		// on its own, guarded only by "if (rtoinfo->srto_initial != 0)" —
		// so this package does not invent that check either.
		if c.RTOInfo.Min != 0 && c.RTOInfo.Max != 0 && minMS > maxMS {
			return nil, invalidArg("Config.RTOInfo.Min %s exceeds Config.RTOInfo.Max %s (net/sctp/socket.c: sctp_setsockopt_rtoinfo)", c.RTOInfo.Min, c.RTOInfo.Max)
		}
		ops = append(ops, configOp{kind: opRTOInfo, initialMS: initialMS, maxMS: maxMS, minMS: minMS})
	}

	if c.DelayedSACK != nil {
		delayMS, err := durationToMillis("Config.DelayedSACK.Delay", c.DelayedSACK.Delay, math.MaxUint32)
		if err != nil {
			return nil, err
		}
		// __sctp_setsockopt_delayed_ack (net/sctp/socket.c) refuses
		// sack_delay above 500 outright; RFC 9260 §6.2 says an
		// implementation MUST NOT allow a larger SACK.Delay.
		if delayMS > 500 {
			return nil, invalidArg("Config.DelayedSACK.Delay %s exceeds RFC 9260 §6.2's 500 ms maximum", c.DelayedSACK.Delay)
		}
		ops = append(ops, configOp{kind: opDelayedSACK, delayMS: delayMS, frequency: c.DelayedSACK.Frequency})
	}

	if c.FragmentsDisabled != nil {
		ops = append(ops, configOp{kind: opFragmentsDisabled, on: *c.FragmentsDisabled})
	}

	if c.ReusePort != nil {
		if style.isEndpoint() {
			return nil, invalidArg("Config.ReusePort applies only to one-to-one sockets (RFC 6458 §8.1.27); refused on an Endpoint")
		}
		ops = append(ops, configOp{kind: opReusePort, on: *c.ReusePort})
	}

	if c.ReceiveNxtInfo != nil {
		ops = append(ops, configOp{kind: opReceiveNxtInfo, on: *c.ReceiveNxtInfo})
	}

	if c.NoDelay != nil {
		ops = append(ops, configOp{kind: opNoDelay, on: *c.NoDelay})
	}

	if c.DefaultSndInfo != nil {
		// sctp_setsockopt_default_sndinfo (net/sctp/socket.c) itself accepts
		// SCTP_UNORDERED | SCTP_ADDR_OVER | SCTP_ABORT | SCTP_EOF; this
		// package narrows a default to the one bit SendFlags exposes as
		// meaningful there (msginfo.go's SndInfo doc comment).
		if err := validateDefaultSndInfo("Config.DefaultSndInfo", c.DefaultSndInfo); err != nil {
			return nil, err
		}
		ops = append(ops, configOp{
			kind:           opDefaultSndInfo,
			sndInfoStream:  c.DefaultSndInfo.Stream,
			sndInfoFlags:   uint16(c.DefaultSndInfo.Flags),
			sndInfoPPID:    networkOrderUint32(c.DefaultSndInfo.PPID),
			sndInfoContext: c.DefaultSndInfo.Context,
		})
	}

	if c.DefaultPrInfo != nil {
		if err := validatePrInfo("Config.DefaultPrInfo", c.DefaultPrInfo); err != nil {
			return nil, err
		}
		policy, value := resolvePrInfo(c.DefaultPrInfo)
		ops = append(ops, configOp{kind: opDefaultPrInfo, prPolicy: policy, prValue: value})
	}

	subscribed, err := buildSubscriptions(c.Notifications, &ops)
	if err != nil {
		return nil, err
	}
	if style.isEndpoint() {
		subscribed |= eventBit(EventAssocChange)
	}

	return &prepared{
		ops:          ops,
		handler:      c.NotificationHandler,
		closeTimeout: closeTimeout,
		abandon:      c.AbandonPolicy,
		subscribed:   subscribed,
		fragLevel:    fragLevel,
	}, nil
}

// resolveCloseTimeout applies Config.CloseTimeout's own doc: negative is
// refused, and zero resolves to 3 s (v1's default).
func resolveCloseTimeout(d time.Duration) (time.Duration, error) {
	if d < 0 {
		return 0, invalidArg("Config.CloseTimeout %s is negative", d)
	}
	if d == 0 {
		return 3 * time.Second, nil
	}
	return d, nil
}

// resolveFragmentInterleave computes the effective FragmentInterleave level:
// Config.FragmentInterleave when set, InterleaveAssocs on an Endpoint when
// it is nil (RFC 6458 §8.1.20's SHOULD default for a one-to-many socket),
// InterleaveNone otherwise. InterleaveStreams is refused outright: Linux
// stores SCTP_FRAGMENT_INTERLEAVE as a plain boolean
// (net/sctp/socket.c: sctp_setsockopt_fragment_interleave sets
// frag_interleave = !!*val), so asking for level 2 would silently deliver
// level 1's cross-association interleaving instead of the cross-stream
// interleaving the caller asked for.
func resolveFragmentInterleave(c *Config, style socketStyle) (FragmentInterleave, error) {
	if c.FragmentInterleave == nil {
		if style.isEndpoint() {
			return InterleaveAssocs, nil
		}
		return InterleaveNone, nil
	}
	switch level := *c.FragmentInterleave; level {
	case InterleaveNone, InterleaveAssocs:
		return level, nil
	case InterleaveStreams:
		return 0, unsupportedField("Config.FragmentInterleave", "Linux stores SCTP_FRAGMENT_INTERLEAVE as a boolean and collapses any nonzero value to InterleaveAssocs (net/sctp/socket.c: sctp_setsockopt_fragment_interleave), so it cannot deliver cross-stream interleaving")
	default:
		return 0, invalidArg("Config.FragmentInterleave is %v, not InterleaveNone, InterleaveAssocs or InterleaveStreams", level)
	}
}

// buildSubscriptions validates every entry of notifications, appends one
// opNotification per distinct EventType (duplicates silently collapse, in
// first-occurrence order) to *ops, and returns the resulting eventSet.
func buildSubscriptions(notifications []EventType, ops *[]configOp) (eventSet, error) {
	var subscribed eventSet
	for i, t := range notifications {
		if _, known := eventTypeNames[t]; !known {
			return 0, invalidArg("Config.Notifications[%d] is %v, not a subscribable notification type", i, t)
		}
		if subscribed.has(t) {
			continue
		}
		subscribed |= eventBit(t)
		*ops = append(*ops, configOp{kind: opNotification, event: t})
	}
	return subscribed, nil
}

// prepareFileStyle validates the FileConn/FileListener form of Config: the
// descriptor is already set up, so only NotificationHandler and CloseTimeout
// may be set (Config.FileConn's own doc comment); every other field set —
// including an empty but non-nil slice — is refused, naming the field.
func prepareFileStyle(c *Config, closeTimeout time.Duration) (*prepared, error) {
	fields := []struct {
		name string
		set  bool
	}{
		{"Control", c.Control != nil},
		{"AbandonPolicy", c.AbandonPolicy != AbandonAbort},
		{"InitMsg", c.InitMsg != (InitMsg{})},
		{"AdaptationLayer", c.AdaptationLayer != nil},
		{"HMACIdentifiers", c.HMACIdentifiers != nil},
		{"AuthChunks", c.AuthChunks != nil},
		{"PartialReliability", c.PartialReliability != nil},
		{"StreamReconfiguration", c.StreamReconfiguration != nil},
		{"DynamicAddressReconfiguration", c.DynamicAddressReconfiguration != nil},
		{"Authentication", c.Authentication != nil},
		{"ExperimentalECN", c.ExperimentalECN != nil},
		{"MessageInterleaving", c.MessageInterleaving},
		{"ReadBuffer", c.ReadBuffer != nil},
		{"WriteBuffer", c.WriteBuffer != nil},
		{"NoDelay", c.NoDelay != nil},
		{"DefaultSndInfo", c.DefaultSndInfo != nil},
		{"DefaultPrInfo", c.DefaultPrInfo != nil},
		{"ReusePort", c.ReusePort != nil},
		{"FragmentsDisabled", c.FragmentsDisabled != nil},
		{"FragmentInterleave", c.FragmentInterleave != nil},
		{"ReceiveNxtInfo", c.ReceiveNxtInfo != nil},
		{"StreamResetMask", c.StreamResetMask != nil},
		{"RTOInfo", c.RTOInfo != nil},
		{"DelayedSACK", c.DelayedSACK != nil},
		{"Notifications", c.Notifications != nil},
	}
	for _, f := range fields {
		if f.set {
			return nil, invalidArg("Config.%s is set; FileConn and FileListener accept only NotificationHandler and CloseTimeout, because the descriptor is already set up", f.name)
		}
	}

	return &prepared{
		ops:          []configOp{{kind: opRecvRcvInfo}, {kind: opAssocChange}},
		handler:      c.NotificationHandler,
		closeTimeout: closeTimeout,
		abandon:      AbandonAbort,
		fragLevel:    InterleaveNone,
		adopted:      true,
	}, nil
}

// --- duration conversions: this package's durations are time.Duration; the
// kernel works in whole milliseconds, or seconds for SCTP_AUTOCLOSE -------

// durationToMillis converts d to the whole-millisecond count a kernel field
// holds, refusing anything that would not convert back exactly: a negative
// d, a value that is not a whole millisecond, or one whose millisecond count
// exceeds limit — naming field rather than rounding or truncating.
//
// limit must not exceed math.MaxUint32: every call site in this package
// passes one of its own compile-time constants (a kernel field's own
// width), so a limit beyond that would be a mistake in this file, not a bad
// Config value from a caller — durationToMillis panics rather than
// truncating a validated ms count down to fit the uint32 it returns and
// silently handing back a smaller value than what it just checked.
func durationToMillis(field string, d time.Duration, limit uint64) (uint32, error) {
	if limit > math.MaxUint32 {
		panic(fmt.Sprintf("sctp: durationToMillis(%s, ...): limit %d exceeds math.MaxUint32, the width of the value this function returns", field, limit))
	}
	if d < 0 {
		return 0, invalidArg("%s %s is negative", field, d)
	}
	if d%time.Millisecond != 0 {
		return 0, invalidArg("%s %s is not a whole number of milliseconds", field, d)
	}
	ms := uint64(d / time.Millisecond)
	if ms > limit {
		return 0, invalidArg("%s %s exceeds the kernel field's %d ms maximum", field, d, limit)
	}
	return uint32(ms), nil
}

// durationToSeconds is durationToMillis for the one kernel field RFC 6458
// carries in seconds instead of milliseconds: SCTP_AUTOCLOSE (§8.1.8). The
// same limit contract applies: it must not exceed math.MaxUint32.
func durationToSeconds(field string, d time.Duration, limit uint64) (uint32, error) {
	if limit > math.MaxUint32 {
		panic(fmt.Sprintf("sctp: durationToSeconds(%s, ...): limit %d exceeds math.MaxUint32, the width of the value this function returns", field, limit))
	}
	if d < 0 {
		return 0, invalidArg("%s %s is negative", field, d)
	}
	if d%time.Second != 0 {
		return 0, invalidArg("%s %s is not a whole number of seconds", field, d)
	}
	s := uint64(d / time.Second)
	if s > limit {
		return 0, invalidArg("%s %s exceeds the kernel field's %d s maximum", field, d, limit)
	}
	return uint32(s), nil
}

// millisToDuration is durationToMillis's read-side inverse: every millisecond
// count this package reads back from the kernel converts through it, so a
// round trip through durationToMillis and millisToDuration is exact for any
// value durationToMillis accepted.
func millisToDuration(ms uint32) time.Duration {
	return time.Duration(ms) * time.Millisecond
}
