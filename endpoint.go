// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// endpoint.go declares Endpoint, the one-to-many socket, and the parts of
// it that need no socket: which association ids are real, the bounded
// decoding of an association id list, and the receive-side check that
// every message an Endpoint returns names one real association. Opening
// an Endpoint, and every method that reaches its descriptor, is in
// endpoint_linux.go.

package sctp

import (
	"encoding/binary"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Endpoint is a one-to-many SCTP socket (RFC 6458 §3): one descriptor
// carrying many associations, each identified by an AssocID. *Endpoint
// implements neither net.Conn nor net.Listener: it keeps message
// boundaries, has no single peer, and learns of new associations from
// notifications rather than from an Accept (RFC 6458 §3.1.3).
//
// Association ids come from one system-wide cyclic pool (idr_alloc_cyclic,
// net/sctp/associola.c), so an id is reused after its association ends.
// Retire an id when EventAssocChange reports the end, and never treat it
// as a lasting peer identity. An Endpoint always delivers EventAssocChange
// records, whatever Config.Notifications says, since its callers route by
// association id (RFC 6458 §3.1.3).
//
// Every method takes the association it acts on as an argument, and every
// message RecvMsg returns names its association in MsgInfo.Rcv.AssocID.
// The reserved scope selectors (SCTP_FUTURE_ASSOC, SCTP_CURRENT_ASSOC,
// SCTP_ALL_ASSOC, RFC 6458 §7.2) are refused wherever an id is taken, so a
// zero AssocID can never select an association by accident, and a
// message whose SCTP_RCVINFO is missing or names no real association is
// reported with ErrMissingRcvInfo or ErrInvalidRcvInfo, never returned as
// if it belonged to one.
//
// Readiness and deadlines are endpoint-wide, not per association (RFC
// 6458 §3.2): a send that waits for buffer space can be released by
// another association's progress, and a reader receives whatever
// association's message comes next. An association that needs readiness
// or backpressure of its own can be moved to a Conn of its own with
// PeelOff.
//
// Every method may be called from several goroutines at once. Sends are
// serialized by one send lock and receives by one receive lock, as on a
// Conn; a reader that reassembles a message across several RecvMsg calls
// must keep other readers away until the message ends (MsgInfo.EOR).
//
//lint:ignore U1000 only the Linux code opens an Endpoint; on other platforms the fields stay unused
type Endpoint struct {
	sock socket

	// peel is the Config snapshot a connection PeelOff returns is built
	// from: the handler, the grace period of Close, and the caller's own
	// subscriptions, without the EventAssocChange delivery an Endpoint
	// always adds.
	peel *prepared

	// addr is the snapshot Addr copies: the endpoint's bound addresses,
	// replaced as a whole after a successful BindAdd or BindRemove, and
	// after a Connect bound an unbound endpoint.
	addr atomic.Pointer[Addr]

	// bindMu serialises BindAdd and BindRemove, each with the snapshot
	// refresh that follows it.
	bindMu sync.Mutex

	handler   NotificationHandler
	closeWait time.Duration // Config.CloseTimeout, resolved: the grace period of Close

	// subs is the logical subscription set the receive path reads: the
	// Config's notifications plus EventAssocChange. It never changes.
	subs atomic.Uint32

	life lifecycle // the close state machine (close.go)
	send sendState
	recv recvState
}

// Network returns the network the Endpoint was opened on: "sctp", "sctp4"
// or "sctp6". It returns "" for a nil Endpoint, or one the package never
// opened.
func (e *Endpoint) Network() string {
	if e == nil {
		return ""
	}
	return e.sock.network
}

// realAssocID reports whether id can name an association. Linux gives
// every association an id above SCTP_ALL_ASSOC (net/sctp/associola.c:
// sctp_assoc_set_id allocates from SCTP_ALL_ASSOC + 1 upwards), because 0,
// 1 and 2 are the scope selectors SCTP_FUTURE_ASSOC, SCTP_CURRENT_ASSOC
// and SCTP_ALL_ASSOC (RFC 6458 §7.2), and none is negative.
func realAssocID(id AssocID) bool {
	return id > assocScopeAll
}

// assocIDArg checks the association id an Endpoint method named, before
// any system call, and refuses a scope selector or a negative id with an
// error matching syscall.EINVAL that names the method.
func assocIDArg(method string, id AssocID) error {
	if realAssocID(id) {
		return nil
	}
	switch id {
	case assocScopeFuture:
		return invalidArg("%s: association id 0 is the scope selector SCTP_FUTURE_ASSOC (RFC 6458 §7.2), not an association", method)
	case assocScopeCurrent:
		return invalidArg("%s: association id 1 is the scope selector SCTP_CURRENT_ASSOC (RFC 6458 §7.2), not an association", method)
	case assocScopeAll:
		return invalidArg("%s: association id 2 is the scope selector SCTP_ALL_ASSOC (RFC 6458 §7.2), not an association", method)
	}
	return invalidArg("%s: association id %d is negative; Linux gives every association an id above 2", method, id)
}

// assocIDListLimit bounds AssocIDs at 1<<20 ids, four MiB of ids. It is a
// fixed bound of the package's own, independent of SCTP_GET_ASSOC_NUMBER,
// which RFC 6458 §8.2.5 calls only a snapshot: no count the kernel reports
// ever sizes an allocation.
const assocIDListLimit = 1 << 20

// decodeAssocIDs decodes and checks struct sctp_assoc_ids (RFC 6458 §8.2.6)
// as SCTP_GET_ASSOC_ID_LIST wrote it into b, cut to the length the kernel
// reported, and returns the ids as a slice of their own, in ascending
// order. Association ids are what an Endpoint's callers route by, so a
// list that is short, has bytes past its last id, repeats an id or holds
// one that is not real is refused whole with an error matching
// ErrInvalidAssocList, never returned in part; a count above
// assocIDListLimit is refused with one matching ErrAssocListTooLarge
// before anything is allocated. An empty list is a non-nil slice of
// length 0. Repeats are found by sorting the slice and comparing
// neighbours, so the check allocates nothing beyond the slice itself.
func decodeAssocIDs(b []byte) ([]AssocID, error) {
	if len(b) < sizeAssocIDs {
		return nil, fmt.Errorf("%w: %d bytes, shorter than its %d-byte header", ErrInvalidAssocList, len(b), sizeAssocIDs)
	}
	count := binary.NativeEndian.Uint32(b[assocIDsNumIDsOff:])
	if count > assocIDListLimit {
		return nil, fmt.Errorf("%w: %d ids, more than %d", ErrAssocListTooLarge, count, assocIDListLimit)
	}
	if want := assocIDsIDsOff + int(count)*sizeAssocID; len(b) != want {
		return nil, fmt.Errorf("%w: %d ids need %d bytes, got %d", ErrInvalidAssocList, count, want, len(b))
	}
	ids := make([]AssocID, count)
	for i := range ids {
		id := AssocID(int32(binary.NativeEndian.Uint32(b[assocIDsIDsOff+i*sizeAssocID:])))
		if !realAssocID(id) {
			return nil, fmt.Errorf("%w: id %d at index %d is not an association id", ErrInvalidAssocList, id, i)
		}
		ids[i] = id
	}
	slices.Sort(ids)
	for i := 1; i < len(ids); i++ {
		if ids[i] == ids[i-1] {
			return nil, fmt.Errorf("%w: id %d appears twice", ErrInvalidAssocList, ids[i])
		}
	}
	return ids, nil
}

// parseEndpointRecvCmsgs is parseRecvCmsgs for an Endpoint, whose callers
// route every message by the association id its SCTP_RCVINFO record
// carries (RFC 6458 §5.3.5). It fills info from the ancillary data oob and
// the msg_flags value flags as parseRecvCmsgs does, and for data, not a
// notification, it then requires exactly one SCTP_RCVINFO record, whole,
// that names a real association: data with none fails with
// ErrMissingRcvInfo, and a record that is short, repeated, malformed or
// that names a scope selector with an error matching ErrInvalidRcvInfo.
// When the check fails, info.Rcv is left zero, so that the bytes cannot
// be taken for another association's.
//
// MSG_CTRUNC comes first, as ErrControlTruncated: put_cmsg (net/core/
// scm.c) cuts short or drops the record it runs out of room for, so a
// record missing or short then says only that the buffer was too small.
// info.Rcv is kept even then when the record arrived whole and names a
// real association.
func parseEndpointRecvCmsgs(oob []byte, flags int, info *MsgInfo) error {
	err := parseRecvCmsgs(oob, flags, info)
	if info.Notification {
		return err
	}
	if cerr := checkRcvInfoRecord(oob, info.Rcv.AssocID); cerr != nil {
		info.Rcv = RcvInfo{}
		if err == nil {
			err = cerr
		}
	}
	return err
}

// checkRcvInfoRecord walks oob as parseRecvCmsgs does and checks that it
// holds exactly one whole SCTP_RCVINFO record, whose association id,
// already decoded as id, is real. Linux attaches one to every message
// once SCTP_RECVRCVINFO is on (net/sctp/ulpevent.c:
// sctp_ulpevent_read_rcvinfo), which an Endpoint enables before any
// association can exist and never turns off.
func checkRcvInfoRecord(oob []byte, id AssocID) error {
	records := 0
	for len(oob) >= sizeCmsghdr {
		length := readWord(oob)
		if length < sizeCmsghdr || length > uint64(len(oob)) {
			return fmt.Errorf("%w: a control message header declares %d bytes where %d remain", ErrInvalidRcvInfo, length, len(oob))
		}
		level := int32(binary.NativeEndian.Uint32(oob[cmsghdrLevelOff:]))
		typ := int32(binary.NativeEndian.Uint32(oob[cmsghdrTypeOff:]))
		if level == ipprotoSCTP && typ == cmsgRcvInfo {
			records++
			if n := int(length) - sizeCmsghdr; n < sizeRcvInfo {
				return fmt.Errorf("%w: a %d-byte record, shorter than struct sctp_rcvinfo's %d", ErrInvalidRcvInfo, n, sizeRcvInfo)
			}
		}
		adv := cmsgAlign(int(length))
		if adv > len(oob) {
			break
		}
		oob = oob[adv:]
	}
	switch {
	case records == 0:
		return ErrMissingRcvInfo
	case records > 1:
		return fmt.Errorf("%w: %d SCTP_RCVINFO records on one message", ErrInvalidRcvInfo, records)
	case !realAssocID(id):
		return fmt.Errorf("%w: association id %d", ErrInvalidRcvInfo, id)
	}
	return nil
}
