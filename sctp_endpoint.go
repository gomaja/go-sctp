package sctp

import (
	"errors"
	"fmt"
	"net"
)

// ErrMissingReceiveInfo reports application data received without the
// SCTP_RCVINFO ancillary item that identifies its association.
//
// SCTPEndpoint enables SCTP_RECVRCVINFO before it can create or accept an
// association, so this error means the per-association routing contract was
// lost. Returning the bytes with a nil association would make it possible to
// answer the wrong peer and is therefore never treated as a successful read.
var ErrMissingReceiveInfo = errors.New("sctp: SCTP_RCVINFO missing from endpoint receive")

// ErrInvalidReceiveInfo reports SCTP_RCVINFO whose association id is a scope
// selector or otherwise cannot identify one routable association. Returning
// application bytes with such metadata could make a one-to-many endpoint reply
// to the wrong peer, so Receive fails closed and returns no RcvInfo.
var ErrInvalidReceiveInfo = errors.New("sctp: invalid SCTP_RCVINFO association id")

// ErrInvalidAssociationList reports a malformed SCTP_GET_ASSOC_ID_LIST result.
// Association ids are security-sensitive routing metadata, so a truncated,
// inconsistent, reserved, or duplicate id list is never returned partially.
var ErrInvalidAssociationList = errors.New("sctp: invalid association id list")

// ErrAssociationListTooLarge reports that an endpoint has more associations
// than AssociationIDs can enumerate within its fixed allocation safety limit.
// SyscallConn remains available to applications that deliberately manage a
// larger caller-owned buffer.
var ErrAssociationListTooLarge = errors.New("sctp: association id list exceeds safety limit")

// associationIDListLimit bounds AssociationIDs at four MiB of id payload. It
// is deliberately independent of SCTP_GET_ASSOC_NUMBER: RFC 6458 §8.2.5 says
// that count is only a snapshot, and no kernel-provided count is trusted as an
// unbounded allocation size.
const associationIDListLimit = 1 << 20

// SCTPEndpoint is a Linux SCTP one-to-many style socket (RFC 6458 §3.1).
// One package-owned SOCK_SEQPACKET descriptor carries any number of
// associations, each identified by the SCTPAssocID in its send and receive
// metadata.
//
// SCTPEndpoint deliberately does not implement net.Conn or net.Listener. It
// has message boundaries rather than stream reads, no single remote address,
// and associations arrive through Receive rather than Accept. Send requires a
// kernel-assigned association id and Receive returns RFC 6458 §5.3.5 RcvInfo;
// this prevents a zero-valued default from silently selecting the wrong peer.
//
// Methods may be called concurrently. All Receive calls consume the same
// endpoint queue, so applications that reassemble a message across calls must
// use one receiving goroutine or dispatch complete fragments before allowing
// another reader. Readiness and write deadlines are endpoint-wide, not
// association-specific (RFC 6458 §3.2); use PeelOff before an association with
// independent backpressure or readiness requirements carries high-volume
// traffic.
//
// The package owns the descriptor from construction until Close or Abort.
// PeelOff returns a second package-owned descriptor and transfers that
// association completely away from this endpoint as required by RFC 6458
// §§3.1 and 9.2. Closing the endpoint does not close a peeled association.
type SCTPEndpoint struct {
	conn    *SCTPConn
	network string
}

// Network returns the canonical network used to create the endpoint: "sctp",
// "sctp4", or "sctp6". It returns the empty string for a nil endpoint.
func (ep *SCTPEndpoint) Network() string {
	if ep == nil {
		return ""
	}
	return ep.network
}

// OpenSCTPEndpoint creates an active-only one-to-many endpoint.
//
// It is not put into the listening state, so peers cannot create inbound
// associations. Call Connect one or more times to initiate associations. The
// descriptor is owned by the returned endpoint; callers never need to wrap a
// borrowed descriptor with NewSCTPConn.
func OpenSCTPEndpoint(network string, laddr *SCTPAddr) (*SCTPEndpoint, error) {
	cfg := SocketConfig{InitMsg: InitMsg{NumOstreams: SCTP_MAX_STREAM}}
	return cfg.OpenEndpoint(network, laddr)
}

// ListenSCTPEndpoint creates a listening one-to-many endpoint.
//
// RFC 6458 §3.1.3 specifies that associations are accepted automatically:
// there is no Accept call. Receive reports SCTP_ASSOC_CHANGE notifications and
// per-message association metadata. The endpoint can also initiate outbound
// associations with Connect.
func ListenSCTPEndpoint(network string, laddr *SCTPAddr) (*SCTPEndpoint, error) {
	cfg := SocketConfig{InitMsg: InitMsg{NumOstreams: SCTP_MAX_STREAM}}
	return cfg.ListenEndpoint(network, laddr)
}

// OpenEndpoint is OpenSCTPEndpoint with this SocketConfig applied before bind.
// Control receives a borrowed, Control-only descriptor exactly as it does for
// Dial and Listen; it must not retain or transfer ownership of that descriptor.
func (cfg *SocketConfig) OpenEndpoint(network string, laddr *SCTPAddr) (*SCTPEndpoint, error) {
	if cfg == nil {
		cfg = &SocketConfig{}
	}
	return openSCTPEndpointConfig(network, laddr, false, cfg.InitMsg,
		cfg.Control, cfg.NotificationHandler, PreAssociationConfig{})
}

// ListenEndpoint is ListenSCTPEndpoint with this SocketConfig applied before
// bind and listen. Association-change notifications and SCTP_RCVINFO are
// enabled after Control returns because they are mandatory to this API's
// routing contract and cannot be disabled by configuration.
func (cfg *SocketConfig) ListenEndpoint(network string, laddr *SCTPAddr) (*SCTPEndpoint, error) {
	if cfg == nil {
		cfg = &SocketConfig{}
	}
	return openSCTPEndpointConfig(network, laddr, true, cfg.InitMsg,
		cfg.Control, cfg.NotificationHandler, PreAssociationConfig{})
}

// OpenEndpoint is SocketConfig.OpenEndpoint with the snapshotted
// pre-association plan.
func (cfg *PreconfiguredSocket) OpenEndpoint(
	network string, laddr *SCTPAddr,
) (*SCTPEndpoint, error) {
	socket, pre := cfg.snapshot()
	return openSCTPEndpointConfig(network, laddr, false, socket.InitMsg,
		socket.Control, socket.NotificationHandler, pre)
}

// ListenEndpoint is SocketConfig.ListenEndpoint with the snapshotted
// pre-association plan.
func (cfg *PreconfiguredSocket) ListenEndpoint(
	network string, laddr *SCTPAddr,
) (*SCTPEndpoint, error) {
	socket, pre := cfg.snapshot()
	return openSCTPEndpointConfig(network, laddr, true, socket.InitMsg,
		socket.Control, socket.NotificationHandler, pre)
}

// Addr returns a copy of the endpoint's bound local address set.
func (ep *SCTPEndpoint) Addr() net.Addr {
	if ep == nil || ep.conn == nil {
		return nil
	}
	return ep.conn.LocalAddr()
}

// validEndpointAssociationID excludes the three scope selectors in the Linux
// UAPI. The kernel's id allocator starts at SCTP_ALL_ASSOC+1 specifically so a
// real association can never be mistaken for FUTURE, CURRENT, or ALL.
func validEndpointAssociationID(id SCTPAssocID) bool {
	return id > SCTP_ALL_ASSOC
}

// decodeRcvInfoPayload decodes the fixed 28-byte struct sctp_rcvinfo payload
// from RFC 6458 §5.3.5 without depending on an operating system's cmsghdr
// envelope. The result is a copy and PPID is converted to host order.
//
// Keeping this boundary platform-neutral makes the hostile byte decoder and
// its fuzz target run on every supported build, including targets where the
// socket-backed endpoint itself returns ErrUnsupported.
func decodeRcvInfoPayload(b []byte) *RcvInfo {
	const rcvInfoPayloadSize = 28
	if len(b) < rcvInfoPayloadSize {
		return nil
	}
	return &RcvInfo{
		SID:     nativeEndian.Uint16(b[0:2]),
		SSN:     nativeEndian.Uint16(b[2:4]),
		Flags:   nativeEndian.Uint16(b[4:6]),
		PPID:    ntohl(nativeEndian.Uint32(b[8:12])),
		TSN:     nativeEndian.Uint32(b[12:16]),
		CumTSN:  nativeEndian.Uint32(b[16:20]),
		Context: nativeEndian.Uint32(b[20:24]),
		AssocID: SCTPAssocID(int32(nativeEndian.Uint32(b[24:28]))),
	}
}

// decodeAssociationIDsPayload validates and copies struct sctp_assoc_ids from
// RFC 6458 §8.2.6. The flexible array is native-endian Linux UAPI data, not
// an SCTP wire structure.
func decodeAssociationIDsPayload(b []byte) ([]SCTPAssocID, error) {
	const headerSize = 4
	if len(b) < headerSize {
		return nil, fmt.Errorf("%w: %d-byte header", ErrInvalidAssociationList, len(b))
	}

	count := nativeEndian.Uint32(b[:headerSize])
	if count > associationIDListLimit {
		return nil, fmt.Errorf("%w: count %d", ErrAssociationListTooLarge, count)
	}
	wantLen := headerSize + int(count)*4
	if len(b) != wantLen {
		return nil, fmt.Errorf("%w: count %d needs %d bytes, got %d",
			ErrInvalidAssociationList, count, wantLen, len(b))
	}

	ids := make([]SCTPAssocID, int(count))
	seen := make(map[SCTPAssocID]struct{}, len(ids))
	for i := range ids {
		offset := headerSize + i*4
		id := SCTPAssocID(int32(nativeEndian.Uint32(b[offset : offset+4])))
		if !validEndpointAssociationID(id) {
			return nil, fmt.Errorf("%w: reserved association id %d at index %d",
				ErrInvalidAssociationList, id, i)
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("%w: duplicate association id %d",
				ErrInvalidAssociationList, id)
		}
		seen[id] = struct{}{}
		ids[i] = id
	}
	return ids, nil
}
