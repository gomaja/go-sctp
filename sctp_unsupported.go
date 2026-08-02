//go:build !linux
// +build !linux

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

package sctp

import (
	"context"
	"net"
	"os"
	"syscall"
	"time"
)

func setsockopt(fd int, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	return 0, 0, ErrUnsupported
}

func getsockoptRaw(fd int, optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	return 0, 0, ErrUnsupported
}

func getsockopt(fd int, optname, optval uintptr, optlen *uint32) (uintptr, uintptr, error) {
	return 0, 0, ErrUnsupported
}

func sctpGetAddrs(fd, id, optname int) (*SCTPAddr, error) {
	return nil, ErrUnsupported
}

func newSCTPConn(fd int, handler NotificationHandler) (*SCTPConn, error) {
	if fd >= 0 {
		if file := os.NewFile(uintptr(fd), "sctp"); file != nil {
			_ = file.Close()
		}
	}
	return nil, ErrUnsupported
}

func openSCTPEndpointConfig(network string, laddr *SCTPAddr, listening bool, options InitMsg, control func(network, address string, c syscall.RawConn) error, handler NotificationHandler, preAssociation PreAssociationConfig) (*SCTPEndpoint, error) {
	if _, err := preparePreAssociationConfig(preAssociation, preAssociationOneToMany); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}

// Connect initiates one association and returns its endpoint-local id.
//
// The endpoint descriptor is non-blocking. A nil error therefore means the
// association was either established immediately or was successfully started;
// completion is reported by the automatically enabled SCTP_ASSOC_CHANGE event
// as SCTP_COMM_UP or SCTP_CANT_STR_ASSOC (RFC 6458 §3.2 and Verified Erratum
// 6112). Connect never translates EALREADY or EISCONN into success, because in
// those cases Linux does not return an association id and reporting id 0 would
// alias SCTP_FUTURE_ASSOC.
//
// Multiple calls may create associations with different peers on the same
// endpoint. The returned id is valid only on this endpoint; the peer assigns a
// different local id to the same association.
func (ep *SCTPEndpoint) Connect(raddr *SCTPAddr) (SCTPAssocID, error) {
	return 0, ErrUnsupported
}

// Send transmits one complete message to info.AssocID using the modern
// SCTP_SNDINFO ancillary item (RFC 6458 §5.3.4).
//
// info is required and its AssocID must be a kernel-assigned id returned by
// Connect, Receive, or SCTP_ASSOC_CHANGE. The reserved FUTURE, CURRENT, and ALL
// selectors are rejected so a zero-valued SndInfo cannot silently route data.
// PPID is in host byte order at this API boundary. pr and auth have the same
// per-message meaning as SCTPConn.SCTPWriteInfo.
//
// Without a write deadline Send is non-blocking and can return EAGAIN. With a
// deadline it waits through endpoint-wide readiness; RFC 6458 §3.2 warns that
// writable readiness may belong to another association. Peel off an
// association that needs independent readiness or sustained backpressure.
func (ep *SCTPEndpoint) Send(b []byte, info *SndInfo, pr *PrInfo, auth *AuthInfo) (int, error) {
	return 0, ErrUnsupported
}

// Receive performs one recvmsg on the shared endpoint queue.
//
// Application data is returned with RFC 6458 §5.3.5 RcvInfo, including the
// endpoint-local AssocID, stream and host-order PPID. flags contains MSG_EOR;
// its absence means b held only a fragment and later Receive calls continue the
// same message. Receive never silently discards that distinction.
//
// With no NotificationHandler, notifications are returned as bytes with
// MSG_NOTIFICATION and nil RcvInfo. With a handler, they are delivered to it
// as one complete record even when b is smaller than the notification, and
// Receive continues to the next application message. The callback runs outside
// the descriptor's poller lock and may re-enter endpoint operations; its byte
// slice is valid only for the duration of the call.
func (ep *SCTPEndpoint) Receive(b []byte) (n int, info *RcvInfo, flags int, err error) {
	return 0, nil, 0, ErrUnsupported
}

// PeelOff transfers one association to a new package-owned SCTPConn (RFC 6458
// §9.2). The id must identify a real association on this endpoint; scope
// selectors are rejected. After success every operation for that association,
// including queued data and close, belongs to the returned connection.
func (ep *SCTPEndpoint) PeelOff(id SCTPAssocID) (*SCTPConn, error) {
	return nil, ErrUnsupported
}

// SyscallConn returns controlled access to the endpoint descriptor.
//
// The descriptor remains package-owned and is valid only for the duration of
// each RawConn callback. A callback must not close it, wrap it in os.File or
// net.Conn, or retain the numeric value after returning. This is the same
// ownership and lifetime contract as net.Conn.SyscallConn.
func (ep *SCTPEndpoint) SyscallConn() (syscall.RawConn, error) {
	return nil, ErrUnsupported
}

// BindAdd atomically adds addr to the endpoint's local address set
// (RFC 6458 §9.1). The endpoint cache is refreshed from the kernel after a
// successful operation. See SCTPConn.BindAdd for port handling and the RFC
// 5061 ASCONF negotiation caveat on established associations.
func (ep *SCTPEndpoint) BindAdd(addr *SCTPAddr) error { return ErrUnsupported }

// BindRemove atomically removes addr from the endpoint's local address set
// (RFC 6458 §9.1). It rejects removal of the last local address. See
// SCTPConn.BindRemove for port handling and established-association semantics.
func (ep *SCTPEndpoint) BindRemove(addr *SCTPAddr) error { return ErrUnsupported }

// LocalAddrs returns a package-owned copy of association id's local address
// set (RFC 6458 §9.5). Scope selectors are rejected: this method always
// describes one live association rather than endpoint defaults.
func (ep *SCTPEndpoint) LocalAddrs(id SCTPAssocID) (*SCTPAddr, error) {
	return nil, ErrUnsupported
}

// PeerAddrs returns a package-owned copy of association id's peer address set
// (RFC 6458 §9.3). Scope selectors are rejected.
func (ep *SCTPEndpoint) PeerAddrs(id SCTPAssocID) (*SCTPAddr, error) {
	return nil, ErrUnsupported
}

// AssociationCount returns a snapshot of the associations currently attached
// to the endpoint (RFC 6458 §8.2.5). The count may change immediately after
// this call returns and must not be used as an authority for later routing.
func (ep *SCTPEndpoint) AssociationCount() (uint32, error) {
	return 0, ErrUnsupported
}

// AssociationIDs returns a validated snapshot of the association identifiers
// currently attached to the endpoint (RFC 6458 §8.2.6).
//
// The list can become stale immediately after return. This method grows a
// small package-owned buffer to a fixed limit rather than allocating from the
// SCTP_GET_ASSOC_NUMBER snapshot; a hostile or inconsistent kernel count can
// therefore never cause an unbounded allocation.
func (ep *SCTPEndpoint) AssociationIDs() ([]SCTPAssocID, error) {
	return nil, ErrUnsupported
}

// SetAutoClose sets the number of idle seconds after which the kernel
// gracefully closes an association on this one-to-many endpoint (RFC 6458
// §8.1.8). Zero disables automatic close. Linux may clamp values to the
// current net.sctp.max_autoclose limit; call GetAutoClose to read it back.
// After an automatic close, Linux may reuse that association id. Applications
// must retire ids when SCTPEndpoint's automatically enabled SCTP_ASSOC_CHANGE
// notification reports termination rather than treating a previously observed
// id as a durable peer identity.
func (ep *SCTPEndpoint) SetAutoClose(seconds uint32) error { return ErrUnsupported }

// GetAutoClose returns the endpoint's SCTP_AUTOCLOSE idle timeout in seconds
// (RFC 6458 §8.1.8). Zero means automatic close is disabled.
func (ep *SCTPEndpoint) GetAutoClose() (uint32, error) { return 0, ErrUnsupported }

// CloseAssociation gracefully shuts down one association while leaving every
// other association and the endpoint descriptor open (RFC 6458 §3.1.5).
// Completion is reported by SCTP_ASSOC_CHANGE with SCTP_SHUTDOWN_COMP.
func (ep *SCTPEndpoint) CloseAssociation(id SCTPAssocID) error { return ErrUnsupported }

// AbortAssociation terminates one association immediately and optionally
// carries cause as the user-specified ABORT data from RFC 6458 §3.1.5. Every
// other association and the endpoint descriptor remain open.
func (ep *SCTPEndpoint) AbortAssociation(id SCTPAssocID, cause []byte) error {
	return ErrUnsupported
}

// Close gracefully shuts down every association still owned by the endpoint
// and releases its descriptor (RFC 6458 §3.1.5). It waits up to three seconds
// for the handshakes and then aborts any associations whose peers did not
// respond. Peeled associations are independent and remain open.
func (ep *SCTPEndpoint) Close() error { return ErrUnsupported }

// Abort immediately terminates every association still owned by the endpoint
// and releases its descriptor. Peeled associations are independent.
func (ep *SCTPEndpoint) Abort() error { return ErrUnsupported }

// SetDeadline sets both endpoint-wide receive and send deadlines.
func (ep *SCTPEndpoint) SetDeadline(t time.Time) error { return ErrUnsupported }

// SetReadDeadline sets the deadline for pending and future Receive calls.
func (ep *SCTPEndpoint) SetReadDeadline(t time.Time) error { return ErrUnsupported }

// SetWriteDeadline sets the deadline used by Send.
func (ep *SCTPEndpoint) SetWriteDeadline(t time.Time) error { return ErrUnsupported }

func (c *SCTPConn) setsockopt(optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	return 0, 0, ErrUnsupported
}

func (c *SCTPConn) getsockopt(optname, optval uintptr, optlen *uint32) (uintptr, uintptr, error) {
	return 0, 0, ErrUnsupported
}

func (c *SCTPConn) getsockoptRaw(optname, optval, optlen uintptr) (uintptr, uintptr, error) {
	return 0, 0, ErrUnsupported
}

func (c *SCTPConn) setInitOpts(options InitMsg) error { return ErrUnsupported }

func (c *SCTPConn) setsockoptInt(optname uintptr, on bool) error { return ErrUnsupported }

func (c *SCTPConn) setsockoptInt32(optname uintptr, value int32) error {
	return ErrUnsupported
}

func (c *SCTPConn) getsockoptInt32(optname uintptr) (int32, error) {
	return 0, ErrUnsupported
}

func (c *SCTPConn) setSockoptBool(optname uintptr, on bool) error { return ErrUnsupported }

func (c *SCTPConn) getSockoptBool(optname uintptr) (bool, error) {
	return false, ErrUnsupported
}

func (c *SCTPConn) setAssocValue(optname uintptr, value uint32) error {
	return ErrUnsupported
}

func (c *SCTPConn) getAssocValue(optname uintptr) (uint32, error) {
	return 0, ErrUnsupported
}

func (c *SCTPConn) setAssocValueBool(optname uintptr, on bool) error {
	return ErrUnsupported
}

func (c *SCTPConn) getAddrs(id, optname int) (*SCTPAddr, error) {
	return nil, ErrUnsupported
}

func (c *SCTPConn) SCTPWrite(b []byte, info *SndRcvInfo) (int, error) {
	return 0, ErrUnsupported
}

func (c *SCTPConn) writeSndRcv(b []byte, info *SndRcvInfo, wait bool) (int, error) {
	return 0, ErrUnsupported
}

func (c *SCTPConn) write(b []byte) (int, error) { return 0, ErrUnsupported }

func (c *SCTPConn) SCTPWriteInfo(b []byte, info *SndInfo, pr *PrInfo, auth *AuthInfo) (int, error) {
	return 0, ErrUnsupported
}

func (c *SCTPConn) SCTPRead(b []byte) (int, *SndRcvInfo, error) {
	if c != nil {
		c.readMu.Lock()
		defer c.readMu.Unlock()
	}
	return 0, nil, ErrUnsupported
}

// SyscallConn is declared here so that code holding a *SCTPConn or
// *SCTPListener still compiles when cross-compiled for a platform without SCTP.
// Without it the linux build has a method the others do not, and a caller who
// reaches for readiness handling — which is exactly what SyscallConn is for —
// fails to build rather than failing at run time with the reason.
func (c *SCTPConn) SyscallConn() (syscall.RawConn, error) {
	return nil, ErrUnsupported
}

func (ln *SCTPListener) SyscallConn() (syscall.RawConn, error) {
	return nil, ErrUnsupported
}

func (c *SCTPConn) SCTPReadFlags(b []byte) (int, *SndRcvInfo, int, error) {
	return 0, nil, 0, ErrUnsupported
}

func (c *SCTPConn) SCTPReadMsg(b, oob []byte) (n, oobn, flags int, err error) {
	return 0, 0, 0, ErrUnsupported
}

func (c *SCTPConn) ReadMsg(max int) ([]byte, *SndRcvInfo, error) {
	return nil, nil, ErrUnsupported
}

func (c *SCTPConn) Close() error {
	return ErrUnsupported
}

func (c *SCTPConn) Abort() error {
	return ErrUnsupported
}

func (c *SCTPConn) CloseWithTimeout(timeout time.Duration) error {
	return ErrUnsupported
}

func (c *SCTPConn) SetWriteBuffer(bytes int) error {
	return ErrUnsupported
}

func (c *SCTPConn) GetWriteBuffer() (int, error) {
	return 0, ErrUnsupported
}

func (c *SCTPConn) SetReadBuffer(bytes int) error {
	return ErrUnsupported
}

func (c *SCTPConn) GetReadBuffer() (int, error) {
	return 0, ErrUnsupported
}

func ListenSCTP(net string, laddr *SCTPAddr) (*SCTPListener, error) {
	return nil, ErrUnsupported
}

func ListenSCTPExt(network string, laddr *SCTPAddr, options InitMsg) (*SCTPListener, error) {
	return nil, ErrUnsupported
}

func listenSCTPExtConfig(network string, laddr *SCTPAddr, options InitMsg, control func(network string, address string, c syscall.RawConn) error, handler NotificationHandler, preAssociation PreAssociationConfig) (*SCTPListener, error) {
	if _, err := preparePreAssociationConfig(preAssociation, preAssociationOneToOne); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}

func FileListener(file *os.File) (*SCTPListener, error) {
	return nil, ErrUnsupported
}

func (ln *SCTPListener) Accept() (net.Conn, error) {
	return nil, ErrUnsupported
}

func (ln *SCTPListener) AcceptSCTP() (*SCTPConn, error) {
	// Retain the configured callback in the portable representation even
	// though this platform can never receive an SCTP notification.
	if ln != nil {
		_ = ln.notificationHandler
	}
	return nil, ErrUnsupported
}

func (ln *SCTPListener) Close() error {
	return ErrUnsupported
}

func DialSCTP(net string, laddr, raddr *SCTPAddr) (*SCTPConn, error) {
	return nil, ErrUnsupported
}

func DialSCTPExt(network string, laddr, raddr *SCTPAddr, options InitMsg) (*SCTPConn, error) {
	return nil, ErrUnsupported
}

func dialSCTPExtConfig(network string, laddr, raddr *SCTPAddr, options InitMsg, control func(network string, address string, c syscall.RawConn) error, handler NotificationHandler, preAssociation PreAssociationConfig) (*SCTPConn, error) {
	if _, err := preparePreAssociationConfig(preAssociation, preAssociationOneToOne); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}

func DialSCTPContext(ctx context.Context, network string, laddr, raddr *SCTPAddr, options InitMsg) (*SCTPConn, error) {
	return DialSCTPContextWithAbandonPolicy(ctx, network, laddr, raddr, options,
		DialAbandonAbort)
}

// DialSCTPContextWithAbandonPolicy is DialSCTPContext with explicit control
// over how a non-established attempt is released when the context expires or
// another pre-establishment error path returns.
func DialSCTPContextWithAbandonPolicy(ctx context.Context, network string, laddr, raddr *SCTPAddr, options InitMsg, policy DialAbandonPolicy) (*SCTPConn, error) {
	if ctx == nil {
		return nil, errNilContext
	}
	if err := validateDialAbandonPolicy(policy); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}

func dialSCTPExtConfigContext(ctx context.Context, network string, laddr, raddr *SCTPAddr, options InitMsg, control func(network string, address string, c syscall.RawConn) error, handler NotificationHandler, preAssociation PreAssociationConfig, policy DialAbandonPolicy) (*SCTPConn, error) {
	if ctx == nil {
		return nil, errNilContext
	}
	if err := validateDialAbandonPolicy(policy); err != nil {
		return nil, err
	}
	if _, err := preparePreAssociationConfig(preAssociation, preAssociationOneToOne); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}

// PeelOff is Linux-only for the same reason as the rest of this file, and
// additionally because it names syscall.SOCK_CLOEXEC, which the syscall package
// does not define everywhere. Keeping it in the shared file is what broke the
// Windows build once already.
func (c *SCTPConn) PeelOff(id int) (*SCTPConn, error) {
	return nil, ErrUnsupported
}

func (c *SCTPConn) SCTPReadNextInfo(b []byte) (int, *SndRcvInfo, *NxtInfo, int, error) {
	return 0, nil, nil, 0, ErrUnsupported
}
