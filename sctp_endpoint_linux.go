//go:build linux
// +build linux

package sctp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

func openSCTPEndpointConfig(
	network string,
	laddr *SCTPAddr,
	listening bool,
	options InitMsg,
	control func(network, address string, c syscall.RawConn) error,
	handler NotificationHandler,
	preAssociation PreAssociationConfig,
) (ep *SCTPEndpoint, err error) {
	network, _, err = canonicalNetwork(network)
	if err != nil {
		return nil, err
	}
	if laddr != nil {
		if err = laddr.validateNetworkFamily(network); err != nil {
			return nil, err
		}
	}
	prepared, err := preparePreAssociationConfig(preAssociation, preAssociationOneToMany)
	if err != nil {
		return nil, err
	}

	// The listening family selection also gives an unbound "sctp" endpoint a
	// dual-stack IPv6 socket where the host supports it. Unlike a one-to-one
	// dial, there is no single remote address from which to choose a family.
	af, ipv6only := favoriteAddrFamily(network, laddr, nil, "listen")
	sock, err := syscall.Socket(af,
		syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC,
		syscall.IPPROTO_SCTP)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil && sock >= 0 {
			// A Control hook could have initiated an association. Abort on a
			// constructor failure so no hidden handshake or descriptor survives.
			_ = abortSctpSocket(sock)
		}
	}()

	if err = setDefaultSockopts(sock, af, ipv6only); err != nil {
		return nil, err
	}
	if control != nil {
		address := ""
		if laddr != nil {
			address = laddr.String()
		}
		if err = control(network, address, rawConn{sockfd: sock}); err != nil {
			return nil, err
		}
	}
	if err = setInitOpts(sock, options); err != nil {
		return nil, err
	}

	// RFC 6458 §3.1.3 says applications using association ids should ensure
	// SCTP_ASSOC_CHANGE is enabled. SCTPEndpoint makes that recommendation a
	// fail-closed package invariant. SCTP_RECVRCVINFO is its other invariant;
	// the prepared one-to-many plan enables it before FragmentInterleave so
	// Receive can route messages using the metadata from §§5.3.5 and 8.1.20.
	event := Event{
		AssocID: SCTPAssocID(SCTP_FUTURE_ASSOC),
		Type:    uint16(SCTP_ASSOC_CHANGE),
		On:      1,
	}
	if _, _, err = setsockopt(sock, SCTP_EVENT,
		uintptr(unsafe.Pointer(&event)), unsafe.Sizeof(event)); err != nil {
		return nil, err
	}
	if err = applyPreparedPreAssociationConfig(sock, prepared); err != nil {
		return nil, err
	}

	if laddr != nil {
		if err = bindLocal(sock, laddr, af); err != nil {
			return nil, err
		}
	}
	if listening {
		backlog := syscall.SOMAXCONN
		if configured, readErr := readSomaxconn(); readErr == nil && configured > backlog {
			backlog = configured
		}
		if err = syscall.Listen(sock, backlog); err != nil {
			return nil, err
		}
	}

	conn, wrapErr := newSCTPConn(sock, handler)
	sock = -1 // newSCTPConn owns and closes it on both success and failure.
	if wrapErr != nil {
		err = wrapErr
		return nil, err
	}
	return &SCTPEndpoint{conn: conn, network: network}, nil
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
	if ep == nil || ep.conn == nil || ep.conn.fd() < 0 {
		return 0, errClosed("connect")
	}
	if raddr == nil {
		return 0, &net.AddrError{Err: "missing remote SCTP address", Addr: "<nil>"}
	}
	if err := raddr.validateNetworkFamily(ep.network); err != nil {
		return 0, err
	}

	var id SCTPAssocID
	err := ep.conn.control("connect", func(fd int) error {
		var connectErr error
		id, connectErr = startEndpointAssociation(fd, raddr)
		return connectErr
	})
	if err != nil {
		return 0, err
	}
	if !validEndpointAssociationID(id) {
		return 0, fmt.Errorf("sctp: kernel returned reserved association id %d: %w",
			id, syscall.EPROTO)
	}

	// An unbound active endpoint is implicitly bound by the first connect.
	// Refresh the cache so Addr reports the real port rather than its pre-connect
	// zero value. Failure does not invalidate the association id just created.
	_, _ = ep.conn.SCTPLocalAddr(SCTP_FUTURE_ASSOC)
	return id, nil
}

func startEndpointAssociation(fd int, raddr *SCTPAddr) (SCTPAssocID, error) {
	buf, err := raddr.MarshalSockaddr()
	if err != nil {
		return 0, err
	}
	param := GetAddrsOld{
		AddrNum: int32(len(buf)),
		Addrs:   uintptr(unsafe.Pointer(&buf[0])),
	}
	optlen := uint32(unsafe.Sizeof(param))
	_, _, err = getsockopt(fd, SCTP_SOCKOPT_CONNECTX3,
		uintptr(unsafe.Pointer(&param)), &optlen)
	if err == nil || errors.Is(err, syscall.EINPROGRESS) {
		return SCTPAssocID(param.AssocID), nil
	}
	if !errors.Is(err, syscall.ENOPROTOOPT) {
		return 0, err
	}

	// CONNECTX3 has been in Linux for years, but retain the package's existing
	// CONNECTX fallback. Its successful syscall return carries the id. A
	// non-blocking EINPROGRESS cannot carry that positive return, so fail safe
	// instead of returning the reserved id 0 and making per-association routing
	// ambiguous.
	r0, _, err := setsockopt(fd, SCTP_SOCKOPT_CONNECTX,
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if err != nil {
		if errors.Is(err, syscall.EINPROGRESS) {
			return 0, fmt.Errorf("sctp: CONNECTX cannot return the id of a pending association: %w",
				errors.ErrUnsupported)
		}
		return 0, err
	}
	id := SCTPAssocID(int32(r0))
	if !validEndpointAssociationID(id) {
		return 0, fmt.Errorf("sctp: CONNECTX returned reserved association id %d: %w",
			id, syscall.EPROTO)
	}
	return id, nil
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
	if ep == nil || ep.conn == nil || ep.conn.fd() < 0 {
		return 0, errClosed("write")
	}
	if info == nil || !validEndpointAssociationID(SCTPAssocID(info.AssocID)) {
		return 0, syscall.EINVAL
	}
	if info.Flags&(SCTP_EOF|SCTP_ABORT|SCTP_SENDALL) != 0 {
		return 0, syscall.EINVAL
	}
	return ep.conn.SCTPWriteInfo(b, info, pr, auth)
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
	if ep == nil || ep.conn == nil || ep.conn.fd() < 0 {
		return 0, nil, 0, errClosed("read")
	}
	if len(b) == 0 {
		return 0, nil, 0, nil
	}

	oobp := oobPool.Get().(*[]byte)
	oob := *oobp
	defer oobPool.Put(oobp)
	var oobn int

	for {
		var notification []byte
		n, oobn, flags, notification, err = ep.conn.recvmsgWithNotification(b, oob)
		if err != nil {
			return n, nil, flags, err
		}
		if notification != nil {
			if handlerErr := ep.conn.notificationHandler(notification); handlerErr != nil {
				return 0, nil, flags, handlerErr
			}
			continue
		}
		if n == 0 && oobn == 0 {
			return 0, nil, flags, io.EOF
		}
		if flags&MSG_NOTIFICATION != 0 {
			return n, nil, flags, nil
		}
		if flags&syscall.MSG_CTRUNC != 0 {
			return n, nil, flags, ErrControlTruncated
		}
		if oobn > 0 {
			info, err = parseRcvInfo(oob[:oobn])
			if err != nil {
				return n, nil, flags, err
			}
		}
		if info == nil {
			return n, nil, flags, ErrMissingReceiveInfo
		}
		return n, info, flags, nil
	}
}

// parseRcvInfo extracts the first complete SCTP_RCVINFO ancillary item and
// copies it into package-owned memory. The wire/API PPID is converted to the
// package-wide host-order convention at this boundary.
func parseRcvInfo(b []byte) (*RcvInfo, error) {
	msgs, err := syscall.ParseSocketControlMessage(b)
	if err != nil {
		return nil, err
	}
	var found *RcvInfo
	for _, msg := range msgs {
		if msg.Header.Level != syscall.IPPROTO_SCTP ||
			msg.Header.Type != SCTP_CMSG_RCVINFO {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("%w: duplicate ancillary item", ErrInvalidReceiveInfo)
		}
		info := decodeRcvInfoPayload(msg.Data)
		if info == nil {
			return nil, fmt.Errorf("%w: %d-byte payload", ErrInvalidReceiveInfo, len(msg.Data))
		}
		if !validEndpointAssociationID(SCTPAssocID(info.AssocID)) {
			return nil, fmt.Errorf("%w: reserved association id %d",
				ErrInvalidReceiveInfo, info.AssocID)
		}
		found = info
	}
	return found, nil
}

// SyscallConn returns controlled access to the endpoint descriptor.
//
// The descriptor remains package-owned and is valid only for the duration of
// each RawConn callback. A callback must not close it, wrap it in os.File or
// net.Conn, or retain the numeric value after returning. This is the same
// ownership and lifetime contract as net.Conn.SyscallConn.
func (ep *SCTPEndpoint) SyscallConn() (syscall.RawConn, error) {
	if ep == nil || ep.conn == nil || ep.conn.fd() < 0 {
		return nil, errClosed("syscallconn")
	}
	return ep.conn.SyscallConn()
}

// BindAdd atomically adds addr to the endpoint's local address set
// (RFC 6458 §9.1). The endpoint cache is refreshed from the kernel after a
// successful operation. See SCTPConn.BindAdd for port handling and the RFC
// 5061 ASCONF negotiation caveat on established associations.
func (ep *SCTPEndpoint) BindAdd(addr *SCTPAddr) error {
	if ep == nil || ep.conn == nil || ep.conn.fd() < 0 {
		return errClosed("bindx")
	}
	return ep.conn.BindAdd(addr)
}

// BindRemove atomically removes addr from the endpoint's local address set
// (RFC 6458 §9.1). It rejects removal of the last local address. See
// SCTPConn.BindRemove for port handling and established-association semantics.
func (ep *SCTPEndpoint) BindRemove(addr *SCTPAddr) error {
	if ep == nil || ep.conn == nil || ep.conn.fd() < 0 {
		return errClosed("bindx")
	}
	return ep.conn.BindRemove(addr)
}

// LocalAddrs returns a package-owned copy of association id's local address
// set (RFC 6458 §9.5). Scope selectors are rejected: this method always
// describes one live association rather than endpoint defaults.
func (ep *SCTPEndpoint) LocalAddrs(id SCTPAssocID) (*SCTPAddr, error) {
	if ep == nil || ep.conn == nil || ep.conn.fd() < 0 {
		return nil, errClosed("getsockopt")
	}
	if !validEndpointAssociationID(id) {
		return nil, syscall.EINVAL
	}
	return ep.conn.SCTPLocalAddr(int(id))
}

// PeerAddrs returns a package-owned copy of association id's peer address set
// (RFC 6458 §9.3). Scope selectors are rejected.
func (ep *SCTPEndpoint) PeerAddrs(id SCTPAssocID) (*SCTPAddr, error) {
	if ep == nil || ep.conn == nil || ep.conn.fd() < 0 {
		return nil, errClosed("getsockopt")
	}
	if !validEndpointAssociationID(id) {
		return nil, syscall.EINVAL
	}
	return ep.conn.SCTPRemoteAddr(int(id))
}

// AssociationCount returns a snapshot of the associations currently attached
// to the endpoint (RFC 6458 §8.2.5). The count may change immediately after
// this call returns and must not be used as an authority for later routing.
func (ep *SCTPEndpoint) AssociationCount() (uint32, error) {
	if ep == nil || ep.conn == nil || ep.conn.fd() < 0 {
		return 0, errClosed("getsockopt")
	}

	var count uint32
	optlen := uint32(unsafe.Sizeof(count))
	err := ep.conn.control("getsockopt", func(fd int) error {
		_, _, err := getsockopt(fd, SCTP_GET_ASSOC_NUMBER,
			uintptr(unsafe.Pointer(&count)), &optlen)
		return err
	})
	if err != nil {
		return 0, err
	}
	if optlen != uint32(unsafe.Sizeof(count)) {
		return 0, fmt.Errorf("sctp: SCTP_GET_ASSOC_NUMBER returned %d bytes: %w",
			optlen, syscall.EPROTO)
	}
	return count, nil
}

// AssociationIDs returns a validated snapshot of the association identifiers
// currently attached to the endpoint (RFC 6458 §8.2.6).
//
// The list can become stale immediately after return. This method grows a
// small package-owned buffer to a fixed limit rather than allocating from the
// SCTP_GET_ASSOC_NUMBER snapshot; a hostile or inconsistent kernel count can
// therefore never cause an unbounded allocation.
func (ep *SCTPEndpoint) AssociationIDs() ([]SCTPAssocID, error) {
	if ep == nil || ep.conn == nil || ep.conn.fd() < 0 {
		return nil, errClosed("getsockopt")
	}

	var ids []SCTPAssocID
	err := ep.conn.control("getsockopt", func(fd int) error {
		var err error
		ids, err = endpointAssociationIDs(fd)
		return err
	})
	return ids, err
}

// endpointAssociationIDs is the descriptor-level implementation shared by the
// public snapshot and Close. Close marks the public object closed before it
// starts teardown, but must keep querying the still-pinned descriptor until
// every per-association shutdown handshake has completed.
func endpointAssociationIDs(fd int) ([]SCTPAssocID, error) {
	const initialCapacity = 16
	for capacity := initialCapacity; capacity <= associationIDListLimit; capacity *= 2 {
		buf := make([]byte, 4+capacity*4)
		optlen := uint32(len(buf))
		_, _, err := getsockopt(fd, SCTP_GET_ASSOC_ID_LIST,
			uintptr(unsafe.Pointer(&buf[0])), &optlen)
		runtime.KeepAlive(buf)
		if errors.Is(err, syscall.EINVAL) && capacity < associationIDListLimit {
			continue
		}
		if errors.Is(err, syscall.EINVAL) {
			return nil, fmt.Errorf("%w: more than %d ids",
				ErrAssociationListTooLarge, associationIDListLimit)
		}
		if err != nil {
			return nil, err
		}
		if optlen > uint32(len(buf)) {
			return nil, fmt.Errorf("%w: kernel length %d exceeds %d-byte buffer",
				ErrInvalidAssociationList, optlen, len(buf))
		}
		return decodeAssociationIDsPayload(buf[:optlen])
	}
	return nil, ErrAssociationListTooLarge
}

// SetAutoClose sets the number of idle seconds after which the kernel
// gracefully closes an association on this one-to-many endpoint (RFC 6458
// §8.1.8). Zero disables automatic close. Linux may clamp values to the
// current net.sctp.max_autoclose limit; call GetAutoClose to read it back.
// After an automatic close, Linux may reuse that association id. Applications
// must retire ids when SCTPEndpoint's automatically enabled SCTP_ASSOC_CHANGE
// notification reports termination rather than treating a previously observed
// id as a durable peer identity.
func (ep *SCTPEndpoint) SetAutoClose(seconds uint32) error {
	if ep == nil || ep.conn == nil || ep.conn.fd() < 0 {
		return errClosed("setsockopt")
	}
	return ep.conn.control("setsockopt", func(fd int) error {
		_, _, err := setsockopt(fd, SCTP_AUTOCLOSE,
			uintptr(unsafe.Pointer(&seconds)), unsafe.Sizeof(seconds))
		return err
	})
}

// GetAutoClose returns the endpoint's SCTP_AUTOCLOSE idle timeout in seconds
// (RFC 6458 §8.1.8). Zero means automatic close is disabled.
func (ep *SCTPEndpoint) GetAutoClose() (uint32, error) {
	if ep == nil || ep.conn == nil || ep.conn.fd() < 0 {
		return 0, errClosed("getsockopt")
	}

	var seconds uint32
	optlen := uint32(unsafe.Sizeof(seconds))
	err := ep.conn.control("getsockopt", func(fd int) error {
		_, _, err := getsockopt(fd, SCTP_AUTOCLOSE,
			uintptr(unsafe.Pointer(&seconds)), &optlen)
		return err
	})
	if err != nil {
		return 0, err
	}
	if optlen != uint32(unsafe.Sizeof(seconds)) {
		return 0, fmt.Errorf("sctp: SCTP_AUTOCLOSE returned %d bytes: %w",
			optlen, syscall.EPROTO)
	}
	return seconds, nil
}

// CloseAssociation gracefully shuts down one association while leaving every
// other association and the endpoint descriptor open (RFC 6458 §3.1.5).
// Completion is reported by SCTP_ASSOC_CHANGE with SCTP_SHUTDOWN_COMP.
func (ep *SCTPEndpoint) CloseAssociation(id SCTPAssocID) error {
	return ep.terminateAssociation(id, nil, SCTP_EOF)
}

// AbortAssociation terminates one association immediately and optionally
// carries cause as the user-specified ABORT data from RFC 6458 §3.1.5. Every
// other association and the endpoint descriptor remain open.
func (ep *SCTPEndpoint) AbortAssociation(id SCTPAssocID, cause []byte) error {
	return ep.terminateAssociation(id, cause, SCTP_ABORT)
}

func (ep *SCTPEndpoint) terminateAssociation(id SCTPAssocID, cause []byte, flag uint16) error {
	if ep == nil || ep.conn == nil || ep.conn.fd() < 0 {
		return errClosed("write")
	}
	if !validEndpointAssociationID(id) {
		return syscall.EINVAL
	}
	return ep.sendAssociationControl(cause, &SndInfo{
		Flags: flag, AssocID: int32(id),
	})
}

// sendAssociationControl bypasses syscall.SendmsgN deliberately. On Linux,
// Go's helper injects one dummy byte when ancillary data accompanies an empty
// payload on anything other than SOCK_DGRAM. RFC 6458 §3.2 requires a true
// zero-data send for SCTP_EOF, and Linux rejects EOF plus that dummy byte with
// EINVAL. A zero-length iovec reaches the kernel with the required semantics.
func (ep *SCTPEndpoint) sendAssociationControl(cause []byte, info *SndInfo) error {
	var sendErr error
	wait := ep.conn.writeWaitEnabled()
	err := ep.conn.raw.Write(func(fd uintptr) bool {
		sendErr = sendAssociationControlFD(int(fd), cause, info)
		if wait && (errors.Is(sendErr, syscall.EAGAIN) ||
			errors.Is(sendErr, syscall.EWOULDBLOCK)) {
			return false
		}
		return true
	})
	if err != nil {
		if ep.conn.fd() < 0 {
			return errClosed("write")
		}
		return normalizePollError("write", err)
	}
	if sendErr != nil && ep.conn.fd() < 0 {
		return errClosed("write")
	}
	return sendErr
}

// sendAssociationControlFD is the raw-descriptor form used while Close owns a
// descriptor it has already hidden from every public endpoint operation.
func sendAssociationControlFD(fd int, cause []byte, info *SndInfo) error {
	param := *info
	param.PPID = htonl(param.PPID)
	data := toBuf(&param)
	hdrLen := syscall.CmsgLen(0)
	cbuf := make([]byte, syscall.CmsgSpace(len(data)))
	hdr := (*syscall.Cmsghdr)(unsafe.Pointer(&cbuf[0]))
	hdr.Level = syscall.IPPROTO_SCTP
	hdr.Type = SCTP_CMSG_SNDINFO
	hdr.SetLen(syscall.CmsgLen(len(data)))
	copy(cbuf[hdrLen:], data)

	var iov syscall.Iovec
	if len(cause) > 0 {
		iov.Base = &cause[0]
		iov.SetLen(len(cause))
	}
	msg := syscall.Msghdr{
		Iov:     &iov,
		Iovlen:  1,
		Control: &cbuf[0],
	}
	msg.SetControllen(len(cbuf))

	for {
		_, err := rawSendmsg(fd, &msg, sendFlags)
		runtime.KeepAlive(cause)
		runtime.KeepAlive(cbuf)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		return err
	}
}

// PeelOff transfers one association to a new package-owned SCTPConn (RFC 6458
// §9.2). The id must identify a real association on this endpoint; scope
// selectors are rejected. After success every operation for that association,
// including queued data and close, belongs to the returned connection.
func (ep *SCTPEndpoint) PeelOff(id SCTPAssocID) (*SCTPConn, error) {
	if ep == nil || ep.conn == nil || ep.conn.fd() < 0 {
		return nil, errClosed("peeloff")
	}
	if !validEndpointAssociationID(id) {
		return nil, syscall.EINVAL
	}
	return ep.conn.PeelOff(int(id))
}

// Close gracefully shuts down every association still owned by the endpoint
// and releases its descriptor (RFC 6458 §3.1.5). It waits up to three seconds
// for the handshakes and then aborts any associations whose peers did not
// respond. Peeled associations are independent and remain open.
func (ep *SCTPEndpoint) Close() error {
	if ep == nil || ep.conn == nil {
		return errClosed("close")
	}
	c := ep.conn
	fd := atomic.SwapInt32(&c._fd, -1)
	if fd < 0 {
		return errClosed("close")
	}
	if c.file == nil || c.raw == nil {
		return closeSCTPEndpointSocket(int(fd), closeTimeout)
	}

	var prepareErr error
	controlErr := c.raw.Control(func(rawfd uintptr) {
		prepareErr = prepareSCTPEndpointClose(int(rawfd), closeTimeout)
	})
	closeErr := c.file.Close()
	if closeErr != nil {
		return normalizePollError("close", closeErr)
	}
	if controlErr != nil {
		return normalizePollError("close", controlErr)
	}
	return prepareErr
}

func closeSCTPEndpointSocket(fd int, timeout time.Duration) error {
	prepareErr := prepareSCTPEndpointClose(fd, timeout)
	if closeErr := syscall.Close(fd); closeErr != nil {
		return closeErr
	}
	return prepareErr
}

// prepareSCTPEndpointClose initiates shutdown separately for every association.
// Linux intentionally ignores shutdown(2) on one-to-many sockets, and a bare
// SCTP_EOF uses association selector zero (SCTP_FUTURE_ASSOC), which cannot
// identify any existing association. RFC 6458 §3.1.5 requires a separate EOF
// send for each association; §5.3.4 defines the SCTP_SNDINFO association-id
// field used to identify each target here.
func prepareSCTPEndpointClose(fd int, timeout time.Duration) error {
	if timeout <= 0 {
		return prepareSctpAbort(fd)
	}

	deadline := time.Now().Add(timeout)
	started := make(map[SCTPAssocID]struct{})
	var initiateErr error
	for delay := shutdownPollMin; ; {
		ids, err := endpointAssociationIDs(fd)
		if err != nil {
			return errors.Join(fmt.Errorf("sctp: list associations during close: %w", err),
				prepareSctpAbort(fd))
		}
		if len(ids) == 0 {
			return initiateErr
		}

		current := make(map[SCTPAssocID]struct{}, len(ids))
		for _, id := range ids {
			current[id] = struct{}{}
			if _, ok := started[id]; ok {
				continue
			}
			err := sendAssociationControlFD(fd, nil, &SndInfo{
				Flags: SCTP_EOF, AssocID: int32(id),
			})
			switch {
			case err == nil:
				started[id] = struct{}{}
			case errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EWOULDBLOCK):
				// Endpoint-wide writability can belong to another association.
				// Retry this id after the next association-list snapshot.
			case errors.Is(err, syscall.EINVAL), errors.Is(err, syscall.ENOTCONN),
				errors.Is(err, syscall.EPIPE), errors.Is(err, syscall.ENOENT):
				// The association disappeared or entered shutdown between the
				// snapshot and send. The next snapshot is authoritative.
				started[id] = struct{}{}
			default:
				initiateErr = errors.Join(initiateErr,
					fmt.Errorf("sctp: shut down association %d: %w", id, err))
				started[id] = struct{}{}
			}
		}
		// Linux may recycle an id after its association is freed. Forget ids
		// absent from this snapshot so a later association reusing one is not
		// mistaken for an EOF that was already sent.
		for id := range started {
			if _, ok := current[id]; !ok {
				delete(started, id)
			}
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.Join(initiateErr, prepareSctpAbort(fd))
		}
		if delay > remaining {
			delay = remaining
		}
		time.Sleep(delay)
		if delay < shutdownPollMax {
			delay *= 2
			if delay > shutdownPollMax {
				delay = shutdownPollMax
			}
		}
	}
}

// Abort immediately terminates every association still owned by the endpoint
// and releases its descriptor. Peeled associations are independent.
func (ep *SCTPEndpoint) Abort() error {
	if ep == nil || ep.conn == nil {
		return errClosed("close")
	}
	return ep.conn.Abort()
}

// SetDeadline sets both endpoint-wide receive and send deadlines.
func (ep *SCTPEndpoint) SetDeadline(t time.Time) error {
	if ep == nil || ep.conn == nil {
		return errClosed("set")
	}
	return ep.conn.SetDeadline(t)
}

// SetReadDeadline sets the deadline for pending and future Receive calls.
func (ep *SCTPEndpoint) SetReadDeadline(t time.Time) error {
	if ep == nil || ep.conn == nil {
		return errClosed("set")
	}
	return ep.conn.SetReadDeadline(t)
}

// SetWriteDeadline sets the deadline used by Send.
func (ep *SCTPEndpoint) SetWriteDeadline(t time.Time) error {
	if ep == nil || ep.conn == nil {
		return errClosed("set")
	}
	return ep.conn.SetWriteDeadline(t)
}
