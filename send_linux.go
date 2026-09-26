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

// send_linux.go is a Conn's send path, SendMsg and Write, and the socket's
// default send parameters, which the send path caches: DefaultSndInfo,
// SetDefaultSndInfo, DefaultPrInfo and SetDefaultPrInfo.
//
// A send allocates nothing. The control message is encoded into the
// connection's own storage (sendState), under the connection's send lock,
// and the one sendmsg(2) runs in a callback bound once, when the Conn is
// built, so no closure is made per call.

package sctp

import (
	"encoding/binary"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// sendFlags is what every send passes to sendmsg(2).
//
// MSG_DONTWAIT makes a full send buffer an EAGAIN, which the send path
// turns into a wait in the runtime poller, where a deadline or Close can
// end it; a blocking sendmsg to a peer that has stopped reading would
// not return until the association failed, bounded only by the
// retransmission and shutdown-guard timers, and nothing could interrupt
// it. MSG_NOSIGNAL keeps a send to an association that is gone from
// raising SIGPIPE: the kernel reports EPIPE either way
// (net/sctp/socket.c: sctp_error sends the signal only without it), and
// the errno is what a caller can act on.
const sendFlags = syscall.MSG_DONTWAIT | syscall.MSG_NOSIGNAL

// testHookSendmsg, when a test sets it, is called in place of rawSendmsg
// by the send path, to count, inspect or script its system calls.
var testHookSendmsg func(fd int, msg *syscall.Msghdr, flags int) (int, error)

// sendState is a Conn's send storage, reused by every send under mu, the
// connection's send lock. It guards the storage from the start of
// encoding the control message until the raw write returns, so
// concurrent sends can never exchange stream, PPID or other metadata. The
// descriptor's write lock (internal/poll: FD.writeLock) is taken inside
// it, by raw.Write.
type sendState struct {
	mu     sync.Mutex
	defSnd SndInfo // the socket's default SndInfo, as last read or set
	defPR  PrInfo  // the socket's default PrInfo, as last read or set

	cbuf [sndCmsgSpace]byte    // SNDINFO, PRINFO and AUTHINFO, the worst case
	name [sizeSockaddrIn6]byte // the destination for SendOptions.Path (Linux layout, sockaddr.go)
	msg  syscall.Msghdr        // points at iov, and at cbuf and name when a send uses them
	iov  syscall.Iovec         // points at b
	b    []byte                // the payload, set only while mu is held
	// flags, wait, n and err carry one send into attempt and its result
	// back out.
	flags int
	wait  bool // false for NoWait
	n     int
	err   error

	term *termState            // the connection's association-error latch
	fn   func(fd uintptr) bool // attempt, bound once
}

// init prepares s for c's sends; newConn calls it for every connection,
// once the association id is known. It binds the attempt callback and
// reads the socket's default send parameters, which the association took
// from its endpoint when it was set up (net/sctp/associola.c:
// sctp_association_init), after Config was applied or, for an accepted or
// adopted socket, as whoever set it up left them; reading them back rather
// than copying Config also captures what Control set. A socket the
// defaults cannot be read from, such as one whose association ended
// before Accept, starts with zero defaults.
func (s *sendState) init(c *Conn) {
	s.bind(&c.term)
	_ = c.sock.control(func(fd int) error {
		snd, err := getDefaultSndInfo(fd)
		if err != nil {
			return err
		}
		pr, err := getDefaultPrInfo(fd)
		if err != nil {
			return err
		}
		s.defSnd, s.defPR = snd, pr
		return nil
	})
}

// bind points s at the connection's latch and binds the attempt callback,
// the part of init that needs no socket.
func (s *sendState) bind(term *termState) {
	s.term = term
	s.fn = s.attempt
	s.msg.Iov = &s.iov
	s.msg.Iovlen = 1
}

// SendMsg sends b as one message, with the per-message parameters in opts
// (RFC 6458 §§5.3, 9.12), and returns len(b) once the kernel has queued it.
// Unless opts.NoWait is set, it waits for send-buffer space, in the
// runtime poller, until the write deadline passes or the connection is
// closed; with NoWait, a send that finds no space fails at once with an
// error matching syscall.EAGAIN, and nothing of the message is queued. A
// successful SendMsg makes no allocation, and SendMsg keeps nothing of b
// or opts after it returns.
//
// A nil opts.Info or opts.PR means the socket's default, in every
// combination (see SendOptions). A message has at least one byte: an
// empty b is refused with an error matching syscall.EINVAL before any
// system call (RFC 9260 §6.2). A message larger than the send buffer, or,
// with FragmentsDisabled, than the fragmentation point, fails with an
// error matching syscall.EMSGSIZE, and nothing of it is queued.
//
// opts.Path is refused, with an error matching syscall.EINVAL, on a
// connection peeled off an Endpoint, where Linux ignores the destination,
// and when it is not an address of the connection's family; a Path that is
// not one of the peer's addresses is refused by the kernel with
// syscall.EADDRNOTAVAIL. Once the association has ended, including one
// that ended before Accept, there is no peer to choose, and a send with
// Path fails as any other send does.
//
// Every error is a *net.OpError with Op "write". Once the association has
// failed, every send returns the error Linux reported for it; once a
// shutdown has started, sends fail with an error matching
// syscall.ESHUTDOWN, and once a gracefully ended association is gone, with
// syscall.EPIPE, never with a signal.
func (c *Conn) SendMsg(b []byte, opts SendOptions) (int, error) {
	if !c.opened() {
		return 0, c.writeError(net.ErrClosed)
	}
	var name [sizeSockaddrIn6]byte
	namelen, err := c.checkSend(b, &opts, &name)
	if err != nil {
		return 0, c.writeError(err)
	}
	if err := c.term.latched(); err != nil {
		return 0, c.writeError(err)
	}
	n, err := c.send.send(&c.sock, b, &opts, name[:namelen])
	if err != nil {
		return 0, c.writeError(err)
	}
	return n, nil
}

// Write sends b as one message with the socket's default send parameters:
// SendMsg with no options, under the same send lock, so that Write and
// SendMsg are atomic with respect to each other. Unlike a net.Conn over a
// byte stream, an empty b is refused with an error matching
// syscall.EINVAL, since an SCTP message has at least one byte.
func (c *Conn) Write(b []byte) (int, error) {
	return c.SendMsg(b, SendOptions{})
}

// writeError wraps a send's error once, with Op "write", the connection's
// network, and its address snapshots as Source and Addr.
func (c *Conn) writeError(err error) error {
	return opError("write", c.network(), c.LocalAddr(), c.RemoteAddr(), err)
}

// checkSend validates a send without taking any lock, and encodes
// opts.Path, when it is set and the connection has an association, into
// name, returning the encoded length (0 without Path). Every refusal
// matches syscall.EINVAL.
func (c *Conn) checkSend(b []byte, opts *SendOptions, name *[sizeSockaddrIn6]byte) (int, error) {
	if len(b) == 0 {
		// RFC 9260 §6.2: an endpoint should not send a DATA chunk with no
		// user data, and Linux refuses the message with the same errno
		// (net/sctp/socket.c: sctp_sendmsg_parse).
		return 0, invalidArg("SendMsg needs a message of at least one byte")
	}
	if err := validateSendOptions(opts); err != nil {
		return 0, err
	}
	if !opts.Path.IsValid() {
		return 0, nil
	}
	if c.kind == kindPeeled {
		return 0, invalidArg("SendOptions.Path is set on a connection peeled off an Endpoint, whose sends Linux never directs (net/sctp/socket.c: sctp_sendmsg_get_daddr ignores msg_name there)")
	}
	n, err := encodePathAddr(name[:], c.sock.family, opts.Path, c.peerPort, c.pathScope.Load())
	if err != nil {
		return 0, invalidArg("SendOptions.Path: %s", strings.TrimPrefix(err.Error(), "sctp: "))
	}
	if c.assoc == 0 {
		// The association ended before Accept and the socket is CLOSED
		// (net/sctp/socket.c: sctp_sock_migrate). A destination there
		// would not name a path of it: sctp_sendmsg would find no
		// association for the address and set up a new one
		// (sctp_sendmsg_new_asoc refuses that only on a socket that is
		// ESTABLISHED or CLOSING). Without one, the send fails as any
		// send on the socket does.
		return 0, nil
	}
	return n, nil
}

// send is one send under the send lock: it points msg at b, the control
// records and the destination, makes the attempt through raw.Write, and
// clears every reference to the caller's memory before it releases the
// lock.
func (s *sendState) send(sock *socket, b []byte, opts *SendOptions, name []byte) (int, error) {
	s.mu.Lock()
	s.b = b
	s.iov.Base = &b[0]
	s.iov.SetLen(len(b))
	if n := s.encode(opts); n > 0 {
		s.msg.Control = &s.cbuf[0]
		s.msg.SetControllen(n)
	} else {
		s.msg.Control = nil
		s.msg.SetControllen(0)
	}
	if len(name) > 0 {
		copy(s.name[:], name)
		s.msg.Name = &s.name[0]
		s.msg.Namelen = uint32(len(name))
	} else {
		s.msg.Name = nil
		s.msg.Namelen = 0
	}
	s.flags = sendFlags
	if opts.More {
		// MSG_MORE (Linux 4.11) sets asoc->force_delay, which lets the
		// kernel hold this message to bundle it with the next
		// (net/sctp/socket.c: sctp_sendmsg_to_asoc).
		s.flags |= syscall.MSG_MORE
	}
	s.wait = !opts.NoWait

	err := sock.raw.Write(s.fn)
	n, serr := s.n, s.err
	s.b, s.iov.Base = nil, nil
	s.n, s.err = 0, nil
	s.mu.Unlock()

	if err == nil {
		err = serr
	}
	if err != nil {
		return 0, err
	}
	return n, nil
}

// encode writes the control records a send carries into cbuf and returns
// their length, 0 for none.
//
// A Conn send with neither Info nor PR carries no SNDINFO or PRINFO, and
// Linux applies the association's defaults itself. Linux applies them only
// to a message without SNDINFO, though, and the default flags and PR
// policy only when there is no PRINFO either (net/sctp/socket.c:
// sctp_sendmsg_update_sinfo), so when one of the two is set the other is
// sent explicitly from the cached default: SNDINFO from Info or defSnd,
// and PRINFO from PR, or from defPR when its policy is not PRNone.
// AUTHINFO is added when AuthKey is set, and is the only record of a send
// that sets nothing else.
func (s *sendState) encode(opts *SendOptions) int {
	var (
		snd *SndInfo
		pr  *PrInfo
	)
	if opts.Info != nil || opts.PR != nil {
		snd = opts.Info
		if snd == nil {
			snd = &s.defSnd
		}
		pr = opts.PR
		if pr == nil && s.defPR.Policy != PRNone {
			pr = &s.defPR
		}
	}
	// A one-to-one or peeled socket ignores snd_assoc_id (RFC 6458 §5.3.4).
	return appendSendCmsgs(s.cbuf[:0], snd, 0, pr, opts.AuthKey)
}

// attempt is the raw.Write callback: one sendmsg, made while the latch
// mutex is held, so that an association error the kernel hands this call
// is latched before any other call can look (termState). It returns false,
// so that the poller waits for buffer space, only on EAGAIN for a send
// that waits; it retries EINTR in place. A latched error ends the send
// without a system call.
//
// A send with a destination (SendOptions.Path) that Linux refuses with
// EADDRNOTAVAIL is made once more without it when the association turns
// out to be gone. Linux finds the association of such a send by address,
// and once the association is gone it answers EADDRNOTAVAIL, as for an
// address that is not a peer's (net/sctp/socket.c: sctp_sendmsg_new_asoc
// on an ESTABLISHED or CLOSING one-to-one socket), and leaves the error it
// set on the socket for the association's end pending; sctp_error hands
// that error over only in place of EPIPE. Without a destination the send
// finds no association (sctp_id2assoc) and gets exactly that, and nothing
// can be queued for an association that does not exist. So the send
// reports what any send does after the end, and the latch sees it.
func (s *sendState) attempt(fd uintptr) bool {
	for {
		s.term.mu.Lock()
		if err := s.term.err; err != nil {
			s.term.mu.Unlock()
			s.n, s.err = 0, err
			return true
		}
		n, err := s.sendmsg(int(fd))
		if err == syscall.EADDRNOTAVAIL && s.msg.Name != nil && assocEnded(int(fd)) {
			s.msg.Name, s.msg.Namelen = nil, 0
			n, err = s.sendmsg(int(fd))
		}
		if err != nil {
			err = s.term.sendErrorLocked(err)
		}
		s.term.mu.Unlock()

		switch {
		case err == syscall.EINTR:
			continue
		case err == syscall.EAGAIN && s.wait:
			return false
		}
		s.n, s.err = n, err
		return true
	}
}

// sendmsg makes the one system call of an attempt.
func (s *sendState) sendmsg(fd int) (int, error) {
	if hook := testHookSendmsg; hook != nil {
		return hook(fd, &s.msg, s.flags)
	}
	return rawSendmsg(fd, &s.msg, s.flags)
}

// assocEnded reports whether the socket's association is gone: SCTP_STATUS
// (RFC 6458 §8.2.1) fails with EINVAL once Linux has freed it
// (net/sctp/socket.c: sctp_getsockopt_sctp_status, sctp_id2assoc), or
// reports it CLOSED (socket.status). It takes nothing from the socket, and
// allocates nothing.
func assocEnded(fd int) bool {
	var b [sizeStatus]byte
	l := uint32(len(b))
	if err := rawGetsockopt(fd, ipprotoSCTP, optStatus, unsafe.Pointer(&b[0]), &l); err != nil {
		return err == syscall.EINVAL
	}
	return AssocState(int32(binary.NativeEndian.Uint32(b[statusStateOff:]))) == StateClosed
}

// DefaultSndInfo reads the socket's default send parameters
// (SCTP_DEFAULT_SNDINFO, RFC 6458 §8.1.31) from the kernel: what Write, and
// SendMsg with a nil SendOptions.Info, send with. Flags holds at most
// SendUnordered; the default PR-SCTP policy, which Linux keeps in the same
// word, is DefaultPrInfo's. Errors are *net.OpError with Op "get".
func (c *Conn) DefaultSndInfo() (*SndInfo, error) {
	if !c.opened() {
		return nil, c.optionError("get", net.ErrClosed)
	}
	c.optMu.Lock()
	defer c.optMu.Unlock()
	var snd SndInfo
	if err := c.sock.control(func(fd int) error {
		var err error
		snd, err = getDefaultSndInfo(fd)
		return err
	}); err != nil {
		return nil, c.optionError("get", err)
	}
	return &snd, nil
}

// SetDefaultSndInfo sets the socket's default send parameters
// (SCTP_DEFAULT_SNDINFO, RFC 6458 §8.1.31) for the association. Flags may
// hold only SendUnordered: Linux refuses SendSACKImmediately in a default
// (net/sctp/socket.c: sctp_setsockopt_default_sndinfo), and the package
// refuses it, and a nil info, with an error matching syscall.EINVAL
// before any system call. Linux keeps the default PR-SCTP policy in the
// same word as the default flags and overwrites it here, so the package
// sets the default PrInfo again afterwards: the two defaults stay
// independent, and the connection's option lock keeps DefaultPrInfo from
// seeing the policy between the two writes. It takes the connection's send
// lock, so it waits for a send in progress. Errors are *net.OpError with
// Op "set".
func (c *Conn) SetDefaultSndInfo(info *SndInfo) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	if info == nil {
		return c.argError("set", invalidArg("SetDefaultSndInfo needs a non-nil *SndInfo"))
	}
	if err := validateDefaultSndInfo("SetDefaultSndInfo", info); err != nil {
		return c.argError("set", err)
	}
	v := *info
	c.send.mu.Lock()
	defer c.send.mu.Unlock()
	c.optMu.Lock()
	defer c.optMu.Unlock()
	if err := c.sock.control(func(fd int) error {
		return setDefaultSndInfo(fd, v.Stream, uint16(v.Flags), networkOrderUint32(v.PPID), v.Context)
	}); err != nil {
		return c.optionError("set", err)
	}
	c.send.defSnd = v
	return nil
}

// DefaultPrInfo reads the socket's default PR-SCTP policy
// (SCTP_DEFAULT_PRINFO, RFC 6458 §8.1.32; RFC 7496 §4) from the kernel:
// what Write, and SendMsg with a nil SendOptions.PR, send with. Errors are
// *net.OpError with Op "get".
func (c *Conn) DefaultPrInfo() (*PrInfo, error) {
	if !c.opened() {
		return nil, c.optionError("get", net.ErrClosed)
	}
	c.optMu.Lock()
	defer c.optMu.Unlock()
	var pr PrInfo
	if err := c.sock.control(func(fd int) error {
		var err error
		pr, err = getDefaultPrInfo(fd)
		return err
	}); err != nil {
		return nil, c.optionError("get", err)
	}
	return &pr, nil
}

// SetDefaultPrInfo sets the socket's default PR-SCTP policy
// (SCTP_DEFAULT_PRINFO, RFC 6458 §8.1.32) for the association. A nil pr,
// PRAll, an unknown policy, and a PRTTL lifetime that is negative, not a
// whole number of milliseconds or beyond the uint32 milliseconds the
// kernel keeps are refused with an error matching syscall.EINVAL before
// any system call. It takes the connection's send lock, so it waits for a
// send in progress. Errors are *net.OpError with Op "set".
func (c *Conn) SetDefaultPrInfo(pr *PrInfo) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	if pr == nil {
		return c.argError("set", invalidArg("SetDefaultPrInfo needs a non-nil *PrInfo"))
	}
	if err := validatePrInfo("SetDefaultPrInfo", pr); err != nil {
		return c.argError("set", err)
	}
	policy, value := resolvePrInfo(pr)
	c.send.mu.Lock()
	defer c.send.mu.Unlock()
	c.optMu.Lock()
	defer c.optMu.Unlock()
	if err := c.sock.control(func(fd int) error {
		return setDefaultPrInfo(fd, policy, value)
	}); err != nil {
		return c.optionError("set", err)
	}
	c.send.defPR = prInfoFromKernel(policy, value)
	return nil
}

// optionError wraps a socket-option failure of c: a *net.OpError with Op
// op ("get" or "set") around an *os.SyscallError naming getsockopt or
// setsockopt, or net.ErrClosed on a released descriptor.
func (c *Conn) optionError(op string, err error) error {
	call := "getsockopt"
	if op == "set" {
		call = "setsockopt"
	}
	return optError(op, call, c.network(), nil, c.LocalAddr(), err)
}

// argError wraps an argument an option method refused before any system
// call.
func (c *Conn) argError(op string, err error) error {
	return opError(op, c.network(), nil, c.LocalAddr(), err)
}

// getDefaultSndInfo reads SCTP_DEFAULT_SNDINFO (RFC 6458 §8.1.31) with
// association id 0: on a connected one-to-one or peeled socket the kernel
// answers for the socket's association, otherwise for the endpoint
// (net/sctp/socket.c: sctp_getsockopt_default_sndinfo, sctp_id2assoc).
// The flags word also carries the default PR-SCTP policy, which is
// dropped here (splitDefaultFlags); the PPID is kept in network order by
// the kernel.
func getDefaultSndInfo(fd int) (SndInfo, error) {
	var b [sizeSndInfo]byte
	l := uint32(len(b))
	if err := rawGetsockopt(fd, ipprotoSCTP, optDefaultSndInfo, unsafe.Pointer(&b[0]), &l); err != nil {
		return SndInfo{}, err
	}
	flags, _ := splitDefaultFlags(binary.NativeEndian.Uint16(b[sndInfoFlagsOff:]))
	return SndInfo{
		Stream:  binary.NativeEndian.Uint16(b[sndInfoStreamOff:]),
		Flags:   flags,
		PPID:    binary.BigEndian.Uint32(b[sndInfoPPIDOff:]),
		Context: binary.NativeEndian.Uint32(b[sndInfoContextOff:]),
	}, nil
}

// getDefaultPrInfo reads SCTP_DEFAULT_PRINFO (RFC 6458 §8.1.32) with
// association id 0, which the kernel answers the same way as
// SCTP_DEFAULT_SNDINFO (net/sctp/socket.c: sctp_getsockopt_default_prinfo).
func getDefaultPrInfo(fd int) (PrInfo, error) {
	var b [sizeDefaultPRInfo]byte
	l := uint32(len(b))
	if err := rawGetsockopt(fd, ipprotoSCTP, optDefaultPRInfo, unsafe.Pointer(&b[0]), &l); err != nil {
		return PrInfo{}, err
	}
	return prInfoFromKernel(binary.NativeEndian.Uint16(b[defaultPRInfoPolicyOff:]), binary.NativeEndian.Uint32(b[defaultPRInfoValueOff:])), nil
}

// prInfoFromKernel is resolvePrInfo's inverse: the PrInfo a kernel policy
// and value describe (RFC 7496 §4.2's table: PRTTL's value is the lifetime
// in milliseconds, PRRtx's and PRPrio's are Value).
func prInfoFromKernel(policy uint16, value uint32) PrInfo {
	switch p := PRPolicy(policy & prPolicyMask); p {
	case PRNone:
		return PrInfo{}
	case PRTTL:
		return PrInfo{Policy: p, TTL: time.Duration(value) * time.Millisecond}
	default: // PRRtx, PRPrio
		return PrInfo{Policy: p, Value: value}
	}
}

// setDefaultSndInfo sets SCTP_DEFAULT_SNDINFO (RFC 6458 §8.1.31) with
// association id 0, for the association on a connected socket and for the
// endpoint otherwise, and keeps the default PR-SCTP policy: Linux holds
// that policy in the same default_flags word, which
// sctp_setsockopt_default_sndinfo overwrites whole (net/sctp/socket.c;
// SCTP_PR_SET_POLICY in sctp_setsockopt_default_prinfo), so the PR default
// is read first and set again afterwards when its policy is not PRNone.
// ppid is already in network order. Conn.SetDefaultSndInfo and the
// Config.DefaultSndInfo step both use it. The error is the bare errno.
func setDefaultSndInfo(fd int, stream, flags uint16, ppid, context uint32) error {
	var pr [sizeDefaultPRInfo]byte
	l := uint32(len(pr))
	if err := rawGetsockopt(fd, ipprotoSCTP, optDefaultPRInfo, unsafe.Pointer(&pr[0]), &l); err != nil {
		return err
	}
	var b [sizeSndInfo]byte
	binary.NativeEndian.PutUint16(b[sndInfoStreamOff:], stream)
	binary.NativeEndian.PutUint16(b[sndInfoFlagsOff:], flags)
	binary.NativeEndian.PutUint32(b[sndInfoPPIDOff:], ppid)
	binary.NativeEndian.PutUint32(b[sndInfoContextOff:], context)
	if err := rawSetsockopt(fd, ipprotoSCTP, optDefaultSndInfo, unsafe.Pointer(&b[0]), uintptr(len(b))); err != nil {
		return err
	}
	policy := binary.NativeEndian.Uint16(pr[defaultPRInfoPolicyOff:]) & prPolicyMask
	if PRPolicy(policy) == PRNone {
		return nil
	}
	return setDefaultPrInfo(fd, policy, binary.NativeEndian.Uint32(pr[defaultPRInfoValueOff:]))
}

// setDefaultPrInfo sets SCTP_DEFAULT_PRINFO (RFC 6458 §8.1.32) with
// association id 0; policy and value are already in the kernel's form
// (resolvePrInfo). The error is the bare errno.
func setDefaultPrInfo(fd int, policy uint16, value uint32) error {
	var b [sizeDefaultPRInfo]byte
	binary.NativeEndian.PutUint32(b[defaultPRInfoValueOff:], value)
	binary.NativeEndian.PutUint16(b[defaultPRInfoPolicyOff:], policy)
	return rawSetsockopt(fd, ipprotoSCTP, optDefaultPRInfo, unsafe.Pointer(&b[0]), uintptr(len(b)))
}
