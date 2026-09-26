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

// options_linux.go holds the typed socket options of a Conn for its
// buffers, its paths, its association and its send and receive behaviour;
// options_ext_linux.go holds those of the negotiated extensions. Each
// method checks its arguments before any system call, lays the value out
// with options.go's codecs, and makes one getsockopt or setsockopt, except
// where its comment says otherwise.
//
// Every association-scoped option names the connection's own association
// id. On a one-to-one socket, and on one peeled off an Endpoint, Linux
// ignores the id and answers for the socket's one association while there
// is one (net/sctp/socket.c: sctp_id2assoc). Once the association has
// ended, the queries that need one, such as Status, Stats and PathInfo,
// fail with Linux's EINVAL, and most other options read or set the
// socket's own defaults, as Linux has them do.
//
// Errors follow net's own option setters: a *net.OpError with Op "get" or
// "set", around an *os.SyscallError naming getsockopt or setsockopt and
// holding the kernel's errno, so that errors.Is(err, syscall.ENOPROTOOPT)
// detects an option the running kernel lacks (net/sctp/socket.c: the
// default case of sctp_setsockopt and sctp_getsockopt). An argument
// refused before any system call matches syscall.EINVAL and names the
// argument, inside the same *net.OpError; on a closed Conn every method
// returns one matching net.ErrClosed.

package sctp

import (
	"encoding/binary"
	"math"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

// --- the option layer -------------------------------------------------------

// callError wraps a failure of the system call named call in an option
// method with Op op. A setter that reads before it writes can fail in its
// getsockopt, and names it.
func (c *Conn) callError(op, call string, err error) error {
	return optError(op, call, c.network(), nil, c.LocalAddr(), err)
}

// getOpt reads SCTP option opt into b, which the caller has prepared, and
// returns the length the kernel reports.
func (c *Conn) getOpt(opt int, b []byte) (int, error) {
	if !c.opened() {
		return 0, c.optionError("get", net.ErrClosed)
	}
	l := uint32(len(b))
	if err := c.sock.getsockopt(opt, unsafe.Pointer(&b[0]), &l); err != nil {
		return 0, c.optionError("get", err)
	}
	return int(l), nil
}

// setOpt writes b to SCTP option opt.
func (c *Conn) setOpt(opt int, b []byte) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	if err := c.sock.setsockopt(opt, unsafe.Pointer(&b[0]), uintptr(len(b))); err != nil {
		return c.optionError("set", err)
	}
	return nil
}

// intOption reads a plain C int option at level.
func (c *Conn) intOption(level, opt int) (int32, error) {
	if !c.opened() {
		return 0, c.optionError("get", net.ErrClosed)
	}
	var b [sizeInt]byte
	l := uint32(len(b))
	if err := c.sock.getsockoptAt(level, opt, unsafe.Pointer(&b[0]), &l); err != nil {
		return 0, c.optionError("get", err)
	}
	return int32(binary.NativeEndian.Uint32(b[:])), nil
}

// setIntOption writes a plain C int option at level.
func (c *Conn) setIntOption(level, opt int, v int32) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	var b [sizeInt]byte
	binary.NativeEndian.PutUint32(b[:], uint32(v))
	if err := c.sock.setsockoptAt(level, opt, unsafe.Pointer(&b[0]), uintptr(len(b))); err != nil {
		return c.optionError("set", err)
	}
	return nil
}

// boolOption reads a boolean SCTP option, a C int that is 0 or not.
func (c *Conn) boolOption(opt int) (bool, error) {
	v, err := c.intOption(ipprotoSCTP, opt)
	return v != 0, err
}

// setBoolOption writes a boolean SCTP option as 0 or 1.
func (c *Conn) setBoolOption(opt int, on bool) error {
	return c.setIntOption(ipprotoSCTP, opt, int32(boolValue(on)))
}

// assocValueOption reads a struct sctp_assoc_value option for the
// connection's association.
func (c *Conn) assocValueOption(opt int) (uint32, error) {
	var b [sizeAssocValue]byte
	binary.NativeEndian.PutUint32(b[assocValueAssocIDOff:], uint32(c.AssocID()))
	if _, err := c.getOpt(opt, b[:]); err != nil {
		return 0, err
	}
	return binary.NativeEndian.Uint32(b[assocValueValueOff:]), nil
}

// setAssocValueOption writes a struct sctp_assoc_value option for the
// connection's association.
func (c *Conn) setAssocValueOption(opt int, v uint32) error {
	var b [sizeAssocValue]byte
	binary.NativeEndian.PutUint32(b[assocValueAssocIDOff:], uint32(c.AssocID()))
	binary.NativeEndian.PutUint32(b[assocValueValueOff:], v)
	return c.setOpt(opt, b[:])
}

// pathAddr encodes path, with the association's peer port, into dst for a
// path option of method name, and returns its length: 0 for the zero
// netip.Addr, the association as a whole. A link-local path without a
// zone takes the association's link-local scope id, when it has one
// (Conn.pathScope, encodePathAddr). An address the socket's family cannot
// carry is refused with an error matching syscall.EINVAL.
func (c *Conn) pathAddr(dst []byte, name string, path netip.Addr) (int, error) {
	n, err := encodePathAddr(dst, c.sock.family, path, c.peerPort, c.pathScope.Load())
	if err != nil {
		return 0, invalidArg("%s: %s", name, strings.TrimPrefix(err.Error(), "sctp: "))
	}
	return n, nil
}

// --- socket buffers -------------------------------------------------------------

// ReadBuffer reports the socket's receive buffer size (SO_RCVBUF). Linux
// doubles the size it is given, to allow for its own bookkeeping
// (net/core/sock.c: __sock_set_rcvbuf), and reports the doubled size.
func (c *Conn) ReadBuffer() (int, error) {
	v, err := c.intOption(syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	return int(v), err
}

// SetReadBuffer sets the socket's receive buffer size (SO_RCVBUF), capped at
// net.core.rmem_max and then doubled by Linux, as Config.ReadBuffer is.
// SetReadBuffer never resizes the association's receive window, which Linux
// fixes from the receive buffer when the association is created (set it with
// Config.ReadBuffer). A later value only moves the point at which
// receive-buffer pressure advertises a zero window: a smaller buffer closes
// the window sooner, and a larger one does not open it any wider. A size
// that is not positive, or beyond the C int the option takes, is refused
// with an error matching syscall.EINVAL.
func (c *Conn) SetReadBuffer(bytes int) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	v, err := bufferSizeArg("SetReadBuffer", bytes)
	if err != nil {
		return c.argError("set", err)
	}
	return c.setIntOption(syscall.SOL_SOCKET, syscall.SO_RCVBUF, v)
}

// WriteBuffer reports the socket's send buffer size (SO_SNDBUF), which
// Linux reports doubled, as for ReadBuffer (net/core/sock.c: sk_setsockopt,
// its SO_SNDBUF case).
func (c *Conn) WriteBuffer() (int, error) {
	v, err := c.intOption(syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	return int(v), err
}

// SetWriteBuffer sets the socket's send buffer size (SO_SNDBUF), capped at
// net.core.wmem_max and then doubled by Linux. It takes effect on the live
// association, for the send-buffer space later sends wait for; a message
// larger than the doubled buffer is refused with EMSGSIZE. Sizes are
// checked as for SetReadBuffer.
func (c *Conn) SetWriteBuffer(bytes int) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	v, err := bufferSizeArg("SetWriteBuffer", bytes)
	if err != nil {
		return c.argError("set", err)
	}
	return c.setIntOption(syscall.SOL_SOCKET, syscall.SO_SNDBUF, v)
}

// --- addresses and paths --------------------------------------------------------

// PrimaryAddr reports the peer address the association sends to by default
// (SCTP_PRIMARY_ADDR, RFC 6458 §8.1.9).
func (c *Conn) PrimaryAddr() (netip.Addr, error) {
	var b [sizePrim]byte
	binary.NativeEndian.PutUint32(b[primAssocIDOff:], uint32(c.AssocID()))
	if _, err := c.getOpt(optPrimaryAddr, b[:]); err != nil {
		return netip.Addr{}, err
	}
	a, err := decodeAddr(b[primAddrOff:])
	if err != nil {
		return netip.Addr{}, c.argError("get", err)
	}
	return a.Addr(), nil
}

// SetPrimaryAddr makes path, one of the peer's addresses, the one the
// association sends to by default (RFC 6458 §8.1.9). The zero netip.Addr is
// refused with an error matching syscall.EINVAL before any system call; an
// address that is not the peer's is refused by Linux with EINVAL
// (net/sctp/socket.c: sctp_setsockopt_primary_addr).
//
// A link-local path given without a zone is completed as for
// SendOptions.Path.
func (c *Conn) SetPrimaryAddr(path netip.Addr) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	if !path.IsValid() {
		return c.argError("set", invalidArg("SetPrimaryAddr needs one peer address, not the zero netip.Addr"))
	}
	var b [sizePrim]byte
	if _, err := c.pathAddr(b[primAddrOff:], "SetPrimaryAddr", path); err != nil {
		return c.argError("set", err)
	}
	binary.NativeEndian.PutUint32(b[primAssocIDOff:], uint32(c.AssocID()))
	return c.setOpt(optPrimaryAddr, b[:])
}

// RequestPeerPrimary asks the peer to make local, one of this side's
// addresses in the association, its primary path to this side, with an
// ASCONF Set Primary Address request (RFC 6458 §8.3.1; RFC 5061 §4.2.4).
// It returns once the request is queued, not when the peer has answered.
// ASCONF must have been negotiated (Config.DynamicAddressReconfiguration):
// otherwise Linux refuses with EPERM, and an address that is not this
// side's with EADDRNOTAVAIL (net/sctp/socket.c:
// sctp_setsockopt_peer_primary_addr). The zero netip.Addr is refused with an
// error matching syscall.EINVAL before any system call.
func (c *Conn) RequestPeerPrimary(local netip.Addr) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	if !local.IsValid() {
		return c.argError("set", invalidArg("RequestPeerPrimary needs one local address, not the zero netip.Addr"))
	}
	var port uint16
	if a := c.laddr.Load(); a != nil {
		port = a.Port
	}
	var b [sizeSetPeerPrim]byte
	// Linux matches the address and the association's local port
	// (net/sctp/associola.c: sctp_assoc_lookup_laddr).
	if _, err := encodeAddr(b[setPeerPrimAddrOff:], c.sock.family, local, port); err != nil {
		return c.argError("set", invalidArg("RequestPeerPrimary: %s", strings.TrimPrefix(err.Error(), "sctp: ")))
	}
	binary.NativeEndian.PutUint32(b[setPeerPrimAssocIDOff:], uint32(c.AssocID()))
	return c.setOpt(optSetPeerPrimaryAddr, b[:])
}

// PathInfo reports the state of one path of the association: the peer
// address path, its reachability, congestion window, smoothed round-trip
// time and RTO, and its MTU (SCTP_GET_PEER_ADDR_INFO, RFC 6458 §8.2.2).
// SRTTTicks is in kernel ticks, as Linux reports it. The zero netip.Addr is
// refused with an error matching syscall.EINVAL before any system call; an
// address that is not the peer's is refused by Linux with EINVAL, and a
// path in the Potentially Failed state with EACCES while PFExposure is
// PFExposeDisabled (net/sctp/socket.c: sctp_getsockopt_peer_addr_info).
//
// A link-local path given without a zone is completed as for
// SendOptions.Path.
func (c *Conn) PathInfo(path netip.Addr) (*PathInfo, error) {
	if !c.opened() {
		return nil, c.optionError("get", net.ErrClosed)
	}
	if !path.IsValid() {
		return nil, c.argError("get", invalidArg("PathInfo needs one peer address, not the zero netip.Addr"))
	}
	var b [sizePathInfo]byte
	if _, err := c.pathAddr(b[pathInfoAddressOff:], "PathInfo", path); err != nil {
		return nil, c.argError("get", err)
	}
	binary.NativeEndian.PutUint32(b[pathInfoAssocIDOff:], uint32(c.AssocID()))
	if _, err := c.getOpt(optGetPeerAddrInfo, b[:]); err != nil {
		return nil, err
	}
	info := decodePathInfo(b[:])
	return &info, nil
}

// PathParams reports the heartbeat, retransmission, path MTU, delayed SACK
// and marking parameters of one path, or, for the zero netip.Addr, the
// association's (SCTP_PEER_ADDR_PARAMS, RFC 6458 §8.1.12). Every field is
// set except IPv6FlowLabel and DSCP, which Linux reports only once a value
// has been set through this option, and which are nil otherwise
// (net/sctp/socket.c: sctp_getsockopt_peer_addr_params). A path that is
// not the peer's is refused by Linux with EINVAL.
//
// A link-local path given without a zone is completed as for
// SendOptions.Path.
func (c *Conn) PathParams(path netip.Addr) (*PathParams, error) {
	if !c.opened() {
		return nil, c.optionError("get", net.ErrClosed)
	}
	var b [sizePathParams]byte
	if _, err := c.pathAddr(b[pathParamsAddressOff:], "PathParams", path); err != nil {
		return nil, c.argError("get", err)
	}
	binary.NativeEndian.PutUint32(b[pathParamsAssocIDOff:], uint32(c.AssocID()))
	if _, err := c.getOpt(optPeerAddrParams, b[:]); err != nil {
		return nil, err
	}
	return decodePathParams(b[:]), nil
}

// SetPathParams changes the parameters of one path, or, for the zero
// netip.Addr, of the association and every path it has
// (SCTP_PEER_ADDR_PARAMS, RFC 6458 §8.1.12). A nil field leaves that
// setting unchanged.
//
// Linux reads a value only together with its switch, so a
// HeartbeatInterval needs Heartbeat set to true in the same call, a
// PathMTU needs PMTUD set to false, and a SACKDelay needs DelayedSACK set
// to true; a HeartbeatInterval of 0 sends heartbeats without a delay
// (SPP_HB_TIME_IS_ZERO). A zero PathMaxRetrans, PathMTU or SACKDelay,
// which Linux would read as "unchanged", a PathMTU below 512 bytes, a
// SACKDelay above RFC 9260 §6.2's 500 ms or not in whole milliseconds, an
// IPv6FlowLabel beyond 20 bits and a DSCP whose low two bits are set are
// refused with an error matching syscall.EINVAL before any system call,
// as is a nil p. DSCP is spp_dscp as RFC 6458 §8.1.12 defines it, with the
// code point in its 6 most significant bits: code point 46 (EF) is 0xb8.
// Linux applies IPv6FlowLabel to IPv6 paths only. A path that is not the
// peer's is refused by Linux with EINVAL
// (net/sctp/socket.c: sctp_setsockopt_peer_addr_params). It takes the
// connection's option lock, which SetPathThresholds holds while it reads
// and writes back the same retransmission limit.
//
// A link-local path given without a zone is completed as for
// SendOptions.Path.
func (c *Conn) SetPathParams(path netip.Addr, p *PathParams) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	if p == nil {
		return c.argError("set", invalidArg("SetPathParams needs a non-nil *PathParams"))
	}
	var addr [sizeSockaddrIn6]byte
	n, err := c.pathAddr(addr[:], "SetPathParams", path)
	if err != nil {
		return c.argError("set", err)
	}
	var b [sizePathParams]byte
	if err := encodePathParams(b[:], c.AssocID(), addr[:n], p, "PathParams"); err != nil {
		return c.argError("set", err)
	}
	// SetPathThresholds reads and writes back the retransmission limit this
	// can set; the option lock keeps it from writing an older one over
	// this.
	c.optMu.Lock()
	defer c.optMu.Unlock()
	return c.setOpt(optPeerAddrParams, b[:])
}

// RequestHeartbeat sends a HEARTBEAT on one path now (SPP_HB_DEMAND, RFC
// 6458 §8.1.12; RFC 9260 §8.3), or, for the zero netip.Addr, on every path
// of the association (net/sctp/socket.c: sctp_setsockopt_peer_addr_params
// applies the request to each transport). It returns once the HEARTBEAT
// is sent, not when it is acknowledged. A path that is not the peer's is
// refused by Linux with EINVAL.
//
// A link-local path given without a zone is completed as for
// SendOptions.Path.
func (c *Conn) RequestHeartbeat(path netip.Addr) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	var addr [sizeSockaddrIn6]byte
	n, err := c.pathAddr(addr[:], "RequestHeartbeat", path)
	if err != nil {
		return c.argError("set", err)
	}
	var b [sizePathParams]byte
	heartbeatDemand(b[:], c.AssocID(), addr[:n])
	return c.setOpt(optPeerAddrParams, b[:])
}

// PathThresholds reports the failure thresholds of one path, or, for the
// zero netip.Addr, the association's (SCTP_PEER_ADDR_THLDS_V2, RFC 7829
// §7.2): the retransmissions after which the path becomes inactive, those
// after which it becomes Potentially Failed, and those after which the
// association switches its primary away from it (RFC 7829 §5). A path that
// is not the peer's is refused by Linux with ENOENT
// (net/sctp/socket.c: sctp_getsockopt_paddr_thresholds).
//
// A link-local path given without a zone is completed as for
// SendOptions.Path.
func (c *Conn) PathThresholds(path netip.Addr) (*PathThresholds, error) {
	if !c.opened() {
		return nil, c.optionError("get", net.ErrClosed)
	}
	var addr [sizeSockaddrIn6]byte
	n, err := c.pathAddr(addr[:], "PathThresholds", path)
	if err != nil {
		return nil, c.argError("get", err)
	}
	v, err := c.readThresholds(addr[:n])
	if err != nil {
		return nil, c.callError("get", "getsockopt", err)
	}
	return &PathThresholds{PathMaxRetrans: &v.maxRetrans, PFThreshold: &v.pf, PrimarySwitchover: &v.switchover}, nil
}

// SetPathThresholds changes the failure thresholds of one path, or, for the
// zero netip.Addr, of the association and every path it has
// (SCTP_PEER_ADDR_THLDS_V2, RFC 7829 §7.2). A nil field leaves that
// threshold unchanged: Linux applies all three whatever they hold
// (net/sctp/socket.c: sctp_setsockopt_paddr_thresholds), so the package
// reads the thresholds, changes the fields given and writes them back,
// holding the connection's option lock so that neither another
// SetPathThresholds nor a SetPathParams changing the retransmission limit
// is lost. For the association as a whole, a nil field
// keeps the association's value, which Linux then applies to every path.
// A nil t and a PathMaxRetrans of 0, which Linux would read as
// "unchanged", are refused with an error matching syscall.EINVAL before
// any system call. Linux refuses a PFThreshold above PrimarySwitchover
// with EINVAL, and a path that is not the peer's with ENOENT.
//
// A link-local path given without a zone is completed as for
// SendOptions.Path.
func (c *Conn) SetPathThresholds(path netip.Addr, t *PathThresholds) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	if t == nil {
		return c.argError("set", invalidArg("SetPathThresholds needs a non-nil *PathThresholds"))
	}
	if t.PathMaxRetrans != nil && *t.PathMaxRetrans == 0 {
		return c.argError("set", invalidArg("PathThresholds.PathMaxRetrans is 0, which Linux reads as leaving the value unchanged"))
	}
	var addr [sizeSockaddrIn6]byte
	n, err := c.pathAddr(addr[:], "SetPathThresholds", path)
	if err != nil {
		return c.argError("set", err)
	}
	c.optMu.Lock()
	defer c.optMu.Unlock()
	cur, err := c.readThresholds(addr[:n])
	if err != nil {
		return c.callError("set", "getsockopt", err)
	}
	v, err := mergePathThresholds(cur, t, "PathThresholds")
	if err != nil {
		return c.argError("set", err)
	}
	l, err := c.sock.storageLayout()
	if err != nil {
		return c.callError("set", "getsockopt", err)
	}
	var buf [sizePathThresholdsKernel64]byte
	b := l.pathThresholds(buf[:], c.AssocID(), addr[:n], v)
	return c.setOpt(optPathThresholds, b)
}

// readThresholds reads the thresholds of the path addr names. The error is
// the bare errno, or net.ErrClosed.
func (c *Conn) readThresholds(addr []byte) (thresholdValues, error) {
	l, err := c.sock.storageLayout()
	if err != nil {
		return thresholdValues{}, err
	}
	var buf [sizePathThresholdsKernel64]byte
	b := l.pathThresholds(buf[:], c.AssocID(), addr, thresholdValues{})
	n := uint32(len(b))
	if err := c.sock.getsockopt(optPathThresholds, unsafe.Pointer(&b[0]), &n); err != nil {
		return thresholdValues{}, err
	}
	return l.thresholdValues(b), nil
}

// PFExposure reports whether the association reports the Potentially
// Failed state of RFC 7829 (SCTP_EXPOSE_POTENTIALLY_FAILED_STATE, RFC
// 7829 §7.3).
func (c *Conn) PFExposure() (PFExposure, error) {
	v, err := c.assocValueOption(optExposePotentiallyFailedState)
	return PFExposure(v), err
}

// SetPFExposure chooses whether the association reports the Potentially
// Failed state of RFC 7829 (RFC 7829 §7.3): in PathInfo, and as
// AddrPotentiallyFailed in a
// PeerAddrChange. With PFExposeDisabled, PathInfo on a path in that state
// fails with EACCES (net/sctp/socket.c: sctp_getsockopt_peer_addr_info).
// Any level may follow any other; a value PFExposure does not name is
// refused with an error matching syscall.EINVAL before any system call, as
// Linux refuses it (net/sctp/socket.c: sctp_setsockopt_pf_expose).
func (c *Conn) SetPFExposure(e PFExposure) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	if e > PFExposeEnabled {
		return c.argError("set", invalidArg("SetPFExposure: %v is not PFExposeUnset, PFExposeDisabled or PFExposeEnabled", e))
	}
	return c.setAssocValueOption(optExposePotentiallyFailedState, uint32(e))
}

// AutoASCONF reports whether the endpoint adds and removes the
// association's local addresses by itself, with ASCONF, as the host's
// addresses come and go (SCTP_AUTO_ASCONF, RFC 6458 §8.1.23). Linux reports
// it on only for an endpoint bound to every address
// (net/sctp/socket.c: sctp_getsockopt_auto_asconf).
func (c *Conn) AutoASCONF() (bool, error) {
	return c.boolOption(optAutoAsconf)
}

// SetAutoASCONF switches automatic ASCONF on or off (RFC 6458 §8.1.23).
// Linux refuses to switch it on, with EINVAL, for an endpoint not bound to
// every address (net/sctp/socket.c: sctp_setsockopt_auto_asconf), and it
// takes effect only where ASCONF was negotiated
// (Config.DynamicAddressReconfiguration).
func (c *Conn) SetAutoASCONF(on bool) error {
	return c.setBoolOption(optAutoAsconf, on)
}

// RemoteUDPEncapsPort reports the peer's UDP port for SCTP over UDP (RFC
// 6951 §6.1, updated by RFC 8899) on one path, or, for the zero
// netip.Addr, the association's; 0 means none. A path that is not the
// peer's is refused by Linux with EINVAL
// (net/sctp/socket.c: sctp_getsockopt_encap_port).
//
// A link-local path given without a zone is completed as for
// SendOptions.Path.
func (c *Conn) RemoteUDPEncapsPort(path netip.Addr) (uint16, error) {
	if !c.opened() {
		return 0, c.optionError("get", net.ErrClosed)
	}
	var addr [sizeSockaddrIn6]byte
	n, err := c.pathAddr(addr[:], "RemoteUDPEncapsPort", path)
	if err != nil {
		return 0, c.argError("get", err)
	}
	l, err := c.sock.storageLayout()
	if err != nil {
		return 0, c.callError("get", "getsockopt", err)
	}
	var buf [sizeUDPEncapsKernel64]byte
	b := l.udpEncaps(buf[:], c.AssocID(), addr[:n], 0)
	if _, err := c.getOpt(optRemoteUDPEncapsPort, b); err != nil {
		return 0, err
	}
	return l.udpEncapsPort(b), nil
}

// SetRemoteUDPEncapsPort sets the peer's UDP port for SCTP over UDP (RFC
// 6951 §6.1, updated by RFC 8899) on one path, or, for the zero
// netip.Addr, on the association and every path it has; 0 sends plain
// SCTP. port is in host byte order, and the package sends it in the
// network byte order RFC 6951 §6.1 specifies. Linux encapsulates only
// while net.sctp.udp_port is set. A path that is not the peer's is refused
// by Linux with EINVAL (net/sctp/socket.c: sctp_setsockopt_encap_port).
//
// A link-local path given without a zone is completed as for
// SendOptions.Path.
func (c *Conn) SetRemoteUDPEncapsPort(path netip.Addr, port uint16) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	var addr [sizeSockaddrIn6]byte
	n, err := c.pathAddr(addr[:], "SetRemoteUDPEncapsPort", path)
	if err != nil {
		return c.argError("set", err)
	}
	l, err := c.sock.storageLayout()
	if err != nil {
		return c.callError("set", "getsockopt", err)
	}
	var buf [sizeUDPEncapsKernel64]byte
	return c.setOpt(optRemoteUDPEncapsPort, l.udpEncaps(buf[:], c.AssocID(), addr[:n], port))
}

// PLPMTUDProbeInterval reports how often Linux probes one path's MTU with
// the packetization-layer procedure of RFC 8899, or, for the zero
// netip.Addr, the association's interval; 0 means it does not probe
// (SCTP_PLPMTUD_PROBE_INTERVAL, a Linux option). A path that is not the
// peer's is refused by Linux with EINVAL
// (net/sctp/socket.c: sctp_getsockopt_probe_interval).
//
// A link-local path given without a zone is completed as for
// SendOptions.Path.
func (c *Conn) PLPMTUDProbeInterval(path netip.Addr) (time.Duration, error) {
	if !c.opened() {
		return 0, c.optionError("get", net.ErrClosed)
	}
	var addr [sizeSockaddrIn6]byte
	n, err := c.pathAddr(addr[:], "PLPMTUDProbeInterval", path)
	if err != nil {
		return 0, c.argError("get", err)
	}
	l, err := c.sock.storageLayout()
	if err != nil {
		return 0, c.callError("get", "getsockopt", err)
	}
	var buf [sizeProbeIntervalKernel64]byte
	b := l.probeInterval(buf[:], c.AssocID(), addr[:n], 0)
	if _, err := c.getOpt(optPLPMTUDProbeInterval, b); err != nil {
		return 0, err
	}
	return millisToDuration(l.probeIntervalMS(b)), nil
}

// SetPLPMTUDProbeInterval sets how often Linux probes one path's MTU with
// the procedure of RFC 8899, or, for the zero netip.Addr, the interval of
// the association and every path it has; 0 stops probing. An interval
// that is negative, not a whole number of milliseconds, beyond the __u32
// milliseconds the kernel keeps, or non-zero and below the 5 s Linux
// accepts (SCTP_PROBE_TIMER_MIN) is refused with an error matching
// syscall.EINVAL before any system call. A path that is not the peer's is
// refused by Linux with EINVAL (net/sctp/socket.c:
// sctp_setsockopt_probe_interval).
//
// A link-local path given without a zone is completed as for
// SendOptions.Path.
func (c *Conn) SetPLPMTUDProbeInterval(path netip.Addr, d time.Duration) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	ms, err := durationToMillis("SetPLPMTUDProbeInterval", d, math.MaxUint32)
	if err != nil {
		return c.argError("set", err)
	}
	if ms != 0 && ms < minProbeIntervalMS {
		return c.argError("set", invalidArg("SetPLPMTUDProbeInterval: %s is below the 5s Linux accepts (SCTP_PROBE_TIMER_MIN)", d))
	}
	var addr [sizeSockaddrIn6]byte
	n, err := c.pathAddr(addr[:], "SetPLPMTUDProbeInterval", path)
	if err != nil {
		return c.argError("set", err)
	}
	l, err := c.sock.storageLayout()
	if err != nil {
		return c.callError("set", "getsockopt", err)
	}
	var buf [sizeProbeIntervalKernel64]byte
	return c.setOpt(optPLPMTUDProbeInterval, l.probeInterval(buf[:], c.AssocID(), addr[:n], ms))
}

// --- the association ---------------------------------------------------------------

// Status reports the association's state, the peer's receive window, the
// DATA chunks unacknowledged and pending, the negotiated stream counts, the
// fragmentation point and the primary path (SCTP_STATUS, RFC 6458 §8.2.1).
// Once the association has ended Linux refuses the query with EINVAL
// (net/sctp/socket.c: sctp_getsockopt_sctp_status).
func (c *Conn) Status() (*Status, error) {
	var b [sizeStatus]byte
	binary.NativeEndian.PutUint32(b[statusAssocIDOff:], uint32(c.AssocID()))
	if _, err := c.getOpt(optStatus, b[:]); err != nil {
		return nil, err
	}
	st := decodeStatus(b[:])
	return &st, nil
}

// Stats reports the association's counters (SCTP_GET_ASSOC_STATS, a Linux
// option since 3.8). MaxRTOTicks is the largest RTO observed since the
// previous Stats, in kernel ticks, with the path it was observed on, and
// the read starts a new observation period (net/sctp/socket.c:
// sctp_getsockopt_assoc_stats). Once the association has ended Linux
// refuses the query with EINVAL.
func (c *Conn) Stats() (*AssocStats, error) {
	if !c.opened() {
		return nil, c.optionError("get", net.ErrClosed)
	}
	l, err := c.sock.storageLayout()
	if err != nil {
		return nil, c.callError("get", "getsockopt", err)
	}
	var buf [sizeAssocStatsKernel64]byte
	b := l.assocStatsRequest(buf[:], c.AssocID())
	if _, err := c.getOpt(optGetAssocStats, b); err != nil {
		return nil, err
	}
	s := l.assocStats(b)
	return &s, nil
}

// AssocInfo reports the association's retransmission limit and cookie life,
// with its number of peer addresses and both receive windows
// (SCTP_ASSOCINFO, RFC 6458 §8.1.2).
func (c *Conn) AssocInfo() (*AssocInfo, error) {
	var b [sizeAssocInfo]byte
	binary.NativeEndian.PutUint32(b[assocInfoAssocIDOff:], uint32(c.AssocID()))
	if _, err := c.getOpt(optAssocInfo, b[:]); err != nil {
		return nil, err
	}
	a := decodeAssocInfo(b[:])
	return &a, nil
}

// SetAssocInfo sets the association's retransmission limit and cookie life
// (SCTP_ASSOCINFO, RFC 6458 §8.1.2); a zero field leaves that value
// unchanged, and the read-only fields are ignored. Linux refuses a limit
// larger than the sum of the paths' limits on a multi-homed association
// with EINVAL (net/sctp/socket.c: sctp_setsockopt_associnfo). A nil a, and
// a CookieLife that is negative, not whole milliseconds or beyond the
// kernel's __u32, are refused with an error matching syscall.EINVAL before
// any system call.
func (c *Conn) SetAssocInfo(a *AssocInfo) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	if a == nil {
		return c.argError("set", invalidArg("SetAssocInfo needs a non-nil *AssocInfo"))
	}
	var b [sizeAssocInfo]byte
	if err := encodeAssocInfo(b[:], c.AssocID(), a, "AssocInfo"); err != nil {
		return c.argError("set", err)
	}
	return c.setOpt(optAssocInfo, b[:])
}

// RTOInfo reports the association's initial, maximum and minimum
// retransmission timeouts (SCTP_RTOINFO, RFC 6458 §8.1.1; RFC 9260 §6.3.1).
func (c *Conn) RTOInfo() (*RTOInfo, error) {
	var b [sizeRTOInfo]byte
	binary.NativeEndian.PutUint32(b[rtoInfoAssocIDOff:], uint32(c.AssocID()))
	if _, err := c.getOpt(optRTOInfo, b[:]); err != nil {
		return nil, err
	}
	r := decodeRTOInfo(b[:])
	return &r, nil
}

// SetRTOInfo sets the association's retransmission timeouts (SCTP_RTOINFO,
// RFC 6458 §8.1.1); a zero field leaves that value unchanged. A nil r, a
// value that is negative, not whole milliseconds or beyond the kernel's
// __u32, and a Min above Max are refused with an error matching
// syscall.EINVAL before any system call; Linux refuses with EINVAL a Min
// above the Max already in force (net/sctp/socket.c:
// sctp_setsockopt_rtoinfo).
func (c *Conn) SetRTOInfo(r *RTOInfo) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	if r == nil {
		return c.argError("set", invalidArg("SetRTOInfo needs a non-nil *RTOInfo"))
	}
	var b [sizeRTOInfo]byte
	if err := encodeRTOInfo(b[:], c.AssocID(), r, "RTOInfo"); err != nil {
		return c.argError("set", err)
	}
	return c.setOpt(optRTOInfo, b[:])
}

// InitMsg reports the INIT parameters this socket announces (SCTP_INITMSG,
// RFC 6458 §8.1.3): Config.InitMsg, or, on an accepted connection, its
// listener's. They are fixed once the association exists; set them with
// Config.InitMsg.
func (c *Conn) InitMsg() (*InitMsg, error) {
	var b [sizeInitMsg]byte
	if _, err := c.getOpt(optInitMsg, b[:]); err != nil {
		return nil, err
	}
	m := decodeInitMsg(b[:])
	return &m, nil
}

// DelayedSACK reports the association's delayed SACK timer and frequency
// (SCTP_DELAYED_SACK, RFC 6458 §8.1.19). With delayed SACK off, Linux
// reports a delay of 0 and a frequency of 1
// (net/sctp/socket.c: sctp_getsockopt_delayed_ack).
func (c *Conn) DelayedSACK() (*DelayedSACK, error) {
	var b [sizeDelayedSACK]byte
	binary.NativeEndian.PutUint32(b[delayedSACKAssocIDOff:], uint32(c.AssocID()))
	if _, err := c.getOpt(optDelayedAckTime, b[:]); err != nil {
		return nil, err
	}
	d := decodeDelayedSACK(b[:])
	return &d, nil
}

// SetDelayedSACK sets the association's delayed SACK timer and frequency
// (SCTP_DELAYED_SACK, RFC 6458 §8.1.19) on the association and every path
// it has. A zero field leaves that value unchanged, and a Frequency of 1
// switches delayed SACK off. A nil d, and a Delay that is negative, not
// whole milliseconds or above RFC 9260 §6.2's 500 ms, are refused with an
// error matching syscall.EINVAL before any system call.
func (c *Conn) SetDelayedSACK(d *DelayedSACK) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	if d == nil {
		return c.argError("set", invalidArg("SetDelayedSACK needs a non-nil *DelayedSACK"))
	}
	var b [sizeDelayedSACK]byte
	if err := encodeDelayedSACK(b[:], c.AssocID(), d, "DelayedSACK"); err != nil {
		return c.argError("set", err)
	}
	return c.setOpt(optDelayedAckTime, b[:])
}

// AdaptationLayer reports the adaptation layer indication this side
// announced in its INIT or INIT ACK (SCTP_ADAPTATION_LAYER, RFC 6458
// §8.1.10; RFC 5061 §4.2.6): Config.AdaptationLayer, or, on an accepted
// connection, its listener's. The peer's arrives as an
// AdaptationIndication notification (EventAdaptationIndication).
func (c *Conn) AdaptationLayer() (uint32, error) {
	var b [sizeSetAdaptation]byte
	if _, err := c.getOpt(optAdaptationLayer, b[:]); err != nil {
		return 0, err
	}
	return binary.NativeEndian.Uint32(b[:]), nil
}

// --- send and receive behaviour ------------------------------------------------

// NoDelay reports whether Nagle-like bundling delays are off (SCTP_NODELAY,
// RFC 6458 §8.1.5).
func (c *Conn) NoDelay() (bool, error) {
	return c.boolOption(optNoDelay)
}

// SetNoDelay switches Nagle-like bundling delays off, so that each message
// is sent as soon as it can be, or back on (SCTP_NODELAY, RFC 6458 §8.1.5).
func (c *Conn) SetNoDelay(on bool) error {
	return c.setBoolOption(optNoDelay, on)
}

// MaxSeg reports the association's fragmentation point: the largest DATA
// chunk payload it sends, the smaller of the path MTU's limit and the
// value SetMaxSeg set (SCTP_MAXSEG, RFC 6458 §8.1.16; net/sctp/socket.c:
// sctp_getsockopt_maxseg reports asoc->frag_point).
func (c *Conn) MaxSeg() (int, error) {
	v, err := c.assocValueOption(optMaxSeg)
	return int(v), err
}

// SetMaxSeg limits the size of the DATA chunks the association sends
// (SCTP_MAXSEG, RFC 6458 §8.1.16); 0 removes the limit, leaving the path
// MTU's. Linux refuses a value smaller than it can fragment into, or
// larger than a chunk can be, with EINVAL (net/sctp/socket.c:
// sctp_setsockopt_maxseg). A negative size, or one beyond the kernel's
// __u32, is refused with an error matching syscall.EINVAL before any
// system call.
func (c *Conn) SetMaxSeg(bytes int) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	v, err := uint32Arg("SetMaxSeg", bytes)
	if err != nil {
		return c.argError("set", err)
	}
	return c.setAssocValueOption(optMaxSeg, v)
}

// MaxBurst reports how many packets the association may send in one burst
// (SCTP_MAX_BURST, RFC 6458 §8.1.24); 0 means no limit.
func (c *Conn) MaxBurst() (int, error) {
	v, err := c.assocValueOption(optMaxBurst)
	return int(v), err
}

// SetMaxBurst sets how many packets the association may send in one burst
// (SCTP_MAX_BURST, RFC 6458 §8.1.24; RFC 9260 §6.1); 0 removes the
// limit. A negative count, or one beyond the kernel's __u32, is refused
// with an error matching syscall.EINVAL before any system call.
func (c *Conn) SetMaxBurst(n int) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	v, err := uint32Arg("SetMaxBurst", n)
	if err != nil {
		return c.argError("set", err)
	}
	return c.setAssocValueOption(optMaxBurst, v)
}

// FragmentsDisabled reports whether a message larger than the path allows
// is refused rather than fragmented (SCTP_DISABLE_FRAGMENTS, RFC 6458
// §8.1.11).
func (c *Conn) FragmentsDisabled() (bool, error) {
	return c.boolOption(optDisableFragments)
}

// SetFragmentsDisabled chooses whether a message larger than the
// fragmentation point is refused, with EMSGSIZE, rather than fragmented
// (SCTP_DISABLE_FRAGMENTS, RFC 6458 §8.1.11).
func (c *Conn) SetFragmentsDisabled(on bool) error {
	return c.setBoolOption(optDisableFragments, on)
}

// FragmentInterleave reports the fragment interleave level
// (SCTP_FRAGMENT_INTERLEAVE, RFC 6458 §8.1.20): InterleaveNone or
// InterleaveAssocs, the two Linux keeps.
func (c *Conn) FragmentInterleave() (FragmentInterleave, error) {
	v, err := c.intOption(ipprotoSCTP, optFragmentInterleave)
	return FragmentInterleave(v), err
}

// SetFragmentInterleave sets the fragment interleave level
// (SCTP_FRAGMENT_INTERLEAVE, RFC 6458 §8.1.20). Linux keeps the level as a
// boolean (net/sctp/socket.c: sctp_setsockopt_fragment_interleave), so
// InterleaveStreams, which it would turn into InterleaveAssocs, is refused
// with an error matching ErrUnsupported, and a level FragmentInterleave
// does not name with one matching syscall.EINVAL, both before any system
// call. InterleaveNone also stops the endpoint offering I-DATA (RFC 8260)
// to later associations.
func (c *Conn) SetFragmentInterleave(level FragmentInterleave) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	switch level {
	case InterleaveNone, InterleaveAssocs:
	case InterleaveStreams:
		return c.argError("set", unsupportedField("SetFragmentInterleave", "Linux stores SCTP_FRAGMENT_INTERLEAVE as a boolean and collapses any nonzero value to InterleaveAssocs (net/sctp/socket.c: sctp_setsockopt_fragment_interleave), so it cannot deliver cross-stream interleaving"))
	default:
		return c.argError("set", invalidArg("SetFragmentInterleave: %v is not InterleaveNone, InterleaveAssocs or InterleaveStreams", level))
	}
	return c.setIntOption(ipprotoSCTP, optFragmentInterleave, int32(level))
}

// PartialDeliveryPoint reports the message size at which Linux starts
// handing a message to reads before all of it has arrived
// (SCTP_PARTIAL_DELIVERY_POINT, RFC 6458 §8.1.21).
func (c *Conn) PartialDeliveryPoint() (int, error) {
	var b [sizeInt]byte
	if _, err := c.getOpt(optPartialDeliveryPoint, b[:]); err != nil {
		return 0, err
	}
	return int(binary.NativeEndian.Uint32(b[:])), nil
}

// SetPartialDeliveryPoint sets the message size at which Linux starts the
// partial delivery of a message (SCTP_PARTIAL_DELIVERY_POINT, RFC 6458
// §8.1.21); a message no larger is delivered in one piece, given a large
// enough buffer. Linux refuses a point above half the receive buffer with
// EINVAL (net/sctp/socket.c: sctp_setsockopt_partial_delivery_point). A
// negative size, or one beyond the kernel's __u32, is refused with an error
// matching syscall.EINVAL before any system call.
func (c *Conn) SetPartialDeliveryPoint(bytes int) error {
	if !c.opened() {
		return c.optionError("set", net.ErrClosed)
	}
	v, err := uint32Arg("SetPartialDeliveryPoint", bytes)
	if err != nil {
		return c.argError("set", err)
	}
	var b [sizeInt]byte
	binary.NativeEndian.PutUint32(b[:], v)
	return c.setOpt(optPartialDeliveryPoint, b[:])
}

// ReceiveNxtInfo reports whether reads describe the next message queued,
// in MsgInfo.Nxt (SCTP_RECVNXTINFO, RFC 6458 §8.1.30).
func (c *Conn) ReceiveNxtInfo() (bool, error) {
	return c.boolOption(optRecvNxtInfo)
}

// SetReceiveNxtInfo chooses whether RecvMsg describes the next message
// queued, in MsgInfo.Nxt, as Config.ReceiveNxtInfo does (SCTP_RECVNXTINFO,
// RFC 6458 §8.1.30).
func (c *Conn) SetReceiveNxtInfo(on bool) error {
	return c.setBoolOption(optRecvNxtInfo, on)
}

// DefaultContext reports the context the association attaches to every
// message it receives, in RcvInfo.Context (SCTP_CONTEXT, RFC 6458 §8.1.25).
func (c *Conn) DefaultContext() (uint32, error) {
	return c.assocValueOption(optContext)
}

// SetDefaultContext sets the context the association attaches to every
// message it receives from the peer, which reads report in RcvInfo.Context
// (SCTP_CONTEXT, RFC 6458 §8.1.25; net/sctp/ulpevent.c copies
// asoc->default_rcv_context). It does not change what this side sends.
func (c *Conn) SetDefaultContext(v uint32) error {
	return c.setAssocValueOption(optContext, v)
}
