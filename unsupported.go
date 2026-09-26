// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

// unsupported.go stubs the package's socket-backed entry points on any
// GOOS other than linux, which this package does not support: the raw
// syscalls and SCTP socket options syscall_linux_other.go and
// syscall_linux_386.go use are Linux-specific, but that is a statement
// about this package's own implementation, not about SCTP or these
// syscalls more broadly — FreeBSD and illumos, among others, have their
// own SCTP stacks this package simply does not target. Every stubbed
// entry point returns ErrUnsupported (errors.go) instead of attempting a
// call the platform cannot honour, so code written against this package
// compiles and fails predictably on every platform, rather than only on
// Linux.
//
// unsupportedStubCases, in unsupported_test.go, lists one case per function
// or method declared in this file, and TestUnsupportedStubManifestIsComplete
// parses this file and requires the two lists to match by name exactly, so
// a stub can never be added here without also being exercised and checked
// against ErrUnsupported by TestUnsupportedEntryPointsReportTheSentinel.
// That check runs against this file's source, not against a fixed list, so
// it stays correct as this file grows.
//
// Addresses, notifications and enumerations are portable and carry no build
// tag. Value-only accessors (LocalAddr, RemoteAddr, Listener.Addr,
// AssocID) return their zero value here, since no Conn or Listener can
// exist on these platforms to hold anything else; every other stub returns
// ErrUnsupported. None of them is carried over from v1's
// sctp_unsupported.go (git show main:sctp_unsupported.go): the API they
// stand in for is new.

package sctp

import (
	"context"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"
)

// sendState is a Conn's send storage. On Linux it holds a syscall.Msghdr,
// which not every platform defines; with no send path here, it is empty.
type sendState struct{}

// recvState is a Conn's receive storage, empty here for the same reason.
type recvState struct{}

// Dial reports ErrUnsupported: SCTP sockets exist only on Linux.
func Dial(context.Context, string, *Addr, *Addr) (*Conn, error) { return nil, ErrUnsupported }

// Dial reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Config) Dial(context.Context, string, *Addr, *Addr) (*Conn, error) {
	return nil, ErrUnsupported
}

// Listen reports ErrUnsupported: SCTP sockets exist only on Linux.
func Listen(string, *Addr) (*Listener, error) { return nil, ErrUnsupported }

// Listen reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Config) Listen(string, *Addr) (*Listener, error) { return nil, ErrUnsupported }

// FileConn reports ErrUnsupported: SCTP sockets exist only on Linux.
func FileConn(*os.File) (*Conn, error) { return nil, ErrUnsupported }

// FileConn reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Config) FileConn(*os.File) (*Conn, error) { return nil, ErrUnsupported }

// FileListener reports ErrUnsupported: SCTP sockets exist only on Linux.
func FileListener(*os.File) (*Listener, error) { return nil, ErrUnsupported }

// FileListener reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Config) FileListener(*os.File) (*Listener, error) { return nil, ErrUnsupported }

// InstallAuthKey reports ErrUnsupported: SCTP sockets exist only on Linux.
func InstallAuthKey(syscall.RawConn, uint16, []byte) error { return ErrUnsupported }

// ActivateAuthKey reports ErrUnsupported: SCTP sockets exist only on Linux.
func ActivateAuthKey(syscall.RawConn, uint16) error { return ErrUnsupported }

// Accept reports ErrUnsupported: SCTP sockets exist only on Linux.
func (l *Listener) Accept() (net.Conn, error) { return nil, ErrUnsupported }

// AcceptSCTP reports ErrUnsupported: SCTP sockets exist only on Linux.
func (l *Listener) AcceptSCTP() (*Conn, error) { return nil, ErrUnsupported }

// Addr returns nil: no Listener is ever bound here.
func (l *Listener) Addr() net.Addr { return nil }

// Close reports ErrUnsupported: SCTP sockets exist only on Linux.
func (l *Listener) Close() error { return ErrUnsupported }

// SetDeadline reports ErrUnsupported: SCTP sockets exist only on Linux.
func (l *Listener) SetDeadline(time.Time) error { return ErrUnsupported }

// BindAdd reports ErrUnsupported: SCTP sockets exist only on Linux.
func (l *Listener) BindAdd(...netip.Addr) error { return ErrUnsupported }

// BindRemove reports ErrUnsupported: SCTP sockets exist only on Linux.
func (l *Listener) BindRemove(...netip.Addr) error { return ErrUnsupported }

// SyscallConn reports ErrUnsupported: SCTP sockets exist only on Linux.
func (l *Listener) SyscallConn() (syscall.RawConn, error) { return nil, ErrUnsupported }

// AssocID returns 0: no association exists here.
func (c *Conn) AssocID() AssocID { return 0 }

// LocalAddr returns nil: no Conn is ever connected here.
func (c *Conn) LocalAddr() net.Addr { return nil }

// RemoteAddr returns nil: no Conn is ever connected here.
func (c *Conn) RemoteAddr() net.Addr { return nil }

// LocalAddrs reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) LocalAddrs() (*Addr, error) { return nil, ErrUnsupported }

// PeerAddrs reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) PeerAddrs() (*Addr, error) { return nil, ErrUnsupported }

// BindAdd reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) BindAdd(...netip.Addr) error { return ErrUnsupported }

// BindRemove reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) BindRemove(...netip.Addr) error { return ErrUnsupported }

// SetDeadline reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetDeadline(time.Time) error { return ErrUnsupported }

// SetReadDeadline reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetReadDeadline(time.Time) error { return ErrUnsupported }

// SetWriteDeadline reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetWriteDeadline(time.Time) error { return ErrUnsupported }

// SyscallConn reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SyscallConn() (syscall.RawConn, error) { return nil, ErrUnsupported }

// Close reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) Close() error { return ErrUnsupported }

// CloseWithTimeout reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) CloseWithTimeout(time.Duration) error { return ErrUnsupported }

// Shutdown reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) Shutdown() error { return ErrUnsupported }

// Abort reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) Abort() error { return ErrUnsupported }

// SendMsg reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SendMsg([]byte, SendOptions) (int, error) { return 0, ErrUnsupported }

// Write reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) Write([]byte) (int, error) { return 0, ErrUnsupported }

// DefaultSndInfo reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) DefaultSndInfo() (*SndInfo, error) { return nil, ErrUnsupported }

// SetDefaultSndInfo reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetDefaultSndInfo(*SndInfo) error { return ErrUnsupported }

// DefaultPrInfo reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) DefaultPrInfo() (*PrInfo, error) { return nil, ErrUnsupported }

// SetDefaultPrInfo reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetDefaultPrInfo(*PrInfo) error { return ErrUnsupported }

// Read reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) Read([]byte) (int, error) { return 0, ErrUnsupported }

// RecvMsg reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) RecvMsg([]byte) (int, MsgInfo, error) { return 0, MsgInfo{}, ErrUnsupported }

// ReadMsg reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) ReadMsg(int) ([]byte, RcvInfo, error) { return nil, RcvInfo{}, ErrUnsupported }

// Subscribe reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) Subscribe(EventType, bool) error { return ErrUnsupported }

// Subscribed reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) Subscribed(EventType) (bool, error) { return false, ErrUnsupported }

// ReadBuffer reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) ReadBuffer() (int, error) { return 0, ErrUnsupported }

// SetReadBuffer reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetReadBuffer(int) error { return ErrUnsupported }

// WriteBuffer reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) WriteBuffer() (int, error) { return 0, ErrUnsupported }

// SetWriteBuffer reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetWriteBuffer(int) error { return ErrUnsupported }

// PrimaryAddr reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) PrimaryAddr() (netip.Addr, error) { return netip.Addr{}, ErrUnsupported }

// SetPrimaryAddr reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetPrimaryAddr(netip.Addr) error { return ErrUnsupported }

// RequestPeerPrimary reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) RequestPeerPrimary(netip.Addr) error { return ErrUnsupported }

// PathInfo reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) PathInfo(netip.Addr) (*PathInfo, error) { return nil, ErrUnsupported }

// PathParams reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) PathParams(netip.Addr) (*PathParams, error) { return nil, ErrUnsupported }

// SetPathParams reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetPathParams(netip.Addr, *PathParams) error { return ErrUnsupported }

// RequestHeartbeat reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) RequestHeartbeat(netip.Addr) error { return ErrUnsupported }

// PathThresholds reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) PathThresholds(netip.Addr) (*PathThresholds, error) { return nil, ErrUnsupported }

// SetPathThresholds reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetPathThresholds(netip.Addr, *PathThresholds) error { return ErrUnsupported }

// PFExposure reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) PFExposure() (PFExposure, error) { return 0, ErrUnsupported }

// SetPFExposure reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetPFExposure(PFExposure) error { return ErrUnsupported }

// AutoASCONF reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) AutoASCONF() (bool, error) { return false, ErrUnsupported }

// SetAutoASCONF reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetAutoASCONF(bool) error { return ErrUnsupported }

// RemoteUDPEncapsPort reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) RemoteUDPEncapsPort(netip.Addr) (uint16, error) { return 0, ErrUnsupported }

// SetRemoteUDPEncapsPort reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetRemoteUDPEncapsPort(netip.Addr, uint16) error { return ErrUnsupported }

// PLPMTUDProbeInterval reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) PLPMTUDProbeInterval(netip.Addr) (time.Duration, error) { return 0, ErrUnsupported }

// SetPLPMTUDProbeInterval reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetPLPMTUDProbeInterval(netip.Addr, time.Duration) error { return ErrUnsupported }

// Status reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) Status() (*Status, error) { return nil, ErrUnsupported }

// Stats reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) Stats() (*AssocStats, error) { return nil, ErrUnsupported }

// AssocInfo reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) AssocInfo() (*AssocInfo, error) { return nil, ErrUnsupported }

// SetAssocInfo reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetAssocInfo(*AssocInfo) error { return ErrUnsupported }

// RTOInfo reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) RTOInfo() (*RTOInfo, error) { return nil, ErrUnsupported }

// SetRTOInfo reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetRTOInfo(*RTOInfo) error { return ErrUnsupported }

// InitMsg reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) InitMsg() (*InitMsg, error) { return nil, ErrUnsupported }

// DelayedSACK reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) DelayedSACK() (*DelayedSACK, error) { return nil, ErrUnsupported }

// SetDelayedSACK reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetDelayedSACK(*DelayedSACK) error { return ErrUnsupported }

// AdaptationLayer reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) AdaptationLayer() (uint32, error) { return 0, ErrUnsupported }

// NoDelay reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) NoDelay() (bool, error) { return false, ErrUnsupported }

// SetNoDelay reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetNoDelay(bool) error { return ErrUnsupported }

// MaxSeg reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) MaxSeg() (int, error) { return 0, ErrUnsupported }

// SetMaxSeg reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetMaxSeg(int) error { return ErrUnsupported }

// MaxBurst reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) MaxBurst() (int, error) { return 0, ErrUnsupported }

// SetMaxBurst reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetMaxBurst(int) error { return ErrUnsupported }

// FragmentsDisabled reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) FragmentsDisabled() (bool, error) { return false, ErrUnsupported }

// SetFragmentsDisabled reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetFragmentsDisabled(bool) error { return ErrUnsupported }

// FragmentInterleave reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) FragmentInterleave() (FragmentInterleave, error) { return 0, ErrUnsupported }

// SetFragmentInterleave reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetFragmentInterleave(FragmentInterleave) error { return ErrUnsupported }

// PartialDeliveryPoint reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) PartialDeliveryPoint() (int, error) { return 0, ErrUnsupported }

// SetPartialDeliveryPoint reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetPartialDeliveryPoint(int) error { return ErrUnsupported }

// ReceiveNxtInfo reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) ReceiveNxtInfo() (bool, error) { return false, ErrUnsupported }

// SetReceiveNxtInfo reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetReceiveNxtInfo(bool) error { return ErrUnsupported }

// DefaultContext reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) DefaultContext() (uint32, error) { return 0, ErrUnsupported }

// SetDefaultContext reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetDefaultContext(uint32) error { return ErrUnsupported }

// PRSupported reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) PRSupported() (bool, error) { return false, ErrUnsupported }

// ReconfigSupported reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) ReconfigSupported() (bool, error) { return false, ErrUnsupported }

// ASCONFSupported reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) ASCONFSupported() (bool, error) { return false, ErrUnsupported }

// AuthSupported reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) AuthSupported() (bool, error) { return false, ErrUnsupported }

// InterleavingSupported reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) InterleavingSupported() (bool, error) { return false, ErrUnsupported }

// ECNSupported reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) ECNSupported() (bool, error) { return false, ErrUnsupported }

// SetAuthKey reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetAuthKey(uint16, []byte) error { return ErrUnsupported }

// ActiveAuthKey reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) ActiveAuthKey() (uint16, error) { return 0, ErrUnsupported }

// SetActiveAuthKey reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetActiveAuthKey(uint16) error { return ErrUnsupported }

// DeactivateAuthKey reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) DeactivateAuthKey(uint16) error { return ErrUnsupported }

// DeleteAuthKey reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) DeleteAuthKey(uint16) error { return ErrUnsupported }

// HMACIdentifiers reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) HMACIdentifiers() ([]HMACID, error) { return nil, ErrUnsupported }

// LocalAuthChunks reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) LocalAuthChunks() ([]uint8, error) { return nil, ErrUnsupported }

// PeerAuthChunks reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) PeerAuthChunks() ([]uint8, error) { return nil, ErrUnsupported }

// StreamResetMask reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) StreamResetMask() (StreamResetMask, error) { return 0, ErrUnsupported }

// SetStreamResetMask reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetStreamResetMask(StreamResetMask) error { return ErrUnsupported }

// ResetStreams reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) ResetStreams(ResetDirection, ...uint16) error { return ErrUnsupported }

// ResetAssoc reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) ResetAssoc() error { return ErrUnsupported }

// AddStreams reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) AddStreams(uint16, uint16) error { return ErrUnsupported }

// StreamScheduler reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) StreamScheduler() (Scheduler, error) { return 0, ErrUnsupported }

// SetStreamScheduler reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetStreamScheduler(Scheduler) error { return ErrUnsupported }

// StreamSchedulerValue reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) StreamSchedulerValue(uint16) (uint16, error) { return 0, ErrUnsupported }

// SetStreamSchedulerValue reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) SetStreamSchedulerValue(uint16, uint16) error { return ErrUnsupported }

// PRStreamStatus reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) PRStreamStatus(uint16, PRPolicy) (*PRStatus, error) { return nil, ErrUnsupported }

// PRAssocStatus reports ErrUnsupported: SCTP sockets exist only on Linux.
func (c *Conn) PRAssocStatus(PRPolicy) (*PRStatus, error) { return nil, ErrUnsupported }
