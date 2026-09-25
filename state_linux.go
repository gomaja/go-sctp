// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

// sendState is a Conn's own send storage: the control-message buffer and
// the syscall.Msghdr a send encodes into before its one raw write, reused
// by every send under the connection's send lock. syscall.Msghdr exists
// only on some platforms, so the type is declared per platform. It holds
// nothing until the send path is built on it.
type sendState struct{}

// recvState is a Conn's own receive storage: the control buffer sized for
// SCTP_RCVINFO and SCTP_NXTINFO, the syscall.Msghdr and the notification
// buffer every receive reuses under the connection's receive lock. It is
// declared per platform for the same reason as sendState, and holds nothing
// until the receive path is built on it.
type recvState struct{}

// init prepares s for c's sends; newConn calls it once the connection's
// association id is known. sendState holds no storage yet, so there is
// nothing to prepare.
func (s *sendState) init(*Conn) {}
