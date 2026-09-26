// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

// recvState is a Conn's own receive storage: the control buffer sized for
// SCTP_RCVINFO and SCTP_NXTINFO, the syscall.Msghdr and the notification
// buffer every receive reuses under the connection's receive lock.
// syscall.Msghdr exists only on some platforms, so the type is declared
// per platform, as sendState is (send_linux.go). It holds nothing until
// the receive path is built on it.
type recvState struct{}
