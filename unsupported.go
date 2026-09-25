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
// No function is declared here yet. Addresses, notifications and
// enumerations are portable and carry no build tag, and every socket-backed
// constructor and method this package will expose is added to the Linux
// build, and stubbed here alongside it, separately. The two types below
// exist only so that Conn, which is portable, compiles here. A stub carried
// over from v1's sctp_unsupported.go (git show main:sctp_unsupported.go)
// brings that file's Wataru Ishida copyright notice into this one the first
// time one is added, the same way addr.go and sockaddr.go already do.

package sctp

// sendState is a Conn's send storage. On Linux it holds a syscall.Msghdr,
// which not every platform defines; with no send path here, it is empty.
type sendState struct{}

// recvState is a Conn's receive storage, empty here for the same reason.
type recvState struct{}
