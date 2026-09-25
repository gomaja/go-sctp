// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
)

// The ten error variables. Each is returned unwrapped by the call that
// documents it; callers compare with errors.Is.
var (
	// ErrUnsupported is returned by socket-backed entry points on a platform
	// without SCTP: a non-Linux GOOS, or Linux with the SCTP module absent.
	// It wraps errors.ErrUnsupported, so errors.Is(err, errors.ErrUnsupported)
	// holds for it directly; a socket creation failure additionally matching
	// the kernel's own errno uses unsupportedErr, below, not this variable.
	ErrUnsupported = fmt.Errorf("sctp: socket operation unsupported: %w", errors.ErrUnsupported)

	// ErrMessageTooLong is ReadMsg's report that a message exceeded the
	// caller's max: the rest of the record is drained from the kernel so the
	// next ReadMsg starts at the next message.
	ErrMessageTooLong = errors.New("sctp: message exceeds the requested maximum")

	// ErrMessageInterrupted is ReadMsg's report that it could not reach the
	// end of a record because the association aborted partway through.
	ErrMessageInterrupted = errors.New("sctp: could not reach end of record: association aborted")

	// ErrNotificationTooLong is ParseNotification's report that a
	// notification's declared length exceeds NotificationReassemblyLimit.
	ErrNotificationTooLong = errors.New("sctp: notification exceeds the reassembly limit")

	// ErrShortNotification is ParseNotification's report that a notification
	// is shorter than its fixed header, or than the fixed portion its type
	// declares.
	ErrShortNotification = errors.New("sctp: notification shorter than its fixed header")

	// ErrControlTruncated reports that the kernel truncated a message's
	// ancillary data (MSG_CTRUNC), so RcvInfo or a notification could not be
	// read in full.
	ErrControlTruncated = errors.New("sctp: ancillary data truncated")

	// ErrInvalidRcvInfo reports that SCTP_RCVINFO named a reserved scope
	// selector (SCTP_FUTURE_ASSOC, SCTP_CURRENT_ASSOC, SCTP_ALL_ASSOC)
	// instead of a real association id.
	ErrInvalidRcvInfo = errors.New("sctp: SCTP_RCVINFO names a scope selector, not an association")

	// ErrMissingRcvInfo reports that data arrived on an Endpoint without
	// SCTP_RCVINFO, so RecvMsg cannot report which association it belongs
	// to.
	ErrMissingRcvInfo = errors.New("sctp: endpoint data arrived without SCTP_RCVINFO")

	// ErrAssocListTooLarge reports that Endpoint.AssocIDs found more
	// associations than a bounded read can return.
	ErrAssocListTooLarge = errors.New("sctp: association id list too large")

	// ErrInvalidAssocList reports that SCTP_GET_ASSOC_ID_LIST returned a
	// buffer whose declared count does not fit what the kernel wrote.
	ErrInvalidAssocList = errors.New("sctp: association id list malformed")
)

// invalidArgError is invalidArg's return type. Its Error is exactly the
// formatted message — nothing from syscall.EINVAL is appended to it — and its
// Unwrap makes errors.Is(err, syscall.EINVAL) hold.
type invalidArgError struct{ msg string }

func (e *invalidArgError) Error() string { return e.msg }
func (e *invalidArgError) Unwrap() error { return syscall.EINVAL }

// invalidArg builds a validation error for a Config field, SendOptions field
// or method argument the package refuses before any system call. The
// message names what was refused, for example "sctp:
// Config.DelayedSACK.Delay 600ms exceeds RFC 9260 §6.2's 500 ms maximum",
// and matches syscall.EINVAL.
func invalidArg(format string, args ...any) error {
	return &invalidArgError{msg: "sctp: " + fmt.Sprintf(format, args...)}
}

// fileClosingErrOnce lazily captures internal/poll's ErrFileClosing sentinel
// ("use of closed file"): the error a syscall.RawConn method (Control,
// Read, Write) returns once the os.File it came from has been closed
// elsewhere, bypassing the os.File's own "already closed" check (which
// gives os.ErrClosed instead — see isFileClosingErr). internal/poll is
// unexported, so its error cannot be imported or type-asserted; capturing
// the actual value, via capturePipeClosingErr below, is the only way to
// compare against it. It is a plain, comparable *errors.errorString — the
// same package-level value every closed file's RawConn returns, confirmed
// empirically on both darwin and linux — so errors.Is finds it through any
// wrapping.
//
// It matches neither net.ErrClosed (poll.errNetClosing{}, a value, not a
// pointer — "use of closed network connection", what a closed *net.TCPConn
// or similar net.Conn reports) nor os.ErrClosed (fs.ErrClosed, "file
// already closed", what a plain *os.File's own Read/Write/Close report
// once Close has been called through that same *os.File). A closed
// *os.File never goes through the net package's wrapping at all — it
// reports one of the other two, os.ErrClosed or this one, depending on
// which code path is used, never net.ErrClosed. The three exist because
// Go's standard library has three different closed-descriptor code paths,
// and this package's sockets — wrapped in an *os.File like any plain file,
// not through the net package — can hit any of the three; opError and
// optError collapse all three to one net.ErrClosed wrap.
//
// The capture is lazy — sync.OnceValue runs capturePipeClosingErr on the
// first call to isFileClosingErr, not at package init — so importing this
// package never opens a pipe on its own; only the first real closed-socket
// check does.
var fileClosingErrOnce = sync.OnceValue(capturePipeClosingErr)

// capturePipeClosingErr triggers internal/poll's ErrFileClosing by closing
// one end of a pipe and then using its already-taken syscall.RawConn: the
// file's poll.FD is marked closing before Close returns, so Control's own
// reference-count check (poll.FD.incref, checked empirically against both
// darwin and linux) fails and returns that sentinel directly, before it
// would ever run the callback. A failure anywhere in this setup (no pipe
// available) leaves the result nil; isFileClosingErr then falls back to
// matching the sentinel's known text instead of the value itself.
func capturePipeClosingErr() error {
	r, w, err := os.Pipe()
	if err != nil {
		return nil
	}
	raw, err := r.SyscallConn()
	if err != nil {
		_ = r.Close()
		_ = w.Close()
		return nil
	}
	_ = r.Close()
	_ = w.Close()
	return raw.Control(func(uintptr) {})
}

// isFileClosingErr reports whether err is, or wraps, internal/poll's
// ErrFileClosing sentinel — including when err is
// os.NewSyscallError(call, thatSentinel), as optError produces, since
// errors.Is follows *os.SyscallError's Unwrap. If capturePipeClosingErr
// could not get a sentinel to compare against (no working pipe on this
// platform or sandbox), this falls back to matching "use of closed file"
// by text at every level of err's own unwrap chain — weaker than a value
// comparison, since two unrelated errors could in principle share that
// text, but better than never recognizing the condition at all.
func isFileClosingErr(err error) bool {
	if sentinel := fileClosingErrOnce(); sentinel != nil {
		return errors.Is(err, sentinel)
	}
	for e := err; e != nil; e = errors.Unwrap(e) {
		if e.Error() == "use of closed file" {
			return true
		}
	}
	return false
}

// opError wraps err for a read, write, message or constructor operation. It
// never double-wraps: an error that is already a *net.OpError is returned
// unchanged. io.EOF is returned unwrapped, so err == io.EOF keeps working.
// An error matching net.ErrClosed or os.ErrClosed, or one isFileClosingErr
// recognizes — the three different ways the standard library reports a
// closed descriptor — collapses to a single net.ErrClosed wrap, never
// nested and never carrying any of the three's own text. Anything else is
// wrapped as the *net.OpError's cause, unchanged: os.ErrDeadlineExceeded
// already implements net.Error (Timeout, Temporary), so op.Timeout() and
// errors.Is(op, os.ErrDeadlineExceeded) hold with no special case here.
func opError(op, network string, source, addr net.Addr, err error) error {
	if err == nil {
		return nil
	}
	if err == io.EOF {
		return io.EOF
	}
	if opErr, ok := err.(*net.OpError); ok {
		return opErr
	}
	if errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed) || isFileClosingErr(err) {
		err = net.ErrClosed
	}
	return &net.OpError{Op: op, Net: network, Source: source, Addr: addr, Err: err}
}

// optError wraps a socket-option failure: a *net.OpError with Op "get" or
// "set" ("bindx" for BindAdd and BindRemove), around
// os.NewSyscallError(call, err), the form net's own option setters use.
// Composing through opError gives the same closed-socket collapse and
// single-*net.OpError guarantee as any other operation: err already
// carrying net.ErrClosed, os.ErrClosed, or the sentinel isFileClosingErr
// recognizes (the descriptor was closed before the syscall was attempted)
// still comes out as one net.ErrClosed wrap. isFileClosingErr's own check
// is errors.Is, which follows *os.SyscallError's Unwrap to find the cause
// this function itself just wrapped, so "get sctp: getsockopt: use of
// closed file" — what os.NewSyscallError("getsockopt", err) alone would
// produce — never reaches the caller; opError's net.ErrClosed replaces err
// before the *net.OpError is built.
func optError(op, call, network string, source, addr net.Addr, err error) error {
	return opError(op, network, source, addr, os.NewSyscallError(call, err))
}

// unsupportedErr reports a socket-creation failure the kernel refused
// because SCTP is unavailable: EPROTONOSUPPORT or ESOCKTNOSUPPORT from
// socket() (inet_create, net/ipv4/af_inet.c). It matches ErrUnsupported,
// errors.ErrUnsupported and the errno itself, so a caller can test for any
// of the three.
type unsupportedErr struct{ errno syscall.Errno }

func (e unsupportedErr) Error() string {
	return fmt.Sprintf("sctp: socket operation unsupported: %s", e.errno)
}

// Unwrap exposes both ErrUnsupported (which itself wraps errors.ErrUnsupported)
// and the errno to errors.Is and errors.As, via Go's multi-error unwrapping.
func (e unsupportedErr) Unwrap() []error {
	return []error{ErrUnsupported, e.errno}
}
