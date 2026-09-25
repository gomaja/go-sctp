// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
)

// TestInvalidArg pins invalidArg's contract: it matches syscall.EINVAL and
// its message starts with "sctp: ".
func TestInvalidArg(t *testing.T) {
	err := invalidArg("Config.%s %v exceeds the maximum", "DelayedSACK.Delay", "600ms")
	if !errors.Is(err, syscall.EINVAL) {
		t.Errorf("invalidArg result does not match syscall.EINVAL: %v", err)
	}
	if !strings.HasPrefix(err.Error(), "sctp: ") {
		t.Errorf("invalidArg message %q does not start with %q", err.Error(), "sctp: ")
	}
	const want = "sctp: Config.DelayedSACK.Delay 600ms exceeds the maximum"
	if err.Error() != want {
		t.Errorf("invalidArg message = %q, want %q", err.Error(), want)
	}
}

// TestOpErrorEOF pins that opError returns io.EOF itself, unwrapped, so
// err == io.EOF keeps working for callers.
func TestOpErrorEOF(t *testing.T) {
	err := opError("read", "sctp", nil, nil, io.EOF)
	if err != io.EOF {
		t.Errorf("opError(io.EOF) = %v (%T), want io.EOF itself", err, err)
	}
}

// TestOpErrorDeadline pins that a deadline error wraps os.ErrDeadlineExceeded
// so that both errors.Is and a direct net.Error assertion see it as a
// timeout.
func TestOpErrorDeadline(t *testing.T) {
	err := opError("read", "sctp", nil, nil, os.ErrDeadlineExceeded)
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("errors.Is(err, os.ErrDeadlineExceeded) is false for %v", err)
	}
	ne, ok := err.(net.Error)
	if !ok {
		t.Fatalf("opError result %v (%T) does not implement net.Error", err, err)
	}
	if !ne.Timeout() {
		t.Errorf("opError(os.ErrDeadlineExceeded).Timeout() = false, want true")
	}
}

// TestOpErrorClosed pins that net.ErrClosed, os.ErrClosed and a real closed
// os.File's syscall.RawConn error all collapse into a single net.ErrClosed
// wrap: errors.Is holds for each, and the message contains "use of closed"
// exactly once — never nested, and never carrying any of the three
// standard-library sentinels' own text ("file already closed" for
// os.ErrClosed, or the closed os.File's "use of closed file" left
// unreplaced).
func TestOpErrorClosed(t *testing.T) {
	pipeErr := closedPipeRawConnError(t)

	for _, tc := range []struct {
		name string
		in   error
	}{
		{"net.ErrClosed", net.ErrClosed},
		{"os.ErrClosed", os.ErrClosed},
		{"closed os.File RawConn error", pipeErr},
	} {
		err := opError("read", "sctp", nil, nil, tc.in)
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s: errors.Is(err, net.ErrClosed) is false for %v", tc.name, err)
		}
		if n := strings.Count(err.Error(), "use of closed"); n != 1 {
			t.Errorf("%s: %q contains \"use of closed\" %d times, want 1", tc.name, err.Error(), n)
		}
		opErr, ok := err.(*net.OpError)
		if !ok {
			t.Fatalf("%s: opError result is %T, want *net.OpError", tc.name, err)
		}
		if opErr.Err != net.ErrClosed {
			t.Errorf("%s: (*net.OpError).Err = %v, want net.ErrClosed itself (no nesting)",
				tc.name, opErr.Err)
		}
	}
}

// closedPipeRawConnError reproduces capturePipeClosingErr's own construction
// on a fresh pipe, independently of fileClosingErrOnce's cached value, and
// fails the test outright if a closed os.File's RawConn ever stops
// returning what opError expects to match. It also checks the property
// fileClosingErrOnce's own doc comment claims: the value it returns is
// distinct from both net.ErrClosed and os.ErrClosed, and equal (by ==) to
// this independently-constructed one — the singleton property
// isFileClosingErr's errors.Is check depends on.
func closedPipeRawConnError(t *testing.T) error {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	raw, err := r.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("close read end: %v", err)
	}
	_ = w.Close()

	got := raw.Control(func(uintptr) {})
	if got == nil {
		t.Fatal("closed os.File's RawConn.Control returned nil, want an error")
	}
	if got == net.ErrClosed || got == os.ErrClosed {
		t.Fatalf("closed os.File's RawConn error is %v, want a value distinct from "+
			"net.ErrClosed and os.ErrClosed", got)
	}
	sentinel := fileClosingErrOnce()
	if sentinel == nil {
		t.Fatal("fileClosingErrOnce() is nil; capturePipeClosingErr failed")
	}
	if got != sentinel {
		t.Fatalf("this pipe's closed RawConn error (%v) != fileClosingErrOnce() (%v); "+
			"the sentinel is not the singleton it is documented to be", got, sentinel)
	}
	return got
}

// TestOpErrorNoDoubleWrap pins that opError never double-wraps: an error
// already a *net.OpError is returned unchanged.
func TestOpErrorNoDoubleWrap(t *testing.T) {
	inner := &net.OpError{Op: "read", Net: "sctp", Err: syscall.ECONNRESET}
	got := opError("write", "sctp4", &net.IPAddr{}, &net.IPAddr{}, inner)
	if got != inner {
		t.Errorf("opError(*net.OpError) returned %#v, want the same value %#v unchanged", got, inner)
	}
	if opErr, ok := got.(*net.OpError); !ok || opErr.Op != "read" {
		t.Errorf("opError changed the wrapped *net.OpError's Op; got %#v", got)
	}
}

// TestOpErrorOther pins that any other error is wrapped as the
// *net.OpError's cause, unchanged.
func TestOpErrorOther(t *testing.T) {
	err := opError("write", "sctp", nil, nil, syscall.ECONNRESET)
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Errorf("errors.Is(err, syscall.ECONNRESET) is false for %v", err)
	}
	opErr, ok := err.(*net.OpError)
	if !ok {
		t.Fatalf("opError result is %T, want *net.OpError", err)
	}
	if opErr.Op != "write" || opErr.Net != "sctp" {
		t.Errorf("opError Op/Net = %q/%q, want write/sctp", opErr.Op, opErr.Net)
	}
}

// TestOpErrorNil pins that a nil cause produces a nil error, the ordinary
// Go convention every caller of opError relies on.
func TestOpErrorNil(t *testing.T) {
	if err := opError("read", "sctp", nil, nil, nil); err != nil {
		t.Errorf("opError(nil) = %v, want nil", err)
	}
}

// TestOptError pins optError's contract: a *net.OpError with Op "get" or
// "set", wrapping os.NewSyscallError(call, errno), so errors.Is(err, errno)
// holds.
func TestOptError(t *testing.T) {
	for _, op := range []string{"get", "set"} {
		call := "getsockopt"
		if op == "set" {
			call = "setsockopt"
		}
		err := optError(op, call, "sctp", nil, nil, syscall.ENOPROTOOPT)
		if !errors.Is(err, syscall.ENOPROTOOPT) {
			t.Errorf("optError(%s): errors.Is(err, syscall.ENOPROTOOPT) is false for %v", op, err)
		}
		opErr, ok := err.(*net.OpError)
		if !ok {
			t.Fatalf("optError(%s) result is %T, want *net.OpError", op, err)
		}
		if opErr.Op != op {
			t.Errorf("optError(%s): Op = %q, want %q", op, opErr.Op, op)
		}
		se, ok := opErr.Err.(*os.SyscallError)
		if !ok {
			t.Fatalf("optError(%s): (*net.OpError).Err is %T, want *os.SyscallError", op, opErr.Err)
		}
		if se.Syscall != call {
			t.Errorf("optError(%s): syscall name = %q, want %q", op, se.Syscall, call)
		}
	}
}

// TestOptErrorClosed pins that optError's closed-socket case collapses the
// same way opError's does: one net.ErrClosed, not
// "getsockopt: use of closed network connection".
func TestOptErrorClosed(t *testing.T) {
	pipeErr := closedPipeRawConnError(t)

	for _, tc := range []struct {
		name string
		in   error
	}{
		{"net.ErrClosed", net.ErrClosed},
		{"os.ErrClosed", os.ErrClosed},
		{"closed os.File RawConn error", pipeErr},
	} {
		err := optError("get", "getsockopt", "sctp", nil, nil, tc.in)
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s: errors.Is(err, net.ErrClosed) is false for %v", tc.name, err)
		}
		if n := strings.Count(err.Error(), "use of closed"); n != 1 {
			t.Errorf("%s: %q contains \"use of closed\" %d times, want 1", tc.name, err.Error(), n)
		}
		// The collapse must discard the os.NewSyscallError(call, ...)
		// wrapping too, not just satisfy errors.Is through it: opErr.Err is
		// net.ErrClosed itself, so the message never carries "getsockopt: "
		// in front of it.
		opErr, ok := err.(*net.OpError)
		if !ok {
			t.Fatalf("%s: optError result is %T, want *net.OpError", tc.name, err)
		}
		if opErr.Err != net.ErrClosed {
			t.Errorf("%s: (*net.OpError).Err = %#v, want net.ErrClosed itself (no os.SyscallError nesting)",
				tc.name, opErr.Err)
		}
		if strings.Contains(err.Error(), "getsockopt") {
			t.Errorf("%s: %q still names the syscall after the closed-socket collapse", tc.name, err.Error())
		}
	}
}

// TestUnsupportedErr pins unsupportedErr's contract: it matches
// ErrUnsupported, errors.ErrUnsupported and its own errno.
func TestUnsupportedErr(t *testing.T) {
	err := error(unsupportedErr{syscall.EPROTONOSUPPORT})
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("errors.Is(err, ErrUnsupported) is false for %v", err)
	}
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("errors.Is(err, errors.ErrUnsupported) is false for %v", err)
	}
	if !errors.Is(err, syscall.EPROTONOSUPPORT) {
		t.Errorf("errors.Is(err, syscall.EPROTONOSUPPORT) is false for %v", err)
	}
	if errors.Is(err, syscall.ESOCKTNOSUPPORT) {
		t.Errorf("errors.Is(err, syscall.ESOCKTNOSUPPORT) is true for an EPROTONOSUPPORT value")
	}

	other := error(unsupportedErr{syscall.ESOCKTNOSUPPORT})
	if !errors.Is(other, ErrUnsupported) || !errors.Is(other, errors.ErrUnsupported) {
		t.Errorf("unsupportedErr{ESOCKTNOSUPPORT} does not match ErrUnsupported/errors.ErrUnsupported: %v", other)
	}
	if !errors.Is(other, syscall.ESOCKTNOSUPPORT) {
		t.Errorf("errors.Is(other, syscall.ESOCKTNOSUPPORT) is false for %v", other)
	}
}

// TestErrUnsupportedMatchesStdlib pins that the package-level ErrUnsupported
// variable itself satisfies errors.Is(ErrUnsupported, errors.ErrUnsupported).
func TestErrUnsupportedMatchesStdlib(t *testing.T) {
	if !errors.Is(ErrUnsupported, errors.ErrUnsupported) {
		t.Errorf("errors.Is(ErrUnsupported, errors.ErrUnsupported) is false")
	}
}

// TestErrorVariablesAreDistinct is a sanity check that the ten error
// variables are ten distinct values, so a caller's errors.Is against one
// never accidentally matches another.
func TestErrorVariablesAreDistinct(t *testing.T) {
	vars := []struct {
		name string
		err  error
	}{
		{"ErrUnsupported", ErrUnsupported},
		{"ErrMessageTooLong", ErrMessageTooLong},
		{"ErrMessageInterrupted", ErrMessageInterrupted},
		{"ErrNotificationTooLong", ErrNotificationTooLong},
		{"ErrShortNotification", ErrShortNotification},
		{"ErrControlTruncated", ErrControlTruncated},
		{"ErrInvalidRcvInfo", ErrInvalidRcvInfo},
		{"ErrMissingRcvInfo", ErrMissingRcvInfo},
		{"ErrAssocListTooLarge", ErrAssocListTooLarge},
		{"ErrInvalidAssocList", ErrInvalidAssocList},
	}
	if len(vars) != 10 {
		t.Fatalf("counted %d error variables, want ten", len(vars))
	}
	for i, a := range vars {
		if a.err == nil {
			t.Errorf("%s is nil", a.name)
		}
		for j, b := range vars {
			if i == j {
				continue
			}
			if errors.Is(a.err, b.err) {
				t.Errorf("%s matches %s via errors.Is; they must stay distinct", a.name, b.name)
			}
		}
	}
}
