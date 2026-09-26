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

// TestOpErrorNoDoubleWrap pins that opError never double-wraps a
// *net.OpError that already describes exactly this operation: the same
// Op, Net, Source and Addr (by their String() forms), including the case
// where Source and Addr are both nil, which sameAddr must equate without
// calling String() on either.
func TestOpErrorNoDoubleWrap(t *testing.T) {
	for _, tc := range []struct {
		name           string
		source, addr   net.Addr
		matchingSource net.Addr
		matchingAddr   net.Addr
	}{
		{"nil Source and Addr", nil, nil, nil, nil},
		{"non-nil Source and Addr", &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}, &net.IPAddr{IP: net.IPv4(127, 0, 0, 2)},
			&net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}, &net.IPAddr{IP: net.IPv4(127, 0, 0, 2)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inner := &net.OpError{Op: "read", Net: "sctp", Source: tc.matchingSource, Addr: tc.matchingAddr, Err: syscall.ECONNRESET}
			got := opError("read", "sctp", tc.source, tc.addr, inner)
			if got != inner {
				t.Errorf("opError(matching *net.OpError) returned %#v, want the same value %#v unchanged", got, inner)
			}
		})
	}
}

// TestOpErrorWrapsMismatchedOpError pins the other half: a *net.OpError
// that does not already describe this exact operation — a different Op,
// Net, Source or Addr, such as one a Config.Control hook or a
// NotificationHandler returned from some other call entirely — is
// wrapped as this operation's cause like any other error, so the Op and
// Net a caller reads always name this call; errors.Is and errors.As
// still reach the foreign error's own cause through it.
func TestOpErrorWrapsMismatchedOpError(t *testing.T) {
	source := &net.IPAddr{IP: net.IPv4(127, 0, 0, 1)}
	other := &net.IPAddr{IP: net.IPv4(10, 0, 0, 9)}
	// baseline already matches op("read", "sctp4", source, source) in
	// every field; each case below changes exactly one of them away from
	// a match, so a sameOpError that dropped any single comparison would
	// wrongly call that one case a match and fail it.
	baseline := func() *net.OpError {
		return &net.OpError{Op: "read", Net: "sctp4", Source: source, Addr: source, Err: syscall.ECONNRESET}
	}
	for _, tc := range []struct {
		name    string
		foreign *net.OpError
	}{
		{"different Op", &net.OpError{Op: "setsockopt", Net: "sctp4", Source: source, Addr: source, Err: syscall.ECONNRESET}},
		{"different Net", &net.OpError{Op: "read", Net: "tcp", Source: source, Addr: source, Err: syscall.ECONNRESET}},
		{"different Source", func() *net.OpError { o := baseline(); o.Source = other; return o }()},
		{"different Addr", func() *net.OpError { o := baseline(); o.Addr = other; return o }()},
		{"nil Source where one is wanted", func() *net.OpError { o := baseline(); o.Source = nil; return o }()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := opError("read", "sctp4", source, source, tc.foreign)
			if got == tc.foreign {
				t.Fatalf("opError(mismatched *net.OpError) returned it unchanged: %#v", got)
			}
			opErr, ok := got.(*net.OpError)
			if !ok {
				t.Fatalf("opError result is %T, want *net.OpError", got)
			}
			if opErr.Op != "read" || opErr.Net != "sctp4" || !sameAddr(opErr.Source, source) || !sameAddr(opErr.Addr, source) {
				t.Errorf("opError(mismatched) = %#v, want Op read, Net sctp4, Source and Addr %v", opErr, source)
			}
			if !errors.Is(got, syscall.ECONNRESET) {
				t.Errorf("errors.Is(got, syscall.ECONNRESET) is false for %v; the foreign error's own cause must still be reachable", got)
			}
			// The foreign *net.OpError is opErr.Err itself, one level down
			// (errors.As would match got at depth 0, before ever looking:
			// both are *net.OpError, so it cannot distinguish the outer
			// wrap from the foreign one it names in an Errorf here).
			if unwrapped := errors.Unwrap(got); unwrapped != tc.foreign {
				t.Errorf("opError's cause is %#v, want the foreign error %#v itself, unwrapped exactly once", unwrapped, tc.foreign)
			}
		})
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

// TestIOOpError pins ioOpError: a joined error is wrapped whole, once,
// keeping every cause, net.ErrClosed among them, where opError would
// collapse it to net.ErrClosed alone; anything else is wrapped exactly as
// opError wraps it.
func TestIOOpError(t *testing.T) {
	joined := errors.Join(ErrMessageInterrupted, net.ErrClosed)
	err := ioOpError("read", "sctp4", nil, nil, joined)
	opErr, ok := err.(*net.OpError)
	if !ok || opErr.Op != "read" || opErr.Net != "sctp4" || opErr.Err != joined {
		t.Fatalf("ioOpError(joined) = %#v, want a read *net.OpError around the joined error", err)
	}
	for _, target := range []error{ErrMessageInterrupted, net.ErrClosed} {
		if !errors.Is(err, target) {
			t.Errorf("ioOpError(joined) does not match %v", target)
		}
	}
	if collapsed := opError("read", "sctp4", nil, nil, joined); errors.Is(collapsed, ErrMessageInterrupted) {
		t.Error("opError kept the joined causes; ioOpError would then be unnecessary")
	}

	for _, in := range []error{nil, io.EOF, os.ErrClosed, syscall.ECONNRESET, &net.OpError{Op: "read", Err: syscall.EIO}} {
		got, want := ioOpError("read", "sctp", nil, nil, in), opError("read", "sctp", nil, nil, in)
		if (got == nil) != (want == nil) || (got != nil && got.Error() != want.Error()) {
			t.Errorf("ioOpError(%v) = %v, opError gives %v", in, got, want)
		}
	}
	if ioOpError("read", "sctp", nil, nil, io.EOF) != io.EOF {
		t.Error("ioOpError wrapped io.EOF")
	}
}

// TestOpErrorForeignClosedNotCollapsed pins that a foreign *net.OpError
// whose own cause happens to match net.ErrClosed is wrapped as given,
// not collapsed to a bare net.ErrClosed: the collapse in opError
// (errors.go) is for a cause this package's own code reports directly,
// not for deciding what a foreign error's cause was. Collapsing it would
// discard the foreign error's own Op and Net, and errors.As could no
// longer reach it.
func TestOpErrorForeignClosedNotCollapsed(t *testing.T) {
	foreign := &net.OpError{Op: "dial", Net: "tcp", Err: net.ErrClosed}
	got := opError("read", "sctp4", nil, nil, foreign)
	opErr, ok := got.(*net.OpError)
	if !ok || opErr.Op != "read" || opErr.Net != "sctp4" {
		t.Fatalf("opError(foreign closed) = %#v, want a *net.OpError with Op read, Net sctp4", got)
	}
	if opErr.Err != foreign {
		t.Errorf("opError's cause is %#v, want the foreign *net.OpError %#v itself, not collapsed", opErr.Err, foreign)
	}
	if !errors.Is(got, net.ErrClosed) {
		t.Errorf("errors.Is(got, net.ErrClosed) is false for %v; the foreign error's own cause must still be reachable", got)
	}
}

// TestJoinAbortCause pins joinAbortCause's three cases: a nil Abort
// result joins nothing; one matching net.ErrClosed joins the bare
// sentinel; any other *net.OpError joins its own cause, never the
// *net.OpError itself, which is what keeps abortInterrupted
// (recv_linux.go) and abortInterruptedNotification (endpoint_linux.go)
// from chaining two wraps into whatever they return.
func TestJoinAbortCause(t *testing.T) {
	base := errors.New("interrupted")

	if got := joinAbortCause(base, nil); got != base {
		t.Errorf("joinAbortCause(base, nil) = %v, want base itself unchanged", got)
	}

	closedCases := []error{
		net.ErrClosed,
		&net.OpError{Op: "close", Net: "sctp", Err: net.ErrClosed},
	}
	for _, aerr := range closedCases {
		got := joinAbortCause(base, aerr)
		if !errors.Is(got, base) || !errors.Is(got, net.ErrClosed) {
			t.Errorf("joinAbortCause(base, %v) = %v, want it to join base and net.ErrClosed", aerr, got)
		}
		if _, ok := aerr.(*net.OpError); ok {
			var opErr *net.OpError
			if errors.As(got, &opErr) && opErr == aerr {
				t.Errorf("joinAbortCause(base, %v) = %v, joined the *net.OpError itself, not the bare sentinel", aerr, got)
			}
		}
	}

	root := errors.New("abort failed")
	aerr := &net.OpError{Op: "close", Net: "sctp", Err: root}
	got := joinAbortCause(base, aerr)
	if !errors.Is(got, base) || !errors.Is(got, root) {
		t.Errorf("joinAbortCause(base, %v) = %v, want it to join base and the abort's own cause %v", aerr, got, root)
	}
	var opErr *net.OpError
	if errors.As(got, &opErr) {
		t.Errorf("joinAbortCause(base, %v) = %v, joined the *net.OpError %#v itself rather than its cause", aerr, got, opErr)
	}

	other := errors.New("something else")
	if got := joinAbortCause(base, other); !errors.Is(got, base) || !errors.Is(got, other) {
		t.Errorf("joinAbortCause(base, %v) = %v, want it to join base and other", other, got)
	}
}
