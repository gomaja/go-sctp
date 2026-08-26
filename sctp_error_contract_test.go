// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"errors"
	"net"
	"reflect"
	"testing"
)

func requireSCTPOpError(
	t *testing.T,
	err error,
	op, network string,
	source, addr *SCTPAddr,
	cause error,
) *net.OpError {
	t.Helper()

	if err == nil {
		t.Fatal("operation returned no error")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("error = %v, want an error wrapping %v", err, cause)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("error type = %T, want *net.OpError", err)
	}
	if opErr.Op != op {
		t.Errorf("Op = %q, want %q", opErr.Op, op)
	}
	if opErr.Net != network {
		t.Errorf("Net = %q, want %q", opErr.Net, network)
	}
	var wantSource, wantAddr net.Addr
	if source != nil {
		wantSource = source
	}
	if addr != nil {
		wantAddr = addr
	}
	if !reflect.DeepEqual(opErr.Source, wantSource) {
		t.Errorf("Source = %#v, want %#v", opErr.Source, wantSource)
	}
	if !reflect.DeepEqual(opErr.Addr, wantAddr) {
		t.Errorf("Addr = %#v, want %#v", opErr.Addr, wantAddr)
	}
	return opErr
}

func TestClosedOperationErrorRetainsNetErrorContract(t *testing.T) {
	err := errClosed("read")
	opErr, ok := err.(*net.OpError)
	if !ok {
		t.Fatalf("closed error type = %T, want *net.OpError", err)
	}
	if _, ok := err.(net.Error); !ok {
		t.Fatalf("closed error type = %T, want net.Error", err)
	}
	if opErr.Op != "read" || opErr.Net != "sctp" || opErr.Err != net.ErrClosed {
		t.Fatalf("closed error = %#v, want read sctp wrapping net.ErrClosed", opErr)
	}
}
