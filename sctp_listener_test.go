//go:build linux
// +build linux

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

package sctp

import (
	"errors"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"
)

// TestListenerDoubleCloseDoesNotCloseRecycledFd covers a use-after-close.
//
// SCTPListener.Close called syscall.Close(ln.fd) without clearing ln.fd, so a
// second Close closed that descriptor number again. The kernel reuses
// descriptor numbers, so by then it may well belong to an unrelated socket
// opened in the meantime: the second Close silently tore down someone else's
// connection and returned nil, reporting success.
//
// The test opens a socket after closing the listener, specifically to occupy
// the recycled number, then closes the listener again.
func TestListenerDoubleCloseDoesNotCloseRecycledFd(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}

	// Claim the freed descriptor number with an unrelated socket.
	victim, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socket: %v", err)
	}
	defer func() { _ = syscall.Close(victim) }()

	// The second Close must not touch it.
	secondErr := ln.Close()

	if !fdIsOpen(victim) {
		t.Fatalf("second Close released descriptor %d, which belonged to an "+
			"unrelated socket (second Close returned %v)", victim, secondErr)
	}
	if !errors.Is(secondErr, net.ErrClosed) {
		t.Errorf("second Close = %v, want net.ErrClosed", secondErr)
	}
}

// TestListenerCloseIsIdempotent checks repeated closes stay safe and keep
// reporting the same error rather than succeeding again.
func TestListenerCloseIsIdempotent(t *testing.T) {
	addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := ln.Close(); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Close #%d = %v, want net.ErrClosed", i+2, err)
		}
	}
}

// TestListenerConcurrentClose asserts exactly one racing caller takes the
// descriptor, the same guarantee SCTPConn.Close provides.
func TestListenerConcurrentClose(t *testing.T) {
	for round := 0; round < 25; round++ {
		addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
		ln, err := ListenSCTP("sctp", addr)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}

		const racers = 8
		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			okCount int
		)
		wg.Add(racers)
		for i := 0; i < racers; i++ {
			go func() {
				defer wg.Done()
				if err := ln.Close(); err == nil {
					mu.Lock()
					okCount++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()

		if okCount != 1 {
			t.Fatalf("round %d: %d callers reported success, want exactly 1",
				round, okCount)
		}
	}
}

// TestListenerCloseUnblocksAccept checks a blocked Accept returns once the
// listener is closed, rather than hanging on a descriptor that is gone.
func TestListenerCloseUnblocksAccept(t *testing.T) {
	addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := ln.AcceptSCTP()
		done <- err
	}()

	// Let Accept reach the syscall before closing under it.
	time.Sleep(300 * time.Millisecond)

	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	select {
	case err := <-done:
		t.Logf("Accept returned %v after Close", err)
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Accept error = %v, want net.ErrClosed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
}

// TestListenerAcceptAfterCloseFails checks Accept on a closed listener reports
// an error instead of operating on a recycled descriptor.
func TestListenerAcceptAfterCloseFails(t *testing.T) {
	addr, _ := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := ln.AcceptSCTP(); !errors.Is(err, net.ErrClosed) {
		t.Errorf("AcceptSCTP error = %v, want net.ErrClosed", err)
	}
}
