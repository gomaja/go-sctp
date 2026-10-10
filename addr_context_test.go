// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests replace net.DefaultResolver and must not run in parallel with
// any test that resolves names. Each Dial blocks until its context ends or
// cleanup releases it, reproducing issue #21 without depending on DNS servers.
type blockedResolver struct {
	entered chan struct{}
	exited  chan struct{}
	release chan struct{}
	calls   atomic.Int32
	mu      sync.Mutex
	done    []chan struct{}
}

func installBlockedResolver(t *testing.T) *blockedResolver {
	t.Helper()
	r := &blockedResolver{
		entered: make(chan struct{}, 1),
		exited:  make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			done := make(chan struct{})
			r.mu.Lock()
			r.done = append(r.done, done)
			r.mu.Unlock()
			defer close(done)
			r.calls.Add(1)
			select {
			case r.entered <- struct{}{}:
			default:
			}
			select {
			case <-ctx.Done():
				select {
				case r.exited <- struct{}{}:
				default:
				}
				return nil, ctx.Err()
			case <-r.release:
				return nil, errors.New("test resolver released")
			}
		},
	}
	t.Cleanup(func() {
		defer func() { net.DefaultResolver = previous }()
		r.wait(t)
	})
	return r
}

// wait joins the Dial callbacks already started. DNS may retry after a
// cancellation, but those callbacks see the same cancelled context and return
// immediately. A WaitGroup cannot be reused here while net starts retries.
func (r *blockedResolver) wait(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	done := append([]chan struct{}(nil), r.done...)
	r.mu.Unlock()
	for _, ch := range done {
		select {
		case <-ch:
		case <-time.After(time.Second):
			t.Fatal("resolver Dial goroutine did not exit")
		}
	}
}

// startBlockedResolution always releases and joins the caller, including on
// failure against the old implementation. The resolver is restored afterward.
func startBlockedResolution(t *testing.T, r *blockedResolver, ctx context.Context, network, address string) <-chan error {
	t.Helper()
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		addr, err := ResolveAddrContext(ctx, network, address)
		if addr != nil {
			t.Errorf("cancelled resolution returned address %v", addr)
		}
		result <- err
	}()
	t.Cleanup(func() {
		close(r.release)
		<-done
	})
	return result
}

func requireResolutionError(t *testing.T, result <-chan error, want error) {
	t.Helper()
	select {
	case err := <-result:
		if !errors.Is(err, want) {
			t.Fatalf("resolution error = %v, want errors.Is(err, %v)", err, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("resolution still blocked one second after %v", want)
	}
}

func TestResolveAddrContextCancellation(t *testing.T) {
	for _, network := range []string{"", "sctp", "sctp4", "sctp6"} {
		t.Run(network, func(t *testing.T) {
			for _, address := range []string{
				"cancel-test.invalid:3868",
				"cancel-test.invalid/127.0.0.1:3868",
				"127.0.0.1/cancel-test.invalid/127.0.0.2:3868",
				"127.0.0.1/127.0.0.2/cancel-test.invalid:3868",
			} {
				t.Run(address, func(t *testing.T) {
					r := installBlockedResolver(t)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					result := startBlockedResolution(t, r, ctx, network, address)
					select {
					case <-r.entered:
					case <-time.After(time.Second):
						t.Fatal("resolution did not enter resolver Dial")
					}
					cancel()
					requireResolutionError(t, result, ctx.Err())
					select {
					case <-r.exited:
					case <-time.After(time.Second):
						t.Fatal("resolver Dial did not exit on cancellation")
					}
					r.wait(t)
				})
			}
		})
	}
}

func TestResolveAddrContextAlreadyCancelled(t *testing.T) {
	for _, network := range []string{"", "sctp", "sctp4", "sctp6"} {
		t.Run(network, func(t *testing.T) {
			r := installBlockedResolver(t)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			result := startBlockedResolution(t, r, ctx, network, "127.0.0.1/cancel-test.invalid:3868")
			requireResolutionError(t, result, ctx.Err())
			// LookupNetIP can return before its DNS goroutine starts. Give an
			// incorrectly started lookup time to reach Dial before checking.
			select {
			case <-r.entered:
				t.Fatal("already-cancelled context started resolver Dial")
			case <-time.After(20 * time.Millisecond):
			}
			if calls := r.calls.Load(); calls != 0 {
				t.Fatalf("already-cancelled context made %d resolver Dial calls, want 0", calls)
			}
		})
	}
}

func TestResolveAddrContextDeadline(t *testing.T) {
	for _, network := range []string{"", "sctp", "sctp4", "sctp6"} {
		t.Run(network, func(t *testing.T) {
			r := installBlockedResolver(t)
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			result := startBlockedResolution(t, r, ctx, network, "deadline-test.invalid:3868")
			requireResolutionError(t, result, context.DeadlineExceeded)
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatalf("context error = %v, want DeadlineExceeded", ctx.Err())
			}
			select {
			case <-r.exited:
			case <-time.After(time.Second):
				t.Fatal("resolver Dial did not exit on deadline")
			}
			r.wait(t)
		})
	}
}

// Literals and wildcards require no lookup, so cancellation must not prevent
// parsing them. Mapped addresses still normalize and IPv6 zones survive.
func TestResolveAddrContextCancelledLiterals(t *testing.T) {
	r := installBlockedResolver(t)
	defer close(r.release)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, network := range []string{"", "sctp", "sctp4", "sctp6"} {
		for _, address := range []string{":3868", "127.0.0.1:3868", "127.0.0.1/127.0.0.2:3868", "[::ffff:127.0.0.1]:3868", "[fe80::1%eth0]/[::1]:3868"} {
			if network == "sctp4" && address == "[fe80::1%eth0]/[::1]:3868" {
				continue
			}
			t.Run(network+"/"+address, func(t *testing.T) {
				addr, err := ResolveAddrContext(ctx, network, address)
				if err != nil {
					t.Fatalf("literal resolution: %v", err)
				}
				want := address
				if address == "[::ffff:127.0.0.1]:3868" {
					want = "127.0.0.1:3868"
				}
				if addr == nil || addr.String() != want {
					t.Fatalf("resolved address = %v, want %s", addr, want)
				}
			})
		}
	}
	if calls := r.calls.Load(); calls != 0 {
		t.Fatalf("literal resolution made %d resolver Dial calls, want 0", calls)
	}
}
