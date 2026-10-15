// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"syscall"
	"testing"
	"time"
)

// cancelAfterErr returns a snapshot taken before cancellation. This is the
// race LockContext permits: its entry check sees nil, then cancellation
// becomes visible while it takes an available lock.
type cancelAfterErr struct {
	context.Context
	cancel context.CancelFunc
}

func (c cancelAfterErr) Err() error {
	err := c.Context.Err()
	c.cancel()
	return err
}

func TestSendContextCanceledAfterLockCheck(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		t.Run(contextCaseName(endpoint, false), func(t *testing.T) {
			c := fakeConn(&fakeRawConn{}, nil)
			if endpoint {
				c.send.term = nil
				c.send.explicit = true
			}
			var calls int
			hookSendmsg(t, func(_ int, msg *syscall.Msghdr, _ int) (int, error) {
				calls++
				return int(msg.Iov.Len), nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// Exercise the shared core past the public method's entry check,
			// so the injected cancellation races LockContext's own check.
			n, err := c.send.send(cancelAfterErr{ctx, cancel}, &c.sock, []byte{1}, &SendOptions{}, nil, c.assoc)
			if n != 0 || !errors.Is(err, context.Canceled) || calls != 0 {
				t.Fatalf("send = %d, %v; sendmsg calls = %d; want 0, context.Canceled, 0", n, err, calls)
			}
			// Refusal after acquisition must also release ownership.
			done := make(chan error, 1)
			go func() { _, err := c.SendMsg([]byte{2}, SendOptions{}); done <- err }()
			select {
			case err := <-done:
				if err != nil || calls != 1 {
					t.Fatalf("next ordinary send = %v; sendmsg calls = %d; want nil, 1", err, calls)
				}
			case <-time.After(time.Second):
				t.Fatal("context refusal retained the send lock")
			}
		})
	}
}

// TestSendMsgContextContendedProgress pins the send path's reliance on a
// shared queue for plain and context callers: a live context makes progress
// under continuing plain traffic, and cancellation leaves no queued message.
// This is a bounded integration check, not a deterministic reproduction of
// the old sendLock's model-checked starvation cycle. The runtime does not
// expose the wake/requeue schedule needed to force that cycle here.
func TestSendMsgContextContendedProgress(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		for _, workers := range []int{4, 16} {
			t.Run(fmt.Sprintf("%s/workers%d", contextCaseName(endpoint, true), workers), func(t *testing.T) {
				c := fakeContextSender(t, endpoint, &fakeRawConn{})
				var victims, ordinary int
				hookSendmsg(t, func(_ int, msg *syscall.Msghdr, _ int) (int, error) {
					switch iovBytes(msg)[0] {
					case 1:
						ordinary++
					case 2:
						victims++
					default:
						t.Error("cancelled message reached sendmsg")
					}
					return int(msg.Iov.Len), nil
				})
				stop := make(chan struct{})
				active := make(chan struct{}, workers)
				failures := make(chan error, workers)
				var group sync.WaitGroup
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				c.state.mu.Lock()
				held := true
				defer func() {
					close(stop)
					if held {
						c.state.mu.Unlock()
					}
					group.Wait()
				}()
				for range workers {
					group.Go(func() {
						first := true
						for {
							select {
							case <-stop:
								return
							default:
							}
							if n, err := c.ordinary([]byte{1}, SendOptions{}); n != 1 || err != nil {
								failures <- fmt.Errorf("ordinary send = %d, %v", n, err)
								return
							}
							if first {
								active <- struct{}{}
								first = false
							}
						}
					})
				}
				waiting := &observedDone{Context: ctx, entered: make(chan struct{})}
				victim := make(chan error, 1)
				group.Go(func() {
					n, err := c.send(waiting, []byte{2}, SendOptions{NoWait: true})
					if err == nil && n != 1 {
						err = fmt.Errorf("victim send = %d bytes, want 1", n)
					}
					victim <- err
				})
				select {
				case <-waiting.entered:
				case <-ctx.Done():
					t.Fatal("victim never entered its context lock wait")
				}
				cancelCtx, cancelWaiter := context.WithCancel(context.Background())
				defer cancelWaiter()
				cancelled := &observedDone{Context: cancelCtx, entered: make(chan struct{})}
				done := make(chan error, 1)
				group.Go(func() { _, err := c.send(cancelled, []byte{3}, SendOptions{}); done <- err })
				select {
				case <-cancelled.entered:
				case <-ctx.Done():
					t.Fatal("cancellable sender never entered its lock wait")
				}
				cancelWaiter()
				contextResult(t, done, context.Canceled)
				c.state.mu.Unlock()
				held = false
				for range workers {
					select {
					case <-active:
					case err := <-failures:
						t.Fatal(err)
					case <-ctx.Done():
						t.Fatal("plain senders did not make progress")
					}
				}
				select {
				case err := <-victim:
					if err != nil {
						t.Fatalf("live victim: %v", err)
					}
				case <-ctx.Done():
					t.Fatal("live victim did not acquire under plain traffic")
				}
				for range 64 {
					if n, err := c.send(ctx, []byte{2}, SendOptions{NoWait: true}); n != 1 || err != nil {
						t.Fatalf("live victim under plain traffic = %d, %v", n, err)
					}
				}
				// The same lock guards the hook's counters; workers still run.
				c.state.mu.Lock()
				gotVictims, gotOrdinary := victims, ordinary
				c.state.mu.Unlock()
				if gotVictims != 65 || gotOrdinary < workers {
					t.Fatalf("accepted victim/plain messages = %d/%d, want 65/at least %d", gotVictims, gotOrdinary, workers)
				}
			})
		}
	}
}
