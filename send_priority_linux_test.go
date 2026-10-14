// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"context"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// TestSendMsgContextRetainsPriority exercises a normal-mode wake that loses
// to a running sender, then checks priority over a fresh waiter. The
// syscalls and poller wait are fake; all acquisition goes through public sends.
func TestSendMsgContextRetainsPriority(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	var script func(*syscall.Msghdr) (int, error)
	hookSendmsg(t, func(_ int, msg *syscall.Msghdr, _ int) (int, error) { return script(msg) })
	for _, endpoint := range []bool{false, true} {
		t.Run(contextCaseName(endpoint, false), func(t *testing.T) {
			verified := 0
			for attempt := range 64 {
				var accepted []byte
				firstF := true
				script = func(msg *syscall.Msghdr) (int, error) {
					tag := iovBytes(msg)[0]
					if tag == 'F' && firstF {
						firstF = false
						return 0, syscall.EAGAIN
					}
					accepted = append(accepted, tag)
					return int(msg.Iov.Len), nil
				}
				raw := &fakeRawConn{}
				c := fakeContextSender(t, endpoint, raw)
				fresh := make(chan error, 1)
				raw.parkWrite = func() error {
					entered := make(chan struct{})
					go func() {
						entered <- struct{}{}
						_, err := c.ordinary([]byte{'B'}, SendOptions{})
						fresh <- err
					}()
					<-entered
					// Let B park behind F, then let the old waiter consume its
					// normal wake and lose to F before the poller returns.
					runtime.Gosched()
					return nil
				}
				c.state.mu.Lock()
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				victimContext := &observedDone{Context: ctx, entered: make(chan struct{})}
				victim := make(chan error, 1)
				go func() {
					_, err := c.send(victimContext, []byte{'V'}, SendOptions{})
					victim <- err
				}()
				select {
				case <-victimContext.entered:
				case <-time.After(time.Second):
					cancel()
					c.state.mu.Unlock()
					<-victim
					t.Fatal("victim did not enter cancellable lock wait")
				}
				// Give the victim time to register while ownership stays held
				// and to exceed the starvation threshold before the wake.
				runtime.Gosched()
				time.Sleep(2 * time.Millisecond)
				c.state.mu.Unlock()
				_, firstErr := c.ordinary([]byte{'F'}, SendOptions{})
				victimErr, freshErr := <-victim, <-fresh
				cancel()
				if firstErr != nil || victimErr != nil || freshErr != nil {
					t.Fatalf("send errors F=%v V=%v B=%v", firstErr, victimErr, freshErr)
				}
				if len(accepted) != 3 {
					t.Fatalf("accepted payloads=%q", accepted)
				}
				if accepted[0] == 'V' {
					// A scheduler preemption let the victim acquire before
					// the intended barger. Retry rather than judge this run.
					continue
				}
				if string(accepted) != "FVB" {
					t.Fatalf("priority lost after normal wake: accepted=%q, want FVB (attempt %d)", accepted, attempt)
				}
				verified++
				if verified == 8 {
					t.Logf("accepted=%q in %d schedules, last attempt=%d", accepted, verified, attempt)
					return
				}
			}
			t.Fatalf("arranged only %d normal-mode barges in 64 attempts, want 8", verified)
		})
	}
}
