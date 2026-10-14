// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"context"
	"errors"
	"math/rand"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func sendLockResult(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("operation did not complete within one second")
	}
}

// TestSendLockBarging pins normal mode's running-locker advantage: a FIFO
// handoff always wakes the parked waiter before the releaser can lock again.
func TestSendLockBarging(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	for range 128 {
		var s sendState
		s.bind(nil)
		m := &s.mu
		m.Lock()
		var order atomic.Int32
		ctx := &observedDone{Context: context.Background(), entered: make(chan struct{})}
		waiter := make(chan error, 1)
		go func() {
			if err := m.acquire(ctx); err != nil {
				waiter <- err
				return
			}
			order.Add(1)
			m.Unlock()
			waiter <- nil
		}()
		select {
		case <-ctx.entered:
		case <-time.After(time.Second):
			t.Fatal("waiter did not reach admission")
		}
		sendLockState(t, m, func(s int32) bool { return s>>lockWaiterShift == 1 })
		result := make(chan bool, 1)
		go func() {
			m.Unlock()
			m.Lock()
			first := order.Add(1) == 1
			m.Unlock()
			result <- first
		}()
		var barged bool
		select {
		case barged = <-result:
		case <-time.After(time.Second):
			t.Fatal("releaser did not reacquire")
		}
		sendLockResult(t, waiter)
		if barged {
			return
		}
	}
	t.Fatal("a running releaser never barged ahead of its parked waiter")
}

func newSendLock() sendLock {
	return sendLock{wake: make(chan struct{}, 1), hand: make(chan struct{}, 1)}
}

func sendLockEmpty(t *testing.T, m *sendLock) {
	t.Helper()
	if n, a, h := m.state.Load(), m.abandoned.Load(), len(m.hand); n != 0 || a != 0 || h != 0 {
		t.Fatalf("unsettled lock: state=%d abandoned=%d hand=%d wake=%d", n, a, h, len(m.wake))
	}
}

func sendLockCycle(m *sendLock) error {
	m.Lock()
	held := m.state.Load()
	m.Unlock()
	if held&lockHeld == 0 {
		return errors.New("acquisition did not hold the lock")
	}
	return nil
}

func sendLockState(t *testing.T, m *sendLock, want func(int32) bool) {
	t.Helper()
	limit := time.Now().Add(time.Second)
	for !want(m.state.Load()) {
		if time.Now().After(limit) {
			t.Fatalf("lock did not reach required state: state=%d abandoned=%d", m.state.Load(), m.abandoned.Load())
		}
		runtime.Gosched()
	}
}

// TestSendLockFastPath leaves both channels nil: touching either would block.
func TestSendLockFastPath(t *testing.T) {
	for _, name := range []string{"Lock", "acquire"} {
		t.Run(name, func(t *testing.T) {
			var m sendLock
			done := make(chan error, 1)
			ctx := &observedDone{Context: context.Background(), entered: make(chan struct{})}
			go func() {
				for range 2 {
					if name == "acquire" {
						if err := m.acquire(ctx); err != nil {
							done <- err
							return
						}
					} else {
						m.Lock()
					}
					held := m.state.Load()
					m.Unlock()
					if held != lockHeld {
						done <- errors.New("uncontended locker was not sole holder")
						return
					}
				}
				done <- nil
			}()
			sendLockResult(t, done)
			select {
			case <-ctx.entered:
				t.Fatal("uncontended acquire called Done")
			default:
			}
			sendLockEmpty(t, &m)
		})
	}
}

func TestSendLockCanceledWait(t *testing.T) {
	m := newSendLock()
	m.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- m.acquire(&observedDone{Context: ctx, entered: entered}) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("waiter did not register")
	}
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("acquire = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation stalled")
	}
	if n, a := m.state.Load(), m.abandoned.Load(); n != lockHeld+1<<lockWaiterShift || a != 1 {
		t.Fatalf("cancellation removed its registration: state=%d abandoned=%d", n, a)
	}
	m.Unlock()
	sendLockEmpty(t, &m)
}

// sendLockStarved seeds a reachable normal wake after a barger has already
// taken the lock (sendLock.unlockSlow). The holder never releases it during
// setup, so even preemption cannot let the waiter acquire early. The caller
// sets a zero threshold; the woken waiter must register in starvation mode.
func sendLockStarved(t *testing.T, m *sendLock) (chan error, chan struct{}) {
	t.Helper()
	m.Lock()
	got := make(chan error, 2)
	release := make(chan struct{})
	go func() {
		m.Lock()
		got <- nil
		select {
		case <-release:
		case <-time.After(time.Second):
			m.Unlock()
			got <- errors.New("handoff holder was not released")
			return
		}
		m.Unlock()
		got <- nil
	}()
	sendLockState(t, m, func(s int32) bool { return s>>lockWaiterShift == 1 })
	m.state.Or(lockWoken)
	m.wake <- struct{}{}
	sendLockState(t, m, func(s int32) bool { return s&lockStarving != 0 })
	return got, release
}

func TestSendLockHandoff(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	threshold := lockStarvation
	lockStarvation = 0
	defer func() { lockStarvation = threshold }()
	m := newSendLock()
	got, release := sendLockStarved(t, &m)
	relocked := make(chan error, 1)
	go func() { m.Unlock(); relocked <- sendLockCycle(&m) }()
	sendLockResult(t, got)
	select {
	case <-relocked:
		close(release)
		t.Fatal("releaser barged ahead of starvation handoff")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	sendLockResult(t, got)
	sendLockResult(t, relocked)
	sendLockEmpty(t, &m)
}

// TestSendLockHandoffYields pins the yield after a starvation handoff: on
// one P, the new owner runs before its releaser continues. The scheduler
// may still pick the releaser first now and then (runtime/proc.go:
// findRunnable takes from the global queue every 61st tick), so a majority
// of rounds decides.
func TestSendLockHandoffYields(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	threshold := lockStarvation
	lockStarvation = 0
	defer func() { lockStarvation = threshold }()
	const rounds = 16
	first := 0
	for range rounds {
		m := newSendLock()
		got, release := sendLockStarved(t, &m)
		m.Unlock()
		if len(got) == 1 {
			first++
		}
		close(release)
		sendLockResult(t, got)
		sendLockResult(t, got)
		sendLockEmpty(t, &m)
	}
	if first <= rounds/2 {
		t.Fatalf("new owner ran before its releaser in %d of %d handoffs", first, rounds)
	}
}

// TestSendLockReleaseMode replays a normal release whose CAS failed because
// a later holder entered starvation mode before the retry Load: it must not
// hand off. internal/sync/mutex.go: Mutex.unlockSlow keeps the release's
// original mode.
func TestSendLockReleaseMode(t *testing.T) {
	m := newSendLock()
	m.state.Store(lockHeld | lockStarving | 1<<lockWaiterShift)
	done := make(chan error, 1)
	go func() { m.unlockSlow(1 << lockWaiterShift); done <- nil }()
	sendLockResult(t, done)
	if s, h := m.state.Load(), len(m.hand); s != lockHeld|lockStarving|1<<lockWaiterShift || h != 0 {
		t.Fatalf("old normal release joined later handoff: state=%d hand=%d", s, h)
	}
}

// TestSendLockStarvationExit settles the last registration in starvation
// mode with a stale lockWoken: the release must clear both bits.
func TestSendLockStarvationExit(t *testing.T) {
	m := newSendLock()
	m.state.Store(lockStarving | lockWoken | 1<<lockWaiterShift)
	m.abandoned.Store(1)
	m.wake <- struct{}{}
	done := make(chan error, 1)
	go func() { m.unlockSlow(lockStarving | lockWoken | 1<<lockWaiterShift); done <- nil }()
	sendLockResult(t, done)
	sendLockEmpty(t, &m)
	if len(m.wake) != 1 {
		t.Fatal("stale wake token was lost")
	}
}

func TestSendLockLiveness(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	m := newSendLock()
	m.Lock()
	stop, joined := make(chan struct{}), make(chan struct{})
	var cycles atomic.Int64
	go func() {
		defer close(joined)
		for {
			select {
			case <-stop:
				return
			default:
			}
			m.Lock()
			cycles.Add(1)
			m.Unlock()
		}
	}()
	sendLockState(t, &m, func(s int32) bool { return s>>lockWaiterShift == 1 })
	defer func() {
		close(stop)
		select {
		case <-joined:
		case <-time.After(time.Second):
			t.Error("hammer did not stop")
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		err := m.acquire(ctx)
		if err == nil {
			held := m.state.Load()
			m.Unlock()
			if held&lockHeld == 0 {
				err = errors.New("waiter did not hold the lock")
			}
		}
		done <- err
	}()
	sendLockState(t, &m, func(s int32) bool { return s>>lockWaiterShift == 2 })
	m.Unlock()
	sendLockResult(t, done)
	if cycles.Load() == 0 {
		t.Fatal("hammer never acquired")
	}
	if waited := time.Since(start); waited > 800*time.Millisecond {
		t.Fatalf("acquisition took %v of its one-second allowance", waited)
	}
}

// TestSendLockWakeClearsWoken observes the wake receiver's own CAS before
// it registers again under the same holder, isolating the normal wake path.
func TestSendLockWakeClearsWoken(t *testing.T) {
	m := newSendLock()
	m.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- m.acquire(ctx) }()
	sendLockState(t, &m, func(s int32) bool { return s>>lockWaiterShift == 1 })
	m.state.Or(lockWoken)
	m.wake <- struct{}{}
	sendLockState(t, &m, func(s int32) bool { return s&lockWoken == 0 && s>>lockWaiterShift == 1 })
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("acquire = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("woken waiter did not cancel")
	}
	m.Unlock()
	sendLockEmpty(t, &m)
}

// TestSendLockStaleHand starts after an older normal release settled the
// last abandoned registration while hand was buffered: lockStarving still
// protects that token (sendLock.unlockSlow). The real acquire registers,
// then may choose cancellation over the hand, leaving another stale hand.
func TestSendLockStaleHand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var m *sendLock
	for range 128 {
		candidate := newSendLock()
		candidate.state.Store(lockStarving)
		candidate.hand <- struct{}{}
		if err := candidate.acquire(ctx); err != nil {
			if err != context.Canceled {
				t.Fatal(err)
			}
			if candidate.abandoned.Load() != 1 {
				t.Fatal("given-up hand receiver did not record abandonment")
			}
			m = &candidate
			break
		}
		candidate.Unlock()
		sendLockEmpty(t, &candidate)
	}
	if m == nil {
		t.Fatal("select never chose cancellation over a ready hand")
	}
	got := make(chan error, 2)
	release := make(chan struct{})
	go func() {
		m.Lock()
		got <- nil
		select {
		case <-release:
		case <-time.After(time.Second):
			m.Unlock()
			got <- errors.New("stale-hand holder was not released")
			return
		}
		m.Unlock()
		got <- nil
	}()
	sendLockResult(t, got)
	second := make(chan error, 1)
	go func() { second <- sendLockCycle(m) }()
	sendLockState(t, m, func(s int32) bool { return s>>lockWaiterShift >= 1 })
	select {
	case <-second:
		close(release)
		t.Fatal("concurrent locker acquired while stale-hand receiver held")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	sendLockResult(t, got)
	sendLockResult(t, second)
	if err := sendLockCycle(m); err != nil {
		t.Fatal(err)
	}
	sendLockEmpty(t, m)
}

// TestSendLockStaleWake models an older settled registration's wake still
// buffered while a new holder runs. Cancellation must not consume that wake;
// the holder's release settles the new registration and clears stale woken.
func TestSendLockStaleWake(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 128 {
		m := newSendLock()
		m.Lock()
		m.state.Or(lockWoken)
		m.wake <- struct{}{}
		if err := m.acquire(ctx); err != context.Canceled {
			t.Fatalf("acquire = %v", err)
		}
		stale := m.state.Load()&lockWoken != 0
		m.Unlock()
		sendLockEmpty(t, &m)
		if stale {
			if len(m.wake) != 1 {
				t.Fatal("cancellation consumed the stale wake")
			}
			return
		}
	}
	t.Fatal("select never chose cancellation over a ready wake")
}

// sendLockCounter has no shared atomics besides the lock itself: worker-local
// totals are joined only after all guarded accesses. In particular an owner
// flag must not supply its own happens-before chain around the plain counter.
func sendLockCounter(t *testing.T, m *sendLock) {
	t.Helper()
	var counter int
	done := make(chan int, 8)
	for range 8 {
		go func() {
			local := 0
			for range 200 {
				m.Lock()
				counter++
				local++
				runtime.Gosched()
				m.Unlock()
			}
			done <- local
		}()
	}
	total := 0
	for range 8 {
		select {
		case n := <-done:
			total += n
		case <-time.After(time.Second):
			t.Fatal("counter-only worker did not finish")
		}
	}
	if counter != total {
		t.Fatalf("guarded counter=%d acquisitions=%d", counter, total)
	}
}

func TestSendLockSynchronization(t *testing.T) {
	m := newSendLock()
	sendLockCounter(t, &m)
	sendLockEmpty(t, &m)
}

// TestSendLockStress observes a normal wake and starvation handoff before
// mixing admission and cancellations. It checks overlapping owners with a
// flag, then checks memory synchronization in a separate counter-only phase.
func TestSendLockStress(t *testing.T) {
	for _, threshold := range []time.Duration{time.Millisecond, 0} {
		t.Run(threshold.String(), func(t *testing.T) {
			previous := lockStarvation
			lockStarvation = 0
			defer func() { lockStarvation = previous }()
			m := newSendLock()
			procs := runtime.GOMAXPROCS(1)
			got, release := sendLockStarved(t, &m)
			var wakes, hands int
			// sendLockStarved observed woken, then its removal and starving entry.
			wakes++
			m.Unlock()
			sendLockResult(t, got)
			hands++
			close(release)
			sendLockResult(t, got)
			runtime.GOMAXPROCS(procs)
			lockStarvation = threshold
			var owner, successes, abandons atomic.Int32
			var counter int
			// Seed a real parked cancellation so even a fast run must settle one.
			m.Lock()
			ctx, cancel := context.WithCancel(context.Background())
			entered := make(chan struct{})
			canceled := make(chan error, 1)
			go func() { canceled <- m.acquire(&observedDone{Context: ctx, entered: entered}) }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("seed waiter did not register")
			}
			cancel()
			select {
			case err := <-canceled:
				if err != context.Canceled {
					t.Fatalf("seed acquire = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("seed cancellation stalled")
			}
			abandons.Add(1)
			m.Unlock()
			done := make(chan error, 8)
			for worker := range 8 {
				go func() {
					random := rand.New(rand.NewSource(int64(worker + 1)))
					for range 500 {
						if random.Intn(3) == 0 {
							m.Lock()
						} else {
							ctx, cancel := context.WithCancel(context.Background())
							var joined chan struct{}
							if random.Intn(2) == 0 {
								cancel()
							} else {
								joined = make(chan struct{})
								go func() { runtime.Gosched(); cancel(); close(joined) }()
							}
							err := m.acquire(ctx)
							cancel()
							if joined != nil {
								select {
								case <-joined:
								case <-time.After(time.Second):
									done <- errors.New("cancellation goroutine did not finish")
									return
								}
							}
							if err != nil {
								if err != context.Canceled {
									done <- err
									return
								}
								abandons.Add(1)
								continue
							}
						}
						if !owner.CompareAndSwap(0, 1) {
							done <- errors.New("overlapping lock holders")
							return
						}
						counter++
						successes.Add(1)
						runtime.Gosched()
						owner.Store(0)
						m.Unlock()
					}
					done <- nil
				}()
			}
			for range 8 {
				sendLockResult(t, done)
			}
			if successes.Load() != int32(counter) {
				t.Fatalf("successes=%d counter=%d", successes.Load(), counter)
			}
			sendLockCounter(t, &m)
			go func() { done <- sendLockCycle(&m) }()
			sendLockResult(t, done)
			sendLockEmpty(t, &m)
			if abandons.Load() == 0 || wakes == 0 || hands == 0 {
				t.Fatal("required cancellation/wake/handoff path not exercised")
			}
			t.Logf("acquisitions=%d abandons=%d observed wakes=%d handoffs=%d", successes.Load(), abandons.Load(), wakes, hands)
		})
	}
}

// TestOrdinarySendWithoutDeadlineMu pins the nil-context path, on both
// socket styles; a caller's write-deadline bookkeeping cannot delay it.
func TestOrdinarySendWithoutDeadlineMu(t *testing.T) {
	for _, name := range []string{"SendMsg", "Write", "Endpoint"} {
		t.Run(name, func(t *testing.T) {
			c := fakeConn(&fakeRawConn{}, nil)
			state := &c.send
			send := func() error { _, err := c.SendMsg([]byte{1}, SendOptions{}); return err }
			if name == "Write" {
				send = func() error { _, err := c.Write([]byte{1}); return err }
			}
			if name == "Endpoint" {
				e := &Endpoint{sock: c.sock}
				e.life.init()
				e.send.bind(nil)
				e.send.explicit = true
				state = &e.send
				send = func() error { _, err := e.SendMsg(7, []byte{1}, SendOptions{}); return err }
			}
			hookSendmsg(t, func(_ int, msg *syscall.Msghdr, _ int) (int, error) { return int(msg.Iov.Len), nil })
			state.deadlineMu.Lock()
			done := make(chan error, 1)
			go func() { done <- send() }()
			// Release and join even on a regression: the hook must outlive the send.
			select {
			case err := <-done:
				state.deadlineMu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				state.deadlineMu.Unlock()
				sendLockResult(t, done)
				t.Fatal("ordinary send took deadlineMu")
			}
		})
	}
}

// TestReadDeadlineWithoutDeadlineMu also pins that writes still coordinate
// with interrupt; the pipe supplies a real pollable file without a socket.
func TestReadDeadlineWithoutDeadlineMu(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	c := fakeConn(&fakeRawConn{}, nil)
	c.sock.file = r
	c.send.writeDeadline = r.SetWriteDeadline
	c.send.deadlineMu.Lock()
	done := make(chan error, 1)
	go func() { done <- c.SetReadDeadline(time.Time{}) }()
	select {
	case err := <-done:
		if err != nil {
			c.send.deadlineMu.Unlock()
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		c.send.deadlineMu.Unlock()
		sendLockResult(t, done)
		t.Fatal("read deadline took deadlineMu")
	}
	started := make(chan struct{})
	go func() { close(started); done <- c.SetWriteDeadline(time.Time{}) }()
	<-started
	select {
	case err := <-done:
		c.send.deadlineMu.Unlock()
		t.Fatalf("write deadline bypassed deadlineMu: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	c.send.deadlineMu.Unlock()
	sendLockResult(t, done)
}

// TestOrdinarySendBufferRetry drives attempt's EAGAIN branch with no ctx.
func TestOrdinarySendBufferRetry(t *testing.T) {
	calls, parks := 0, 0
	c := fakeConn(&fakeRawConn{parkWrite: func() error { parks++; return nil }}, nil)
	hookSendmsg(t, func(_ int, msg *syscall.Msghdr, _ int) (int, error) {
		calls++
		if calls == 1 {
			return 0, syscall.EAGAIN
		}
		return int(msg.Iov.Len), nil
	})
	n, err := c.SendMsg([]byte{1}, SendOptions{})
	if n != 1 || err != nil || calls != 2 || parks != 1 {
		t.Fatalf("send = %d, %v; calls=%d parks=%d", n, err, calls, parks)
	}
}
