// Copyright 2019 Wataru Ishida. All rights reserved.
// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// This file includes modifications by gomaja.

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
	"math"
	"net"
	"runtime"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// These tests drive the close state machine (close.go) with fake system
// calls and a fake clock, so every outcome, every ordering of Close against
// Abort and the whole backoff schedule are checked on every platform,
// without a socket and without real waiting. Whether the real Linux steps
// behind closeOps do what the contract says is a separate question, answered
// against a kernel.

// hangGuard bounds how long a test waits in real time for a result the
// state machine should produce at once. The fake clock never advances on
// its own, so a correct lifecycle never gets anywhere near it; it exists
// only to turn a hang into a failure instead of a stuck test binary.
const hangGuard = 10 * time.Second

// fakeClock is the lifecycle's time source under test. now reports the
// clock's own time, which only moves when the lifecycle waits. In auto mode
// every after(d) moves the clock forward by d and returns a channel that has
// already fired, so a whole grace period elapses without any real waiting.
// In manual mode after(d) returns a channel that fires only when the test
// calls advance, and reports d on waiting, so a test can act while the
// lifecycle is parked in its wait.
type fakeClock struct {
	mu      sync.Mutex
	t       time.Time
	auto    bool
	waits   []time.Duration // every d passed to after, in order
	pending []fakeTimer
	// waiting receives d from every after call in manual mode. It is
	// buffered well past the number of waits any one test makes, so that
	// after never blocks on a test that does not read it, and a test that
	// does can wait on it until the lifecycle is parked.
	waiting chan time.Duration
	// hook, when set, runs on every after call with its zero-based index,
	// before the channel is chosen. It returns true to make that one wait
	// never fire, whatever the mode.
	hook func(n int) bool
}

type fakeTimer struct {
	at time.Time
	c  chan time.Time
}

// fakeEpoch is an arbitrary fixed starting time, far from the zero Time so
// that no deadline arithmetic can wrap.
var fakeEpoch = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func newAutoClock() *fakeClock { return &fakeClock{t: fakeEpoch, auto: true} }

func newManualClock() *fakeClock {
	return &fakeClock{t: fakeEpoch, waiting: make(chan time.Duration, 1024)}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) after(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	n := len(c.waits)
	c.waits = append(c.waits, d)
	hook := c.hook
	c.mu.Unlock()

	if hook != nil && hook(n) {
		return nil // a nil channel never fires
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	if c.auto {
		c.t = c.t.Add(d)
		ch <- c.t
		return ch
	}
	c.pending = append(c.pending, fakeTimer{at: c.t.Add(d), c: ch})
	c.waiting <- d
	return ch
}

// advance moves a manual clock forward by d and fires every timer now due.
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
	kept := c.pending[:0]
	for _, p := range c.pending {
		if p.at.After(c.t) {
			kept = append(kept, p)
			continue
		}
		p.c <- c.t
	}
	c.pending = kept
}

func (c *fakeClock) recordedWaits() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.waits...)
}

// fakeOps implements closeOps with scripted results and counts every call.
type fakeOps struct {
	*fakeClock

	mu sync.Mutex
	// gone answers the n-th assocGone call (zero-based). Nil means the
	// association never goes away: a peer that never answers the SHUTDOWN.
	gone        func(n int) (bool, error)
	shutdownErr error
	abortiveErr error
	releaseErr  error
	// abortiveGate, when set, makes abortive block until it is closed, and
	// abortiveEntered is closed when abortive starts.
	abortiveGate    chan struct{}
	abortiveEntered chan struct{}

	goneCalls, shutdownCalls, abortiveCalls, releaseCalls int
	goneResults                                           []goneResult
}

type goneResult struct {
	gone bool
	err  error
}

func (f *fakeOps) assocGone() (bool, error) {
	f.mu.Lock()
	n := f.goneCalls
	f.goneCalls++
	script := f.gone
	f.mu.Unlock()
	var r goneResult
	if script != nil {
		r.gone, r.err = script(n)
	}
	f.mu.Lock()
	f.goneResults = append(f.goneResults, r)
	f.mu.Unlock()
	return r.gone, r.err
}

func (f *fakeOps) startShutdown() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shutdownCalls++
	return f.shutdownErr
}

func (f *fakeOps) abortive() error {
	f.mu.Lock()
	f.abortiveCalls++
	gate, entered := f.abortiveGate, f.abortiveEntered
	f.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if gate != nil {
		<-gate
	}
	return f.abortiveErr
}

func (f *fakeOps) release() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseCalls++
	return f.releaseErr
}

// callCounts is a consistent snapshot of fakeOps's counters.
type callCounts struct{ gone, shutdown, abortive, release int }

func (f *fakeOps) counts() callCounts {
	f.mu.Lock()
	defer f.mu.Unlock()
	return callCounts{f.goneCalls, f.shutdownCalls, f.abortiveCalls, f.releaseCalls}
}

// goneAfter scripts an association that is still there for the first n
// polls and gone from then on.
func goneAfter(n int) func(int) (bool, error) {
	return func(call int) (bool, error) { return call >= n, nil }
}

func newLifecycleForTest() *lifecycle {
	l := new(lifecycle)
	l.init()
	return l
}

// wantReleased asserts that l has reached closed and signalled done.
func wantReleased(t *testing.T, l *lifecycle) {
	t.Helper()
	if got := lifeState(l.state.Load()); got != lifeClosed {
		t.Errorf("state = %d, want lifeClosed (%d)", got, lifeClosed)
	}
	select {
	case <-l.done:
	default:
		t.Error("done is not closed although the descriptor was released")
	}
}

// wantClosedErr asserts that err reports an already closed connection.
func wantClosedErr(t *testing.T, what string, err error) {
	t.Helper()
	if !errors.Is(err, net.ErrClosed) {
		t.Errorf("%s = %v, want an error matching net.ErrClosed", what, err)
	}
}

func sumDurations(ds []time.Duration) time.Duration {
	var s time.Duration
	for _, d := range ds {
		s += d
	}
	return s
}

// TestLifecycleCloseGraceful is the ordinary Close: the peer answers the
// SHUTDOWN, the association goes away while close is polling, and the
// descriptor is released as it is, with no ABORT (RFC 9260 §9.2). It also
// carries over the property of v1's TestCloseWithRespondingPeerReturnsPromptly:
// close stops waiting at the first poll that finds the association gone,
// rather than running out its grace period.
func TestLifecycleCloseGraceful(t *testing.T) {
	ops := &fakeOps{fakeClock: newAutoClock(), gone: goneAfter(2)}
	l := newLifecycleForTest()

	if err := l.close(ops, 3*time.Second); err != nil {
		t.Fatalf("close = %v, want nil", err)
	}
	got := ops.counts()
	want := callCounts{gone: 3, shutdown: 1, abortive: 0, release: 1}
	if got != want {
		t.Errorf("calls = %+v, want %+v", got, want)
	}
	if waits := ops.recordedWaits(); !slices.Equal(waits, []time.Duration{shutdownPollMin, 2 * shutdownPollMin}) {
		t.Errorf("waits = %v, want [200µs 400µs]: one backoff step between each poll, and none after the association is gone", waits)
	}
	wantReleased(t, l)
}

// TestLifecycleCloseGraceExpiry is a peer that never answers the SHUTDOWN:
// close spends exactly its grace period polling on the backoff schedule,
// then falls back to the abortive close and still returns nil. It carries
// over v1's TestCloseTimeoutBoundsTheShutdownWait: the grace period bounds
// the wait and is also spent in full, so neither a wait that returns early
// nor one that overruns passes.
func TestLifecycleCloseGraceExpiry(t *testing.T) {
	const grace = 3 * time.Second
	ops := &fakeOps{fakeClock: newAutoClock()} // gone == nil: never answers
	l := newLifecycleForTest()

	if err := l.close(ops, grace); err != nil {
		t.Fatalf("close = %v, want nil", err)
	}
	// 200 µs doubling to 20 ms: the seven doubling steps take 25.4 ms,
	// 148 steps of 20 ms take the next 2.96 s, and the last wait is the
	// 14.6 ms that are left.
	waits := ops.recordedWaits()
	head := []time.Duration{
		200 * time.Microsecond, 400 * time.Microsecond, 800 * time.Microsecond,
		1600 * time.Microsecond, 3200 * time.Microsecond, 6400 * time.Microsecond,
		12800 * time.Microsecond,
	}
	if len(waits) != 156 {
		t.Errorf("close waited %d times, want 156", len(waits))
	} else {
		if !slices.Equal(waits[:7], head) {
			t.Errorf("first waits = %v, want %v", waits[:7], head)
		}
		for i := 7; i < 155; i++ {
			if waits[i] != 20*time.Millisecond {
				t.Errorf("wait %d = %v, want the 20 ms cap", i, waits[i])
				break
			}
		}
		if last := waits[155]; last != 14600*time.Microsecond {
			t.Errorf("last wait = %v, want the 14.6 ms left of the grace period", last)
		}
	}
	if total := sumDurations(waits); total != grace {
		t.Errorf("time spent waiting = %v, want exactly the grace period %v", total, grace)
	}
	if elapsed := ops.now().Sub(fakeEpoch); elapsed != grace {
		t.Errorf("fake clock moved %v, want %v", elapsed, grace)
	}
	for i, w := range waits {
		if w <= 0 || w > shutdownPollMax {
			t.Errorf("wait %d = %v, want within (0, %v]", i, w, shutdownPollMax)
		}
	}
	got := ops.counts()
	// One poll before each wait, and a last one when the grace runs out.
	want := callCounts{gone: len(waits) + 1, shutdown: 1, abortive: 1, release: 0}
	if got != want {
		t.Errorf("calls = %+v, want %+v", got, want)
	}
	wantReleased(t, l)
}

// TestLifecycleAbortOvertakesClose is Abort arriving while Close waits for
// the SHUTDOWN handshake: the ABORT goes out at once instead of at the end
// of the grace period (RFC 9260 §§9.1, 11.1.4), both calls return nil, and
// Abort returns only once the descriptor has been released. The clock
// never advances, so close can only return because of the abort.
func TestLifecycleAbortOvertakesClose(t *testing.T) {
	gate := make(chan struct{})
	ops := &fakeOps{
		fakeClock:       newManualClock(),
		abortiveGate:    gate,
		abortiveEntered: make(chan struct{}),
	}
	l := newLifecycleForTest()

	closeRes := make(chan error, 1)
	go func() { closeRes <- l.close(ops, 3*time.Second) }()

	select {
	case <-ops.waiting:
	case <-time.After(hangGuard):
		t.Fatal("close never reached its wait")
	}

	type abortResult struct {
		err          error
		doneReleased bool
	}
	abortRes := make(chan abortResult, 1)
	go func() {
		err := l.abortNow(ops)
		released := lifeState(l.state.Load()) == lifeClosed
		select {
		case <-l.done:
		default:
			released = false
		}
		abortRes <- abortResult{err, released}
	}()

	select {
	case <-ops.abortiveEntered:
	case <-time.After(hangGuard):
		t.Fatal("the abortive close never started after abortNow")
	}
	// abortive is blocked on the gate, so the descriptor is not released
	// yet and abortNow must still be waiting. Hold the gate a little, so
	// that an abortNow that did not wait for the release would have
	// returned by now.
	select {
	case r := <-abortRes:
		t.Fatalf("abortNow returned %v before the descriptor was released", r.err)
	case <-time.After(50 * time.Millisecond):
	}
	close(gate)

	select {
	case err := <-closeRes:
		if err != nil {
			t.Errorf("close = %v, want nil", err)
		}
	case <-time.After(hangGuard):
		t.Fatal("close did not return after abortNow")
	}
	select {
	case r := <-abortRes:
		if r.err != nil {
			t.Errorf("abortNow = %v, want nil", r.err)
		}
		if !r.doneReleased {
			t.Error("abortNow returned before the lifecycle was closed and done signalled")
		}
	case <-time.After(hangGuard):
		t.Fatal("abortNow did not return after the descriptor was released")
	}

	if elapsed := ops.now().Sub(fakeEpoch); elapsed != 0 {
		t.Errorf("fake clock moved %v; close must return because of the abort, not a timer", elapsed)
	}
	got := ops.counts()
	want := callCounts{gone: 1, shutdown: 1, abortive: 1, release: 0}
	if got != want {
		t.Errorf("calls = %+v, want %+v", got, want)
	}
	wantReleased(t, l)
}

// TestLifecycleClosedAfterRelease carries over v1's
// TestDoubleCloseReturnsNetErrClosed for every way the descriptor can be
// released: afterwards close, abortNow and shutdown all report net.ErrClosed
// and touch nothing, so a descriptor number the process has since reused
// can never be closed or aborted a second time.
func TestLifecycleClosedAfterRelease(t *testing.T) {
	cases := []struct {
		name    string
		gone    func(int) (bool, error)
		release func(l *lifecycle, ops *fakeOps) error
	}{
		{"graceful close", goneAfter(1), func(l *lifecycle, ops *fakeOps) error { return l.close(ops, time.Second) }},
		{"grace expiry", nil, func(l *lifecycle, ops *fakeOps) error { return l.close(ops, time.Second) }},
		{"zero grace", nil, func(l *lifecycle, ops *fakeOps) error { return l.close(ops, 0) }},
		{"abort from open", nil, func(l *lifecycle, ops *fakeOps) error { return l.abortNow(ops) }},
		{"shutdown then close", goneAfter(0), func(l *lifecycle, ops *fakeOps) error {
			if err := l.shutdown(ops); err != nil {
				return err
			}
			return l.close(ops, time.Second)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ops := &fakeOps{fakeClock: newAutoClock(), gone: tc.gone}
			l := newLifecycleForTest()
			if err := tc.release(l, ops); err != nil {
				t.Fatalf("first release = %v, want nil", err)
			}
			wantReleased(t, l)
			before := ops.counts()

			wantClosedErr(t, "second close", l.close(ops, time.Second))
			wantClosedErr(t, "close with zero grace", l.close(ops, 0))
			wantClosedErr(t, "abortNow", l.abortNow(ops))
			wantClosedErr(t, "shutdown", l.shutdown(ops))

			if after := ops.counts(); after != before {
				t.Errorf("calls after release went from %+v to %+v; a released descriptor must not be touched", before, after)
			}
		})
	}
}

// TestLifecycleConcurrentClose races two closes on one lifecycle: exactly one
// proceeds and releases the descriptor, and the other reports
// net.ErrClosed. Meant to be run under -race as well.
func TestLifecycleConcurrentClose(t *testing.T) {
	for round := 0; round < 200; round++ {
		// A peer that answers after a few polls keeps the winner polling
		// while the loser arrives.
		ops := &fakeOps{fakeClock: newAutoClock(), gone: goneAfter(round % 5)}
		l := newLifecycleForTest()

		start := make(chan struct{})
		results := make(chan error, 2)
		for range 2 {
			go func() {
				<-start
				results <- l.close(ops, time.Second)
			}()
		}
		close(start)

		var ok, closed int
		for range 2 {
			err := <-results
			switch {
			case err == nil:
				ok++
			case errors.Is(err, net.ErrClosed):
				closed++
			default:
				t.Fatalf("round %d: close = %v, want nil or net.ErrClosed", round, err)
			}
		}
		if ok != 1 || closed != 1 {
			t.Fatalf("round %d: %d closes succeeded and %d reported net.ErrClosed, want 1 and 1", round, ok, closed)
		}
		c := ops.counts()
		if c.shutdown != 1 || c.release+c.abortive != 1 {
			t.Fatalf("round %d: calls = %+v, want one startShutdown and one release", round, c)
		}
		wantReleased(t, l)
	}
}

// TestLifecycleConcurrentCloseAndAbort carries over v1's
// TestConcurrentCloseAndAbort: eight goroutines race Close against Abort,
// and the descriptor is released exactly once. What each caller sees
// changed from v1, where exactly one call succeeded: now an Abort that
// arrives while a Close is waiting overtakes it, and both return nil. So
// the invariants are that at most one close succeeds, that when none does
// exactly one abort did the release from open, and that every other caller
// reports net.ErrClosed.
func TestLifecycleConcurrentCloseAndAbort(t *testing.T) {
	for round := 0; round < 200; round++ {
		// The peer never answers, so a winning close keeps polling long
		// enough for aborts to find it closing.
		ops := &fakeOps{fakeClock: newAutoClock()}
		l := newLifecycleForTest()

		const racers = 8
		type result struct {
			isClose bool
			err     error
		}
		start := make(chan struct{})
		results := make(chan result, racers)
		for i := range racers {
			go func() {
				<-start
				if i%2 == 0 {
					results <- result{true, l.close(ops, time.Second)}
				} else {
					results <- result{false, l.abortNow(ops)}
				}
			}()
		}
		close(start)

		var closeOK, abortOK int
		for range racers {
			r := <-results
			switch {
			case r.err == nil && r.isClose:
				closeOK++
			case r.err == nil:
				abortOK++
			case !errors.Is(r.err, net.ErrClosed):
				t.Fatalf("round %d: close=%v returned %v, want nil or net.ErrClosed", round, r.isClose, r.err)
			}
		}
		if closeOK > 1 {
			t.Fatalf("round %d: %d closes succeeded; only the one that left the open state may", round, closeOK)
		}
		if closeOK == 0 && abortOK != 1 {
			t.Fatalf("round %d: no close succeeded and %d aborts did, want exactly one abort from open", round, abortOK)
		}
		c := ops.counts()
		if c.release+c.abortive != 1 {
			t.Fatalf("round %d: calls = %+v, want the descriptor released exactly once", round, c)
		}
		if c.shutdown > 1 {
			t.Fatalf("round %d: startShutdown ran %d times, want at most once", round, c.shutdown)
		}
		wantReleased(t, l)
	}
}

// TestLifecycleConcurrentAbortsDuringClose sends many aborts at a close that
// is waiting: the abort channel is closed once and only once (a second
// close of a channel panics), the abortive close runs once, and every abort
// returns nil or net.ErrClosed. The aborts are released together from a
// spin barrier, round after round, so that several of them find the
// lifecycle closing at the same moment.
func TestLifecycleConcurrentAbortsDuringClose(t *testing.T) {
	// One spinning racer per processor but one, which the test itself and
	// the close need; spinning on more would only wait for preemption.
	racers := max(2, runtime.GOMAXPROCS(0)-1)
	for round := 0; round < 200; round++ {
		ops := &fakeOps{fakeClock: newManualClock()}
		l := newLifecycleForTest()

		closeRes := make(chan error, 1)
		go func() { closeRes <- l.close(ops, time.Hour) }()
		select {
		case <-ops.waiting:
		case <-time.After(hangGuard):
			t.Fatalf("round %d: close never reached its wait", round)
		}

		var ready, release atomic.Int32
		aborts := make(chan error, racers)
		for range racers {
			go func() {
				ready.Add(1)
				for release.Load() == 0 {
					if runtime.GOMAXPROCS(0) < 3 {
						runtime.Gosched()
					}
				}
				aborts <- l.abortNow(ops)
			}()
		}
		for ready.Load() != int32(racers) {
			runtime.Gosched()
		}
		release.Store(1)

		for range racers {
			select {
			case err := <-aborts:
				if err != nil && !errors.Is(err, net.ErrClosed) {
					t.Fatalf("round %d: abortNow = %v, want nil or net.ErrClosed", round, err)
				}
			case <-time.After(hangGuard):
				t.Fatalf("round %d: an abortNow never returned", round)
			}
		}
		select {
		case err := <-closeRes:
			if err != nil {
				t.Fatalf("round %d: close = %v, want nil", round, err)
			}
		case <-time.After(hangGuard):
			t.Fatalf("round %d: close did not return", round)
		}
		if c := ops.counts(); c.abortive != 1 || c.release != 0 {
			t.Fatalf("round %d: calls = %+v, want exactly one abortive close", round, c)
		}
		wantReleased(t, l)
	}
}

// TestLifecycleAbortiveCloseIsExclusive covers the two calls that go from
// open straight to the abortive close, abortNow and close with no grace
// period: while that abortive close is still running, a second abortNow or
// close reports net.ErrClosed at once instead of waiting for it, so of two
// racing calls exactly one succeeds, as with v1's Abort.
func TestLifecycleAbortiveCloseIsExclusive(t *testing.T) {
	starts := []struct {
		name string
		run  func(l *lifecycle, ops *fakeOps) error
	}{
		{"abortNow", func(l *lifecycle, ops *fakeOps) error { return l.abortNow(ops) }},
		{"close with zero grace", func(l *lifecycle, ops *fakeOps) error { return l.close(ops, 0) }},
	}
	for _, first := range starts {
		t.Run(first.name, func(t *testing.T) {
			gate := make(chan struct{})
			ops := &fakeOps{
				fakeClock:       newManualClock(),
				abortiveGate:    gate,
				abortiveEntered: make(chan struct{}),
			}
			l := newLifecycleForTest()
			firstRes := make(chan error, 1)
			go func() { firstRes <- first.run(l, ops) }()
			select {
			case <-ops.abortiveEntered:
			case <-time.After(hangGuard):
				t.Fatal("the abortive close never started")
			}

			// The gate is still shut, so a call that waited for the release
			// instead of reporting net.ErrClosed would never return here.
			second := make(chan error, 3)
			go func() {
				second <- l.abortNow(ops)
				second <- l.close(ops, 0)
				second <- l.close(ops, time.Second)
			}()
			for range 3 {
				select {
				case err := <-second:
					wantClosedErr(t, "a call during the abortive close", err)
				case <-time.After(hangGuard):
					t.Fatal("a call during the abortive close waited for it instead of reporting net.ErrClosed")
				}
			}

			close(gate)
			if err := <-firstRes; err != nil {
				t.Errorf("first call = %v, want nil", err)
			}
			if c := ops.counts(); c.abortive != 1 {
				t.Errorf("calls = %+v, want one abortive close", c)
			}
			wantReleased(t, l)
		})
	}
}

// TestLifecycleShutdownOnce pins Shutdown's contract: the first call starts
// the graceful shutdown and reports that call's result, every later call is
// a no-op returning nil (Linux ignores a second SHUTDOWN primitive in every
// shutdown state, net/sctp/sm_statetable.c: TYPE_SCTP_PRIMITIVE_SHUTDOWN
// maps them to sctp_sf_ignore_primitive), a later close starts shutdown
// again and waits, and after close it reports net.ErrClosed.
func TestLifecycleShutdownOnce(t *testing.T) {
	t.Run("twice", func(t *testing.T) {
		ops := &fakeOps{fakeClock: newAutoClock()}
		l := newLifecycleForTest()
		for i := range 2 {
			if err := l.shutdown(ops); err != nil {
				t.Errorf("shutdown %d = %v, want nil", i+1, err)
			}
		}
		if c := ops.counts(); c.shutdown != 1 {
			t.Errorf("startShutdown ran %d times, want once", c.shutdown)
		}
		if got := lifeState(l.state.Load()); got != lifeOpen {
			t.Errorf("state after shutdown = %d, want lifeOpen: Shutdown keeps the connection open", got)
		}
	})
	t.Run("first error is reported once", func(t *testing.T) {
		ops := &fakeOps{fakeClock: newAutoClock(), shutdownErr: syscall.ENOTCONN}
		l := newLifecycleForTest()
		if err := l.shutdown(ops); !errors.Is(err, syscall.ENOTCONN) {
			t.Errorf("first shutdown = %v, want the startShutdown error ENOTCONN", err)
		}
		if err := l.shutdown(ops); err != nil {
			t.Errorf("second shutdown = %v, want nil without another attempt", err)
		}
		if c := ops.counts(); c.shutdown != 1 {
			t.Errorf("startShutdown ran %d times, want once", c.shutdown)
		}
	})
	t.Run("then close starts shutdown again and waits", func(t *testing.T) {
		ops := &fakeOps{fakeClock: newAutoClock(), gone: goneAfter(1)}
		l := newLifecycleForTest()
		if err := l.shutdown(ops); err != nil {
			t.Fatalf("shutdown = %v", err)
		}
		if err := l.close(ops, time.Second); err != nil {
			t.Fatalf("close = %v, want nil", err)
		}
		want := callCounts{gone: 2, shutdown: 2, abortive: 0, release: 1}
		if c := ops.counts(); c != want {
			t.Errorf("calls = %+v, want %+v", c, want)
		}
		wantReleased(t, l)
	})
	t.Run("close after shutdown claimed the start", func(t *testing.T) {
		ops := &fakeOps{fakeClock: newAutoClock(), gone: goneAfter(1)}
		l := newLifecycleForTest()
		l.shut.Store(true) // Shutdown won its CAS but has not called startShutdown.
		if err := l.close(ops, time.Second); err != nil {
			t.Fatalf("close = %v, want nil", err)
		}
		want := callCounts{gone: 2, shutdown: 1, abortive: 0, release: 1}
		if c := ops.counts(); c != want {
			t.Errorf("calls = %+v, want %+v", c, want)
		}
		wantReleased(t, l)
	})
	t.Run("while closing", func(t *testing.T) {
		ops := &fakeOps{fakeClock: newManualClock()}
		l := newLifecycleForTest()
		closeRes := make(chan error, 1)
		go func() { closeRes <- l.close(ops, time.Second) }()
		select {
		case <-ops.waiting:
		case <-time.After(hangGuard):
			t.Fatal("close never reached its wait")
		}
		wantClosedErr(t, "shutdown while closing", l.shutdown(ops))
		ops.advance(time.Second)
		for {
			select {
			case err := <-closeRes:
				if err != nil {
					t.Errorf("close = %v, want nil", err)
				}
				if c := ops.counts(); c.shutdown != 1 {
					t.Errorf("startShutdown ran %d times, want once", c.shutdown)
				}
				return
			case <-ops.waiting:
				ops.advance(time.Second)
			case <-time.After(hangGuard):
				t.Fatal("close did not return after its grace period")
			}
		}
	})
	t.Run("after close", func(t *testing.T) {
		ops := &fakeOps{fakeClock: newAutoClock(), gone: goneAfter(0)}
		l := newLifecycleForTest()
		if err := l.close(ops, time.Second); err != nil {
			t.Fatalf("close = %v", err)
		}
		wantClosedErr(t, "shutdown after close", l.shutdown(ops))
		if c := ops.counts(); c.shutdown != 1 {
			t.Errorf("startShutdown ran %d times, want once (from close only)", c.shutdown)
		}
	})
}

// TestLifecycleCloseNonPositiveGraceAborts carries over v1's
// TestCloseTimeoutZeroIsImmediate: a grace period of zero or less skips
// the graceful shutdown and goes straight to the abortive close, with no
// SHUTDOWN, no poll and no wait.
func TestLifecycleCloseNonPositiveGraceAborts(t *testing.T) {
	for _, grace := range []time.Duration{0, -1, -time.Second, math.MinInt64} {
		ops := &fakeOps{fakeClock: newAutoClock(), gone: goneAfter(0)}
		l := newLifecycleForTest()
		if err := l.close(ops, grace); err != nil {
			t.Errorf("grace %v: close = %v, want nil", grace, err)
		}
		want := callCounts{gone: 0, shutdown: 0, abortive: 1, release: 0}
		if c := ops.counts(); c != want {
			t.Errorf("grace %v: calls = %+v, want %+v", grace, c, want)
		}
		if waits := ops.recordedWaits(); len(waits) != 0 {
			t.Errorf("grace %v: waited %v, want no wait at all", grace, waits)
		}
		wantReleased(t, l)
		wantClosedErr(t, "abortNow after a zero-grace close", l.abortNow(ops))
	}
}

// TestLifecycleCloseSubMicrosecondGrace carries over v1's
// TestCloseSubMicrosecondTimeout. v1 guarded a timeval conversion that
// could round a tiny timeout down to "wait forever"; the wait is now a
// timer, and the equivalent property is that a grace period shorter than
// the first 200 µs backoff step still bounds the wait: the one wait is cut
// to the grace itself and the close ends in the abortive fallback.
func TestLifecycleCloseSubMicrosecondGrace(t *testing.T) {
	for _, grace := range []time.Duration{1, 999, shutdownPollMin - 1} {
		ops := &fakeOps{fakeClock: newAutoClock()}
		l := newLifecycleForTest()
		if err := l.close(ops, grace); err != nil {
			t.Errorf("grace %v: close = %v, want nil", grace, err)
		}
		if waits := ops.recordedWaits(); !slices.Equal(waits, []time.Duration{grace}) {
			t.Errorf("grace %v: waits = %v, want exactly one wait of %v", grace, waits, grace)
		}
		want := callCounts{gone: 2, shutdown: 1, abortive: 1, release: 0}
		if c := ops.counts(); c != want {
			t.Errorf("grace %v: calls = %+v, want %+v", grace, c, want)
		}
		wantReleased(t, l)
	}
}

// TestLifecycleAbortFromOpenDoesNotWait carries over v1's
// TestAbortDoesNotWait: an Abort on an open connection performs no
// handshake, so it neither starts a SHUTDOWN, nor polls, nor waits.
func TestLifecycleAbortFromOpenDoesNotWait(t *testing.T) {
	ops := &fakeOps{fakeClock: newManualClock()}
	l := newLifecycleForTest()
	if err := l.abortNow(ops); err != nil {
		t.Fatalf("abortNow = %v, want nil", err)
	}
	want := callCounts{gone: 0, shutdown: 0, abortive: 1, release: 0}
	if c := ops.counts(); c != want {
		t.Errorf("calls = %+v, want %+v", c, want)
	}
	if waits := ops.recordedWaits(); len(waits) != 0 {
		t.Errorf("abortNow waited %v, want no wait", waits)
	}
	wantReleased(t, l)
}

// TestLifecycleCloseProbeFailureAborts carries over v1's
// TestWaitAssocGoneDoesNotTreatProbeFailureAsCompletion: a status query that
// fails for any reason other than the association being gone is not
// evidence that the shutdown completed. close aborts rather than leave a
// live association behind, and reports the query's error joined with the
// abortive close's.
func TestLifecycleCloseProbeFailureAborts(t *testing.T) {
	errAbortive := errors.New("abortive failed")
	for _, abortiveErr := range []error{nil, errAbortive} {
		ops := &fakeOps{
			fakeClock: newAutoClock(),
			gone: func(n int) (bool, error) {
				if n == 0 {
					return false, nil
				}
				return false, syscall.EIO
			},
			abortiveErr: abortiveErr,
		}
		l := newLifecycleForTest()
		err := l.close(ops, time.Minute)
		if !errors.Is(err, syscall.EIO) {
			t.Errorf("close = %v, want it to report the query's EIO", err)
		}
		if abortiveErr != nil && !errors.Is(err, abortiveErr) {
			t.Errorf("close = %v, want it to report the abortive close's error too", err)
		}
		want := callCounts{gone: 2, shutdown: 1, abortive: 1, release: 0}
		if c := ops.counts(); c != want {
			t.Errorf("calls = %+v, want %+v: the failed query must not count as completion", c, want)
		}
		wantReleased(t, l)
	}
}

// TestLifecycleCloseStartShutdownErrorStillWaits pins how close reads a
// failed startShutdown: the one non-blocking call can only fail because the
// association is already gone or already shutting down, so close does not
// abort on it; the poll decides.
func TestLifecycleCloseStartShutdownErrorStillWaits(t *testing.T) {
	ops := &fakeOps{fakeClock: newAutoClock(), gone: goneAfter(1), shutdownErr: syscall.EPIPE}
	l := newLifecycleForTest()
	if err := l.close(ops, time.Second); err != nil {
		t.Fatalf("close = %v, want nil: a failed startShutdown is not a close failure", err)
	}
	want := callCounts{gone: 2, shutdown: 1, abortive: 0, release: 1}
	if c := ops.counts(); c != want {
		t.Errorf("calls = %+v, want %+v", c, want)
	}
	wantReleased(t, l)
}

// TestLifecycleReportsReleaseErrors pins which error each path returns: the
// release's on a graceful close, the abortive close's on every abortive
// path. Timing out and being overtaken by Abort are outcomes, not errors,
// so with steps that succeed every path returns nil (checked above).
func TestLifecycleReportsReleaseErrors(t *testing.T) {
	errRelease := errors.New("release failed")
	errAbortive := errors.New("abortive failed")
	cases := []struct {
		name string
		gone func(int) (bool, error)
		run  func(l *lifecycle, ops *fakeOps) error
		want error
	}{
		{"graceful", goneAfter(0), func(l *lifecycle, ops *fakeOps) error { return l.close(ops, time.Second) }, errRelease},
		{"grace expiry", nil, func(l *lifecycle, ops *fakeOps) error { return l.close(ops, time.Second) }, errAbortive},
		{"zero grace", nil, func(l *lifecycle, ops *fakeOps) error { return l.close(ops, 0) }, errAbortive},
		{"abort from open", nil, func(l *lifecycle, ops *fakeOps) error { return l.abortNow(ops) }, errAbortive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ops := &fakeOps{fakeClock: newAutoClock(), gone: tc.gone, releaseErr: errRelease, abortiveErr: errAbortive}
			l := newLifecycleForTest()
			if err := tc.run(l, ops); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
			wantReleased(t, l)
		})
	}
}

// TestLifecycleZeroValueReportsClosed covers a lifecycle that was never
// initialised, which is what a zero Conn holds: every call reports
// net.ErrClosed and none reaches a system call, so a Conn the package never
// opened can never close or abort some other descriptor.
func TestLifecycleZeroValueReportsClosed(t *testing.T) {
	var c Conn
	ops := &fakeOps{fakeClock: newAutoClock()}
	wantClosedErr(t, "close", c.life.close(ops, time.Second))
	wantClosedErr(t, "close with zero grace", c.life.close(ops, 0))
	wantClosedErr(t, "abortNow", c.life.abortNow(ops))
	wantClosedErr(t, "shutdown", c.life.shutdown(ops))
	if got := ops.counts(); got != (callCounts{}) {
		t.Errorf("calls = %+v, want none", got)
	}
}

// TestLifecycleClosedErrorWrapsOnce pins the hand-off between the lifecycle
// and the methods that call it: the lifecycle reports a closed connection
// as the bare net.ErrClosed, and the calling method adds the connection's
// own context with opError, which yields exactly one *net.OpError around
// it, never a nested one.
func TestLifecycleClosedErrorWrapsOnce(t *testing.T) {
	ops := &fakeOps{fakeClock: newAutoClock()}
	l := newLifecycleForTest()
	if err := l.abortNow(ops); err != nil {
		t.Fatalf("abortNow = %v", err)
	}
	laddr := &Addr{Port: 1}
	raddr := &Addr{Port: 2}
	err := opError("close", "sctp4", laddr, raddr, l.close(ops, time.Second))
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Fatalf("err = %#v, want a *net.OpError", err)
	}
	if opErr.Op != "close" || opErr.Net != "sctp4" || opErr.Source != laddr || opErr.Addr != raddr {
		t.Errorf("OpError = %+v, want Op close, Net sctp4 and the connection's addresses", opErr)
	}
	if opErr.Err != net.ErrClosed {
		t.Errorf("OpError.Err = %#v, want net.ErrClosed itself, not wrapped again", opErr.Err)
	}
}

// TestConnKindZeroIsNoKind pins what connKind's doc promises: the zero
// value, which a zero Conn holds, is none of the four kinds a real
// connection has, and the four are distinct.
func TestConnKindZeroIsNoKind(t *testing.T) {
	var zero Conn
	seen := map[connKind]bool{zero.kind: true}
	for _, k := range []connKind{kindDialed, kindAccepted, kindPeeled, kindAdopted} {
		if seen[k] {
			t.Errorf("connKind %d is the zero value or repeats another kind", k)
		}
		seen[k] = true
	}
}

// TestCloseClockReusesOneTimer pins the production time source: now is the
// current time, and the wait uses one timer, made on the first step and
// reset for each later one, which fires every time.
func TestCloseClockReusesOneTimer(t *testing.T) {
	var c closeClock

	before := time.Now()
	now := c.now()
	if now.Before(before) || now.After(time.Now()) {
		t.Errorf("now = %v, want the current time", now)
	}

	first := c.after(time.Microsecond)
	select {
	case <-first:
	case <-time.After(hangGuard):
		t.Fatal("the first wait never fired")
	}
	second := c.after(time.Microsecond)
	if second != first {
		t.Error("after returned a new channel; the timer must be reused, not recreated")
	}
	select {
	case <-second:
	case <-time.After(hangGuard):
		t.Fatal("the reset timer never fired")
	}
}

// TestCloseClockAllocatesNothingPerStep pins the allocation half of the
// same contract: once the timer exists, a backoff step allocates nothing.
// The garbage collector is paused so a collection cannot be counted
// against it, and the test is skipped under the race detector, whose own
// instrumentation allocates.
func TestCloseClockAllocatesNothingPerStep(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector")
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	var c closeClock
	c.after(time.Hour)
	allocs := testing.AllocsPerRun(100, func() { c.after(time.Hour) })
	if allocs != 0 {
		t.Errorf("after allocated %.1f times per step, want 0", allocs)
	}
}

// FuzzLifecycleClose carries over v1's FuzzCloseWithTimeout. It varies the
// grace period (including the zero and negative values that select the
// abortive path and the sub-microsecond ones), what each status poll
// answers, whether and when an Abort arrives during the wait, and which
// steps fail. The invariants: close always returns, the descriptor is
// released exactly once by exactly one of release or abortive, the waits
// follow the backoff schedule and never exceed the grace period, the error
// reflects what failed, and every later call reports net.ErrClosed.
//
// Each byte of script answers one poll: 0 or 1 still there, 2 gone, 3 a
// failed query. Polls beyond the script find the association still there.
// abortAt, when not zero, sends an Abort during the abortAt-th wait. The
// low bits of failures make startShutdown, abortive and release fail.
func FuzzLifecycleClose(f *testing.F) {
	for _, ns := range []int64{0, -1, 1, 999, int64(time.Millisecond), int64(3 * time.Second), int64(time.Hour), math.MinInt64, math.MaxInt64} {
		f.Add(ns, []byte{0, 0, 2}, uint8(0), uint8(0))
		f.Add(ns, []byte{}, uint8(0), uint8(0))
	}
	f.Add(int64(3*time.Second), []byte{0, 1, 3}, uint8(0), uint8(0))
	f.Add(int64(3*time.Second), []byte{0, 0, 0, 0}, uint8(3), uint8(0))
	f.Add(int64(3*time.Second), []byte{0, 2}, uint8(1), uint8(7))
	f.Add(int64(time.Second), []byte{}, uint8(200), uint8(6))

	errShutdown := errors.New("startShutdown failed")
	errAbortive := errors.New("abortive failed")
	errRelease := errors.New("release failed")

	f.Fuzz(func(t *testing.T, ns int64, script []byte, abortAt uint8, failures uint8) {
		// The fake clock makes a long grace period cost nothing but loop
		// iterations; a minute is some three thousand of them.
		grace := min(time.Duration(ns), time.Minute)

		l := newLifecycleForTest()
		ops := &fakeOps{fakeClock: newAutoClock()}
		ops.gone = func(n int) (bool, error) {
			if n >= len(script) {
				return false, nil
			}
			switch script[n] % 4 {
			case 2:
				return true, nil
			case 3:
				return false, syscall.EIO
			default:
				return false, nil
			}
		}
		if failures&1 != 0 {
			ops.shutdownErr = errShutdown
		}
		if failures&2 != 0 {
			ops.abortiveErr = errAbortive
		}
		if failures&4 != 0 {
			ops.releaseErr = errRelease
		}

		abortRes := make(chan error, 1)
		aborted := false
		if abortAt != 0 {
			ops.hook = func(n int) bool {
				if n != int(abortAt)-1 {
					return false
				}
				aborted = true
				go func() { abortRes <- l.abortNow(ops) }()
				// Park this wait for good, and hold it until the abort has
				// been requested, so the abort is what ends it.
				for lifeState(l.state.Load()) != lifeAborting {
					runtime.Gosched()
				}
				return true
			}
		}

		closeRes := make(chan error, 1)
		go func() { closeRes <- l.close(ops, grace) }()
		var err error
		guard := time.NewTimer(hangGuard)
		select {
		case err = <-closeRes:
			guard.Stop()
		case <-guard.C:
			t.Fatalf("grace %v: close never returned", grace)
		}

		c := ops.counts()
		waits := ops.recordedWaits()
		if c.release+c.abortive != 1 {
			t.Fatalf("grace %v: calls = %+v, want the descriptor released exactly once", grace, c)
		}
		wantReleased(t, l)

		if grace <= 0 {
			want := callCounts{abortive: 1}
			if c != want || len(waits) != 0 {
				t.Fatalf("grace %v: calls = %+v, waits %v, want only the abortive close", grace, c, waits)
			}
			if (failures&2 != 0) != (err != nil) || (err != nil && !errors.Is(err, errAbortive)) {
				t.Fatalf("grace %v: close = %v, want the abortive close's result", grace, err)
			}
		} else {
			if c.shutdown != 1 {
				t.Fatalf("grace %v: startShutdown ran %d times, want once", grace, c.shutdown)
			}
			// The waits follow the backoff schedule, each one cut to what
			// is left of the grace period.
			step := shutdownPollMin
			var spent time.Duration
			for i, w := range waits {
				if want := min(step, grace-spent); w != want {
					t.Fatalf("grace %v: wait %d = %v, want %v (waits %v)", grace, i, w, want, waits)
				}
				spent += w
				step = min(step*2, shutdownPollMax)
			}
			if spent > grace {
				t.Fatalf("grace %v: waited %v in total, beyond the grace period", grace, spent)
			}

			ops.mu.Lock()
			results := append([]goneResult(nil), ops.goneResults...)
			ops.mu.Unlock()
			if len(results) == 0 {
				t.Fatalf("grace %v: close never polled the association", grace)
			}
			last := results[len(results)-1]
			switch {
			case last.err != nil:
				if !errors.Is(err, syscall.EIO) || c.abortive != 1 {
					t.Fatalf("grace %v: after a failed poll close = %v with calls %+v, want EIO and the abortive close", grace, err, c)
				}
			case last.gone:
				if c.release != 1 {
					t.Fatalf("grace %v: association gone but calls = %+v, want a plain release", grace, c)
				}
				if (failures&4 != 0) != (err != nil) || (err != nil && !errors.Is(err, errRelease)) {
					t.Fatalf("grace %v: close = %v, want the release's result", grace, err)
				}
			default:
				// Still there at the last poll: the grace period ran out,
				// or an abort overtook the wait.
				if c.abortive != 1 {
					t.Fatalf("grace %v: calls = %+v, want the abortive fallback", grace, c)
				}
				if !aborted && spent != grace {
					t.Fatalf("grace %v: fell back after waiting %v without an abort, want the whole grace period", grace, spent)
				}
				if (failures&2 != 0) != (err != nil) || (err != nil && !errors.Is(err, errAbortive)) {
					t.Fatalf("grace %v: close = %v, want the abortive close's result", grace, err)
				}
			}
			if !aborted && len(results) != len(waits)+1 {
				t.Fatalf("grace %v: %d polls for %d waits, want one poll before each wait and one after the last", grace, len(results), len(waits))
			}
			if aborted && len(results) != len(waits) {
				t.Fatalf("grace %v: %d polls for %d waits, want no poll after the wait the abort ended", grace, len(results), len(waits))
			}
			if errors.Is(err, errShutdown) {
				t.Fatalf("grace %v: close = %v; a failed startShutdown is not a close failure", grace, err)
			}
		}

		if aborted {
			select {
			case aerr := <-abortRes:
				if aerr != nil {
					t.Fatalf("abortNow during the wait = %v, want nil", aerr)
				}
			case <-time.After(hangGuard):
				t.Fatal("abortNow never returned")
			}
		}

		before := ops.counts()
		wantClosedErr(t, "close after release", l.close(ops, grace))
		wantClosedErr(t, "abortNow after release", l.abortNow(ops))
		wantClosedErr(t, "shutdown after release", l.shutdown(ops))
		if after := ops.counts(); after != before {
			t.Fatalf("calls after release went from %+v to %+v", before, after)
		}
	})
}
