// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestNoWaitQueuesBehindExistingWriter is issue #29's socket-free
// reproducer. SendMsg keeps its existing lock wait, including with NoWait.
func TestNoWaitQueuesBehindExistingWriter(t *testing.T) {
	parked, space := make(chan struct{}), make(chan struct{})
	raw := &fakeRawConn{parkWrite: func() error { close(parked); <-space; return nil }}
	c := fakeConn(raw, nil)
	var calls atomic.Int32
	hookSendmsg(t, func(_ int, msg *syscall.Msghdr, _ int) (int, error) {
		if calls.Add(1) == 1 {
			return 0, syscall.EAGAIN
		}
		return int(msg.Iov.Len), nil
	})
	first, second := make(chan error, 1), make(chan error, 1)
	go func() { _, err := c.SendMsg([]byte{1}, SendOptions{}); first <- err }()
	<-parked
	entered := make(chan struct{})
	go func() { close(entered); _, err := c.SendMsg([]byte{2}, SendOptions{NoWait: true}); second <- err }()
	<-entered
	early := false
	var earlyErr error
	select {
	case earlyErr = <-second:
		early = true
	case <-time.After(50 * time.Millisecond):
	}
	before := calls.Load()
	close(space)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if !early {
		if err := <-second; err != nil {
			t.Fatal(err)
		}
	}
	if early || before != 1 {
		t.Fatalf("NoWait bypassed parked writer: returned=%v (err %v) calls=%d", early, earlyErr, before)
	}
	if calls.Load() != 3 {
		t.Fatalf("send calls=%d, want 3", calls.Load())
	}
	t.Log("NoWait DATA was blocked by send lock until existing writer resumed")
}

// contextSender exercises the same assertions on both public send paths.
type contextSender struct {
	send          func(context.Context, []byte, SendOptions) (int, error)
	ordinary      func([]byte, SendOptions) (int, error)
	raw           syscall.RawConn
	state         *sendState
	deadline      func(time.Time) error
	bothDeadlines func(time.Time) error
}

func fakeContextSender(t *testing.T, endpoint bool, raw *fakeRawConn) contextSender {
	t.Helper()
	// A pipe supplies a pollable file for deadline setters; no SCTP socket
	// is opened, and raw's callbacks still use only the sendmsg hook.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	c := fakeConn(raw, nil)
	c.sock.file = r
	c.send.writeDeadline = r.SetWriteDeadline
	if !endpoint {
		return contextSender{send: c.SendMsgContext, ordinary: c.SendMsg, raw: &connRawConn{c}, state: &c.send, deadline: c.SetWriteDeadline, bothDeadlines: c.SetDeadline}
	}
	e := &Endpoint{sock: c.sock}
	e.life.init()
	e.send.bind(nil)
	e.send.explicit = true
	e.send.writeDeadline = r.SetWriteDeadline
	return contextSender{send: func(ctx context.Context, b []byte, opts SendOptions) (int, error) {
		return e.SendMsgContext(ctx, 7, b, opts)
	}, ordinary: func(b []byte, opts SendOptions) (int, error) { return e.SendMsg(7, b, opts) }, raw: &endpointRawConn{e}, state: &e.send, deadline: e.SetWriteDeadline, bothDeadlines: e.SetDeadline}
}

func contextResult(t *testing.T, done <-chan error, cause error) {
	t.Helper()
	select {
	case err := <-done:
		wantOp(t, "SendMsgContext", "write", err, cause)
		if errors.Is(err, os.ErrDeadlineExceeded) && cause != os.ErrDeadlineExceeded {
			t.Fatalf("context interruption also matches os.ErrDeadlineExceeded: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SendMsgContext did not return within one second")
	}
}

// observedDone reports that acquisition reached its cancellable select.
// Its Context supplies cancellation and Err without changing their meaning.
type observedDone struct {
	context.Context
	entered chan struct{}
	once    sync.Once
}

func (c *observedDone) Done() <-chan struct{} {
	c.once.Do(func() { close(c.entered) })
	return c.Context.Done()
}

func TestSendMsgContextLockCancellation(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		for _, noWait := range []bool{false, true} {
			t.Run(contextCaseName(endpoint, noWait), func(t *testing.T) {
				parked, space := make(chan struct{}), make(chan struct{})
				raw := &fakeRawConn{parkWrite: func() error { close(parked); <-space; return nil }}
				c := fakeContextSender(t, endpoint, raw)
				var payloads []byte
				hookSendmsg(t, func(_ int, msg *syscall.Msghdr, _ int) (int, error) {
					payloads = append(payloads, iovBytes(msg)[0])
					if len(payloads) == 1 {
						return 0, syscall.EAGAIN
					}
					return int(msg.Iov.Len), nil
				})
				first := make(chan error, 1)
				go func() { _, err := c.send(context.Background(), []byte{1}, SendOptions{}); first <- err }()
				<-parked
				ctx, cancel := context.WithCancel(context.Background())
				waiting := &observedDone{Context: ctx, entered: make(chan struct{})}
				done := make(chan error, 1)
				go func() { _, err := c.send(waiting, []byte{2}, SendOptions{NoWait: noWait}); done <- err }()
				// The first writer owns the lock when Done is observed.
				select {
				case <-waiting.entered:
				case <-time.After(time.Second):
					cancel()
					close(space)
					t.Fatalf("lock acquisition did not observe the context (first send: %v)", <-first)
				}
				cancel()
				contextResult(t, done, context.Canceled)
				close(space)
				if err := <-first; err != nil {
					t.Fatal(err)
				}
				if string(payloads) != "\x01\x01" {
					t.Fatalf("sendmsg payloads = %v", payloads)
				}
			})
		}
	}
}

func contextCaseName(endpoint, noWait bool) string {
	name := "Conn"
	if endpoint {
		name = "Endpoint"
	}
	if noWait {
		name += "/NoWait"
	} else {
		name += "/wait"
	}
	return name
}

func TestSendMsgContextDoneAtEntry(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		t.Run(contextCaseName(endpoint, false), func(t *testing.T) {
			c := fakeContextSender(t, endpoint, &fakeRawConn{})
			hookSendmsg(t, func(int, *syscall.Msghdr, int) (int, error) { t.Error("sendmsg called"); return 0, nil })
			ctx, cancel := context.WithDeadline(context.Background(), aLongTimeAgo)
			defer cancel()
			c.state.mu.Lock()
			defer c.state.mu.Unlock()
			done := make(chan error, 1)
			go func() { _, err := c.send(ctx, []byte{1}, SendOptions{}); done <- err }()
			contextResult(t, done, context.DeadlineExceeded)
			// Entry cancellation also wins over argument validation.
			n, err := c.send(ctx, nil, SendOptions{})
			wantOp(t, "done context and empty payload", "write", err, context.DeadlineExceeded)
			if n != 0 {
				t.Errorf("done context returned %d bytes", n)
			}
		})
	}
}

// TestSendMsgContextNilContext pins the refusal before validation, lock
// acquisition or a system call, including on a nil receiver.
func TestSendMsgContextNilContext(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		t.Run(contextCaseName(endpoint, false), func(t *testing.T) {
			c := fakeContextSender(t, endpoint, &fakeRawConn{})
			hookSendmsg(t, func(int, *syscall.Msghdr, int) (int, error) {
				t.Error("nil context reached sendmsg")
				return 0, nil
			})
			c.state.mu.Lock()
			defer c.state.mu.Unlock()
			n, err := c.send(nil, nil, SendOptions{})
			wantOp(t, "nil context", "write", err, syscall.EINVAL)
			if n != 0 {
				t.Errorf("nil context returned %d bytes", n)
			}
			var conn *Conn
			var e *Endpoint
			nilReceiver := contextSender{send: conn.SendMsgContext}
			if endpoint {
				nilReceiver.send = func(ctx context.Context, b []byte, opts SendOptions) (int, error) {
					return e.SendMsgContext(ctx, 0, b, opts)
				}
			}
			n, err = nilReceiver.send(nil, nil, SendOptions{})
			wantOp(t, "nil context and receiver", "write", err, syscall.EINVAL)
			if n != 0 {
				t.Errorf("nil context and receiver returned %d bytes", n)
			}
		})
	}
}

// TestSendMsgContextDeadlineAttribution pins a write deadline that ended
// the buffer wait before cancellation, even when interrupt runs between
// raw.Write returning and send stopping its callback, and the caller has
// renewed the deadline in between.
func TestSendMsgContextDeadlineAttribution(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		for _, tc := range []struct {
			name              string
			deadlineFirst     bool
			noDeadline        bool
			renew             string
			replaceDuringWait bool
			replaceBeforeSend bool
		}{
			{name: "deadline then context", deadlineFirst: true},
			{name: "context first"},
			{name: "context first without deadline", noDeadline: true},
			{name: "deadline then clear", deadlineFirst: true, renew: "clear"},
			{name: "deadline then extend", deadlineFirst: true, renew: "extend"},
			{name: "deadline then SetDeadline", deadlineFirst: true, renew: "SetDeadline"},
			{name: "context first then clear", renew: "clear"},
			{name: "context first then extend", renew: "extend"},
			{name: "context first then SetDeadline", renew: "SetDeadline"},
			{name: "deadline replaced during wait", deadlineFirst: true, replaceDuringWait: true},
			{name: "deadline replaced before send", replaceBeforeSend: true},
		} {
			t.Run(contextCaseName(endpoint, false)+"/"+tc.name, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				interrupted := make(chan struct{})
				previousInterrupt, previousWriteReturn := testHookSendInterrupt, testHookSendWriteReturn
				testHookSendInterrupt = func() { close(interrupted) }
				t.Cleanup(func() {
					testHookSendInterrupt, testHookSendWriteReturn = previousInterrupt, previousWriteReturn
				})
				cancelAndWait := func() {
					cancel()
					select {
					case <-interrupted:
					case <-time.After(time.Second):
						t.Fatal("interrupt did not run")
					}
				}
				raw := &fakeRawConn{}
				c := fakeContextSender(t, endpoint, raw)
				var applied time.Time
				writeDeadline := c.state.writeDeadline
				c.state.writeDeadline = func(d time.Time) error {
					applied = d
					return writeDeadline(d)
				}
				deadline := time.Now().Add(time.Hour)
				wantDeadline := deadline
				if tc.deadlineFirst && !tc.replaceDuringWait {
					deadline = aLongTimeAgo
					wantDeadline = deadline
				} else if tc.noDeadline {
					deadline = time.Time{}
					wantDeadline = deadline
				}
				setDeadline := func(set func(time.Time) error, d time.Time) {
					if err := set(d); err != nil {
						t.Fatal(err)
					}
				}
				if tc.replaceBeforeSend {
					setDeadline(c.deadline, aLongTimeAgo)
				}
				if err := c.deadline(deadline); err != nil {
					t.Fatal(err)
				}
				raw.parkWrite = func() error {
					if tc.replaceDuringWait {
						setDeadline(c.deadline, aLongTimeAgo)
						setDeadline(c.deadline, wantDeadline)
					}
					if !tc.deadlineFirst || tc.replaceDuringWait {
						cancelAndWait()
					}
					// internal/poll/fd_unix.go: FD.RawWrite returns a failed
					// waitWrite without calling the attempt again.
					return os.ErrDeadlineExceeded
				}
				testHookSendWriteReturn = func() {
					if tc.renew != "" {
						set := c.deadline
						wantDeadline = time.Now().Add(time.Hour)
						switch tc.renew {
						case "clear":
							wantDeadline = time.Time{}
						case "SetDeadline":
							set = c.bothDeadlines
						}
						setDeadline(set, wantDeadline)
					}
					if tc.deadlineFirst && !tc.replaceDuringWait {
						cancelAndWait()
					}
				}
				calls := 0
				hookSendmsg(t, func(int, *syscall.Msghdr, int) (int, error) {
					calls++
					return 0, syscall.EAGAIN
				})
				n, err := c.send(ctx, []byte{1}, SendOptions{})
				want, other := error(context.Canceled), error(os.ErrDeadlineExceeded)
				if tc.deadlineFirst {
					want, other = other, want
				}
				wantOp(t, "SendMsgContext", "write", err, want)
				if n != 0 || errors.Is(err, other) {
					t.Errorf("send = %d, %v; want only %v", n, err, want)
				}
				if calls != 1 {
					t.Errorf("sendmsg calls = %d, want 1", calls)
				}
				if !applied.Equal(wantDeadline) {
					t.Errorf("restored write deadline = %v, want %v", applied, wantDeadline)
				}
			})
		}
	}
}

func TestSendMsgContextAcceptanceWins(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		t.Run(contextCaseName(endpoint, false), func(t *testing.T) {
			c := fakeContextSender(t, endpoint, &fakeRawConn{})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hookSendmsg(t, func(_ int, msg *syscall.Msghdr, _ int) (int, error) { cancel(); return int(msg.Iov.Len), nil })
			if n, err := c.send(ctx, []byte{1}, SendOptions{}); n != 1 || err != nil {
				t.Fatalf("send = %d, %v", n, err)
			}
		})
	}
}

// cancelOnDone makes cancellation and an available lock ready in the same
// select. Both choices must queue nothing: acquiring the lock requires a
// second context check. Its embedded Context still supplies the real Err.
type cancelOnDone struct {
	context.Context
	cancel context.CancelFunc
	unlock func()
}

func (c cancelOnDone) Done() <-chan struct{} {
	c.cancel()
	c.unlock()
	return c.Context.Done()
}

func TestSendMsgContextCanceledAtAcquisition(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		t.Run(contextCaseName(endpoint, false), func(t *testing.T) {
			c := fakeContextSender(t, endpoint, &fakeRawConn{})
			var calls int
			hookSendmsg(t, func(_ int, msg *syscall.Msghdr, _ int) (int, error) { calls++; return int(msg.Iov.Len), nil })
			for range 128 {
				ctx, cancel := context.WithCancel(context.Background())
				c.state.mu.Lock()
				n, err := c.send(cancelOnDone{ctx, cancel, c.state.mu.Unlock}, []byte{1}, SendOptions{})
				cancel()
				if n != 0 || !errors.Is(err, context.Canceled) {
					t.Fatalf("send = %d, %v; want 0, context.Canceled", n, err)
				}
			}
			if calls != 0 {
				t.Errorf("sendmsg calls = %d, want 0", calls)
			}
		})
	}
}

// TestSendMsgContextRestoreDeadline holds interrupt after it has moved the
// deadline. RawWrite is allowed to return, but the send must join interrupt
// before restoring the latest caller value or allowing another writer.
func TestSendMsgContextRestoreDeadline(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		for _, mode := range []string{"zero", "future", "changed", "SetDeadline"} {
			t.Run(contextCaseName(endpoint, false)+"/"+mode, func(t *testing.T) {
				parked, expired, moved, finish := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
				var once sync.Once
				raw := &fakeRawConn{parkWrite: func() error { close(parked); <-expired; return os.ErrDeadlineExceeded }}
				c := fakeContextSender(t, endpoint, raw)
				var mu sync.Mutex
				var applied time.Time
				c.state.writeDeadline = func(d time.Time) error {
					mu.Lock()
					applied = d
					mu.Unlock()
					if d.Equal(aLongTimeAgo) {
						once.Do(func() { close(expired) })
					}
					return senderFile(c).SetWriteDeadline(d)
				}
				want := time.Time{}
				if mode == "future" {
					want = time.Now().Add(time.Hour)
				}
				if err := c.deadline(want); err != nil {
					t.Fatal(err)
				}
				testHookSendInterrupt = func() { close(moved); <-finish }
				t.Cleanup(func() { testHookSendInterrupt = nil })
				var calls atomic.Int32
				hookSendmsg(t, func(int, *syscall.Msghdr, int) (int, error) { calls.Add(1); return 0, syscall.EAGAIN })
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				done := make(chan error, 1)
				go func() { _, err := c.send(ctx, []byte{1}, SendOptions{}); done <- err }()
				<-parked
				cancel()
				<-moved
				if mode == "changed" || mode == "SetDeadline" {
					want = time.Now().Add(2 * time.Hour)
					set := c.deadline
					if mode == "SetDeadline" {
						set = c.bothDeadlines
					}
					if err := set(want); err != nil {
						t.Fatal(err)
					}
				}
				mu.Lock()
				got := applied
				mu.Unlock()
				if got != aLongTimeAgo {
					t.Errorf("deadline reset before RawWrite and interrupt returned: %v", got)
				}
				select {
				case err := <-done:
					t.Errorf("returned before interrupt finished: %v", err)
				case <-time.After(30 * time.Millisecond):
				}
				close(finish)
				contextResult(t, done, context.Canceled)
				mu.Lock()
				got = applied
				mu.Unlock()
				if got != want {
					t.Errorf("restored %v, want latest caller deadline %v", got, want)
				}
				// Probe the file's actual poller deadline as well as the
				// recorded setter value: zero and future allow a callback.
				fileRaw, err := senderFile(c).SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				if err := fileRaw.Write(func(uintptr) bool { return true }); err != nil {
					t.Errorf("restored poller deadline refused a raw Write: %v", err)
				}
				if calls.Load() != 1 {
					t.Errorf("sendmsg calls = %d, want 1", calls.Load())
				}
			})
		}
	}
}

func TestSendMsgContextRawWriteSerialization(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		t.Run(contextCaseName(endpoint, false), func(t *testing.T) {
			parked, space := make(chan struct{}), make(chan struct{})
			raw := &fakeRawConn{parkWrite: func() error { close(parked); <-space; return nil }}
			c := fakeContextSender(t, endpoint, raw)
			var calls atomic.Int32
			hookSendmsg(t, func(_ int, msg *syscall.Msghdr, _ int) (int, error) {
				if calls.Add(1) == 1 {
					return 0, syscall.EAGAIN
				}
				return int(msg.Iov.Len), nil
			})
			first := make(chan error, 1)
			go func() { _, err := c.send(context.Background(), []byte{1}, SendOptions{}); first <- err }()
			<-parked
			entered, release := make(chan struct{}), make(chan struct{})
			rawDone := make(chan error, 1)
			go func() { rawDone <- c.raw.Write(func(uintptr) bool { close(entered); <-release; return true }) }()
			select {
			case <-entered:
				t.Error("raw Write entered behind parked send")
			case <-time.After(30 * time.Millisecond):
			}
			close(space)
			if err := <-first; err != nil {
				t.Fatal(err)
			}
			<-entered
			ctx, cancel := context.WithCancel(context.Background())
			waiting := &observedDone{Context: ctx, entered: make(chan struct{})}
			done := make(chan error, 1)
			go func() { _, err := c.send(waiting, []byte{2}, SendOptions{}); done <- err }()
			select {
			case <-waiting.entered:
			case <-time.After(time.Second):
				cancel()
				close(release)
				t.Fatalf("lock acquisition behind raw Write did not observe the context (raw Write: %v)", <-rawDone)
			}
			cancel()
			contextResult(t, done, context.Canceled)
			close(release)
			if err := <-rawDone; err != nil {
				t.Fatal(err)
			}
			if calls.Load() != 2 {
				t.Fatalf("sendmsg calls = %d, want 2", calls.Load())
			}
		})
	}
}

func TestSendMsgContextZeroAllocs(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector")
	}
	for _, endpoint := range []bool{false, true} {
		t.Run(contextCaseName(endpoint, false), func(t *testing.T) {
			c := fakeContextSender(t, endpoint, &fakeRawConn{})
			hookSendmsg(t, func(_ int, msg *syscall.Msghdr, _ int) (int, error) { return int(msg.Iov.Len), nil })
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			b := []byte{1}
			for _, ctx := range []context.Context{context.Background(), ctx} {
				var failed error
				allocs := testing.AllocsPerRun(1000, func() { _, failed = c.send(ctx, b, SendOptions{}) })
				if failed != nil {
					t.Fatal(failed)
				}
				if allocs != 0 {
					t.Errorf("AllocsPerRun = %v, want 0", allocs)
				}
			}
		})
	}
}

// TestSendMsgContextFreshContextZeroAllocs compares creating a context
// alone with creating it and sending. A new context is used in every
// iteration, including AllocsPerRun's warm-up, so cancelCtx.Done's lazy
// channel (context/context.go: cancelCtx.Done) cannot be warmed away.
func TestSendMsgContextFreshContextZeroAllocs(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector")
	}
	for _, endpoint := range []bool{false, true} {
		t.Run(contextCaseName(endpoint, false), func(t *testing.T) {
			c := fakeContextSender(t, endpoint, &fakeRawConn{})
			hookSendmsg(t, func(_ int, msg *syscall.Msghdr, _ int) (int, error) { return int(msg.Iov.Len), nil })
			payload := []byte{1}
			for name, makeContext := range map[string]func() (context.Context, context.CancelFunc){
				"WithCancel": func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) },
				"WithTimeout": func() (context.Context, context.CancelFunc) {
					return context.WithTimeout(context.Background(), time.Hour)
				},
			} {
				t.Run(name, func(t *testing.T) {
					baseline := testing.AllocsPerRun(1000, func() { _, cancel := makeContext(); cancel() })
					for _, noWait := range []bool{false, true} {
						var failed error
						actual := testing.AllocsPerRun(1000, func() {
							ctx, cancel := makeContext()
							_, failed = c.send(ctx, payload, SendOptions{NoWait: noWait})
							cancel()
						})
						if failed != nil {
							t.Fatal(failed)
						}
						if actual != baseline {
							t.Errorf("NoWait %v: context and send allocated %v, context alone %v; want zero added by send", noWait, actual, baseline)
						}
					}
				})
			}
		})
	}
}

func TestSendContextDeadlineErrorsKeepAddresses(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		t.Run(contextCaseName(endpoint, false), func(t *testing.T) {
			c := fakeContextSender(t, endpoint, &fakeRawConn{})
			addr := loopback4(4242)
			setters := []func(time.Time) error{c.deadline, c.bothDeadlines}
			if raw, ok := c.raw.(*connRawConn); ok {
				raw.c.laddr.Store(addr)
				raw.c.life.state.Store(int32(lifeClosed))
				setters = append(setters, raw.c.SetReadDeadline)
			} else {
				raw := c.raw.(*endpointRawConn)
				raw.e.addr.Store(addr)
				raw.e.life.state.Store(int32(lifeClosed))
				setters = append(setters, raw.e.SetReadDeadline)
			}
			if err := senderFile(c).Close(); err != nil {
				t.Fatal(err)
			}
			for _, set := range setters {
				err := set(time.Time{})
				wantOp(t, "deadline after Close", "set", err, net.ErrClosed)
				var op *net.OpError
				if !errors.As(err, &op) || op.Addr == nil || op.Addr.String() != addr.String() {
					t.Errorf("deadline error lost local address: %v", err)
				}
			}
		})
	}
}

func senderFile(c contextSender) *os.File {
	if raw, ok := c.raw.(*connRawConn); ok {
		return raw.c.sock.file
	}
	return c.raw.(*endpointRawConn).e.sock.file
}

func TestSendMsgContextReadDeadline(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		t.Run(contextCaseName(endpoint, false), func(t *testing.T) {
			parked, expired := make(chan struct{}), make(chan struct{})
			c := fakeContextSender(t, endpoint, &fakeRawConn{parkWrite: func() error { close(parked); <-expired; return os.ErrDeadlineExceeded }})
			file := senderFile(c)
			c.state.writeDeadline = func(d time.Time) error {
				if d.Equal(aLongTimeAgo) {
					close(expired)
				}
				return file.SetWriteDeadline(d)
			}
			readDeadline := time.Now().Add(80 * time.Millisecond)
			if err := file.SetReadDeadline(readDeadline); err != nil {
				t.Fatal(err)
			}
			hookSendmsg(t, func(int, *syscall.Msghdr, int) (int, error) { return 0, syscall.EAGAIN })
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { _, err := c.send(ctx, []byte{1}, SendOptions{}); done <- err }()
			<-parked
			cancel()
			contextResult(t, done, context.Canceled)
			read := make(chan error, 1)
			go func() { var b [1]byte; _, err := file.Read(b[:]); read <- err }()
			select {
			case err := <-read:
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("Read: %v", err)
				}
				if time.Now().Before(readDeadline.Add(-10 * time.Millisecond)) {
					t.Fatal("cancellation moved the read deadline into the past")
				}
			case <-time.After(time.Second):
				_ = file.SetReadDeadline(aLongTimeAgo)
				t.Fatalf("cancellation cleared the caller's read deadline (Read: %v)", <-read)
			}
		})
	}
}

func TestSendMsgContextSetDeadlineDuringInterrupt(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		t.Run(contextCaseName(endpoint, false), func(t *testing.T) {
			parked, expired, moved, finish := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			c := fakeContextSender(t, endpoint, &fakeRawConn{parkWrite: func() error { close(parked); <-expired; return os.ErrDeadlineExceeded }})
			file := senderFile(c)
			var once sync.Once
			c.state.writeDeadline = func(d time.Time) error {
				if d.Equal(aLongTimeAgo) {
					once.Do(func() { close(expired) })
				}
				return file.SetWriteDeadline(d)
			}
			testHookSendInterrupt = func() { close(moved); <-finish }
			t.Cleanup(func() { testHookSendInterrupt = nil })
			hookSendmsg(t, func(int, *syscall.Msghdr, int) (int, error) { return 0, syscall.EAGAIN })
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { _, err := c.send(ctx, []byte{1}, SendOptions{}); done <- err }()
			<-parked
			cancel()
			<-moved
			if err := c.bothDeadlines(aLongTimeAgo); err != nil {
				t.Fatal(err)
			}
			// Read must see SetDeadline's read part before restore can run.
			read := make(chan error, 1)
			go func() { var b [1]byte; _, err := file.Read(b[:]); read <- err }()
			select {
			case err := <-read:
				if !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Errorf("Read = %v", err)
				}
			case <-time.After(time.Second):
				_ = file.SetReadDeadline(aLongTimeAgo)
				t.Errorf("SetDeadline deferred its read part until restore (Read: %v)", <-read)
			}
			close(finish)
			contextResult(t, done, context.Canceled)
		})
	}
}

func TestSendMsgContextInterruptOtherOutcomes(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		for _, result := range []string{"accepted", "closed"} {
			t.Run(contextCaseName(endpoint, false)+"/"+result, func(t *testing.T) {
				moved := make(chan struct{})
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				raw := &fakeRawConn{parkWrite: func() error {
					cancel()
					<-moved
					if result == "closed" {
						return os.ErrClosed
					}
					return nil
				}}
				c := fakeContextSender(t, endpoint, raw)
				file := senderFile(c)
				c.state.writeDeadline = func(d time.Time) error {
					if d.Equal(aLongTimeAgo) {
						close(moved)
					}
					return file.SetWriteDeadline(d)
				}
				calls := 0
				hookSendmsg(t, func(_ int, msg *syscall.Msghdr, _ int) (int, error) {
					calls++
					if calls == 1 {
						return 0, syscall.EAGAIN
					}
					return int(msg.Iov.Len), nil
				})
				n, err := c.send(ctx, []byte{1}, SendOptions{})
				if result == "accepted" {
					if n != 1 || err != nil {
						t.Fatalf("known acceptance = %d, %v", n, err)
					}
				} else {
					wantOp(t, "closed while interrupted", "write", err, net.ErrClosed)
					if n != 0 || errors.Is(err, context.Canceled) {
						t.Fatalf("close replaced with context: %d, %v", n, err)
					}
				}
			})
		}
	}
}

// realContextSender creates the sender and a peer that has not read any
// DATA. The receiver's window is smaller than the default send buffer and
// large enough to reopen on loopback (socket_linux_test.go: closingReadBuffer).
func realContextSender(t *testing.T, endpoint bool, cfg *Config) (contextSender, *Conn, func() uint64) {
	t.Helper()
	if !endpoint {
		c, peer := connPair(t, cfg, &Config{ReadBuffer: new(closingReadBuffer)})
		raw, err := c.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		return contextSender{send: c.SendMsgContext, ordinary: c.SendMsg, raw: raw, state: &c.send, deadline: c.SetWriteDeadline, bothDeadlines: c.SetDeadline}, peer, func() uint64 {
			stats, err := c.Stats()
			if err != nil {
				t.Fatal(err)
			}
			return stats.SACKsIn
		}
	}
	l := mustListen(t, &Config{ReadBuffer: new(closingReadBuffer)}, "sctp4", loopback4(0))
	e := openEndpoint(t, cfg, "sctp4", loopback4(0))
	id, err := e.Connect(listenerAddr(t, l))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := l.AcceptSCTP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Abort() })
	awaitCommUp(t, e)
	raw, err := e.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	return contextSender{send: func(ctx context.Context, b []byte, opts SendOptions) (int, error) {
		return e.SendMsgContext(ctx, id, b, opts)
	}, ordinary: func(b []byte, opts SendOptions) (int, error) { return e.SendMsg(id, b, opts) }, raw: raw, state: &e.send, deadline: e.SetWriteDeadline, bothDeadlines: e.SetDeadline}, peer, func() uint64 { return endpointStats(t, e, id).SACKsIn }
}

// fillContextBuffer fills through the public NoWait path and numbers every
// success. The SACK check makes the second refusal lasting, rather than an
// EAGAIN for DATA still in flight (socket_linux_test.go: awaitClosedWindow).
func fillContextBuffer(t *testing.T, c contextSender, peer *Conn, sacks func() uint64, ppid uint32) int {
	t.Helper()
	queued := 0
	fill := func() {
		for {
			if queued > 1<<20 {
				t.Fatal("send buffer never filled")
			}
			_, err := c.send(context.Background(), wireMessage(queued, 1000), SendOptions{Info: &SndInfo{PPID: ppid}, NoWait: true})
			if errors.Is(err, syscall.EAGAIN) {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			queued++
		}
	}
	fill()
	awaitClosedWindow(t, peer, sacks)
	fill()
	return queued
}

func TestSendMsgContextBufferCancellation(t *testing.T) { testContextBufferCancellation(t, false) }
func TestEndpointSendMsgContextBufferCancellation(t *testing.T) {
	testContextBufferCancellation(t, true)
}

func testContextBufferCancellation(t *testing.T, endpoint bool) {
	for _, deadlineFirst := range []bool{false, true} {
		name := "context"
		if deadlineFirst {
			name = "write deadline"
		}
		t.Run(name, func(t *testing.T) {
			c, peer, sacks := realContextSender(t, endpoint, nil)
			const queuedPPID, canceledPPID = 0x29290001, 0x29290002
			queued := fillContextBuffer(t, c, peer, sacks, queuedPPID)
			ctxWait := 75 * time.Millisecond
			cause := error(context.DeadlineExceeded)
			if deadlineFirst {
				ctxWait = 5 * time.Second
				cause = os.ErrDeadlineExceeded
				if err := c.deadline(time.Now().Add(75 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), ctxWait)
			defer cancel()
			start := time.Now()
			n, err := c.send(ctx, numbered(1<<20), SendOptions{Info: &SndInfo{PPID: canceledPPID}})
			wantOp(t, "full-buffer send", "write", err, cause)
			if n != 0 {
				t.Errorf("failed send returned %d bytes", n)
			}
			if d := time.Since(start); d < 50*time.Millisecond || d > time.Second {
				t.Errorf("send returned after %v, want 50ms..1s", d)
			}
			if deadlineFirst {
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					t.Errorf("write deadline also matches context: %v", err)
				}
			} else if errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("context also matches write deadline: %v", err)
			}
			if err := c.deadline(time.Time{}); err != nil {
				t.Fatal(err)
			}
			setReadDeadline(t, peer, 10*time.Second)
			for i := range queued {
				b, info, err := peer.ReadMsg(1024)
				if err != nil {
					t.Fatal(err)
				}
				if numberOf(b) != i || info.PPID != queuedPPID {
					t.Fatalf("message %d = id %d, PPID %#x; canceled id must never arrive", i, numberOf(b), info.PPID)
				}
			}
			// A fresh send proves the restored descriptor is usable. Reading
			// it also proves no canceled message preceded it in the stream.
			if _, err := c.send(context.Background(), numbered(queued), SendOptions{Info: &SndInfo{PPID: queuedPPID}}); err != nil {
				t.Fatal(err)
			}
			b, info, err := peer.ReadMsg(1024)
			if err != nil || numberOf(b) != queued || info.PPID != queuedPPID {
				t.Fatalf("after cancellation = %d, PPID %#x, %v", numberOf(b), info.PPID, err)
			}
			wantNothingQueued(t, peer, 100*time.Millisecond)
		})
	}
}

func TestSendMsgContextRealZeroAllocs(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector")
	}
	for _, endpoint := range []bool{false, true} {
		t.Run(contextCaseName(endpoint, true), func(t *testing.T) {
			c, peer, _ := realContextSender(t, endpoint, &Config{WriteBuffer: new(1 << 20), NoDelay: new(true)})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			payload := numbered(0)
			for _, ctx := range []context.Context{context.Background(), ctx} {
				var failed error
				// NoWait prevents the slow peer from causing an AfterFunc
				// registration. The enlarged buffer holds all 101 messages
				// even if the peer reads nothing during the measurement.
				allocs, mallocs, bytes := sendAllocs(50, func() { _, failed = c.send(ctx, payload, SendOptions{NoWait: true}) })
				if failed != nil {
					t.Fatal(failed)
				}
				if allocs != 0 || mallocs >= 0.05 || bytes >= 4 {
					t.Errorf("AllocsPerRun %v; %.4f allocations and %.2f bytes per send, want 0", allocs, mallocs, bytes)
				}
				setReadDeadline(t, peer, 5*time.Second)
				for range 101 {
					if _, _, err := peer.ReadMsg(1024); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

// stressSendContext records whether the public method's first context
// check refused the send. A later context refusal before any EAGAIN is
// at the send lock, including its check after acquisition; one after an
// EAGAIN is in the buffer wait. Err may also be called by context.AfterFunc.
type stressSendContext struct {
	context.Context
	errCalls     atomic.Uint32
	entryRefused atomic.Bool
}

func (c *stressSendContext) Err() error {
	err := c.Context.Err()
	if c.errCalls.Add(1) == 1 && err != nil {
		c.entryRefused.Store(true)
	}
	return err
}

// TestSendMsgContextConcurrentDelivery forces buffer waits with a small
// send buffer, large messages and a slow reader, while caller deadlines
// change. IDs have one owner, so a failed send arriving or a successful
// one arriving twice cannot be hidden by a matching aggregate count.
func TestSendMsgContextConcurrentDelivery(t *testing.T) {
	for _, endpoint := range []bool{false, true} {
		t.Run(contextCaseName(endpoint, false), func(t *testing.T) {
			c, peer, _ := realContextSender(t, endpoint, &Config{WriteBuffer: new(16 << 10), NoDelay: new(true)})
			const workers, sends = 8, 64
			const marker = workers * sends
			const payloadSize = 4 << 10
			accepted := make([]bool, marker)
			counts := make([]int, marker)
			bufferWaits := make([]atomic.Bool, marker)
			waitCancels := make([]context.CancelFunc, marker)
			timers := make([]*time.Timer, marker)
			var entryFailures, lockFailures, bufferFailures, noWaitRefusals atomic.Int32
			var interrupts atomic.Int32
			var pastMoved atomic.Bool
			writeDeadline := c.state.writeDeadline
			c.state.writeDeadline = func(d time.Time) error {
				err := writeDeadline(d)
				if d.Equal(aLongTimeAgo) && err == nil {
					pastMoved.Store(true)
				}
				return err
			}
			previousInterrupt := testHookSendInterrupt
			testHookSendInterrupt = func() {
				// Count only an interrupt that moved the actual poller
				// deadline, rather than merely invoking the callback.
				if pastMoved.Swap(false) {
					interrupts.Add(1)
				}
				if previousInterrupt != nil {
					previousInterrupt()
				}
			}
			t.Cleanup(func() { testHookSendInterrupt = previousInterrupt })
			hookSendmsg(t, func(fd int, msg *syscall.Msghdr, flags int) (int, error) {
				n, err := rawSendmsg(fd, msg, flags)
				id := numberOf(iovBytes(msg))
				if err == syscall.EAGAIN && id >= 0 && id < marker {
					bufferWaits[id].Store(true)
					// These contexts stay live through the lock wait and
					// cancel only after reaching the first buffer wait.
					if waitCancels[id] != nil && timers[id] == nil {
						timers[id] = time.AfterFunc(time.Millisecond, waitCancels[id])
					}
				}
				return n, err
			})
			setReadDeadline(t, peer, 30*time.Second)
			received := make(chan error, 1)
			go func() {
				for {
					b, _, err := peer.ReadMsg(payloadSize)
					if err != nil {
						_ = peer.Abort()
						received <- err
						return
					}
					id := numberOf(b)
					if id == marker {
						received <- nil
						return
					}
					if id < 0 || id >= marker || len(b) != payloadSize {
						received <- fmt.Errorf("unexpected payload id %d", id)
						return
					}
					counts[id]++
					time.Sleep(2 * time.Millisecond)
				}
			}()
			churnStop, churnDone := make(chan struct{}), make(chan error, 1)
			go func() {
				for i := 0; ; i++ {
					select {
					case <-churnStop:
						churnDone <- c.bothDeadlines(time.Time{})
						return
					default:
					}
					deadline := time.Time{}
					if i%2 != 0 {
						deadline = time.Now().Add(time.Hour)
					}
					set := c.deadline
					if i%4 >= 2 {
						set = c.bothDeadlines
					}
					if err := set(deadline); err != nil {
						churnDone <- err
						return
					}
					time.Sleep(100 * time.Microsecond)
				}
			}()
			var wg sync.WaitGroup
			errs := make(chan error, workers)
			for worker := range workers {
				wg.Go(func() {
					rng := rand.New(rand.NewPCG(uint64(worker+1), 29))
					for i := range sends {
						id := worker*sends + i
						ctx := context.Background()
						var observed *stressSendContext
						cancel := func() {}
						kind := rng.IntN(4)
						if kind != 0 {
							ctx, cancel = context.WithCancel(ctx)
							observed = &stressSendContext{Context: ctx}
							ctx = observed
							if kind == 3 {
								waitCancels[id] = cancel
							} else if rng.IntN(3) == 0 {
								cancel()
							} else {
								timers[id] = time.AfterFunc(time.Duration(100+rng.IntN(1900))*time.Microsecond, cancel)
							}
						}
						payload := make([]byte, payloadSize)
						binary.BigEndian.PutUint32(payload, uint32(id))
						var n int
						var err error
						if kind == 0 {
							n, err = c.ordinary(payload, SendOptions{})
						} else {
							n, err = c.send(ctx, payload, SendOptions{NoWait: kind == 2})
						}
						if timers[id] != nil {
							timers[id].Stop()
						}
						cancel()
						if err == nil {
							if n != len(payload) {
								errs <- fmt.Errorf("id %d: short success %d", id, n)
								return
							}
							accepted[id] = true
						} else {
							if n != 0 {
								errs <- fmt.Errorf("id %d: failed send returned %d, %w", id, n, err)
								return
							}
							if errors.Is(err, syscall.EAGAIN) {
								noWaitRefusals.Add(1)
							} else if observed != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
								if observed.entryRefused.Load() {
									entryFailures.Add(1)
								} else if bufferWaits[id].Load() {
									bufferFailures.Add(1)
								} else {
									lockFailures.Add(1)
								}
							} else {
								errs <- fmt.Errorf("id %d: unexpected send result %d, %w", id, n, err)
								return
							}
						}
					}
				})
			}
			wg.Wait()
			close(churnStop)
			if err := <-churnDone; err != nil {
				t.Error(err)
			}
			close(errs)
			for err := range errs {
				t.Error(err)
			}
			// The caller's final deadline is zero. A blocking send must
			// still work after all interrupts and restores have finished.
			if _, err := c.ordinary(numbered(marker), SendOptions{}); err != nil {
				t.Fatal(err)
			}
			if err := <-received; err != nil {
				t.Fatal(err)
			}
			successes, failures := 0, 0
			for id, success := range accepted {
				want := 0
				if success {
					want = 1
					successes++
				} else {
					failures++
				}
				if counts[id] != want {
					t.Errorf("id %d: success %v, arrivals %d, want %d", id, success, counts[id], want)
				}
			}
			if successes == 0 || failures == 0 {
				t.Fatalf("stress did not mix results: successes %d, failures %d", successes, failures)
			}
			if int(entryFailures.Load()+lockFailures.Load()+bufferFailures.Load()+noWaitRefusals.Load()) != failures {
				t.Errorf("failure counts do not account for all %d failed sends", failures)
			}
			if interrupts.Load() == 0 {
				t.Error("interrupt count = 0; no interrupt moved the write deadline into the past")
			}
			if bufferFailures.Load() == 0 {
				t.Error("buffer-wait context failures = 0; no send waiting for space was canceled")
			}
			wantNothingQueued(t, peer, 100*time.Millisecond)
			t.Logf("%d successful sends arrived exactly once; %d failed sends never arrived", successes, failures)
			t.Logf("context failures: entry=%d lock=%d buffer=%d; NoWait refusals=%d; interrupts=%d", entryFailures.Load(), lockFailures.Load(), bufferFailures.Load(), noWaitRefusals.Load(), interrupts.Load())
		})
	}
}
