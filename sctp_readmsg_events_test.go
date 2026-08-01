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
	"bytes"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestInterruptedNotificationFailsConnectionClosed(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	defer func() { _ = syscall.Close(fds[1]) }()

	file := os.NewFile(uintptr(fds[0]), "interrupted-notification")
	if file == nil {
		_ = syscall.Close(fds[0])
		t.Fatal("os.NewFile returned nil")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		_ = file.Close()
		t.Fatalf("SyscallConn: %v", err)
	}
	conn := &SCTPConn{_fd: int32(fds[0]), file: file, raw: raw}
	defer func() {
		if conn.fd() >= 0 {
			_ = conn.Abort()
		}
	}()

	header := notifSized(SCTP_ASSOC_CHANGE, assocChangeMinSize,
		notificationHeaderSize, 0)
	accumulator := notificationAccumulator{retain: true}
	accumulator.add(header)
	err = conn.abortInterruptedNotification(&accumulator, os.ErrDeadlineExceeded)
	if !errors.Is(err, ErrShortNotification) {
		t.Errorf("error = %v, want ErrShortNotification", err)
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("error = %v, want os.ErrDeadlineExceeded", err)
	}
	if got := conn.fd(); got != -1 {
		t.Errorf("connection fd = %d after interrupted notification, want -1", got)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_FCNTL,
		uintptr(fds[0]), syscall.F_GETFD, 0); errno != syscall.EBADF {
		t.Errorf("fcntl on aborted descriptor = %v, want EBADF", errno)
	}
}

func TestRecvmsgNotificationInterruptionAlwaysFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		second    func([]byte) (int, int, int, error)
		wantCause error
	}{
		{"recvmsg error", func([]byte) (int, int, int, error) {
			return 0, 0, 0, syscall.EIO
		}, syscall.EIO},
		{"EOF", func([]byte) (int, int, int, error) {
			return 0, 0, 0, nil
		}, io.EOF},
		{"application data", func(dst []byte) (int, int, int, error) {
			dst[0] = 0xAA
			return 1, 0, syscall.MSG_EOR, nil
		}, syscall.EPROTO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
			if err != nil {
				t.Fatalf("socketpair: %v", err)
			}
			defer func() { _ = syscall.Close(fds[1]) }()

			file := os.NewFile(uintptr(fds[0]), "interrupted-notification-recvmsg")
			if file == nil {
				_ = syscall.Close(fds[0])
				t.Fatal("os.NewFile returned nil")
			}
			raw, err := file.SyscallConn()
			if err != nil {
				_ = file.Close()
				t.Fatalf("SyscallConn: %v", err)
			}
			conn := &SCTPConn{
				_fd: int32(fds[0]), file: file, raw: raw,
				notificationHandler: func([]byte) error { return nil },
			}
			defer func() {
				if conn.fd() >= 0 {
					_ = conn.Abort()
				}
			}()

			header := notifSized(SCTP_ASSOC_CHANGE, assocChangeMinSize,
				notificationHeaderSize, 0)
			calls := 0
			receive := func(_ int, dst, _ []byte, _ int) (int, int, int, error) {
				calls++
				if calls == 1 {
					copy(dst, header)
					return len(header), 0, MSG_NOTIFICATION, nil
				}
				return tc.second(dst)
			}

			n, oobn, _, notification, err := conn.recvmsgWithNotificationUsing(
				make([]byte, notificationHeaderSize), nil, receive)
			if n != 0 || oobn != 0 || notification != nil {
				t.Errorf("result = (%d, %d, %v), want no returned record", n, oobn, notification)
			}
			if !errors.Is(err, ErrShortNotification) {
				t.Errorf("error = %v, want ErrShortNotification", err)
			}
			if !errors.Is(err, tc.wantCause) {
				t.Errorf("error = %v, want cause %v", err, tc.wantCause)
			}
			if calls != 2 {
				t.Errorf("recvmsg calls = %d, want 2", calls)
			}
			if conn.fd() != -1 {
				t.Errorf("connection fd = %d, want closed", conn.fd())
			}
		})
	}
}

func TestReadMsgNotificationInterruptionAlwaysFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		second    func([]byte) (int, int, int, error)
		wantCause error
	}{
		{"recvmsg error", func([]byte) (int, int, int, error) {
			return 0, 0, 0, syscall.EIO
		}, syscall.EIO},
		{"EOF", func([]byte) (int, int, int, error) {
			return 0, 0, 0, nil
		}, io.EOF},
		{"application data", func(dst []byte) (int, int, int, error) {
			dst[0] = 0xBB
			return 1, 0, syscall.MSG_EOR, nil
		}, syscall.EPROTO},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
			if err != nil {
				t.Fatalf("socketpair: %v", err)
			}
			defer func() { _ = syscall.Close(fds[1]) }()

			file := os.NewFile(uintptr(fds[0]), "interrupted-readmsg-notification")
			if file == nil {
				_ = syscall.Close(fds[0])
				t.Fatal("os.NewFile returned nil")
			}
			raw, err := file.SyscallConn()
			if err != nil {
				_ = file.Close()
				t.Fatalf("SyscallConn: %v", err)
			}
			conn := &SCTPConn{
				_fd: int32(fds[0]), file: file, raw: raw,
				notificationHandler: func([]byte) error { return nil },
			}
			defer func() {
				if conn.fd() >= 0 {
					_ = conn.Abort()
				}
			}()

			header := notifSized(SCTP_ASSOC_CHANGE, assocChangeMinSize,
				notificationHeaderSize, 0)
			calls := 0
			receive := func(_ int, dst, _ []byte, _ int) (int, int, int, error) {
				calls++
				if calls == 1 {
					copy(dst, header)
					return len(header), 0, MSG_NOTIFICATION, nil
				}
				return tc.second(dst)
			}

			payload, info, err := conn.readMsgUsing(64, receive)
			if len(payload) != 0 || info != nil {
				t.Errorf("result = (% x, %+v), want no returned record", payload, info)
			}
			if !errors.Is(err, ErrShortNotification) {
				t.Errorf("error = %v, want ErrShortNotification", err)
			}
			if !errors.Is(err, tc.wantCause) {
				t.Errorf("error = %v, want cause %v", err, tc.wantCause)
			}
			if calls != 2 {
				t.Errorf("recvmsg calls = %d, want 2", calls)
			}
			if conn.fd() != -1 {
				t.Errorf("connection fd = %d, want closed", conn.fd())
			}
		})
	}
}

func TestReadMsgApplicationInterruptionAlwaysFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		secondErr error
		deadline  bool
		wantCause error
	}{
		{"recvmsg error", syscall.EIO, false, syscall.EIO},
		{"EOF", nil, false, io.EOF},
		{"poller deadline", syscall.EAGAIN, true, os.ErrDeadlineExceeded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
			if err != nil {
				t.Fatalf("socketpair: %v", err)
			}
			defer func() { _ = syscall.Close(fds[1]) }()

			if tc.deadline {
				if err := syscall.SetNonblock(fds[0], true); err != nil {
					t.Fatalf("SetNonblock: %v", err)
				}
			}
			file := os.NewFile(uintptr(fds[0]), "interrupted-readmsg-application")
			if file == nil {
				_ = syscall.Close(fds[0])
				t.Fatal("os.NewFile returned nil")
			}
			raw, err := file.SyscallConn()
			if err != nil {
				_ = file.Close()
				t.Fatalf("SyscallConn: %v", err)
			}
			conn := &SCTPConn{_fd: int32(fds[0]), file: file, raw: raw}
			defer func() {
				if conn.fd() >= 0 {
					_ = conn.Abort()
				}
			}()
			if tc.deadline {
				if err := file.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
					t.Fatalf("SetReadDeadline: %v", err)
				}
			}

			want := []byte("prefix")
			calls := 0
			receive := func(_ int, dst, _ []byte, _ int) (int, int, int, error) {
				calls++
				if calls == 1 {
					copy(dst, want)
					return len(want), 0, 0, nil
				}
				return 0, 0, 0, tc.secondErr
			}

			payload, info, err := conn.readMsgUsing(64, receive)
			if !bytes.Equal(payload, want) || info != nil {
				t.Errorf("result = (%q, %+v), want prefix and nil info", payload, info)
			}
			if !errors.Is(err, ErrMessageInterrupted) {
				t.Errorf("error = %v, want ErrMessageInterrupted", err)
			}
			if !errors.Is(err, tc.wantCause) {
				t.Errorf("error = %v, want cause %v", err, tc.wantCause)
			}
			if calls < 2 {
				t.Errorf("recvmsg calls = %d, want at least 2", calls)
			}
			if conn.fd() != -1 {
				t.Errorf("connection fd = %d, want closed", conn.fd())
			}
		})
	}
}

// TestReadMsgHandlerReassemblesNotification uses a one-byte ReadMsg limit so a
// 20-byte SCTP_ASSOC_CHANGE necessarily arrives through many recvmsg calls.
// NotificationHandler is nevertheless a record callback: it must run once,
// with bytes that ParseNotification accepts as the complete kernel event.
func TestReadMsgHandlerReassemblesNotification(t *testing.T) {
	var (
		handlerCalls int32
		handlerSize  int32
	)
	handler := func(b []byte) error {
		atomic.AddInt32(&handlerCalls, 1)
		atomic.StoreInt32(&handlerSize, int32(len(b)))
		note, err := ParseNotification(b)
		if err != nil {
			return err
		}
		change, ok := note.(*AssocChange)
		if !ok || change.State != SCTP_COMM_UP {
			return errors.New("notification is not SCTP_ASSOC_CHANGE/COMM_UP")
		}
		if int(change.Length()) != len(b) {
			return errors.New("notification header length does not match callback bytes")
		}
		return nil
	}

	cfg := SocketConfig{
		NotificationHandler: handler,
		Control: func(_ string, _ string, raw syscall.RawConn) error {
			var callErr error
			if err := raw.Control(func(fd uintptr) {
				event := Event{Type: uint16(SCTP_ASSOC_CHANGE), On: 1}
				_, _, callErr = setsockopt(int(fd), SCTP_EVENT,
					uintptr(unsafe.Pointer(&event)), unsafe.Sizeof(event))
			}); err != nil {
				return err
			}
			return callErr
		},
	}
	ln, err := cfg.Listen("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	type accepted struct {
		conn *SCTPConn
		err  error
	}
	acceptedCh := make(chan accepted, 1)
	go func() {
		conn, acceptErr := ln.AcceptSCTP()
		acceptedCh <- accepted{conn: conn, err: acceptErr}
	}()
	client, err := DialSCTP("sctp4", nil, ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Abort() }()
	acceptedResult := <-acceptedCh
	if acceptedResult.err != nil {
		t.Fatalf("accept: %v", acceptedResult.err)
	}
	server := acceptedResult.conn
	defer func() { _ = server.Abort() }()

	if _, err := client.SCTPWrite([]byte{'x'}, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, _, err := server.ReadMsg(1)
	if err != nil {
		t.Fatalf("ReadMsg: %v", err)
	}
	if !bytes.Equal(got, []byte{'x'}) {
		t.Fatalf("ReadMsg = %q, want x", got)
	}
	if calls := atomic.LoadInt32(&handlerCalls); calls != 1 {
		t.Fatalf("handler calls = %d, want 1", calls)
	}
	if size := atomic.LoadInt32(&handlerSize); size != assocChangeMinSize {
		t.Fatalf("handler size = %d, want %d", size, assocChangeMinSize)
	}
}

// TestReadMsgNotificationHandlerMayReenterRead guards the runtime-poller lock
// boundary. syscall.RawConn.Read holds internal/poll's per-descriptor read lock
// while its callback runs. Calling user code there deadlocks if that handler
// reads the same connection: the nested read waits for a lock the outer callback
// cannot release until the handler returns.
//
// Subscribe on the listening endpoint so the accepted socket has a real
// SCTP_ASSOC_CHANGE/COMM_UP notification queued ahead of two application
// records. The handler consumes the first record with a nested read; the outer
// ReadMsg must then return the second.
func TestReadMsgNotificationHandlerMayReenterRead(t *testing.T) {
	var (
		server       *SCTPConn
		handlerCalls int32
		nested       []byte
	)
	handler := func(b []byte) error {
		if atomic.AddInt32(&handlerCalls, 1) != 1 {
			return nil
		}
		note, err := ParseNotification(b)
		if err != nil {
			return err
		}
		change, ok := note.(*AssocChange)
		if !ok || change.State != SCTP_COMM_UP {
			return errors.New("first notification is not SCTP_ASSOC_CHANGE/COMM_UP")
		}
		buf := make([]byte, 64)
		n, _, _, err := server.SCTPReadFlags(buf)
		if err != nil {
			return err
		}
		nested = append([]byte(nil), buf[:n]...)
		return nil
	}

	cfg := SocketConfig{
		NotificationHandler: handler,
		Control: func(_ string, _ string, raw syscall.RawConn) error {
			var callErr error
			if err := raw.Control(func(fd uintptr) {
				event := Event{Type: uint16(SCTP_ASSOC_CHANGE), On: 1}
				_, _, callErr = setsockopt(int(fd), SCTP_EVENT,
					uintptr(unsafe.Pointer(&event)), unsafe.Sizeof(event))
			}); err != nil {
				return err
			}
			return callErr
		},
	}
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := cfg.Listen("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	type accepted struct {
		conn *SCTPConn
		err  error
	}
	acceptedCh := make(chan accepted, 1)
	go func() {
		conn, acceptErr := ln.AcceptSCTP()
		acceptedCh <- accepted{conn: conn, err: acceptErr}
	}()

	client, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = client.Abort() }()
	gotAccepted := <-acceptedCh
	if gotAccepted.err != nil {
		t.Fatalf("accept: %v", gotAccepted.err)
	}
	server = gotAccepted.conn
	defer func() { _ = server.Abort() }()

	first := []byte("read by the reentrant handler")
	second := []byte("returned by the outer ReadMsg")
	if _, err := client.SCTPWrite(first, nil); err != nil {
		t.Fatalf("write first record: %v", err)
	}
	if _, err := client.SCTPWrite(second, nil); err != nil {
		t.Fatalf("write second record: %v", err)
	}

	type result struct {
		b   []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		b, _, readErr := server.ReadMsg(4096)
		done <- result{b: b, err: readErr}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("ReadMsg: %v", got.err)
		}
		if !bytes.Equal(nested, first) {
			t.Errorf("handler read %q, want %q", nested, first)
		}
		if !bytes.Equal(got.b, second) {
			t.Errorf("ReadMsg returned %q, want %q", got.b, second)
		}
		if calls := atomic.LoadInt32(&handlerCalls); calls != 1 {
			t.Errorf("handler called %d times, want 1", calls)
		}
	case <-time.After(5 * time.Second):
		_ = server.Abort()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		t.Fatal("NotificationHandler deadlocked while re-entering ReadMsg's connection")
	}
}

// TestReadMsgWithNotificationsSubscribed exercises the path that matters in
// production: the reader is subscribed to association events, so the
// SCTPReadFlags retry loop can be entered by a notification arriving while a
// message is being reassembled. Reassembly must still produce whole messages.
func TestReadMsgWithNotificationsSubscribed(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	var notifications int32
	handler := func([]byte) error {
		atomic.AddInt32(&notifications, 1)
		return nil
	}

	type accepted struct {
		conn *SCTPConn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, err := ln.AcceptSCTP()
		if c != nil {
			c.notificationHandler = handler
			// Subscribe to everything, so events interleave with data.
			_ = c.SubscribeEvents(SCTP_EVENT_DATA_IO | SCTP_EVENT_ASSOCIATION |
				SCTP_EVENT_ADDRESS | SCTP_EVENT_SHUTDOWN |
				SCTP_EVENT_PARTIAL_DELIVERY)
		}
		ch <- accepted{c, err}
	}()

	client, err := DialSCTP("sctp", nil, ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Closed explicitly at the end of the test to raise a SHUTDOWN event; the
	// cleanup only covers early failure paths.
	closed := false
	defer func() {
		if !closed {
			_ = client.Close()
		}
	}()

	a := <-ch
	if a.err != nil {
		t.Fatalf("accept: %v", a.err)
	}
	server := a.conn
	defer func() { _ = server.Close() }()

	// Sizes that span the reassembly loop, sent back to back so events and
	// data compete on the same socket.
	sizes := []int{1, 2048, 4096, 20000, 60000}
	for _, size := range sizes {
		msg := fill(size)
		if _, err := client.SCTPWrite(msg, nil); err != nil {
			t.Fatalf("write %d: %v", size, err)
		}

		got, _, err := server.ReadMsg(1 << 20)
		if err != nil {
			t.Fatalf("ReadMsg %d: %v", size, err)
		}
		if !bytes.Equal(got, msg) {
			t.Errorf("size %d: reassembled %d bytes and they do not match",
				size, len(got))
		}
	}

	// A stable loopback association raises no address or error events, so the
	// data phase above may well see none. Close the peer to force a real
	// SHUTDOWN notification and confirm the handler is actually wired up and
	// that the retry loop in SCTPReadFlags is exercised at least once.
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	closed = true
	buf := make([]byte, 4096)
	for i := 0; i < 16; i++ {
		if _, _, err := server.SCTPRead(buf); err != nil {
			break
		}
	}
	if got := atomic.LoadInt32(&notifications); got == 0 {
		t.Error("no notification was ever delivered; the interleaving path in " +
			"SCTPReadFlags was never exercised, so this test proves nothing")
	} else {
		t.Logf("notifications delivered: %d", got)
	}
}

// TestReadMsgPeerAbortMidMessage checks that an association aborted while a
// message is in flight surfaces an error instead of hanging or returning a
// silently short message as if it were complete.
func TestReadMsgPeerAbortMidMessage(t *testing.T) {
	client, server := eorPair(t)

	// Queue a large message, then abort without a graceful shutdown.
	msg := fill(200000)
	if _, err := client.SCTPWrite(msg, nil); err != nil {
		t.Skipf("write did not fit the send buffer: %v", err)
	}
	if err := client.Abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}

	got, _, err := server.ReadMsg(1 << 20)

	// Either the whole message beat the ABORT to the receiver, or the read
	// fails. What must not happen is a short read reported as success.
	if err == nil {
		if !bytes.Equal(got, msg) {
			t.Errorf("ReadMsg reported success with %d of %d bytes",
				len(got), len(msg))
		}
		return
	}
	t.Logf("aborted association surfaced: %v (%d bytes buffered)", err, len(got))
}

// TestReadMsgAfterPeerClose verifies a clean shutdown terminates ReadMsg
// rather than leaving it blocked.
func TestReadMsgAfterPeerClose(t *testing.T) {
	client, server := eorPair(t)

	want := []byte("final message")
	if _, err := client.SCTPWrite(want, nil); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	got, _, err := server.ReadMsg(4096)
	if err != nil {
		t.Fatalf("ReadMsg before EOF: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}

	// The next read must report the shutdown, not block.
	_, _, err = server.ReadMsg(4096)
	if err == nil {
		t.Fatal("ReadMsg after peer close returned nil error, want EOF or a socket error")
	}
	if !errors.Is(err, io.EOF) {
		t.Logf("peer close surfaced as %v (not io.EOF, acceptable)", err)
	}
}

// TestReadMsgOnClosedConn ensures ReadMsg on a closed descriptor returns an
// error rather than reading from a recycled fd.
func TestReadMsgOnClosedConn(t *testing.T) {
	client, server := eorPair(t)
	_ = client

	if err := server.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, _, err := server.ReadMsg(4096)
	if err == nil {
		t.Fatal("ReadMsg on a closed conn returned nil error")
	}
	if !errors.Is(err, syscall.EBADF) && !errors.Is(err, io.EOF) {
		t.Logf("closed conn surfaced as %v", err)
	}
}
