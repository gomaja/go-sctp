// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"syscall"
	"testing"
	"time"
)

// TestReadUnkeptNotificationBeforeShutdown checks that a malformed record's
// verdict precedes the end its valid prefix reports (RFC 6458 §6.1.1), even
// when the script has nothing more queued to wake the poller.
func TestReadUnkeptNotificationBeforeShutdown(t *testing.T) {
	for _, reader := range []string{"Read", "ReadMsg"} {
		for _, declared := range []uint32{sizeAssocChange - 1, sizeAssocChange + 1, NotificationReassemblyLimit + 1} {
			t.Run(fmt.Sprintf("%s/declared=%d", reader, declared), func(t *testing.T) {
				rec := assocChangeRecord(AssocShutdownComplete, 7, nil)
				binary.NativeEndian.PutUint32(rec[4:], declared)
				script := &recvScript{steps: []recvStep{{data: rec, flags: msgNotification | msgEOR}}, done: syscall.EAGAIN}
				hookRecvmsg(t, script.recvmsg)
				c := scriptConn(t, nil)
				setReadDeadline(t, c, 200*time.Millisecond)
				read := func() (int, RcvInfo, error) {
					if reader == "Read" {
						n, err := c.Read(make([]byte, 64))
						return n, RcvInfo{}, err
					}
					b, info, err := c.ReadMsg(64)
					return len(b), info, err
				}
				n, info, err := read()
				target := ErrShortNotification
				if declared > NotificationReassemblyLimit {
					target = ErrNotificationTooLong
				}
				wantReadError(t, err, target)
				if n != 0 || info != (RcvInfo{}) || script.step != 1 || script.calls != 1 {
					t.Fatalf("n=%d info=%+v step=%d calls=%d", n, info, script.step, script.calls)
				}
				n, info, err = read()
				if n != 0 || info != (RcvInfo{}) || err != io.EOF || script.calls != 1 {
					t.Fatalf("next: n=%d info=%+v err=%v calls=%d", n, info, err, script.calls)
				}
			})
		}
	}
}

// TestReadMsgInterleavedNotificationVerdict keeps the first fragment's
// metadata and the rest of its message when an unkept notification fails
// between fragments; a malformed terminal record must also end the read
// without parking in the poller.
func TestReadMsgInterleavedNotificationVerdict(t *testing.T) {
	for _, terminal := range []bool{false, true} {
		t.Run(fmt.Sprintf("terminal=%t", terminal), func(t *testing.T) {
			rec := assocChangeRecord(AssocCommUp, 7, nil)
			if terminal {
				rec = assocChangeRecord(AssocShutdownComplete, 7, nil)
			}
			binary.NativeEndian.PutUint32(rec[4:], uint32(len(rec)+1))
			first := RcvInfo{AssocID: 7, Stream: 3, PPID: 42}
			steps := []recvStep{{data: []byte("before/"), rcv: &first}, {data: rec, flags: msgNotification | msgEOR}}
			if !terminal {
				steps = append(steps, recvStep{data: []byte("after"), flags: msgEOR}, recvStep{data: []byte("following-data"), rcv: &first, flags: msgEOR})
			}
			script := &recvScript{steps: steps, done: syscall.EAGAIN}
			hookRecvmsg(t, script.recvmsg)
			c := scriptConn(t, nil)
			setReadDeadline(t, c, 200*time.Millisecond)
			b, info, err := c.ReadMsg(64)
			wantReadError(t, err, ErrShortNotification)
			want := "before/after"
			if terminal {
				want = "before/"
				if !errors.Is(err, ErrMessageInterrupted) || !errors.Is(err, io.EOF) {
					t.Fatalf("terminal error: %v", err)
				}
			}
			if string(b) != want || info != first || script.off != 0 {
				t.Fatalf("data=%q info=%+v step=%d off=%d", b, info, script.step, script.off)
			}
			if !terminal {
				if script.step != 3 {
					t.Fatalf("consumed step %d, want 3", script.step)
				}
				b, info, err = c.ReadMsg(64)
				if string(b) != "following-data" || info != first || err != nil {
					t.Fatalf("following: %q %+v %v", b, info, err)
				}
			} else if script.calls != 3 || c.opened() {
				t.Fatalf("terminal calls=%d open=%t", script.calls, c.opened())
			}
		})
	}
}

// TestReadMsgCutNotificationVerdict checks both framing and typed parsing
// errors in the record that aborts partial delivery. ErrMessageInterrupted
// must retain the notification's own cause, kept or not.
func TestReadMsgCutNotificationVerdict(t *testing.T) {
	for _, kept := range []bool{false, true} {
		for _, shape := range []string{"framing", "parse", "valid"} {
			if shape == "parse" && !kept {
				continue
			}
			t.Run(fmt.Sprintf("kept=%t/%s", kept, shape), func(t *testing.T) {
				rec := assocChangeRecord(AssocRestart, 7, nil)
				if shape == "framing" {
					binary.NativeEndian.PutUint32(rec[4:], uint32(len(rec)+1))
				}
				if shape == "parse" {
					rec = notif(EventPartialDelivery, 8)
				}
				calls := 0
				var handler NotificationHandler
				var subs []EventType
				if kept {
					handler = func(Notification) error { calls++; return nil }
					subs = []EventType{EventAssocChange, EventPartialDelivery}
				}
				c := scriptConn(t, handler, subs...)
				first := RcvInfo{AssocID: 7, Stream: 3}
				script := &recvScript{steps: []recvStep{{data: []byte("prefix"), rcv: &first}, {data: rec, flags: msgNotification | msgEOR}, {data: []byte("following-data"), flags: msgEOR}}}
				hookRecvmsg(t, script.recvmsg)
				b, info, err := c.ReadMsg(64)
				wantReadError(t, err, ErrMessageInterrupted)
				if shape != "valid" && !errors.Is(err, ErrShortNotification) {
					t.Fatalf("notification verdict lost: %v", err)
				}
				if shape == "valid" && errors.Is(err, ErrShortNotification) {
					t.Fatalf("valid notification rejected: %v", err)
				}
				wantCalls := 0
				if kept && shape == "valid" {
					wantCalls = 1
				}
				if string(b) != "prefix" || info != first || script.step != 2 || script.off != 0 || calls != wantCalls || c.opened() {
					t.Fatalf("data=%q info=%+v step=%d off=%d calls=%d open=%t err=%v", b, info, script.step, script.off, calls, c.opened(), err)
				}
			})
		}
	}
}

// TestReadMsgQueueFullNotificationVerdict reaches the no-retention policy
// after a handler's pending queue fills. The queue's overflow error must
// not hide a later malformed record's independent framing error.
func TestReadMsgQueueFullNotificationVerdict(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("malformed=%t", malformed), func(t *testing.T) {
			calls := 0
			c := scriptConn(t, func(Notification) error { calls++; return nil }, EventAssocChange)
			last := assocChangeRecord(AssocCommUp, 7, nil)
			if malformed {
				binary.NativeEndian.PutUint32(last[4:], uint32(len(last)+1))
			}
			first := RcvInfo{AssocID: 7, Stream: 3}
			script := &recvScript{steps: []recvStep{
				{data: []byte("before/"), rcv: &first},
				{data: commUp(NotificationReassemblyLimit, 0), flags: msgNotification | msgEOR},
				{data: assocChangeRecord(AssocCommUp, 7, nil), flags: msgNotification | msgEOR},
				{data: last, flags: msgNotification | msgEOR},
				{data: []byte("after"), flags: msgEOR},
				{data: []byte("following-data"), rcv: &first, flags: msgEOR},
			}}
			hookRecvmsg(t, script.recvmsg)
			b, info, err := c.ReadMsg(64)
			wantReadError(t, err, ErrNotificationTooLong)
			if errors.Is(err, ErrShortNotification) != malformed {
				t.Fatalf("malformed=%t: %v", malformed, err)
			}
			if string(b) != "before/after" || info != first || script.step != 5 || calls != 1 {
				t.Fatalf("data=%q info=%+v step=%d calls=%d", b, info, script.step, calls)
			}
			b, info, err = c.ReadMsg(64)
			if string(b) != "following-data" || info != first || err != nil {
				t.Fatalf("following: %q %+v %v", b, info, err)
			}
		})
	}
}

// FuzzReceiveNotificationVerdict compares three receive policies with a
// framing oracle independent of notificationAccumulator (RFC 6458 §6.1).
// Association state is held at CommUp so the corpus varies framing without
// ending the connection; terminal prefixes have their own regression tests.
func FuzzReceiveNotificationVerdict(f *testing.F) {
	for _, n := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 16, 20, 4096} {
		for _, declared := range []uint32{0, 4, 7, 8, uint32(max(0, n-1)), uint32(n), uint32(n + 1), NotificationReassemblyLimit, NotificationReassemblyLimit + 1} {
			rec := make([]byte, n)
			if n >= 2 {
				binary.NativeEndian.PutUint16(rec, uint16(EventAssocChange))
			}
			if n >= 8 {
				binary.NativeEndian.PutUint32(rec[4:], declared)
			}
			f.Add(rec, uint16(3), uint16(8), uint16(12))
		}
	}
	for _, declared := range []int{4, 100} {
		f.Add(notifSized(EventPeerAddrChange, declared, 16, 0), uint16(0), uint16(3), uint16(8))
	}
	f.Fuzz(func(t *testing.T, record []byte, x, y, z uint16) {
		record = append([]byte(nil), record[:min(len(record), 4096)]...)
		if len(record) >= 10 && EventType(binary.NativeEndian.Uint16(record)) == EventAssocChange {
			binary.NativeEndian.PutUint16(record[8:], uint16(AssocCommUp))
		}
		var verdict error
		if len(record) < 8 {
			verdict = ErrShortNotification
		} else {
			declared := binary.NativeEndian.Uint32(record[4:])
			switch {
			case declared < 8:
				verdict = ErrShortNotification
			case declared > NotificationReassemblyLimit:
				verdict = ErrNotificationTooLong
			case uint32(len(record)) != declared:
				verdict = ErrShortNotification
			}
		}
		cuts := []int{int(x) % (len(record) + 1), int(y) % (len(record) + 1), int(z) % (len(record) + 1)}
		slices.Sort(cuts)
		steps := make([]recvStep, 0, 5)
		start := 0
		for _, end := range cuts {
			if end > start {
				steps = append(steps, recvStep{data: record[start:end], flags: msgNotification})
				start = end
			}
		}
		steps = append(steps, recvStep{data: record[start:], flags: msgNotification | msgEOR})
		recordSteps := len(steps)
		first := RcvInfo{AssocID: 7, Stream: 3, PPID: 42}
		steps = append(steps, recvStep{data: []byte("following-data"), rcv: &first, flags: msgEOR})
		for _, reader := range []string{"Read", "RecvMsg", "Endpoint"} {
			script := &recvScript{steps: steps}
			hookRecvmsg(t, script.recvmsg)
			buf := make([]byte, 8192)
			var read func() (int, MsgInfo, error)
			switch reader {
			case "Read":
				c := scriptConn(t, nil)
				read = func() (int, MsgInfo, error) { n, err := c.Read(buf); return n, MsgInfo{}, err }
			case "RecvMsg":
				c := scriptConn(t, nil, EventAssocChange)
				read = func() (int, MsgInfo, error) { return c.RecvMsg(buf) }
			case "Endpoint":
				e := scriptEndpoint(t, nil)
				read = func() (int, MsgInfo, error) { return e.RecvMsg(buf) }
			}
			n, info, err := read()
			if verdict != nil {
				wantReadError(t, err, verdict)
				if n != 0 || info != (MsgInfo{}) || script.step != recordSteps || script.off != 0 {
					t.Fatalf("%s rejected record: n=%d info=%+v step=%d/%d off=%d", reader, n, info, script.step, recordSteps, script.off)
				}
			} else {
				if err != nil {
					t.Fatalf("%s valid record: %v", reader, err)
				}
				if reader == "Read" {
					if string(buf[:n]) != "following-data" || script.step != recordSteps+1 {
						t.Fatalf("silent record: %q step=%d", buf[:n], script.step)
					}
					continue
				}
				if !info.Notification || !info.EOR || !bytes.Equal(buf[:n], record) || script.step != recordSteps {
					t.Fatalf("%s valid raw record: n=%d info=%+v step=%d", reader, n, info, script.step)
				}
			}
			n, info, err = read()
			if err != nil || string(buf[:n]) != "following-data" || script.step != recordSteps+1 || script.off != 0 {
				t.Fatalf("%s following: %q info=%+v err=%v step=%d off=%d", reader, buf[:n], info, err, script.step, script.off)
			}
			if reader != "Read" && (!info.EOR || info.Notification || info.Rcv != first) {
				t.Fatalf("%s following metadata: %+v", reader, info)
			}
		}
	})
}
