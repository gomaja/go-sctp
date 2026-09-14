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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sctp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

type retainedLargeRead struct {
	payload []byte
	info    *SndRcvInfo
	want    []byte
	meta    SndRcvInfo
}

// Reusing assembly storage must not overwrite results across size classes or
// impose a message limit independent of the caller's max.
func TestReadMsgLargeMixedResultsRemainOwned(t *testing.T) {
	sizes := []int{
		4095, 168, 4096, 255, 4097, 256, 4136, 257,
		2047, 2048, 2049, 8191, 8192, 8193,
		// Repeat each boundary with both exact and larger maximums below.
		32767, 32767, 32768, 32768, 32769, 32769,
		65535, 65536, 70000,
		4136, 168, 4096,
	}
	conn := newScriptedReadConn(t, nil)
	retained := make([]retainedLargeRead, 0, len(sizes))
	for i, size := range sizes {
		payload := fill(size)
		payload[0] = byte(i)
		first := SndRcvInfo{
			Stream: uint16(i), SSN: uint16(i + 1), Flags: SCTP_UNORDERED,
			PPID: uint32(0x11220000 + i), Context: uint32(i + 3),
			TTL: 4, TSN: uint32(i + 5), CumTSN: 6, AssocID: int32(-i - 1),
		}
		other := SndRcvInfo{Stream: 31, PPID: 0xffffffff, AssocID: 32}
		cut := size / 2
		receiver := &scriptedRecvmsg{steps: []scriptedRecvmsgStep{
			{data: payload[:cut], oob: buildSndRcvCmsg(&first)},
			{data: payload[cut:], oob: buildSndRcvCmsg(&other), flags: syscall.MSG_EOR},
		}}
		// Alternate exact limits with larger limits to exercise both completion
		// at max and completion before the end of an assembly buffer.
		max := size
		if i%2 == 0 {
			max += 4096
		}
		got, info, err := conn.readMsgUsing(max, receiver.receive)
		if err != nil {
			t.Fatalf("size=%d max=%d: %v", size, max, err)
		}
		retained = append(retained, retainedLargeRead{got, info, payload, first})
		for j, previous := range retained {
			requireOwnedReadResult(t, fmt.Sprintf("record %d after read %d", j, i),
				previous.payload, previous.want, previous.info, previous.meta)
		}
	}

	for i := range retained {
		if retained[i].info == nil || len(retained[i].payload) == 0 {
			t.Fatal("cannot verify caller mutation of an incomplete result")
		}
		retained[i].payload[0] ^= 0xff
		retained[i].info.Stream ^= 0xffff
		for j := i + 1; j < len(retained); j++ {
			other := retained[j]
			requireOwnedReadResult(t, fmt.Sprintf("record %d after mutating %d", j, i),
				other.payload, other.want, other.info, other.meta)
		}
	}
}

// The rejected prefix is caller-owned too, and draining must leave the next
// large record intact even when its allocation uses the same size class.
func TestReadMsgLargeRejectedPrefixSurvivesNextRecord(t *testing.T) {
	for _, max := range []int{257, 2048, 4095, 4096, 4097, 4136, 8192, 32767, 32768, 32769, 65535} {
		t.Run(fmt.Sprint(max), func(t *testing.T) {
			oversized := fill(max + 8193)
			next := bytes.Repeat([]byte{0xd3, 0x19, 0x6e}, (max+2)/3)[:max]
			first := SndRcvInfo{Stream: 1, PPID: 0x11223344, AssocID: -1}
			nextInfo := SndRcvInfo{Stream: 2, PPID: 0xaabbccdd, AssocID: 2}
			receiver := &scriptedRecvmsg{steps: []scriptedRecvmsgStep{
				{data: oversized, oob: buildSndRcvCmsg(&first), flags: syscall.MSG_EOR},
				{data: next, oob: buildSndRcvCmsg(&nextInfo), flags: syscall.MSG_EOR},
			}}
			conn := newScriptedReadConn(t, nil)
			got, info, err := conn.readMsgUsing(max, receiver.receive)
			if !errors.Is(err, ErrMsgTooLong) {
				t.Fatalf("oversized read: %v, want ErrMsgTooLong", err)
			}
			requireOwnedReadResult(t, "rejected prefix", got, oversized[:max], info, first)
			later, laterInfo, err := conn.readMsgUsing(max, receiver.receive)
			if err != nil {
				t.Fatalf("read after oversized record: %v", err)
			}
			requireOwnedReadResult(t, "next record", later, next, laterInfo, nextInfo)
			requireOwnedReadResult(t, "retained rejected prefix", got, oversized[:max], info, first)
		})
	}
}

// Nested handlers can hold more active records than a cache class can retain.
// A cache miss must not wait for an outer handler or alias its active storage.
func TestReadMsgLargeNestedCacheExhaustion(t *testing.T) {
	const records = 6
	receiver := &scriptedRecvmsg{}
	wants := make([]retainedLargeRead, records)
	for i := range wants {
		payload := bytes.Repeat([]byte{byte(i + 1)}, 4136)
		first := SndRcvInfo{Stream: uint16(i + 1), PPID: uint32(0x11223300 + i), AssocID: int32(i + 1)}
		wants[i] = retainedLargeRead{want: payload, meta: first}
		receiver.steps = append(receiver.steps, scriptedRecvmsgStep{
			data: payload[:4096], oob: buildSndRcvCmsg(&first),
		})
		if i < records-1 {
			receiver.steps = append(receiver.steps, scriptedRecvmsgStep{
				data: ownershipNotification(byte(i)), flags: MSG_NOTIFICATION | syscall.MSG_EOR,
			})
		}
		receiver.steps = append(receiver.steps, scriptedRecvmsgStep{
			data: payload[4096:], flags: syscall.MSG_EOR,
		})
	}

	conn := newScriptedReadConn(t, nil)
	var read func() error
	started, active, peak := 0, 0, 0
	read = func() error {
		i := started
		if i >= records {
			return errors.New("unexpected nested read")
		}
		started++
		active++
		if active > peak {
			peak = active
		}
		defer func() { active-- }()
		data, info, err := conn.readMsgUsing(65535, receiver.receive)
		if err != nil {
			return err
		}
		wants[i].payload, wants[i].info = data, info
		for j := i; j < records; j++ {
			previous := wants[j]
			requireOwnedReadResult(t, fmt.Sprintf("nested record %d after return %d", j, i),
				previous.payload, previous.want, previous.info, previous.meta)
		}
		return nil
	}
	conn.notificationHandler = func([]byte) error { return read() }
	if err := read(); err != nil {
		t.Fatal(err)
	}
	if started != records || peak != records || active != 0 {
		t.Fatalf("nested reads: started=%d peak=%d active=%d", started, peak, active)
	}
	// Returned results must also survive subsequent same-class reuse.
	if _, _, err := conn.readMsgUsing(65535, readMsgFixture(fill(4136), nil)); err != nil {
		t.Fatal(err)
	}
	for i, previous := range wants {
		requireOwnedReadResult(t, fmt.Sprintf("retained nested record %d", i),
			previous.payload, previous.want, previous.info, previous.meta)
	}
}

// Both the fragmented application record and the queued notifications exceed
// the initial receive buffer. Nested reads must not reuse storage still owned
// by the outer call or by the handler's earlier result.
func TestReadMsgLargeInterleavedNotificationReentry(t *testing.T) {
	outer := fill(4136)
	nested := bytes.Repeat([]byte{0xd7}, 65536)
	last := bytes.Repeat([]byte{0x3a}, 4136)
	firstInfo := SndRcvInfo{Stream: 1, PPID: 0x11223344, Context: 5, AssocID: -1}
	otherInfo := SndRcvInfo{Stream: 9, PPID: 0xffffffff, Context: 10, AssocID: 9}
	nestedInfo := SndRcvInfo{Stream: 2, PPID: 0x55667788, Context: 6, AssocID: 2}
	lastInfo := SndRcvInfo{Stream: 3, PPID: 0x99aabbcc, Context: 7, AssocID: 3}
	notes := [][]byte{
		notifSized(SCTP_ASSOC_CHANGE, 4097, 4097, 0x5a),
		notifSized(SCTP_ASSOC_CHANGE, 4136, 4136, 0x6b),
	}
	for _, note := range notes {
		nativeEndian.PutUint16(note[8:10], uint16(SCTP_COMM_UP))
	}
	receiver := &scriptedRecvmsg{steps: []scriptedRecvmsgStep{
		{data: outer[:2049], oob: buildSndRcvCmsg(&firstInfo)},
		{data: notes[0][:257], flags: MSG_NOTIFICATION},
		{data: notes[0][257:], flags: MSG_NOTIFICATION | syscall.MSG_EOR},
		{data: notes[1], flags: MSG_NOTIFICATION | syscall.MSG_EOR},
		{data: outer[2049:], oob: buildSndRcvCmsg(&otherInfo), flags: syscall.MSG_EOR},
		{data: nested, oob: buildSndRcvCmsg(&nestedInfo), flags: syscall.MSG_EOR},
		{data: last, oob: buildSndRcvCmsg(&lastInfo), flags: syscall.MSG_EOR},
	}}
	var conn *SCTPConn
	var nestedData, lastData []byte
	var nestedMeta, lastMeta *SndRcvInfo
	var retainedNotes [][]byte
	handler := func(note []byte) error {
		index := len(retainedNotes)
		if index >= len(notes) || !bytes.Equal(note, notes[index]) {
			return errors.New("notification bytes or order changed")
		}
		if _, err := ParseNotification(note); err != nil {
			return err
		}
		retainedNotes = append(retainedNotes, note)
		var err error
		if index == 0 {
			nestedData, nestedMeta, err = conn.readMsgUsing(70000, receiver.receive)
		} else {
			lastData, lastMeta, err = conn.readMsgUsing(65535, receiver.receive)
		}
		return err
	}
	conn = newScriptedReadConn(t, handler)
	got, info, err := conn.readMsgUsing(65535, receiver.receive)
	if err != nil {
		t.Fatalf("outer read: %v", err)
	}
	if len(retainedNotes) != len(notes) {
		t.Fatalf("handler calls = %d, want %d", len(retainedNotes), len(notes))
	}
	requireOwnedReadResult(t, "outer after nested reads", got, outer, info, firstInfo)
	requireOwnedReadResult(t, "first nested read", nestedData, nested, nestedMeta, nestedInfo)
	requireOwnedReadResult(t, "second nested read", lastData, last, lastMeta, lastInfo)
	for i, note := range retainedNotes {
		if !bytes.Equal(note, notes[i]) {
			t.Errorf("retained notification %d changed after nested reads", i)
		}
	}
}

func TestReadMsgLargeControlTruncationRetainsPayload(t *testing.T) {
	payload := fill(4136)
	next := bytes.Repeat([]byte{0x9d}, len(payload))
	first := SndRcvInfo{Stream: 1, PPID: 0x11223344, AssocID: -1}
	other := SndRcvInfo{Stream: 2, PPID: 0xaabbccdd, AssocID: 2}
	receiver := &scriptedRecvmsg{steps: []scriptedRecvmsgStep{
		{data: payload[:4096], oob: buildSndRcvCmsg(&first)},
		{data: payload[4096:], oob: buildSndRcvCmsg(&other), flags: syscall.MSG_CTRUNC | syscall.MSG_EOR},
		{data: next, oob: buildSndRcvCmsg(&other), flags: syscall.MSG_EOR},
	}}
	conn := newScriptedReadConn(t, nil)
	got, info, err := conn.readMsgUsing(65535, receiver.receive)
	if !errors.Is(err, ErrControlTruncated) {
		t.Fatalf("read: %v, want ErrControlTruncated", err)
	}
	later, laterInfo, err := conn.readMsgUsing(65535, receiver.receive)
	if err != nil {
		t.Fatalf("read after truncated control: %v", err)
	}
	requireOwnedReadResult(t, "truncated control result after later read", got, payload, info, first)
	requireOwnedReadResult(t, "later record", later, next, laterInfo, other)
}

func TestReadMsgLargeInterruptedPrefix(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cause error
		want  error
	}{
		{"receive_error", syscall.EIO, syscall.EIO},
		{"EOF", nil, io.EOF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := fill(4136)
			first := SndRcvInfo{Stream: 1, PPID: 0x12345678, AssocID: -1}
			receiver := &scriptedRecvmsg{steps: []scriptedRecvmsgStep{
				{data: payload, oob: buildSndRcvCmsg(&first)},
			}}
			receive := func(fd int, dst, oob []byte, flags int) (int, int, int, error) {
				if receiver.step == len(receiver.steps) {
					return 0, 0, 0, tc.cause
				}
				return receiver.receive(fd, dst, oob, flags)
			}
			conn := newScriptedReadConn(t, nil)
			got, info, err := conn.readMsgUsing(65535, receive)
			if !errors.Is(err, ErrMessageInterrupted) || !errors.Is(err, tc.want) {
				t.Fatalf("read: %v, want ErrMessageInterrupted and %v", err, tc.want)
			}
			requireOwnedReadResult(t, "interrupted prefix", got, payload, info, first)
			if conn.fd() != -1 {
				t.Fatal("interrupted record left the connection open")
			}
			other := newScriptedReadConn(t, nil)
			_, _, readErr := other.readMsgUsing(65535, readMsgFixture(bytes.Repeat([]byte{0xa5}, 4136), nil))
			if readErr != nil {
				t.Fatalf("subsequent read: %v", readErr)
			}
			requireOwnedReadResult(t, "interrupted prefix after storage reuse", got, payload, info, first)
		})
	}
}

func TestReadMsgLargePollInterruptionRetainsPrefix(t *testing.T) {
	for _, closeConn := range []bool{false, true} {
		t.Run(fmt.Sprintf("close=%t", closeConn), func(t *testing.T) {
			_, conn := eorPair(t)
			payload := fill(4136)
			first := SndRcvInfo{Stream: 1, PPID: 0x12345678}
			receiver := &scriptedRecvmsg{steps: []scriptedRecvmsgStep{
				{data: payload, oob: buildSndRcvCmsg(&first)},
			}}
			partial := make(chan struct{}, 1)
			interrupted := make(chan error, 1)
			go func() {
				<-partial
				if closeConn {
					interrupted <- conn.Close()
				} else {
					interrupted <- conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
				}
			}()
			if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			receive := func(fd int, dst, oob []byte, flags int) (int, int, int, error) {
				if receiver.step == len(receiver.steps) {
					select {
					case partial <- struct{}{}:
					default:
					}
					return 0, 0, 0, syscall.EAGAIN
				}
				return receiver.receive(fd, dst, oob, flags)
			}
			got, info, err := conn.readMsgUsing(65535, receive)
			want := error(os.ErrDeadlineExceeded)
			if closeConn {
				want = net.ErrClosed
			}
			if !errors.Is(err, ErrMessageInterrupted) || !errors.Is(err, want) {
				t.Fatalf("read: %v, want ErrMessageInterrupted and %v", err, want)
			}
			if interruptErr := <-interrupted; interruptErr != nil {
				t.Fatalf("interrupt read: %v", interruptErr)
			}
			other := newScriptedReadConn(t, nil)
			if _, _, readErr := other.readMsgUsing(65535, readMsgFixture(bytes.Repeat([]byte{0x5a}, 4136), nil)); readErr != nil {
				t.Fatal(readErr)
			}
			requireOwnedReadResult(t, "poll-interrupted prefix after reuse", got, payload, info, first)
		})
	}
}

func TestReadMsgLargeHandlerPanicReleasesScratch(t *testing.T) {
	payload := fill(4136)
	conn := newScriptedReadConn(t, nil)
	if _, _, err := conn.readMsgUsing(65535, readMsgFixture(payload, nil)); err != nil {
		t.Fatal(err)
	}
	counts := func() [4]int {
		var result [4]int
		for i := range readMsgBuffers {
			p := &readMsgBuffers[i]
			p.mu.Lock()
			result[i] = p.count
			p.mu.Unlock()
		}
		return result
	}
	before := counts()
	panicValue := errors.New("handler panic")
	conn.notificationHandler = func([]byte) error { panic(panicValue) }
	receiver := &scriptedRecvmsg{steps: []scriptedRecvmsgStep{
		{data: payload[:4096]},
		{data: ownershipNotification(0x5a), flags: MSG_NOTIFICATION | syscall.MSG_EOR},
		{data: payload[4096:], flags: syscall.MSG_EOR},
	}}
	func() {
		defer func() {
			if got := recover(); got != panicValue {
				t.Errorf("panic = %v, want handler panic", got)
			}
		}()
		_, _, _ = conn.readMsgUsing(65535, receiver.receive)
	}()
	if after := counts(); after != before {
		t.Fatalf("panic leaked assembly storage: cache counts %v, want %v", after, before)
	}
	got, _, err := conn.readMsgUsing(65535, readMsgFixture(payload, nil))
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("read after handler panic: length=%d err=%v", len(got), err)
	}
}

// Concurrent readers retain mixed-size records, including records beyond the
// commonly used 65535 limit. Payload identity determines the expected metadata,
// independently of goroutine completion order.
func TestReadMsgLargeConcurrentMixedRecords(t *testing.T) {
	client, server := sndinfoPair(t)
	deadline := time.Now().Add(10 * time.Second)
	if err := client.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if err := server.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	sizes := []int{4136, 168, 65535, 256, 65536, 4095, 4096, 4097}
	wants := make([][]byte, len(sizes))
	for i, size := range sizes {
		wants[i] = fill(size)
		binary.BigEndian.PutUint32(wants[i][:4], uint32(i))
	}
	type result struct {
		payload []byte
		info    *SndRcvInfo
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, len(sizes))
	for range sizes {
		go func() {
			<-start
			payload, info, err := server.ReadMsg(70000)
			results <- result{payload, info, err}
		}()
	}
	close(start)
	for i, payload := range wants {
		n, err := client.SCTPWrite(payload, &SndRcvInfo{Stream: uint16(i % 4), PPID: uint32(i)})
		if err != nil || n != len(payload) {
			t.Fatalf("write record %d = (%d, %v), want %d bytes", i, n, err, len(payload))
		}
	}
	retained := make([]result, len(sizes))
	for i := range retained {
		retained[i] = <-results
	}
	seen := make(map[uint32]bool, len(sizes))
	for _, got := range retained {
		if got.err != nil || got.info == nil || len(got.payload) < 4 {
			t.Errorf("read result length=%d metadata=%+v error=%v", len(got.payload), got.info, got.err)
			continue
		}
		id := binary.BigEndian.Uint32(got.payload[:4])
		if id >= uint32(len(wants)) || seen[id] {
			t.Errorf("unknown or duplicate record identity %d", id)
			continue
		}
		seen[id] = true
		if !bytes.Equal(got.payload, wants[id]) {
			t.Errorf("record %d changed after concurrent later reads", id)
		}
		if got.info.PPID != id || got.info.Stream != uint16(id%4) {
			t.Errorf("record %d metadata = %+v", id, got.info)
		}
	}
	if len(seen) != len(sizes) {
		t.Errorf("received %d distinct records, want %d", len(seen), len(sizes))
	}
}
