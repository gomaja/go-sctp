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
// implied. See the License for the specific language governing permissions
// and limitations under the License.

package sctp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

type scriptedRecvmsgStep struct {
	data  []byte
	oob   []byte
	flags int
}

// scriptedRecvmsg replaces only recvmsg. readMsgUsing still exercises the real
// poller lock, reassembly, ancillary parser, notification policy and ownership
// boundary. A step is one kernel record fragment; when dst is smaller than the
// step, receive splits it further just as recvmsg would.
type scriptedRecvmsg struct {
	steps  []scriptedRecvmsgStep
	step   int
	offset int
	calls  int
}

func (s *scriptedRecvmsg) receive(_ int, dst, oob []byte, _ int) (int, int, int, error) {
	s.calls++
	if s.step >= len(s.steps) {
		return 0, 0, 0, syscall.EIO
	}

	current := &s.steps[s.step]
	remaining := current.data[s.offset:]
	n := copy(dst, remaining)
	if n == 0 {
		return 0, 0, 0, syscall.ENOBUFS
	}

	// Poison the pooled ancillary buffer before every receive. A returned
	// SndRcvInfo that aliases it changes as soon as the next fragment arrives.
	for i := range oob {
		oob[i] = byte(0xa0 + s.calls%31)
	}
	oobn := copy(oob, current.oob)

	s.offset += n
	flags := current.flags
	if s.offset != len(current.data) {
		flags &^= syscall.MSG_EOR
		return n, oobn, flags, nil
	}

	s.step++
	s.offset = 0
	return n, oobn, flags, nil
}

type ownershipTestingTB interface {
	Helper()
	Fatalf(format string, args ...any)
	Cleanup(func())
}

// newScriptedReadConn supplies a real syscall.RawConn and poller without
// requiring a kernel SCTP association. The injected recvmsg function owns the
// receive queue, so an AF_UNIX socket pair is sufficient for these unit tests.
func newScriptedReadConn(t ownershipTestingTB, handler NotificationHandler) *SCTPConn {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}

	file := os.NewFile(uintptr(fds[0]), "readmsg-ownership")
	if file == nil {
		_ = syscall.Close(fds[0])
		_ = syscall.Close(fds[1])
		t.Fatalf("os.NewFile returned nil")
	}
	raw, err := file.SyscallConn()
	if err != nil {
		_ = file.Close()
		_ = syscall.Close(fds[1])
		t.Fatalf("SyscallConn: %v", err)
	}
	t.Cleanup(func() {
		_ = file.Close()
		_ = syscall.Close(fds[1])
	})
	return &SCTPConn{
		_fd:                 int32(fds[0]),
		file:                file,
		raw:                 raw,
		notificationHandler: handler,
	}
}

func ownershipNotification(fill byte) []byte {
	note := notifSized(SCTP_ASSOC_CHANGE, assocChangeMinSize,
		assocChangeMinSize, fill)
	nativeEndian.PutUint16(note[8:10], uint16(SCTP_COMM_UP))
	return note
}

func requireOwnedReadResult(t *testing.T, name string, payload, wantPayload []byte,
	info *SndRcvInfo, wantInfo SndRcvInfo,
) {
	t.Helper()
	if !bytes.Equal(payload, wantPayload) {
		t.Errorf("%s payload = %x, want %x", name, payload, wantPayload)
	}
	if info == nil {
		t.Errorf("%s metadata is nil, want %+v", name, wantInfo)
		return
	}
	if *info != wantInfo {
		t.Errorf("%s metadata = %+v, want %+v", name, *info, wantInfo)
	}
}

// TestReadMsgResultsSurviveInterleavedNotificationReentry catches three
// ownership regressions at once: returning the assembly scratch directly to a
// pool, returning metadata backed by the pooled oob buffer, or replacing the
// first fragment's metadata with a later fragment's. The handler performs the
// next read before the outer call returns, which makes all three mutations
// deterministic rather than dependent on a later garbage collection.
func TestReadMsgResultsSurviveInterleavedNotificationReentry(t *testing.T) {
	firstInfo := SndRcvInfo{
		Stream: 1, SSN: 2, Flags: SCTP_UNORDERED, PPID: 0x11223344,
		Context: 0x55667788, TTL: 9, TSN: 10, CumTSN: 11, AssocID: -12,
	}
	laterFragmentInfo := SndRcvInfo{
		Stream: 21, SSN: 22, Flags: SCTP_ADDR_OVER, PPID: 0xa1a2a3a4,
		Context: 25, TTL: 26, TSN: 27, CumTSN: 28, AssocID: 29,
	}
	nestedInfo := SndRcvInfo{
		Stream: 31, SSN: 32, Flags: SCTP_UNORDERED, PPID: 0xb1b2b3b4,
		Context: 35, TTL: 36, TSN: 37, CumTSN: 38, AssocID: 39,
	}
	thirdInfo := SndRcvInfo{
		Stream: 41, SSN: 42, Flags: SCTP_ABORT, PPID: 0xc1c2c3c4,
		Context: 45, TTL: 46, TSN: 47, CumTSN: 48, AssocID: 49,
	}
	note := ownershipNotification(0x5a)

	receiver := &scriptedRecvmsg{steps: []scriptedRecvmsgStep{
		{data: []byte("outer-prefix/"), oob: buildSndRcvCmsg(&firstInfo)},
		{data: note[:7], flags: MSG_NOTIFICATION},
		{data: note[7:], flags: MSG_NOTIFICATION | syscall.MSG_EOR},
		{data: []byte("outer-suffix"), oob: buildSndRcvCmsg(&laterFragmentInfo), flags: syscall.MSG_EOR},
		{data: []byte("nested-record"), oob: buildSndRcvCmsg(&nestedInfo), flags: syscall.MSG_EOR},
		{data: []byte("third-record"), oob: buildSndRcvCmsg(&thirdInfo), flags: syscall.MSG_EOR},
	}}

	var (
		conn       *SCTPConn
		nestedData []byte
		nestedMeta *SndRcvInfo
		nestedErr  error
		handled    int
	)
	handler := func(got []byte) error {
		handled++
		if !bytes.Equal(got, note) {
			return errors.New("notification callback received corrupt bytes")
		}
		if _, err := ParseNotification(got); err != nil {
			return err
		}
		nestedData, nestedMeta, nestedErr = conn.readMsgUsing(128, receiver.receive)
		return nestedErr
	}
	conn = newScriptedReadConn(t, handler)

	outerData, outerMeta, err := conn.readMsgUsing(128, receiver.receive)
	if err != nil {
		t.Fatalf("outer readMsgUsing: %v", err)
	}
	if handled != 1 {
		t.Fatalf("notification handler calls = %d, want 1", handled)
	}
	requireOwnedReadResult(t, "outer after nested read", outerData,
		[]byte("outer-prefix/outer-suffix"), outerMeta, firstInfo)
	requireOwnedReadResult(t, "nested", nestedData,
		[]byte("nested-record"), nestedMeta, nestedInfo)

	thirdData, thirdMeta, err := conn.readMsgUsing(128, receiver.receive)
	if err != nil {
		t.Fatalf("third readMsgUsing: %v", err)
	}
	requireOwnedReadResult(t, "outer after third read", outerData,
		[]byte("outer-prefix/outer-suffix"), outerMeta, firstInfo)
	requireOwnedReadResult(t, "nested after third read", nestedData,
		[]byte("nested-record"), nestedMeta, nestedInfo)
	requireOwnedReadResult(t, "third", thirdData,
		[]byte("third-record"), thirdMeta, thirdInfo)

	// Caller mutation of one result must not leak into either retained result.
	thirdData[0] ^= 0xff
	thirdMeta.Stream ^= 0xffff
	requireOwnedReadResult(t, "outer after caller mutation", outerData,
		[]byte("outer-prefix/outer-suffix"), outerMeta, firstInfo)
	requireOwnedReadResult(t, "nested after caller mutation", nestedData,
		[]byte("nested-record"), nestedMeta, nestedInfo)
}

// TestReadMsgLaterFragmentControlTruncationPreservesFirstInfo proves a later
// fragment cannot silently replace or invalidate already-copied first-fragment
// metadata. The truncated control data is still reported because discarding
// MSG_CTRUNC would hide a kernel boundary failure.
func TestReadMsgLaterFragmentControlTruncationPreservesFirstInfo(t *testing.T) {
	wantInfo := SndRcvInfo{
		Stream: 3, SSN: 4, Flags: SCTP_UNORDERED, PPID: 0x01020304,
		Context: 6, TTL: 7, TSN: 8, CumTSN: 9, AssocID: 10,
	}
	otherInfo := SndRcvInfo{
		Stream: 13, SSN: 14, Flags: SCTP_ABORT, PPID: 0xaabbccdd,
		Context: 16, TTL: 17, TSN: 18, CumTSN: 19, AssocID: 20,
	}
	nextInfo := SndRcvInfo{Stream: 23, PPID: 0x23232323, AssocID: 24}
	receiver := &scriptedRecvmsg{steps: []scriptedRecvmsgStep{
		{data: []byte("trusted-"), oob: buildSndRcvCmsg(&wantInfo)},
		{data: []byte("payload"), oob: buildSndRcvCmsg(&otherInfo), flags: syscall.MSG_CTRUNC | syscall.MSG_EOR},
		{data: []byte("next"), oob: buildSndRcvCmsg(&nextInfo), flags: syscall.MSG_EOR},
	}}
	conn := newScriptedReadConn(t, nil)

	got, info, err := conn.readMsgUsing(64, receiver.receive)
	if !errors.Is(err, ErrControlTruncated) {
		t.Fatalf("readMsgUsing error = %v, want ErrControlTruncated", err)
	}
	requireOwnedReadResult(t, "truncated record", got,
		[]byte("trusted-payload"), info, wantInfo)

	next, nextMeta, err := conn.readMsgUsing(64, receiver.receive)
	if err != nil {
		t.Fatalf("read after truncated control: %v", err)
	}
	requireOwnedReadResult(t, "record after truncation", next,
		[]byte("next"), nextMeta, nextInfo)
}

// TestReadMsgMalformedFirstControlDoesNotLosePayload catches an optimization
// that treats a non-empty but unparsable control buffer as absent. The payload
// record is complete and remains available, while its metadata is rejected.
func TestReadMsgMalformedFirstControlDoesNotLosePayload(t *testing.T) {
	nextInfo := SndRcvInfo{Stream: 7, PPID: 0x71727374, AssocID: 8}
	badHeader := syscall.Cmsghdr{Level: syscall.IPPROTO_SCTP, Type: SCTP_CMSG_SNDRCV}
	badHeader.SetLen(syscall.CmsgLen(1)) // Declares one data byte that is absent.
	malformed := append([]byte(nil), toBuf(&badHeader)...)
	receiver := &scriptedRecvmsg{steps: []scriptedRecvmsgStep{
		{data: []byte("complete-with-bad-control"), oob: malformed, flags: syscall.MSG_EOR},
		{data: []byte("next"), oob: buildSndRcvCmsg(&nextInfo), flags: syscall.MSG_EOR},
	}}
	conn := newScriptedReadConn(t, nil)

	got, info, err := conn.readMsgUsing(64, receiver.receive)
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("readMsgUsing error = %v, want EINVAL for malformed control", err)
	}
	if info != nil {
		t.Fatalf("metadata = %+v, want nil for malformed control", info)
	}
	if !bytes.Equal(got, []byte("complete-with-bad-control")) {
		t.Fatalf("payload = %q, want complete record", got)
	}

	next, nextMeta, err := conn.readMsgUsing(64, receiver.receive)
	if err != nil {
		t.Fatalf("read after malformed control: %v", err)
	}
	requireOwnedReadResult(t, "record after malformed control", next,
		[]byte("next"), nextMeta, nextInfo)
}

// TestReadMsgBoundsQueuedNotificationRetention covers the aggregate bound, not
// merely one oversized event. A notification exactly at the per-event limit is
// deliverable; another valid event between the same application's fragments
// must be drained but not retained or delivered once the queue would exceed the
// bound. The next application record must remain framed correctly.
func TestReadMsgBoundsQueuedNotificationRetention(t *testing.T) {
	atLimit := notifSized(SCTP_ASSOC_CHANGE, NotificationReassemblyLimit,
		NotificationReassemblyLimit, 0x66)
	nativeEndian.PutUint16(atLimit[8:10], uint16(SCTP_COMM_UP))
	overAggregate := ownershipNotification(0x77)

	var handledLengths []int
	conn := newScriptedReadConn(t, func(note []byte) error {
		handledLengths = append(handledLengths, len(note))
		return nil
	})
	receiver := &scriptedRecvmsg{steps: []scriptedRecvmsgStep{
		{data: []byte("before/")},
		{data: atLimit, flags: MSG_NOTIFICATION | syscall.MSG_EOR},
		{data: overAggregate, flags: MSG_NOTIFICATION | syscall.MSG_EOR},
		{data: []byte("after"), flags: syscall.MSG_EOR},
		{data: []byte("next-record"), flags: syscall.MSG_EOR},
	}}

	got, info, err := conn.readMsgUsing(64, receiver.receive)
	if !errors.Is(err, ErrNotificationTooLong) {
		t.Fatalf("readMsgUsing error = %v, want ErrNotificationTooLong", err)
	}
	if info != nil {
		t.Fatalf("metadata = %+v, want nil", info)
	}
	if !bytes.Equal(got, []byte("before/after")) {
		t.Fatalf("payload = %q, want complete application record", got)
	}
	if len(handledLengths) != 1 || handledLengths[0] != NotificationReassemblyLimit {
		t.Fatalf("handler lengths = %v, want [%d]", handledLengths,
			NotificationReassemblyLimit)
	}

	next, _, err := conn.readMsgUsing(64, receiver.receive)
	if err != nil {
		t.Fatalf("read after aggregate notification overflow: %v", err)
	}
	if !bytes.Equal(next, []byte("next-record")) {
		t.Fatalf("next payload = %q, want next-record", next)
	}
}

// TestConcurrentReadMsgResultsRemainIndependent drives the public API over a
// real SCTP association. Every reader receives one multi-fragment record, then
// retains both payload and metadata until all later reads have completed. The
// payload embeds the PPID, so record stealing and metadata/result aliasing are
// observable without relying on goroutine completion order.
func TestConcurrentReadMsgResultsRemainIndependent(t *testing.T) {
	client, server := sndinfoPair(t)
	if err := server.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	const records = 12
	wants := make(map[uint32][]byte, records)
	for i := 0; i < records; i++ {
		ppid := uint32(0x70000000 + i)
		payload := fill(4096 + i*37)
		binary.BigEndian.PutUint32(payload[:4], ppid)
		wants[ppid] = append([]byte(nil), payload...)
		n, err := client.SCTPWrite(payload, &SndRcvInfo{
			Stream: uint16(i % 4), PPID: ppid,
		})
		if err != nil {
			t.Fatalf("write record %d: %v", i, err)
		}
		if n != len(payload) {
			t.Fatalf("write record %d = %d bytes, want %d", i, n, len(payload))
		}
	}

	type result struct {
		payload []byte
		info    *SndRcvInfo
		err     error
	}
	start := make(chan struct{})
	results := make(chan result, records)
	var wg sync.WaitGroup
	for i := 0; i < records; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			payload, info, err := server.ReadMsg(16 * 1024)
			results <- result{payload: payload, info: info, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	retained := make([]result, 0, records)
	seen := make(map[uint32]bool, records)
	for got := range results {
		if got.err != nil {
			t.Errorf("ReadMsg: %v", got.err)
			continue
		}
		if got.info == nil {
			t.Error("ReadMsg returned nil metadata")
			continue
		}
		if len(got.payload) < 4 {
			t.Errorf("ReadMsg returned %d payload bytes", len(got.payload))
			continue
		}
		ppid := binary.BigEndian.Uint32(got.payload[:4])
		want, ok := wants[ppid]
		if !ok {
			t.Errorf("payload identifies unknown PPID %#x", ppid)
			continue
		}
		if seen[ppid] {
			t.Errorf("payload for PPID %#x returned more than once", ppid)
			continue
		}
		seen[ppid] = true
		if !bytes.Equal(got.payload, want) {
			t.Errorf("PPID %#x payload changed after concurrent later reads", ppid)
		}
		if got.info.PPID != ppid {
			t.Errorf("payload PPID %#x arrived with metadata PPID %#x", ppid,
				got.info.PPID)
		}
		wantStream := uint16((ppid - 0x70000000) % 4)
		if got.info.Stream != wantStream {
			t.Errorf("payload PPID %#x arrived on stream %d, want %d", ppid,
				got.info.Stream, wantStream)
		}
		retained = append(retained, got)
	}
	if len(seen) != records {
		t.Fatalf("received %d distinct records, want %d", len(seen), records)
	}

	// Mutating one caller-owned result must not affect another retained result.
	if len(retained) >= 2 {
		otherPayload := append([]byte(nil), retained[1].payload...)
		otherInfo := *retained[1].info
		retained[0].payload[0] ^= 0xff
		retained[0].info.Stream ^= 0xffff
		if !bytes.Equal(retained[1].payload, otherPayload) {
			t.Error("mutating one returned payload changed another")
		}
		if *retained[1].info != otherInfo {
			t.Error("mutating one returned SndRcvInfo changed another")
		}
	}
}

// FuzzReadMsgScriptedOwnership varies application fragment boundaries, the
// notification split, message sizes and max on the deterministic recvmsg seam.
// Each case performs a later read before checking the first result again, so a
// pooled-buffer ownership regression is part of every seed and fuzz mutation.
func FuzzReadMsgScriptedOwnership(f *testing.F) {
	f.Add([]byte("two fragments"), uint16(64), uint16(4), uint8(7))
	f.Add(fill(2048), uint16(2048), uint16(2047), uint8(1))
	f.Add(fill(2049), uint16(2048), uint16(2048), uint8(19))
	f.Add(fill(4097), uint16(4096), uint16(2049), uint8(8))

	handlerCalls := 0
	conn := newScriptedReadConn(f, func(note []byte) error {
		handlerCalls++
		if _, err := ParseNotification(note); err != nil {
			return err
		}
		return nil
	})

	f.Fuzz(func(t *testing.T, input []byte, rawMax, rawCut uint16, rawNoteCut uint8) {
		if len(input) > 16*1024-2 {
			input = input[:16*1024-2]
		}
		payload := make([]byte, 0, len(input)+2)
		payload = append(payload, 0x91)
		payload = append(payload, input...)
		payload = append(payload, 0x6e)
		max := int(rawMax)%(16*1024) + 1
		cut := int(rawCut)%(len(payload)-1) + 1

		firstInfo := SndRcvInfo{
			Stream: 1, SSN: 2, Flags: SCTP_UNORDERED, PPID: 0x10203040,
			Context: 5, TTL: 6, TSN: 7, CumTSN: 8, AssocID: -9,
		}
		laterInfo := SndRcvInfo{
			Stream: 11, SSN: 12, Flags: SCTP_ABORT, PPID: 0xa0b0c0d0,
			Context: 15, TTL: 16, TSN: 17, CumTSN: 18, AssocID: 19,
		}
		note := ownershipNotification(0x4c)
		noteCut := int(rawNoteCut)%(len(note)-1) + 1
		laterPayload := []byte("later-fuzz-record")
		laterResultInfo := SndRcvInfo{Stream: 21, PPID: 0x51525354, AssocID: 22}
		receiver := &scriptedRecvmsg{steps: []scriptedRecvmsgStep{
			{data: payload[:cut], oob: buildSndRcvCmsg(&firstInfo)},
			{data: note[:noteCut], flags: MSG_NOTIFICATION},
			{data: note[noteCut:], flags: MSG_NOTIFICATION | syscall.MSG_EOR},
			{data: payload[cut:], oob: buildSndRcvCmsg(&laterInfo), flags: syscall.MSG_EOR},
			{data: laterPayload, oob: buildSndRcvCmsg(&laterResultInfo), flags: syscall.MSG_EOR},
		}}

		callsBefore := handlerCalls
		got, info, err := conn.readMsgUsing(max, receiver.receive)
		wantLen := len(payload)
		if wantLen > max {
			wantLen = max
			if !errors.Is(err, ErrMsgTooLong) {
				t.Fatalf("len=%d max=%d error = %v, want ErrMsgTooLong", len(payload), max, err)
			}
		} else if err != nil {
			t.Fatalf("len=%d max=%d error = %v, want nil", len(payload), max, err)
		}
		want := append([]byte(nil), payload[:wantLen]...)
		requireOwnedReadResult(t, "fuzz first read", got, want, info, firstInfo)
		if handlerCalls != callsBefore+1 {
			t.Fatalf("notification handler calls advanced from %d to %d, want one call",
				callsBefore, handlerCalls)
		}

		later, laterMeta, err := conn.readMsgUsing(64, receiver.receive)
		if err != nil {
			t.Fatalf("later read: %v", err)
		}
		requireOwnedReadResult(t, "fuzz later read", later, laterPayload,
			laterMeta, laterResultInfo)
		requireOwnedReadResult(t, "fuzz first read after later read", got, want,
			info, firstInfo)
	})
}
