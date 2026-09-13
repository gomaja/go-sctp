//go:build linux
// +build linux

package sctp

import (
	"bytes"
	"fmt"
	"runtime"
	"syscall"
	"testing"
)

// readMsgFixture replaces only the kernel receive operation. The real poller,
// reassembly, metadata parser and result ownership remain under measurement;
// no sender allocations can be included in this process's allocation totals.
func readMsgFixture(payload []byte, control []byte) recvmsgFunc {
	offset := 0
	return func(_ int, dst, oob []byte, _ int) (int, int, int, error) {
		n := copy(dst, payload[offset:])
		offset += n
		flags := 0
		if offset == len(payload) {
			flags = syscall.MSG_EOR
			offset = 0
		}
		return n, copy(oob, control), flags, nil
	}
}

// Reintroducing eager scratch allocation or separately escaping receive state
// must exceed these budgets. They are regression guards for this implementation,
// not a public allocation guarantee or an allowance for an entire upper layer.
func TestReadMsgAllocationBudget(t *testing.T) {
	_, conn := eorPair(t)
	wantInfo := SndRcvInfo{Stream: 3, SSN: 7, PPID: 0x11223344,
		Context: 11, TTL: 13, TSN: 17, CumTSN: 19, AssocID: 23}
	control := buildSndRcvCmsg(&wantInfo)
	for _, tc := range []struct {
		size, max int
		bytes     uint64
		allocs    uint64
	}{
		{168, 168, 1024, 8},
		{168, 65535, 1024, 8},
		{255, 65535, 1024, 8},
		{256, 65535, 1024, 8},
		{257, 65535, 4096, 9},
		{2047, 65535, 4096, 9},
		{2048, 65535, 4096, 9},
		{2049, 65535, 8192, 10},
		{65535, 65535, 200000, 16},
	} {
		t.Run(fmt.Sprintf("size=%d/max=%d", tc.size, tc.max), func(t *testing.T) {
			payload := fill(tc.size)
			receive := readMsgFixture(payload, control)
			read := func() {
				got, info, err := conn.readMsgUsing(tc.max, receive)
				if err != nil || !bytes.Equal(got, payload) || info == nil || *info != wantInfo {
					t.Fatalf("ReadMsg returned invalid payload or metadata: len=%d info=%+v err=%v", len(got), info, err)
				}
			}
			for i := 0; i < 100; i++ {
				read()
			}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			const records = 1000
			for i := 0; i < records; i++ {
				read()
			}
			runtime.ReadMemStats(&after)
			allocated := (after.TotalAlloc - before.TotalAlloc) / records
			allocations := (after.Mallocs - before.Mallocs) / records
			t.Logf("%d bytes/record, %d allocations/record", allocated, allocations)
			if allocated > tc.bytes || allocations > tc.allocs {
				t.Fatalf("ReadMsg allocation budget exceeded: %d bytes, %d allocations; limits %d bytes, %d allocations",
					allocated, allocations, tc.bytes, tc.allocs)
			}
		})
	}
}

func BenchmarkReadMsgAssembly(b *testing.B) {
	for _, size := range []int{168, 255, 256, 257, 2047, 2048, 2049, 65535} {
		for _, metadata := range []bool{false, true} {
			b.Run(fmt.Sprintf("size=%d/metadata=%t", size, metadata), func(b *testing.B) {
				_, conn := benchPair(b)
				payload := fill(size)
				var control []byte
				wantInfo := SndRcvInfo{Stream: 3, PPID: 0x11223344}
				if metadata {
					control = buildSndRcvCmsg(&wantInfo)
				}
				receive := readMsgFixture(payload, control)
				b.SetBytes(int64(size))
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					got, info, err := conn.readMsgUsing(65535, receive)
					if err != nil || !bytes.Equal(got, payload) {
						b.Fatalf("ReadMsg payload: len=%d err=%v", len(got), err)
					}
					if (metadata && (info == nil || *info != wantInfo)) || (!metadata && info != nil) {
						b.Fatalf("ReadMsg metadata = %+v", info)
					}
				}
			})
		}
	}
}
