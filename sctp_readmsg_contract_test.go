//go:build linux
// +build linux

package sctp

import (
	"bytes"
	"runtime"
	"runtime/debug"
	"testing"
)

// clearReadMsgClass empties one size class so the next borrow must allocate.
// It nils the slots directly instead of draining through get, because get on an
// empty class allocates and would be counted as part of the measurement.
func clearReadMsgClass(p *readMsgBufferCache) {
	p.mu.Lock()
	for i := range p.buffers {
		p.buffers[i] = nil
	}
	p.count = 0
	p.mu.Unlock()
}

// measureReadMsg reports allocations and bytes per record over a warmed loop.
// before runs inside the measured loop, so it must not allocate.
//
// Collection is paused for the measured loop. The cold case allocates a fresh
// buffer every iteration, and the resulting collections are themselves counted
// by MemStats: that noise reads as 5.033 allocations per record at 1000 records
// and 5.002 at 10000, shrinking with the sample because it is not a per-call
// cost. With the collector paused both cases land on exact integers, which is
// what lets this test assert the documented figures rather than a tolerance.
func measureReadMsg(t *testing.T, conn *SCTPConn, size, max int, control []byte,
	before func()) (allocs, bytesPer float64) {
	t.Helper()

	payload := fill(size)
	want := payload
	if size > max {
		want = payload[:max]
	}
	receive := readMsgFixture(payload, control)
	read := func() {
		if before != nil {
			before()
		}
		got, info, err := conn.readMsgUsing(max, receive)
		if !bytes.Equal(got, want) {
			t.Fatalf("payload len=%d want %d (err %v)", len(got), len(want), err)
		}
		if (control == nil) != (info == nil) {
			t.Fatalf("metadata presence = %v, want %v", info != nil, control != nil)
		}
	}

	for i := 0; i < 100; i++ {
		read()
	}
	defer debug.SetGCPercent(debug.SetGCPercent(-1))

	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	const records = 1000
	for i := 0; i < records; i++ {
		read()
	}
	runtime.ReadMemStats(&m1)

	return float64(m1.Mallocs-m0.Mallocs) / records,
		float64(m1.TotalAlloc-m0.TotalAlloc) / records
}

// Growing the heap costs a few runtime allocations of its own, which MemStats
// counts even with collection paused. The two margins below are on different
// scales on purpose, and sharing one between them made this test fail about a
// third of the time.
//
// Counts stay near exact: the small records land on integers and the worst
// case, a 65535-byte record with metadata, measured 6.003 per record. A margin
// well under 1 still rejects a change of a whole allocation per call, which is
// the regression worth catching.
//
// Bytes carry that same bookkeeping spread across a much larger number. The
// warm baseline for a 257-byte record measures 896.0 but drifts to 896.3, which
// is enough to put a 2048-byte delta at 2047.7. The margin only has to separate
// the class size from the alternatives a defect would produce — the record
// itself at 257, or a doubled class at 4096 — so a few bytes is ample.
const (
	allocMargin     = 0.05
	allocByteMargin = 16.0
)

func within(got, want, margin float64) bool {
	return got-want < margin && want-got < margin
}

// The ReadMsg documentation publishes a warm and a cold allocation figure and
// tells callers to budget against the cold one. TestReadMsgAllocationBudget
// guards loose ceilings so a regression cannot pass unnoticed; this test pins
// the exact published numbers, so the documentation cannot drift away from the
// implementation without failing here.
//
// It mutates the process-global cache, so it must not call t.Parallel. Go holds
// parallel tests paused until the sequential pass finishes, which is what keeps
// that safe.
func TestReadMsgDocumentedAllocationContract(t *testing.T) {
	if raceDetectorEnabled {
		t.Skip("the race detector allocates on its own account, so exact " +
			"per-call counts only hold without it; TestReadMsgAllocationBudget " +
			"keeps guarding the ceilings under -race")
	}
	_, conn := eorPair(t)
	meta := buildSndRcvCmsg(&SndRcvInfo{Stream: 3, PPID: 0x11223344})

	t.Run("warm", func(t *testing.T) {
		for _, tc := range []struct {
			name      string
			size, max int
			metadata  bool
			want      int
		}{
			// A record within the initial buffer never grows and never
			// borrows, so it stays one allocation cheaper than the rest.
			{"below-boundary", 168, 65535, false, 3},
			{"at-boundary", 256, 65535, false, 3},
			{"above-boundary", 257, 65535, false, 4},
			{"large", 65535, 65535, false, 4},
			// The initial buffer is min(256, max), so a small max still
			// admits its own largest record without growing.
			{"small-max", 168, 168, false, 3},

			{"below-boundary-metadata", 168, 65535, true, 5},
			{"at-boundary-metadata", 256, 65535, true, 5},
			{"above-boundary-metadata", 257, 65535, true, 6},
			{"large-metadata", 65535, 65535, true, 6},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var control []byte
				if tc.metadata {
					control = meta
				}
				got, bytesPer := measureReadMsg(t, conn, tc.size, tc.max, control, nil)
				t.Logf("%.4f allocations, %.1f bytes per record", got, bytesPer)
				if !within(got, float64(tc.want), allocMargin) {
					t.Fatalf("warm ReadMsg allocated %.4f times per record, documented %d",
						got, tc.want)
				}
			})
		}
	})

	// A call that finds its class empty allocates the whole class, not the
	// record. That is the figure callers are told to budget against, and for a
	// small record it dominates: 2048 bytes to carry 257.
	t.Run("cold", func(t *testing.T) {
		const size, max = 257, 65535
		class := &readMsgBuffers[0]

		warmAllocs, warmBytes := measureReadMsg(t, conn, size, max, nil, nil)
		coldAllocs, coldBytes := measureReadMsg(t, conn, size, max, nil, func() {
			clearReadMsgClass(class)
		})
		t.Logf("warm %.4f allocations / %.1f bytes; cold %.4f allocations / %.1f bytes",
			warmAllocs, warmBytes, coldAllocs, coldBytes)

		if !within(coldAllocs, warmAllocs+1, allocMargin) {
			t.Fatalf("cold ReadMsg allocated %.4f times per record, want warm+1 = %.4f",
				coldAllocs, warmAllocs+1)
		}
		if grew := coldBytes - warmBytes; !within(grew, float64(class.size), allocByteMargin) {
			t.Fatalf("cold ReadMsg allocated %.1f extra bytes per record, want the "+
				"whole %d-byte class", grew, class.size)
		}
		if class.size <= size {
			t.Fatalf("class %d does not exceed record %d; the documented "+
				"statement that a cold small record allocates more than itself "+
				"no longer holds", class.size, size)
		}
	})
}
