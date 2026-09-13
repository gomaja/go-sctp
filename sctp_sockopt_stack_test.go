//go:build linux

package sctp

import (
	"errors"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

type stackGrowthRawConn struct {
	syscall.RawConn
}

func (c stackGrowthRawConn) Control(f func(uintptr)) error {
	return growSocketOptionStack(32, func() error { return c.RawConn.Control(f) })
}

// Grow the caller's stack while its socket-option buffer is in use. Keeping
// pointers intact must not depend on an unusually large initial stack.
//
//go:noinline
func growSocketOptionStack(depth int, f func() error) error {
	var frame [4096]byte
	frame[0] = byte(depth)
	var err error
	if depth == 0 {
		err = f()
	} else {
		err = growSocketOptionStack(depth-1, f)
	}
	runtime.KeepAlive(&frame)
	return err
}

func TestSubscribedEventsSurvivesStackGrowth(t *testing.T) {
	_, server := eorPair(t)
	// Configure independently through the raw syscall boundary, so a broken
	// setter cannot make the getter agree with the same bug.
	param := EventSubscribe{DataIO: 1}
	if _, _, err := setsockopt(server.fd(), SCTP_EVENTS,
		uintptr(unsafe.Pointer(&param)), unsafe.Sizeof(param)); err != nil {
		t.Fatal(err)
	}
	server.raw = stackGrowthRawConn{server.raw}
	got, err := server.SubscribedEvents()
	if err != nil || got != SCTP_EVENT_DATA_IO {
		t.Fatalf("SubscribedEvents after stack growth = %#x, %v; want %#x, nil", got, err, SCTP_EVENT_DATA_IO)
	}
}

func TestRawGetsockoptSurvivesStackGrowth(t *testing.T) {
	_, server := eorPair(t)
	if err := setsockoptInt32(server.fd(), SCTP_NODELAY, 1); err != nil {
		t.Fatal(err)
	}
	server.raw = stackGrowthRawConn{server.raw}
	var got [2]int32
	optlen := uint32(unsafe.Sizeof(got))
	_, _, err := server.Getsockopt(SCTP_NODELAY,
		uintptr(unsafe.Pointer(&got)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil || got != [2]int32{1, 0} || optlen != 4 {
		t.Fatalf("Getsockopt after stack growth = %v, length %d, %v; want [1 0], 4, nil", got, optlen, err)
	}
}

func TestInternalRawGetsockoptSurvivesStackGrowth(t *testing.T) {
	_, server := eorPair(t)
	if err := setsockoptInt32(server.fd(), SCTP_NODELAY, 1); err != nil {
		t.Fatal(err)
	}
	server.raw = stackGrowthRawConn{server.raw}
	var got [2]int32
	optlen := uint32(unsafe.Sizeof(got))
	_, _, err := server.getsockoptRaw(SCTP_NODELAY,
		uintptr(unsafe.Pointer(&got)), uintptr(unsafe.Pointer(&optlen)))
	if err != nil || got != [2]int32{1, 0} || optlen != 4 {
		t.Fatalf("getsockoptRaw after stack growth = %v, length %d, %v; want [1 0], 4, nil", got, optlen, err)
	}
}

func TestSubscribeEventsSurvivesStackGrowth(t *testing.T) {
	client, server := eorPair(t)
	server.raw = stackGrowthRawConn{server.raw}
	for _, want := range []int{SCTP_EVENT_DATA_IO, 0} {
		if err := server.SubscribeEvents(want); err != nil {
			t.Fatal(err)
		}
		// Inspect the actual kernel option independently of SubscribedEvents.
		var got EventSubscribe
		optlen := uint32(unsafe.Sizeof(got))
		if _, _, err := getsockopt(server.fd(), SCTP_EVENTS,
			uintptr(unsafe.Pointer(&got)), &optlen); err != nil {
			t.Fatal(err)
		}
		if got != (EventSubscribe{DataIO: uint8(want)}) {
			t.Fatalf("kernel subscription = %+v, want only DATA_IO=%d", got, want)
		}
		payload := []byte("subscription survives stack growth")
		if _, err := client.SCTPWrite(payload, &SndRcvInfo{Stream: 1, PPID: 0x11223344}); err != nil {
			t.Fatal(err)
		}
		if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 128)
		n, info, flags, err := server.SCTPReadFlags(buf)
		if err != nil || string(buf[:n]) != string(payload) || flags != syscall.MSG_EOR {
			t.Fatalf("read = %q, flags %#x, %v", buf[:n], flags, err)
		}
		if want == 0 {
			if info != nil {
				t.Fatalf("unexpected metadata with subscription off: %+v", info)
			}
		} else if info == nil || info.Stream != 1 || info.PPID != 0x11223344 {
			t.Fatalf("metadata = %+v, want stream 1 PPID 0x11223344", info)
		}
	}
}

var errOptionFinalized = errors.New("socket option finalized during Control")

type collectingRawConn struct {
	syscall.RawConn
	finalized <-chan struct{}
}

func (c collectingRawConn) Control(f func(uintptr)) error {
	runtime.GC()
	runtime.GC()
	select {
	case <-c.finalized:
		return errOptionFinalized
	case <-time.After(20 * time.Millisecond):
		return c.RawConn.Control(f)
	}
}

type finalizableRtoOption struct {
	info RtoInfo
	// Avoid the tiny allocator's shared-block finalization behavior.
	_ [64]byte
}

func newFinalizableRtoOption(done chan<- struct{}) *RtoInfo {
	option := &finalizableRtoOption{info: RtoInfo{Initial: 2345, Max: 56789, Min: 678}}
	runtime.SetFinalizer(option, func(*finalizableRtoOption) { close(done) })
	return &option.info
}

func TestSetRtoInfoKeepsOptionAlive(t *testing.T) {
	_, server := eorPair(t)
	done := make(chan struct{})
	raw := server.raw
	server.raw = collectingRawConn{raw, done}
	if err := server.SetRtoInfo(newFinalizableRtoOption(done)); err != nil {
		t.Fatalf("SetRtoInfo: %v", err)
	}
	server.raw = raw
	verifyLifetimeRto(t, server)
	verifyOptionReleased(t, done)
}

func TestRawSetsockoptKeepsOptionAlive(t *testing.T) {
	_, server := eorPair(t)
	done := make(chan struct{})
	raw := server.raw
	server.raw = collectingRawConn{raw, done}
	if _, _, err := server.Setsockopt(SCTP_RTOINFO,
		uintptr(unsafe.Pointer(newFinalizableRtoOption(done))), unsafe.Sizeof(RtoInfo{})); err != nil {
		t.Fatalf("Setsockopt: %v", err)
	}
	server.raw = raw
	verifyLifetimeRto(t, server)
	verifyOptionReleased(t, done)
}

func verifyLifetimeRto(t *testing.T, conn *SCTPConn) {
	t.Helper()
	got, err := conn.GetRtoInfo()
	if err != nil || got == nil || got.Initial != 2345 || got.Min != 678 || got.Max != 56789 {
		t.Fatalf("RTO after collection = %+v, %v; want Initial=2345 Min=678 Max=56789", got, err)
	}
}

func verifyOptionReleased(t *testing.T, done <-chan struct{}) {
	t.Helper()
	runtime.GC()
	runtime.GC()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("option remained reachable after the syscall returned")
	}
}
