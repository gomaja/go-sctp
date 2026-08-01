//go:build linux
// +build linux

package sctp

import (
	"bytes"
	"errors"
	"syscall"
	"testing"
)

func useOOBPoolSize(t *testing.T, size int) {
	t.Helper()
	old := oobPool
	oobPool = newOOBPool(size)
	t.Cleanup(func() { oobPool = old })
}

func TestSCTPReadMsgExposesControlTruncation(t *testing.T) {
	client, server := eorPair(t)
	if err := server.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
		t.Fatalf("subscribe data info: %v", err)
	}

	want := []byte("control data must not disappear silently")
	if _, err := client.SCTPWrite(want, &SndRcvInfo{Stream: 1, PPID: 0x11223344}); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 256)
	oob := make([]byte, 1)
	n, oobn, flags, err := server.SCTPReadMsg(buf, oob)
	if err != nil {
		t.Fatalf("SCTPReadMsg: %v", err)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("payload = %q, want %q", buf[:n], want)
	}
	if oobn > len(oob) {
		t.Fatalf("oobn = %d, larger than the %d-byte buffer", oobn, len(oob))
	}
	if flags&syscall.MSG_CTRUNC == 0 {
		t.Fatalf("flags = %#x, want MSG_CTRUNC for a one-byte control buffer", flags)
	}
}

func TestSCTPReadMsgReturnsParseableControlData(t *testing.T) {
	client, server := eorPair(t)
	if err := server.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
		t.Fatalf("subscribe data info: %v", err)
	}

	const ppid = 0x10203040
	if _, err := client.SCTPWrite([]byte("complete control"),
		&SndRcvInfo{Stream: 1, PPID: ppid}); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 256)
	oob := make([]byte, 512)
	_, oobn, flags, err := server.SCTPReadMsg(buf, oob)
	if err != nil {
		t.Fatalf("SCTPReadMsg: %v", err)
	}
	if flags&syscall.MSG_CTRUNC != 0 {
		t.Fatalf("flags = %#x, control data was truncated", flags)
	}
	info, err := parseSndRcvInfo(oob[:oobn])
	if err != nil {
		t.Fatalf("parse control data: %v", err)
	}
	if info == nil {
		t.Fatal("no SCTP send/receive information in returned control data")
	}
	if info.Stream != 1 || info.PPID != ppid {
		t.Fatalf("control info = stream %d PPID %#x, want stream 1 PPID %#x",
			info.Stream, info.PPID, ppid)
	}
}

func TestSCTPReadFlagsReportsControlTruncation(t *testing.T) {
	client, server := eorPair(t)
	if err := server.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
		t.Fatalf("subscribe data info: %v", err)
	}
	useOOBPoolSize(t, 1)

	want := []byte("high-level truncated control")
	if _, err := client.SCTPWrite(want,
		&SndRcvInfo{Stream: 1, PPID: 0x11223344}); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 256)
	n, info, flags, err := server.SCTPReadFlags(buf)
	if !errors.Is(err, ErrControlTruncated) {
		t.Fatalf("SCTPReadFlags error = %v, want ErrControlTruncated", err)
	}
	if info != nil {
		t.Fatalf("SCTPReadFlags returned untrustworthy info after truncation: %+v", info)
	}
	if flags&syscall.MSG_CTRUNC == 0 {
		t.Fatalf("flags = %#x, want MSG_CTRUNC", flags)
	}
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("payload = %q, want %q", buf[:n], want)
	}
}

func TestReadMsgReportsControlTruncation(t *testing.T) {
	client, server := eorPair(t)
	if err := server.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
		t.Fatalf("subscribe data info: %v", err)
	}
	useOOBPoolSize(t, 1)

	want := []byte("framed truncated control")
	if _, err := client.SCTPWrite(want,
		&SndRcvInfo{Stream: 2, PPID: 0x55667788}); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, info, err := server.ReadMsg(256)
	if !errors.Is(err, ErrControlTruncated) {
		t.Fatalf("ReadMsg error = %v, want ErrControlTruncated", err)
	}
	if info != nil {
		t.Fatalf("ReadMsg returned untrustworthy info after truncation: %+v", info)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload = %q, want %q", got, want)
	}
}
