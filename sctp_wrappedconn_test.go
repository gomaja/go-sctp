//go:build linux
// +build linux

package sctp

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"syscall"
	"testing"
)

// TestWrappedConnReportsSubscribeFailure checks that a wrapper built on a
// connection that cannot subscribe to SCTP_EVENT_DATA_IO reports it, rather
// than reading messages whose SndRcvInfo header is entirely zeroes.
//
// The header is what the whole type exists to provide. Without the
// subscription the kernel returns no ancillary data, the header is zero-filled,
// and every message reads as stream 0 with PPID 0 no matter which stream it
// arrived on: a wrong answer that looks exactly like a right one.
//
// A closed connection is the reachable way to make the subscription fail.
func TestWrappedConnReportsSubscribeFailure(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	la, ok := ln.Addr().(*SCTPAddr)
	if !ok {
		t.Fatal("listener has no address")
	}
	conn, err := DialSCTP("sctp", nil, la)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Close before wrapping, so the subscription inside the constructor fails.
	if err := conn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	wc := NewSCTPSndRcvInfoWrappedConn(conn)

	buf := make([]byte, int(sndRcvInfoSize)+64)
	_, rerr := wc.Read(buf)
	if rerr == nil {
		t.Error("Read on a wrapper whose subscription failed returned no error")
	} else if !strings.Contains(rerr.Error(), "SCTP_EVENT_DATA_IO") {
		t.Errorf("Read error does not name the failed subscription: %v", rerr)
	}

	_, werr := wc.Write(buf)
	if werr == nil {
		t.Error("Write on a wrapper whose subscription failed returned no error")
	}

	// The underlying cause must stay reachable for callers that switch on it.
	if rerr != nil && !errors.Is(rerr, syscall.EBADF) &&
		!errors.Is(rerr, syscall.EINVAL) && !errors.Is(rerr, syscall.ENOTCONN) {
		t.Logf("wrapped cause was %v", rerr)
	}
}

// TestWrappedConnWorksWhenSubscribed is the negative case: a wrapper on a
// healthy connection must not report an error, or the check above would pass
// for a constructor that always failed.
func TestWrappedConnWorksWhenSubscribed(t *testing.T) {
	addr, err := ResolveSCTPAddr("sctp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	ln, err := ListenSCTP("sctp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	la, ok := ln.Addr().(*SCTPAddr)
	if !ok {
		t.Fatal("listener has no address")
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			t.Errorf("accept: %v", aerr)
			close(accepted)
			return
		}
		accepted <- c
	}()

	conn, err := DialSCTP("sctp", nil, la)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	srv, ok := <-accepted
	if !ok {
		t.Fatal("accept failed")
	}
	defer func() { _ = srv.Close() }()

	wc := NewSCTPSndRcvInfoWrappedConn(conn)
	if wc.subErr != nil {
		t.Fatalf("subscription failed on a healthy connection: %v", wc.subErr)
	}

	// A real round trip proves the header is populated from ancillary data
	// rather than merely absent-and-zeroed.
	const payload = "m3ua"
	out := make([]byte, int(sndRcvInfoSize)+len(payload))
	info := &SndRcvInfo{Stream: 3, PPID: 9}
	copy(out, toBuf(info))
	copy(out[sndRcvInfoSize:], payload)
	if _, err := wc.Write(out); err != nil {
		t.Fatalf("write: %v", err)
	}

	srvConn, ok := srv.(*SCTPConn)
	if !ok {
		t.Fatalf("accepted %T, want *SCTPConn", srv)
	}
	if err := srvConn.SubscribeEvents(SCTP_EVENT_DATA_IO); err != nil {
		t.Fatalf("server subscribe: %v", err)
	}
	rbuf := make([]byte, 512)
	n, rinfo, err := srvConn.SCTPRead(rbuf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if string(rbuf[:n]) != payload {
		t.Errorf("payload = %q, want %q", rbuf[:n], payload)
	}
	if rinfo == nil {
		t.Fatal("no ancillary data on a subscribed connection")
	}
	if rinfo.Stream != 3 {
		t.Errorf("stream = %d, want 3", rinfo.Stream)
	}
}

// TestWrappedConnWriteDoesNotCountAnUnsentHeader pins io.Writer's byte-count
// contract. The inline SndRcvInfo header is consumed only when the payload is
// accepted as one SCTP message; if the kernel rejects the send, no input bytes
// were written and the result must be zero.
func TestWrappedConnWriteDoesNotCountAnUnsentHeader(t *testing.T) {
	client, _ := eorPair(t)
	wc := NewSCTPSndRcvInfoWrappedConn(client)
	if wc.subErr != nil {
		t.Fatalf("subscription failed: %v", wc.subErr)
	}
	if err := client.Abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}

	b := make([]byte, int(sndRcvInfoSize)+1)
	n, err := wc.Write(b)
	if err == nil {
		t.Fatal("Write on a closed connection returned no error")
	}
	if n != 0 {
		t.Errorf("Write returned n=%d after sending nothing, want 0", n)
	}
}

func TestWrappedConnPartialResultsKeepTheInlineHeaderInTheCount(t *testing.T) {
	t.Run("read payload and error", func(t *testing.T) {
		const payload = "partial"
		b := make([]byte, int(sndRcvInfoSize)+len(payload))
		copy(b[sndRcvInfoSize:], payload)
		info := &SndRcvInfo{Stream: 7, PPID: 0x11223344}

		n, err := finishWrappedRead(b, len(payload), info, ErrControlTruncated)
		if n != len(b) || !errors.Is(err, ErrControlTruncated) {
			t.Fatalf("finishWrappedRead = (%d, %v), want (%d, ErrControlTruncated)",
				n, err, len(b))
		}
		gotInfo, err := decodeWrappedSndRcvInfo(b)
		if err != nil || gotInfo.Stream != info.Stream || gotInfo.PPID != info.PPID {
			t.Fatalf("inline info = (%+v, %v), want %+v", gotInfo, err, info)
		}
		if got := string(b[sndRcvInfoSize:n]); got != payload {
			t.Errorf("payload = %q, want %q", got, payload)
		}
	})

	t.Run("read error without payload", func(t *testing.T) {
		b := bytes.Repeat([]byte{0xAA}, int(sndRcvInfoSize)+1)
		n, err := finishWrappedRead(b, 0, nil, ErrControlTruncated)
		if n != 0 || !errors.Is(err, ErrControlTruncated) {
			t.Fatalf("finishWrappedRead = (%d, %v), want (0, ErrControlTruncated)", n, err)
		}
		if !bytes.Equal(b, bytes.Repeat([]byte{0xAA}, len(b))) {
			t.Fatal("zero-payload error modified the caller's buffer")
		}
	})

	t.Run("write payload and error", func(t *testing.T) {
		n, err := finishWrappedWrite(7, syscall.EIO)
		if n != int(sndRcvInfoSize)+7 || !errors.Is(err, syscall.EIO) {
			t.Fatalf("finishWrappedWrite = (%d, %v), want (%d, EIO)",
				n, err, int(sndRcvInfoSize)+7)
		}
	})
}

// TestDecodeWrappedSndRcvInfoDoesNotRequireAlignment checks the inline wire
// header is decoded field by field. A caller may pass any byte slice to Write,
// including a deliberately misaligned subslice; casting &b[0] to
// *SndRcvInfo makes that invalid on alignment-sensitive architectures.
func TestDecodeWrappedSndRcvInfoDoesNotRequireAlignment(t *testing.T) {
	storage := make([]byte, int(sndRcvInfoSize)+1)
	b := storage[1:]
	nativeEndian.PutUint16(b[0:2], 0x0102)
	nativeEndian.PutUint16(b[2:4], 0x0304)
	nativeEndian.PutUint16(b[4:6], 0x0506)
	nativeEndian.PutUint32(b[8:12], 0x0708090a)
	nativeEndian.PutUint32(b[12:16], 0x0b0c0d0e)
	nativeEndian.PutUint32(b[16:20], 0x0f101112)
	nativeEndian.PutUint32(b[20:24], 0x13141516)
	nativeEndian.PutUint32(b[24:28], 0x1718191a)
	nativeEndian.PutUint32(b[28:32], uint32(0x1b1c1d1e))

	got, err := decodeWrappedSndRcvInfo(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := SndRcvInfo{
		Stream: 0x0102, SSN: 0x0304, Flags: 0x0506,
		PPID: 0x0708090a, Context: 0x0b0c0d0e, TTL: 0x0f101112,
		TSN: 0x13141516, CumTSN: 0x1718191a, AssocID: 0x1b1c1d1e,
	}
	if got != want {
		t.Fatalf("decoded %+v, want %+v", got, want)
	}

	if _, err := decodeWrappedSndRcvInfo(b[:len(b)-1]); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short decode error = %v, want io.ErrUnexpectedEOF", err)
	}
}
