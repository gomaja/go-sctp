// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"
)

const wirePartialPPID = 0x57490017
const wireFollowingPPID = 0x57490018

// Partial delivery must end at the abort record, not at the EOR of the
// following message (RFC 6458 §6.1.7; RFC 3758 §3.6).
func partialDeliveryServer(s *hostStep) {
	l := s.listen(&Config{ReadBuffer: new(16384)}, s.port, s.h.local[0])
	s.send("ready")
	c := s.accept(l)
	if err := c.SetPartialDeliveryPoint(4096); err != nil {
		s.t.Fatal(err)
	}
	drop := s.dropInput("--dport", portArg(s.port), "--chunk-types", "any", "DATA", "-m", "statistic", "--mode", "nth", "--every", "5", "--packet", "4")
	s.send("reading")
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		s.t.Fatal(err)
	}
	b, info, err := c.ReadMsg(1 << 20)
	s.fact("prefix_bytes", len(b))
	s.fact("interrupted", boolValue(errors.Is(err, ErrMessageInterrupted)))
	if !errors.Is(err, ErrMessageInterrupted) || !errors.Is(err, errPartialDeliveryAborted) || len(b) == 0 || len(b) >= 100<<10 || info.PPID != wirePartialPPID || !bytes.Equal(b, bytes.Repeat([]byte{'A'}, len(b))) {
		s.t.Fatalf("partial delivery: n=%d info=%+v err=%v", len(b), info, err)
	}
	b, info, err = c.ReadMsg(1 << 20)
	if err != nil || !bytes.Equal(b, []byte("following message")) || info.PPID != wireFollowingPPID {
		s.t.Fatalf("following=%q info=%+v err=%v", b, info, err)
	}
	s.fact("following", 1)
	s.fact("dropped", drop.lift())
	s.fact("teardown_ns", time.Now().UnixNano())
	s.send("received")
	s.recordEnd(s.readUntilEOF(c), nil)
}

func partialDeliveryClient(s *hostStep) {
	s.expect("ready")
	c := s.dialA(&Config{RTOInfo: wireFastRTO, WriteBuffer: new(4 << 20)})
	s.expect("reading")
	s.mustSend(c, bytes.Repeat([]byte{'A'}, 100<<10), SendOptions{Info: &SndInfo{Stream: 0, PPID: wirePartialPPID}, PR: &PrInfo{Policy: PRRtx, Value: 0}})
	time.Sleep(time.Second)
	s.mustSend(c, []byte("following message"), SendOptions{Info: &SndInfo{PPID: wireFollowingPPID}})
	s.expect("received")
	s.closeGracefully(c)
}

// I-DATA's stream pieces need independent EOR boundaries and the first
// piece's metadata (RFC 8260 §2.1; RFC 6458 §5.3.5).
func readInterleavedToEOF(c *Conn) ([]wireRecv, error) {
	if err := c.SetReadDeadline(time.Now().Add(wireStepWait)); err != nil {
		return nil, err
	}
	var streams [2]wireRecv
	var got []wireRecv
	var buf [4096]byte
	for {
		n, info, err := c.RecvMsg(buf[:])
		if err == io.EOF {
			for _, m := range streams {
				if len(m.data) != 0 {
					return got, fmt.Errorf("stream %d ended without EOR", m.info.Stream)
				}
			}
			return got, nil
		}
		if err != nil {
			return got, err
		}
		if info.Notification {
			return got, fmt.Errorf("unexpected notification during I-DATA delivery")
		}
		stream := int(info.Rcv.Stream)
		if stream >= len(streams) {
			return got, fmt.Errorf("unexpected stream %d", stream)
		}
		m := &streams[stream]
		if len(m.data) == 0 {
			m.info = info.Rcv
		}
		m.data = append(m.data, buf[:n]...)
		if info.EOR {
			got = append(got, *m)
			*m = wireRecv{}
		}
	}
}
