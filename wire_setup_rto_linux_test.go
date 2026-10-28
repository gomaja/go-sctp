// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"bytes"
	"context"
	"time"
)

const (
	wireSetupRTO     = 1200 * time.Millisecond
	wireSetupTimeout = 900 * time.Millisecond
	wireSetupMaxInit = 2 * time.Second
	wirePPIDSetupRTO = 0x57490016
)

// setupRTOServer drops INITs on INPUT, so the client remains in
// COOKIE-WAIT and every transmission is still visible in its capture.
func setupRTOServer(s *hostStep) {
	_ = s.listen(nil, s.port, s.h.local[0])
	drop := s.dropInput("--dport", portArg(s.port), "--chunk-types", "any", "INIT")
	s.send("ready")
	s.expect("done")
	n := drop.lift()
	if n == 0 {
		s.t.Error("the INPUT drop matched no INIT: the setup never reached this host")
	}
	s.fact("dropped", n)
}

// setupRTOClient compares the setup override with the same lasting RTO
// without it. A single path waits 200 ms, then 400 ms, then 800 ms between
// INITs: T1 doubles up to MaxInitTimeout, independently of RTO.Max
// (net/sctp/sm_sideeffect.c: sctp_cmd_t1_timer_update; RFC 9260 §5.1).
func setupRTOClient(setup bool) func(*hostStep) {
	return func(s *hostStep) {
		s.expect("ready")
		cfg := &Config{
			RTOInfo:       wireFastRTO,
			InitMsg:       InitMsg{MaxAttempts: 8, MaxInitTimeout: wireSetupMaxInit},
			AbandonPolicy: AbandonQuiet,
		}
		if setup {
			cfg.SetupRTOInitial = wireSetupRTO
		}
		deadline := time.Now().Add(wireSetupTimeout)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		c, err := cfg.Dial(ctx, "sctp4", wireAddr(0, s.h.local[0]), wireAddr(s.port, s.h.peer[0]))
		s.fact("deadline_ns", deadline.UnixNano())
		s.fact("return_ns", time.Now().UnixNano())
		s.fact("lasting_initial_ns", wireFastRTO.Initial.Nanoseconds())
		s.fact("setup_initial_ns", cfg.SetupRTOInitial.Nanoseconds())
		s.fact("max_init_timeout_ns", wireSetupMaxInit.Nanoseconds())
		if err == nil {
			_ = c.Abort()
			s.t.Fatal("Dial succeeded against a peer that drops every INIT")
		}
		wantDialError(s.t, err, context.DeadlineExceeded)
		// Keep the rule until Dial has released the setup; the sentinel
		// bounds the analyzer's check for any transmission after return.
		s.send("done")
	}
}

// setupRTOResidualServer drops the first DATA, then lifts the rule well
// before either retransmission timer could expire. The retry must arrive
// after the connect-time initial RTO, even though Dial restored RTOInfo.
func setupRTOResidualServer(s *hostStep) {
	l := s.listen(nil, s.port, s.h.local[0])
	s.send("ready")
	c := s.accept(l)
	drop := s.dropInput("--dport", portArg(s.port), "--chunk-types", "any", "DATA")
	s.send("silent")
	s.expect("sent")
	time.Sleep(80 * time.Millisecond)
	n := drop.lift()
	s.fact("dropped", n)
	if n != 1 {
		s.t.Errorf("the INPUT drop matched %d packets, want only the first DATA", n)
	}
	b, info := recvWithin(s.t, c, wireStepWait)
	if info.PPID != wirePPIDSetupRTO || !bytes.Equal(b, []byte("first DATA after setup")) {
		s.t.Errorf("received %q with PPID %#x, want the setup RTO message", b, info.PPID)
	}
	s.fact("received", 1)
	s.send("received")
	// The same end record as recordEnd, which would count only the
	// messages read here, after the one already received.
	rest, err := readMessagesToEOF(c)
	if err != nil {
		s.fact("eof", 0)
		s.t.Fatal(err)
	}
	s.fact("eof", 1)
	if len(rest) != 0 {
		s.t.Errorf("%d extra messages arrived", len(rest))
	}
}

func setupRTOResidualClient(s *hostStep) {
	s.expect("ready")
	c := s.dialA(&Config{RTOInfo: wireFastRTO, SetupRTOInitial: wireSetupRTO})
	if got, err := c.RTOInfo(); err != nil || *got != *wireFastRTO {
		s.t.Fatalf("RTOInfo = %v, %v; want lasting values %v", got, err, wireFastRTO)
	}
	// A heartbeat would measure an RTT and replace the residual before
	// this case sends DATA (RFC 9260 §6.3.1 C1-C3).
	if err := c.SetPathParams(s.h.peer[0], &PathParams{Heartbeat: new(false)}); err != nil {
		s.t.Fatalf("disable heartbeats: %v", err)
	}
	s.expect("silent")
	s.fact("setup_initial_ns", wireSetupRTO.Nanoseconds())
	s.fact("lasting_initial_ns", wireFastRTO.Initial.Nanoseconds())
	s.fact("sent_ns", time.Now().UnixNano())
	s.mustSend(c, []byte("first DATA after setup"), SendOptions{Info: &SndInfo{PPID: wirePPIDSetupRTO}})
	s.send("sent")
	s.expect("received")
	s.closeGracefully(c)
}
