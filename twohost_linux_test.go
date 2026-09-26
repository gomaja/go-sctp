// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestTwoHost runs the cases that need a second host but no capture: a
// peer at a private address, or loss on a real path (see the two-host
// harness in wire_linux_test.go). Their assertions are the ordinary
// test's; testdata/wire/run.sh runs them after the wire cases.
func TestTwoHost(t *testing.T) {
	runTwoHost(t, twoHostCases)
}

var twoHostCases = []twoHostCase{
	{name: "local-addrs-wildcard-sctp4", port: 41101, server: localAddrsServer, client: localAddrsClient("sctp4")},
	{name: "local-addrs-wildcard-sctp", port: 41102, server: localAddrsServer, client: localAddrsClient("sctp")},
	{name: "etimedout-dialed", port: 41103, server: timedOutServer("dialed"), client: timedOutClient("dialed")},
	{name: "etimedout-accepted", port: 41104, server: timedOutServer("accepted"), client: timedOutClient("accepted")},
	{name: "etimedout-peeled", port: 41105, server: timedOutServer("peeled"), client: timedOutClient("peeled")},
	{name: "pr-default-ttl-config", port: 41106, server: prDefaultTTLServer, client: prDefaultTTLClient("config")},
	{name: "pr-default-ttl-setters", port: 41107, server: prDefaultTTLServer, client: prDefaultTTLClient("setters")},
	{name: "pr-default-ttl-endpoint", port: 41108, server: prDefaultTTLServer, client: prDefaultTTLClient("endpoint")},
	{name: "eshutdown-while-blocked", port: 41109, server: eshutdownServer, client: eshutdownClient},
}

// --- LocalAddrs against a wildcard-bound client ----------------------------------------

func localAddrsServer(s *hostStep) {
	l := s.listen(nil, s.port, s.h.local[0])
	s.send("ready")
	c := s.accept(l)
	s.expect("done")
	_ = c.Abort()
}

// localAddrsClient dials the server's private address from a
// wildcard-bound socket. Linux keeps two local address sets: the
// endpoint's, which for a wildcard bind is every address in the network
// namespace, loopback included, and the association's, restricted to the
// scope of the peer's address, which for a private peer leaves loopback
// out (net/sctp/bind_addr.c: sctp_bind_addr_copy, sctp_in_scope). LocalAddrs
// and LocalAddr must report the association's set, as SCTP_GET_LOCAL_ADDRS
// with the association's own id does (RFC 6458 §9.5), and not the
// endpoint's, which id 0 returns. On loopback both sets are the same, so
// only a peer on another host can tell them apart.
func localAddrsClient(network string) func(*hostStep) {
	return func(s *hostStep) {
		s.expect("ready")
		c, err := Dial(testContext(s.t, wireStepWait), network, nil, wireAddr(s.port, s.h.peer[0]))
		if err != nil {
			s.t.Fatalf("Dial: %v", err)
		}
		s.t.Cleanup(func() { _ = c.Abort() })
		loopback := netip.MustParseAddr("127.0.0.1")

		endpoint, err := c.sock.getAddrs(optGetLocalAddrs, 0)
		if err != nil {
			s.t.Fatalf("SCTP_GET_LOCAL_ADDRS for id 0: %v", err)
		}
		if !hasAddr(endpoint, loopback) || !hasAddr(endpoint, s.h.local[0]) {
			s.t.Fatalf("the endpoint's set %v lacks 127.0.0.1 or %v; a wildcard bind covers the whole namespace", endpoint, s.h.local[0])
		}
		direct, err := c.sock.getAddrs(optGetLocalAddrs, c.AssocID())
		if err != nil {
			s.t.Fatalf("SCTP_GET_LOCAL_ADDRS for id %d: %v", c.AssocID(), err)
		}
		live, err := c.LocalAddrs()
		if err != nil {
			s.t.Fatalf("LocalAddrs: %v", err)
		}
		if got, want := ipStrings(live), ipStrings(direct); !equalStrings(got, want) {
			s.t.Errorf("LocalAddrs = %v, want the association's set %v", got, want)
		}
		if hasAddr(live, loopback) {
			s.t.Errorf("LocalAddrs = %v holds 127.0.0.1, which is out of scope for the private peer %v: that is the endpoint's set %v", live, s.h.peer[0], endpoint)
		}
		if !hasAddr(live, s.h.local[0]) {
			s.t.Errorf("LocalAddrs = %v lacks %v, the address the association runs from", live, s.h.local[0])
		}
		for _, ip := range live.IPs {
			if !hasAddr(endpoint, ip) {
				s.t.Errorf("LocalAddrs holds %v, which the endpoint's set %v lacks", ip, endpoint)
			}
			if ip.Is4In6() {
				s.t.Errorf("LocalAddrs reports %v in IPv4-mapped form", ip)
			}
		}
		if got := ipStrings(c.LocalAddr().(*Addr)); !equalStrings(got, ipStrings(live)) {
			s.t.Errorf("LocalAddr snapshot = %v, want %v", got, ipStrings(live))
		}
		peers, err := c.PeerAddrs()
		if err != nil {
			s.t.Fatalf("PeerAddrs: %v", err)
		}
		if got := ipStrings(peers); !equalStrings(got, []string{s.h.peer[0].String()}) {
			s.t.Errorf("PeerAddrs = %v, want [%v]", got, s.h.peer[0])
		}
		s.fact("endpoint_addrs", strings.Join(ipStrings(endpoint), ","))
		s.fact("assoc_addrs", strings.Join(ipStrings(live), ","))
		s.send("done")
		s.closeGracefully(c)
	}
}

// hasAddr reports whether a holds ip.
func hasAddr(a *Addr, ip netip.Addr) bool {
	for _, x := range a.IPs {
		if x == ip {
			return true
		}
	}
	return false
}

// --- ETIMEDOUT, sticky for reads and sends --------------------------------------------

// timedOutFailing reports whether this side holds the connection that
// fails in the ETIMEDOUT case of kind: the client's for a dialed or peeled
// connection, the server's for an accepted one. The other side drops what
// the failing side sends.
func timedOutFailing(s *hostStep, kind string) bool {
	return s.h.server == (kind == "accepted")
}

func timedOutServer(kind string) func(*hostStep) {
	return func(s *hostStep) {
		var cfg *Config
		if kind == "accepted" {
			cfg = &Config{RTOInfo: wireFastRTO}
		}
		l := s.listen(cfg, s.port, s.h.local[0])
		s.send("ready")
		timedOut(s, kind, s.accept(l), "--dport")
	}
}

func timedOutClient(kind string) func(*hostStep) {
	return func(s *hostStep) {
		s.expect("ready")
		var c *Conn
		switch kind {
		case "dialed":
			c = s.dialA(&Config{RTOInfo: wireFastRTO})
		case "accepted":
			c = s.dialA(nil)
		case "peeled":
			e := s.endpointA(&Config{RTOInfo: wireFastRTO})
			c = s.peel(e, s.connect(e, s.port))
		default:
			s.t.Fatalf("unknown kind %q", kind)
		}
		timedOut(s, kind, c, "--sport")
	}
}

// timedOut is both sides of the ETIMEDOUT case. The side that does not
// fail drops everything the failing side sends it, on its INPUT hook; the
// failing side sets a retransmission limit of 2 (RFC 9260 §8.1,
// Association.Max.Retrans; RFC 6458 §8.1.2) and sends one message, which
// is never acknowledged, while a reader waits. Linux ends the association
// with ETIMEDOUT when the limit is exceeded (net/sctp/sm_statefuns.c:
// sctp_sf_do_6_3_3_rtx), and from then on every read and every send
// returns that error, the reader parked before the failure included, and
// no read waits: each has a deadline far beyond the expected result, so a
// hang fails the test instead of passing it.
func timedOut(s *hostStep, kind string, c *Conn, dir string) {
	s.t.Helper()
	if !timedOutFailing(s, kind) {
		s.expect("silence")
		drop := s.dropInput(dir, portArg(s.port))
		s.send("silent")
		s.expect("failed")
		n := drop.lift()
		if n == 0 {
			s.t.Error("the INPUT drop matched no packet: the message never came")
		}
		s.fact(s.h.role()+"_dropped", n)
		return
	}
	if err := c.SetAssocInfo(&AssocInfo{MaxRetrans: 2}); err != nil {
		s.t.Fatalf("SetAssocInfo: %v", err)
	}
	s.send("silence")
	s.expect("silent")

	const bound = 20 * time.Second
	setReadDeadline(s.t, c, bound)
	parked := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 64))
		parked <- err
	}()
	sent := time.Now()
	if _, err := c.Write([]byte("never acknowledged")); err != nil {
		s.t.Fatalf("Write: %v", err)
	}
	var err error
	select {
	case err = <-parked:
	case <-time.After(bound + time.Second):
		s.t.Fatal("the parked read never returned")
	}
	failedAfter := time.Since(sent)
	wantReadError(s.t, err, syscall.ETIMEDOUT)

	for i := range 3 {
		setReadDeadline(s.t, c, bound)
		start := time.Now()
		_, err := c.Read(make([]byte, 64))
		wantReadError(s.t, err, syscall.ETIMEDOUT)
		if d := time.Since(start); d > time.Second {
			s.t.Errorf("read %d after the failure took %v", i, d)
		}
	}
	_, _, err = c.RecvMsg(make([]byte, 64))
	wantReadError(s.t, err, syscall.ETIMEDOUT)
	_, _, err = c.ReadMsg(64)
	wantReadError(s.t, err, syscall.ETIMEDOUT)
	calls := countSendmsg(s.t)
	for range 3 {
		_, err := c.Write([]byte("after the failure"))
		wantWriteError(s.t, err, syscall.ETIMEDOUT)
		_, err = c.SendMsg([]byte("after the failure"), SendOptions{Info: &SndInfo{Stream: 1}, NoWait: true})
		wantWriteError(s.t, err, syscall.ETIMEDOUT)
	}
	if n := calls.Load(); n != 0 {
		s.t.Errorf("%d sendmsg calls after the error was latched, want none", n)
	}
	s.fact("failed_after_ms", failedAfter.Milliseconds())
	s.send("failed")
}

// --- PR-SCTP: the default policy in every combination ----------------------------------

// The defaults of the PR-TTL cases: a default SndInfo, and a default PrInfo
// whose 1 ms lifetime has always run out by the first retransmission.
var (
	ttlDefSnd = SndInfo{Stream: 1, Flags: SendUnordered, PPID: 46, Context: 7}
	ttlDefPR  = PrInfo{Policy: PRTTL, TTL: time.Millisecond}
)

// ttlSend is one message of the PR-TTL cases, and whether the default
// policy must apply to it.
type ttlSend struct {
	name       string
	opts       SendOptions
	write      bool // Write instead of SendMsg; a Conn only
	ttl        bool // carries the default PrInfo, and is abandoned
	wantStream uint16
	wantPPID   uint32
}

var ttlSends = []ttlSend{
	{name: "neither", ttl: true},
	{name: "Write", write: true, ttl: true},
	{name: "Info only", opts: SendOptions{Info: &SndInfo{Stream: 2, PPID: 99, Context: 3}}, ttl: true},
	{name: "PR only", opts: SendOptions{PR: &PrInfo{Policy: PRRtx, Value: 1000}}, wantStream: 1, wantPPID: 46},
	{name: "both", opts: SendOptions{Info: &SndInfo{Stream: 3, Flags: SendUnordered, PPID: 77}, PR: &PrInfo{Policy: PRNone}}, wantStream: 3, wantPPID: 77},
}

// prDefaultTTLServer drops everything the client sends until the client
// has counted its abandoned messages, then reads what arrives: exactly the
// messages that did not carry the default policy.
func prDefaultTTLServer(s *hostStep) {
	l := s.listen(nil, s.port, s.h.local[0])
	s.send("ready")
	c := s.accept(l)
	s.expect("silence")
	drop := s.dropInput("--dport", portArg(s.port))
	s.send("silent")
	s.expect("counted")
	n := drop.lift()
	if n == 0 {
		s.t.Error("the INPUT drop matched no packet: the messages never came")
	}
	s.fact("dropped", n)
	want := map[string]ttlSend{}
	for _, m := range ttlSends {
		if !m.ttl {
			want[m.name] = m
		}
	}
	for range len(want) {
		b, info := recvWithin(s.t, c, wireStepWait)
		m, ok := want[string(b)]
		if !ok {
			s.t.Fatalf("%q arrived: it carried the 1 ms default lifetime and must have been abandoned (or arrived twice)", b)
		}
		delete(want, m.name)
		if info.Stream != m.wantStream || info.PPID != m.wantPPID || !info.Unordered {
			s.t.Errorf("%s arrived on stream %d with PPID %d, unordered %v; want stream %d, PPID %d, unordered", m.name, info.Stream, info.PPID, info.Unordered, m.wantStream, m.wantPPID)
		}
	}
	wantNothingQueued(s.t, c, 500*time.Millisecond)
	s.send("received")
	if got := s.readUntilEOF(c); len(got) != 0 {
		s.t.Errorf("%d more messages arrived", len(got))
	}
}

// prDefaultTTLClient sets a default SndInfo and a default PrInfo with a
// 1 ms lifetime, through Config, through the setters with the SndInfo set
// last (setting SCTP_DEFAULT_SNDINFO rewrites the word Linux keeps the
// default policy in, and the package must restore it: net/sctp/socket.c:
// sctp_setsockopt_default_sndinfo, sctp_setsockopt_default_prinfo), or on
// an Endpoint, and sends a message for each combination of SendOptions.Info
// and SendOptions.PR while the server drops them. A nil field means the
// default (RFC 6458 §§8.1.31, 8.1.32), so every message without a PR of
// its own carries the lifetime, expires before its first retransmission,
// and is abandoned (net/sctp/chunk.c: sctp_chunk_abandoned):
// PRAssocStatus(PRTTL) counts exactly those (RFC 7496 §4.4). On an
// Endpoint, which has no PR status of its own, the association is peeled
// off to read it; its counters move with it.
func prDefaultTTLClient(setup string) func(*hostStep) {
	return func(s *hostStep) {
		s.expect("ready")
		defaults := &Config{RTOInfo: wireFastRTO, DefaultSndInfo: new(ttlDefSnd), DefaultPrInfo: new(ttlDefPR)}
		switch setup {
		case "config":
			ttlOnConn(s, s.dialA(defaults))
		case "setters":
			c := s.dialA(&Config{RTOInfo: wireFastRTO})
			if err := c.SetDefaultPrInfo(new(ttlDefPR)); err != nil {
				s.t.Fatalf("SetDefaultPrInfo: %v", err)
			}
			if err := c.SetDefaultSndInfo(new(ttlDefSnd)); err != nil {
				s.t.Fatalf("SetDefaultSndInfo: %v", err)
			}
			ttlOnConn(s, c)
		case "endpoint":
			e := s.endpointA(defaults)
			id := s.connect(e, s.port)
			s.send("silence")
			s.expect("silent")
			want := sendTTLCases(s, func(m ttlSend) error {
				_, err := e.SendMsg(id, []byte(m.name), m.opts)
				return err
			}, false)
			countTTL(s, s.peel(e, id), want)
		default:
			s.t.Fatalf("unknown setup %q", setup)
		}
	}
}

// ttlOnConn is prDefaultTTLClient's sends and count on a Conn whose
// defaults are set.
func ttlOnConn(s *hostStep, c *Conn) {
	s.t.Helper()
	if got, err := c.DefaultSndInfo(); err != nil || *got != ttlDefSnd {
		s.t.Fatalf("DefaultSndInfo = %+v, %v; want %+v", got, err, ttlDefSnd)
	}
	if got, err := c.DefaultPrInfo(); err != nil || *got != ttlDefPR {
		s.t.Fatalf("DefaultPrInfo = %+v, %v; want %+v, which setting the default SndInfo must not clear", got, err, ttlDefPR)
	}
	s.send("silence")
	s.expect("silent")
	want := sendTTLCases(s, func(m ttlSend) error {
		var err error
		if m.write {
			_, err = c.Write([]byte(m.name))
		} else {
			_, err = c.SendMsg([]byte(m.name), m.opts)
		}
		return err
	}, true)
	countTTL(s, c, want)
}

// sendTTLCases sends every ttlSend, Write only on a Conn, and returns how
// many carry the default policy.
func sendTTLCases(s *hostStep, send func(ttlSend) error, conn bool) int {
	s.t.Helper()
	want := 0
	for _, m := range ttlSends {
		if m.write && !conn {
			continue
		}
		if err := send(m); err != nil {
			s.t.Fatalf("%s: send: %v", m.name, err)
		}
		if m.ttl {
			want++
		}
	}
	return want
}

// countTTL waits until PRAssocStatus(PRTTL) has counted want messages,
// checks that it counts no more, and tells the server, which then reads
// the rest.
func countTTL(s *hostStep, c *Conn, want int) {
	s.t.Helper()
	total := func(p PRPolicy) uint64 {
		st, err := c.PRAssocStatus(p)
		if err != nil {
			s.t.Fatalf("PRAssocStatus(%v): %v", p, err)
		}
		return st.AbandonedSent + st.AbandonedUnsent
	}
	// The association outlives the wait: with the peer silent it fails
	// after net.sctp.association_max_retrans (10) retransmission timeouts,
	// several seconds at the short RTO.
	deadline := time.Now().Add(2 * time.Second)
	for got := total(PRTTL); got < uint64(want); got = total(PRTTL) {
		if time.Now().After(deadline) {
			s.t.Fatalf("PRAssocStatus(PRTTL) counts %d abandoned messages 2 s after the sends, want %d", got, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Several retransmission timeouts more, which would abandon anything
	// else carrying the policy.
	time.Sleep(time.Second)
	if got := total(PRTTL); got != uint64(want) {
		s.t.Errorf("PRAssocStatus(PRTTL) counts %d abandoned messages, want exactly %d", got, want)
	}
	if got := total(PRRtx); got != 0 {
		s.t.Errorf("PRAssocStatus(PRRtx) counts %d, want 0: the PR-only message has a limit of 1000", got)
	}
	if got := total(PRAll); got != uint64(want) {
		s.t.Errorf("PRAssocStatus(PRAll) counts %d, want %d", got, want)
	}
	s.fact("ttl_abandoned", want)
	s.send("counted")
	s.expect("received")
	s.closeGracefully(c)
}

// --- ESHUTDOWN while the SHUTDOWN handshake is blocked -------------------------------

func eshutdownServer(s *hostStep) {
	l := s.listen(nil, s.port, s.h.local[0])
	s.send("ready")
	c := s.accept(l)
	s.expect("armed")
	if err := c.Shutdown(); err != nil {
		s.t.Fatalf("Shutdown: %v", err)
	}
	s.send("shutdown")
	// This end completes its part: the client's SHUTDOWN ACK arrives, and
	// the SHUTDOWN COMPLETE goes out.
	if got := s.readUntilEOF(c); len(got) != 0 {
		s.t.Errorf("%d messages arrived after the Shutdown", len(got))
	}
	s.expect("done")
}

// eshutdownClient drops, on its INPUT hook, the SHUTDOWN COMPLETE that
// ends the server's Shutdown, so that once it has received the server's
// SHUTDOWN and answered it, this end stays in SHUTDOWN-ACK-SENT (RFC 9260
// §9.2). For as long as that lasts, every send fails with ESHUTDOWN
// (net/sctp/sm_statetable.c: the SEND primitive is sctp_sf_error_shutdown
// in every shutdown state). Once the drop is lifted, the next SHUTDOWN
// ACK retransmission draws the SHUTDOWN COMPLETE (RFC 9260 §8.4, rule 5),
// the association ends, and sends fail with EPIPE, without SIGPIPE.
func eshutdownClient(s *hostStep) {
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGPIPE)
	defer signal.Stop(sig)

	s.expect("ready")
	c := s.dialA(&Config{RTOInfo: wireFastRTO})
	drop := s.dropInput("--sport", portArg(s.port), "--chunk-types", "any", "SHUTDOWN_COMPLETE")
	s.send("armed")
	s.expect("shutdown")
	// The SHUTDOWN has arrived when reads end (net/sctp/sm_sideeffect.c:
	// sctp_cmd_new_state marks a one-to-one socket shut for reading).
	setReadDeadline(s.t, c, wireStepWait)
	if n, err := c.Read(make([]byte, 64)); !errors.Is(err, io.EOF) {
		s.t.Fatalf("Read after the server's Shutdown = %d, %v; want io.EOF", n, err)
	}
	blocked := time.Now()
	sends := 0
	for time.Since(blocked) < time.Second {
		_, err := c.Write([]byte("while blocked"))
		wantWriteError(s.t, err, syscall.ESHUTDOWN)
		_, err = c.SendMsg([]byte("while blocked"), SendOptions{Info: &SndInfo{Stream: 1}})
		wantWriteError(s.t, err, syscall.ESHUTDOWN)
		sends += 2
		time.Sleep(50 * time.Millisecond)
	}
	st, err := c.Status()
	if err != nil {
		s.t.Fatalf("Status: %v", err)
	}
	if st.State != StateShutdownAckSent {
		s.t.Errorf("Status().State = %v while the SHUTDOWN COMPLETE is dropped, want %v", st.State, StateShutdownAckSent)
	}
	n := drop.lift()
	if n == 0 {
		s.t.Error("the drop matched no SHUTDOWN COMPLETE")
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := c.Write([]byte("after the drop"))
		if errors.Is(err, syscall.EPIPE) {
			wantWriteError(s.t, err, syscall.EPIPE)
			break
		}
		wantWriteError(s.t, err, syscall.ESHUTDOWN)
		if time.Now().After(deadline) {
			s.t.Fatal("sends still fail with ESHUTDOWN 10 s after the drop was lifted")
		}
		time.Sleep(20 * time.Millisecond)
	}
	for range 3 {
		_, err := c.SendMsg([]byte("gone"), SendOptions{Info: &SndInfo{Stream: 1}})
		wantWriteError(s.t, err, syscall.EPIPE)
	}
	if err := c.term.latched(); err != nil {
		s.t.Errorf("a graceful end latched %v", err)
	}
	select {
	case got := <-sig:
		s.t.Errorf("received %v; every send passes MSG_NOSIGNAL", got)
	case <-time.After(200 * time.Millisecond):
	}
	s.fact("eshutdown_sends", sends)
	s.fact("dropped", n)
	s.send("done")
}
