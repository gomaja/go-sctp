// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The hosts of the synthetic captures.
var (
	clientA = netip.MustParseAddr("10.0.1.3")
	clientB = netip.MustParseAddr("10.0.2.3")
	serverA = netip.MustParseAddr("10.0.1.2")
	serverB = netip.MustParseAddr("10.0.2.2")
	t0      = time.Unix(1_800_000_000, 0)
)

// setupFacts names the four hosts and places the sentinel on port 9.
func setupFacts() facts {
	return facts{
		"setup": {
			"client_a": clientA.String(), "client_b": clientB.String(),
			"server_a": serverA.String(), "server_b": serverB.String(),
		},
		sentinelCase: {"port": "9"},
	}
}

// sentinels are the two INITs to the closed port, at end.
func sentinels(end time.Time) []frame {
	return []frame{
		{number: 9000, at: end, length: 82, src: clientA, dst: serverA, sport: 5000, dport: 9, chunks: []int{chunkINIT}},
		{number: 9001, at: end, length: 82, src: clientB, dst: serverB, sport: 5001, dport: 9, chunks: []int{chunkINIT}},
	}
}

// c2s and s2c build a frame on port at t+ms, holding chunks.
func c2s(n int, ms float64, port uint16, chunks ...int) frame {
	return frame{number: n, at: t0.Add(time.Duration(ms * float64(time.Millisecond))), length: 98, src: clientA, dst: serverA, sport: 40000, dport: port, chunks: chunks}
}

func s2c(n int, ms float64, port uint16, chunks ...int) frame {
	return frame{number: n, at: t0.Add(time.Duration(ms * float64(time.Millisecond))), length: 98, src: serverA, dst: clientA, sport: port, dport: 40000, chunks: chunks}
}

// withData adds DATA chunks to f.
func withData(f frame, d ...dataChunk) frame {
	for _, c := range d {
		f.chunks = append(f.chunks, chunkDATA)
		f.data = append(f.data, c)
	}
	return f
}

// check runs one claim on frames and caseFacts and returns its result.
func check(t *testing.T, c claim, frames []frame, caseFacts map[string]string) result {
	t.Helper()
	fs := setupFacts()
	fs[c.name] = caseFacts
	e, err := newEnv(append(frames, sentinels(t0.Add(time.Hour))...), fs, 1500)
	if err != nil {
		t.Fatalf("newEnv: %v", err)
	}
	return runClaim(e, c)
}

func ns(ms float64) string {
	return fmt.Sprint(t0.Add(time.Duration(ms * float64(time.Millisecond))).UnixNano())
}

func wantPass(t *testing.T, r result) {
	t.Helper()
	if r.err != nil {
		t.Fatalf("%s failed: %v", r.name, r.err)
	}
}

func wantFail(t *testing.T, r result, substr string) {
	t.Helper()
	if r.err == nil {
		t.Fatalf("%s passed, want a failure mentioning %q", r.name, substr)
	}
	if !strings.Contains(r.err.Error(), substr) {
		t.Fatalf("%s failed with %q, want it to mention %q", r.name, r.err, substr)
	}
}

func claimNamed(t *testing.T, name string) claim {
	t.Helper()
	for _, c := range claims {
		if c.name == name {
			return c
		}
	}
	t.Fatalf("no claim %s", name)
	return claim{}
}

// --- parsing -------------------------------------------------------------------

func line(cols ...string) string { return strings.Join(cols, "\t") }

func TestParseFramesReadsChunksAndDATAFields(t *testing.T) {
	out := line("7", "1800000000.000123000", "98", "10.0.1.3", "10.0.1.2", "40000", "41005",
		"3,0,0", "10,11", "0,1", "1464401921,16909060", "1,0", "0,1", "99", "", "") + "\n" +
		line("8", "1800000000.000200000", "70", "10.0.1.3", "10.0.1.2", "40000", "41005",
			"6", "", "", "", "", "", "", "", "12") + "\n"
	frames, err := parseFrames(out)
	if err != nil {
		t.Fatal(err)
	}
	f := frames[0]
	if f.number != 7 || !f.at.Equal(t0.Add(123*time.Microsecond)) || f.dport != 41005 || f.src != clientA {
		t.Errorf("frame = %+v", f)
	}
	want := []dataChunk{{tsn: 10, sid: 0, ppid: 0x57490001, u: true}, {tsn: 11, sid: 1, ppid: 0x01020304, i: true}}
	if len(f.data) != 2 || f.data[0] != want[0] || f.data[1] != want[1] || len(f.sackCum) != 1 || f.sackCum[0] != 99 {
		t.Errorf("DATA %+v, SACK %v; want %+v, [99]", f.data, f.sackCum, want)
	}
	if a := frames[1]; len(a.chunks) != 1 || a.chunks[0] != chunkABORT || len(a.causes) != 1 || a.causes[0] != causeUserAbort {
		t.Errorf("ABORT frame %+v, want one ABORT with cause 12", a)
	}
}

func TestParseFramesFailsClosed(t *testing.T) {
	good := []string{"7", "1800000000.000123000", "98", "10.0.1.3", "10.0.1.2", "40000", "41005", "0", "10", "0", "5", "0", "0", "", "", ""}
	for name, mutate := range map[string]func([]string) []string{
		"a missing column":             func(c []string) []string { return c[:len(c)-1] },
		"a DATA chunk without its TSN": func(c []string) []string { c[8] = ""; return c },
		"a TSN without a DATA chunk":   func(c []string) []string { c[7] = "3"; c[13] = "4"; return c },
		"a SACK without its ack":       func(c []string) []string { c[7] = "0,3"; return c },
		"a malformed time":             func(c []string) []string { c[1] = "soon"; return c },
		"a malformed address":          func(c []string) []string { c[3] = "10.0.1"; return c },
		"a malformed bit":              func(c []string) []string { c[11] = "maybe"; return c },
		"no chunk at all":              func(c []string) []string { c[7] = ""; return c },
		"a malformed cause":            func(c []string) []string { c[15] = "user"; return c },
	} {
		t.Run(name, func(t *testing.T) {
			cols := mutate(append([]string(nil), good...))
			if _, err := parseFrames(line(cols...) + "\n"); err == nil {
				t.Error("parsed without an error")
			}
		})
	}
	if _, err := parseFrames(""); err == nil {
		t.Error("an empty capture parsed without an error")
	}
}

func TestParseFactsRefusesDuplicatesAndMalformedLines(t *testing.T) {
	fs := facts{}
	if err := parseFacts(strings.NewReader("a port 41005\na close_ns 1\n"), "x", fs); err != nil {
		t.Fatal(err)
	}
	if fs["a"]["close_ns"] != "1" {
		t.Errorf("facts = %v", fs)
	}
	if err := parseFacts(strings.NewReader("a port 41006\n"), "y", fs); err == nil {
		t.Error("a fact recorded twice was accepted")
	}
	if err := parseFacts(strings.NewReader("a key\n"), "z", facts{}); err == nil {
		t.Error("a line without a value was accepted")
	}
}

// --- the environment -------------------------------------------------------------

func TestNewEnvFailsClosed(t *testing.T) {
	ok := []frame{c2s(1, 0, 41005, chunkINIT)}
	for name, tc := range map[string]struct {
		frames []frame
		facts  func(facts)
		want   string
	}{
		"an unknown host": {
			frames: []frame{{number: 1, at: t0, length: 98, src: netip.MustParseAddr("10.9.9.9"), dst: serverA, chunks: []int{chunkINIT}}},
			want:   "neither host",
		},
		"a frame beyond the MTU": {
			frames: []frame{{number: 1, at: t0, length: 9000, src: clientA, dst: serverA, chunks: []int{chunkDATA}, data: []dataChunk{{}}}},
			want:   "super-packet",
		},
		"a missing sentinel": {
			frames: ok,
			facts:  func(fs facts) { delete(fs, sentinelCase) },
			want:   "not proven complete",
		},
		"a missing host fact": {
			frames: ok,
			facts:  func(fs facts) { delete(fs["setup"], "server_b") },
			want:   "server_b",
		},
	} {
		t.Run(name, func(t *testing.T) {
			fs := setupFacts()
			if tc.facts != nil {
				tc.facts(fs)
			}
			_, err := newEnv(append(tc.frames, sentinels(t0.Add(time.Hour))...), fs, 1500)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("newEnv = %v, want an error mentioning %q", err, tc.want)
			}
		})
	}

	fs := setupFacts()
	e, err := newEnv(append(ok, sentinels(t0.Add(time.Hour))[:1]...), fs, 1500)
	if err == nil {
		t.Errorf("a capture with one sentinel of two was accepted: %+v", e)
	}
}

func TestSentinelBoundsTheCapture(t *testing.T) {
	e, err := newEnv(append([]frame{c2s(1, 0, 41005, chunkINIT)}, sentinels(t0.Add(time.Second))...), setupFacts(), 1500)
	if err != nil {
		t.Fatal(err)
	}
	if !e.captureEnd.Equal(t0.Add(time.Second)) {
		t.Errorf("capture end %v, want the sentinel's %v", e.captureEnd, t0.Add(time.Second))
	}
}

func TestAnalyzeFailsClosed(t *testing.T) {
	fs := setupFacts()
	fs["graceful-close"] = map[string]string{"port": "41022", "close_ns": ns(0), "eof": "1"}
	e, err := newEnv(sentinels(t0.Add(time.Hour)), fs, 1500)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := analyze(e, claims, regexp.MustCompile("no-such-claim")); err == nil {
		t.Error("a filter matching no claim was accepted")
	}
	results, err := analyze(e, claims, regexp.MustCompile("^graceful"))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		switch r.name {
		case "graceful-close":
			wantFail(t, r, "no frame on port 41022")
		case "graceful-peeled-close":
			wantFail(t, r, "no facts")
		}
	}
	fs["made-up-case"] = map[string]string{"port": "1"}
	if _, err := analyze(e, claims, regexp.MustCompile("")); err == nil {
		t.Error("facts for a case no claim checks were accepted")
	}
}

// --- claims ------------------------------------------------------------------------

// abortCapture is a Close at 0 ms and an Abort at 500 ms on port 41005:
// the SHUTDOWN at once, and ABORTs at the given times.
func abortCapture(abortsAt ...float64) []frame {
	frames := []frame{c2s(1, 0.02, 41005, chunkSHUTDOWN)}
	for i, at := range abortsAt {
		frames = append(frames, userAbort(c2s(2+i, at, 41005, chunkABORT)))
	}
	return frames
}

// userAbort gives an ABORT frame the User-Initiated Abort cause.
func userAbort(f frame) frame {
	f.causes = []uint16{causeUserAbort}
	return f
}

func abortFacts() map[string]string {
	return map[string]string{"port": "41005", "close_ns": ns(0), "abort_ns": ns(500), "grace_ns": fmt.Sprint(int64(3 * time.Second)), "dropped_0": "2"}
}

func TestCheckAbortDuringClose(t *testing.T) {
	c := claimNamed(t, "abort-during-close")
	wantPass(t, check(t, c, abortCapture(500.2), abortFacts()))
	wantFail(t, check(t, c, abortCapture(3000.1), abortFacts()), "want within 100ms")
	wantFail(t, check(t, c, abortCapture(599.9, 3000.1), abortFacts()), "want exactly one")
	wantFail(t, check(t, c, abortCapture(498), abortFacts()), "want within 100ms")
	wantFail(t, check(t, c, abortCapture(), abortFacts()), "want exactly one")
	noShutdown := abortCapture(500.2)[1:]
	wantFail(t, check(t, c, noShutdown, abortFacts()), "never started the shutdown")
	later := append(abortCapture(500.2), c2s(9, 3000, 41005, chunkSHUTDOWN))
	wantFail(t, check(t, c, later, abortFacts()), "after its ABORT")
	undropped := abortFacts()
	undropped["dropped_0"] = "0"
	wantFail(t, check(t, c, abortCapture(500.2), undropped), "matched nothing")
	violation := abortCapture(500.2)
	violation[1].causes = []uint16{13}
	wantFail(t, check(t, c, violation, abortFacts()), "User-Initiated Abort")
	bare := abortCapture(500.2)
	bare[1].causes = nil
	wantFail(t, check(t, c, bare, abortFacts()), "User-Initiated Abort")

	// The capture must reach past the grace expiry.
	fs := setupFacts()
	fs[c.name] = abortFacts()
	e, err := newEnv(append(abortCapture(500.2), sentinels(t0.Add(3*time.Second))...), fs, 1500)
	if err != nil {
		t.Fatal(err)
	}
	wantFail(t, runClaim(e, c), "proven complete only")
}

func TestCheckAbandon(t *testing.T) {
	facts := map[string]string{"port": "41001", "deadline_ns": ns(500), "return_ns": ns(501), "dropped": "1"}
	abort := claimNamed(t, "abandon-abort-cookie-wait")
	quiet := claimNamed(t, "abandon-quiet-cookie-wait")
	init := c2s(1, 0, 41001, chunkINIT)
	wantPass(t, check(t, abort, []frame{init, userAbort(c2s(2, 500.5, 41001, chunkABORT))}, facts))
	wantFail(t, check(t, abort, []frame{init, c2s(2, 500.5, 41001, chunkABORT)}, facts), "User-Initiated Abort")
	wantFail(t, check(t, abort, []frame{init}, facts), "want exactly one")
	wantFail(t, check(t, abort, []frame{init, s2c(2, 0.1, 41001, chunkINITACK), userAbort(c2s(3, 500.5, 41001, chunkABORT))}, facts), "never held in COOKIE-WAIT")
	wantPass(t, check(t, quiet, []frame{init}, facts))
	wantFail(t, check(t, quiet, []frame{init, c2s(2, 500.5, 41001, chunkABORT)}, facts), "AbandonQuiet sent an ABORT")
	wantFail(t, check(t, quiet, []frame{init, c2s(2, 600, 41001, chunkINIT)}, facts), "after the context ended")

	echoed := claimNamed(t, "abandon-abort-cookie-echoed")
	setup := []frame{init, s2c(2, 0.1, 41001, chunkINITACK), c2s(3, 0.2, 41001, chunkCOOKIEECHO)}
	wantPass(t, check(t, echoed, append(setup, userAbort(c2s(4, 500.5, 41001, chunkABORT))), facts))
	wantFail(t, check(t, echoed, append(setup, s2c(4, 0.3, 41001, chunkCOOKIEACK), userAbort(c2s(5, 500.5, 41001, chunkABORT))), facts), "never held in COOKIE-ECHOED")
}

func TestCheckMore(t *testing.T) {
	c := claimNamed(t, "more")
	d := func(tsn, ppid uint32) dataChunk { return dataChunk{tsn: tsn, ppid: ppid} }
	good := []frame{
		withData(c2s(1, 0, 41017), d(1, ppidAlone1)),
		withData(c2s(2, 1, 41017), d(2, ppidAlone2)),
		withData(c2s(3, 600, 41017), d(3, ppidMore1), d(4, ppidMore2)),
	}
	wantPass(t, check(t, c, good, map[string]string{"port": "41017"}))
	split := []frame{good[0], good[1],
		withData(c2s(3, 600, 41017), d(3, ppidMore1)),
		withData(c2s(4, 601, 41017), d(4, ppidMore2)),
	}
	wantFail(t, check(t, c, split, map[string]string{"port": "41017"}), "want both messages in one packet")
	bundled := []frame{withData(c2s(1, 0, 41017), d(1, ppidAlone1), d(2, ppidAlone2)), good[2]}
	wantFail(t, check(t, c, bundled, map[string]string{"port": "41017"}), "want two packets")
}

func TestCheckPPIDByteOrder(t *testing.T) {
	c := claimNamed(t, "ppid-byte-order")
	ppids := []uint32{0x01020304, 0x11223344, 0x89abcdef, 0xfedcba98}
	facts := map[string]string{"port": "41018"}
	var frames []frame
	for i, p := range ppids {
		facts[fmt.Sprintf("sent_ppid_%d", i)] = fmt.Sprintf("%#x", p)
		facts[fmt.Sprintf("api_ppid_%d", i)] = fmt.Sprintf("%#x", p)
		frames = append(frames, withData(c2s(i+1, float64(i), 41018), dataChunk{tsn: uint32(i), ppid: p}))
	}
	wantPass(t, check(t, c, frames, facts))
	swapped := append([]frame(nil), frames...)
	swapped[0] = withData(c2s(1, 0, 41018), dataChunk{tsn: 0, ppid: 0x04030201})
	wantFail(t, check(t, c, swapped, facts), "0x1020304 on the wire, want one")
	facts["api_ppid_2"] = "0xefcdab89"
	wantFail(t, check(t, c, frames, facts), "received through the API")
}

func TestCheckPRRtxLimit(t *testing.T) {
	c := claimNamed(t, "pr-rtx-limit")
	facts := map[string]string{
		"port": "41021", "limit": "2", "sent_ns": ns(0), "abandoned_ns": ns(1100), "dropped": "3",
		"stream_abandoned_sent": "1", "stream_abandoned_unsent": "0", "assoc_abandoned_sent": "1",
		"first_delivered_ppid": fmt.Sprintf("%#x", ppidAfter),
	}
	tx := func(n int, ms float64) frame {
		return withData(c2s(n, ms, 41021), dataChunk{tsn: 100, ppid: ppidAbandoned})
	}
	fwd := c2s(5, 1000, 41021, chunkFORWARDTSN)
	fwd.fwdTSN = []uint32{100}
	next := withData(c2s(6, 1200, 41021), dataChunk{tsn: 101, ppid: ppidAfter})
	wantPass(t, check(t, c, []frame{tx(1, 0), tx(2, 200), tx(3, 600), fwd, next}, facts))
	wantFail(t, check(t, c, []frame{tx(1, 0), tx(2, 200), tx(3, 600), tx(4, 999), fwd, next}, facts), "on the wire 4 times")
	wantFail(t, check(t, c, []frame{tx(1, 0), tx(2, 200), tx(3, 600), next}, facts), "no FORWARD TSN")
}

func TestCheckRequestHeartbeat(t *testing.T) {
	c := claimNamed(t, "request-heartbeat")
	facts := map[string]string{
		"port":           "41014",
		"quiet_start_ns": ns(0), "quiet_end_ns": ns(400),
		"one_start_ns": ns(400), "one_end_ns": ns(800),
		"every_start_ns": ns(800), "every_end_ns": ns(1200),
	}
	hb := func(n int, ms float64, dst netip.Addr) frame {
		f := c2s(n, ms, 41014, chunkHEARTBEAT)
		f.dst = dst
		if dst == serverB {
			f.src = clientB
		}
		return f
	}
	good := []frame{hb(1, 400.1, serverB), hb(2, 800.1, serverA), hb(3, 800.1, serverB)}
	wantPass(t, check(t, c, good, facts))
	wantFail(t, check(t, c, append(good, hb(4, 100, serverA)), facts), "nothing requested")
	wantFail(t, check(t, c, []frame{hb(1, 400.1, serverA), good[1], good[2]}, facts), "want exactly one, to server-b")
	wantFail(t, check(t, c, []frame{good[0], good[1]}, facts), "one to server-a and one to server-b")
}

// TestClaimsIgnoreAnEphemeralPortEqualToTheCasePort: a frame of another
// association whose client-side ephemeral port happens to equal a case's
// server port belongs to that other association, in either direction, and
// no claim may count it.
func TestClaimsIgnoreAnEphemeralPortEqualToTheCasePort(t *testing.T) {
	c := claimNamed(t, "graceful-close")
	facts := map[string]string{"port": "41022", "close_ns": ns(0), "eof": "1"}
	good := []frame{
		c2s(1, 0.1, 41022, chunkSHUTDOWN),
		s2c(2, 0.2, 41022, chunkSHUTDOWNACK),
		c2s(3, 0.3, 41022, chunkSHUTDOWNCOMPLETE),
	}
	wantPass(t, check(t, c, good, facts))
	// Another association: the client's ephemeral port is 41022, the
	// server's port 41005. Its ABORTs, either way, are not this claim's.
	other := c2s(4, 0.4, 41005, chunkABORT)
	other.sport = 41022
	back := s2c(5, 0.5, 41005, chunkABORT)
	back.dport = 41022
	wantPass(t, check(t, c, append(good, other, back), facts))
	// The claim's own ABORT still fails it.
	wantFail(t, check(t, c, append(good, c2s(6, 0.6, 41022, chunkABORT)), facts), "holds an ABORT")
}
