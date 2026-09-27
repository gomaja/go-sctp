// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"math/bits"
	"time"
)

// claims are the properties proven from the capture, one per case of
// TestWire (wire_linux_test.go), in the order it runs them.
var claims = []claim{
	{"abandon-abort-cookie-wait", 1, checkAbandon(true, false)},
	{"abandon-quiet-cookie-wait", 1, checkAbandon(false, false)},
	{"abandon-abort-cookie-echoed", 1, checkAbandon(true, true)},
	{"abandon-quiet-cookie-echoed", 1, checkAbandon(false, true)},
	{"abort-during-close", 1, checkAbortDuringClose},
	{"abort-during-peeled-close", 1, checkAbortDuringClose},
	{"abort-during-endpoint-close", 2, checkAbortDuringClose},
	{"peeled-close-full-buffer", 1, checkCloseWhileFull},
	{"endpoint-close-full-buffers", 2, checkCloseWhileFull},
	{"sack-immediately", 1, checkSACKImmediately},
	{"unordered", 1, checkUnordered},
	{"request-heartbeat", 1, checkRequestHeartbeat},
	{"periodic-heartbeat", 1, checkPeriodicHeartbeat},
	{"message-interleaving", 1, checkMessageInterleaving},
	{"nowait-refusal", 1, checkNoWaitRefusal},
	{"path", 1, checkPath},
	{"more", 1, checkMore},
	{"ppid-byte-order", 1, checkPPIDByteOrder},
	{"close-after-burst", 1, checkCloseAfterBurst},
	{"simultaneous-close", 1, checkSimultaneousClose},
	{"pr-rtx-limit", 1, checkPRRtxLimit},
	{"graceful-close", 1, checkGracefulClose},
	{"graceful-peeled-close", 1, checkGracefulClose},
}

// The PPIDs wire_linux_test.go marks its messages with.
const (
	ppidPlain      = 0x57490001
	ppidSACKNow    = 0x57490002
	ppidUnordered  = 0x57490003
	ppidOrdered    = 0x57490004
	ppidDefault    = 0x57490005
	ppidFill       = 0x57490006
	ppidRefused    = 0x57490007
	ppidLast       = 0x57490008
	ppidPrimary    = 0x57490009
	ppidPath       = 0x5749000a
	ppidAlone1     = 0x5749000b
	ppidAlone2     = 0x5749000c
	ppidMore1      = 0x5749000d
	ppidMore2      = 0x5749000e
	ppidBurst      = 0x5749000f
	ppidAbandoned  = 0x57490010
	ppidAfter      = 0x57490011
	ppidInterleave = 0x57490013
)

// abortLimit is how soon after the Abort call its ABORT must be on the
// wire.
const abortLimit = 100 * time.Millisecond

// checkAbandon: a Dial abandoned when its context ends sends an ABORT with
// AbandonAbort and nothing with AbandonQuiet, both in COOKIE-WAIT (the
// server's INPUT drops the INIT, so no INIT ACK comes) and in
// COOKIE-ECHOED (the INIT ACK comes and the server's INPUT drops the
// COOKIE ECHO) (RFC 9260 §§5.1, 9.1).
func checkAbandon(abort, echoed bool) func(r *claimRun) {
	return func(r *claimRun) {
		port := r.ports[0]
		deadline, returned := r.time("deadline_ns"), r.time("return_ns")
		out, in := r.out(port), r.in(port)
		init := r.first(out, chunkINIT, "the setup never started")
		r.note("%s", r.describe(init, deadline, "deadline"))
		last := init
		if echoed {
			initAck := r.first(in, chunkINITACK, "the server never answered the INIT")
			echo := r.first(after(out, initAck.at), chunkCOOKIEECHO, "the client never echoed the cookie")
			if !echo.at.Before(deadline) {
				r.failf("the COOKIE ECHO (frame %d) came after the context ended", echo.number)
			}
			if ack := with(in, chunkCOOKIEACK); len(ack) != 0 {
				r.failf("the server answered the COOKIE ECHO (frame %d): the setup was never held in COOKIE-ECHOED", ack[0].number)
			}
			r.note("%s", r.describe(initAck, deadline, "deadline"))
			r.note("%s: the setup is in COOKIE-ECHOED, and no COOKIE ACK ever comes", r.describe(echo, deadline, "deadline"))
			last = echo
		} else {
			if len(in) != 0 {
				r.failf("the server answered (frame %d): the setup was never held in COOKIE-WAIT", in[0].number)
			}
			r.note("no chunk from the server: the setup is in COOKIE-WAIT")
		}
		aborts := with(out, chunkABORT)
		late := after(out, deadline.Add(-tolerance))
		if !abort {
			if len(aborts) != 0 {
				r.failf("AbandonQuiet sent an ABORT (frame %d)", aborts[0].number)
			}
			if len(late) != 0 {
				r.failf("the client sent %s after the context ended", r.describe(late[0], deadline, "deadline"))
			}
			r.covered(returned.Add(900*time.Millisecond), "a second after Dial returned")
			r.dropped("dropped")
			r.note("nothing from the client from the deadline to the end of the capture, deadline%s", signed(r.env.captureEnd.Sub(deadline)))
			return
		}
		if len(aborts) != 1 || aborts[0].count(chunkABORT) != 1 {
			r.failf("%d frames with an ABORT, want exactly one", len(aborts))
		}
		a := aborts[0]
		if a.at.Before(deadline.Add(-tolerance)) || a.at.After(returned.Add(tolerance)) || !a.at.After(last.at) {
			r.failf("the ABORT (frame %d) is at deadline%s, want it after the setup and between the deadline and Dial's return at deadline%s",
				a.number, signed(a.at.Sub(deadline)), signed(returned.Sub(deadline)))
		}
		if len(after(out, a.at)) != 0 {
			r.failf("the client sent more after the ABORT")
		}
		r.userAbort(a)
		r.dropped("dropped")
		r.note("%s with the User-Initiated Abort cause, before Dial returned at deadline%s", r.describe(a, deadline, "deadline"), signed(returned.Sub(deadline)))
	}
}

// checkAbortDuringClose: an Abort called while Close waits for a silent
// peer sends the ABORT at once, less than 100 ms after the call, and the
// ABORT Close would have sent when its grace period ran out never comes
// (RFC 9260 §§9.1, 9.2). The Close had started the shutdown: its SHUTDOWN
// is on the wire before the Abort.
func checkAbortDuringClose(r *claimRun) {
	closeAt, abortAt := r.time("close_ns"), r.time("abort_ns")
	grace := r.duration("grace_ns")
	expiry := closeAt.Add(grace)
	r.covered(expiry.Add(500*time.Millisecond), "the grace period ran out")
	for i, port := range r.ports {
		out := r.out(port)
		shut := r.first(after(out, closeAt.Add(-tolerance)), chunkSHUTDOWN, "Close never started the shutdown")
		if !shut.at.Before(abortAt) {
			r.failf("the SHUTDOWN (frame %d) is at abort%s, want it before the Abort", shut.number, signed(shut.at.Sub(abortAt)))
		}
		aborts := with(out, chunkABORT)
		if len(aborts) != 1 || aborts[0].count(chunkABORT) != 1 {
			r.failf("port %d: %d frames with an ABORT, want exactly one", port, len(aborts))
		}
		a := aborts[0]
		if d := a.at.Sub(abortAt); d < -tolerance || d >= abortLimit {
			r.failf("port %d: the ABORT (frame %d) is at abort%s, want within %v after the Abort call", port, a.number, signed(d), abortLimit)
		}
		if rest := after(out, a.at); len(rest) != 0 {
			r.failf("port %d: the client sent %s after its ABORT", port, r.describe(rest[0], expiry, "grace expiry"))
		}
		r.userAbort(a)
		r.dropped(fmt.Sprintf("dropped_%d", i))
		r.note("%s", r.describe(shut, closeAt, "close"))
		r.note("%s with the User-Initiated Abort cause, limit %v", r.describe(a, abortAt, "abort"), abortLimit)
		r.note("nothing more from the client on port %d up to the end of the capture, grace expiry%s", port, signed(r.env.captureEnd.Sub(expiry)))
	}
}

// checkCloseWhileFull: Close with a full send buffer starts the shutdown
// without waiting for buffer space (an SCTP_EOF send on a peeled or
// one-to-many socket), the kernel sends every queued message once the peer
// drains, and only then the SHUTDOWN, answered by SHUTDOWN ACK and
// SHUTDOWN COMPLETE, with no ABORT (RFC 9260 §9.2).
func checkCloseWhileFull(r *claimRun) {
	closeAt, drainAt := r.time("close_ns"), r.time("drain_ns")
	grace := r.duration("grace_ns")
	for i, port := range r.ports {
		queued := r.int(fmt.Sprintf("queued_%d", i))
		out, in := r.out(port), r.in(port)
		r.noABORT(r.all(port))
		sent := dataWith(out, ppidFill)
		tsns := distinctTSNs(sent)
		if int64(len(tsns)) != queued {
			r.failf("port %d: %d distinct queued messages on the wire, want %d", port, len(tsns), queued)
		}
		top := maxTSN(tsns)
		acked := r.firstSACKCovering(in, top)
		if !acked.at.After(closeAt) {
			r.failf("port %d: every queued message was acknowledged (frame %d) before Close was called: the send buffer was not full of waiting messages", port, acked.number)
		}
		shut := r.first(out, chunkSHUTDOWN, "the shutdown never started")
		if !shut.at.After(drainAt) {
			r.failf("port %d: the SHUTDOWN (frame %d) is at drain%s, before the server started reading", port, shut.number, signed(shut.at.Sub(drainAt)))
		}
		if last := sent[len(sent)-1].f; !shut.at.After(last.at) {
			r.failf("port %d: the SHUTDOWN (frame %d) precedes queued DATA (frame %d)", port, shut.number, last.number)
		}
		if acked.at.After(shut.at) {
			r.failf("port %d: the SHUTDOWN (frame %d) came before the SACK acknowledging every message (frame %d)", port, shut.number, acked.number)
		}
		if d := shut.at.Sub(acked.at); d > 200*time.Millisecond {
			r.failf("port %d: the SHUTDOWN came %v after the last acknowledgement: the shutdown was not pending", port, d)
		}
		if !shut.at.Before(closeAt.Add(grace)) {
			r.failf("port %d: the SHUTDOWN came after the grace period", port)
		}
		shutAck := r.first(after(in, shut.at), chunkSHUTDOWNACK, "the server never acknowledged the SHUTDOWN")
		done := r.first(after(out, shutAck.at), chunkSHUTDOWNCOMPLETE, "the client never completed the shutdown")
		r.note("port %d: %d queued messages, TSNs %d to %d, all on the wire and acknowledged by frame %d at drain%s",
			port, queued, tsns[0], top, acked.number, signed(acked.at.Sub(drainAt)))
		r.note("%s", r.describe(shut, closeAt, "close"))
		r.note("%s", r.describe(shutAck, closeAt, "close"))
		r.note("%s", r.describe(done, closeAt, "close"))
		if got := r.int(fmt.Sprintf("received_%d", i)); got != queued {
			r.failf("port %d: the server received %d of the %d queued messages", port, got, queued)
		}
	}
	if r.int("eof") != 1 {
		r.failf("the server did not reach io.EOF")
	}
	r.note("Close returned at close%s, the server reached io.EOF, no ABORT", signed(r.time("close_return_ns").Sub(closeAt)))
}

// firstSACKCovering is the first frame of in whose SACK acknowledges tsn.
func (r *claimRun) firstSACKCovering(in []frame, tsn uint32) frame {
	for _, f := range in {
		for _, c := range f.sackCum {
			if tsnAtLeast(c, tsn) {
				return f
			}
		}
	}
	r.failf("no SACK acknowledges TSN %d", tsn)
	return frame{}
}

// flagCheck fails unless every transmission of ppid in frames has the
// wanted bit, and there is at least one.
func (r *claimRun) flagCheck(frames []frame, ppid uint32, bit string, get func(dataChunk) bool, want bool) {
	sent := dataWith(frames, ppid)
	if len(sent) == 0 {
		r.failf("no DATA with PPID %#x", ppid)
	}
	for _, s := range sent {
		if get(s.d) != want {
			r.failf("frame %d: DATA TSN %d with PPID %#x has %s %v, want %v", s.f.number, s.d.tsn, ppid, bit, get(s.d), want)
		}
	}
	r.note("PPID %#x: %d DATA chunk(s), %s %v (frame %d, TSN %d)", ppid, len(sent), bit, want, sent[0].f.number, sent[0].d.tsn)
}

func iBit(d dataChunk) bool { return d.i }
func uBit(d dataChunk) bool { return d.u }

// checkSACKImmediately: SendSACKImmediately sets the DATA chunk's I bit
// (RFC 9260 §§3.3.1, 11.1.5), and a message without it leaves the bit
// clear.
func checkSACKImmediately(r *claimRun) {
	out := r.out(r.ports[0])
	r.flagCheck(out, ppidPlain, "I", iBit, false)
	r.flagCheck(out, ppidSACKNow, "I", iBit, true)
}

// checkUnordered: SendUnordered sets the U bit (RFC 9260 §3.3.1), per
// message and as the default SndInfo's flag on a send with only a PrInfo,
// and an explicit SndInfo without the flag leaves it clear.
func checkUnordered(r *claimRun) {
	out := r.out(r.ports[0])
	r.flagCheck(out, ppidUnordered, "U", uBit, true)
	r.flagCheck(out, ppidOrdered, "U", uBit, false)
	r.flagCheck(out, ppidDefault, "U", uBit, true)
}

// checkRequestHeartbeat: with periodic heartbeats off, no HEARTBEAT goes
// out in a quiet window; RequestHeartbeat for the server's network B
// address sends exactly one HEARTBEAT, to that address; RequestHeartbeat
// for the zero address sends exactly one to each of the server's addresses
// (RFC 9260 §8.3; RFC 6458 §8.1.12).
func checkRequestHeartbeat(r *claimRun) {
	serverA, serverB := r.setupAddr("server_a"), r.setupAddr("server_b")
	out := with(r.out(r.ports[0]), chunkHEARTBEAT)
	window := func(name string) map[string]int {
		start, end := r.time(name+"_start_ns"), r.time(name+"_end_ns")
		r.covered(end, "the "+name+" window ended")
		got := map[string]int{}
		for _, f := range out {
			if !f.at.Before(start.Add(-tolerance)) && !f.at.After(end) {
				got[r.env.names[f.dst]] += f.count(chunkHEARTBEAT)
				r.note("%s window: %s", name, r.describe(f, start, name))
			}
		}
		return got
	}
	a, b := r.env.names[serverA], r.env.names[serverB]
	if got := window("quiet"); len(got) != 0 {
		r.failf("HEARTBEATs %v with nothing requested: periodic heartbeats are not off", got)
	}
	if got := window("one"); len(got) != 1 || got[b] != 1 {
		r.failf("RequestHeartbeat(%s) sent HEARTBEATs %v, want exactly one, to %s", b, got, b)
	}
	if got := window("every"); len(got) != 2 || got[a] != 1 || got[b] != 1 {
		r.failf("RequestHeartbeat(zero address) sent HEARTBEATs %v, want exactly one to %s and one to %s", got, a, b)
	}
}

// checkPeriodicHeartbeat checks the idle path timers (RFC 9260 §8.3).
// net/sctp/transport.c: sctp_transport_timeout and
// sctp_transport_reset_hb_timer schedule each heartbeat at the interval
// plus RTO/2 plus a random value below RTO.
func checkPeriodicHeartbeat(r *claimRun) {
	start, end := r.time("start_ns"), r.time("end_ns")
	r.covered(end, "the idle heartbeat window ended")
	interval, rtoMin, rtoMax := r.duration("interval_ns"), r.duration("rto_min_ns"), r.duration("rto_max_ns")
	if interval <= 0 || rtoMin <= 0 || rtoMax < rtoMin {
		r.failf("invalid heartbeat timer bounds: interval %v, RTO %v-%v", interval, rtoMin, rtoMax)
	}
	var beats, acks []frame
	for _, f := range r.out(r.ports[0]) {
		if f.has(chunkHEARTBEAT) && !f.at.Before(start) && !f.at.After(end) {
			beats = append(beats, f)
		}
	}
	// A HEARTBEAT sent just before the window closes is answered after it.
	// RFC 9260 §8.3 counts a HEARTBEAT as unacknowledged only once one RTO
	// has passed, so its HEARTBEAT ACK is accepted up to the largest RTO
	// after the window, and the capture must reach that far.
	ackLimit := end.Add(rtoMax)
	r.covered(ackLimit, "the answer to a HEARTBEAT sent as the idle window closed")
	for _, f := range r.in(r.ports[0]) {
		if f.has(chunkHEARTBEATACK) && !f.at.Before(start) && !f.at.After(ackLimit) {
			acks = append(acks, f)
		}
	}
	if len(beats) == 0 {
		r.failf("no HEARTBEAT in the idle window")
	}
	for _, key := range []string{"server_a", "server_b"} {
		addr := r.setupAddr(key)
		var path []frame
		for _, f := range beats {
			if f.dst == addr {
				path = append(path, f)
			}
		}
		if len(path) < 2 {
			r.failf("%s has %d HEARTBEATs, fewer than two", r.env.names[addr], len(path))
		}
		for i, f := range path {
			if f.count(chunkHEARTBEAT) != 1 {
				r.failf("frame %d has %d HEARTBEAT chunks, want one", f.number, f.count(chunkHEARTBEAT))
			}
			// The answer must come before the next HEARTBEAT on the path,
			// inside the window or after it, so that the answer to a later
			// probe cannot stand in for a missing one.
			next, hasNext := time.Time{}, false
			for _, g := range r.out(r.ports[0]) {
				if g.has(chunkHEARTBEAT) && g.dst == addr && g.at.After(f.at) && (!hasNext || g.at.Before(next)) {
					next, hasNext = g.at, true
				}
			}
			var ack *frame
			for j := range acks {
				if acks[j].src == addr && acks[j].dst == f.src && acks[j].at.After(f.at) &&
					(!hasNext || acks[j].at.Before(next)) {
					ack = &acks[j]
					break
				}
			}
			if ack == nil {
				r.failf("frame %d HEARTBEAT to %s has no HEARTBEAT ACK", f.number, r.env.names[addr])
			}
			r.note("frame %d HEARTBEAT to %s answered by frame %d", f.number, r.env.names[addr], ack.number)
			if i == 0 {
				continue
			}
			spacing := f.at.Sub(path[i-1].at)
			low := interval + rtoMin/2 - tolerance
			high := interval + 3*rtoMax/2 + tolerance
			if spacing < low || spacing > high {
				r.failf("%s HEARTBEAT spacing %v outside %v-%v (net/sctp/transport.c: sctp_transport_timeout, sctp_transport_reset_hb_timer)", r.env.names[addr], spacing, low, high)
			}
			r.note("%s HEARTBEAT spacing %v (timer range %v-%v)", r.env.names[addr], spacing, low, high)
		}
	}
}

// checkMessageInterleaving proves the two large messages used I-DATA, with
// one stream's fragments separated by the other's (RFC 8260 §§2.1-2.2).
func checkMessageInterleaving(r *claimRun) {
	out := r.out(r.ports[0])
	var fragments []dataChunk
	var fragmentFrames []int
	seenTSN := map[uint32]bool{}
	for _, f := range out {
		if f.has(chunkDATA) {
			r.failf("frame %d has a DATA chunk on the I-DATA association", f.number)
		}
		for _, d := range f.data {
			if d.kind != chunkIDATA {
				continue
			}
			if !seenTSN[d.tsn] {
				fragments = append(fragments, d)
				fragmentFrames = append(fragmentFrames, f.number)
				seenTSN[d.tsn] = true
			}
		}
	}
	if len(fragments) == 0 {
		r.failf("no I-DATA on the association")
	}
	var counts, begins [2]int
	for _, d := range fragments {
		if d.sid > 1 {
			r.failf("I-DATA on unexpected stream %d", d.sid)
		}
		counts[d.sid]++
		if d.b {
			begins[d.sid]++
			if want := ppidInterleave + uint32(d.sid); d.ppid != want {
				r.failf("stream %d I-DATA PPID %#x, want %#x", d.sid, d.ppid, want)
			}
		}
	}
	for sid := range counts {
		if counts[sid] < 2 || begins[sid] != 1 {
			r.failf("stream %d has %d I-DATA fragments and %d beginnings, want multiple fragments of one message", sid, counts[sid], begins[sid])
		}
	}
	first, middle, last := -1, -1, -1
	for i := 0; i < len(fragments); i++ {
		for j := i + 1; j < len(fragments); j++ {
			if fragments[j].sid == fragments[i].sid {
				continue
			}
			for k := j + 1; k < len(fragments); k++ {
				if fragments[k].sid == fragments[i].sid {
					first, middle, last = i, j, k
					break
				}
			}
			if first >= 0 {
				break
			}
		}
		if first >= 0 {
			break
		}
	}
	if first < 0 {
		r.failf("I-DATA fragments of the two streams were not interleaved")
	}
	if dropped := r.int("dropped"); dropped < 1 {
		r.failf("the receiver's INPUT drop matched %d packets", dropped)
	}
	if received, eof := r.int("received"), r.int("eof"); received != 2 || eof != 1 {
		r.failf("the server received %d complete messages, EOF %d; want two and EOF", received, eof)
	}
	r.note("frames %d, %d, %d: I-DATA streams %d, %d, %d interleaved",
		fragmentFrames[first], fragmentFrames[middle], fragmentFrames[last],
		fragments[first].sid, fragments[middle].sid, fragments[last].sid)
	r.note("%d stream-0 and %d stream-1 I-DATA fragments, no DATA, %d receiver INPUT drops, both complete messages received",
		counts[0], counts[1], r.int("dropped"))
}

// checkNoWaitRefusal: a NoWait send refused with EAGAIN puts no DATA on
// the wire, anywhere in the capture, while every message queued before it
// and the one sent after it arrive.
func checkNoWaitRefusal(r *claimRun) {
	if refused := dataWith(r.env.frames, ppidRefused); len(refused) != 0 {
		r.failf("the refused message is on the wire: frame %d, TSN %d", refused[0].f.number, refused[0].d.tsn)
	}
	out := r.out(r.ports[0])
	queued := r.int("queued")
	if n := int64(len(distinctTSNs(dataWith(out, ppidFill)))); n != queued {
		r.failf("%d distinct queued messages on the wire, want %d", n, queued)
	}
	last := dataWith(out, ppidLast)
	if len(last) == 0 {
		r.failf("the message sent after the refusal is not on the wire")
	}
	if got := r.int("received_fill"); got != queued {
		r.failf("the server received %d of the %d queued messages", got, queued)
	}
	refusedAt := r.time("refused_ns")
	r.covered(last[0].f.at, "the last message went out")
	r.note("%d queued messages on the wire; the refused NoWait send put no DATA with PPID %#x in any of the capture's %d frames",
		queued, ppidRefused, len(r.env.frames))
	r.note("%s carries the message sent after the refusal", r.describe(last[0].f, refusedAt, "refusal"))
}

// checkPath: on a two-homed association every DATA chunk sent with
// SendOptions.Path goes to that address, the server's network B one, and
// every other DATA chunk follows the primary path, to network A.
func checkPath(r *claimRun) {
	serverA, serverB := r.setupAddr("server_a"), r.setupAddr("server_b")
	out := r.out(r.ports[0])
	each := r.int("each")
	for _, c := range []struct {
		ppid uint32
		to   string
		want string
	}{{ppidPath, "server_b", r.env.names[serverB]}, {ppidPrimary, "server_a", r.env.names[serverA]}} {
		sent := dataWith(out, c.ppid)
		if n := int64(len(distinctTSNs(sent))); n != each {
			r.failf("%d messages with PPID %#x on the wire, want %d", n, c.ppid, each)
		}
		for _, s := range sent {
			if got := r.env.names[s.f.dst]; got != c.want {
				r.failf("frame %d: DATA TSN %d with PPID %#x went to %s, want %s", s.f.number, s.d.tsn, c.ppid, got, c.want)
			}
		}
		r.note("PPID %#x: %d DATA chunks, every one to %s (first: frame %d)", c.ppid, len(sent), c.want, sent[0].f.number)
	}
}

// checkMore: with NoDelay on, two small messages sent without More leave
// in two packets, and two sent with More on the first leave in one.
func checkMore(r *claimRun) {
	out := r.out(r.ports[0])
	firstFrame := func(ppid uint32) frame {
		sent := dataWith(out, ppid)
		if len(sent) == 0 {
			r.failf("no DATA with PPID %#x", ppid)
		}
		return sent[0].f
	}
	a1, a2 := firstFrame(ppidAlone1), firstFrame(ppidAlone2)
	if a1.number == a2.number || len(a1.data) != 1 || len(a2.data) != 1 {
		r.failf("without More: frames %d (%d DATA) and %d (%d DATA), want two packets of one DATA chunk each", a1.number, len(a1.data), a2.number, len(a2.data))
	}
	m1, m2 := firstFrame(ppidMore1), firstFrame(ppidMore2)
	if m1.number != m2.number || len(m1.data) != 2 {
		r.failf("with More: frames %d and %d (%d DATA), want both messages in one packet", m1.number, m2.number, len(m1.data))
	}
	r.note("without More: frame %d and frame %d, one DATA chunk each", a1.number, a2.number)
	r.note("with More: frame %d holds both DATA chunks, TSNs %d and %d", m1.number, m1.data[0].tsn, m1.data[1].tsn)
}

// checkPPIDByteOrder: every PPID is on the wire as the value the API was
// given, which is network byte order on the wire (RFC 9260 §3.3.1), and the
// server's API returned the same value; no DATA chunk carries a
// byte-swapped one.
func checkPPIDByteOrder(r *claimRun) {
	out := r.out(r.ports[0])
	swapped := map[uint32]uint32{}
	for i := range 4 {
		want := r.uint32(fmt.Sprintf("sent_ppid_%d", i))
		sent := dataWith(out, want)
		if len(sent) != 1 {
			r.failf("%d DATA chunks with PPID %#x on the wire, want one", len(sent), want)
		}
		swapped[bits.ReverseBytes32(want)] = want
		if got := r.uint32(fmt.Sprintf("api_ppid_%d", i)); got != want {
			r.failf("message %d: sent with PPID %#x, on the wire as %#x, received through the API as %#x", i, want, want, got)
		}
		r.note("frame %d: DATA TSN %d, PPID %#x on the wire and through both APIs", sent[0].f.number, sent[0].d.tsn, want)
	}
	for _, f := range out {
		for _, d := range f.data {
			if orig, ok := swapped[d.ppid]; ok && orig != d.ppid {
				r.failf("frame %d carries PPID %#x, the byte-swapped %#x", f.number, d.ppid, orig)
			}
		}
	}
}

// checkCloseAfterBurst: Close called while a burst is still queued sends
// every queued message before the SHUTDOWN (RFC 9260 §9.2), and the
// shutdown completes without an ABORT.
func checkCloseAfterBurst(r *claimRun) {
	closeAt := r.time("close_ns")
	count := r.int("count")
	out, in := r.out(r.ports[0]), r.in(r.ports[0])
	r.noABORT(r.all(r.ports[0]))
	sent := dataWith(out, ppidBurst)
	tsns := distinctTSNs(sent)
	if int64(len(tsns)) != count {
		r.failf("%d distinct messages of the burst on the wire, want %d", len(tsns), count)
	}
	last := sent[len(sent)-1].f
	if !last.at.After(closeAt) {
		r.failf("the whole burst was on the wire before Close was called: nothing was queued")
	}
	shut := r.first(out, chunkSHUTDOWN, "the shutdown never started")
	if !shut.at.After(last.at) {
		r.failf("the SHUTDOWN (frame %d) precedes DATA of the burst (frame %d)", shut.number, last.number)
	}
	acked := r.firstSACKCovering(in, maxTSN(tsns))
	if acked.at.After(shut.at) {
		r.failf("the SHUTDOWN (frame %d) came before the SACK acknowledging the whole burst (frame %d)", shut.number, acked.number)
	}
	shutAck := r.first(after(in, shut.at), chunkSHUTDOWNACK, "the server never acknowledged the SHUTDOWN")
	done := r.first(after(out, shutAck.at), chunkSHUTDOWNCOMPLETE, "the client never completed the shutdown")
	queued := 0
	for _, s := range sent {
		if s.f.at.After(closeAt) {
			queued++
		}
	}
	r.note("%d messages, TSNs %d to %d; %d DATA transmissions after Close was called, the last in frame %d at close%s",
		count, tsns[0], maxTSN(tsns), queued, last.number, signed(last.at.Sub(closeAt)))
	r.note("frame %d acknowledges the whole burst at close%s", acked.number, signed(acked.at.Sub(closeAt)))
	r.note("%s", r.describe(shut, closeAt, "close"))
	r.note("%s", r.describe(shutAck, closeAt, "close"))
	r.note("%s", r.describe(done, closeAt, "close"))
	if got := r.int("received"); got != count || r.int("eof") != 1 {
		r.failf("the server received %d of %d messages (io.EOF: %v)", got, count, r.facts["eof"])
	}
}

// checkSimultaneousClose: both ends' SHUTDOWNs are on the wire before
// either end acknowledges one, so both ends were in SHUTDOWN-SENT at once,
// and the association still ends with SHUTDOWN ACK and SHUTDOWN COMPLETE
// and no ABORT (RFC 9260 §9.2).
func checkSimultaneousClose(r *claimRun) {
	clientAt, serverAt := r.time("client_close_ns"), r.time("server_close_ns")
	if d := clientAt.Sub(serverAt).Abs(); d > 50*time.Millisecond {
		r.failf("the two Close calls were %v apart", d)
	}
	all := r.all(r.ports[0])
	out, in := r.out(r.ports[0]), r.in(r.ports[0])
	r.noABORT(all)
	shutOut := r.first(out, chunkSHUTDOWN, "the client never sent a SHUTDOWN")
	shutIn := r.first(in, chunkSHUTDOWN, "the server never sent a SHUTDOWN")
	ack := r.first(all, chunkSHUTDOWNACK, "nobody acknowledged a SHUTDOWN")
	if !shutOut.at.Before(ack.at) || !shutIn.at.Before(ack.at) {
		r.failf("the first SHUTDOWN ACK (frame %d) precedes a SHUTDOWN: the closes did not cross", ack.number)
	}
	done := r.first(after(all, ack.at), chunkSHUTDOWNCOMPLETE, "the shutdown never completed")
	r.dropped("client_dropped")
	r.dropped("server_dropped")
	r.note("%s", r.describe(shutOut, clientAt, "client close"))
	r.note("%s", r.describe(shutIn, clientAt, "client close"))
	r.note("%s: the first acknowledgement, after both SHUTDOWNs", r.describe(ack, clientAt, "client close"))
	r.note("%s; no ABORT either way", r.describe(done, clientAt, "client close"))
}

// checkPRRtxLimit: a message with a PRRtx limit of 2, sent while the
// server drops everything, is on the wire exactly three times, the
// original and two retransmissions, and is then abandoned: a FORWARD TSN
// moves the peer past it (RFC 3758 §3.5), the next message follows it, and
// PRStreamStatus and PRAssocStatus count it (RFC 7496 §4).
func checkPRRtxLimit(r *claimRun) {
	limit := r.int("limit")
	sentAt, abandonedAt := r.time("sent_ns"), r.time("abandoned_ns")
	out := r.out(r.ports[0])
	sent := dataWith(out, ppidAbandoned)
	tsns := distinctTSNs(sent)
	if len(tsns) != 1 {
		r.failf("%d TSNs carry the message, want one", len(tsns))
	}
	if int64(len(sent)) != limit+1 {
		r.failf("the message is on the wire %d times, want %d: the original and %d retransmissions", len(sent), limit+1, limit)
	}
	for k, s := range sent {
		r.note("transmission %d: %s", k+1, r.describe(s.f, sentAt, "send"))
	}
	last := sent[len(sent)-1].f
	if last.at.After(abandonedAt) {
		r.failf("a transmission (frame %d) came after PRStreamStatus counted the message abandoned", last.number)
	}
	var fwd *frame
	for _, f := range with(after(out, last.at), chunkFORWARDTSN) {
		for _, t := range f.fwdTSN {
			if tsnAtLeast(t, tsns[0]) {
				fwd = &f
				break
			}
		}
		if fwd != nil {
			break
		}
	}
	if fwd == nil {
		r.failf("no FORWARD TSN moves the peer past TSN %d", tsns[0])
	}
	r.note("%s, new cumulative TSN %d", r.describe(*fwd, sentAt, "send"), fwd.fwdTSN[0])
	next := dataWith(out, ppidAfter)
	if len(next) == 0 || !tsnAtLeast(next[0].d.tsn, tsns[0]+1) {
		r.failf("the message sent after the abandoned one is missing or does not follow it")
	}
	r.dropped("dropped")
	if r.int("stream_abandoned_sent") != 1 || r.int("stream_abandoned_unsent") != 0 || r.int("assoc_abandoned_sent") != 1 {
		r.failf("PR status: stream %s sent / %s unsent, association %s sent; want 1, 0, 1",
			r.facts["stream_abandoned_sent"], r.facts["stream_abandoned_unsent"], r.facts["assoc_abandoned_sent"])
	}
	if got := r.uint32("first_delivered_ppid"); got != ppidAfter {
		r.failf("the server's first message has PPID %#x, want the one sent after the abandoned one", got)
	}
	r.note("PRStreamStatus and PRAssocStatus count it abandoned after being sent; the server's first message is the next one, TSN %d", next[0].d.tsn)
}

// checkGracefulClose: Close performs SHUTDOWN, SHUTDOWN ACK, SHUTDOWN
// COMPLETE, in that order, with no ABORT and no DATA after the SHUTDOWN
// (RFC 9260 §9.2), and the server reads io.EOF.
func checkGracefulClose(r *claimRun) {
	closeAt := r.time("close_ns")
	out, in := r.out(r.ports[0]), r.in(r.ports[0])
	r.noABORT(r.all(r.ports[0]))
	shut := r.first(after(out, closeAt.Add(-tolerance)), chunkSHUTDOWN, "Close never started the shutdown")
	if d := with(after(out, shut.at), chunkDATA); len(d) != 0 {
		r.failf("DATA (frame %d) after the SHUTDOWN", d[0].number)
	}
	shutAck := r.first(after(in, shut.at), chunkSHUTDOWNACK, "the server never acknowledged the SHUTDOWN")
	done := r.first(after(out, shutAck.at), chunkSHUTDOWNCOMPLETE, "the client never completed the shutdown")
	r.note("%s", r.describe(shut, closeAt, "close"))
	r.note("%s", r.describe(shutAck, closeAt, "close"))
	r.note("%s", r.describe(done, closeAt, "close"))
	if r.int("eof") != 1 {
		r.failf("the server did not reach io.EOF")
	}
}

// dropped fails unless the INPUT drop the fact key counts matched a
// packet: a drop that matched nothing never made the loss the case needs.
func (r *claimRun) dropped(key string) {
	if r.int(key) == 0 {
		r.failf("the INPUT drop (%s) matched nothing", key)
	}
}
