// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"
)

func TestCheckPositiveCounts(t *testing.T) {
	for _, tc := range []struct {
		claim string
		key   string
	}{
		{"path", "each"},
		{"close-after-burst", "count"},
		{"nowait-refusal", "queued"},
		{"peeled-close-full-buffer", "queued_0"},
	} {
		t.Run(tc.claim, func(t *testing.T) {
			for _, value := range []string{"", "-1", "0"} {
				t.Run("count="+value, func(t *testing.T) {
					facts := map[string]string{"port": "41001", "close_ns": ns(10), "drain_ns": ns(15), "grace_ns": "1000000000"}
					if value != "" {
						facts[tc.key] = value
					}
					want := "no fact " + tc.key
					if value != "" {
						want = tc.key + " must be positive"
					}
					frames := []frame{c2s(1, 0, 41001, chunkINIT)}
					if tc.claim == "nowait-refusal" {
						facts["received_fill"] = "0"
						facts["refused_ns"] = ns(1)
						frames = append(frames, withData(c2s(2, 2, 41001), dataChunk{tsn: 1, ppid: ppidLast}))
					}
					wantFail(t, check(t, claimNamed(t, tc.claim), frames, facts), want)
				})
			}
		})
	}
}

// captureCase starts with a complete synthetic capture and changes one fact or
// frame at a time, so each failure identifies the property the checker lost.
type captureCase struct {
	name   string
	change func([]frame, map[string]string) []frame
	want   string
}

func checkCaptureCases(t *testing.T, name string, good []frame, facts map[string]string, cases []captureCase) {
	t.Helper()
	c := claimNamed(t, name)
	t.Run("complete", func(t *testing.T) { wantPass(t, check(t, c, good, facts)) })
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frames := slices.Clone(good)
			for i := range frames {
				frames[i].chunks = slices.Clone(frames[i].chunks)
				frames[i].data = slices.Clone(frames[i].data)
				frames[i].sackCum = slices.Clone(frames[i].sackCum)
			}
			changed := maps.Clone(facts)
			frames = tc.change(frames, changed)
			if tc.want == "" {
				wantPass(t, check(t, c, frames, changed))
			} else {
				wantFail(t, check(t, c, frames, changed), tc.want)
			}
		})
	}
}

func factCase(key, value, want string) captureCase {
	return captureCase{key + "=" + value, func(f []frame, facts map[string]string) []frame {
		facts[key] = value
		return f
	}, want}
}

func removeFrame(i int, want string) captureCase {
	return captureCase{fmt.Sprintf("missing-frame-%d", i), func(f []frame, _ map[string]string) []frame {
		return append(f[:i], f[i+1:]...)
	}, want}
}

func sack(n int, ms float64, port uint16, tsn uint32) frame {
	f := s2c(n, ms, port, chunkSACK)
	f.sackCum = []uint32{tsn}
	return f
}

func TestCheckSACKImmediately(t *testing.T) {
	good := []frame{
		withData(c2s(1, 0, 41001), dataChunk{tsn: 1, ppid: ppidPlain}),
		withData(c2s(2, 1, 41001), dataChunk{tsn: 2, ppid: ppidSACKNow, i: true}),
	}
	cases := []captureCase{removeFrame(0, "no DATA"), removeFrame(1, "no DATA")}
	for i := range good {
		cases = append(cases, captureCase{fmt.Sprintf("wrong-bit-%d", i), func(f []frame, _ map[string]string) []frame {
			f[i].data[0].i = !f[i].data[0].i
			return f
		}, "has I"})
		cases = append(cases, captureCase{fmt.Sprintf("wrong-retransmission-%d", i), func(f []frame, _ map[string]string) []frame {
			retry := withData(c2s(3, 2, 41001), f[i].data[0])
			retry.data[0].i = !retry.data[0].i
			return append(f, retry)
		}, "has I"})
	}
	checkCaptureCases(t, "sack-immediately", good, map[string]string{"port": "41001"}, cases)
}

func TestCheckUnordered(t *testing.T) {
	good := []frame{
		withData(c2s(1, 0, 41001), dataChunk{tsn: 1, ppid: ppidUnordered, u: true}),
		withData(c2s(2, 1, 41001), dataChunk{tsn: 2, ppid: ppidOrdered}),
		withData(c2s(3, 2, 41001), dataChunk{tsn: 3, ppid: ppidDefault, u: true}),
	}
	var cases []captureCase
	for i := range good {
		cases = append(cases, removeFrame(i, "no DATA"))
		cases = append(cases, captureCase{fmt.Sprintf("wrong-bit-%d", i), func(f []frame, _ map[string]string) []frame {
			f[i].data[0].u = !f[i].data[0].u
			return f
		}, "has U"})
		cases = append(cases, captureCase{fmt.Sprintf("wrong-retransmission-%d", i), func(f []frame, _ map[string]string) []frame {
			retry := withData(c2s(4, 3, 41001), f[i].data[0])
			retry.data[0].u = !retry.data[0].u
			return append(f, retry)
		}, "has U"})
	}
	checkCaptureCases(t, "unordered", good, map[string]string{"port": "41001"}, cases)
}

func TestCheckNoWaitRefusal(t *testing.T) {
	for _, count := range []int{1, 2} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			good := []frame{}
			for i := range count {
				good = append(good, withData(c2s(i+1, float64(i), 41001), dataChunk{tsn: uint32(i + 1), ppid: ppidFill}))
			}
			good = append(good, withData(c2s(3, 20, 41001), dataChunk{tsn: 3, ppid: ppidLast}))
			facts := map[string]string{"port": "41001", "queued": fmt.Sprint(count), "received_fill": fmt.Sprint(count), "refused_ns": ns(10)}
			checkCaptureCases(t, "nowait-refusal", good, facts, []captureCase{
				{"refused-on-other-port", func(f []frame, _ map[string]string) []frame {
					return append(f, withData(c2s(4, 21, 41002), dataChunk{tsn: 4, ppid: ppidRefused}))
				}, "refused message"},
				removeFrame(0, "distinct queued messages"),
				{"extra-message", func(f []frame, _ map[string]string) []frame {
					return append(f, withData(c2s(4, 21, 41001), dataChunk{tsn: 99, ppid: ppidFill}))
				}, "distinct queued messages"},
				removeFrame(len(good)-1, "after the refusal"),
				factCase("received_fill", "0", "the server received"),
			})
		})
	}
}

func TestCheckPath(t *testing.T) {
	for _, count := range []int{1, 2} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			var good []frame
			for i := range count {
				path := withData(c2s(2*i+1, float64(2*i), 41001), dataChunk{tsn: uint32(2*i + 1), ppid: ppidPath})
				path.dst = serverB
				good = append(good, path, withData(c2s(2*i+2, float64(2*i+1), 41001), dataChunk{tsn: uint32(2*i + 2), ppid: ppidPrimary}))
			}
			cases := []captureCase{removeFrame(0, "messages with PPID"), removeFrame(1, "messages with PPID")}
			for _, ppid := range []uint32{ppidPath, ppidPrimary} {
				cases = append(cases, captureCase{fmt.Sprintf("extra-message-%x", ppid), func(f []frame, _ map[string]string) []frame {
					extra := withData(c2s(9, 9, 41001), dataChunk{tsn: 99, ppid: ppid})
					if ppid == ppidPath {
						extra.dst = serverB
					}
					return append(f, extra)
				}, "messages with PPID"})
			}
			for i := range good {
				cases = append(cases, captureCase{fmt.Sprintf("wrong-path-%d", i), func(f []frame, _ map[string]string) []frame {
					if f[i].dst == serverB {
						f[i].dst = serverA
					} else {
						f[i].dst = serverB
					}
					return f
				}, "went to"})
			}
			checkCaptureCases(t, "path", good, map[string]string{"port": "41001", "each": fmt.Sprint(count)}, cases)
		})
	}
}

func TestCheckCloseAfterBurst(t *testing.T) {
	for _, count := range []int{1, 2} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			good := []frame{}
			for i := range count {
				good = append(good, withData(c2s(i+1, float64(11+i), 41001), dataChunk{tsn: uint32(i + 1), ppid: ppidBurst}))
			}
			good = append(good, sack(3, 20, 41001, uint32(count)), c2s(4, 21, 41001, chunkSHUTDOWN), s2c(5, 22, 41001, chunkSHUTDOWNACK), c2s(6, 23, 41001, chunkSHUTDOWNCOMPLETE))
			facts := map[string]string{"port": "41001", "count": fmt.Sprint(count), "close_ns": ns(10), "received": fmt.Sprint(count), "eof": "1"}
			checkCaptureCases(t, "close-after-burst", good, facts, []captureCase{
				removeFrame(0, "distinct messages"),
				{"extra-message", func(f []frame, _ map[string]string) []frame {
					return append(f, withData(c2s(9, 19, 41001), dataChunk{tsn: 99, ppid: ppidBurst}))
				}, "distinct messages"},
				factCase("close_ns", ns(float64(11+count)), "nothing was queued"),
				factCase("close_ns", ns(float64(10+count)), "nothing was queued"),
				factCase("close_ns", fmt.Sprint(good[count-1].at.UnixNano()-1), ""),
				{"shutdown-at-data", func(f []frame, _ map[string]string) []frame { f[count+1].at = f[count-1].at; return f }, "precedes DATA"},
				{"sack-at-shutdown", func(f []frame, _ map[string]string) []frame { f[count].at = f[count+1].at; return f }, ""},
				{"shutdown-before-data", func(f []frame, _ map[string]string) []frame { f[count+1].at = t0; return f }, "precedes DATA"},
				removeFrame(count, "no SACK"),
				{"sack-too-small", func(f []frame, _ map[string]string) []frame { f[count].sackCum[0]--; return f }, "no SACK"},
				{"shutdown-before-sack", func(f []frame, _ map[string]string) []frame {
					f[count].at = f[count+1].at.Add(time.Nanosecond)
					return f
				}, "came before the SACK"},
				removeFrame(count+1, "shutdown never started"),
				removeFrame(count+2, "never acknowledged"),
				removeFrame(count+3, "never completed"),
				{"abort", func(f []frame, _ map[string]string) []frame { return append(f, c2s(7, 24, 41001, chunkABORT)) }, "ABORT"},
				factCase("received", "0", "the server received"),
				factCase("eof", "0", "io.EOF"),
			})
		})
	}
}

func TestCheckCloseWhileFull(t *testing.T) {
	for _, name := range []string{"peeled-close-full-buffer", "endpoint-close-full-buffers"} {
		t.Run(name, func(t *testing.T) {
			c := claimNamed(t, name)
			facts := map[string]string{"port": "41001", "close_ns": ns(10), "drain_ns": ns(15), "grace_ns": "1000000000", "close_return_ns": ns(30), "eof": "1"}
			var good []frame
			for i := range c.ports {
				port := uint16(41001 + i)
				facts[fmt.Sprintf("queued_%d", i)] = "2"
				facts[fmt.Sprintf("received_%d", i)] = "2"
				good = append(good,
					withData(c2s(i*6+1, 0, port), dataChunk{tsn: 1, ppid: ppidFill}),
					withData(c2s(i*6+2, 16, port), dataChunk{tsn: 2, ppid: ppidFill}),
					sack(i*6+3, 20, port, 2),
					c2s(i*6+4, 21, port, chunkSHUTDOWN),
					s2c(i*6+5, 22, port, chunkSHUTDOWNACK),
					c2s(i*6+6, 23, port, chunkSHUTDOWNCOMPLETE))
			}
			cases := []captureCase{
				factCase("eof", "0", "io.EOF"),
				factCase("close_ns", ns(20), "before Close was called"),
				factCase("close_ns", fmt.Sprint(t0.Add(20*time.Millisecond).UnixNano()-1), ""),
				factCase("drain_ns", ns(21), "before the server started reading"),
				factCase("drain_ns", fmt.Sprint(t0.Add(21*time.Millisecond).UnixNano()-1), ""),
				factCase("grace_ns", "11000000", "after the grace period"),
				factCase("grace_ns", "11000001", ""),
			}
			for i := range c.ports {
				base := i * 6
				cases = append(cases,
					captureCase{fmt.Sprintf("data-at-shutdown-%d", i), func(f []frame, _ map[string]string) []frame { f[base+1].at = f[base+3].at; return f }, "precedes queued DATA"},
					captureCase{fmt.Sprintf("sack-at-shutdown-%d", i), func(f []frame, _ map[string]string) []frame { f[base+2].at = f[base+3].at; return f }, ""},
					captureCase{fmt.Sprintf("empty-queue-%d", i), func(f []frame, facts map[string]string) []frame { facts[fmt.Sprintf("queued_%d", i)] = "0"; return f }, "must be positive"},
					captureCase{fmt.Sprintf("negative-queue-%d", i), func(f []frame, facts map[string]string) []frame { facts[fmt.Sprintf("queued_%d", i)] = "-1"; return f }, "must be positive"},
					captureCase{fmt.Sprintf("unset-queue-%d", i), func(f []frame, facts map[string]string) []frame { delete(facts, fmt.Sprintf("queued_%d", i)); return f }, "no fact"},
					captureCase{fmt.Sprintf("one-message-%d", i), func(f []frame, facts map[string]string) []frame {
						facts[fmt.Sprintf("queued_%d", i)] = "1"
						facts[fmt.Sprintf("received_%d", i)] = "1"
						f[base].data = nil
						f[base].chunks = []int{chunkINIT}
						return f
					}, ""},
					removeFrame(base, "distinct queued messages"),
					captureCase{fmt.Sprintf("extra-message-%d", i), func(f []frame, _ map[string]string) []frame {
						f[base+2].sackCum[0] = 99
						extra := withData(c2s(20, 1, uint16(41001+i)), dataChunk{tsn: 99, ppid: ppidFill})
						return append(f[:base+1], append([]frame{extra}, f[base+1:]...)...)
					}, "distinct queued messages"},
					removeFrame(base+2, "no SACK"),
					removeFrame(base+3, "shutdown never started"),
					removeFrame(base+4, "never acknowledged"),
					removeFrame(base+5, "never completed"),
					factCase(fmt.Sprintf("received_%d", i), "1", "the server received"),
					captureCase{fmt.Sprintf("early-sack-%d", i), func(f []frame, _ map[string]string) []frame { f[base+2].at = t0; return f }, "before Close was called"},
					captureCase{fmt.Sprintf("early-shutdown-%d", i), func(f []frame, _ map[string]string) []frame { f[base+3].at = t0; return f }, "before the server started reading"},
					captureCase{fmt.Sprintf("late-data-%d", i), func(f []frame, _ map[string]string) []frame {
						f[base+1].at = f[base+3].at.Add(time.Nanosecond)
						return f
					}, "precedes queued DATA"},
					captureCase{fmt.Sprintf("late-sack-%d", i), func(f []frame, _ map[string]string) []frame {
						f[base+2].at = f[base+3].at.Add(time.Nanosecond)
						return f
					}, "came before the SACK"},
					captureCase{fmt.Sprintf("late-shutdown-%d", i), func(f []frame, _ map[string]string) []frame {
						for j := 3; j < 6; j++ {
							f[base+j].at = f[base+j].at.Add(201 * time.Millisecond)
						}
						return f
					}, "not pending"},
					captureCase{fmt.Sprintf("abort-%d", i), func(f []frame, _ map[string]string) []frame {
						return append(f, c2s(20, 30, uint16(41001+i), chunkABORT))
					}, "ABORT"},
				)
			}
			for _, gap := range []time.Duration{200*time.Millisecond - time.Nanosecond, 200 * time.Millisecond, 200*time.Millisecond + time.Nanosecond} {
				want := ""
				if gap > 200*time.Millisecond {
					want = "not pending"
				}
				cases = append(cases, captureCase{fmt.Sprintf("shutdown-gap-%v", gap), func(f []frame, _ map[string]string) []frame {
					for i := range c.ports {
						base := i * 6
						for j := 3; j < 6; j++ {
							f[base+j].at = f[base+j].at.Add(gap - time.Millisecond)
						}
					}
					return f
				}, want})
			}
			cases = append(cases, factCase("grace_ns", "10000000", "after the grace period"))
			checkCaptureCases(t, name, good, facts, cases)
		})
	}
}

func TestCheckSimultaneousClose(t *testing.T) {
	good := []frame{c2s(1, 11, 41001, chunkSHUTDOWN), s2c(2, 12, 41001, chunkSHUTDOWN), s2c(3, 20, 41001, chunkSHUTDOWNACK), c2s(4, 21, 41001, chunkSHUTDOWNCOMPLETE)}
	facts := map[string]string{"port": "41001", "client_close_ns": ns(10), "server_close_ns": ns(10), "client_dropped": "1", "server_dropped": "1"}
	checkCaptureCases(t, "simultaneous-close", good, facts, []captureCase{
		factCase("client_close_ns", ns(60.000001), "Close calls"),
		factCase("server_close_ns", ns(60.000001), "Close calls"),
		removeFrame(0, "client never sent"),
		removeFrame(1, "server never sent"),
		removeFrame(2, "nobody acknowledged"),
		removeFrame(3, "never completed"),
		{"client-shutdown-late", func(f []frame, _ map[string]string) []frame { f[0].at = f[2].at; return f }, "did not cross"},
		{"server-shutdown-late", func(f []frame, _ map[string]string) []frame { f[1].at = f[2].at; return f }, "did not cross"},
		{"abort", func(f []frame, _ map[string]string) []frame { return append(f, s2c(5, 22, 41001, chunkABORT)) }, "ABORT"},
		factCase("client_dropped", "0", "matched nothing"),
		factCase("server_dropped", "0", "matched nothing"),
	})
	for _, key := range []string{"client_close_ns", "server_close_ns"} {
		for _, ms := range []float64{59.999999, 60} {
			t.Run(fmt.Sprintf("%s/%v", key, ms), func(t *testing.T) {
				f := maps.Clone(facts)
				f[key] = ns(ms)
				wantPass(t, check(t, claimNamed(t, "simultaneous-close"), good, f))
			})
		}
	}
}

func TestCheckGracefulClose(t *testing.T) {
	for _, name := range []string{"graceful-close", "graceful-peeled-close"} {
		t.Run(name, func(t *testing.T) {
			good := []frame{withData(c2s(1, 0, 41001), dataChunk{tsn: 1}), c2s(2, 10, 41001, chunkSHUTDOWN), s2c(3, 11, 41001, chunkSHUTDOWNACK), c2s(4, 12, 41001, chunkSHUTDOWNCOMPLETE)}
			facts := map[string]string{"port": "41001", "close_ns": ns(10), "eof": "1"}
			checkCaptureCases(t, name, good, facts, []captureCase{
				removeFrame(1, "Close never started"),
				removeFrame(2, "never acknowledged"),
				removeFrame(3, "never completed"),
				{"late-data", func(f []frame, _ map[string]string) []frame { f[0].at = f[1].at.Add(time.Nanosecond); return f }, "DATA"},
				{"abort", func(f []frame, _ map[string]string) []frame { return append(f, s2c(5, 13, 41001, chunkABORT)) }, "ABORT"},
				factCase("eof", "0", "io.EOF"),
			})
		})
	}
}
