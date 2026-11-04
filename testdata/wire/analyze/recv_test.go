// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"testing"
)

func TestPartialDeliveryBoundaryClaim(t *testing.T) {
	c := claimNamed(t, "partial-delivery-boundary")
	facts := map[string]string{"port": "41030", "prefix_bytes": "4096", "interrupted": "1", "following": "1", "dropped": "2", "teardown_ns": ns(1500), "eof": "1", "received": "0"}
	prefix := withData(c2s(1, 1, 41030), dataChunk{tsn: 10, ppid: 0x57490017})
	fwd := c2s(2, 500, 41030, chunkFORWARDTSN)
	fwd.fwdTSN = []uint32{12}
	following := withData(c2s(3, 1000, 41030), dataChunk{tsn: 13, ppid: 0x57490018})
	good := []frame{prefix, fwd, following}
	wantPass(t, check(t, c, good, facts))
	wantFail(t, check(t, c, []frame{prefix, following}, facts), "FORWARD TSN")
	wantFail(t, check(t, c, append(append([]frame(nil), good...), s2c(4, 1100, 41030, chunkABORT)), facts), "ABORT")
	wantFail(t, check(t, c, good[:2], facts), "following DATA")
	wantFail(t, check(t, c, good[1:], facts), "partial DATA")
	earlyFollowing := withData(c2s(3, 499, 41030), dataChunk{tsn: 13, ppid: 0x57490018})
	wantFail(t, check(t, c, []frame{prefix, fwd, earlyFollowing}, facts), "following DATA")
	latePrefix := withData(c2s(1, 501, 41030), dataChunk{tsn: 10, ppid: 0x57490017})
	wantFail(t, check(t, c, []frame{latePrefix, fwd, following}, facts), "partial DATA")

	for _, field := range []string{"prefix_bytes", "interrupted", "following", "dropped"} {
		bad := make(map[string]string)
		for k, v := range facts {
			bad[k] = v
		}
		bad[field] = "0"
		wantFail(t, check(t, c, good, bad), field)
	}
	for _, n := range []int{-1, 0, 1, 102399, 102400, 102401} {
		bad := make(map[string]string)
		for k, v := range facts {
			bad[k] = v
		}
		bad["prefix_bytes"] = fmt.Sprint(n)
		result := check(t, c, good, bad)
		if n > 0 && n < 102400 {
			wantPass(t, result)
		} else {
			wantFail(t, result, "prefix_bytes")
		}
	}
	lateAbort := append(append([]frame(nil), good...), s2c(4, 1501, 41030, chunkABORT))
	wantPass(t, check(t, c, lateAbort, facts))
	exactAbort := append(append([]frame(nil), good...), s2c(4, 1500, 41030, chunkABORT))
	wantFail(t, check(t, c, exactAbort, facts), "ABORT")
	for _, at := range []int{999, 1000, 1001} {
		bad := make(map[string]string)
		for k, v := range facts {
			bad[k] = v
		}
		bad["teardown_ns"] = ns(float64(at))
		result := check(t, c, good, bad)
		if at < 1000 {
			wantFail(t, result, "teardown")
		} else {
			wantPass(t, result)
		}
	}

}

func TestPartialDeliveryForwardTSNValue(t *testing.T) {
	c := claimNamed(t, "partial-delivery-boundary")
	facts := map[string]string{"port": "41030", "prefix_bytes": "4096", "interrupted": "1", "following": "1", "dropped": "2", "teardown_ns": ns(1500)}
	for _, start := range []uint32{0, 10, 0xffffffff} {
		for _, delta := range []int32{-1, 0, 1} {
			t.Run(fmt.Sprintf("start=%d/delta=%d", start, delta), func(t *testing.T) {
				prefix := withData(c2s(1, 1, 41030), dataChunk{tsn: start, ppid: 0x57490017})
				fwd := c2s(2, 500, 41030, chunkFORWARDTSN)
				fwd.fwdTSN = []uint32{start + uint32(delta)}
				following := withData(c2s(3, 1000, 41030), dataChunk{tsn: start + 2, ppid: 0x57490018})
				result := check(t, c, []frame{prefix, fwd, following}, facts)
				if delta < 0 {
					wantFail(t, result, "cumulative TSN")
				} else {
					wantPass(t, result)
				}
			})
		}
	}
}
