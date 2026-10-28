// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func setupRTOFacts(port, initial string) map[string]string {
	return map[string]string{
		"port": port, "deadline_ns": ns(900), "return_ns": ns(901),
		"lasting_initial_ns": "200000000", "setup_initial_ns": initial,
		"max_init_timeout_ns": "2000000000", "dropped": "1",
	}
}

func TestSetupRTOSingleINITClaim(t *testing.T) {
	c := claimNamed(t, "setup-rto-initial-single-init")
	facts := setupRTOFacts("41027", "1200000000")
	good := []frame{c2s(1, 0, 41027, chunkINIT)}
	wantPass(t, check(t, c, good, facts))
	wantFail(t, check(t, c, append(append([]frame(nil), good...), c2s(2, 200, 41027, chunkINIT)), facts), "want exactly 1 INIT")
	wantFail(t, check(t, c, []frame{c2s(1, 0, 41027, chunkABORT)}, facts), "no INIT")
	wantFail(t, check(t, c, append(append([]frame(nil), good...), s2c(2, 10, 41027, chunkINITACK)), facts), "server answered")
	wrong := setupRTOFacts("41027", "200000000")
	wantFail(t, check(t, c, good, wrong), "does not exceed")
	wrong = setupRTOFacts("41027", "1200000000")
	wrong["dropped"] = "0"
	wantFail(t, check(t, c, good, wrong), "INPUT rule dropped")
}

func TestSetupRTOUnsetClaim(t *testing.T) {
	c := claimNamed(t, "setup-rto-initial-unset")
	facts := setupRTOFacts("41028", "0")
	facts["dropped"] = "3"
	good := []frame{c2s(1, 0, 41028, chunkINIT), c2s(2, 200, 41028, chunkINIT), c2s(3, 600, 41028, chunkINIT)}
	wantPass(t, check(t, c, good, facts))
	wantFail(t, check(t, c, good[:1], facts), "want exactly 3 INIT")
	wantFail(t, check(t, c, append(append([]frame(nil), good...), c2s(4, 800, 41028, chunkINIT)), facts), "want exactly 3 INIT")
	late := append([]frame(nil), good...)
	late[2] = c2s(3, 950, 41028, chunkINIT)
	wantFail(t, check(t, c, late, facts), "after the deadline")
	wrongAssociation := append([]frame(nil), good...)
	wrongAssociation[2].sport++
	wantFail(t, check(t, c, wrongAssociation, facts), "original association")
	squeezed := []frame{c2s(1, 0, 41028, chunkINIT), c2s(2, 10, 41028, chunkINIT), c2s(3, 20, 41028, chunkINIT)}
	wantFail(t, check(t, c, squeezed, facts), "followed the previous one by 10ms, want the T1 interval 200ms")
	undoubled := []frame{c2s(1, 0, 41028, chunkINIT), c2s(2, 200, 41028, chunkINIT), c2s(3, 400, 41028, chunkINIT)}
	wantFail(t, check(t, c, undoubled, facts), "followed the previous one by 200ms, want the T1 interval 400ms")
	wrong := setupRTOFacts("41028", "1200000000")
	wantFail(t, check(t, c, good, wrong), "unset case recorded")
}

func TestSetupRTOResidualClaim(t *testing.T) {
	c := claimNamed(t, "setup-rto-initial-data-residual")
	facts := map[string]string{
		"port": "41029", "setup_initial_ns": "1200000000", "lasting_initial_ns": "200000000",
		"sent_ns": ns(0), "dropped": "1", "received": "1", "eof": "1",
	}
	first := withData(c2s(1, 1, 41029), dataChunk{tsn: 10, ppid: ppidSetupRTO})
	retry := withData(c2s(2, 1201, 41029), dataChunk{tsn: 10, ppid: ppidSetupRTO})
	ack := s2c(3, 1202, 41029, chunkSACK)
	ack.sackCum = []uint32{10}
	good := []frame{first, retry, ack}
	wantPass(t, check(t, c, good, facts))
	wrong := withData(c2s(2, 201, 41029), dataChunk{tsn: 10, ppid: ppidSetupRTO})
	wantFail(t, check(t, c, []frame{first, wrong, ack}, facts), "first DATA retransmission after")
	wrong = withData(c2s(2, 1201, 41029), dataChunk{tsn: 11, ppid: ppidSetupRTO})
	wantFail(t, check(t, c, []frame{first, wrong, ack}, facts), "one retry of its TSN")
	wantFail(t, check(t, c, []frame{first, ack}, facts), "one retry of its TSN")
	wantFail(t, check(t, c, append(append([]frame(nil), good...), s2c(4, 50, 41029, chunkHEARTBEATACK)), facts), "measured an RTT")
	wantFail(t, check(t, c, good[:2], facts), "no SACK acknowledges")
	wrongFacts := map[string]string{
		"port": "41029", "setup_initial_ns": "1200000000", "lasting_initial_ns": "200000000",
		"sent_ns": ns(0), "dropped": "0", "received": "1", "eof": "1",
	}
	wantFail(t, check(t, c, good, wrongFacts), "exactly one DATA dropped")
}
