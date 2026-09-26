// Copyright 2019 Wataru Ishida. All rights reserved.
// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// This file includes modifications by gomaja.

//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

// options_ext_linux_test.go tests the options of options_ext_linux.go:
// the negotiated extensions, authentication, stream reconfiguration,
// stream scheduling and partial reliability.

package sctp

import (
	"encoding/binary"
	"errors"
	"slices"
	"sort"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// --- negotiated extensions ------------------------------------------------

// TestNegotiatedExtensionsFollowConfig: each getter reports what the
// association negotiated, with the feature switched on at both ends and
// off at both ends through Config.
func TestNegotiatedExtensionsFollowConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  func(on bool) *Config
		get  func(*Conn) (bool, error)
	}{
		{"PRSupported", func(on bool) *Config { return &Config{PartialReliability: &on} }, (*Conn).PRSupported},
		{"ReconfigSupported", func(on bool) *Config { return &Config{StreamReconfiguration: &on} }, (*Conn).ReconfigSupported},
		{"AuthSupported", func(on bool) *Config { return &Config{Authentication: &on} }, (*Conn).AuthSupported},
		{"ASCONFSupported", func(on bool) *Config {
			return &Config{Authentication: new(true), DynamicAddressReconfiguration: &on}
		}, (*Conn).ASCONFSupported},
		{"ECNSupported", func(on bool) *Config { return &Config{ExperimentalECN: &on} }, (*Conn).ECNSupported},
		{"InterleavingSupported", func(on bool) *Config {
			return &Config{FragmentInterleave: new(InterleaveAssocs), MessageInterleaving: on}
		}, (*Conn).InterleavingSupported},
	}
	for _, tc := range cases {
		for _, on := range []bool{true, false} {
			t.Run(tc.name+" "+strconv.FormatBool(on), func(t *testing.T) {
				cfg := tc.cfg(on)
				if cfg.MessageInterleaving {
					l, err := cfg.Listen("sctp4", loopback4(0))
					if errors.Is(err, syscall.EPERM) {
						t.Skip("net.sctp.intl_enable is 0; the other sysctl state covers MessageInterleaving true")
					}
					if err == nil {
						_ = l.Close()
					}
				}
				client, server := connPair(t, cfg, cfg)
				for side, c := range map[string]*Conn{"client": client, "server": server} {
					if got, err := tc.get(c); err != nil || got != on {
						t.Errorf("%s %s = %v, %v; want %v", side, tc.name, got, err, on)
					}
				}
			})
		}
	}
}

// --- authentication ------------------------------------------------------

// authConfig switches AUTH on at both ends, whatever net.sctp.auth_enable
// says (SCTP_AUTH_SUPPORTED), and asks the peer to authenticate DATA.
func authConfig() *Config {
	return &Config{Authentication: new(true), HMACIdentifiers: []HMACID{HMACSHA256, HMACSHA1}, AuthChunks: []uint8{0}}
}

// TestAuthKeyLifecycle walks the rollover RFC 4895 §6.1 describes on a live
// association: install two keys, activate one, refuse to delete the active
// key, switch, deactivate the old one and delete it (v1
// TestAuthKeyManagement).
func TestAuthKeyLifecycle(t *testing.T) {
	client, _ := connPair(t, authConfig(), authConfig())
	for key, secret := range map[uint16]string{1: "0123456789abcdef", 2: "fedcba9876543210"} {
		if err := client.SetAuthKey(key, []byte(secret)); err != nil {
			t.Fatalf("SetAuthKey(%d): %v", key, err)
		}
	}
	if err := client.SetActiveAuthKey(1); err != nil {
		t.Fatalf("SetActiveAuthKey(1): %v", err)
	}
	if got, err := client.ActiveAuthKey(); err != nil || got != 1 {
		t.Errorf("ActiveAuthKey = %d, %v; want 1", got, err)
	}
	// Linux refuses to delete the active key (net/sctp/auth.c:
	// sctp_auth_del_key_id).
	wantKernelError(t, "DeleteAuthKey(active)", "set", client.DeleteAuthKey(1), syscall.EINVAL)
	if err := client.SetActiveAuthKey(2); err != nil {
		t.Fatalf("SetActiveAuthKey(2): %v", err)
	}
	if err := client.DeactivateAuthKey(1); err != nil {
		t.Fatalf("DeactivateAuthKey(1): %v", err)
	}
	if err := client.DeleteAuthKey(1); err != nil {
		t.Fatalf("DeleteAuthKey(1) after deactivating it: %v", err)
	}
	wantKernelError(t, "DeleteAuthKey(1) twice", "set", client.DeleteAuthKey(1), syscall.EINVAL)

	// Linux checks the key length against the option's (net/sctp/socket.c:
	// sctp_setsockopt_auth_key), so a length past the end cannot make it
	// read beyond the buffer (v1 TestSetAuthKeyValidatesLength).
	lying := make([]byte, sizeAuthKey+8)
	binary.NativeEndian.PutUint16(lying[authKeyKeyNumberOff:], 9)
	binary.NativeEndian.PutUint16(lying[authKeyKeyLengthOff:], 200)
	var rawErr error
	rawFd(t, mustSyscallConn(t, client), func(fd int) {
		rawErr = rawSetsockopt(fd, ipprotoSCTP, optAuthKey, unsafe.Pointer(&lying[0]), uintptr(len(lying)))
	})
	if rawErr != syscall.EINVAL {
		t.Errorf("a key length past the option = %v, want EINVAL", rawErr)
	}
	calls := countSockopts(t)
	wantOpError(t, "SetAuthKey(empty)", "set", client.SetAuthKey(3, nil), syscall.EINVAL)
	if n := calls.Load(); n != 0 {
		t.Errorf("%d option system calls for an empty key, want 0", n)
	}
}

// TestAuthListsReadBack: the HMAC identifiers and chunk lists the
// association carries read back in the kernel's order, and each side's
// local list is what the other sees as the peer's.
func TestAuthListsReadBack(t *testing.T) {
	client, server := connPair(t, authConfig(), authConfig())
	idents, err := client.HMACIdentifiers()
	if err != nil || !slices.Equal(idents, []HMACID{HMACSHA256, HMACSHA1}) {
		t.Errorf("HMACIdentifiers = %v, %v; want [HMACSHA256 HMACSHA1], the preference order set", idents, err)
	}
	local, err := client.LocalAuthChunks()
	if err != nil || !slices.Contains(local, 0) {
		t.Errorf("LocalAuthChunks = %v, %v; want DATA (0) among them", local, err)
	}
	peer, err := server.PeerAuthChunks()
	if err != nil {
		t.Fatalf("PeerAuthChunks: %v", err)
	}
	sort.Slice(local, func(i, j int) bool { return local[i] < local[j] })
	sort.Slice(peer, func(i, j int) bool { return peer[i] < peer[j] })
	if !slices.Equal(peer, local) {
		t.Errorf("server PeerAuthChunks = %v, client LocalAuthChunks = %v; want the same list", peer, local)
	}
}

// TestAuthOptionsWithoutAuth: with AUTH off at both ends, every AUTH
// option on the association fails with Linux's EACCES (net/sctp/socket.c:
// sctp_getsockopt_active_key and the auth chunk getters; net/sctp/auth.c:
// the key operations), a privilege-sounding errno worth pinning (v1
// TestAuthDisabledReportsEACCES, TestAuthOptionsWithoutSysctl).
func TestAuthOptionsWithoutAuth(t *testing.T) {
	cfg := &Config{Authentication: new(false)}
	client, _ := connPair(t, cfg, cfg)
	cases := map[string]struct {
		op  string
		err error
	}{
		"ActiveAuthKey":     {"get", get2(client.ActiveAuthKey())},
		"HMACIdentifiers":   {"get", get2(client.HMACIdentifiers())},
		"LocalAuthChunks":   {"get", get2(client.LocalAuthChunks())},
		"PeerAuthChunks":    {"get", get2(client.PeerAuthChunks())},
		"SetAuthKey":        {"set", client.SetAuthKey(1, []byte("key"))},
		"SetActiveAuthKey":  {"set", client.SetActiveAuthKey(1)},
		"DeactivateAuthKey": {"set", client.DeactivateAuthKey(1)},
		"DeleteAuthKey":     {"set", client.DeleteAuthKey(1)},
	}
	for name, tc := range cases {
		wantKernelError(t, name, tc.op, tc.err, syscall.EACCES)
	}
}

// --- stream reconfiguration ------------------------------------------------

// TestReconfigurationWithoutTheExtension: without RFC 6525 negotiated,
// every request fails with ENOPROTOOPT (net/sctp/stream.c:
// sctp_send_reset_streams, sctp_send_reset_assoc, sctp_send_add_streams),
// the errno that makes a merely un-negotiated option look absent (v1
// TestResetStreamsNeedsExtension, TestResetAssoc, TestAddStreams).
func TestReconfigurationWithoutTheExtension(t *testing.T) {
	cfg := &Config{StreamReconfiguration: new(false)}
	client, _ := connPair(t, cfg, cfg)
	wantKernelError(t, "ResetStreams", "set", client.ResetStreams(ResetOutgoing), syscall.ENOPROTOOPT)
	wantKernelError(t, "ResetAssoc", "set", client.ResetAssoc(), syscall.ENOPROTOOPT)
	wantKernelError(t, "AddStreams", "set", client.AddStreams(0, 2), syscall.ENOPROTOOPT)
}

// TestResetStreams covers RFC 6525 §6.3.2 on a live association, one
// request at a time: each waits for the EventStreamReset reporting its
// outcome, since only one request may be outstanding (v1 TestResetStreams,
// TestResetStreamsWireLayout, TestReconfigurationEventsDecodeFromKernelBytes).
func TestResetStreams(t *testing.T) {
	client, _ := connPair(t, reconfConfig(EventStreamReset, EventAssocReset), reconfConfig())
	for _, tc := range []struct {
		name    string
		dir     ResetDirection
		streams []uint16
	}{
		{"all streams, both directions", ResetIncoming | ResetOutgoing, nil},
		{"one outgoing stream", ResetOutgoing, []uint16{0}},
		{"several outgoing streams", ResetOutgoing, []uint16{0, 1, 2}},
		{"incoming streams 7 and 9", ResetIncoming, []uint16{7, 9}},
		{"incoming alone", ResetIncoming, nil},
		{"outgoing alone", ResetOutgoing, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := client.ResetStreams(tc.dir, tc.streams...); err != nil {
				t.Fatalf("ResetStreams(%v, %v): %v", tc.dir, tc.streams, err)
			}
			// Each direction is answered on its own, with one event: the
			// peer's response for this side's outgoing streams, and the
			// peer's own request for its outgoing, this side's incoming
			// (net/sctp/stream.c: sctp_process_strreset_resp,
			// sctp_process_strreset_outreq).
			wantIn, wantOut := tc.dir&ResetIncoming != 0, tc.dir&ResetOutgoing != 0
			for wantIn || wantOut {
				sr := awaitEvent(t, client, EventStreamReset).(*StreamReset)
				if sr.Denied || sr.Failed {
					t.Fatalf("the peer refused the reset: %+v", sr)
				}
				if len(tc.streams) != 0 && !slices.Equal(sr.Streams, tc.streams) {
					t.Errorf("StreamReset.Streams = %v, want %v", sr.Streams, tc.streams)
				}
				wantIn = wantIn && !sr.Incoming
				wantOut = wantOut && !sr.Outgoing
			}
		})
	}
	st, err := client.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	// A stream the association does not have is refused by Linux, which
	// shows the list is read as stream ids.
	wantKernelError(t, "ResetStreams(a stream past the end)", "set", client.ResetStreams(ResetOutgoing, st.OutStreams+100), syscall.EINVAL)
	calls := countSockopts(t)
	wantOpError(t, "ResetStreams(no direction)", "set", client.ResetStreams(0), syscall.EINVAL)
	wantOpError(t, "ResetStreams(unknown direction)", "set", client.ResetStreams(ResetIncoming|0x80), syscall.EINVAL)
	wantOpError(t, "ResetStreams(65536 streams)", "set", client.ResetStreams(ResetOutgoing, make([]uint16, 65536)...), syscall.EINVAL)
	if n := calls.Load(); n != 0 {
		t.Errorf("%d option system calls for refused requests, want 0", n)
	}

	if err := client.ResetAssoc(); err != nil {
		t.Fatalf("ResetAssoc: %v", err)
	}
	if ar := awaitEvent(t, client, EventAssocReset).(*AssocReset); ar.Denied || ar.Failed {
		t.Errorf("the peer refused the association reset: %+v", ar)
	}
}

// TestAddStreamsWidensTheAssociation: AddStreams on an association with
// RFC 6525 negotiated widens it by the number asked for, and the
// EventStreamChange reports the streams added, not the new width, as
// Linux fills it (net/sctp/stream.c: sctp_process_strreset_resp; v1
// TestAddStreams, TestStreamChangeReportsAddedStreamsNotTheNewWidth).
func TestAddStreamsWidensTheAssociation(t *testing.T) {
	client, _ := connPair(t, reconfConfig(EventStreamChange), reconfConfig())
	before, err := client.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if err := client.AddStreams(0, 3); err != nil {
		t.Fatalf("AddStreams(0, 3): %v", err)
	}
	sc := awaitEvent(t, client, EventStreamChange).(*StreamChange)
	if sc.Denied || sc.Failed || sc.InStreams != 0 || sc.OutStreams != 3 {
		t.Errorf("StreamChange = %+v, want 3 outbound streams added", sc)
	}
	after, err := client.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if after.OutStreams != before.OutStreams+3 {
		t.Errorf("OutStreams went from %d to %d, want %d", before.OutStreams, after.OutStreams, before.OutStreams+3)
	}
	if _, err := client.SendMsg([]byte("on a new stream"), SendOptions{Info: &SndInfo{Stream: before.OutStreams + 1}}); err != nil {
		t.Errorf("SendMsg on added stream %d: %v", before.OutStreams+1, err)
	}
	wantOpError(t, "AddStreams(0, 0)", "set", client.AddStreams(0, 0), syscall.EINVAL)
}

// TestAddStreamsDeniedByThePeer: a peer whose mask leaves out
// EnableChangeAssocReq denies the request, which only the event reports
// (v1 TestStreamChangeReportsDeniedWhenThePeerRefuses).
func TestAddStreamsDeniedByThePeer(t *testing.T) {
	mask := EnableResetStreamReq | EnableResetAssocReq
	client, _ := connPair(t, reconfConfig(EventStreamChange), &Config{StreamReconfiguration: new(true), StreamResetMask: &mask})
	before, err := client.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if err := client.AddStreams(0, 3); err != nil {
		t.Fatalf("AddStreams: %v", err)
	}
	if sc := awaitEvent(t, client, EventStreamChange).(*StreamChange); !sc.Denied || sc.Failed {
		t.Errorf("StreamChange = %+v, want Denied alone", sc)
	}
	if after, err := client.Status(); err != nil || after.OutStreams != before.OutStreams {
		t.Errorf("OutStreams = %d, %v after the denial, want %d", after.OutStreams, err, before.OutStreams)
	}
}

// TestReconfigurationRequestInProgress: while one request is outstanding,
// the next ResetStreams, ResetAssoc or AddStreams fails with EINPROGRESS
// (RFC 6525 §5.1.1; net/sctp/stream.c; pion/sctp #508, #509). The
// request is kept outstanding by asking a peer whose send queue is
// stalled to reset its outgoing streams: it answers "in progress" until
// its queue drains (sctp_process_strreset_inreq), which it cannot while
// this side does not read.
func TestReconfigurationRequestInProgress(t *testing.T) {
	stalled, waiting := connPair(t, reconfConfig(), reconfConfig())
	fillSendBuffer(t, stalled, fill(512))
	if err := waiting.ResetStreams(ResetIncoming); err != nil {
		t.Fatalf("ResetStreams: %v", err)
	}
	wantKernelError(t, "a second ResetStreams", "set", waiting.ResetStreams(ResetIncoming), syscall.EINPROGRESS)
	wantKernelError(t, "ResetAssoc", "set", waiting.ResetAssoc(), syscall.EINPROGRESS)
	wantKernelError(t, "AddStreams", "set", waiting.AddStreams(1, 1), syscall.EINPROGRESS)
}

// --- stream scheduling ----------------------------------------------------

// TestEveryStreamSchedulerIsSelectable: each Scheduler Linux names can be
// selected and read back; SchedFC and SchedWFQ only on kernels that have
// them (Linux 6.4), and the kernel's own error is returned elsewhere. The
// package refuses a value past SchedWFQ, and the kernel refuses it too,
// which is how a sixth kernel scheduler would be noticed (v1
// TestEveryStreamSchedulerIsSelectable).
func TestEveryStreamSchedulerIsSelectable(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	for _, s := range []Scheduler{SchedFCFS, SchedPrio, SchedRR, SchedFC, SchedWFQ} {
		err := client.SetStreamScheduler(s)
		if (s == SchedFC || s == SchedWFQ) && (errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOPROTOOPT)) {
			t.Logf("%v: %v (a kernel before Linux 6.4)", s, err)
			continue
		}
		if err != nil {
			t.Errorf("SetStreamScheduler(%v): %v", s, err)
			continue
		}
		if got, err := client.StreamScheduler(); err != nil || got != s {
			t.Errorf("StreamScheduler = %v, %v; want %v", got, err, s)
		}
	}
	wantOpError(t, "SetStreamScheduler(SchedWFQ+1)", "set", client.SetStreamScheduler(SchedWFQ+1), syscall.EINVAL)
	var b [sizeAssocValue]byte
	binary.NativeEndian.PutUint32(b[assocValueValueOff:], uint32(SchedWFQ+1))
	var err error
	rawFd(t, mustSyscallConn(t, client), func(fd int) {
		err = rawSetsockopt(fd, ipprotoSCTP, optStreamScheduler, unsafe.Pointer(&b[0]), uintptr(len(b)))
	})
	if err != syscall.EINVAL {
		t.Errorf("the kernel answered %v for scheduler %d, want EINVAL; it may have grown a scheduler this package does not name", err, SchedWFQ+1)
	}
}

// TestOnlyPrioAndWFQKeepAStreamValue: every scheduler accepts a per-stream
// value, but only SchedPrio (a priority) and SchedWFQ (a weight) keep it;
// the others read back 0 (net/sctp/stream_sched*.c; v1
// TestOnlyPrioAndWFQKeepAStreamValue, TestStreamSchedulerRoundTrips).
func TestOnlyPrioAndWFQKeepAStreamValue(t *testing.T) {
	for _, tc := range []struct {
		s     Scheduler
		keeps bool
	}{
		{SchedFCFS, false}, {SchedPrio, true}, {SchedRR, false}, {SchedFC, false}, {SchedWFQ, true},
	} {
		t.Run(tc.s.String(), func(t *testing.T) {
			client, _ := connPair(t, nil, nil)
			if err := client.SetStreamScheduler(tc.s); err != nil {
				if (tc.s == SchedFC || tc.s == SchedWFQ) && (errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOPROTOOPT)) {
					t.Skipf("%v: %v (a kernel before Linux 6.4)", tc.s, err)
				}
				t.Fatalf("SetStreamScheduler: %v", err)
			}
			if err := client.SetStreamSchedulerValue(1, 7); err != nil {
				t.Fatalf("SetStreamSchedulerValue: %v", err)
			}
			want := uint16(0)
			if tc.keeps {
				want = 7
			}
			if got, err := client.StreamSchedulerValue(1); err != nil || got != want {
				t.Errorf("StreamSchedulerValue(1) = %d, %v; want %d", got, err, want)
			}
			st, err := client.Status()
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			wantKernelError(t, "StreamSchedulerValue(a stream past the end)", "get", get2(client.StreamSchedulerValue(st.OutStreams)), syscall.EINVAL)
		})
	}
}

// schedulerOrder sends one burst on streams 0 and 1 under scheduler s,
// with the receiver not reading, and returns the order the receiver then
// sees the streams in.
func schedulerOrder(t *testing.T, s Scheduler, weights map[uint16]uint16) []uint16 {
	t.Helper()
	client, server := connPair(t, &Config{WriteBuffer: new(65536)}, nil)
	if err := client.SetStreamScheduler(s); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOPROTOOPT) {
			t.Skipf("%v: %v (a kernel before Linux 6.4)", s, err)
		}
		t.Fatalf("SetStreamScheduler(%v): %v", s, err)
	}
	for sid, w := range weights {
		if err := client.SetStreamSchedulerValue(sid, w); err != nil {
			t.Fatalf("SetStreamSchedulerValue(%d, %d): %v", sid, w, err)
		}
	}
	payload := make([]byte, 1200)
	sent := 0
	for i := 0; i < 400; i++ {
		if _, err := client.SendMsg(payload, SendOptions{Info: &SndInfo{Stream: uint16(i % 2)}, NoWait: true}); err != nil {
			break
		}
		sent++
	}
	if sent < 40 {
		t.Skipf("only %d messages were queued; the send buffer never backed up", sent)
	}
	order := make([]uint16, 0, sent)
	buf := make([]byte, 2048)
	for len(order) < sent {
		setReadDeadline(t, server, 2*time.Second)
		_, info, err := server.RecvMsg(buf)
		if err != nil {
			break
		}
		order = append(order, info.Rcv.Stream)
	}
	return order
}

// longestRun is the longest stretch of one stream in the head of a
// delivery order, while the send queue is still deep enough for the
// scheduler to be choosing.
func longestRun(order []uint16) int {
	if len(order) > 60 {
		order = order[:60]
	}
	best, run := 0, 0
	for i, sid := range order {
		if i > 0 && sid == order[i-1] {
			run++
		} else {
			run = 1
		}
		best = max(best, run)
	}
	return best
}

// TestWFQReordersRelativeToFCFS: SchedWFQ with a 10:1 weight groups a
// stream's messages where SchedFCFS alternates them, which a scheduler
// stored and never consulted could not show (v1
// TestWFQReordersRelativeToFCFS).
func TestWFQReordersRelativeToFCFS(t *testing.T) {
	fcfs := schedulerOrder(t, SchedFCFS, nil)
	wfq := schedulerOrder(t, SchedWFQ, map[uint16]uint16{0: 10, 1: 1})
	if len(fcfs) < 40 || len(wfq) < 40 {
		t.Skipf("too few messages delivered to compare (%d and %d)", len(fcfs), len(wfq))
	}
	fcfsRun, wfqRun := longestRun(fcfs), longestRun(wfq)
	t.Logf("longest same-stream run in the head: FCFS %d, WFQ %d", fcfsRun, wfqRun)
	if wfqRun <= fcfsRun {
		t.Errorf("WFQ weighted 10:1 grouped a stream into runs of at most %d, FCFS reached %d", wfqRun, fcfsRun)
	}
	if fcfsRun > 2 {
		t.Errorf("FCFS produced runs of %d; the send queue was not deep, so this compares nothing", fcfsRun)
	}
}

// --- partial reliability -------------------------------------------------

// TestPRStatus: on a fresh association nothing has been abandoned, for one
// stream and for the association, and a stream past the end or PRNone is
// refused (v1 TestPrStreamStatusNeedsAssociation, TestPrAssocStatus).
func TestPRStatus(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	for _, p := range []PRPolicy{PRTTL, PRRtx, PRPrio, PRAll} {
		if s, err := client.PRAssocStatus(p); err != nil || *s != (PRStatus{}) {
			t.Errorf("PRAssocStatus(%v) = %+v, %v; want zero counts", p, s, err)
		}
		if s, err := client.PRStreamStatus(3, p); err != nil || *s != (PRStatus{}) {
			t.Errorf("PRStreamStatus(3, %v) = %+v, %v; want zero counts", p, s, err)
		}
	}
	st, err := client.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	wantKernelError(t, "PRStreamStatus(a stream past the end)", "get", get2(client.PRStreamStatus(st.OutStreams, PRTTL)), syscall.EINVAL)
	calls := countSockopts(t)
	wantOpError(t, "PRAssocStatus(PRNone)", "get", get2(client.PRAssocStatus(PRNone)), syscall.EINVAL)
	wantOpError(t, "PRStreamStatus(PRAll|PRTTL)", "get", get2(client.PRStreamStatus(0, PRAll|PRTTL)), syscall.EINVAL)
	if n := calls.Load(); n != 0 {
		t.Errorf("%d option system calls for refused policies, want 0", n)
	}
}
