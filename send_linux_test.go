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

package sctp

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"reflect"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// Conn is an io.Writer: Write sends one message with the socket's
// defaults.
var _ io.Writer = (*Conn)(nil)

// --- helpers ------------------------------------------------------------------

// recvInfo reads one message into b with RecvMsg and returns its
// SCTP_RCVINFO, skipping the notifications a subscribed caller receives.
// The send tests use it to see what arrived, and how.
func recvInfo(c *Conn, b []byte) (int, RcvInfo, error) {
	for {
		n, info, err := c.RecvMsg(b)
		if err != nil {
			return 0, RcvInfo{}, err
		}
		if !info.Notification {
			return n, info.Rcv, nil
		}
	}
}

// recvWithin reads one message from c, failing the test unless one arrives
// within d.
func recvWithin(t testing.TB, c *Conn, d time.Duration) ([]byte, RcvInfo) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1<<16)
	n, info, err := recvInfo(c, buf)
	if err != nil {
		t.Fatalf("receiving: %v", err)
	}
	return buf[:n], info
}

// wantNothingQueued fails the test if a message arrives on c within d.
func wantNothingQueued(t testing.TB, c *Conn, d time.Duration) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(d)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1<<16)
	if n, _, err := recvInfo(c, buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a read found %d bytes (%q), %v; want nothing queued", n, buf[:min(n, 32)], err)
	}
}

// wantWriteError asserts that err is a *net.OpError with Op "write"
// matching target.
func wantWriteError(t testing.TB, err, target error) {
	t.Helper()
	_ = writeOpError(t, err, target)
}

// writeOpError is wantWriteError, returning the *net.OpError.
func writeOpError(t testing.TB, err, target error) *net.OpError {
	t.Helper()
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "write" {
		t.Fatalf("err = %#v (%v), want a *net.OpError with Op write", err, err)
	}
	if !errors.Is(err, target) {
		t.Fatalf("err = %v, want it to match %v", err, target)
	}
	return opErr
}

// hookSendmsg routes every sendmsg the send path makes through f until the
// test ends. The test must not send from goroutines that outlive it.
func hookSendmsg(t testing.TB, f func(fd int, msg *syscall.Msghdr, flags int) (int, error)) {
	t.Helper()
	testHookSendmsg = f
	t.Cleanup(func() { testHookSendmsg = nil })
}

// countSendmsg counts the sendmsg calls the send path makes until the test
// ends.
func countSendmsg(t testing.TB) *atomic.Int64 {
	t.Helper()
	calls := new(atomic.Int64)
	hookSendmsg(t, func(fd int, msg *syscall.Msghdr, flags int) (int, error) {
		calls.Add(1)
		return rawSendmsg(fd, msg, flags)
	})
	return calls
}

// sentRecords is what one sendmsg call carried besides its payload.
type sentRecords struct {
	snd      *SndInfo
	sndAssoc AssocID
	pr       *PrInfo
	key      *uint16
	flags    int
	name     []byte // msg_name, nil when the kernel chooses the path
}

// decodeSent reads back the control records and destination msg carries,
// independently of the encoder: the layouts are read field by field at
// abi.go's offsets.
func decodeSent(msg *syscall.Msghdr, flags int) sentRecords {
	r := sentRecords{flags: flags}
	if msg.Name != nil {
		r.name = bytes.Clone(unsafe.Slice(msg.Name, msg.Namelen))
	}
	if msg.Control == nil {
		return r
	}
	oob := unsafe.Slice(msg.Control, int(msg.Controllen))
	for len(oob) >= sizeCmsghdr {
		l := int(readWord(oob))
		if l < sizeCmsghdr || l > len(oob) {
			break
		}
		typ := int32(binary.NativeEndian.Uint32(oob[cmsghdrTypeOff:]))
		p := oob[sizeCmsghdr:l]
		switch typ {
		case cmsgSndInfo:
			flags, _ := splitDefaultFlags(binary.NativeEndian.Uint16(p[sndInfoFlagsOff:]))
			r.snd = &SndInfo{
				Stream:  binary.NativeEndian.Uint16(p[sndInfoStreamOff:]),
				Flags:   flags | SendFlags(binary.NativeEndian.Uint16(p[sndInfoFlagsOff:])&sndFlagSackImmediately),
				PPID:    binary.BigEndian.Uint32(p[sndInfoPPIDOff:]),
				Context: binary.NativeEndian.Uint32(p[sndInfoContextOff:]),
			}
			r.sndAssoc = AssocID(binary.NativeEndian.Uint32(p[sndInfoAssocIDOff:]))
		case cmsgPrInfo:
			r.pr = &PrInfo{
				Policy: PRPolicy(binary.NativeEndian.Uint16(p[prInfoPolicyOff:])),
				Value:  binary.NativeEndian.Uint32(p[prInfoValueOff:]),
			}
		case cmsgAuthInfo:
			k := binary.NativeEndian.Uint16(p[authInfoKeyNumberOff:])
			r.key = &k
		}
		oob = oob[min(cmsgAlign(l), len(oob)):]
	}
	return r
}

// captureSends records what every sendmsg of the send path carried until
// the test ends, and passes the call on.
func captureSends(t testing.TB) func() []sentRecords {
	t.Helper()
	var (
		mu   sync.Mutex
		sent []sentRecords
	)
	hookSendmsg(t, func(fd int, msg *syscall.Msghdr, flags int) (int, error) {
		r := decodeSent(msg, flags)
		mu.Lock()
		sent = append(sent, r)
		mu.Unlock()
		return rawSendmsg(fd, msg, flags)
	})
	return func() []sentRecords {
		mu.Lock()
		defer mu.Unlock()
		out := sent
		sent = nil
		return out
	}
}

// numbered is a 64-byte message carrying i.
func numbered(i int) []byte {
	b := make([]byte, 64)
	binary.BigEndian.PutUint32(b, uint32(i))
	copy(b[4:], "numbered message")
	return b
}

// numberOf is the number numbered put in b.
func numberOf(b []byte) int {
	if len(b) < 4 {
		return -1
	}
	return int(binary.BigEndian.Uint32(b))
}

// statusFragPoint reads the association's fragmentation point from
// SCTP_STATUS (RFC 6458 §8.2.1).
func statusFragPoint(t testing.TB, c *Conn) int {
	t.Helper()
	var b [sizeStatus]byte
	getRawOpt(t, mustSyscallConn(t, c), optStatus, b[:])
	return int(binary.NativeEndian.Uint32(b[statusFragmentationPointOff:]))
}

// signalStorm sends SIGURG to this process every 200 µs until stop is
// called, so that system calls on other threads are interrupted. SIGURG is
// what the runtime itself uses for preemption, so it is delivered without
// ending the process; signal.Notify keeps the runtime's own handler in
// place.
func signalStorm(t testing.TB) (stop func()) {
	t.Helper()
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGURG)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			select {
			case <-done:
				return
			default:
			}
			_ = syscall.Kill(os.Getpid(), syscall.SIGURG)
			time.Sleep(200 * time.Microsecond)
		}
	})
	var once sync.Once
	stop = func() {
		once.Do(func() {
			close(done)
			wg.Wait()
			signal.Stop(ch)
		})
	}
	t.Cleanup(stop)
	return stop
}

// --- sending with metadata ------------------------------------------------------

// TestSendMsgDeliversStreamAndPPID: a message sent with SendOptions.Info
// arrives on the stream it names, with its PPID intact in host order, and
// SendMsg reports the whole message sent. Stream 0 would be where an
// ignored SCTP_SNDINFO put the message, so a non-zero stream is what shows
// the record was applied.
func TestSendMsgDeliversStreamAndPPID(t *testing.T) {
	client, server := connPair(t, nil, nil)
	payload := []byte("sndinfo")
	n, err := client.SendMsg(payload, SendOptions{Info: &SndInfo{Stream: 3, PPID: 0xabcd}})
	if err != nil || n != len(payload) {
		t.Fatalf("SendMsg = %d, %v; want %d, nil", n, err, len(payload))
	}
	got, info := recvWithin(t, server, 5*time.Second)
	if !bytes.Equal(got, payload) {
		t.Errorf("payload = %q, want %q", got, payload)
	}
	if info.Stream != 3 {
		t.Errorf("stream = %d, want 3; stream 0 means SCTP_SNDINFO was ignored", info.Stream)
	}
	if info.PPID != 0xabcd {
		t.Errorf("PPID = %#x, want 0xabcd", info.PPID)
	}
}

// TestSendMsgWithPrInfo: SNDINFO and PRINFO together. Two records in one
// sendmsg are where the alignment between records matters: the second
// header read at the wrong offset would be refused or misread. The
// lifetime is long, so the message must arrive.
func TestSendMsgWithPrInfo(t *testing.T) {
	client, server := connPair(t, nil, nil)
	payload := []byte("prinfo")
	if _, err := client.SendMsg(payload, SendOptions{
		Info: &SndInfo{Stream: 1},
		PR:   &PrInfo{Policy: PRTTL, TTL: 30 * time.Second},
	}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	got, info := recvWithin(t, server, 5*time.Second)
	if !bytes.Equal(got, payload) || info.Stream != 1 {
		t.Errorf("received %q on stream %d, want %q on stream 1", got, info.Stream, payload)
	}
}

// authPair is an association with AUTH on (RFC 4895) and DATA
// authenticated in the client-to-server direction, so that
// SendOptions.AuthKey names the key of a real AUTH chunk. It is set up
// with Config.Authentication, which works whatever net.sctp.auth_enable
// says; a kernel that cannot do AUTH at all skips the test.
func authPair(t *testing.T) (client, server *Conn) {
	t.Helper()
	l, err := (&Config{Authentication: new(true), AuthChunks: []uint8{chunkTypeDataForAuth}}).Listen("sctp4", loopback4(0))
	if err != nil {
		t.Skipf("AUTH is not available here: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return dialAccept(t, &Config{Authentication: new(true)}, l)
}

// TestSendMsgWithAuthKey: SendOptions.AuthKey reaches the kernel as
// SCTP_AUTHINFO. With the null key (0, which every association has), the
// message arrives, alone and with the other two records; AUTHINFO carries
// a 2-byte payload, the one record whose alignment padding is not zero,
// so the combined send is also the one where missing padding would make
// the kernel read the next header at the wrong offset. A key the
// association does not have is refused with EINVAL
// (net/sctp/chunk.c: sctp_datamsg_from_user), which shows that the
// record was read rather than dropped.
func TestSendMsgWithAuthKey(t *testing.T) {
	client, server := authPair(t)
	null, missing := uint16(0), uint16(9)

	if _, err := client.SendMsg([]byte("key only"), SendOptions{AuthKey: &null}); err != nil {
		t.Fatalf("SendMsg with AuthKey 0: %v", err)
	}
	if got, _ := recvWithin(t, server, 5*time.Second); string(got) != "key only" {
		t.Errorf("received %q, want %q", got, "key only")
	}

	if _, err := client.SendMsg([]byte("all three"), SendOptions{
		Info:    &SndInfo{Stream: 6},
		PR:      &PrInfo{Policy: PRTTL, TTL: 30 * time.Second},
		AuthKey: &null,
	}); err != nil {
		t.Fatalf("SendMsg with Info, PR and AuthKey: %v", err)
	}
	if got, info := recvWithin(t, server, 5*time.Second); string(got) != "all three" || info.Stream != 6 {
		t.Errorf("received %q on stream %d, want %q on stream 6", got, info.Stream, "all three")
	}

	_, err := client.SendMsg([]byte("unknown key"), SendOptions{AuthKey: &missing})
	wantWriteError(t, err, syscall.EINVAL)
	wantNothingQueued(t, server, 300*time.Millisecond)
}

// TestSendMsgRefusesBadPrPolicy: a PR policy outside SCTP_PR_SCTP_MASK is
// refused with EINVAL before any system call, as the kernel would refuse
// it (net/sctp/socket.c: sctp_msghdr_parse).
func TestSendMsgRefusesBadPrPolicy(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	calls := countSendmsg(t)
	_, err := client.SendMsg([]byte("bad"), SendOptions{Info: &SndInfo{}, PR: &PrInfo{Policy: 0x40, Value: 1}})
	wantWriteError(t, err, syscall.EINVAL)
	if n := calls.Load(); n != 0 {
		t.Errorf("%d sendmsg calls for a refused PR policy, want 0", n)
	}
}

// --- defaults -------------------------------------------------------------------

// TestSendDefaultsAllCombinations: a nil Info or PR means the socket's
// default in all four combinations. Linux applies the defaults only to a
// message with no SNDINFO, and the default flags and PR policy only when
// there is no PRINFO either (net/sctp/socket.c:
// sctp_sendmsg_update_sinfo), so the package sends a default explicitly
// whenever only one of the two is set. Each combination is checked twice:
// in the records the send carried, read back from the sendmsg call, and in
// the stream, PPID and unordered bit the receiver sees. The defaults are
// set through Config on a dialed connection, inherited by an accepted one,
// and set through the setters, where the default SndInfo is set after the
// default PrInfo, so the PR policy must survive it.
func TestSendDefaultsAllCombinations(t *testing.T) {
	defSnd := SndInfo{Stream: 1, Flags: SendUnordered, PPID: 46, Context: 7}
	defPR := PrInfo{Policy: PRTTL, TTL: time.Second}
	defCfg := func() *Config {
		return &Config{DefaultSndInfo: new(defSnd), DefaultPrInfo: new(defPR)}
	}
	setups := []struct {
		name  string
		setup func(t *testing.T) (sender, receiver *Conn)
	}{
		{"Config on a dialed connection", func(t *testing.T) (*Conn, *Conn) {
			return connPair(t, defCfg(), nil)
		}},
		{"Config inherited by an accepted connection", func(t *testing.T) (*Conn, *Conn) {
			client, server := connPair(t, nil, defCfg())
			return server, client
		}},
		{"setters, SndInfo after PrInfo", func(t *testing.T) (*Conn, *Conn) {
			client, server := connPair(t, nil, nil)
			if err := client.SetDefaultPrInfo(new(defPR)); err != nil {
				t.Fatalf("SetDefaultPrInfo: %v", err)
			}
			if err := client.SetDefaultSndInfo(new(defSnd)); err != nil {
				t.Fatalf("SetDefaultSndInfo: %v", err)
			}
			return client, server
		}},
	}
	info := &SndInfo{Stream: 2, PPID: 99, Context: 3}
	prRtx := &PrInfo{Policy: PRRtx, Value: 3}
	both := &SndInfo{Stream: 3, Flags: SendUnordered, PPID: 77}
	none := &PrInfo{Policy: PRNone}
	cases := []struct {
		name       string
		opts       SendOptions
		write      bool
		wantSnd    *SndInfo // the SNDINFO sent; nil: none
		wantPR     *PrInfo  // the PRINFO sent; nil: none
		wantStream uint16
		wantPPID   uint32
		wantUnord  bool
	}{
		{name: "neither", wantStream: 1, wantPPID: 46, wantUnord: true},
		{name: "Write", write: true, wantStream: 1, wantPPID: 46, wantUnord: true},
		{
			name: "Info only", opts: SendOptions{Info: info},
			wantSnd: info, wantPR: &PrInfo{Policy: PRTTL, Value: 1000},
			wantStream: 2, wantPPID: 99,
		},
		{
			name: "PR only", opts: SendOptions{PR: prRtx},
			wantSnd: &defSnd, wantPR: prRtx,
			wantStream: 1, wantPPID: 46, wantUnord: true,
		},
		{
			name: "both", opts: SendOptions{Info: both, PR: none},
			wantSnd: both, wantPR: none,
			wantStream: 3, wantPPID: 77, wantUnord: true,
		},
	}
	for _, s := range setups {
		t.Run(s.name, func(t *testing.T) {
			sender, receiver := s.setup(t)
			if got, err := sender.DefaultSndInfo(); err != nil || *got != defSnd {
				t.Fatalf("DefaultSndInfo = %+v, %v; want %+v", got, err, defSnd)
			}
			if got, err := sender.DefaultPrInfo(); err != nil || *got != defPR {
				t.Fatalf("DefaultPrInfo = %+v, %v; want %+v, which setting the default SndInfo must not clear", got, err, defPR)
			}
			sent := captureSends(t)
			for _, tc := range cases {
				payload := []byte(tc.name)
				var err error
				if tc.write {
					_, err = sender.Write(payload)
				} else {
					_, err = sender.SendMsg(payload, tc.opts)
				}
				if err != nil {
					t.Fatalf("%s: send: %v", tc.name, err)
				}
				recs := sent()
				if len(recs) != 1 {
					t.Fatalf("%s: %d sendmsg calls, want 1", tc.name, len(recs))
				}
				r := recs[0]
				if (r.snd == nil) != (tc.wantSnd == nil) || (r.snd != nil && *r.snd != *tc.wantSnd) {
					t.Errorf("%s: SNDINFO sent = %+v, want %+v", tc.name, r.snd, tc.wantSnd)
				}
				if (r.pr == nil) != (tc.wantPR == nil) || (r.pr != nil && *r.pr != *tc.wantPR) {
					t.Errorf("%s: PRINFO sent = %+v, want %+v", tc.name, r.pr, tc.wantPR)
				}
				got, rinfo := recvWithin(t, receiver, 5*time.Second)
				if string(got) != tc.name {
					t.Fatalf("%s: received %q", tc.name, got)
				}
				if rinfo.Stream != tc.wantStream || rinfo.PPID != tc.wantPPID || rinfo.Unordered != tc.wantUnord {
					t.Errorf("%s: received stream %d PPID %d unordered %v, want stream %d PPID %d unordered %v",
						tc.name, rinfo.Stream, rinfo.PPID, rinfo.Unordered, tc.wantStream, tc.wantPPID, tc.wantUnord)
				}
			}

			// With no default PR policy, Info alone sends no PRINFO.
			if err := sender.SetDefaultPrInfo(&PrInfo{Policy: PRNone}); err != nil {
				t.Fatalf("SetDefaultPrInfo(PRNone): %v", err)
			}
			if _, err := sender.SendMsg([]byte("no PR default"), SendOptions{Info: info}); err != nil {
				t.Fatalf("send: %v", err)
			}
			if r := sent(); len(r) != 1 || r[0].pr != nil || r[0].snd == nil || *r[0].snd != *info {
				t.Errorf("with no default PR policy, Info alone sent %+v, want its SNDINFO and no PRINFO", r)
			}
			recvWithin(t, receiver, 5*time.Second)
		})
	}
}

// TestDefaultSndInfoKeepsTheControlPrDefault: Linux keeps the default PR
// policy in the same word as the default send flags, and setting
// SCTP_DEFAULT_SNDINFO overwrites the word (net/sctp/socket.c:
// sctp_setsockopt_default_sndinfo). A PR default set by Config.Control
// survives Config.DefaultSndInfo, which is applied after it.
func TestDefaultSndInfoKeepsTheControlPrDefault(t *testing.T) {
	cfg := &Config{
		Control: func(_, _ string, rc syscall.RawConn) error {
			var b [sizeDefaultPRInfo]byte
			binary.NativeEndian.PutUint32(b[defaultPRInfoValueOff:], 5)
			binary.NativeEndian.PutUint16(b[defaultPRInfoPolicyOff:], uint16(PRRtx))
			var serr error
			if err := rc.Control(func(fd uintptr) {
				serr = rawSetsockopt(int(fd), ipprotoSCTP, optDefaultPRInfo, unsafe.Pointer(&b[0]), uintptr(len(b)))
			}); err != nil {
				return err
			}
			return serr
		},
		DefaultSndInfo: &SndInfo{Stream: 2, PPID: 8},
	}
	client, _ := connPair(t, cfg, nil)
	want := PrInfo{Policy: PRRtx, Value: 5}
	if got, err := client.DefaultPrInfo(); err != nil || *got != want {
		t.Errorf("DefaultPrInfo = %+v, %v; want Control's %+v", got, err, want)
	}
	if client.send.defPR != want {
		t.Errorf("cached default PrInfo = %+v, want %+v", client.send.defPR, want)
	}
	if got, err := client.DefaultSndInfo(); err != nil || *got != *cfg.DefaultSndInfo {
		t.Errorf("DefaultSndInfo = %+v, %v; want %+v", got, err, *cfg.DefaultSndInfo)
	}
}

// TestDefaultInfoRoundTrip covers the four default methods: each getter
// reads what its setter wrote, from the kernel; the setters update the
// cache the send path uses; refusals are EINVAL before any system call,
// and every failure is a *net.OpError with Op "get" or "set".
func TestDefaultInfoRoundTrip(t *testing.T) {
	client, _ := connPair(t, nil, nil)

	if got, err := client.DefaultSndInfo(); err != nil || *got != (SndInfo{}) {
		t.Errorf("initial DefaultSndInfo = %+v, %v; want the zero SndInfo", got, err)
	}
	if got, err := client.DefaultPrInfo(); err != nil || *got != (PrInfo{}) {
		t.Errorf("initial DefaultPrInfo = %+v, %v; want the zero PrInfo", got, err)
	}

	snd := SndInfo{Stream: 4, Flags: SendUnordered, PPID: 0x01020304, Context: 11}
	if err := client.SetDefaultSndInfo(&snd); err != nil {
		t.Fatalf("SetDefaultSndInfo: %v", err)
	}
	if got, err := client.DefaultSndInfo(); err != nil || *got != snd {
		t.Errorf("DefaultSndInfo = %+v, %v; want %+v", got, err, snd)
	}
	if client.send.defSnd != snd {
		t.Errorf("cached default SndInfo = %+v, want %+v", client.send.defSnd, snd)
	}
	for _, pr := range []PrInfo{
		{Policy: PRTTL, TTL: 1500 * time.Millisecond},
		{Policy: PRRtx, Value: 2},
		{Policy: PRPrio, Value: 7},
		{Policy: PRNone},
	} {
		if err := client.SetDefaultPrInfo(&pr); err != nil {
			t.Fatalf("SetDefaultPrInfo(%+v): %v", pr, err)
		}
		if got, err := client.DefaultPrInfo(); err != nil || *got != pr {
			t.Errorf("DefaultPrInfo = %+v, %v; want %+v", got, err, pr)
		}
		if client.send.defPR != pr {
			t.Errorf("cached default PrInfo = %+v, want %+v", client.send.defPR, pr)
		}
	}

	// struct sctp_sndinfo is exactly 16 bytes to the kernel: a shorter
	// option, such as one missing snd_assoc_id, is refused
	// (net/sctp/socket.c: sctp_setsockopt_default_sndinfo).
	var short [sizeSndInfo]byte
	var serr error
	rawFd(t, mustSyscallConn(t, client), func(fd int) {
		serr = rawSetsockopt(fd, ipprotoSCTP, optDefaultSndInfo, unsafe.Pointer(&short[0]), 12)
	})
	if serr != syscall.EINVAL {
		t.Errorf("a 12-byte SCTP_DEFAULT_SNDINFO = %v, want EINVAL", serr)
	}

	calls := countSendmsg(t)
	wantOp := func(what, op string, err, target error) {
		t.Helper()
		var opErr *net.OpError
		if !errors.As(err, &opErr) || opErr.Op != op || !errors.Is(err, target) {
			t.Errorf("%s = %v, want a *net.OpError with Op %s matching %v", what, err, op, target)
		}
	}
	wantOp("SetDefaultSndInfo(SendSACKImmediately)", "set", client.SetDefaultSndInfo(&SndInfo{Flags: SendSACKImmediately}), syscall.EINVAL)
	wantOp("SetDefaultSndInfo(nil)", "set", client.SetDefaultSndInfo(nil), syscall.EINVAL)
	wantOp("SetDefaultPrInfo(PRAll)", "set", client.SetDefaultPrInfo(&PrInfo{Policy: PRAll}), syscall.EINVAL)
	wantOp("SetDefaultPrInfo(nil)", "set", client.SetDefaultPrInfo(nil), syscall.EINVAL)
	wantOp("SetDefaultPrInfo(1.5 ms)", "set", client.SetDefaultPrInfo(&PrInfo{Policy: PRTTL, TTL: 1500 * time.Microsecond}), syscall.EINVAL)
	wantOp("SetDefaultPrInfo(0x40)", "set", client.SetDefaultPrInfo(&PrInfo{Policy: 0x40, Value: 1}), syscall.EINVAL)
	if client.send.defSnd != snd || client.send.defPR != (PrInfo{}) {
		t.Errorf("refused settings changed the cache: %+v, %+v", client.send.defSnd, client.send.defPR)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d sendmsg calls, want 0", n)
	}

	if err := client.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	_, err := client.DefaultSndInfo()
	wantOp("DefaultSndInfo after Abort", "get", err, net.ErrClosed)
	_, err = client.DefaultPrInfo()
	wantOp("DefaultPrInfo after Abort", "get", err, net.ErrClosed)
	wantOp("SetDefaultSndInfo after Abort", "set", client.SetDefaultSndInfo(&SndInfo{Stream: 9}), net.ErrClosed)
	wantOp("SetDefaultPrInfo after Abort", "set", client.SetDefaultPrInfo(&PrInfo{Policy: PRRtx, Value: 1}), net.ErrClosed)
	if client.send.defSnd != snd || client.send.defPR != (PrInfo{}) {
		t.Errorf("failed settings changed the cache: %+v, %+v", client.send.defSnd, client.send.defPR)
	}
}

// --- what SendMsg refuses -------------------------------------------------------

// TestSendEmptyRefused: an empty message is refused with EINVAL before any
// system call, whatever the options (RFC 9260 §6.2: no DATA chunk without
// user data). The send path never substitutes a byte of its own, so no
// message reaches the peer: the next one it receives is the one sent
// afterwards.
func TestSendEmptyRefused(t *testing.T) {
	client, server := connPair(t, nil, nil)
	calls := countSendmsg(t)
	key := uint16(0)
	opts := map[string]SendOptions{
		"defaults":        {},
		"Info":            {Info: &SndInfo{PPID: 0x11223344}},
		"PR":              {PR: &PrInfo{Policy: PRTTL, TTL: time.Second}},
		"AuthKey":         {AuthKey: &key},
		"Info, PR, key":   {Info: &SndInfo{}, PR: &PrInfo{Policy: PRRtx, Value: 2}, AuthKey: &key},
		"NoWait and More": {NoWait: true, More: true},
		"Path":            {Path: netip.MustParseAddr("127.0.0.1")},
	}
	for name, o := range opts {
		for _, b := range [][]byte{nil, {}} {
			n, err := client.SendMsg(b, o)
			wantWriteError(t, err, syscall.EINVAL)
			if n != 0 {
				t.Errorf("%s: SendMsg(%v) reported %d bytes", name, b, n)
			}
		}
	}
	for _, b := range [][]byte{nil, {}} {
		n, err := client.Write(b)
		wantWriteError(t, err, syscall.EINVAL)
		if n != 0 {
			t.Errorf("Write(%v) reported %d bytes", b, n)
		}
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d sendmsg calls for empty messages, want 0", n)
	}

	want := []byte("after the empty ones")
	if _, err := client.Write(want); err != nil {
		t.Fatalf("Write after the refused sends: %v", err)
	}
	if got, _ := recvWithin(t, server, 5*time.Second); !bytes.Equal(got, want) {
		t.Errorf("the peer received %q first, want %q", got, want)
	}
}

// TestSendMessageTooLarge: Linux refuses a message larger than the send
// buffer with EMSGSIZE before it waits for anything, NoWait or not
// (net/sctp/socket.c: sctp_sendmsg_parse), and, with fragmentation
// disabled, one larger than the fragmentation point
// (sctp_sendmsg_to_asoc). Nothing of a refused message reaches the peer.
func TestSendMessageTooLarge(t *testing.T) {
	t.Run("send buffer", func(t *testing.T) {
		client, server := connPair(t, nil, nil)
		sndbuf := getIntOpt(t, mustSyscallConn(t, client), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
		big := make([]byte, sndbuf+1)
		_, err := client.Write(big)
		wantWriteError(t, err, syscall.EMSGSIZE)
		_, err = client.SendMsg(big, SendOptions{NoWait: true})
		wantWriteError(t, err, syscall.EMSGSIZE)
		_, err = client.SendMsg(big, SendOptions{Info: &SndInfo{Stream: 1}})
		wantWriteError(t, err, syscall.EMSGSIZE)

		if _, err := client.Write([]byte("marker")); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if got, _ := recvWithin(t, server, 5*time.Second); string(got) != "marker" {
			t.Errorf("the peer received %d bytes first, want the marker", len(got))
		}
	})
	t.Run("fragmentation disabled", func(t *testing.T) {
		client, server := connPair(t, &Config{FragmentsDisabled: new(true)}, nil)
		frag := statusFragPoint(t, client)
		if frag <= 0 {
			t.Fatalf("fragmentation point = %d", frag)
		}
		_, err := client.Write(make([]byte, frag+1))
		wantWriteError(t, err, syscall.EMSGSIZE)
		_, err = client.SendMsg(make([]byte, frag+1), SendOptions{NoWait: true})
		wantWriteError(t, err, syscall.EMSGSIZE)
		fits := fill(frag)
		if _, err := client.Write(fits); err != nil {
			t.Fatalf("Write of exactly the fragmentation point (%d bytes): %v", frag, err)
		}
		if got, _ := recvWithin(t, server, 5*time.Second); !bytes.Equal(got, fits) {
			t.Errorf("the peer received %d bytes first, want the %d-byte message", len(got), frag)
		}
	})
}

// --- Path -----------------------------------------------------------------------

// TestSendPathNotPeer: a Path that is not one of the peer's addresses is
// left to the kernel, which refuses it with EADDRNOTAVAIL on an
// established one-to-one socket (net/sctp/socket.c:
// sctp_sendmsg_new_asoc), while the peer's own address is accepted and
// the message arrives.
func TestSendPathNotPeer(t *testing.T) {
	client, server := connPair(t, nil, nil)
	calls := countSendmsg(t)
	_, err := client.SendMsg([]byte("nowhere"), SendOptions{Path: netip.MustParseAddr("127.0.0.9")})
	wantWriteError(t, err, syscall.EADDRNOTAVAIL)
	if n := calls.Load(); n != 1 {
		t.Errorf("%d sendmsg calls, want 1: the kernel decides", n)
	}

	peer := client.RemoteAddr().(*Addr).IPs[0]
	if _, err := client.SendMsg([]byte("via the peer"), SendOptions{Path: peer}); err != nil {
		t.Fatalf("SendMsg with Path %v, the peer's address: %v", peer, err)
	}
	if got, _ := recvWithin(t, server, 5*time.Second); string(got) != "via the peer" {
		t.Errorf("received %q", got)
	}
}

// TestSendPathAfterTheAssociationEnds: once the association has gone, a
// send with Path reports what any send would: the error Linux set on the
// socket after the peer's ABORT, latched for every later send, or EPIPE
// after a graceful end. Linux looks a destination up among the
// associations by address, finds none, and answers EADDRNOTAVAIL
// (net/sctp/socket.c: sctp_sendmsg_new_asoc on an ESTABLISHED or CLOSING
// one-to-one socket), which sctp_error does not turn into the pending
// error as it turns EPIPE.
func TestSendPathAfterTheAssociationEnds(t *testing.T) {
	for _, abort := range []bool{true, false} {
		name := "graceful end"
		if abort {
			name = "peer ABORT"
		}
		t.Run(name, func(t *testing.T) {
			client, server := connPair(t, nil, nil)
			peer := client.RemoteAddr().(*Addr).IPs[0]
			var err error
			if abort {
				err = server.Abort()
			} else {
				err = server.Shutdown()
			}
			if err != nil {
				t.Fatalf("ending the association: %v", err)
			}
			want := syscall.EPIPE
			if abort {
				want = syscall.ECONNRESET
			}
			deadline := time.Now().Add(5 * time.Second)
			for {
				if time.Now().After(deadline) {
					t.Fatalf("sends with Path never failed with %v", want)
				}
				_, err := client.SendMsg([]byte("pathed"), SendOptions{Path: peer})
				if err == nil || (!abort && errors.Is(err, syscall.ESHUTDOWN)) {
					time.Sleep(5 * time.Millisecond)
					continue
				}
				wantWriteError(t, err, want)
				break
			}
			if abort {
				if got := client.term.latched(); got != syscall.ECONNRESET {
					t.Errorf("latched %v, want ECONNRESET", got)
				}
			}
			_, err = client.SendMsg([]byte("pathed"), SendOptions{Path: peer})
			wantWriteError(t, err, want)
			_, err = client.Write([]byte("plain"))
			wantWriteError(t, err, want)
		})
	}
}

// TestSendPathEncoding: Path is encoded as the destination with the
// association's peer port, on both socket families; an IPv4 Path on an
// AF_INET6 socket goes IPv4-mapped (RFC 6458 §9.1, Held Erratum 4921),
// and one given IPv4-mapped on an AF_INET socket goes plain.
func TestSendPathEncoding(t *testing.T) {
	for _, tc := range []struct {
		name, network string
		path          netip.Addr
		want          func(port uint16) []byte
	}{
		{"sctp4", "sctp4", netip.MustParseAddr("127.0.0.1"), func(p uint16) []byte {
			return rawSockaddrIn(netip.MustParseAddr("127.0.0.1"), p)
		}},
		{"sctp4 given a mapped address", "sctp4", netip.MustParseAddr("::ffff:127.0.0.1"), func(p uint16) []byte {
			return rawSockaddrIn(netip.MustParseAddr("127.0.0.1"), p)
		}},
		{"dual-stack sctp", "sctp", netip.MustParseAddr("127.0.0.1"), func(p uint16) []byte {
			return rawSockaddrIn6(netip.MustParseAddr("::ffff:127.0.0.1"), p, 0)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l := mustListen(t, nil, "sctp4", loopback4(0))
			laddr := listenerAddr(t, l)
			accepted := make(chan *Conn, 1)
			go func() {
				c, err := l.AcceptSCTP()
				if err != nil {
					close(accepted)
					return
				}
				accepted <- c
			}()
			client, err := Dial(testContext(t, 10*time.Second), tc.network, nil, laddr)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			t.Cleanup(func() { _ = client.Abort() })
			server, ok := <-accepted
			if !ok {
				t.Fatal("AcceptSCTP failed")
			}
			t.Cleanup(func() { _ = server.Abort() })

			sent := captureSends(t)
			if _, err := client.SendMsg([]byte("pathed"), SendOptions{Path: tc.path}); err != nil {
				t.Fatalf("SendMsg with Path %v: %v", tc.path, err)
			}
			recs := sent()
			if len(recs) != 1 || !bytes.Equal(recs[0].name, tc.want(laddr.Port)) {
				t.Errorf("sendmsg calls %+v, want one with msg_name % x", recs, tc.want(laddr.Port))
			}
			if got, _ := recvWithin(t, server, 5*time.Second); string(got) != "pathed" {
				t.Errorf("received %q", got)
			}
			if _, err := client.Write([]byte("unpathed")); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if recs := sent(); len(recs) != 1 || recs[0].name != nil {
				t.Errorf("a send without Path made sendmsg calls %+v, want one without msg_name", recs)
			}
			recvWithin(t, server, 5*time.Second)
		})
	}
}

// TestSendPathRefusedBeforeAnySyscall: a Path the connection cannot use is
// refused with EINVAL before any system call. On a connection peeled off
// an Endpoint, Linux ignores the destination (net/sctp/socket.c:
// sctp_sendmsg_get_daddr skips msg_name on a
// SCTP_SOCKET_UDP_HIGH_BANDWIDTH socket), so honouring the call silently
// would send to the primary path instead.
func TestSendPathRefusedBeforeAnySyscall(t *testing.T) {
	client4, _ := connPair(t, nil, nil)
	l6, err := Listen("sctp6", addrOf(0, "::1"))
	if err != nil {
		t.Skipf("no IPv6 loopback to listen on: %v", err)
	}
	t.Cleanup(func() { _ = l6.Close() })
	client6, _ := dialAcceptNetwork(t, "sctp6", l6)
	calls := countSendmsg(t)

	for _, tc := range []struct {
		name string
		c    *Conn
		path string
	}{
		{"IPv6 on an AF_INET socket", client4, "::1"},
		{"zone on a global address", client6, "2001:db8::1%lo"},
		{"unknown zone", client6, "fe80::1%sctp-no-such-interface"},
	} {
		_, err := tc.c.SendMsg([]byte("x"), SendOptions{Path: netip.MustParseAddr(tc.path)})
		if !errors.Is(err, syscall.EINVAL) {
			t.Errorf("%s: SendMsg = %v, want EINVAL", tc.name, err)
		}
	}

	kind := client4.kind
	client4.kind = kindPeeled
	_, err = client4.SendMsg([]byte("x"), SendOptions{Path: netip.MustParseAddr("127.0.0.1")})
	client4.kind = kind
	wantWriteError(t, err, syscall.EINVAL)

	if n := calls.Load(); n != 0 {
		t.Errorf("%d sendmsg calls, want 0", n)
	}
}

// dialAcceptNetwork is dialAccept on network.
func dialAcceptNetwork(t testing.TB, network string, l *Listener) (client, server *Conn) {
	t.Helper()
	accepted := make(chan *Conn, 1)
	go func() {
		c, err := l.AcceptSCTP()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	client, err := Dial(testContext(t, 10*time.Second), network, nil, listenerAddr(t, l))
	if err != nil {
		t.Fatalf("Dial %s: %v", network, err)
	}
	t.Cleanup(func() { _ = client.Abort() })
	server, ok := <-accepted
	if !ok {
		t.Fatal("AcceptSCTP failed")
	}
	t.Cleanup(func() { _ = server.Abort() })
	return client, server
}

// TestSendPathAfterTheAssociationEndedBeforeAccept: a connection whose
// association ended before Accept has no association and no peer, and
// its socket is CLOSED (net/sctp/socket.c: sctp_sock_migrate). A send
// there fails as any send does, Path or not; Linux would otherwise treat
// the destination as a request for a new association
// (sctp_sendmsg_new_asoc sets one up from a socket that is not
// ESTABLISHED or CLOSING), and a Conn never starts a second association.
func TestSendPathAfterTheAssociationEndedBeforeAccept(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	laddr := listenerAddr(t, l)
	client, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, laddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	waitAssocClosed(t, laddr.Port)
	server, err := l.AcceptSCTP()
	if err != nil {
		t.Fatalf("AcceptSCTP: %v", err)
	}
	t.Cleanup(func() { _ = server.Abort() })
	if server.AssocID() != 0 {
		t.Fatalf("AssocID = %d, want 0 for an association that ended before Accept", server.AssocID())
	}
	baseline := countAssocs(t)

	_, err = server.SendMsg([]byte("x"), SendOptions{Path: netip.MustParseAddr("127.0.0.1")})
	wantWriteError(t, err, syscall.EPIPE)
	_, err = server.Write([]byte("x"))
	wantWriteError(t, err, syscall.EPIPE)
	time.Sleep(100 * time.Millisecond)
	if got := countAssocs(t); got > baseline {
		t.Errorf("%d associations after the sends, %d before: a send started a new association", got, baseline)
	}
}

// --- NoWait and waiting -----------------------------------------------------------

// TestNoWaitRefusalQueuesNothing: against a peer that does not read, NoWait
// sends fill the buffer and the first refused one returns EAGAIN at once.
// Linux refuses buffer space before it builds the message
// (net/sctp/socket.c: sctp_sendmsg_to_asoc waits, or with MSG_DONTWAIT
// refuses, in sctp_wait_for_sndbuf before sctp_datamsg_from_user), so
// nothing of it is queued: once the peer reads, it gets exactly the
// accepted messages, in order, and nothing after them.
func TestNoWaitRefusalQueuesNothing(t *testing.T) {
	client, server := connPair(t, nil, nil)
	// Only a guard: a NoWait send that waited would end here, not hang.
	if err := client.SetWriteDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	accepted := 0
	for ; ; accepted++ {
		if accepted > 1<<20 {
			t.Fatal("the send buffer never filled")
		}
		start := time.Now()
		_, err := client.SendMsg(numbered(accepted), SendOptions{NoWait: true})
		if err == nil {
			continue
		}
		wantWriteError(t, err, syscall.EAGAIN)
		if d := time.Since(start); d > time.Second {
			t.Errorf("the refusal took %v; NoWait must not wait", d)
		}
		break
	}

	for i := range accepted {
		got, _ := recvWithin(t, server, 5*time.Second)
		if numberOf(got) != i {
			t.Fatalf("message %d read is number %d", i, numberOf(got))
		}
	}
	wantNothingQueued(t, server, 300*time.Millisecond)
}

// TestNoWaitWaitsBehindParkedSend: a NoWait send takes the connection's
// send lock like any send, so it waits behind a send that is waiting for
// buffer space; a write deadline then releases both with the deadline
// error.
func TestNoWaitWaitsBehindParkedSend(t *testing.T) {
	client, server := connPair(t, nil, &Config{ReadBuffer: new(closingReadBuffer)})
	payload := fill(512)
	fillSendBufferStable(t, client, server, payload)

	blocking := make(chan error, 1)
	go func() {
		_, err := client.SendMsg(payload, SendOptions{})
		blocking <- err
	}()
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-blocking:
		t.Fatalf("a blocking send on a full buffer returned %v", err)
	default:
	}

	nowait := make(chan error, 1)
	go func() {
		_, err := client.SendMsg(payload, SendOptions{NoWait: true})
		nowait <- err
	}()
	time.Sleep(200 * time.Millisecond)
	select {
	case err := <-nowait:
		t.Fatalf("a NoWait send returned %v while another send held the send lock; it must wait for the lock", err)
	default:
	}

	if err := client.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	for name, ch := range map[string]chan error{"blocking": blocking, "NoWait": nowait} {
		select {
		case err := <-ch:
			wantWriteError(t, err, os.ErrDeadlineExceeded)
		case <-time.After(5 * time.Second):
			t.Fatalf("the %s send was not released by the deadline", name)
		}
	}
}

// TestSendWaitsForBufferSpace: a send without NoWait waits for buffer
// space in the runtime poller, and returns once the peer drains, when a
// deadline set while it waits passes, or when the connection is closed.
func TestSendWaitsForBufferSpace(t *testing.T) {
	t.Run("drain", func(t *testing.T) {
		client, server := connPair(t, nil, &Config{ReadBuffer: new(closingReadBuffer)})
		payload := fill(512)
		sent := fillSendBufferStable(t, client, server, payload)
		drained := make(chan error, 1)
		go func() {
			time.Sleep(250 * time.Millisecond)
			if err := server.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
				drained <- err
				return
			}
			buf := make([]byte, 1024)
			for range sent + 1 {
				if _, _, err := recvInfo(server, buf); err != nil {
					drained <- err
					return
				}
			}
			drained <- nil
		}()
		start := time.Now()
		n, err := client.SendMsg(payload, SendOptions{Info: &SndInfo{Stream: 1}})
		if err != nil || n != len(payload) {
			t.Fatalf("SendMsg = %d, %v; want %d, nil", n, err, len(payload))
		}
		if d := time.Since(start); d < 200*time.Millisecond {
			t.Errorf("returned after %v, before the drain that made room started", d)
		}
		if err := <-drained; err != nil {
			t.Fatalf("draining: %v", err)
		}
	})
	t.Run("deadline set while waiting", func(t *testing.T) {
		client, server := connPair(t, nil, &Config{ReadBuffer: new(closingReadBuffer)})
		payload := fill(512)
		fillSendBufferStable(t, client, server, payload)
		done := make(chan error, 1)
		go func() {
			_, err := client.Write(payload)
			done <- err
		}()
		time.Sleep(200 * time.Millisecond)
		select {
		case err := <-done:
			t.Fatalf("Write on a full buffer returned %v instead of waiting", err)
		default:
		}
		deadline := time.Now().Add(300 * time.Millisecond)
		if err := client.SetWriteDeadline(deadline); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		select {
		case err := <-done:
			opErr := writeOpError(t, err, os.ErrDeadlineExceeded)
			if errors.Is(err, syscall.EAGAIN) {
				t.Error("the deadline is reported as EAGAIN too, so it cannot be told from a NoWait refusal")
			}
			if !opErr.Timeout() {
				t.Error("the deadline error's Timeout() is false")
			}
			if time.Now().Before(deadline.Add(-100 * time.Millisecond)) {
				t.Error("Write returned well before the deadline")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("the deadline did not release the waiting Write")
		}
	})
	t.Run("deadline set before", func(t *testing.T) {
		client, server := connPair(t, nil, &Config{ReadBuffer: new(closingReadBuffer)})
		payload := fill(512)
		fillSendBufferStable(t, client, server, payload)
		if err := client.SetWriteDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		start := time.Now()
		_, err := client.SendMsg(payload, SendOptions{})
		wantWriteError(t, err, os.ErrDeadlineExceeded)
		if d := time.Since(start); d < 250*time.Millisecond || d > 5*time.Second {
			t.Errorf("returned after %v against a 300 ms deadline", d)
		}
	})
	t.Run("Close", func(t *testing.T) {
		cfg := &Config{CloseTimeout: 300 * time.Millisecond}
		client, server := connPair(t, cfg, &Config{ReadBuffer: new(closingReadBuffer)})
		payload := fill(512)
		fillSendBufferStable(t, client, server, payload)
		done := make(chan error, 1)
		go func() {
			_, err := client.SendMsg(payload, SendOptions{})
			done <- err
		}()
		time.Sleep(200 * time.Millisecond)
		closed := make(chan error, 1)
		go func() { closed <- client.Close() }()
		select {
		case err := <-done:
			wantWriteError(t, err, net.ErrClosed)
		case <-time.After(5 * time.Second):
			t.Fatal("Close did not release the waiting send")
		}
		if err := <-closed; err != nil {
			t.Errorf("Close: %v", err)
		}
	})
}

// --- deadlines --------------------------------------------------------------------

// TestWriteDeadlineInThePast: a write deadline that has passed fails every
// send before any attempt, NoWait included, and clearing it restores
// sends.
func TestWriteDeadlineInThePast(t *testing.T) {
	client, server := connPair(t, nil, nil)
	if err := client.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	calls := countSendmsg(t)
	for name, send := range map[string]func() error{
		"Write": func() error { _, err := client.Write([]byte("late")); return err },
		"SendMsg": func() error {
			_, err := client.SendMsg([]byte("late"), SendOptions{Info: &SndInfo{}})
			return err
		},
		"NoWait": func() error { _, err := client.SendMsg([]byte("late"), SendOptions{NoWait: true}); return err },
	} {
		start := time.Now()
		opErr := writeOpError(t, send(), os.ErrDeadlineExceeded)
		if !opErr.Timeout() {
			t.Errorf("%s: Timeout() is false", name)
		}
		if d := time.Since(start); d > time.Second {
			t.Errorf("%s took %v with a deadline already passed", name, d)
		}
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d sendmsg calls with a deadline already passed, want 0", n)
	}

	if err := client.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("clearing the deadline: %v", err)
	}
	if _, err := client.Write([]byte("fine now")); err != nil {
		t.Fatalf("Write after clearing the deadline: %v", err)
	}
	if got, _ := recvWithin(t, server, 5*time.Second); string(got) != "fine now" {
		t.Errorf("received %q, want only the message sent after clearing the deadline", got)
	}
}

// TestSetDeadlineSetsBoth: SetDeadline sets the write and the read
// deadline.
func TestSetDeadlineSetsBoth(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	if err := client.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	_, err := client.Write([]byte("x"))
	wantWriteError(t, err, os.ErrDeadlineExceeded)
	if _, _, err := recvInfo(client, make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("read err = %v, want os.ErrDeadlineExceeded", err)
	}
}

// TestDeadlineFlipFlop alternates the write and read deadlines between
// passed, in the future and none, 50 times, across SendMsg, a NoWait send
// and a read, and checks that every call obeys the deadline in force when
// it starts: a passed one fails the call at once, even with a message
// queued for a read; a future one lets a send through and ends a read that
// finds nothing at the deadline; none lets everything through. Numbered
// messages show that no failed send queued anything and nothing was lost.
// The reads rotate through Read, RecvMsg and ReadMsg.
func TestDeadlineFlipFlop(t *testing.T) {
	// NoDelay: a small message is sent at once, not held until the
	// previous one is acknowledged (RFC 6458 §8.1.5), which the peer may
	// delay by up to 200 ms (RFC 9260 §6.2), longer than the future
	// deadline a read of it runs under.
	client, server := connPair(t, &Config{NoDelay: new(true)}, nil)
	const (
		iterations = 50
		future     = 100 * time.Millisecond
	)
	var (
		next     int // the number of the next message to send
		expected int // the number of the next message the server must read
		queued   int // messages sent and not yet read
	)
	send := func(i int, opts SendOptions, wantErr error) {
		t.Helper()
		start := time.Now()
		_, err := client.SendMsg(numbered(next), opts)
		if wantErr != nil {
			wantWriteError(t, err, wantErr)
			if d := time.Since(start); d > time.Second {
				t.Fatalf("iteration %d: a send with a passed deadline took %v", i, d)
			}
			return
		}
		if err != nil {
			t.Fatalf("iteration %d: send %d: %v", i, next, err)
		}
		next++
		queued++
	}
	// Reads rotate through the three receive calls, which all wait in the
	// same poller and follow the same read deadline.
	readers := []func() ([]byte, error){
		func() ([]byte, error) { b := make([]byte, 256); n, err := server.Read(b); return b[:n], err },
		func() ([]byte, error) { b := make([]byte, 256); n, _, err := server.RecvMsg(b); return b[:n], err },
		func() ([]byte, error) { b, _, err := server.ReadMsg(256); return b, err },
	}
	reads := 0
	readOne := func() ([]byte, error) {
		reads++
		return readers[reads%len(readers)]()
	}
	read := func(i int) {
		t.Helper()
		b, err := readOne()
		if err != nil {
			t.Fatalf("iteration %d: read: %v", i, err)
		}
		if got := numberOf(b); got != expected {
			t.Fatalf("iteration %d: read message %d, want %d", i, got, expected)
		}
		expected++
		queued--
	}
	start := time.Now()
	for i := range iterations {
		var dl time.Time
		switch i % 3 {
		case 0:
			dl = time.Now().Add(-time.Second)
		case 1:
			dl = time.Now().Add(future)
		}
		if err := client.SetWriteDeadline(dl); err != nil {
			t.Fatalf("SetWriteDeadline: %v", err)
		}
		if err := server.SetReadDeadline(dl); err != nil {
			t.Fatalf("SetReadDeadline: %v", err)
		}
		switch i % 3 {
		case 0: // passed
			send(i, SendOptions{Info: &SndInfo{Stream: 1}}, os.ErrDeadlineExceeded)
			send(i, SendOptions{NoWait: true}, os.ErrDeadlineExceeded)
			rstart := time.Now()
			if _, err := readOne(); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("iteration %d: a read with a passed deadline and %d messages queued = %v, want os.ErrDeadlineExceeded", i, queued, err)
			}
			if d := time.Since(rstart); d > time.Second {
				t.Fatalf("iteration %d: a read with a passed deadline took %v", i, d)
			}
		case 1: // future
			send(i, SendOptions{Info: &SndInfo{Stream: 1}}, nil)
			send(i, SendOptions{NoWait: true}, nil)
			for queued > 0 {
				read(i)
			}
			rstart := time.Now()
			if _, err := readOne(); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("iteration %d: a read of nothing with a future deadline = %v, want os.ErrDeadlineExceeded", i, err)
			}
			if d := time.Since(rstart); d > 2*time.Second {
				t.Fatalf("iteration %d: a read with a %v deadline took %v", i, future, d)
			}
		case 2: // none; one message is left for the next, passed, iteration
			send(i, SendOptions{Info: &SndInfo{Stream: 1}}, nil)
			send(i, SendOptions{NoWait: true}, nil)
			send(i, SendOptions{}, nil)
			for queued > 1 {
				read(i)
			}
		}
	}
	if err := server.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	for queued > 0 {
		read(iterations)
	}
	if expected != next {
		t.Errorf("read %d messages, sent %d", expected, next)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("%d iterations took %v", iterations, d)
	}
}

// --- concurrency and signals ------------------------------------------------------

// TestConcurrentSendsKeepMetadata: 8 goroutines send 500 messages each,
// every goroutine on its own stream, with PPIDs of its own and, for half
// of them, unordered. Each payload carries its sender and sequence number,
// and the receiver checks every message's RcvInfo against it: concurrent
// sends must never exchange stream, PPID or flags, since the control
// message is encoded in the connection's shared storage under the send
// lock. Ordered streams must also keep each sender's order.
func TestConcurrentSendsKeepMetadata(t *testing.T) {
	client, server := connPair(t, nil, nil)
	const senders, perSender = 8, 500

	recvErr := make(chan error, 1)
	go func() {
		if err := server.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
			recvErr <- err
			return
		}
		lastOrdered := make([]int, senders)
		for g := range lastOrdered {
			lastOrdered[g] = -1
		}
		counts := make([]int, senders)
		buf := make([]byte, 256)
		for range senders * perSender {
			n, info, err := recvInfo(server, buf)
			if err != nil {
				recvErr <- err
				return
			}
			if n != 8 {
				recvErr <- fmt.Errorf("a %d-byte message, want 8", n)
				return
			}
			g, i := int(buf[0]), int(binary.BigEndian.Uint32(buf[4:]))
			unordered := buf[1] == 1
			if g >= senders || info.Stream != uint16(g+1) || info.PPID != uint32(g)<<16|uint32(i) || info.Unordered != unordered {
				recvErr <- fmt.Errorf("message %d of sender %d arrived with stream %d, PPID %#x, unordered %v; want stream %d, PPID %#x, unordered %v",
					i, g, info.Stream, info.PPID, info.Unordered, g+1, uint32(g)<<16|uint32(i), unordered)
				return
			}
			if !unordered {
				if i <= lastOrdered[g] {
					recvErr <- fmt.Errorf("sender %d: message %d after %d on an ordered stream", g, i, lastOrdered[g])
					return
				}
				lastOrdered[g] = i
			}
			counts[g]++
		}
		for g, n := range counts {
			if n != perSender {
				recvErr <- fmt.Errorf("sender %d: %d messages, want %d", g, n, perSender)
				return
			}
		}
		recvErr <- nil
	}()

	var wg sync.WaitGroup
	sendErr := make(chan error, senders)
	for g := range senders {
		wg.Go(func() {
			flags := SendFlags(0)
			if g%2 == 1 {
				flags = SendUnordered
			}
			for i := range perSender {
				b := make([]byte, 8)
				b[0] = byte(g)
				if flags == SendUnordered {
					b[1] = 1
				}
				binary.BigEndian.PutUint32(b[4:], uint32(i))
				info := &SndInfo{Stream: uint16(g + 1), Flags: flags, PPID: uint32(g)<<16 | uint32(i)}
				if _, err := client.SendMsg(b, SendOptions{Info: info}); err != nil {
					sendErr <- fmt.Errorf("sender %d message %d: %w", g, i, err)
					return
				}
			}
		})
	}
	wg.Wait()
	close(sendErr)
	for err := range sendErr {
		t.Fatal(err)
	}
	if err := <-recvErr; err != nil {
		t.Fatal(err)
	}
}

// TestSendRetriesEINTR: a sendmsg interrupted by a signal is retried in
// place; the caller never sees EINTR, and the message is sent once.
func TestSendRetriesEINTR(t *testing.T) {
	client, server := connPair(t, nil, nil)
	var calls atomic.Int64
	hookSendmsg(t, func(fd int, msg *syscall.Msghdr, flags int) (int, error) {
		if calls.Add(1) <= 3 {
			return 0, syscall.EINTR
		}
		return rawSendmsg(fd, msg, flags)
	})
	n, err := client.SendMsg([]byte("interrupted"), SendOptions{Info: &SndInfo{Stream: 1}})
	if err != nil || n != len("interrupted") {
		t.Fatalf("SendMsg = %d, %v; want the message sent despite EINTR", n, err)
	}
	if got := calls.Load(); got != 4 {
		t.Errorf("%d sendmsg calls, want 4 (three interrupted, then the send)", got)
	}
	if got, _ := recvWithin(t, server, 5*time.Second); string(got) != "interrupted" {
		t.Errorf("received %q", got)
	}
	wantNothingQueued(t, server, 200*time.Millisecond)
}

// TestSendSurvivesSignals: 2000 sends, and the reads that drain them, all
// complete while the process is signalled continuously.
func TestSendSurvivesSignals(t *testing.T) {
	client, server := connPair(t, nil, nil)
	const messages = 2000
	stop := signalStorm(t)
	defer stop()

	recvErr := make(chan error, 1)
	go func() {
		if err := server.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
			recvErr <- err
			return
		}
		buf := make([]byte, 256)
		for i := range messages {
			n, _, err := recvInfo(server, buf)
			if err != nil {
				recvErr <- fmt.Errorf("read %d: %w", i, err)
				return
			}
			if got := numberOf(buf[:n]); got != i {
				recvErr <- fmt.Errorf("read message %d, want %d", got, i)
				return
			}
		}
		recvErr <- nil
	}()
	for i := range messages {
		if _, err := client.SendMsg(numbered(i), SendOptions{Info: &SndInfo{Stream: 1}}); err != nil {
			if errors.Is(err, syscall.EINTR) {
				t.Fatalf("send %d returned EINTR; a signal during sendmsg must be retried", i)
			}
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if err := <-recvErr; err != nil {
		t.Fatal(err)
	}
}

// TestDialNeverReturnsAnUnestablishedAssociation: under continuous signals,
// a dial either fails or hands back a connection whose first send
// succeeds. A connection whose association was never established would
// fail that send with EPIPE and SCTP_STATUS would find no association.
func TestDialNeverReturnsAnUnestablishedAssociation(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	laddr := listenerAddr(t, l)
	var srv sync.WaitGroup
	srv.Go(func() {
		for {
			c, err := l.AcceptSCTP()
			if err != nil {
				return
			}
			srv.Go(func() {
				defer func() { _ = c.Close() }()
				_ = drainUntilEnd(c)
			})
		}
	})

	stop := signalStorm(t)
	// Bound each attempt's own setup: RFC 6458 §8.1.3 lets MaxAttempts and
	// MaxInitTimeout override the INIT retransmission limits, which default
	// to 8 attempts and RFC 9260 §16's 60 s RTO.Max.
	cfg := &Config{InitMsg: InitMsg{MaxAttempts: 2, MaxInitTimeout: time.Second}}
	rounds, perRound := 4, 500
	if testing.Short() {
		rounds, perRound = 1, 200
	}
	// A dial that fails, and a connection whose association ended after it
	// was established and before the probe, are both acceptable outcomes
	// under the storm; a connection that never had one is not.
	var dead atomic.Int64
	for range rounds {
		var wg sync.WaitGroup
		for range perRound {
			wg.Go(func() {
				c, err := cfg.Dial(context.Background(), "sctp4", nil, laddr)
				if err != nil {
					return
				}
				defer func() { _ = c.Close() }()
				if _, err := c.Write([]byte("probe")); err != nil {
					if _, state, serr := c.sock.status(); serr != nil || state == StateClosed {
						dead.Add(1)
					}
				}
			})
		}
		wg.Wait()
	}
	stop()
	_ = l.Close()
	srv.Wait()

	if n := dead.Load(); n > 0 {
		t.Errorf("%d of %d dials reported success but carried no association", n, rounds*perRound)
	}
}

// --- after the association ends ----------------------------------------------------

// wantNoSIGPIPE fails the test if a SIGPIPE arrives within 200 ms.
func wantNoSIGPIPE(t testing.TB, sig <-chan os.Signal) {
	t.Helper()
	select {
	case s := <-sig:
		t.Errorf("received %v; every send passes MSG_NOSIGNAL, so a send to a gone association must report EPIPE without a signal", s)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestSendAfterPeerShutdown: after the peer's Shutdown, a send fails with
// ESHUTDOWN while the shutdown is in progress (net/sctp/sm_statefuns.c:
// sctp_sf_error_shutdown) and with EPIPE once the association is gone
// (net/sctp/socket.c: sctp_sendmsg); on loopback the handshake completes
// too fast to tell the two apart, so either is accepted until the first
// EPIPE, and every send after it is EPIPE. No SIGPIPE is raised: every
// send passes MSG_NOSIGNAL (sctp_error).
func TestSendAfterPeerShutdown(t *testing.T) {
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGPIPE)
	defer signal.Stop(sig)

	client, server := connPair(t, nil, nil)
	if err := server.Shutdown(); err != nil {
		t.Fatalf("peer Shutdown: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for sawEPIPE := false; !sawEPIPE; {
		if time.Now().After(deadline) {
			t.Fatal("sends never failed with EPIPE after the peer's shutdown")
		}
		_, err := client.Write([]byte("after the shutdown"))
		switch {
		case err == nil:
			time.Sleep(5 * time.Millisecond)
		case errors.Is(err, syscall.EPIPE):
			wantWriteError(t, err, syscall.EPIPE)
			sawEPIPE = true
		default:
			wantWriteError(t, err, syscall.ESHUTDOWN)
		}
	}
	for range 5 {
		_, err := client.SendMsg([]byte("still gone"), SendOptions{Info: &SndInfo{Stream: 1}})
		wantWriteError(t, err, syscall.EPIPE)
	}
	if err := client.term.latched(); err != nil {
		t.Errorf("a graceful end latched %v", err)
	}
	wantNoSIGPIPE(t, sig)
}

// TestSendAfterPeerAbortIsSticky: after the peer's ABORT, Linux sets
// ECONNRESET on the socket and hands it to the first call that looks
// (net/sctp/sm_sideeffect.c: sctp_cmd_set_sk_err; net/sctp/socket.c:
// sctp_error). The send that takes it latches it, and every later send
// returns it too, without a system call, where Linux alone would answer
// EPIPE from then on. No SIGPIPE is raised.
func TestSendAfterPeerAbortIsSticky(t *testing.T) {
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGPIPE)
	defer signal.Stop(sig)

	client, server := connPair(t, nil, nil)
	if err := server.Abort(); err != nil {
		t.Fatalf("peer Abort: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if time.Now().After(deadline) {
			t.Fatal("sends kept succeeding after the peer's ABORT")
		}
		_, err := client.Write([]byte("after the abort"))
		if err == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}
		wantWriteError(t, err, syscall.ECONNRESET)
		break
	}
	calls := countSendmsg(t)
	for range 5 {
		_, err := client.SendMsg([]byte("still reset"), SendOptions{Info: &SndInfo{Stream: 1}})
		wantWriteError(t, err, syscall.ECONNRESET)
		_, err = client.SendMsg([]byte("still reset"), SendOptions{NoWait: true})
		wantWriteError(t, err, syscall.ECONNRESET)
	}
	if n := calls.Load(); n != 0 {
		t.Errorf("%d sendmsg calls after the error was latched, want 0", n)
	}
	wantNoSIGPIPE(t, sig)
}

// TestSendLatchRules drives the send path's rules for the association
// error with a scripted sendmsg: ECONNRESET, ETIMEDOUT and ECONNABORTED are
// latched and returned by every later send without a system call; EPIPE
// is the graceful case and is not latched, unless the connection has seen
// its association fail, when the error is out of reach and ENOTCONN is
// latched instead; ESHUTDOWN is not latched. The latch mutex is held
// around the system call.
func TestSendLatchRules(t *testing.T) {
	for _, tc := range []struct {
		name      string
		ret       syscall.Errno
		failed    bool
		want      error
		latched   error
		laterCall bool // a later send reaches sendmsg again
	}{
		{name: "ECONNRESET", ret: syscall.ECONNRESET, want: syscall.ECONNRESET, latched: syscall.ECONNRESET},
		{name: "ETIMEDOUT", ret: syscall.ETIMEDOUT, want: syscall.ETIMEDOUT, latched: syscall.ETIMEDOUT},
		{name: "ECONNABORTED", ret: syscall.ECONNABORTED, want: syscall.ECONNABORTED, latched: syscall.ECONNABORTED},
		{name: "EPIPE", ret: syscall.EPIPE, want: syscall.EPIPE, laterCall: true},
		{name: "EPIPE after a failure", ret: syscall.EPIPE, failed: true, want: syscall.ENOTCONN, latched: syscall.ENOTCONN},
		{name: "ESHUTDOWN", ret: syscall.ESHUTDOWN, want: syscall.ESHUTDOWN, laterCall: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := connPair(t, nil, nil)
			if tc.failed {
				client.term.markFailed()
			}
			var calls atomic.Int64
			var heldEvery atomic.Bool
			heldEvery.Store(true)
			hookSendmsg(t, func(int, *syscall.Msghdr, int) (int, error) {
				calls.Add(1)
				if client.term.mu.TryLock() {
					client.term.mu.Unlock()
					heldEvery.Store(false)
				}
				return 0, tc.ret
			})
			_, err := client.SendMsg([]byte("x"), SendOptions{})
			wantWriteError(t, err, tc.want)
			if got := client.term.latched(); got != tc.latched {
				t.Errorf("latched %v, want %v", got, tc.latched)
			}
			_, err = client.Write([]byte("y"))
			wantWriteError(t, err, tc.want)
			if want := map[bool]int64{true: 2, false: 1}[tc.laterCall]; calls.Load() != want {
				t.Errorf("%d sendmsg calls for two sends, want %d", calls.Load(), want)
			}
			if !heldEvery.Load() {
				t.Error("the latch mutex was not held around sendmsg")
			}
		})
	}
}

// --- errors -------------------------------------------------------------------------

// TestSendErrorsCarryConnectionContext: every send error is a *net.OpError
// with Op "write", the connection's network, its local address snapshot as
// Source and its peer's as Addr, wrapping the cause once; a closed
// connection gives net.ErrClosed, never nested.
func TestSendErrorsCarryConnectionContext(t *testing.T) {
	for _, network := range []string{"sctp4", "sctp"} {
		t.Run(network, func(t *testing.T) {
			l := mustListen(t, nil, "sctp4", loopback4(0))
			client, _ := dialAcceptNetwork(t, network, l)
			wantContext := func(what string, err, cause error) {
				t.Helper()
				opErr := writeOpError(t, err, cause)
				if opErr.Net != network {
					t.Errorf("%s: Net = %q, want %q", what, opErr.Net, network)
				}
				if !reflect.DeepEqual(opErr.Source, client.LocalAddr()) {
					t.Errorf("%s: Source = %v, want %v", what, opErr.Source, client.LocalAddr())
				}
				if !reflect.DeepEqual(opErr.Addr, client.RemoteAddr()) {
					t.Errorf("%s: Addr = %v, want %v", what, opErr.Addr, client.RemoteAddr())
				}
				if _, nested := opErr.Err.(*net.OpError); nested {
					t.Errorf("%s: a *net.OpError inside the *net.OpError: %#v", what, opErr.Err)
				}
			}

			_, err := client.SendMsg(nil, SendOptions{})
			wantContext("empty message", err, syscall.EINVAL)
			if err := client.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
				t.Fatalf("SetWriteDeadline: %v", err)
			}
			_, err = client.Write([]byte{1})
			wantContext("deadline", err, os.ErrDeadlineExceeded)
			if err := client.SetWriteDeadline(time.Time{}); err != nil {
				t.Fatalf("SetWriteDeadline: %v", err)
			}

			if err := client.Abort(); err != nil {
				t.Fatalf("Abort: %v", err)
			}
			_, err = client.Write([]byte{1})
			wantContext("Write after Abort", err, net.ErrClosed)
			_, err = client.SendMsg([]byte{1}, SendOptions{NoWait: true})
			wantContext("SendMsg after Abort", err, net.ErrClosed)
		})
	}

	var nilConn *Conn
	_, err := nilConn.Write([]byte{1})
	wantWriteError(t, err, net.ErrClosed)
	_, err = new(Conn).SendMsg([]byte{1}, SendOptions{})
	wantWriteError(t, err, net.ErrClosed)
}

// TestSendMsgRetainsNothing: once SendMsg returns, the connection's send
// storage no longer refers to the caller's payload.
func TestSendMsgRetainsNothing(t *testing.T) {
	client, _ := connPair(t, nil, nil)
	if _, err := client.SendMsg([]byte("kept?"), SendOptions{Info: &SndInfo{Stream: 1}}); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	if client.send.b != nil || client.send.iov.Base != nil {
		t.Errorf("after SendMsg the send storage still refers to the payload: b %p, iov.Base %p", client.send.b, client.send.iov.Base)
	}
	if _, err := client.SendMsg(nil, SendOptions{}); err == nil {
		t.Fatal("an empty SendMsg succeeded")
	}
	if client.send.b != nil || client.send.iov.Base != nil {
		t.Error("after a refused SendMsg the send storage refers to a payload")
	}
}

// TestSendFlags: every send passes MSG_DONTWAIT, so a full buffer is a
// wait in the runtime poller rather than in the kernel, and MSG_NOSIGNAL;
// More adds MSG_MORE (net/sctp/socket.c sets
// asoc->force_delay from it in sctp_sendmsg_to_asoc). A send without Path
// has no destination, and one without Info or PR no SNDINFO or PRINFO.
func TestSendFlags(t *testing.T) {
	client, server := connPair(t, nil, nil)
	sent := captureSends(t)
	base := syscall.MSG_DONTWAIT | syscall.MSG_NOSIGNAL
	for _, tc := range []struct {
		name  string
		opts  SendOptions
		flags int
	}{
		{"defaults", SendOptions{}, base},
		{"NoWait", SendOptions{NoWait: true}, base},
		{"More", SendOptions{More: true}, base | syscall.MSG_MORE},
		{"after More", SendOptions{}, base},
	} {
		if _, err := client.SendMsg([]byte(tc.name), tc.opts); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		recs := sent()
		if len(recs) != 1 {
			t.Fatalf("%s: %d sendmsg calls, want 1", tc.name, len(recs))
		}
		r := recs[0]
		if r.flags != tc.flags {
			t.Errorf("%s: flags %#x, want %#x", tc.name, r.flags, tc.flags)
		}
		if r.name != nil || r.snd != nil || r.pr != nil || r.key != nil {
			t.Errorf("%s: sent %+v, want no destination and no control records", tc.name, r)
		}
	}
	for range 4 {
		recvWithin(t, server, 5*time.Second)
	}
}

// --- ported from v1 sctp_streams_test.go ----------------------------------------

// TestStreams: 128 clients each send one message on each of 11 streams,
// with the stream number as PPID; the server echoes every message on the
// stream and with the PPID it arrived with, and each client checks the
// echo's stream, PPID and payload.
func TestStreams(t *testing.T) {
	const clients, streams = 128, 11
	cfg := &Config{InitMsg: InitMsg{OutStreams: streams, MaxInStreams: streams}}
	l := mustListen(t, cfg, "sctp4", loopback4(0))
	laddr := listenerAddr(t, l)

	var srv sync.WaitGroup
	srv.Go(func() {
		for {
			c, err := l.AcceptSCTP()
			if err != nil {
				return
			}
			srv.Go(func() {
				defer func() { _ = c.Close() }()
				// Bounded, so that a read that never ends fails the test
				// instead of hanging it.
				if err := c.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
					t.Errorf("SetReadDeadline: %v", err)
					return
				}
				buf := make([]byte, 512)
				for {
					n, info, err := recvInfo(c, buf)
					if err != nil {
						if err != io.EOF {
							t.Errorf("echo read: %v", err)
						}
						return
					}
					if _, err := c.SendMsg(buf[:n], SendOptions{Info: &SndInfo{Stream: info.Stream, PPID: info.PPID}}); err != nil {
						t.Errorf("echo: %v", err)
						return
					}
				}
			})
		}
	})

	var rmu sync.Mutex
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	randomText := func() string {
		const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		rmu.Lock()
		defer rmu.Unlock()
		b := make([]byte, r.Intn(255))
		for i := range b {
			b[i] = chars[r.Intn(len(chars))]
		}
		return string(b)
	}

	var wg sync.WaitGroup
	for c := range clients {
		wg.Go(func() {
			conn, err := cfg.Dial(context.Background(), "sctp4", nil, laddr)
			if err != nil {
				t.Errorf("client %d: Dial: %v", c, err)
				return
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Errorf("client %d: SetReadDeadline: %v", c, err)
				return
			}
			buf := make([]byte, 512)
			for s := range uint16(streams) {
				text := fmt.Sprintf("Test %s ***\n\t\t%d %d ***", randomText(), c, s)
				if _, err := conn.SendMsg([]byte(text), SendOptions{Info: &SndInfo{Stream: s, PPID: uint32(s)}}); err != nil {
					t.Errorf("client %d stream %d: SendMsg: %v", c, s, err)
					return
				}
				n, info, err := recvInfo(conn, buf)
				if err != nil {
					t.Errorf("client %d stream %d: read: %v", c, s, err)
					return
				}
				if info.Stream != s || info.PPID != uint32(s) {
					t.Errorf("client %d: the echo came on stream %d with PPID %d, want %d and %d", c, info.Stream, info.PPID, s, s)
					return
				}
				if string(buf[:n]) != text {
					t.Errorf("client %d stream %d: echo %q, want %q", c, s, buf[:n], text)
					return
				}
			}
		})
	}
	wg.Wait()
	_ = l.Close()
	srv.Wait()
}

// --- benchmarks ---------------------------------------------------------------------

// benchSend measures send against a helper-process peer that reads and
// discards, so that allocs/op counts the sender alone. Sends wait for
// buffer space, so a peer slower than the sender costs time, not errors.
func benchSend(b *testing.B, send func(c *Conn, payload []byte) error) {
	peer := startHelperPeer(b, "sctp4", "127.0.0.1:0", false)
	cfg := &Config{NoDelay: new(true)}
	c, err := cfg.Dial(testContext(b, 10*time.Second), "sctp4", nil, peer)
	if err != nil {
		b.Fatalf("Dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	payload := make([]byte, 512)
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if err := send(c, payload); err != nil {
			b.Fatalf("send: %v", err)
		}
	}
}

// BenchmarkSendMsg sends with an SndInfo naming a stream and a PPID, the
// common case (v1 BenchmarkSCTPWrite and BenchmarkSCTPWriteInfo).
func BenchmarkSendMsg(b *testing.B) {
	info := &SndInfo{Stream: 1, PPID: 0x1234}
	benchSend(b, func(c *Conn, p []byte) error {
		_, err := c.SendMsg(p, SendOptions{Info: info})
		return err
	})
}

// BenchmarkSendMsgInfoPR adds a PR-SCTP policy, two control records.
func BenchmarkSendMsgInfoPR(b *testing.B) {
	info := &SndInfo{Stream: 1, PPID: 0x1234}
	pr := &PrInfo{Policy: PRTTL, TTL: 30 * time.Second}
	benchSend(b, func(c *Conn, p []byte) error {
		_, err := c.SendMsg(p, SendOptions{Info: info, PR: pr})
		return err
	})
}

// BenchmarkWrite sends with no control records at all (v1
// BenchmarkSCTPWriteNoInfo); the difference against BenchmarkSendMsg is
// what encoding SNDINFO costs.
func BenchmarkWrite(b *testing.B) {
	benchSend(b, func(c *Conn, p []byte) error {
		_, err := c.Write(p)
		return err
	})
}

// benchmarkEchoRoundTrip drives client and server, both net.Conn, through
// b.N request/reply round trips of size bytes each, after one warm-up
// round trip that also checks the payload survives the echo intact (v1
// benchmarkEchoRoundTrip).
func benchmarkEchoRoundTrip(b *testing.B, client, server net.Conn, size int) {
	b.Helper()
	deadline := time.Now().Add(10 * time.Minute)
	if err := client.SetDeadline(deadline); err != nil {
		b.Fatalf("client deadline: %v", err)
	}
	if err := server.SetDeadline(deadline); err != nil {
		b.Fatalf("server deadline: %v", err)
	}

	finished := make(chan struct{})
	go func() {
		defer close(finished)
		buf := make([]byte, size)
		for {
			if _, err := io.ReadFull(server, buf); err != nil {
				return
			}
			if _, err := server.Write(buf); err != nil {
				return
			}
		}
	}()
	b.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		<-finished
	})

	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}
	reply := make([]byte, size)
	if _, err := client.Write(payload); err != nil {
		b.Fatalf("warm-up write: %v", err)
	}
	if _, err := io.ReadFull(client, reply); err != nil {
		b.Fatalf("warm-up read: %v", err)
	}
	if !bytes.Equal(reply, payload) {
		b.Fatal("warm-up echo changed the payload")
	}

	b.SetBytes(int64(2 * size))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := client.Write(payload); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(client, reply); err != nil {
			b.Fatalf("read: %v", err)
		}
	}
}

// benchTCPPair is a connected TCP pair on loopback, the comparison point
// BenchmarkTransportEcho measures SCTP against.
func benchTCPPair(b *testing.B) (client, server net.Conn) {
	b.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("TCP listen: %v", err)
	}
	b.Cleanup(func() { _ = ln.Close() })

	type result struct {
		conn net.Conn
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		accepted <- result{conn, err}
	}()
	client, err = net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		b.Fatalf("TCP dial: %v", err)
	}
	b.Cleanup(func() { _ = client.Close() })
	r := <-accepted
	if r.err != nil {
		b.Fatalf("TCP accept: %v", r.err)
	}
	server = r.conn
	b.Cleanup(func() { _ = server.Close() })
	return client, server
}

// BenchmarkTransportEcho compares one request/reply round trip's latency
// and throughput over SCTP against TCP, at a few message sizes (v1
// BenchmarkTransportEcho): informational, since net.Conn's contract is
// the same read/write shape either way and nothing here asserts a
// relative bound.
func BenchmarkTransportEcho(b *testing.B) {
	for _, transport := range []struct {
		name string
		pair func(b *testing.B) (client, server net.Conn)
	}{
		{"SCTP", func(b *testing.B) (net.Conn, net.Conn) {
			return connPair(b, &Config{NoDelay: new(true)}, &Config{NoDelay: new(true)})
		}},
		{"TCP", benchTCPPair},
	} {
		b.Run(transport.name, func(b *testing.B) {
			for _, size := range []int{64, 512, 4096} {
				b.Run(fmt.Sprintf("bytes=%d", size), func(b *testing.B) {
					client, server := transport.pair(b)
					benchmarkEchoRoundTrip(b, client, server, size)
				})
			}
		})
	}
}

// BenchmarkConcurrentEcho spreads b.N request/reply round trips over a
// growing number of concurrently dialed peers against one listener, so
// ns/op stays "per round trip" however many peers are running at once
// (v1 BenchmarkConcurrentEcho).
func BenchmarkConcurrentEcho(b *testing.B) {
	for _, peers := range []int{1, 4, 16, 64} {
		b.Run(fmt.Sprintf("peers=%d", peers), func(b *testing.B) {
			l := mustListen(b, &Config{NoDelay: new(true)}, "sctp4", loopback4(0))
			var srvWG sync.WaitGroup
			srvWG.Add(1)
			go func() {
				defer srvWG.Done()
				for {
					c, err := l.AcceptSCTP()
					if err != nil {
						return
					}
					srvWG.Add(1)
					go func(c *Conn) {
						defer srvWG.Done()
						defer func() { _ = c.Close() }()
						buf := make([]byte, 4096)
						for {
							n, err := c.Read(buf)
							if err != nil {
								return
							}
							if _, err := c.Write(buf[:n]); err != nil {
								return
							}
						}
					}(c)
				}
			}()
			raddr := listenerAddr(b, l)

			conns := make([]*Conn, 0, peers)
			for i := range peers {
				c, err := (&Config{NoDelay: new(true)}).Dial(testContext(b, 5*time.Minute), "sctp4", nil, raddr)
				if err != nil {
					b.Fatalf("dial %d: %v", i, err)
				}
				conns = append(conns, c)
			}
			b.Cleanup(func() {
				for _, c := range conns {
					_ = c.Close()
				}
				_ = l.Close()
				srvWG.Wait()
			})

			each := b.N / peers
			if each == 0 {
				each = 1
			}
			payload := make([]byte, 512)

			b.ReportAllocs()
			b.ResetTimer()
			var wg sync.WaitGroup
			for _, c := range conns {
				wg.Add(1)
				go func(c *Conn) {
					defer wg.Done()
					buf := make([]byte, 4096)
					for range each {
						if _, err := c.Write(payload); err != nil {
							return
						}
						if _, err := c.Read(buf); err != nil {
							return
						}
					}
				}(c)
			}
			wg.Wait()
			b.StopTimer()
		})
	}
}
