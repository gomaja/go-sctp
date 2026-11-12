// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"syscall"
	"testing"
)

func TestDiagRequest(t *testing.T) {
	for _, tc := range []struct {
		name, local, peer string
		family            byte
	}{
		{"IPv4", "192.0.2.1:4660", "192.0.2.2:22136", 2},
		{"mapped", "[::ffff:192.0.2.1]:4660", "[::ffff:192.0.2.2]:22136", 2},
		{"IPv6", "[2001:db8::1]:4660", "[2001:db8::2]:22136", 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := diagSelector{local: netip.MustParseAddrPort(tc.local), peer: netip.MustParseAddrPort(tc.peer), cookie: 0x0123456789abcdef, ifindex: 0x12345678}
			b := s.request(7, false)
			if len(b) != 72 || binary.NativeEndian.Uint32(b) != 72 || binary.NativeEndian.Uint16(b[4:]) != 20 || binary.NativeEndian.Uint16(b[6:]) != 1 || binary.NativeEndian.Uint32(b[8:]) != 7 {
				t.Fatalf("header: %x", b)
			}
			p := b[16:]
			if p[0] != tc.family || p[1] != 132 || p[2] != 2 || p[3] != 0 || binary.NativeEndian.Uint32(p[4:]) != 0xffffffff {
				t.Fatalf("request: %x", p)
			}
			if string(p[8:12]) != "\x12\x34\x56\x78" {
				t.Fatalf("ports: %x", p[8:12])
			}
			for _, a := range []struct {
				off int
				ip  netip.Addr
			}{{12, s.local.Addr().Unmap()}, {28, s.peer.Addr().Unmap()}} {
				var want [16]byte
				copy(want[:], a.ip.AsSlice())
				if string(p[a.off:a.off+16]) != string(want[:]) {
					t.Fatalf("address: %x want %x", p[a.off:a.off+16], want)
				}
			}
			if binary.NativeEndian.Uint32(p[44:]) != s.ifindex || binary.NativeEndian.Uint32(p[48:]) != 0x89abcdef || binary.NativeEndian.Uint32(p[52:]) != 0x01234567 {
				t.Fatalf("identity: %x", p[44:])
			}
			probe := s.request(8, true)
			if binary.NativeEndian.Uint16(probe[6:]) != 0x301 || binary.NativeEndian.Uint32(probe[20:]) != 0 {
				t.Fatalf("probe: %x", probe)
			}
		})
	}
}

func diagTestMessage(typ uint16, payload []byte) []byte {
	b := make([]byte, (16+len(payload)+3)&^3)
	binary.NativeEndian.PutUint32(b, uint32(16+len(payload)))
	binary.NativeEndian.PutUint16(b[4:], typ)
	binary.NativeEndian.PutUint32(b[8:], 7)
	copy(b[16:], payload)
	return b
}

func diagTestReply() []byte {
	b := make([]byte, 72+4+368)
	b[0] = 10 // The reply's family need not be the lookup family.
	binary.NativeEndian.PutUint32(b[44:], 0x89abcdef)
	binary.NativeEndian.PutUint32(b[48:], 0x01234567)
	binary.NativeEndian.PutUint32(b[56:], 4321)
	binary.NativeEndian.PutUint32(b[60:], 8765)
	binary.NativeEndian.PutUint16(b[72:], 372)
	binary.NativeEndian.PutUint16(b[74:], 2)
	binary.NativeEndian.PutUint32(b[76+28:], 24)
	binary.NativeEndian.PutUint32(b[76+32:], 99)
	binary.NativeEndian.PutUint32(b[76+336:], 4096)
	return diagTestMessage(20, b)
}

func TestDiagReply(t *testing.T) {
	const cookie = 0x0123456789abcdef
	valid := diagTestReply()
	for _, tc := range []struct {
		name   string
		change func([]byte) []byte
		ok     bool
	}{
		{"valid", func(b []byte) []byte { return b }, true},
		{"wrong sequence", func(b []byte) []byte { b[8]++; return b }, false},
		{"wrong type", func(b []byte) []byte { binary.NativeEndian.PutUint16(b[4:], 19); return b }, false},
		{"short header", func(b []byte) []byte { return b[:15] }, false},
		{"short message", func(b []byte) []byte { return b[:len(b)-1] }, false},
		{"short base", func(b []byte) []byte { return diagTestMessage(20, b[16:16+71]) }, false},
		{"no INFO", func(b []byte) []byte { return diagTestMessage(20, b[16:16+72]) }, false},
		{"short INFO", func(b []byte) []byte {
			binary.NativeEndian.PutUint16(b[88:], 4+339)
			return diagTestMessage(20, b[16:16+72+4+339])
		}, false},
		{"minimum INFO", func(b []byte) []byte {
			binary.NativeEndian.PutUint16(b[88:], 4+340)
			return diagTestMessage(20, b[16:16+72+4+340])
		}, true},
		{"cookie mismatch", func(b []byte) []byte { b[16+44]++; return b }, false},
		{"attribute short header", func(b []byte) []byte { return diagTestMessage(20, append(b[16:88], 1, 2)) }, false},
		{"attribute short length", func(b []byte) []byte { binary.NativeEndian.PutUint16(b[88:], 3); return b }, false},
		{"PAD and unknown", func(b []byte) []byte {
			p := append([]byte{}, b[16:88]...)
			attrs := make([]byte, 12)
			binary.NativeEndian.PutUint16(attrs, 4)
			binary.NativeEndian.PutUint16(attrs[2:], 14)
			binary.NativeEndian.PutUint16(attrs[4:], 5)
			binary.NativeEndian.PutUint16(attrs[6:], 99)
			p = append(p, attrs...)
			return diagTestMessage(20, append(p, b[88:]...))
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q, done, err := parseDiagReply(tc.change(append([]byte{}, valid...)), 7, cookie, false)
			if !tc.ok {
				if err == nil {
					t.Fatal("accepted malformed reply")
				}
				return
			}
			if err != nil || !done || q == nil || *q != (AssocQueues{SendCharged: 8765, RecvCharged: 4321, Unsent: 24, PrimaryInFlight: 4096}) {
				t.Fatalf("got %+v, done %v, err %v", q, done, err)
			}
		})
	}
	for _, errno := range []syscall.Errno{syscall.ENOENT, syscall.ESTALE, syscall.EINVAL, syscall.EPERM, syscall.EOPNOTSUPP} {
		p := make([]byte, 4)
		binary.NativeEndian.PutUint32(p, uint32(-int32(errno)))
		_, _, err := parseDiagReply(diagTestMessage(2, p), 7, cookie, false)
		if !errors.Is(err, errno) {
			t.Errorf("errno %v: %v", errno, err)
		}
	}
}

func TestDiagAvailability(t *testing.T) {
	for _, tc := range []struct {
		name        string
		typ         uint16
		errno       syscall.Errno
		unsupported bool
	}{
		{"unavailable DONE", 3, syscall.ENOENT, true}, {"available DONE", 3, 0, false}, {"unavailable ERROR", 2, syscall.ENOENT, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			exchange := func(req []byte, probe bool) (*AssocQueues, error) {
				calls++
				if !probe {
					return nil, syscall.ENOENT
				}
				p := make([]byte, 4)
				binary.NativeEndian.PutUint32(p, uint32(-int32(tc.errno)))
				b := diagTestMessage(tc.typ, p)
				copy(b[8:12], req[8:12])
				q, _, err := parseDiagReply(b, 2, 0, true)
				return q, err
			}
			_, err := queryDiag(diagSelector{}, exchange)
			if calls != 2 || errors.Is(err, ErrUnsupported) != tc.unsupported || (!tc.unsupported && !errors.Is(err, syscall.ENOENT)) {
				t.Fatalf("calls %d error %v", calls, err)
			}
			if tc.unsupported && !strings.Contains(err.Error(), "sctp_diag") {
				t.Fatal(err)
			}
		})
	}
}

func TestSendBacklogMeminfo(t *testing.T) {
	b := make([]byte, 36)
	binary.NativeEndian.PutUint32(b[8:], 777)
	binary.NativeEndian.PutUint32(b[12:], 212992)
	binary.NativeEndian.PutUint32(b[20:], 217600)
	for _, n := range []int{0, 20, 23, 24, 36, 37} {
		v, err := decodeSendBacklog(b, n)
		if n < 24 || n > 36 {
			if err == nil {
				t.Errorf("length %d accepted", n)
			}
			continue
		}
		if err != nil || v.Charged != 217600 || v.Limit != 212992 {
			t.Errorf("length %d: %+v %v", n, v, err)
		}
	}
}

func TestDiagProbeSkipsEntries(t *testing.T) {
	b := diagTestReply()
	q, done, err := parseDiagReply(b, 7, 0, true)
	if err != nil || done || q != nil {
		t.Fatalf("entry before DONE = %+v, %v, %v", q, done, err)
	}
	b = append(b, diagTestMessage(3, make([]byte, 4))...)
	q, done, err = parseDiagReply(b, 7, 0, true)
	if err != nil || !done || q != nil {
		t.Fatalf("entries and DONE = %+v, %v, %v", q, done, err)
	}
}

func TestDiagOnlyProbesENOENT(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.ESTALE, syscall.EINVAL, syscall.EPERM} {
		calls := 0
		_, err := queryDiag(diagSelector{}, func([]byte, bool) (*AssocQueues, error) {
			calls++
			return nil, errno
		})
		if calls != 1 || !errors.Is(err, errno) || errors.Is(err, ErrUnsupported) {
			t.Errorf("errno %v: %d calls, error %v", errno, calls, err)
		}
	}
}

func FuzzDiagReply(f *testing.F) {
	f.Add(diagTestReply())
	f.Add([]byte{})
	f.Add(diagTestMessage(2, []byte{254, 255, 255, 255}))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = parseDiagReply(b, 7, 0x0123456789abcdef, false)
		_, _, _ = parseDiagReply(b, 7, 0, true)
	})
}
