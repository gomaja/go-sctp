// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A connection-wide EOR flag cannot identify which I-DATA stream was cut.
func TestRecvInterleavedPartialDelivery(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, subscribed := range []bool{false, true} {
			for _, handled := range []bool{false, true} {
				for _, bComplete := range []bool{false, true} {
					t.Run(fmt.Sprintf("raw=%t/subscribed=%t/handler=%t/B-complete=%t", raw, subscribed, handled, bComplete), func(t *testing.T) {
						var received []*PartialDelivery
						var handler NotificationHandler
						if handled {
							handler = func(n Notification) error { received = append(received, n.(*PartialDelivery)); return nil }
						}
						var subs []EventType
						if subscribed {
							subs = []EventType{EventPartialDelivery}
						}
						c := scriptConn(t, handler, subs...)
						c.recv.interleaved = true
						pd := notif(EventPartialDelivery, sizePDAPIEvent)
						binary.NativeEndian.PutUint32(pd[pdapiEventStreamOff:], 1)
						binary.NativeEndian.PutUint32(pd[pdapiEventSeqOff:], 17)
						flags := int32(0)
						if bComplete {
							flags = msgEOR
						}
						script := &recvScript{steps: []recvStep{
							{data: []byte("A-prefix"), rcv: &RcvInfo{Stream: 1}},
							{data: []byte("B-piece"), rcv: &RcvInfo{Stream: 2}, flags: flags},
							{data: pd, flags: msgNotification | msgEOR},
							{data: []byte("after"), rcv: &RcvInfo{Stream: 3}, flags: msgEOR},
						}}
						hookRecvmsg(t, script.recvmsg)
						buf := make([]byte, 64)
						read := func() (int, MsgInfo, error) {
							if raw {
								return c.RecvMsg(buf)
							}
							n, e := c.Read(buf)
							return n, MsgInfo{}, e
						}
						for _, want := range []string{"A-prefix", "B-piece"} {
							n, _, err := read()
							if string(buf[:n]) != want || err != nil {
								t.Fatalf("piece=%q err=%v", buf[:n], err)
							}
						}
						n, info, err := read()
						if raw && subscribed && !handled {
							if err != nil || !info.Notification || !info.EOR {
								t.Fatalf("notification: %+v %v", info, err)
							}
							note, e := ParseNotification(buf[:n])
							if e != nil {
								t.Fatal(e)
							}
							received = append(received, note.(*PartialDelivery))
							n, info, err = read()
						}
						if string(buf[:n]) != "after" || err != nil || info.Notification {
							t.Fatalf("following=%q info=%+v err=%v", buf[:n], info, err)
						}
						wantNotes := 0
						if subscribed && (raw || handled) {
							wantNotes = 1
						}
						if len(received) != wantNotes {
							t.Fatalf("records=%d, want %d", len(received), wantNotes)
						}
						if wantNotes == 1 && (received[0].Stream != 1 || received[0].SeqNum != 17) {
							t.Fatalf("cut identity=%+v", received[0])
						}
					})
				}
			}
		}
	}
}

func TestReadMsgEndedInterleaving(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			if enabled && readSysctl(t, "intl_enable") != "1" {
				t.Skip("I-DATA requires the other sysctl state")
			}
			cfg := &Config{MessageInterleaving: enabled, FragmentInterleave: new(InterleaveAssocs)}
			l := mustListen(t, cfg, "sctp4", loopback4(0))
			addr := listenerAddr(t, l)
			peer, err := cfg.Dial(testContext(t, 5*time.Second), "sctp4", nil, addr)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = peer.Abort() })
			if _, err := peer.Write([]byte("queued")); err != nil {
				t.Fatal(err)
			}
			if err := peer.Close(); err != nil {
				t.Fatal(err)
			}
			waitAssocClosed(t, addr.Port)
			c, err := l.AcceptSCTP()
			if err != nil {
				t.Fatal(err)
			}
			accepted := c
			t.Cleanup(func() { _ = accepted.Abort() })
			if c.AssocID() != 0 {
				t.Fatalf("association still live: %d", c.AssocID())
			}
			got, queryErr := c.InterleavingSupported()
			t.Logf("ended accepted socket: requested=%t getter=%t err=%v", enabled, got, queryErr)
			// An ended accepted socket need not retain the listener's default.
			// Set the socket default explicitly before another Conn is built.
			var fd int
			rawFd(t, mustSyscallConn(t, c), func(src int) {
				var e error
				fd, e = syscall.Dup(src)
				if e != nil {
					t.Fatal(e)
				}
			})
			sock, e := wrapSocketFile(fd, afInet, "sctp4")
			if e != nil {
				t.Fatal(e)
			}
			if e := sock.control(func(fd int) error {
				level := InterleaveNone
				if enabled {
					level = InterleaveAssocs
				}
				// InterleaveNone disables I-DATA without its privileged
				// capability setter, which requires intl_enable even for 0.
				if e := setIntOpt(fd, ipprotoSCTP, optFragmentInterleave, int32(level)); e != nil {
					return e
				}
				if enabled {
					return setAssocValue(fd, optInterleavingSupported, 1)
				}
				return nil
			}); e != nil {
				_ = sock.file.Close()
				t.Fatal(e)
			}
			c, e = newConn(sock, kindDialed, &prepared{})
			if e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() { _ = c.Abort() })
			setReadDeadline(t, c, time.Second)
			b, _, err := c.ReadMsg(64)
			if !enabled {
				if string(b) != "queued" || err != nil {
					t.Fatalf("DATA=%q %v", b, err)
				}
				return
			}
			wantReadError(t, err, ErrUnsupported)
			if b != nil {
				t.Fatalf("refusal consumed %q", b)
			}
			buf := make([]byte, 64)
			n, info, err := c.RecvMsg(buf)
			if string(buf[:n]) != "queued" || !info.EOR || err != nil {
				t.Fatalf("queued=%q %+v %v", buf[:n], info, err)
			}
		})
	}
}

// recvInitRawConn injects a single Control error after the option hook
// identifies the capability query, leaving all other calls real.
type recvInitRawConn struct {
	syscall.RawConn
	fail bool
}

func (r *recvInitRawConn) Control(fn func(uintptr)) error {
	if r.fail {
		r.fail = false
		return syscall.EIO
	}
	return r.RawConn.Control(fn)
}

func TestConnInitInterleavingQuery(t *testing.T) {
	for _, ended := range []bool{false, true} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("ended=%t/query-fails=%t", ended, fail), func(t *testing.T) {
				client, server := connPair(t, nil, nil)
				if ended {
					if err := client.Close(); err != nil {
						t.Fatal(err)
					}
					waitAssocClosed(t, server.LocalAddr().(*Addr).Port)
				}
				var fd int
				rawFd(t, mustSyscallConn(t, server), func(src int) {
					var err error
					fd, err = syscall.Dup(src)
					if err != nil {
						t.Fatal(err)
					}
				})
				sock, err := wrapSocketFile(fd, afInet, "sctp4")
				if err != nil {
					t.Fatal(err)
				}
				raw := &recvInitRawConn{RawConn: sock.raw}
				sock.raw = raw
				queries, statuses := 0, 0
				hook := func(opt int) {
					if opt == optInterleavingSupported {
						queries++
						raw.fail = fail
					}
					if opt == optStatus {
						statuses++
					}
				}
				testHookSockopt.Store(&hook)
				t.Cleanup(func() { testHookSockopt.Store(nil) })
				c, err := newConn(sock, kindDialed, &prepared{})
				if c != nil {
					t.Cleanup(func() { _ = c.Abort() })
				}
				if queries != 1 || statuses != 1 {
					t.Fatalf("query count=%d status count=%d, want one each", queries, statuses)
				}
				if fail && !ended {
					if c != nil || !errors.Is(err, net.ErrClosed) {
						t.Fatalf("live query failure: c=%v err=%v", c, err)
					}
					return
				}
				if err != nil || c == nil {
					t.Fatalf("constructor: c=%v err=%v", c, err)
				}
			})
		}
	}
}

func receiveDoc(t *testing.T, file, name string) string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	if name == "" {
		return strings.Join(strings.Fields(f.Doc.Text()), " ")
	}
	var text string
	ast.Inspect(f, func(n ast.Node) bool {
		v, ok := n.(*ast.ValueSpec)
		if ok {
			for _, id := range v.Names {
				if id.Name == name {
					text = v.Doc.Text()
				}
			}
		}
		return true
	})
	if text == "" {
		t.Fatalf("missing documentation for %s", name)
	}
	return strings.Join(strings.Fields(text), " ")
}

func TestReceiveEndpointDocumentation(t *testing.T) {
	text := receiveDoc(t, "doc.go", "")
	if !strings.Contains(text, "an Endpoint always delivers [EventAssocChange]") || !strings.Contains(text, "[EventPartialDelivery] only when subscribed") {
		t.Fatal("notification documentation must distinguish unconditional association changes from subscribed partial-delivery records")
	}
}

func TestReceiveControlTruncatedDocumentation(t *testing.T) {
	text := receiveDoc(t, "errors.go", "ErrControlTruncated")
	if !strings.Contains(text, "metadata the package parsed may be incomplete or absent") {
		t.Fatal("control truncation documentation must allow unrelated ancillary data to have been truncated")
	}
}
