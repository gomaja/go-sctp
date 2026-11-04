// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// RFC 6458 §6.1.7 places the abort record between the abandoned DATA
// message's pieces and later messages (RFC 3758 §3.6).
func TestReadMsgPartialDeliveryBoundary(t *testing.T) {
	for _, subscribed := range []bool{false, true} {
		for _, handled := range []bool{false, true} {
			t.Run(fmt.Sprintf("subscribed=%t/handler=%t", subscribed, handled), func(t *testing.T) {
				calls := 0
				var handler NotificationHandler
				if handled {
					handler = func(n Notification) error {
						if _, ok := n.(*PartialDelivery); !ok {
							t.Errorf("notification %T", n)
						}
						calls++
						return nil
					}
				}
				var subs []EventType
				if subscribed {
					subs = []EventType{EventPartialDelivery}
				}
				c := scriptConn(t, handler, subs...)
				first := RcvInfo{Stream: 3, PPID: 42, AssocID: 7}
				next := RcvInfo{Stream: 4, PPID: 43, AssocID: 7}
				script := &recvScript{steps: []recvStep{
					{data: []byte("prefix"), rcv: &first},
					{data: notif(EventPartialDelivery, sizePDAPIEvent), flags: msgNotification | msgEOR},
					{data: []byte("next"), rcv: &next, flags: msgEOR},
				}}
				hookRecvmsg(t, script.recvmsg)
				b, info, err := c.ReadMsg(64)
				wantReadError(t, err, ErrMessageInterrupted)
				if !errors.Is(err, errPartialDeliveryAborted) || string(b) != "prefix" || info != first || !c.opened() || script.step != 2 {
					t.Fatalf("prefix=%q info=%+v err=%v open=%t step=%d", b, info, err, c.opened(), script.step)
				}
				wantCalls := 0
				if subscribed && handled {
					wantCalls = 1
				}
				if calls != wantCalls {
					t.Fatalf("handler calls %d, want %d", calls, wantCalls)
				}
				b, info, err = c.ReadMsg(64)
				if string(b) != "next" || info != next || err != nil {
					t.Fatalf("following=%q %+v %v", b, info, err)
				}
			})
		}
	}
}

func TestReadPartialDeliveryBoundary(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, subscribed := range []bool{false, true} {
			for _, handled := range []bool{false, true} {
				for _, partial := range []bool{false, true} {
					t.Run(fmt.Sprintf("raw=%t/subscribed=%t/handler=%t/partial=%t", raw, subscribed, handled, partial), func(t *testing.T) {
						calls := 0
						var handler NotificationHandler
						if handled {
							handler = func(Notification) error { calls++; return nil }
						}
						var subs []EventType
						if subscribed {
							subs = []EventType{EventPartialDelivery}
						}
						c := scriptConn(t, handler, subs...)
						flags := int32(msgEOR)
						if partial {
							flags = 0
						}
						script := &recvScript{steps: []recvStep{
							{data: []byte("prefix"), flags: flags},
							{data: notif(EventPartialDelivery, sizePDAPIEvent), flags: msgNotification | msgEOR},
							{data: []byte("next"), flags: msgEOR},
							{data: []byte("last"), flags: msgEOR},
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
						n, _, err := read()
						if string(buf[:n]) != "prefix" || err != nil {
							t.Fatalf("prefix=%q %v", buf[:n], err)
						}
						delivered := subscribed && (raw || handled)
						// Read cannot deliver a record, even if a handler receives it.
						interrupted := partial && (!raw || !delivered)
						n, info, err := read()
						if interrupted {
							wantReadError(t, err, ErrMessageInterrupted)
							if n != 0 || !c.opened() || script.step != 2 {
								t.Fatalf("interruption n=%d open=%t step=%d", n, c.opened(), script.step)
							}
							n, info, err = read()
						} else if raw && subscribed && !handled {
							if !info.Notification || !info.EOR || n != sizePDAPIEvent || err != nil {
								t.Fatalf("record: n=%d info=%+v err=%v", n, info, err)
							}
							n, info, err = read()
						}
						if string(buf[:n]) != "next" || info.Notification || err != nil {
							t.Fatalf("next=%q %+v %v", buf[:n], info, err)
						}
						n, _, err = read()
						if string(buf[:n]) != "last" || err != nil {
							t.Fatalf("last=%q %v", buf[:n], err)
						}
						wantCalls := 0
						if subscribed && handled {
							wantCalls = 1
						}
						if calls != wantCalls {
							t.Fatalf("handler calls %d, want %d", calls, wantCalls)
						}
					})
				}
			}
		}
	}
}

func TestReadMsgControlTruncatedOnce(t *testing.T) {
	for _, first := range []bool{false, true} {
		for _, max := range []int{8, 2048} {
			t.Run(fmt.Sprintf("first=%t/max=%d", first, max), func(t *testing.T) {
				c := scriptConn(t, nil)
				steps := make([]recvStep, 1000)
				for i := range steps {
					steps[i] = recvStep{data: []byte{'a'}, flags: msgCtrunc}
					if i == 0 && !first {
						steps[i].flags = 0
					}
				}
				steps[len(steps)-1].flags |= msgEOR
				hookRecvmsg(t, (&recvScript{steps: steps}).recvmsg)
				b, _, err := c.ReadMsg(max)
				wantReadError(t, err, ErrControlTruncated)
				if strings.Count(err.Error(), ErrControlTruncated.Error()) != 1 || len(b) != min(max, 1000) || errors.Is(err, ErrMessageTooLong) != (max < 1000) {
					t.Fatalf("n=%d err=%v", len(b), err)
				}
			})
		}
	}
}

func TestReadMsgInterleavingRefused(t *testing.T) {

	level := InterleaveAssocs
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			if enabled && readSysctl(t, "intl_enable") != "1" {
				t.Skip("I-DATA requires net.sctp.intl_enable=1; covered in the other sysctl state")
			}
			cfg := &Config{MessageInterleaving: enabled, FragmentInterleave: &level}
			client, server := connPair(t, cfg, cfg)
			setReadDeadline(t, server, time.Second)
			if _, err := client.Write([]byte("queued")); err != nil {
				t.Fatal(err)
			}
			for _, max := range []int{-1, 0, 1, 64} {
				b, _, err := server.ReadMsg(max)
				if max <= 0 {
					wantReadError(t, err, syscall.EINVAL)
					continue
				}
				if enabled {
					wantReadError(t, err, ErrUnsupported)
					if b != nil || !strings.Contains(err.Error(), "I-DATA") || !strings.Contains(err.Error(), "RecvMsg") {
						t.Fatalf("%q %v", b, err)
					}
				} else {
					break
				}
			}
			if enabled {
				b := make([]byte, 64)
				n, info, err := server.RecvMsg(b)
				if string(b[:n]) != "queued" || !info.EOR || err != nil {
					t.Fatalf("queued=%q %+v %v", b[:n], info, err)
				}
			}
			if err := server.Abort(); err != nil {
				t.Fatal(err)
			}
			_, _, err := server.ReadMsg(1)
			wantReadError(t, err, net.ErrClosed)
		})
	}
}

// Internal records still receive dropRecord's framing verdict.
func TestReadPartialDeliveryFraming(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, declared := range []uint32{0, 7, 8, sizePDAPIEvent - 1, sizePDAPIEvent, sizePDAPIEvent + 1, NotificationReassemblyLimit + 1} {
			t.Run(fmt.Sprintf("raw=%t/length=%d", raw, declared), func(t *testing.T) {
				rec := notif(EventPartialDelivery, sizePDAPIEvent)
				binary.NativeEndian.PutUint32(rec[4:], declared)
				c := scriptConn(t, nil)
				script := &recvScript{steps: []recvStep{{data: rec, flags: msgNotification | msgEOR}, {data: []byte("next"), flags: msgEOR}}}
				hookRecvmsg(t, script.recvmsg)
				buf := make([]byte, 64)
				read := func() (int, error) {
					if raw {
						n, _, e := c.RecvMsg(buf)
						return n, e
					}
					return c.Read(buf)
				}
				n, err := read()
				if declared == sizePDAPIEvent {
					if !bytes.Equal(buf[:n], []byte("next")) || err != nil {
						t.Fatalf("%q %v", buf[:n], err)
					}
					return
				}
				target := ErrShortNotification
				if declared > NotificationReassemblyLimit {
					target = ErrNotificationTooLong
				}
				wantReadError(t, err, target)
				if n != 0 || script.step != 1 {
					t.Fatalf("n=%d step=%d", n, script.step)
				}
				n, err = read()
				if string(buf[:n]) != "next" || err != nil {
					t.Fatalf("following=%q %v", buf[:n], err)
				}
			})
		}
	}
}

// A read parked between DATA pieces, or in a cut notification, must
// normalize the local shutdown's EOF before joining interruption errors.
func TestReadMsgLocalAbortCause(t *testing.T) {
	for _, closing := range []bool{false, true} {
		for _, cutRecord := range []bool{false, true} {
			if closing && cutRecord {
				continue
			}
			t.Run(fmt.Sprintf("grace=%t/cut-record=%t", closing, cutRecord), func(t *testing.T) {
				client, server := connPair(t, nil, nil)
				if _, err := server.Write([]byte("prime")); err != nil {
					t.Fatal(err)
				}
				if b, _, err := client.ReadMsg(64); string(b) != "prime" || err != nil {
					t.Fatalf("prime=%q %v", b, err)
				}
				if closing {
					args := []string{"INPUT", "-p", "sctp", "--sport", fmt.Sprint(client.LocalAddr().(*Addr).Port), "-m", "sctp", "--chunk-types", "any", "SHUTDOWN", "-j", "DROP"}
					if out, err := exec.Command("iptables", append([]string{"-I"}, args...)...).CombinedOutput(); err != nil {
						t.Fatalf("drop: %v %s", err, out)
					}
					t.Cleanup(func() {
						if out, err := exec.Command("iptables", append([]string{"-D"}, args...)...).CombinedOutput(); err != nil {
							t.Errorf("restore: %v %s", err, out)
						}
					})
				}
				steps := []recvStep{{data: []byte("prefix")}}
				if cutRecord {
					steps = append(steps, recvStep{data: commUp(sizeAssocChange, 0)[:notificationHeaderSize], flags: msgNotification})
				}
				script := &recvScript{steps: steps}
				parked := make(chan struct{})
				once := sync.Once{}
				hookRecvmsg(t, func(fd int, msg *syscall.Msghdr, flags int) (int, error) {
					if script.step < len(script.steps) {
						return script.recvmsg(fd, msg, flags)
					}
					if cutRecord {
						once.Do(func() { close(parked) })
						for lifeState(client.life.state.Load()) == lifeOpen {
							time.Sleep(time.Millisecond)
						}
						msg.SetControllen(0)
						msg.Flags = 0
						return 0, nil
					}
					n, err := rawRecvmsg(fd, msg, flags)
					if err == syscall.EAGAIN {
						once.Do(func() { close(parked) })
					}
					return n, err
				})
				done := make(chan error, 1)
				go func() {
					b, _, err := client.ReadMsg(64)
					if string(b) != "prefix" {
						err = fmt.Errorf("prefix=%q: %w", b, err)
					}
					done <- err
				}()
				select {
				case <-parked:
				case <-time.After(3 * time.Second):
					t.Fatal("read did not park")
				}
				start := time.Now()
				if closing {
					if err := client.CloseWithTimeout(60 * time.Millisecond); err != nil {
						t.Fatal(err)
					}
					if time.Since(start) < 60*time.Millisecond {
						t.Fatal("Close did not reach its grace expiry")
					}
				} else {
					if err := client.Abort(); err != nil {
						t.Fatal(err)
					}
				}
				select {
				case err := <-done:
					wantReadError(t, err, ErrMessageInterrupted)
					if !errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
						t.Fatalf("local abort cause: %v", err)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("read did not wake")
				}
			})
		}
	}
}
