// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

const backlogWait = 30 * time.Second

// backlogPair covers sockets created by Dial, Accept and PeelOff. The
// wildcard case keeps an IPv4 association on a dual-stack IPv6 socket.
func backlogPair(t *testing.T, kind, network string) (sender, peer *Conn) {
	t.Helper()
	cfg := &Config{
		ReadBuffer: new(closingReadBuffer), WriteBuffer: new(1 << 20), NoDelay: new(true),
		Notifications: []EventType{EventAssocChange},
	}
	var local *Addr
	remoteIP := netip.MustParseAddr("127.0.0.1")
	switch network {
	case "sctp4":
		local = loopback4(0)
	case "sctp6":
		remoteIP = netip.IPv6Loopback()
		local = &Addr{IPs: []netip.Addr{remoteIP}}
	}
	var remote *Addr
	var listener *Listener
	var endpoint *Endpoint
	if kind == "peeled" {
		endpoint = listenEndpoint(t, cfg, network, local)
		remote = &Addr{IPs: []netip.Addr{remoteIP}, Port: endpointAddr(t, endpoint).Port}
	} else {
		listener = mustListen(t, cfg, network, local)
		if err := listener.SetDeadline(time.Now().Add(backlogWait)); err != nil {
			t.Fatalf("listener SetDeadline: %v", err)
		}
		remote = &Addr{IPs: []netip.Addr{remoteIP}, Port: listenerAddr(t, listener).Port}
	}
	client, err := cfg.Dial(testContext(t, backlogWait), network, local, remote)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Abort() })
	var server *Conn
	if endpoint != nil {
		id := awaitCommUp(t, endpoint).AssocID
		server, err = endpoint.PeelOff(id)
	} else {
		server, err = listener.AcceptSCTP()
	}
	if err != nil {
		t.Fatalf("accept or peel: %v", err)
	}
	t.Cleanup(func() { _ = server.Abort() })
	backlogCommUp(t, client)
	if endpoint == nil {
		backlogCommUp(t, server)
	}
	if kind == "dialed" {
		sender, peer = client, server
	} else {
		sender, peer = server, client
	}
	wantFamily := afInet
	if network != "sctp4" {
		wantFamily = afInet6
	}
	if sender.sock.family != wantFamily {
		t.Fatalf("sender socket family = %d, want %d", sender.sock.family, wantFamily)
	}
	return sender, peer
}

// Consume establishment notifications before asserting receive charges:
// their queued storage belongs to the association too.
func backlogCommUp(t *testing.T, c *Conn) {
	t.Helper()
	setReadDeadline(t, c, backlogWait)
	buf := make([]byte, 1<<16)
	n, info, err := c.RecvMsg(buf)
	if err != nil || !info.Notification || !info.EOR {
		t.Fatalf("establishment RecvMsg = %d, %+v, %v", n, info, err)
	}
	note, err := ParseNotification(buf[:n])
	if err != nil {
		t.Fatalf("ParseNotification: %v", err)
	}
	if change, ok := note.(*AssocChange); !ok || change.State != AssocCommUp {
		t.Fatalf("establishment notification = %+v, want AssocCommUp", note)
	}
	if err := c.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear read deadline: %v", err)
	}
}

// backlogPoll waits on state, rather than an assumed scheduling delay.
func backlogPoll(t *testing.T, what string, ready func() (bool, string)) {
	t.Helper()
	deadline := time.Now().Add(backlogWait)
	for {
		ok, state := ready()
		if ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("waiting for %s: %s", what, state)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A full buffer remains full once the peer has announced a zero window
// and the sender has processed that SACK. Use the queue tests' longer
// polling budget for emulated kernels and busy test hosts.
func backlogClosedWindow(t *testing.T, receiver *Conn, sacksIn func() uint64) {
	t.Helper()
	backlogPoll(t, "acknowledged zero receive window", func() (bool, string) {
		info, err := receiver.AssocInfo()
		if err != nil {
			t.Fatalf("receiver AssocInfo: %v", err)
		}
		stats, err := receiver.Stats()
		if err != nil {
			t.Fatalf("receiver Stats: %v", err)
		}
		in := sacksIn()
		return info.LocalRwnd == 0 && in >= stats.SACKsOut,
			fmt.Sprintf("receive window=%d SACKs received=%d sent=%d", info.LocalRwnd, in, stats.SACKsOut)
	})
}

func backlogDrain(t *testing.T, peer *Conn, payload []byte, messages int) {
	t.Helper()
	setReadDeadline(t, peer, backlogWait)
	buf := make([]byte, len(payload))
	for i := range messages {
		n, err := peer.Read(buf)
		if err != nil || n != len(payload) || !bytes.Equal(buf[:n], payload) {
			t.Fatalf("drain message %d/%d = %d bytes, %v; want %d matching bytes", i+1, messages, n, err, len(payload))
		}
	}
}

func backlogConnEmpty(t *testing.T, c *Conn) {
	t.Helper()
	backlogPoll(t, "empty connection queues", func() (bool, string) {
		socket, err := c.SendBacklog()
		if err != nil {
			t.Fatalf("SendBacklog: %v", err)
		}
		assoc, err := c.AssocQueues()
		if err != nil {
			t.Fatalf("AssocQueues: %v", err)
		}
		return socket.Charged == 0 && *assoc == (AssocQueues{}), fmt.Sprintf("socket=%+v association=%+v", socket, assoc)
	})
}

func TestConnSendBacklogAndAssocQueues(t *testing.T) {
	for _, network := range []string{"sctp4", "sctp", "sctp6"} {
		for _, kind := range []string{"dialed", "accepted", "peeled"} {
			t.Run(network+"/"+kind, func(t *testing.T) {
				sender, peer := backlogPair(t, kind, network)
				backlogConnEmpty(t, sender)
				payload := fill(4096)
				messages := fillSendBuffer(t, sender, payload)
				backlogClosedWindow(t, peer, func() uint64 {
					stats, err := sender.Stats()
					if err != nil {
						t.Fatalf("sender Stats: %v", err)
					}
					return stats.SACKsIn
				})
				messages += fillSendBuffer(t, sender, payload)
				if err := sender.SetWriteDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
					t.Fatalf("SetWriteDeadline: %v", err)
				}
				for {
					n, err := sender.Write(payload)
					if err != nil {
						if n != 0 {
							t.Fatalf("timed-out Write returned %d bytes", n)
						}
						wantOp(t, "stalled Write", "write", err, os.ErrDeadlineExceeded)
						break
					}
					if n != len(payload) {
						t.Fatalf("Write = %d, want %d", n, len(payload))
					}
					messages++
				}
				limit, err := sender.WriteBuffer()
				if err != nil {
					t.Fatalf("WriteBuffer: %v", err)
				}
				backlogPoll(t, "charged stalled sender", func() (bool, string) {
					socket, err := sender.SendBacklog()
					if err != nil {
						t.Fatalf("SendBacklog: %v", err)
					}
					assoc, err := sender.AssocQueues()
					if err != nil {
						t.Fatalf("AssocQueues: %v", err)
					}
					if socket.Limit != limit {
						t.Fatalf("SendBacklog limit = %d, WriteBuffer = %d", socket.Limit, limit)
					}
					return socket.Charged >= limit && assoc.SendCharged == socket.Charged && assoc.Unsent >= 1 && assoc.PrimaryInFlight > 0,
						fmt.Sprintf("socket=%+v association=%+v", socket, assoc)
				})
				peerQueues, err := peer.AssocQueues()
				if err != nil || peerQueues == nil || peerQueues.RecvCharged <= 0 {
					t.Fatalf("stalled peer AssocQueues = %+v, %v; want receive charge", peerQueues, err)
				}
				if err := sender.SetWriteDeadline(time.Time{}); err != nil {
					t.Fatalf("clear write deadline: %v", err)
				}
				backlogDrain(t, peer, payload, messages)
				backlogConnEmpty(t, sender)
				backlogConnEmpty(t, peer)
			})
		}
	}
}

func TestEndpointSendBacklogAndAssocQueues(t *testing.T) {
	e := openEndpoint(t, &Config{WriteBuffer: new(1 << 20), NoDelay: new(true)}, "sctp4", loopback4(0))
	connect := func() (AssocID, *Conn) {
		l := mustListen(t, &Config{ReadBuffer: new(closingReadBuffer), Notifications: []EventType{EventAssocChange}}, "sctp4", loopback4(0))
		if err := l.SetDeadline(time.Now().Add(backlogWait)); err != nil {
			t.Fatalf("listener SetDeadline: %v", err)
		}
		id, err := e.Connect(listenerAddr(t, l))
		if err != nil {
			t.Fatalf("Connect: %v", err)
		}
		peer, err := l.AcceptSCTP()
		if err != nil {
			t.Fatalf("AcceptSCTP: %v", err)
		}
		t.Cleanup(func() { _ = peer.Abort() })
		if up := awaitCommUp(t, e); up.AssocID != id {
			t.Fatalf("AssocCommUp id = %d, Connect id = %d", up.AssocID, id)
		}
		backlogCommUp(t, peer)
		return id, peer
	}
	stalledID, peer := connect()
	idleID, idlePeer := connect()
	payload := fill(4096)
	messages := fillEndpoint(t, e, []AssocID{stalledID}, payload)[stalledID]
	backlogClosedWindow(t, peer, func() uint64 { return endpointStats(t, e, stalledID).SACKsIn })
	messages += fillEndpoint(t, e, []AssocID{stalledID}, payload)[stalledID]
	if err := e.SetWriteDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	for {
		n, err := e.SendMsg(stalledID, payload, SendOptions{})
		if err != nil {
			if n != 0 {
				t.Fatalf("timed-out SendMsg returned %d bytes", n)
			}
			wantOp(t, "stalled SendMsg", "write", err, os.ErrDeadlineExceeded)
			break
		}
		if n != len(payload) {
			t.Fatalf("SendMsg = %d, want %d", n, len(payload))
		}
		messages++
	}
	var limit int
	var optionErr error
	if err := mustEndpointRawConn(t, e).Control(func(fd uintptr) {
		limit, optionErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if optionErr != nil {
		t.Fatalf("SO_SNDBUF: %v", optionErr)
	}
	backlogPoll(t, "endpoint association accounting", func() (bool, string) {
		socket, err := e.SendBacklog()
		if err != nil {
			t.Fatalf("SendBacklog: %v", err)
		}
		stalled, err := e.AssocQueues(stalledID)
		if err != nil {
			t.Fatalf("stalled AssocQueues: %v", err)
		}
		idle, err := e.AssocQueues(idleID)
		if err != nil {
			t.Fatalf("idle AssocQueues: %v", err)
		}
		if socket.Limit != limit {
			t.Fatalf("SendBacklog limit = %d, SO_SNDBUF = %d", socket.Limit, limit)
		}
		return socket.Charged >= limit && idle.SendCharged == 0 && idle.Unsent == 0 && idle.PrimaryInFlight == 0 &&
				stalled.SendCharged > 0 && socket.Charged == stalled.SendCharged+idle.SendCharged && stalled.Unsent >= 1 && stalled.PrimaryInFlight > 0,
			fmt.Sprintf("socket=%+v stalled=%+v idle=%+v", socket, stalled, idle)
	})
	if err := e.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatalf("clear write deadline: %v", err)
	}
	backlogDrain(t, peer, payload, messages)
	backlogPoll(t, "empty endpoint queues", func() (bool, string) {
		socket, err := e.SendBacklog()
		if err != nil {
			t.Fatalf("SendBacklog: %v", err)
		}
		stalled, err := e.AssocQueues(stalledID)
		if err != nil {
			t.Fatalf("stalled AssocQueues: %v", err)
		}
		idle, err := e.AssocQueues(idleID)
		if err != nil {
			t.Fatalf("idle AssocQueues: %v", err)
		}
		return socket.Charged == 0 && *stalled == (AssocQueues{}) && *idle == (AssocQueues{}),
			fmt.Sprintf("socket=%+v stalled=%+v idle=%+v", socket, stalled, idle)
	})
	backlogConnEmpty(t, peer)
	backlogConnEmpty(t, idlePeer)
}

func TestEndpointAssocQueuesInvalidID(t *testing.T) {
	e := openEndpoint(t, nil, "sctp4", loopback4(0))
	for _, id := range []AssocID{-1, 0, 1, 2} {
		t.Run(fmt.Sprint(id), func(t *testing.T) {
			queues, err := e.AssocQueues(id)
			if queues != nil {
				t.Errorf("AssocQueues(%d) = %+v, want nil", id, queues)
			}
			wantOp(t, "AssocQueues reserved id", "get", err, syscall.EINVAL)
		})
	}
	queues, err := e.AssocQueues(AssocID(1<<31 - 1))
	if queues != nil {
		t.Errorf("AssocQueues(unknown) = %+v, want nil", queues)
	}
	wantOp(t, "AssocQueues unknown id", "get", err, syscall.EINVAL)
}

func TestConnBacklogAfterPeerAbort(t *testing.T) {
	for _, kind := range []string{"dialed", "accepted", "peeled"} {
		t.Run(kind, func(t *testing.T) {
			c, peer := backlogPair(t, kind, "sctp4")
			if err := peer.Abort(); err != nil {
				t.Fatalf("peer Abort: %v", err)
			}
			waitGone(t, c)
			queues, err := c.AssocQueues()
			if queues != nil || (!errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESTALE)) {
				t.Fatalf("AssocQueues after peer abort = %+v, %v; want nil and ENOENT or ESTALE", queues, err)
			}
			var opErr *net.OpError
			if !errors.As(err, &opErr) || opErr.Op != "get" {
				t.Fatalf("AssocQueues error = %v, want *net.OpError with Op get", err)
			}
			backlog, err := c.SendBacklog()
			if err != nil || backlog == nil || backlog.Charged != 0 || backlog.Limit <= 0 {
				t.Fatalf("SendBacklog after peer abort = %+v, %v; want zero charge and positive limit", backlog, err)
			}
		})
	}
}

func TestBacklogClosed(t *testing.T) {
	c, _ := connPair(t, nil, nil)
	if err := c.Abort(); err != nil {
		t.Fatalf("Conn Abort: %v", err)
	}
	e := openEndpoint(t, nil, "sctp4", loopback4(0))
	if err := e.Abort(); err != nil {
		t.Fatalf("Endpoint Abort: %v", err)
	}
	checks := []struct {
		name string
		call func() error
	}{
		{"Conn.SendBacklog", func() error { _, err := c.SendBacklog(); return err }},
		{"Conn.AssocQueues", func() error { _, err := c.AssocQueues(); return err }},
		{"Endpoint.SendBacklog", func() error { _, err := e.SendBacklog(); return err }},
		{"Endpoint.AssocQueues", func() error { _, err := e.AssocQueues(3); return err }},
		{"Endpoint.AssocQueues/reserved", func() error { _, err := e.AssocQueues(0); return err }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			wantOp(t, check.name, "get", check.call(), net.ErrClosed)
		})
	}
}
