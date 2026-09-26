// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp_test

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/gomaja/go-sctp"
)

// A Listener and a dialed Conn, used as net.Listener and net.Conn: each
// Write is one message, and the server echoes it.
func ExampleListen() {
	laddr, err := sctp.ResolveAddr("sctp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	ln, err := sctp.Listen("sctp4", laddr)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 1024)
		if n, err := conn.Read(buf); err == nil {
			_, _ = conn.Write(buf[:n])
		}
		_ = conn.Close()
	}()

	// Dial returns once the association is established. The context
	// bounds the setup; without one, a peer that never answers keeps it
	// waiting for as long as the kernel retransmits its INIT.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := sctp.Dial(ctx, "sctp4", nil, ln.Addr().(*sctp.Addr))
	if err != nil {
		log.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Fatal(err)
	}

	if _, err := conn.Write([]byte("hello")); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])

	// Close shuts the association down gracefully.
	if err := conn.Close(); err != nil {
		log.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		log.Fatal(err)
	}
	// Output: hello
}

// Messages with their stream and payload protocol identifier (PPID), and a
// NotificationHandler that receives the association's start. The server
// asks for four outgoing streams and echoes each message on the stream and
// with the PPID it arrived with.
func ExampleConn_SendMsg() {
	laddr, err := sctp.ResolveAddr("sctp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	server := &sctp.Config{
		InitMsg:       sctp.InitMsg{OutStreams: 4, MaxInStreams: 4},
		Notifications: []sctp.EventType{sctp.EventAssocChange},
		NotificationHandler: func(n sctp.Notification) error {
			if ac, ok := n.(*sctp.AssocChange); ok && ac.State == sctp.AssocCommUp {
				fmt.Println("server: association up,", ac.OutStreams, "outgoing streams")
			}
			return nil
		},
	}
	ln, err := server.Listen("sctp4", laddr)
	if err != nil {
		log.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.AcceptSCTP()
		if err != nil {
			return
		}
		// The handler runs inside this read, before the message returns.
		buf := make([]byte, 1024)
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err == nil {
			n, info, err := conn.RecvMsg(buf)
			if err == nil && info.EOR {
				fmt.Printf("server: %q on stream %d, PPID %d\n", buf[:n], info.Rcv.Stream, info.Rcv.PPID)
				reply := sctp.SendOptions{Info: &sctp.SndInfo{Stream: info.Rcv.Stream, PPID: info.Rcv.PPID}}
				_, _ = conn.SendMsg(buf[:n], reply)
			}
		}
		_ = conn.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := sctp.Dial(ctx, "sctp4", nil, ln.Addr().(*sctp.Addr))
	if err != nil {
		log.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Fatal(err)
	}

	opts := sctp.SendOptions{Info: &sctp.SndInfo{Stream: 2, PPID: 46}}
	if _, err := conn.SendMsg([]byte("request"), opts); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 1024)
	n, info, err := conn.RecvMsg(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("client: %q on stream %d, PPID %d\n", buf[:n], info.Rcv.Stream, info.Rcv.PPID)

	<-done
	if err := conn.Close(); err != nil {
		log.Fatal(err)
	}
	if err := ln.Close(); err != nil {
		log.Fatal(err)
	}
	// Output:
	// server: association up, 4 outgoing streams
	// server: "request" on stream 2, PPID 46
	// client: "request" on stream 2, PPID 46
}

// A one-to-many Endpoint learns of each association from an AssocChange
// notification, and PeelOff moves one association to a Conn of its own.
func ExampleEndpoint_PeelOff() {
	laddr, err := sctp.ResolveAddr("sctp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	ep, err := sctp.ListenEndpoint("sctp4", laddr)
	if err != nil {
		log.Fatal(err)
	}
	if err := ep.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := sctp.Dial(ctx, "sctp4", nil, ep.Addr().(*sctp.Addr))
	if err != nil {
		log.Fatal(err)
	}

	// Without a NotificationHandler, RecvMsg returns a notification's bytes
	// with MsgInfo.Notification set. An Endpoint always receives
	// EventAssocChange, which names every new association.
	var id sctp.AssocID
	buf := make([]byte, sctp.NotificationMaxSize)
	for id == 0 {
		n, info, err := ep.RecvMsg(buf)
		if err != nil {
			log.Fatal(err)
		}
		if !info.Notification {
			continue
		}
		note, err := sctp.ParseNotification(buf[:n])
		if err != nil {
			log.Fatal(err)
		}
		if ac, ok := note.(*sctp.AssocChange); ok && ac.State == sctp.AssocCommUp {
			fmt.Println("endpoint:", ac.State)
			id = ac.AssocID
		}
	}

	conn, err := ep.PeelOff(id)
	if err != nil {
		log.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		log.Fatal(err)
	}
	fmt.Println("peeled off the same association:", conn.AssocID() == id)

	if _, err := client.Write([]byte("hello")); err != nil {
		log.Fatal(err)
	}
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("peeled connection read %q\n", buf[:n])

	// The client's Close shuts the association down; the peeled Conn then
	// finds it gone, and the endpoint holds none.
	for _, c := range []interface{ Close() error }{client, conn, ep} {
		if err := c.Close(); err != nil {
			log.Fatal(err)
		}
	}
	// Output:
	// endpoint: AssocCommUp
	// peeled off the same association: true
	// peeled connection read "hello"
}
