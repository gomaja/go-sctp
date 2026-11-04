// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// This file includes modifications by gomaja.

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gomaja/go-sctp"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	flag := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	server := flag.Bool("server", false, "run the echo server instead of the client")
	ips := flag.String("ip", "127.0.0.1", "comma-separated addresses: the server's to bind, the client's peer (server: empty for every address)")
	port := flag.Int("port", 0, "the server's port (server: 0 lets the kernel choose)")
	lport := flag.Int("lport", 0, "client only: the local port to bind (0 lets the kernel choose)")
	bufsize := flag.Int("bufsize", 256, "message size the client sends, and the largest the server echoes")
	sndbuf := flag.Int("sndbuf", 0, "socket send buffer size (SO_SNDBUF; 0 keeps the kernel default)")
	rcvbuf := flag.Int("rcvbuf", 0, "socket receive buffer size (SO_RCVBUF; 0 keeps the kernel default)")
	count := flag.Int("count", 0, "client only: messages to send before exiting (0 sends until interrupted)")
	interval := flag.Duration("interval", time.Second, "client only: pause between messages")
	if err := flag.Parse(os.Args[1:]); err != nil {
		return err
	}
	invalid := func(message string) error { flag.Usage(); return errors.New(message) }

	addrs, err := parseIPs(*ips)
	if err != nil {
		return err
	}
	if *port < 0 || *port > 65535 || *lport < 0 || *lport > 65535 {
		return invalid("ports must be within 0-65535")
	}
	if !*server && *port == 0 {
		return invalid("the client requires -port within 1-65535")
	}
	if *bufsize <= 0 {
		return invalid("-bufsize must be positive")
	}
	addr := &sctp.Addr{IPs: addrs, Port: uint16(*port)}
	cfg := newConfig(*sndbuf, *rcvbuf)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *server {
		err = runServer(ctx, cfg, addr, *bufsize)
	} else {
		var laddr *sctp.Addr
		if *lport != 0 {
			laddr = &sctp.Addr{Port: uint16(*lport)}
		}
		err = runClient(ctx, cfg, laddr, addr, *bufsize, *count, *interval, os.Stdout)
	}
	return err
}

// parseIPs parses the -ip flag: comma-separated IP addresses, none for an
// empty list.
func parseIPs(list string) ([]netip.Addr, error) {
	var ips []netip.Addr
	for _, s := range strings.Split(list, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		ip, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("-ip: %w", err)
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

// newConfig returns the Config both sides use. Socket buffer sizes are
// pre-association settings: Linux sets an association's receive window from
// the receive buffer when the association is created, so they go in the
// Config, before the socket connects or listens. A size of 0 leaves the
// field nil, which keeps the kernel's default.
func newConfig(sndbuf, rcvbuf int) *sctp.Config {
	cfg := &sctp.Config{
		// Offer ten streams each way; the association uses the smaller of
		// what each side offers.
		InitMsg:       sctp.InitMsg{OutStreams: 10, MaxInStreams: 10},
		NoDelay:       new(true),
		Notifications: []sctp.EventType{sctp.EventAssocChange, sctp.EventPeerAddrChange},
		NotificationHandler: func(n sctp.Notification) error {
			switch n := n.(type) {
			case *sctp.AssocChange:
				log.Printf("association %d: %v (%d out, %d in streams)", n.AssocID, n.State, n.OutStreams, n.InStreams)
			case *sctp.PeerAddrChange:
				log.Printf("association %d: path %v %v (%v)", n.AssocID, n.Addr, n.State, n.Reason)
			}
			return nil
		},
	}
	if sndbuf != 0 {
		cfg.WriteBuffer = new(sndbuf)
	}
	if rcvbuf != 0 {
		cfg.ReadBuffer = new(rcvbuf)
	}
	return cfg
}

// bufferReporter is the part of *sctp.Conn that bufferSizes reads.
type bufferReporter interface {
	WriteBuffer() (int, error)
	ReadBuffer() (int, error)
}

// bufferSizes reports the send and receive buffer sizes the socket ended up
// with. Linux doubles the size it is given, to allow for its own
// bookkeeping, and reports the doubled size.
func bufferSizes(c bufferReporter) (send, receive int, err error) {
	if send, err = c.WriteBuffer(); err != nil {
		return 0, 0, fmt.Errorf("send buffer: %w", err)
	}
	if receive, err = c.ReadBuffer(); err != nil {
		return 0, 0, fmt.Errorf("receive buffer: %w", err)
	}
	return send, receive, nil
}

// runServer listens on addr and echoes every association until ctx is
// done.
func runServer(ctx context.Context, cfg *sctp.Config, addr *sctp.Addr, bufsize int) (retErr error) {
	l, err := cfg.Listen("sctp", addr)
	if err != nil {
		return err
	}
	// The address is logged once the listener is up; a caller that asked
	// for port 0 learns the port from this line.
	log.Printf("listening on %v", l.Addr())
	stop := context.AfterFunc(ctx, func() {
		if err := l.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Printf("closing listener: %v", err)
		}
	})
	defer stop()
	defer func() {
		if err := l.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = errors.Join(retErr, err)
		}
	}()
	for {
		c, err := l.AcceptSCTP()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			if !retryAccept(err) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		go func() {
			defer func() {
				if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
					log.Printf("closing association: %v", err)
				}
			}()
			send, receive, err := bufferSizes(c)
			if err != nil {
				log.Printf("association %d: %v", c.AssocID(), err)
				return
			}
			log.Printf("association %d from %v: send buffer %d, receive buffer %d", c.AssocID(), c.RemoteAddr(), send, receive)
			if err := echo(c, bufsize); err != nil {
				log.Printf("association %d: %v", c.AssocID(), err)
			}
		}()
	}
}

// echo sends every message c receives back on the stream and with the PPID
// it arrived with, until the peer shuts the association down.
type echoConn interface {
	ReadMsg(int) ([]byte, sctp.RcvInfo, error)
	SendMsg([]byte, sctp.SendOptions) (int, error)
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

func retryAccept(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) || errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM)
}

func echo(c echoConn, bufsize int) error {
	for {
		// ReadMsg reads one whole message, however many reads the kernel
		// delivers it in; one longer than bufsize is refused with
		// sctp.ErrMessageTooLong.
		if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		msg, info, err := c.ReadMsg(bufsize)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		opts := sctp.SendOptions{Info: &sctp.SndInfo{Stream: info.Stream, PPID: info.PPID}}
		if err := c.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		if _, err := c.SendMsg(msg, opts); err != nil {
			return err
		}
	}
}

// runClient sets up an association with raddr, bound to laddr when it is not
// nil, and sends count messages of bufsize bytes, or messages until ctx is
// done when count is 0, pausing for interval between them. It checks every
// echo and prints one line per message to out.
func runClient(ctx context.Context, cfg *sctp.Config, laddr, raddr *sctp.Addr, bufsize, count int, interval time.Duration, out io.Writer) (retErr error) {
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	c, err := cfg.Dial(dialCtx, "sctp", laddr, raddr)
	cancel()
	if err != nil {
		return err
	}
	defer func() {
		if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			retErr = errors.Join(retErr, err)
		}
	}()

	status, err := c.Status()
	if err != nil {
		return err
	}
	if status.OutStreams == 0 {
		return errors.New("the association has no outgoing stream")
	}
	send, receive, err := bufferSizes(c)
	if err != nil {
		return err
	}
	log.Printf("association %d: %v -> %v, %d outgoing streams, send buffer %d, receive buffer %d",
		c.AssocID(), c.LocalAddr(), c.RemoteAddr(), status.OutStreams, send, receive)

	payload := make([]byte, bufsize)
	for i := 0; count == 0 || i < count; i++ {
		if i > 0 && interval > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(interval):
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		stream := uint16(i % int(status.OutStreams))
		for j := range payload {
			payload[j] = byte(i + j)
		}
		if err := c.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		info := &sctp.SndInfo{Stream: stream, PPID: uint32(stream)}
		if _, err := c.SendMsg(payload, sctp.SendOptions{Info: info}); err != nil {
			return err
		}
		if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			return err
		}
		msg, rcv, err := c.ReadMsg(bufsize)
		if err != nil {
			return err
		}
		if !bytes.Equal(msg, payload) || rcv.Stream != stream || rcv.PPID != uint32(stream) {
			return fmt.Errorf("message %d: sent %d bytes on stream %d with PPID %d, got back %d bytes on stream %d with PPID %d",
				i, len(payload), stream, stream, len(msg), rcv.Stream, rcv.PPID)
		}
		if _, err := fmt.Fprintf(out, "message %d: %d bytes echoed on stream %d, PPID %d\n", i, len(msg), rcv.Stream, rcv.PPID); err != nil {
			return err
		}
	}
	return nil
}
