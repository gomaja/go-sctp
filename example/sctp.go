package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/gomaja/go-sctp"
)

// payloadRand fills the example's send buffer. It is seeded from the clock only
// so successive runs differ; the bytes carry no meaning and are never checked,
// so a weak source is the right one here.
var payloadRand = rand.New(rand.NewSource(time.Now().UnixNano()))

type bufferSizer interface {
	SetWriteBuffer(int) error
	SetReadBuffer(int) error
	GetWriteBuffer() (int, error)
	GetReadBuffer() (int, error)
}

func configureBuffers(conn bufferSizer, send, receive int) (int, int, error) {
	if send != 0 {
		if err := conn.SetWriteBuffer(send); err != nil {
			return 0, 0, fmt.Errorf("set write buffer: %w", err)
		}
	}
	if receive != 0 {
		if err := conn.SetReadBuffer(receive); err != nil {
			return 0, 0, fmt.Errorf("set read buffer: %w", err)
		}
	}

	actualSend, err := conn.GetWriteBuffer()
	if err != nil {
		return 0, 0, fmt.Errorf("get write buffer: %w", err)
	}
	actualReceive, err := conn.GetReadBuffer()
	if err != nil {
		return 0, 0, fmt.Errorf("get read buffer: %w", err)
	}
	return actualSend, actualReceive, nil
}

func serveClient(conn net.Conn, bufsize int) error {
	for {
		buf := make([]byte, bufsize+128) // add overhead of SCTPSndRcvInfoWrappedConn
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("read failed: %v", err)
			return err
		}
		log.Printf("read: %d", n)
		n, err = conn.Write(buf[:n])
		if err != nil {
			log.Printf("write failed: %v", err)
			return err
		}
		log.Printf("write: %d", n)
	}
}

func main() {
	var server = flag.Bool("server", false, "")
	var ip = flag.String("ip", "0.0.0.0", "")
	var port = flag.Int("port", 0, "")
	var lport = flag.Int("lport", 0, "")
	var bufsize = flag.Int("bufsize", 256, "")
	var sndbuf = flag.Int("sndbuf", 0, "")
	var rcvbuf = flag.Int("rcvbuf", 0, "")

	flag.Parse()

	ips := []net.IPAddr{}

	for _, i := range strings.Split(*ip, ",") {
		if a, err := net.ResolveIPAddr("ip", i); err == nil {
			log.Printf("Resolved address '%s' to %s", i, a)
			ips = append(ips, *a)
		} else {
			log.Printf("Error resolving address '%s': %v", i, err)
		}
	}

	addr := &sctp.SCTPAddr{
		IPAddrs: ips,
		Port:    *port,
	}
	log.Printf("raw addr: %+v\n", addr.ToRawSockAddrBuf())

	if *server {
		ln, err := sctp.ListenSCTP("sctp", addr)
		if err != nil {
			log.Fatalf("failed to listen: %v", err)
		}
		log.Printf("Listen on %s", ln.Addr())

		for {
			conn, err := ln.AcceptSCTP()
			if err != nil {
				log.Fatalf("failed to accept: %v", err)
			}
			log.Printf("Accepted Connection from RemoteAddr: %s", conn.RemoteAddr())
			wconn := sctp.NewSCTPSndRcvInfoWrappedConn(conn)
			*sndbuf, *rcvbuf, err = configureBuffers(wconn, *sndbuf, *rcvbuf)
			if err != nil {
				_ = wconn.Close()
				log.Fatalf("failed to configure buffers: %v", err)
			}
			log.Printf("SndBufSize: %d, RcvBufSize: %d", *sndbuf, *rcvbuf)

			go func(client net.Conn) {
				defer func() { _ = client.Close() }()
				if err := serveClient(client, *bufsize); err != nil {
					log.Printf("serveClient: %v", err)
				}
			}(wconn)
		}

	} else {
		var laddr *sctp.SCTPAddr
		if *lport != 0 {
			laddr = &sctp.SCTPAddr{
				Port: *lport,
			}
		}
		conn, err := sctp.DialSCTP("sctp", laddr, addr)
		if err != nil {
			log.Fatalf("failed to dial: %v", err)
		}

		log.Printf("Dial LocalAddr: %s; RemoteAddr: %s", conn.LocalAddr(), conn.RemoteAddr())

		*sndbuf, *rcvbuf, err = configureBuffers(conn, *sndbuf, *rcvbuf)
		if err != nil {
			log.Fatalf("failed to configure buffers: %v", err)
		}
		log.Printf("SndBufSize: %d, RcvBufSize: %d", *sndbuf, *rcvbuf)
		if err := conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO); err != nil {
			log.Fatalf("failed to subscribe to data io events: %v", err)
		}

		ppid := 0
		for {
			info := &sctp.SndRcvInfo{
				Stream: uint16(ppid),
				PPID:   uint32(ppid),
			}
			ppid += 1
			buf := make([]byte, *bufsize)
			// Filler bytes for the payload, not a secret: an explicit source
			// rather than the deprecated package-level rand.Read, which draws
			// from the global source. crypto/rand would be the wrong answer
			// here — nothing about this payload needs to be unpredictable.
			payloadRand.Read(buf)
			n, err := conn.SCTPWrite(buf, info)
			if err != nil {
				log.Fatalf("failed to write: %v", err)
			}
			log.Printf("write: len %d", n)
			n, info, err = conn.SCTPRead(buf)
			if err != nil {
				log.Fatalf("failed to read: %v", err)
			}
			log.Printf("read: len %d, info: %+v", n, info)
			time.Sleep(time.Second)
		}
	}
}
