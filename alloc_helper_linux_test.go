// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The helper-process peer. testing.AllocsPerRun counts the allocations of
// every goroutine in the process, so a peer in the same process would be
// counted against the call being measured. The peer therefore runs in a
// process of its own: the test binary started again with
// -test.run=^TestHelperPeer$ and helperPeerEnv set, which makes
// TestHelperPeer listen and report its port on standard output. In the
// default mode it accepts one association and reads and discards
// everything until the association ends, for measuring sends. In the
// sending mode it accepts helperPeerConnsEnv associations, one after the
// other, and on each answers every request "count size" with count
// messages of size bytes, until the association ends, for measuring
// receives.
const (
	helperPeerEnv        = "SCTP_HELPER_PEER"         // "1" selects the helper
	helperPeerNetworkEnv = "SCTP_HELPER_PEER_NETWORK" // "sctp4" or "sctp6"
	helperPeerAddrEnv    = "SCTP_HELPER_PEER_ADDR"    // the address to listen on
	helperPeerAuthEnv    = "SCTP_HELPER_PEER_AUTH"    // "1": AUTH on, DATA authenticated
	helperPeerModeEnv    = "SCTP_HELPER_PEER_MODE"    // "send" selects the sending mode
	helperPeerConnsEnv   = "SCTP_HELPER_PEER_CONNS"   // associations the sending mode serves
	helperPeerPortPrefix = "SCTP_HELPER_PEER_PORT="

	// helperPeerLifetime bounds how long a helper outlives a parent that
	// never ends its association.
	helperPeerLifetime = 2 * time.Minute
)

// chunkTypeDataForAuth is the DATA chunk type (RFC 9260 §3.3.1), which the
// helper asks its peer to authenticate when AUTH is requested, so that
// SendOptions.AuthKey selects the key of a real AUTH chunk (RFC 4895 §6.2)
// rather than being ignored (net/sctp/chunk.c: sctp_datamsg_from_user
// looks the key up only when the peer requires AUTH on DATA).
const chunkTypeDataForAuth = 0

// TestHelperPeer is the helper-process peer's entry point. Run without
// helperPeerEnv, as in any ordinary test run, it returns at once.
func TestHelperPeer(t *testing.T) {
	if os.Getenv(helperPeerEnv) != "1" {
		return
	}
	os.Exit(runHelperPeer(os.Stdout, os.Stderr))
}

// runHelperPeer is the helper's whole life, returning its exit status.
func runHelperPeer(stdout, stderr io.Writer) int {
	network := os.Getenv(helperPeerNetworkEnv)
	laddr, err := ResolveAddr(network, os.Getenv(helperPeerAddrEnv))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "helper peer: ResolveAddr: %v\n", err)
		return 1
	}
	sending := os.Getenv(helperPeerModeEnv) == "send"
	cfg := &Config{}
	if os.Getenv(helperPeerAuthEnv) == "1" {
		cfg.Authentication = new(true)
		cfg.AuthChunks = []uint8{chunkTypeDataForAuth}
	}
	if sending {
		cfg.NoDelay = new(true)
	}
	l, err := cfg.Listen(network, laddr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "helper peer: Listen %s %v: %v\n", network, laddr, err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%s%d\n", helperPeerPortPrefix, l.Addr().(*Addr).Port)
	time.AfterFunc(helperPeerLifetime, func() { os.Exit(2) })

	conns := 1
	if sending {
		if conns, err = strconv.Atoi(os.Getenv(helperPeerConnsEnv)); err != nil || conns < 1 {
			_, _ = fmt.Fprintf(stderr, "helper peer: %s=%q\n", helperPeerConnsEnv, os.Getenv(helperPeerConnsEnv))
			return 1
		}
	}
	for range conns {
		c, err := l.AcceptSCTP()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "helper peer: AcceptSCTP: %v\n", err)
			return 1
		}
		if sending {
			err = answerRequests(c)
		} else {
			err = drainUntilEnd(c)
		}
		_ = c.Abort()
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "helper peer: %v\n", err)
			return 1
		}
	}
	_ = l.Close()
	return 0
}

// drainUntilEnd reads and discards everything c receives until the
// association ends, and returns nil then, whether the end was graceful or
// not.
func drainUntilEnd(c *Conn) error {
	buf := make([]byte, 1<<16)
	for {
		if _, err := c.Read(buf); err != nil {
			return nil
		}
	}
}

// answerRequests serves the sending mode's requests on c until the
// association ends: each "count size" is answered with count messages of
// size bytes, the first four of each holding its number.
func answerRequests(c *Conn) error {
	buf := make([]byte, 64)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil
		}
		var count, size int
		if _, err := fmt.Sscanf(string(buf[:n]), "%d %d", &count, &size); err != nil || size < 4 {
			return fmt.Errorf("bad request %q", buf[:n])
		}
		msg := make([]byte, size)
		for i := range count {
			binary.BigEndian.PutUint32(msg, uint32(i))
			if _, err := c.Write(msg); err != nil {
				return nil
			}
		}
	}
}

// helperPeer is a running helper process.
type helperPeer struct {
	cmd    *exec.Cmd
	stderr bytes.Buffer
	done   chan struct{} // closed once its standard output reached EOF
}

// startHelperPeer starts a helper peer listening on address (network
// "sctp4" or "sctp6"), with AUTH on and DATA authenticated when auth is
// set, and returns the address to dial. The helper exits once the
// association the test sets up with it ends; cleanup waits for that, and
// kills it if it does not come.
func startHelperPeer(t testing.TB, network, address string, auth bool) *Addr {
	t.Helper()
	return startHelper(t, network, address, auth, 0)
}

// startHelperSender starts a helper peer in the sending mode, serving
// conns associations one after the other, and returns the address to dial.
func startHelperSender(t testing.TB, network, address string, conns int) *Addr {
	t.Helper()
	return startHelper(t, network, address, false, conns)
}

// startHelper starts a helper peer, in the sending mode when conns is not
// zero.
func startHelper(t testing.TB, network, address string, auth bool, conns int) *Addr {
	t.Helper()
	laddr, err := ResolveAddr(network, address)
	if err != nil {
		t.Fatalf("ResolveAddr(%q, %q): %v", network, address, err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot locate the test binary for the helper peer: %v", err)
	}
	p := &helperPeer{done: make(chan struct{})}
	p.cmd = exec.Command(exe, "-test.run=^TestHelperPeer$", "-test.count=1")
	p.cmd.Env = append(os.Environ(),
		helperPeerEnv+"=1",
		helperPeerNetworkEnv+"="+network,
		helperPeerAddrEnv+"="+address,
	)
	if auth {
		p.cmd.Env = append(p.cmd.Env, helperPeerAuthEnv+"=1")
	}
	if conns > 0 {
		p.cmd.Env = append(p.cmd.Env, helperPeerModeEnv+"=send", helperPeerConnsEnv+"="+strconv.Itoa(conns))
	}
	p.cmd.Stderr = &p.stderr
	stdout, err := p.cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("helper peer stdout: %v", err)
	}
	if err := p.cmd.Start(); err != nil {
		t.Fatalf("starting the helper peer: %v", err)
	}

	port := make(chan uint16, 1)
	go func() {
		defer close(p.done)
		s := bufio.NewScanner(stdout)
		for s.Scan() {
			if v, ok := strings.CutPrefix(s.Text(), helperPeerPortPrefix); ok {
				if n, err := strconv.ParseUint(v, 10, 16); err == nil {
					port <- uint16(n)
				}
			}
		}
	}()
	t.Cleanup(func() {
		select {
		case <-p.done:
		case <-time.After(10 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.done
		}
		_ = p.cmd.Wait()
	})

	select {
	case n := <-port:
		return &Addr{IPs: laddr.IPs, Port: n}
	case <-p.done:
		_ = p.cmd.Wait()
		t.Fatalf("the helper peer exited before listening: %s", strings.TrimSpace(p.stderr.String()))
	case <-time.After(10 * time.Second):
		t.Fatal("the helper peer did not report a port within 10 s")
	}
	return nil
}

// sendAllocs measures f, one send, over runs calls with the collector
// paused and the scheduler on one processor: the per-call allocation count
// testing.AllocsPerRun reports, and, from a separate run, the mean count
// and bytes per call as fractions, so that a stray allocation by the
// runtime and a real per-call one can be told apart with separate margins.
func sendAllocs(runs int, f func()) (allocsPerRun, mallocs, bytes float64) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	allocsPerRun = testing.AllocsPerRun(runs, f)

	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for range runs {
		f()
	}
	runtime.ReadMemStats(&after)
	mallocs = float64(after.Mallocs-before.Mallocs) / float64(runs)
	bytes = float64(after.TotalAlloc-before.TotalAlloc) / float64(runs)
	return allocsPerRun, mallocs, bytes
}

// TestSendMsgZeroAllocs pins that SendMsg and Write allocate nothing per
// call, on a real association to a peer in another process: with no
// options, with each option and combination that adds work, and for
// Write. A heap-allocated payload is reused, as a caller reusing its
// buffer would; the per-call count must be zero, and the mean per call
// must stay under a small fraction of one allocation (a stray one by the
// runtime) and a few bytes (less than the smallest allocation).
func TestSendMsgZeroAllocs(t *testing.T) {
	if underRaceDetector {
		t.Skip("allocation counts are unreliable under the race detector, whose instrumentation allocates on its own account")
	}
	const (
		runs          = 1000
		mallocsMargin = 0.05 // per call: fewer than 1 in 20 calls saw a stray allocation
		bytesMargin   = 4.0  // per call: less than the smallest allocation, 8 bytes
	)
	info := &SndInfo{Stream: 1, PPID: 0x1234, Context: 5}
	pr := &PrInfo{Policy: PRTTL, TTL: 30 * time.Second}
	key := uint16(0) // the null key every association has (RFC 4895 §6.1)

	cases := []struct {
		name            string
		network, listen string
		auth            bool
		zone            string // an interface the case needs
		opts            func(peer *Addr) SendOptions
		write           bool
		inline          bool // build the options in each call, as a caller would
	}{
		{name: "no options", opts: func(*Addr) SendOptions { return SendOptions{} }},
		{name: "Info", opts: func(*Addr) SendOptions { return SendOptions{Info: info} }},
		{name: "Info+PR", opts: func(*Addr) SendOptions { return SendOptions{Info: info, PR: pr} }},
		{name: "PR", opts: func(*Addr) SendOptions { return SendOptions{PR: pr} }},
		{name: "Info+PR+AuthKey", auth: true, opts: func(*Addr) SendOptions { return SendOptions{Info: info, PR: pr, AuthKey: &key} }},
		{name: "AuthKey", auth: true, opts: func(*Addr) SendOptions { return SendOptions{AuthKey: &key} }},
		{name: "Path", opts: func(p *Addr) SendOptions { return SendOptions{Path: p.IPs[0]} }},
		{
			name: "zoned link-local Path", network: "sctp6", listen: "[fe80::1%zone0]:0", zone: "zone0",
			opts: func(p *Addr) SendOptions { return SendOptions{Path: p.IPs[0]} },
		},
		{name: "More", opts: func(*Addr) SendOptions { return SendOptions{More: true} }},
		{name: "options built per call", inline: true},
		{name: "Write", write: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			network, listen := tc.network, tc.listen
			if network == "" {
				network, listen = "sctp4", "127.0.0.1:0"
			}
			if tc.zone != "" {
				if _, err := net.InterfaceByName(tc.zone); err != nil {
					t.Skipf("no interface %s (the Linux suite adds a dummy link %s with fe80::1): %v", tc.zone, tc.zone, err)
				}
			}
			peer := startHelperPeer(t, network, listen, tc.auth)
			// NoDelay sends each message at once, rather than holding
			// small ones until earlier data is acknowledged (RFC 6458
			// §8.1.5), which only makes the run slower.
			cfg := &Config{NoDelay: new(true)}
			if tc.auth {
				cfg.Authentication = new(true)
			}
			client, err := cfg.Dial(testContext(t, 10*time.Second), network, nil, peer)
			if err != nil {
				t.Fatalf("Dial %v: %v", peer, err)
			}
			defer func() { _ = client.Close() }()

			var opts SendOptions
			if tc.opts != nil {
				opts = tc.opts(peer)
			}
			payload := fill(64)
			var failed error
			send := func() {
				var n int
				var err error
				switch {
				case tc.write:
					n, err = client.Write(payload)
				case tc.inline:
					// SendMsg keeps nothing of its options, so these stay
					// on this function's stack.
					n, err = client.SendMsg(payload, SendOptions{
						Info: &SndInfo{Stream: 1, PPID: 0x1234},
						PR:   &PrInfo{Policy: PRTTL, TTL: 30 * time.Second},
					})
				default:
					n, err = client.SendMsg(payload, opts)
					if tc.name == "More" {
						// Bursts of two: a message with More set
						// is held for the next (MSG_MORE), and a burst
						// that never ends would sit in the kernel.
						opts.More = !opts.More
					}
				}
				if (err != nil || n != len(payload)) && failed == nil {
					failed = fmt.Errorf("send = %d, %v; want %d, nil", n, err, len(payload))
				}
			}
			allocs, mallocs, bytes := sendAllocs(runs, send)
			if failed != nil {
				t.Fatal(failed)
			}
			if opts.More {
				// Let the last burst go.
				if _, err := client.Write(payload); err != nil {
					t.Fatalf("closing the burst: %v", err)
				}
			}
			if allocs != 0 {
				t.Errorf("testing.AllocsPerRun = %v allocations per send, want 0", allocs)
			}
			if mallocs >= mallocsMargin {
				t.Errorf("%.3f allocations per send on average, want fewer than %v", mallocs, mallocsMargin)
			}
			if bytes >= bytesMargin {
				t.Errorf("%.1f bytes allocated per send on average, want fewer than %v", bytes, bytesMargin)
			}
		})
	}
}
