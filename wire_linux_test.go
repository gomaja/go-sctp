// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The two-host harness. testdata/wire/run.sh starts this test binary in
// two containers joined by two Docker networks, A and B, one process per
// container, with:
//
//   - SCTP_WIRE_ROLE: the side this process plays, "client" or "server";
//   - SCTP_WIRE_PEER: the other container's addresses on networks A and B,
//     in that order, separated by "/";
//   - SCTP_WIRE_FACTS: the file where this process records, case by case,
//     the ports, API call times and counts that the capture analyzer
//     (testdata/wire/analyze) checks the client's capture against.
//
// Without SCTP_WIRE_ROLE, TestWire and TestTwoHost skip and say why.
//
// Both processes run the same cases in the same order. For each case they
// meet over a TCP connection to wireControlPort on the server, the control
// connection, which also carries the case's own steps: a side that must
// act only after the other has done something waits for its word. SCTP is
// never used for this, so a case can drop every SCTP packet of an
// association without cutting its own coordination.
//
// Loss is made with iptables on the INPUT hook of the host that receives
// the packets, never on OUTPUT of the host that sends them: the capture
// runs on the sending host, and a packet dropped on OUTPUT never reaches
// its capture point, while one dropped on the receiver's INPUT has already
// crossed the wire. Loopback cannot stand in for this, since traffic on lo
// bypasses the queueing layer a real path goes through.
const (
	wireRoleEnv     = "SCTP_WIRE_ROLE"
	wirePeerEnv     = "SCTP_WIRE_PEER"
	wireFactsEnv    = "SCTP_WIRE_FACTS"
	wireControlPort = 7411

	// wireStepWait bounds every wait for the other side and every SCTP
	// setup, so that a failure on one side ends the case on the other
	// instead of stalling the run.
	wireStepWait = 60 * time.Second

	// wireGrace is the grace period of the Close calls in the wire cases:
	// the default, 3 s, set explicitly so the analyzer is told the value
	// the calls used.
	wireGrace = 3 * time.Second

	// wireDrainGrace is the grace period of the Close calls that wait for a
	// peer to drain a full send buffer first: long enough that a slow
	// drain never looks like the ABORT fallback.
	wireDrainGrace = 10 * time.Second

	// wireSmallBuffer is the send or receive buffer of the cases that fill
	// a send buffer: small, so that a few messages close the peer's window
	// (RFC 9260 §6.1 rule A) and fill the send buffer behind it.
	wireSmallBuffer = 4096
)

// wireFastRTO shortens the retransmission timers of the cases that wait
// for them (RFC 9260 §6.3.1; RFC 6458 §8.1.1): T3-rtx, T2-shutdown and
// the timer that confirms a new path.
var wireFastRTO = &RTOInfo{Initial: 200 * time.Millisecond, Min: 100 * time.Millisecond, Max: 400 * time.Millisecond}

// twoHost is this process's side of the harness.
type twoHost struct {
	server bool
	local  [2]netip.Addr // this host's addresses on networks A and B
	peer   [2]netip.Addr // the other host's
	ctl    *net.TCPListener

	mu    sync.Mutex // serialises writes to facts
	facts *os.File
}

var (
	twoHostOnce sync.Once
	twoHostSide *twoHost
	twoHostErr  error
)

// twoHostSetup returns this process's side of the harness, set up once for
// the whole run, or skips the test when testdata/wire/run.sh did not start
// the process.
func twoHostSetup(t *testing.T) *twoHost {
	t.Helper()
	if os.Getenv(wireRoleEnv) == "" {
		t.Skipf("two-host test: testdata/wire/run.sh runs it in two containers, with %s and %s set", wireRoleEnv, wirePeerEnv)
	}
	twoHostOnce.Do(func() { twoHostSide, twoHostErr = newTwoHost() })
	if twoHostErr != nil {
		t.Fatalf("two-host setup: %v", twoHostErr)
	}
	return twoHostSide
}

func newTwoHost() (*twoHost, error) {
	h := &twoHost{}
	switch role := os.Getenv(wireRoleEnv); role {
	case "server":
		h.server = true
	case "client":
	default:
		return nil, fmt.Errorf("%s=%q, want client or server", wireRoleEnv, role)
	}
	peers := strings.Split(os.Getenv(wirePeerEnv), "/")
	if len(peers) != 2 {
		return nil, fmt.Errorf("%s=%q, want the peer's addresses on networks A and B, separated by /", wirePeerEnv, os.Getenv(wirePeerEnv))
	}
	for i, p := range peers {
		a, err := netip.ParseAddr(p)
		if err != nil || !a.Is4() {
			return nil, fmt.Errorf("%s: %q is not an IPv4 address", wirePeerEnv, p)
		}
		h.peer[i] = a
		if h.local[i], err = localToward(a); err != nil {
			return nil, fmt.Errorf("no route to the peer's address %v: %v", a, err)
		}
	}
	if h.local[0] == h.local[1] {
		return nil, fmt.Errorf("both of the peer's addresses are reached from %v; the two networks must be separate paths", h.local[0])
	}
	path := os.Getenv(wireFactsEnv)
	if path == "" {
		return nil, fmt.Errorf("%s is not set", wireFactsEnv)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	h.facts = f
	if h.server {
		ln, err := net.ListenTCP("tcp4", &net.TCPAddr{Port: wireControlPort})
		if err != nil {
			return nil, err
		}
		h.ctl = ln
	}
	role := h.role()
	for i, network := range []string{"a", "b"} {
		if err := h.record("setup", role+"_"+network, h.local[i]); err != nil {
			return nil, err
		}
	}
	return h, nil
}

// localToward is the local address the routing table picks for dst. A
// connected UDP socket sends nothing; connecting it only binds the source.
func localToward(dst netip.Addr) (netip.Addr, error) {
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(netip.AddrPortFrom(dst, 9)))
	if err != nil {
		return netip.Addr{}, err
	}
	defer func() { _ = c.Close() }()
	return c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap(), nil
}

func (h *twoHost) role() string {
	if h.server {
		return "server"
	}
	return "client"
}

func (h *twoHost) peerRole() string {
	if h.server {
		return "client"
	}
	return "server"
}

// record appends one fact, "case key value", to the facts file.
func (h *twoHost) record(name, key string, value any) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := fmt.Fprintf(h.facts, "%s %s %v\n", name, key, value)
	return err
}

// twoHostCase is one case of the harness: what each side does. The server
// listens on port (and on port+1 for a case with two associations), which
// is how the analyzer finds the case's packets in the capture.
type twoHostCase struct {
	name   string
	port   uint16
	server func(s *hostStep)
	client func(s *hostStep)
}

// runTwoHost runs every case as a subtest, playing this process's side.
func runTwoHost(t *testing.T, cases []twoHostCase) {
	h := twoHostSetup(t)
	checkEphemeralRange(t, cases)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := h.step(t, c.name, c.port)
			if !h.server {
				s.fact("port", c.port)
			}
			if h.server {
				c.server(s)
			} else {
				c.client(s)
			}
			// Neither side starts the next case while the other is still
			// in this one.
			s.send("end")
			s.expect("end")
		})
	}
}

// checkEphemeralRange refuses to run cases whose ports, or the control
// port, lie in the host's ephemeral port range, which SCTP draws its local
// ports from (net/sctp/socket.c: sctp_get_port_local): a dialer's own port
// could then equal a case's server port, and the analyzer would have to
// tell the two associations apart by direction alone. testdata/wire/run.sh
// sets the range to 49152-60999.
func checkEphemeralRange(t *testing.T, cases []twoHostCase) {
	t.Helper()
	const path = "/proc/sys/net/ipv4/ip_local_port_range"
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var low, high int
	if _, err := fmt.Sscan(string(b), &low, &high); err != nil {
		t.Fatalf("%s = %q: %v", path, b, err)
	}
	ports := []int{wireControlPort}
	for _, c := range cases {
		// A case with two associations also uses port+1.
		ports = append(ports, int(c.port), int(c.port)+1)
	}
	for _, p := range ports {
		if p >= low && p <= high {
			t.Fatalf("port %d lies in the ephemeral port range %d-%d, where a dialer's own port could equal it", p, low, high)
		}
	}
}

// hostStep is one case in progress on this side: its control connection
// to the other side, and the helpers the cases share.
type hostStep struct {
	t     *testing.T
	h     *twoHost
	name  string
	port  uint16
	conn  net.Conn
	rd    *bufio.Reader
	drops int
}

// step meets the other side for case name over a new control connection.
func (h *twoHost) step(t *testing.T, name string, port uint16) *hostStep {
	t.Helper()
	s := &hostStep{t: t, h: h, name: name, port: port}
	deadline := time.Now().Add(wireStepWait)
	if h.server {
		if err := h.ctl.SetDeadline(deadline); err != nil {
			t.Fatalf("control listener deadline: %v", err)
		}
		c, err := h.ctl.Accept()
		if err != nil {
			t.Fatalf("waiting for the client to reach %s: %v", name, err)
		}
		s.conn = c
	} else {
		addr := netip.AddrPortFrom(h.peer[0], wireControlPort).String()
		for {
			c, err := net.DialTimeout("tcp4", addr, time.Second)
			if err == nil {
				s.conn = c
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("reaching the server's control port %s for %s: %v", addr, name, err)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	t.Cleanup(func() { _ = s.conn.Close() })
	s.rd = bufio.NewReader(s.conn)
	s.send("step", name)
	if got := s.expect("step"); len(got) != 1 || got[0] != name {
		t.Fatalf("the %s is at step %v, this %s at %s", h.peerRole(), got, h.role(), name)
	}
	return s
}

// send tells the other side words, as one line.
func (s *hostStep) send(words ...any) {
	s.t.Helper()
	_ = s.conn.SetWriteDeadline(time.Now().Add(wireStepWait))
	if _, err := fmt.Fprintln(s.conn, words...); err != nil {
		s.t.Fatalf("telling the %s %v: %v", s.h.peerRole(), words, err)
	}
}

// expect waits for the other side's next line, which must start with
// word, and returns the rest of it.
func (s *hostStep) expect(word string) []string {
	s.t.Helper()
	_ = s.conn.SetReadDeadline(time.Now().Add(wireStepWait))
	line, err := s.rd.ReadString('\n')
	if err != nil {
		s.t.Fatalf("waiting for %q from the %s: %v (the %s ends a case early when it fails; see its log)", word, s.h.peerRole(), err, s.h.peerRole())
	}
	f := strings.Fields(line)
	if len(f) == 0 || f[0] != word {
		s.t.Fatalf("the %s said %q, want %q", s.h.peerRole(), strings.TrimSpace(line), word)
	}
	return f[1:]
}

// expectInts is expect for a line of integers after word.
func (s *hostStep) expectInts(word string) []int64 {
	s.t.Helper()
	var out []int64
	for _, f := range s.expect(word) {
		n, err := strconv.ParseInt(f, 10, 64)
		if err != nil {
			s.t.Fatalf("the %s said %s %v: %v", s.h.peerRole(), word, f, err)
		}
		out = append(out, n)
	}
	return out
}

// fact records one fact of this case for the analyzer.
func (s *hostStep) fact(key string, value any) {
	s.t.Helper()
	if err := s.h.record(s.name, key, value); err != nil {
		s.t.Fatalf("recording %s: %v", key, err)
	}
}

// wireAddr is an *Addr of port and ips.
func wireAddr(port uint16, ips ...netip.Addr) *Addr {
	return &Addr{IPs: ips, Port: port}
}

// listen listens with cfg on port of ips.
func (s *hostStep) listen(cfg *Config, port uint16, ips ...netip.Addr) *Listener {
	s.t.Helper()
	return mustListen(s.t, cfg, "sctp4", wireAddr(port, ips...))
}

// accept accepts one association on l, aborted on cleanup.
func (s *hostStep) accept(l *Listener) *Conn {
	s.t.Helper()
	if err := l.SetDeadline(time.Now().Add(wireStepWait)); err != nil {
		s.t.Fatalf("listener deadline: %v", err)
	}
	c, err := l.AcceptSCTP()
	if err != nil {
		s.t.Fatalf("AcceptSCTP: %v", err)
	}
	s.t.Cleanup(func() { _ = c.Abort() })
	return c
}

// dial dials port on remote from local with cfg, aborted on cleanup.
func (s *hostStep) dial(cfg *Config, local []netip.Addr, port uint16, remote ...netip.Addr) *Conn {
	s.t.Helper()
	c, err := cfg.Dial(testContext(s.t, wireStepWait), "sctp4", wireAddr(0, local...), wireAddr(port, remote...))
	if err != nil {
		s.t.Fatalf("Dial %v:%d: %v", remote, port, err)
	}
	s.t.Cleanup(func() { _ = c.Abort() })
	return c
}

// dialA dials the server on network A, from this host's network A address.
func (s *hostStep) dialA(cfg *Config) *Conn {
	s.t.Helper()
	return s.dial(cfg, []netip.Addr{s.h.local[0]}, s.port, s.h.peer[0])
}

// endpointA opens a connect-only Endpoint with cfg on this host's network
// A address.
func (s *hostStep) endpointA(cfg *Config) *Endpoint {
	s.t.Helper()
	return openEndpoint(s.t, cfg, "sctp4", wireAddr(0, s.h.local[0]))
}

// connect starts an association from e to port on the server's network A
// address and waits until it is up: Endpoint.Connect only starts the setup
// (RFC 6458 §3.1.6), and the AssocChange record reports its outcome (RFC
// 6458 §6.1.1).
func (s *hostStep) connect(e *Endpoint, port uint16) AssocID {
	s.t.Helper()
	id, err := e.Connect(wireAddr(port, s.h.peer[0]))
	if err != nil {
		s.t.Fatalf("Connect to port %d: %v", port, err)
	}
	if ac := awaitCommUp(s.t, e); ac.AssocID != id {
		s.t.Fatalf("association %d came up, want %d", ac.AssocID, id)
	}
	return id
}

// peel peels association id off e, aborted on cleanup.
func (s *hostStep) peel(e *Endpoint, id AssocID) *Conn {
	s.t.Helper()
	c, err := e.PeelOff(id)
	if err != nil {
		s.t.Fatalf("PeelOff(%d): %v", id, err)
	}
	s.t.Cleanup(func() { _ = c.Abort() })
	return c
}

// twoHomedDial dials the server on both its addresses from both of this
// host's, makes network A's path the primary, and waits until both paths
// are confirmed (RFC 9260 §5.4), so that neither the paths nor their
// verification heartbeats change during the case.
func (s *hostStep) twoHomedDial(cfg *Config) *Conn {
	s.t.Helper()
	c := s.dial(cfg, s.h.local[:], s.port, s.h.peer[:]...)
	if err := c.SetPrimaryAddr(s.h.peer[0]); err != nil {
		s.t.Fatalf("SetPrimaryAddr(%v): %v", s.h.peer[0], err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for _, p := range s.h.peer {
		for {
			pi, err := c.PathInfo(p)
			if err != nil {
				s.t.Fatalf("PathInfo(%v): %v", p, err)
			}
			if pi.State == PathActive {
				break
			}
			if time.Now().After(deadline) {
				s.t.Fatalf("the path to %v is still %v after 10 s", p, pi.State)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	return c
}

// wireMessage is a message of size bytes that carries i in its first four,
// in network order, for numberOf.
func wireMessage(i, size int) []byte {
	b := make([]byte, size)
	binary.BigEndian.PutUint32(b, uint32(i))
	for j := 4; j < size; j++ {
		b[j] = byte(j)
	}
	return b
}

// mustSend sends b with opts on c.
func (s *hostStep) mustSend(c *Conn, b []byte, opts SendOptions) {
	s.t.Helper()
	if _, err := c.SendMsg(b, opts); err != nil {
		s.t.Fatalf("SendMsg(%d bytes, %+v): %v", len(b), opts, err)
	}
}

// closeGracefully closes c and requires the graceful outcome: nil, well
// within the grace period.
func (s *hostStep) closeGracefully(c *Conn) {
	s.t.Helper()
	start := time.Now()
	if err := c.Close(); err != nil {
		s.t.Fatalf("Close: %v", err)
	}
	if d := time.Since(start); d >= wireGrace {
		s.t.Errorf("Close took %v, a whole grace period: it aborted instead of completing the shutdown", d)
	}
}

// wireRecv is one message a server received.
type wireRecv struct {
	data []byte
	info RcvInfo
}

// readUntilEOF reads whole messages from c until io.EOF.
func (s *hostStep) readUntilEOF(c *Conn) []wireRecv {
	s.t.Helper()
	got, err := readMessagesToEOF(c)
	if err != nil {
		s.t.Fatal(err)
	}
	return got
}

// recordEnd records how many messages arrived and whether the reads
// reached io.EOF, before a failure ends the case, so that the analyzer
// still checks the capture.
func (s *hostStep) recordEnd(got []wireRecv, err error) {
	s.t.Helper()
	s.fact("received", len(got))
	if err == nil {
		s.fact("eof", 1)
	} else {
		s.fact("eof", 0)
		s.t.Fatal(err)
	}
}

// readMessagesToEOF is readUntilEOF for a goroutine, which must not end
// the test itself.
func readMessagesToEOF(c *Conn) ([]wireRecv, error) {
	if err := c.SetReadDeadline(time.Now().Add(wireStepWait)); err != nil {
		return nil, err
	}
	var got []wireRecv
	for {
		b, info, err := c.ReadMsg(1 << 16)
		if errors.Is(err, io.EOF) {
			return got, nil
		}
		if err != nil {
			return got, fmt.Errorf("ReadMsg after %d messages: %v", len(got), err)
		}
		got = append(got, wireRecv{data: b, info: info})
	}
}

// serveUntilEOF listens with cfg on the case's port of ips, accepts one
// association and reads it until the client's graceful close ends it.
func (s *hostStep) serveUntilEOF(cfg *Config, ips ...netip.Addr) []wireRecv {
	s.t.Helper()
	l := s.listen(cfg, s.port, ips...)
	s.send("ready")
	got, err := readMessagesToEOF(s.accept(l))
	s.recordEnd(got, err)
	return got
}

// wantPPIDs checks that got holds one message for each PPID of want, in
// any order, and returns them by PPID.
func (s *hostStep) wantPPIDs(got []wireRecv, want ...uint32) map[uint32]wireRecv {
	s.t.Helper()
	by := make(map[uint32]wireRecv, len(got))
	for _, m := range got {
		if _, dup := by[m.info.PPID]; dup {
			s.t.Errorf("two messages with PPID %#x", m.info.PPID)
		}
		by[m.info.PPID] = m
	}
	if len(got) != len(want) {
		s.t.Errorf("received %d messages, want %d", len(got), len(want))
	}
	for _, p := range want {
		if _, ok := by[p]; !ok {
			s.t.Errorf("no message with PPID %#x arrived", p)
		}
	}
	return by
}

// fillNoWait sends numbered messages of size bytes with PPID ppid and
// NoWait until the send buffer refuses one with EAGAIN, and returns how
// many were accepted. The peer must not be reading.
func (s *hostStep) fillNoWait(send func([]byte, SendOptions) (int, error), ppid uint32, size int) int {
	s.t.Helper()
	for i := 0; i < 1<<16; i++ {
		_, err := send(wireMessage(i, size), SendOptions{Info: &SndInfo{PPID: ppid}, NoWait: true})
		if errors.Is(err, syscall.EAGAIN) {
			if i == 0 {
				s.t.Fatal("the first NoWait send was refused")
			}
			return i
		}
		if err != nil {
			s.t.Fatalf("NoWait send %d: %v", i, err)
		}
	}
	s.t.Fatalf("the send buffer never filled after 65536 messages of %d bytes", size)
	return 0
}

// --- INPUT drops -------------------------------------------------------------

// inputDrop is an iptables rule on this host's INPUT hook that drops the
// SCTP packets it matches, identified by a comment so that its packet
// counter can be read: a drop that matched nothing never made the loss the
// case depends on, and fails the case.
type inputDrop struct {
	t      *testing.T
	tag    string
	rule   []string
	active bool
}

// dropInput installs a rule dropping the SCTP packets that match, which
// are options of the iptables sctp match: "--dport", "--sport",
// "--chunk-types".
func (s *hostStep) dropInput(match ...string) *inputDrop {
	s.t.Helper()
	d := &inputDrop{t: s.t, tag: fmt.Sprintf("sctpwire:%s:%d", s.name, s.drops)}
	s.drops++
	d.rule = append([]string{"-p", "sctp", "-m", "sctp"}, match...)
	d.rule = append(d.rule, "-m", "comment", "--comment", d.tag, "-j", "DROP")
	iptables(s.t, append([]string{"-I", "INPUT", "1"}, d.rule...)...)
	d.active = true
	s.t.Cleanup(func() {
		if d.active {
			if out, err := runIptables(append([]string{"-D", "INPUT"}, d.rule...)...); err != nil {
				s.t.Errorf("removing %s: %v: %s", d.tag, err, out)
			}
		}
	})
	return d
}

// portArg is port as an iptables argument.
func portArg(port uint16) string { return strconv.Itoa(int(port)) }

// packets reads the rule's packet counter.
func (d *inputDrop) packets() int {
	d.t.Helper()
	out := iptables(d.t, "-L", "INPUT", "-v", "-x", "-n")
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "/* "+d.tag+" */") {
			continue
		}
		f := strings.Fields(line)
		n, err := strconv.Atoi(f[0])
		if err != nil {
			d.t.Fatalf("iptables counter %q: %v", line, err)
		}
		return n
	}
	d.t.Fatalf("rule %s is not in the INPUT chain:\n%s", d.tag, out)
	return 0
}

// lift removes the rule and returns how many packets it dropped.
func (d *inputDrop) lift() int {
	d.t.Helper()
	n := d.packets()
	iptables(d.t, append([]string{"-D", "INPUT"}, d.rule...)...)
	d.active = false
	return n
}

func runIptables(args ...string) (string, error) {
	out, err := exec.Command("iptables", append([]string{"-w", "5"}, args...)...).CombinedOutput()
	return string(out), err
}

func iptables(t *testing.T, args ...string) string {
	t.Helper()
	out, err := runIptables(args...)
	if err != nil {
		t.Fatalf("iptables %v: %v: %s", args, err, out)
	}
	return out
}

// --- the wire cases ------------------------------------------------------------

// PPIDs that mark the messages the analyzer looks for, one per role in the
// cases; testdata/wire/analyze/claims.go names the same values.
const (
	wirePPIDPlain      uint32 = 0x57490001
	wirePPIDSACKNow    uint32 = 0x57490002
	wirePPIDUnordered  uint32 = 0x57490003
	wirePPIDOrdered    uint32 = 0x57490004
	wirePPIDDefault    uint32 = 0x57490005
	wirePPIDFill       uint32 = 0x57490006
	wirePPIDRefused    uint32 = 0x57490007
	wirePPIDLast       uint32 = 0x57490008
	wirePPIDPrimary    uint32 = 0x57490009
	wirePPIDPath       uint32 = 0x5749000a
	wirePPIDAlone1     uint32 = 0x5749000b
	wirePPIDAlone2     uint32 = 0x5749000c
	wirePPIDMore1      uint32 = 0x5749000d
	wirePPIDMore2      uint32 = 0x5749000e
	wirePPIDBurst      uint32 = 0x5749000f
	wirePPIDAbandoned  uint32 = 0x57490010
	wirePPIDAfter      uint32 = 0x57490011
	wirePPIDGraceful   uint32 = 0x57490012
	wirePPIDInterleave uint32 = 0x57490013
)

// The PPIDs of the byte-order case: each has four different bytes, so any
// reordering shows, and two have the top bit set.
var wireOrderPPIDs = [4]uint32{0x01020304, 0x11223344, 0x89abcdef, 0xfedcba98}

// TestWire runs the cases whose outcome testdata/wire/analyze proves from
// the capture taken on the client's host. Each side's own assertions run
// here too; the capture is what shows the packets the kernel sent.
func TestWire(t *testing.T) {
	runTwoHost(t, wireCases)
}

var wireCases = []twoHostCase{
	{name: "abandon-abort-cookie-wait", port: 41001, server: abandonServer(false), client: abandonClient(AbandonAbort)},
	{name: "abandon-quiet-cookie-wait", port: 41002, server: abandonServer(false), client: abandonClient(AbandonQuiet)},
	{name: "abandon-abort-cookie-echoed", port: 41003, server: abandonServer(true), client: abandonClient(AbandonAbort)},
	{name: "abandon-quiet-cookie-echoed", port: 41004, server: abandonServer(true), client: abandonClient(AbandonQuiet)},
	{name: "abort-during-close", port: 41005, server: silentServer(1), client: abortDuringCloseClient},
	{name: "abort-during-peeled-close", port: 41006, server: silentServer(1), client: abortDuringPeeledCloseClient},
	{name: "abort-during-endpoint-close", port: 41007, server: silentServer(2), client: abortDuringEndpointCloseClient},
	{name: "peeled-close-full-buffer", port: 41009, server: drainingServer(1), client: peeledCloseFullBufferClient},
	{name: "endpoint-close-full-buffers", port: 41010, server: drainingServer(2), client: endpointCloseFullBuffersClient},
	{name: "sack-immediately", port: 41012, server: sackImmediatelyServer, client: sackImmediatelyClient},
	{name: "unordered", port: 41013, server: unorderedServer, client: unorderedClient},
	{name: "request-heartbeat", port: 41014, server: twoHomedServer, client: requestHeartbeatClient},
	{name: "periodic-heartbeat", port: 41024, server: twoHomedServer, client: periodicHeartbeatClient},
	{name: "message-interleaving", port: 41025, server: interleavingServer, client: interleavingClient},
	{name: "nowait-refusal", port: 41015, server: noWaitServer, client: noWaitClient},
	{name: "path", port: 41016, server: twoHomedServer, client: pathClient},
	{name: "more", port: 41017, server: moreServer, client: moreClient},
	{name: "ppid-byte-order", port: 41018, server: ppidServer, client: ppidClient},
	{name: "close-after-burst", port: 41019, server: burstServer, client: burstClient},
	{name: "simultaneous-close", port: 41020, server: simultaneousCloseServer, client: simultaneousCloseClient},
	{name: "pr-rtx-limit", port: 41021, server: prRtxServer, client: prRtxClient},
	{name: "graceful-close", port: 41022, server: gracefulServer, client: gracefulClient},
	{name: "graceful-peeled-close", port: 41023, server: gracefulServer, client: gracefulPeeledClient},
	{name: "capture-sentinel", port: wireSentinelPort, server: func(*hostStep) {}, client: sentinelClient},
}

// wireSentinelPort is a port the server never listens on.
const wireSentinelPort = 9

// sentinelClient ends the wire cases with one INIT to a port the server
// does not listen on, on each network, which the server's kernel answers
// with an ABORT (RFC 9260 §8.4, rule 3; net/sctp/sm_statefuns.c:
// sctp_sf_do_5_1B_init hands an INIT that only the control socket
// received to sctp_sf_tabort_8_4_8). The analyzer requires both INITs
// in the capture: the capture holds each interface's packets in the order
// they crossed it, so the sentinel proves that every packet before it is
// there, and the claims that rest on the absence of a packet are checked
// only up to it.
func sentinelClient(s *hostStep) {
	for i := range s.h.peer {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := Dial(ctx, "sctp4", wireAddr(0, s.h.local[i]), wireAddr(s.port, s.h.peer[i]))
		cancel()
		if err == nil {
			_ = c.Abort()
			s.t.Fatalf("Dial to %v:%d succeeded; the server listens there", s.h.peer[i], s.port)
		}
		wantDialError(s.t, err, syscall.ECONNREFUSED)
	}
}

// --- AbandonPolicy: an abandoned setup in COOKIE-WAIT and in COOKIE-ECHOED

// abandonServer listens, and drops on its INPUT hook the client's setup
// packets: all of them for COOKIE-WAIT, so the INIT is never answered and
// the client stays in COOKIE-WAIT; only the COOKIE ECHO for COOKIE-ECHOED,
// so the INIT ACK goes out and the client stays in COOKIE-ECHOED (RFC 9260
// §5.1).
func abandonServer(echoed bool) func(*hostStep) {
	return func(s *hostStep) {
		l := s.listen(nil, s.port, s.h.local[0])
		match := []string{"--dport", portArg(s.port)}
		if echoed {
			match = append(match, "--chunk-types", "any", "COOKIE_ECHO")
		}
		drop := s.dropInput(match...)
		s.send("ready")
		s.expect("done")
		n := drop.lift()
		if n == 0 {
			s.t.Error("the INPUT drop matched no packet: the client's setup never reached this host")
		}
		s.fact("dropped", n)
		// The dropped setup left no association to accept here.
		if err := l.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			s.t.Fatalf("listener deadline: %v", err)
		}
		if c, err := l.AcceptSCTP(); err == nil {
			_ = c.Abort()
			s.t.Error("an association was accepted from a setup this host never completed")
		} else if !errors.Is(err, os.ErrDeadlineExceeded) {
			s.t.Errorf("AcceptSCTP: %v", err)
		}
	}
}

// abandonClient dials with policy under a context that ends 500 ms in,
// long after the setup has reached the state the server holds it in, and
// well before the first INIT or COOKIE ECHO retransmission (T1 starts at
// net.sctp.rto_initial, 3 s by default).
func abandonClient(policy AbandonPolicy) func(*hostStep) {
	return func(s *hostStep) {
		s.expect("ready")
		deadline := time.Now().Add(500 * time.Millisecond)
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		c, err := (&Config{AbandonPolicy: policy}).Dial(ctx, "sctp4", wireAddr(0, s.h.local[0]), wireAddr(s.port, s.h.peer[0]))
		returned := time.Now()
		s.fact("deadline_ns", deadline.UnixNano())
		s.fact("return_ns", returned.UnixNano())
		s.fact("policy", policy)
		if err == nil {
			_ = c.Abort()
			s.t.Fatal("Dial succeeded against a peer that drops the setup")
		}
		wantDialError(s.t, err, context.DeadlineExceeded)
		// Leave time for a chunk sent late, which there must not be, to
		// reach the capture.
		time.Sleep(time.Second)
		s.send("done")
	}
}

// --- Abort during a pending Close ------------------------------------------------

// silentServer accepts count associations, on the case's port and the
// ones after it, and when the client asks drops on its INPUT hook every
// packet the client sends them, so that no SHUTDOWN is answered and the
// client's Close waits. It keeps its associations until the client is
// done, then aborts them: the client's own ABORT never arrived.
func silentServer(count int) func(*hostStep) {
	return func(s *hostStep) {
		var ls []*Listener
		for i := range count {
			ls = append(ls, s.listen(nil, s.port+uint16(i), s.h.local[0]))
		}
		s.send("ready")
		var conns []*Conn
		for _, l := range ls {
			conns = append(conns, s.accept(l))
		}
		s.expect("silence")
		var drops []*inputDrop
		for i := range count {
			drops = append(drops, s.dropInput("--dport", portArg(s.port+uint16(i))))
		}
		s.send("silent")
		s.expect("done")
		for i, d := range drops {
			n := d.lift()
			if n == 0 {
				s.t.Errorf("the INPUT drop for port %d matched no packet: the client's SHUTDOWN never came", s.port+uint16(i))
			}
			s.fact(fmt.Sprintf("dropped_%d", i), n)
		}
		for _, c := range conns {
			_ = c.Abort()
		}
	}
}

// abortDuringClose calls closeFn, which must stay waiting for a peer that
// never answers, calls abortFn from another goroutine half a second later,
// and records when each was called and returned. The analyzer checks that
// the capture holds the ABORT less than 100 ms after the Abort call, and
// nothing from the client at the moment the grace period would have run
// out (RFC 9260 §§9.1, 9.2).
func abortDuringClose(s *hostStep, closeFn, abortFn func() error) {
	s.t.Helper()
	type result struct {
		err error
		at  time.Time
	}
	closed := make(chan result, 1)
	closeCall := time.Now()
	go func() {
		err := closeFn()
		closed <- result{err, time.Now()}
	}()
	s.fact("close_ns", closeCall.UnixNano())
	s.fact("grace_ns", wireGrace.Nanoseconds())
	time.Sleep(500 * time.Millisecond)
	select {
	case r := <-closed:
		s.t.Fatalf("Close returned %v with its peer silent, before the Abort", r.err)
	default:
	}
	abortCall := time.Now()
	err := abortFn()
	abortReturn := time.Now()
	s.fact("abort_ns", abortCall.UnixNano())
	s.fact("abort_return_ns", abortReturn.UnixNano())
	if err != nil {
		s.t.Errorf("Abort during Close: %v, want nil", err)
	}
	var r result
	select {
	case r = <-closed:
	case <-time.After(wireGrace):
		s.t.Fatal("Close still waits a whole grace period after the Abort")
	}
	s.fact("close_return_ns", r.at.UnixNano())
	if r.err != nil {
		s.t.Errorf("Close overtaken by Abort returned %v, want nil", r.err)
	}
	// Stay until well past the moment the grace period would have run out,
	// so that the capture covers it.
	time.Sleep(time.Until(closeCall.Add(wireGrace + 700*time.Millisecond)))
	s.send("done")
}

func abortDuringCloseClient(s *hostStep) {
	s.expect("ready")
	c := s.dialA(&Config{CloseTimeout: wireGrace})
	s.send("silence")
	s.expect("silent")
	abortDuringClose(s, c.Close, c.Abort)
}

// abortDuringPeeledCloseClient is abortDuringCloseClient on a connection
// peeled off an Endpoint, whose Close starts the shutdown with an
// SCTP_EOF send.
func abortDuringPeeledCloseClient(s *hostStep) {
	s.expect("ready")
	e := s.endpointA(&Config{CloseTimeout: wireGrace})
	c := s.peel(e, s.connect(e, s.port))
	s.send("silence")
	s.expect("silent")
	abortDuringClose(s, c.Close, c.Abort)
}

// abortDuringEndpointCloseClient is the same for Endpoint.Close with two
// associations.
func abortDuringEndpointCloseClient(s *hostStep) {
	s.expect("ready")
	e := s.endpointA(&Config{CloseTimeout: wireGrace})
	s.connect(e, s.port)
	s.connect(e, s.port+1)
	s.send("silence")
	s.expect("silent")
	abortDuringClose(s, e.Close, e.Abort)
}

// --- Close with a full send buffer ---------------------------------------------

// drainingServer accepts count associations with a small receive window
// and reads nothing until the client, whose send buffer is then full, has
// called Close; a second later it reads every association to io.EOF and
// checks that every queued message arrived, in order.
func drainingServer(count int) func(*hostStep) {
	return func(s *hostStep) {
		cfg := &Config{ReadBuffer: new(wireSmallBuffer)}
		var ls []*Listener
		for i := range count {
			ls = append(ls, s.listen(cfg, s.port+uint16(i), s.h.local[0]))
		}
		s.send("ready")
		var conns []*Conn
		for _, l := range ls {
			conns = append(conns, s.accept(l))
		}
		queued := s.expectInts("full")
		if len(queued) != count {
			s.t.Fatalf("the client reported %d counts, want %d", len(queued), count)
		}
		s.expect("closing")
		time.Sleep(time.Second)
		s.fact("drain_ns", time.Now().UnixNano())
		// Every association drains at once, as independent peers would.
		got := make([][]wireRecv, count)
		errs := make([]error, count)
		var wg sync.WaitGroup
		for i, c := range conns {
			wg.Go(func() { got[i], errs[i] = readMessagesToEOF(c) })
		}
		wg.Wait()
		eof := 1
		for i := range conns {
			s.fact(fmt.Sprintf("received_%d", i), len(got[i]))
			if errs[i] != nil {
				eof = 0
			}
		}
		s.fact("eof", eof)
		for i := range conns {
			if errs[i] != nil {
				s.t.Fatalf("association %d: %v", i, errs[i])
			}
			for n, m := range got[i] {
				if numberOf(m.data) != n || m.info.PPID != wirePPIDFill {
					s.t.Fatalf("association %d: message %d carries number %d, PPID %#x", i, n, numberOf(m.data), m.info.PPID)
				}
			}
			if int64(len(got[i])) != queued[i] {
				s.t.Errorf("association %d: %d messages arrived before io.EOF, want the %d queued", i, len(got[i]), queued[i])
			}
		}
		s.send("drained")
	}
}

// closeWhileFull calls closeFn while the send buffer is full, tells the
// server, which starts reading a second later, and requires the graceful
// outcome: Close returns nil once the peer has drained the queue and
// completed the shutdown, within the grace period. The client's short
// retransmission timeout keeps the probing of the closed window (RFC 9260
// §6.1 rule A) from backing off for seconds. The SCTP_EOF send
// that starts the shutdown on a one-to-many or peeled socket never waits
// for buffer space (net/sctp/socket.c: sctp_sendmsg_check_sflags starts
// the SHUTDOWN primitive and returns before sctp_sendmsg_to_asoc), and the
// kernel holds the SHUTDOWN until the queue is acknowledged (RFC 9260
// §9.2, SHUTDOWN-PENDING).
func closeWhileFull(s *hostStep, closeFn func() error, queued ...int) {
	s.t.Helper()
	words := []any{"full"}
	for _, n := range queued {
		words = append(words, n)
	}
	s.send(words...)
	for i, n := range queued {
		s.fact(fmt.Sprintf("queued_%d", i), n)
	}
	s.fact("grace_ns", wireDrainGrace.Nanoseconds())
	closed := make(chan error, 1)
	closeCall := time.Now()
	go func() { closed <- closeFn() }()
	s.fact("close_ns", closeCall.UnixNano())
	s.send("closing")
	var err error
	select {
	case err = <-closed:
	case <-time.After(2 * wireDrainGrace):
		s.t.Fatal("Close still waits two grace periods after it was called")
	}
	closeReturn := time.Now()
	s.fact("close_return_ns", closeReturn.UnixNano())
	if err != nil {
		s.t.Errorf("Close with a full send buffer: %v, want nil", err)
	}
	if d := closeReturn.Sub(closeCall); d >= wireDrainGrace {
		s.t.Errorf("Close took %v, a whole grace period: it aborted instead of completing the shutdown", d)
	}
	s.expect("drained")
}

func peeledCloseFullBufferClient(s *hostStep) {
	s.expect("ready")
	e := s.endpointA(&Config{CloseTimeout: wireDrainGrace, RTOInfo: wireFastRTO, WriteBuffer: new(wireSmallBuffer)})
	c := s.peel(e, s.connect(e, s.port))
	n := s.fillNoWait(c.SendMsg, wirePPIDFill, 1000)
	closeWhileFull(s, c.Close, n)
}

func endpointCloseFullBuffersClient(s *hostStep) {
	s.expect("ready")
	// The two associations share the endpoint's send buffer (Linux's
	// net.sctp.sndbuf_policy 0), which is four times the peeled case's, so
	// that sending to each in turn fills it only once both peers' windows
	// are closed and both associations have messages waiting.
	e := s.endpointA(&Config{CloseTimeout: wireDrainGrace, RTOInfo: wireFastRTO, WriteBuffer: new(4 * wireSmallBuffer)})
	ids := []AssocID{s.connect(e, s.port), s.connect(e, s.port+1)}
	queued := make([]int, len(ids))
	for i := 0; ; i++ {
		k := i % len(ids)
		_, err := e.SendMsg(ids[k], wireMessage(queued[k], 1000), SendOptions{Info: &SndInfo{PPID: wirePPIDFill}, NoWait: true})
		if errors.Is(err, syscall.EAGAIN) {
			break
		}
		if err != nil {
			s.t.Fatalf("NoWait send %d: %v", i, err)
		}
		queued[k]++
		if i > 1<<16 {
			s.t.Fatal("the send buffer never filled")
		}
	}
	for i, n := range queued {
		if n == 0 {
			s.t.Fatalf("association %d had no message queued when the buffer filled", i)
		}
	}
	closeWhileFull(s, e.Close, queued...)
}

// --- SndInfo flags on the wire ----------------------------------------------------

func sackImmediatelyServer(s *hostStep) {
	s.wantPPIDs(s.serveUntilEOF(nil, s.h.local[0]), wirePPIDPlain, wirePPIDSACKNow)
}

// sackImmediatelyClient sends one message without and one with
// SendSACKImmediately, which is the I bit of the DATA chunk (RFC 9260
// §§3.3.1, 11.1.5).
func sackImmediatelyClient(s *hostStep) {
	s.expect("ready")
	c := s.dialA(nil)
	s.mustSend(c, []byte("without the I bit"), SendOptions{Info: &SndInfo{PPID: wirePPIDPlain}})
	s.mustSend(c, []byte("with the I bit"), SendOptions{Info: &SndInfo{PPID: wirePPIDSACKNow, Flags: SendSACKImmediately}})
	s.closeGracefully(c)
}

func unorderedServer(s *hostStep) {
	by := s.wantPPIDs(s.serveUntilEOF(nil, s.h.local[0]), wirePPIDUnordered, wirePPIDOrdered, wirePPIDDefault)
	for ppid, want := range map[uint32]bool{wirePPIDUnordered: true, wirePPIDOrdered: false, wirePPIDDefault: true} {
		if got := by[ppid].info.Unordered; got != want {
			s.t.Errorf("PPID %#x arrived with Unordered %v, want %v", ppid, got, want)
		}
	}
}

// unorderedClient sends with the U bit (RFC 9260 §3.3.1) set per message,
// with an explicit SndInfo that leaves it clear, which replaces the
// default that sets it, and with only a PrInfo, so that the default
// SndInfo, flag included, applies: the package sends it explicitly, since
// Linux applies the default flags only to a message carrying neither
// SNDINFO nor PRINFO (net/sctp/socket.c: sctp_sendmsg_update_sinfo).
func unorderedClient(s *hostStep) {
	s.expect("ready")
	c := s.dialA(&Config{DefaultSndInfo: &SndInfo{Flags: SendUnordered, PPID: wirePPIDDefault}})
	if ok, err := c.PRSupported(); err != nil || !ok {
		s.t.Fatalf("PRSupported = %v, %v; the PR-only send needs PR-SCTP negotiated", ok, err)
	}
	s.mustSend(c, []byte("unordered per message"), SendOptions{Info: &SndInfo{PPID: wirePPIDUnordered, Flags: SendUnordered}})
	s.mustSend(c, []byte("explicit SndInfo, ordered"), SendOptions{Info: &SndInfo{PPID: wirePPIDOrdered}})
	s.mustSend(c, []byte("PR only, the default SndInfo"), SendOptions{PR: &PrInfo{Policy: PRTTL, TTL: time.Minute}})
	s.closeGracefully(c)
}

// --- paths: RequestHeartbeat and SendOptions.Path ---------------------------------

// twoHomedServer listens on both of its addresses and reads until the
// client's graceful close.
func twoHomedServer(s *hostStep) {
	got := s.serveUntilEOF(nil, s.h.local[:]...)
	for i, m := range got {
		s.fact(fmt.Sprintf("ppid_%d", i), fmt.Sprintf("%#x", m.info.PPID))
	}
}

// requestHeartbeatClient turns periodic heartbeats off on the association
// and every path, and checks that each path reports them off, so that
// every HEARTBEAT that follows answers a request: the heartbeat timer then
// sends nothing (net/sctp/sm_statefuns.c: sctp_sf_sendbeat_8_3 sends only
// with SPP_HB_ENABLE), while a demanded heartbeat is sent regardless of
// that flag (net/sctp/socket.c: sctp_apply_peer_addr_params issues the
// REQUESTHEARTBEAT primitive for SPP_HB_DEMAND before, and apart from, the
// SPP_HB_ENABLE and SPP_HB_DISABLE handling). It then marks three windows
// for the analyzer: one with no request, one after RequestHeartbeat for
// the server's network B address, and one after RequestHeartbeat for the
// zero address, which asks for a HEARTBEAT on every path (RFC 9260 §8.3;
// RFC 6458 §8.1.12, SPP_HB_DEMAND; sctp_setsockopt_peer_addr_params
// applies an association-wide request to each transport).
func requestHeartbeatClient(s *hostStep) {
	s.expect("ready")
	c := s.twoHomedDial(&Config{RTOInfo: wireFastRTO})
	if err := c.SetPathParams(netip.Addr{}, &PathParams{Heartbeat: new(false)}); err != nil {
		s.t.Fatalf("SetPathParams(heartbeats off): %v", err)
	}
	for _, p := range s.h.peer {
		pp, err := c.PathParams(p)
		if err != nil {
			s.t.Fatalf("PathParams(%v): %v", p, err)
		}
		if pp.Heartbeat == nil || *pp.Heartbeat {
			s.t.Fatalf("PathParams(%v).Heartbeat = %v after turning heartbeats off", p, pp.Heartbeat)
		}
	}
	// Any heartbeat already under way is answered by now.
	time.Sleep(500 * time.Millisecond)
	window := func(name string, request func() error) {
		start := time.Now()
		if err := request(); err != nil {
			s.t.Fatalf("%s: RequestHeartbeat: %v", name, err)
		}
		time.Sleep(400 * time.Millisecond)
		s.fact(name+"_start_ns", start.UnixNano())
		s.fact(name+"_end_ns", time.Now().UnixNano())
	}
	window("quiet", func() error { return nil })
	window("one", func() error { return c.RequestHeartbeat(s.h.peer[1]) })
	window("every", func() error { return c.RequestHeartbeat(netip.Addr{}) })
	s.closeGracefully(c)
}

// periodicHeartbeatClient leaves a confirmed two-path association idle
// while Linux sends timer-driven probes on both paths (RFC 9260 §8.3;
// net/sctp/transport.c: sctp_transport_timeout,
// sctp_transport_reset_hb_timer).
func periodicHeartbeatClient(s *hostStep) {
	s.expect("ready")
	rto := wireFastRTO
	c := s.twoHomedDial(&Config{RTOInfo: rto})
	const interval = time.Second
	if err := c.SetPathParams(netip.Addr{}, &PathParams{Heartbeat: new(true), HeartbeatInterval: new(interval)}); err != nil {
		s.t.Fatalf("SetPathParams(periodic heartbeats): %v", err)
	}
	for _, p := range s.h.peer {
		params, err := c.PathParams(p)
		if err != nil {
			s.t.Fatalf("PathParams(%v): %v", p, err)
		}
		if params.Heartbeat == nil || !*params.Heartbeat || params.HeartbeatInterval == nil || *params.HeartbeatInterval != interval {
			s.t.Fatalf("PathParams(%v) = %+v, want heartbeats every %v", p, params, interval)
		}
		info, err := c.PathInfo(p)
		if err != nil {
			s.t.Fatalf("PathInfo(%v): %v", p, err)
		}
		if info.RTO < rto.Min || info.RTO > rto.Max {
			s.t.Fatalf("PathInfo(%v).RTO = %v, want %v..%v", p, info.RTO, rto.Min, rto.Max)
		}
	}
	s.fact("interval_ns", interval.Nanoseconds())
	s.fact("rto_min_ns", rto.Min.Nanoseconds())
	s.fact("rto_max_ns", rto.Max.Nanoseconds())
	s.fact("start_ns", time.Now().UnixNano())
	time.Sleep(4500 * time.Millisecond)
	s.fact("end_ns", time.Now().UnixNano())
	s.closeGracefully(c)
}

// enableWireInterleaving sets the network namespace's I-DATA switch for
// this case and restores its previous value at the end.
func enableWireInterleaving(t *testing.T) {
	t.Helper()
	const path = "/proc/sys/net/sctp/intl_enable"
	previous, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		t.Fatalf("enabling %s: %v", path, err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(path, previous, 0o644); err != nil {
			t.Errorf("restoring %s: %v", path, err)
		}
	})
}

func interleavingConfig() *Config {
	return &Config{MessageInterleaving: true, FragmentInterleave: new(InterleaveAssocs),
		WriteBuffer: new(256 << 10), RTOInfo: wireFastRTO, CloseTimeout: 15 * time.Second}
}

func interleavingServer(s *hostStep) {
	enableWireInterleaving(s.t)
	l := s.listen(interleavingConfig(), s.port, s.h.local[0])
	s.send("ready")
	c := s.accept(l)
	drop := s.dropInput("--dport", portArg(s.port))
	s.send("drop-ready")
	s.expect("queued")
	// Keep the first congestion window unacknowledged until both messages
	// have entered the sender's scheduler.
	time.Sleep(100 * time.Millisecond)
	if n := drop.lift(); n == 0 {
		s.t.Fatal("the INPUT drop matched no packet before both messages were queued")
	} else {
		s.fact("dropped", n)
	}
	got, err := readMessagesToEOF(c)
	s.recordEnd(got, err)
	if len(got) != 2 {
		s.t.Fatalf("received %d messages, want two", len(got))
	}
	seen := [2]bool{}
	for _, m := range got {
		stream := int(m.info.Stream)
		if stream > 1 || seen[stream] || m.info.PPID != wirePPIDInterleave+uint32(stream) ||
			!bytes.Equal(m.data, wireMessage(stream, 32<<10)) {
			s.t.Fatalf("message on stream %d: PPID %#x, size %d, content matches %v", stream, m.info.PPID, len(m.data), bytes.Equal(m.data, wireMessage(stream, 32<<10)))
		}
		seen[stream] = true
	}
}

// interleavingClient queues two fragmented messages on different streams.
// RFC 8260 §§2.1-2.2 permits their fragments to interleave as I-DATA.
func interleavingClient(s *hostStep) {
	enableWireInterleaving(s.t)
	s.expect("ready")
	c := s.dialA(interleavingConfig())
	if err := c.SetStreamScheduler(SchedRR); err != nil {
		s.t.Fatalf("SetStreamScheduler(SchedRR): %v", err)
	}
	s.expect("drop-ready")
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for stream := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.SendMsg(wireMessage(stream, 32<<10), SendOptions{
				Info: &SndInfo{Stream: uint16(stream), PPID: wirePPIDInterleave + uint32(stream)},
			})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			s.t.Fatalf("sending interleaved messages: %v", err)
		}
	}
	s.send("queued")
	s.closeGracefully(c)
}

// pathClient sends messages alternately to the primary path, the kernel's
// choice, and with SendOptions.Path set to the server's network B address
// (RFC 6458 §5.3.4, SCTP_ADDR_OVER's use of the destination address).
func pathClient(s *hostStep) {
	s.expect("ready")
	c := s.twoHomedDial(&Config{RTOInfo: wireFastRTO})
	const each = 5
	for i := range each {
		s.mustSend(c, wireMessage(i, 100), SendOptions{Info: &SndInfo{PPID: wirePPIDPrimary}})
		s.mustSend(c, wireMessage(i, 100), SendOptions{Info: &SndInfo{PPID: wirePPIDPath}, Path: s.h.peer[1]})
	}
	s.fact("each", each)
	s.closeGracefully(c)
}

// --- NoWait, More, PPID --------------------------------------------------------------

func noWaitServer(s *hostStep) {
	l := s.listen(&Config{ReadBuffer: new(wireSmallBuffer)}, s.port, s.h.local[0])
	s.send("ready")
	c := s.accept(l)
	queued := s.expectInts("refused")
	// Drain everything the client queued, and its last message after it.
	setReadDeadline(s.t, c, wireStepWait)
	fills := 0
	for {
		b, info, err := c.ReadMsg(1 << 16)
		if err != nil {
			s.t.Fatalf("ReadMsg after %d messages: %v", fills, err)
		}
		if info.PPID == wirePPIDLast {
			break
		}
		if info.PPID != wirePPIDFill || numberOf(b) != fills {
			s.fact("received_fill", fills)
			s.t.Fatalf("message %d: PPID %#x, number %d; the refused message must never arrive", fills, info.PPID, numberOf(b))
		}
		fills++
	}
	if len(queued) != 1 || int64(fills) != queued[0] {
		s.t.Errorf("%d queued messages arrived, the client queued %v", fills, queued)
	}
	s.fact("received_fill", fills)
	s.send("drained")
	if got := s.readUntilEOF(c); len(got) != 0 {
		s.t.Errorf("%d more messages arrived after the last one", len(got))
	}
}

// noWaitClient fills the send buffer while the server reads nothing, then
// makes one more NoWait send, which must be refused with EAGAIN and put
// nothing on the wire: Linux waits for, or refuses, buffer space before it
// builds the message (net/sctp/socket.c: sctp_sendmsg_to_asoc).
func noWaitClient(s *hostStep) {
	s.expect("ready")
	c := s.dialA(&Config{WriteBuffer: new(wireSmallBuffer)})
	n := s.fillNoWait(c.SendMsg, wirePPIDFill, 1000)
	s.fact("queued", n)
	s.fact("refused_ns", time.Now().UnixNano())
	_, err := c.SendMsg(wireMessage(1<<20, 100), SendOptions{Info: &SndInfo{PPID: wirePPIDRefused}, NoWait: true})
	wantWriteError(s.t, err, syscall.EAGAIN)
	s.send("refused", n)
	// The last message waits for the room the server's reading makes.
	s.mustSend(c, []byte("last"), SendOptions{Info: &SndInfo{PPID: wirePPIDLast}})
	s.expect("drained")
	s.closeGracefully(c)
}

func moreServer(s *hostStep) {
	s.wantPPIDs(s.serveUntilEOF(nil, s.h.local[0]), wirePPIDAlone1, wirePPIDAlone2, wirePPIDMore1, wirePPIDMore2)
}

// moreClient sends two pairs of small messages with NoDelay on: the first
// pair without More, which go out in two packets, the second with More on
// the first message, which Linux holds until the second arrives and
// bundles with it (MSG_MORE; net/sctp/socket.c: sctp_sendmsg_to_asoc sets
// force_delay, and net/sctp/output.c: sctp_packet_can_append_data delays
// a chunk while it is set).
func moreClient(s *hostStep) {
	s.expect("ready")
	c := s.dialA(&Config{NoDelay: new(true)})
	s.mustSend(c, []byte("alone 1"), SendOptions{Info: &SndInfo{PPID: wirePPIDAlone1}})
	s.mustSend(c, []byte("alone 2"), SendOptions{Info: &SndInfo{PPID: wirePPIDAlone2}})
	// Both are acknowledged and nothing is in flight before the second pair.
	time.Sleep(500 * time.Millisecond)
	s.mustSend(c, []byte("more 1"), SendOptions{Info: &SndInfo{PPID: wirePPIDMore1}, More: true})
	s.mustSend(c, []byte("more 2"), SendOptions{Info: &SndInfo{PPID: wirePPIDMore2}})
	s.closeGracefully(c)
}

func ppidServer(s *hostStep) {
	got := s.serveUntilEOF(nil, s.h.local[0])
	for _, m := range got {
		if i := numberOf(m.data); i >= 0 && i < len(wireOrderPPIDs) {
			s.fact(fmt.Sprintf("api_ppid_%d", i), fmt.Sprintf("%#x", m.info.PPID))
		}
	}
	if len(got) != len(wireOrderPPIDs) {
		s.t.Fatalf("received %d messages, want %d", len(got), len(wireOrderPPIDs))
	}
	for _, m := range got {
		i := numberOf(m.data)
		if i < 0 || i >= len(wireOrderPPIDs) {
			s.t.Fatalf("message number %d", i)
		}
		// Host order through the API: the stack performs no byte order
		// conversion of rcv_ppid (RFC 6458 §5.3.5), Linux copies the
		// wire's bytes, and the package converts them.
		if m.info.PPID != wireOrderPPIDs[i] {
			s.t.Errorf("message %d arrived with PPID %#x, want %#x", i, m.info.PPID, wireOrderPPIDs[i])
		}
	}
}

// ppidClient sends a PPID through each path that carries one: an explicit
// SndInfo, twice, Write with a Config default (SCTP_DEFAULT_SNDINFO), and a
// PR-only send with a default set by SetDefaultSndInfo, which the package
// sends as an explicit SNDINFO.
func ppidClient(s *hostStep) {
	s.expect("ready")
	for i, p := range wireOrderPPIDs {
		s.fact(fmt.Sprintf("sent_ppid_%d", i), fmt.Sprintf("%#x", p))
	}
	c := s.dialA(&Config{DefaultSndInfo: &SndInfo{PPID: wireOrderPPIDs[2]}})
	s.mustSend(c, wireMessage(0, 64), SendOptions{Info: &SndInfo{PPID: wireOrderPPIDs[0]}})
	s.mustSend(c, wireMessage(1, 64), SendOptions{Info: &SndInfo{Stream: 1, PPID: wireOrderPPIDs[1]}})
	if _, err := c.Write(wireMessage(2, 64)); err != nil {
		s.t.Fatalf("Write: %v", err)
	}
	if err := c.SetDefaultSndInfo(&SndInfo{PPID: wireOrderPPIDs[3]}); err != nil {
		s.t.Fatalf("SetDefaultSndInfo: %v", err)
	}
	s.mustSend(c, wireMessage(3, 64), SendOptions{PR: &PrInfo{Policy: PRTTL, TTL: time.Minute}})
	s.closeGracefully(c)
}

// --- Close: after a burst, at both ends at once, gracefully ------------------------

// The burst of the close-after-burst case: 100 messages of 1000 bytes,
// against a receive window of 32 KiB, so that most of it is still queued
// when Close is called. The window and a send buffer of 256 KiB hold it all
// with room to spare, whatever each message costs the kernel on top of its
// payload.
const (
	wireBurst       = 100
	wireBurstWindow = 32 << 10
	wireBurstBuffer = 256 << 10
)

// burstServer reads nothing until the client has called Close, and then
// reads everything, to io.EOF.
func burstServer(s *hostStep) {
	l := s.listen(&Config{ReadBuffer: new(wireBurstWindow)}, s.port, s.h.local[0])
	s.send("ready")
	c := s.accept(l)
	s.expect("closing")
	time.Sleep(300 * time.Millisecond)
	got, err := readMessagesToEOF(c)
	s.recordEnd(got, err)
	if len(got) != wireBurst {
		s.t.Errorf("received %d messages before io.EOF, want all %d", len(got), wireBurst)
	}
	for i, m := range got {
		if numberOf(m.data) != i {
			s.t.Fatalf("message %d carries number %d", i, numberOf(m.data))
		}
	}
}

// burstClient queues a burst larger than the server's receive window, which
// the server does not open until after the Close call, and calls Close
// straight after the last send: Linux sends the SHUTDOWN only once every
// queued message is sent and acknowledged (RFC 9260 §9.2; net/sctp/
// sm_statefuns.c: sctp_sf_do_9_2_prm_shutdown enters SHUTDOWN-PENDING).
func burstClient(s *hostStep) {
	s.expect("ready")
	c := s.dialA(&Config{WriteBuffer: new(wireBurstBuffer)})
	// The burst fits in the window and the send buffer together, so no send
	// waits for the server, which reads only after the Close call; the
	// deadline fails the case at once if one does.
	if err := c.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		s.t.Fatalf("SetWriteDeadline: %v", err)
	}
	for i := range wireBurst {
		s.mustSend(c, wireMessage(i, 1000), SendOptions{Info: &SndInfo{PPID: wirePPIDBurst}})
	}
	s.send("closing")
	s.fact("count", wireBurst)
	s.fact("close_ns", time.Now().UnixNano())
	s.closeGracefully(c)
}

// simultaneousClose has each side drop the other's SHUTDOWN on its INPUT
// hook, so that each end's Close sends its SHUTDOWN before it sees the
// other's and both are in SHUTDOWN-SENT at once (RFC 9260 §9.2). The drops
// are lifted once both SHUTDOWNs are out, and the retransmitted ones
// (T2-shutdown) cross. Both Close calls must complete gracefully.
func simultaneousClose(s *hostStep, c *Conn, dir string) {
	s.t.Helper()
	drop := s.dropInput(dir, portArg(s.port), "--chunk-types", "any", "SHUTDOWN")
	s.send("armed")
	s.expect("armed")
	// The server names an instant and both sides close then; the two
	// containers read one kernel clock.
	var at time.Time
	if s.h.server {
		at = time.Now().Add(200 * time.Millisecond)
		s.send("at", at.UnixNano())
	} else {
		at = time.Unix(0, s.expectInts("at")[0])
	}
	time.Sleep(time.Until(at))
	closed := make(chan error, 1)
	closeCall := time.Now()
	go func() { closed <- c.Close() }()
	role := s.h.role()
	s.fact(role+"_close_ns", closeCall.UnixNano())
	time.Sleep(300 * time.Millisecond)
	n := drop.lift()
	s.fact(role+"_dropped", n)
	if n == 0 {
		s.t.Errorf("the drop matched no SHUTDOWN: the %s's SHUTDOWN never came while this side was closing", s.h.peerRole())
	}
	var err error
	select {
	case err = <-closed:
	case <-time.After(2 * wireGrace):
		s.t.Fatal("Close still waits two grace periods after it was called")
	}
	if err != nil {
		s.t.Errorf("Close: %v, want nil", err)
	}
	if d := time.Since(closeCall); d >= wireGrace+300*time.Millisecond {
		s.t.Errorf("Close took %v, a whole grace period: it aborted instead of completing the shutdown", d)
	}
	s.send("closed")
	s.expect("closed")
}

func simultaneousCloseServer(s *hostStep) {
	l := s.listen(&Config{RTOInfo: wireFastRTO, CloseTimeout: wireGrace}, s.port, s.h.local[0])
	s.send("ready")
	simultaneousClose(s, s.accept(l), "--dport")
}

func simultaneousCloseClient(s *hostStep) {
	s.expect("ready")
	simultaneousClose(s, s.dialA(&Config{RTOInfo: wireFastRTO, CloseTimeout: wireGrace}), "--sport")
}

func gracefulServer(s *hostStep) {
	s.wantPPIDs(s.serveUntilEOF(nil, s.h.local[0]), wirePPIDGraceful)
}

// gracefulClient sends one message and closes: SHUTDOWN, SHUTDOWN ACK,
// SHUTDOWN COMPLETE (RFC 9260 §9.2).
func gracefulClient(s *hostStep) {
	s.expect("ready")
	c := s.dialA(nil)
	s.mustSend(c, []byte("before the close"), SendOptions{Info: &SndInfo{PPID: wirePPIDGraceful}})
	s.fact("close_ns", time.Now().UnixNano())
	s.closeGracefully(c)
}

// gracefulPeeledClient is gracefulClient on a peeled connection, whose
// Close starts the shutdown with an SCTP_EOF send.
func gracefulPeeledClient(s *hostStep) {
	s.expect("ready")
	e := s.endpointA(nil)
	c := s.peel(e, s.connect(e, s.port))
	s.mustSend(c, []byte("before the close"), SendOptions{Info: &SndInfo{PPID: wirePPIDGraceful}})
	s.fact("close_ns", time.Now().UnixNano())
	s.closeGracefully(c)
}

// --- PR-SCTP: the retransmission limit ------------------------------------------------

func prRtxServer(s *hostStep) {
	l := s.listen(nil, s.port, s.h.local[0])
	s.send("ready")
	c := s.accept(l)
	s.expect("silence")
	drop := s.dropInput("--dport", portArg(s.port))
	s.send("silent")
	s.expect("abandoned")
	n := drop.lift()
	if n == 0 {
		s.t.Error("the INPUT drop matched no packet: the message never came")
	}
	s.fact("dropped", n)
	// The FORWARD TSN moves this end past the abandoned message (RFC 3758
	// §3.6), which is never delivered: the next message is the first.
	b, info := recvWithin(s.t, c, wireStepWait)
	if info.PPID != wirePPIDAfter {
		s.t.Errorf("the first message delivered is %q with PPID %#x, want the one sent after the abandoned one", b, info.PPID)
	}
	s.fact("first_delivered_ppid", fmt.Sprintf("%#x", info.PPID))
	s.send("received")
	if got := s.readUntilEOF(c); len(got) != 0 {
		s.t.Errorf("%d more messages arrived", len(got))
	}
}

// prRtxClient sends one message with a PRRtx limit of 2 while the server
// drops everything: Linux abandons it at the T3-rtx expiry that finds it
// sent more times than the limit (net/sctp/chunk.c: sctp_chunk_abandoned,
// sent_count > limit; net/sctp/outqueue.c: sctp_retransmit_mark), so it is
// on the wire exactly three times, and PRStreamStatus counts it as
// abandoned after being sent (RFC 7496 §§4.3, 4.4).
func prRtxClient(s *hostStep) {
	s.expect("ready")
	c := s.dialA(&Config{RTOInfo: wireFastRTO})
	if ok, err := c.PRSupported(); err != nil || !ok {
		s.t.Fatalf("PRSupported = %v, %v; want PR-SCTP negotiated", ok, err)
	}
	const (
		stream = 1
		limit  = 2
	)
	s.send("silence")
	s.expect("silent")
	s.fact("limit", limit)
	s.fact("sent_ns", time.Now().UnixNano())
	s.mustSend(c, []byte("abandoned after two retransmissions"), SendOptions{
		Info: &SndInfo{Stream: stream, PPID: wirePPIDAbandoned},
		PR:   &PrInfo{Policy: PRRtx, Value: limit},
	})
	deadline := time.Now().Add(10 * time.Second)
	var st *PRStatus
	for {
		var err error
		if st, err = c.PRStreamStatus(stream, PRRtx); err != nil {
			s.t.Fatalf("PRStreamStatus: %v", err)
		}
		if st.AbandonedSent+st.AbandonedUnsent != 0 {
			break
		}
		if time.Now().After(deadline) {
			s.t.Fatal("the message is not abandoned 10 s after it was sent")
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.fact("abandoned_ns", time.Now().UnixNano())
	s.fact("stream_abandoned_sent", st.AbandonedSent)
	s.fact("stream_abandoned_unsent", st.AbandonedUnsent)
	if *st != (PRStatus{AbandonedSent: 1}) {
		s.t.Errorf("PRStreamStatus(%d, PRRtx) = %+v, want one message abandoned after being sent", stream, *st)
	}
	assoc, err := c.PRAssocStatus(PRRtx)
	if err != nil {
		s.t.Fatalf("PRAssocStatus: %v", err)
	}
	s.fact("assoc_abandoned_sent", assoc.AbandonedSent)
	if *assoc != *st {
		s.t.Errorf("PRAssocStatus(PRRtx) = %+v, want the stream's %+v", *assoc, *st)
	}
	s.send("abandoned")
	s.mustSend(c, []byte("after"), SendOptions{Info: &SndInfo{Stream: stream, PPID: wirePPIDAfter}})
	s.expect("received")
	s.closeGracefully(c)
}
