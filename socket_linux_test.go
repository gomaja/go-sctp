// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"bufio"
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
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// --- helpers shared by the Linux socket tests ------------------------------

// loopback4 is 127.0.0.1 with port.
func loopback4(port uint16) *Addr {
	return &Addr{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Port: port}
}

// mustListen listens with cfg and closes the listener on cleanup.
func mustListen(t testing.TB, cfg *Config, network string, laddr *Addr) *Listener {
	t.Helper()
	l, err := cfg.Listen(network, laddr)
	if err != nil {
		t.Fatalf("Listen(%q, %v): %v", network, laddr, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

// listenerAddr is l's Addr snapshot as an *Addr.
func listenerAddr(t testing.TB, l *Listener) *Addr {
	t.Helper()
	a, ok := l.Addr().(*Addr)
	if !ok || a == nil || a.Port == 0 {
		t.Fatalf("listener Addr = %#v, want an *Addr with a port", l.Addr())
	}
	return a
}

// testContext is a context that ends with the test, bounded to d.
func testContext(t testing.TB, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// dialAccept dials l with cfg and accepts the association on l. Both
// connections are aborted on cleanup, which is a no-op once a test has
// closed them itself.
func dialAccept(t testing.TB, cfg *Config, l *Listener) (client, server *Conn) {
	t.Helper()
	type result struct {
		c   *Conn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		c, err := l.AcceptSCTP()
		ch <- result{c, err}
	}()
	client, err := cfg.Dial(testContext(t, 10*time.Second), "sctp4", nil, listenerAddr(t, l))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Abort() })
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("AcceptSCTP: %v", r.err)
		}
		server = r.c
	case <-time.After(10 * time.Second):
		t.Fatal("AcceptSCTP did not return within 10 s of a successful Dial")
	}
	t.Cleanup(func() { _ = server.Abort() })
	return client, server
}

// connPair sets up one association over 127.0.0.1, the client from
// clientCfg and the server accepted from a listener made with serverCfg.
func connPair(t testing.TB, clientCfg, serverCfg *Config) (client, server *Conn) {
	t.Helper()
	return dialAccept(t, clientCfg, mustListen(t, serverCfg, "sctp4", loopback4(0)))
}

// sendRaw sends b as one message through c's SyscallConn, waiting through
// the poller while the send buffer is full. The send path proper is
// separate from what these tests exercise; this is only a way to put
// messages on an association.
func sendRaw(c *Conn, b []byte) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Write(func(fd uintptr) bool {
		_, serr = syscall.SendmsgN(int(fd), b, nil, nil, syscall.MSG_DONTWAIT|syscall.MSG_NOSIGNAL)
		return serr != syscall.EAGAIN
	}); err != nil {
		return err
	}
	return serr
}

// sendRawOnce makes one send attempt and returns EAGAIN rather than wait.
func sendRawOnce(c *Conn, b []byte) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	var serr error
	if err := rc.Control(func(fd uintptr) {
		_, serr = syscall.SendmsgN(int(fd), b, nil, nil, syscall.MSG_DONTWAIT|syscall.MSG_NOSIGNAL)
	}); err != nil {
		return err
	}
	return serr
}

// fill returns n bytes of a repeating pattern.
func fill(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// fillSendBuffer sends payload until the socket refuses more with EAGAIN,
// and returns how many messages it accepted. The peer must not be reading.
func fillSendBuffer(t testing.TB, c *Conn, payload []byte) int {
	t.Helper()
	for i := 0; i < 1<<20; i++ {
		if err := sendRawOnce(c, payload); err != nil {
			if errors.Is(err, syscall.EAGAIN) {
				return i
			}
			t.Fatalf("send %d: %v", i, err)
		}
	}
	t.Fatalf("the send buffer never filled after 1048576 messages of %d bytes", len(payload))
	return 0
}

// openFds counts the descriptors this process holds.
func openFds(t testing.TB) int {
	t.Helper()
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(ents)
}

// fdIsOpen reports whether fd is an open descriptor in this process.
func fdIsOpen(fd int) bool {
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	return errno == 0
}

// isNonblocking reports whether fd has O_NONBLOCK set. A descriptor that
// cannot be queried reports false, so that a test asserting non-blocking
// mode fails rather than passes on it.
func isNonblocking(fd int) bool {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFL, 0)
	return errno == 0 && flags&syscall.O_NONBLOCK != 0
}

// isCloseOnExec reports whether fd has FD_CLOEXEC set.
func isCloseOnExec(fd int) bool {
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
	return errno == 0 && flags&syscall.FD_CLOEXEC != 0
}

// rawFd runs f with the descriptor behind rc.
func rawFd(t testing.TB, rc syscall.RawConn, f func(fd int)) {
	t.Helper()
	if err := rc.Control(func(fd uintptr) { f(int(fd)) }); err != nil {
		t.Fatalf("Control: %v", err)
	}
}

// unreachableAddr is TEST-NET-1 (RFC 5737), which the Linux suite routes
// to a dummy link so that an INIT sent there vanishes without an answer.
func unreachableAddr() *Addr {
	return &Addr{IPs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, Port: 9999}
}

var (
	silentPeerOnce sync.Once
	silentPeerOK   bool
	silentPeerWhy  string
)

// silentPeerAvailable reports whether an INIT to unreachableAddr is
// dropped rather than answered: only then does an association stay in
// COOKIE-WAIT long enough for a dial to be abandoned. A non-blocking
// connect reports EINPROGRESS either way, so SO_ERROR is watched for a
// moment for a refusal (an ICMP unreachable becomes ECONNREFUSED or
// similar).
func silentPeerAvailable(t testing.TB) bool {
	t.Helper()
	silentPeerOnce.Do(func() {
		fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, ipprotoSCTP)
		if err != nil {
			silentPeerWhy = fmt.Sprintf("socket: %v", err)
			return
		}
		defer func() { _ = syscall.Close(fd) }()
		addrs, err := encodeAddrs(afInet, unreachableAddr().IPs, unreachableAddr().Port)
		if err != nil {
			silentPeerWhy = err.Error()
			return
		}
		arg := connectx3Arg{addrNum: int32(len(addrs)), addrs: unsafe.Pointer(&addrs[0])}
		l := uint32(unsafe.Sizeof(arg))
		if err := rawGetsockopt(fd, ipprotoSCTP, optSockoptConnectx3, unsafe.Pointer(&arg), &l); err != syscall.EINPROGRESS {
			silentPeerWhy = fmt.Sprintf("connect to 192.0.2.1 gave %v, not EINPROGRESS", err)
			return
		}
		deadline := time.Now().Add(300 * time.Millisecond)
		for time.Now().Before(deadline) {
			soerr, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
			if err != nil || soerr != 0 {
				silentPeerWhy = fmt.Sprintf("192.0.2.1 answered (SO_ERROR %v, %v)", syscall.Errno(soerr), err)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		silentPeerOK = true
	})
	if !silentPeerOK {
		t.Logf("no silent peer: %s", silentPeerWhy)
	}
	return silentPeerOK
}

// countAssocs counts the associations the kernel holds, from
// /proc/net/sctp/assocs.
func countAssocs(t testing.TB) int {
	t.Helper()
	f, err := os.Open("/proc/net/sctp/assocs")
	if err != nil {
		t.Skipf("cannot read /proc/net/sctp/assocs: %v", err)
	}
	defer func() { _ = f.Close() }()
	n := 0
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "ASSOC") {
			continue
		}
		n++
	}
	if err := s.Err(); err != nil {
		t.Fatalf("scanning /proc/net/sctp/assocs: %v", err)
	}
	return n
}

// waitAssocsAtMost polls countAssocs until it is at most want or 5 s
// pass, and returns the last count: the kernel frees an aborted
// association within microseconds, but asynchronously.
func waitAssocsAtMost(t testing.TB, want int) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := countAssocs(t)
		if got <= want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// availableLoopbacks lists the loopback addresses among 127.0.0.1-4 that
// an SCTP socket can bind; the Linux suite adds 127.0.0.2-4.
func availableLoopbacks(t testing.TB) []string {
	t.Helper()
	var got []string
	for _, s := range []string{"127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"} {
		l, err := Listen("sctp4", &Addr{IPs: []netip.Addr{netip.MustParseAddr(s)}})
		if err != nil {
			continue
		}
		_ = l.Close()
		got = append(got, s)
	}
	return got
}

// requireLoopbacks skips unless n loopback addresses can be bound.
func requireLoopbacks(t testing.TB, n int) []string {
	t.Helper()
	got := availableLoopbacks(t)
	if len(got) < n {
		t.Skipf("only %d loopback addresses usable (%v); this test needs %d. "+
			"Add them with: ip addr add 127.0.0.N/8 dev lo", len(got), got, n)
	}
	return got
}

// addrOf builds an *Addr from textual IPs.
func addrOf(port uint16, ips ...string) *Addr {
	a := &Addr{Port: port}
	for _, s := range ips {
		a.IPs = append(a.IPs, netip.MustParseAddr(s))
	}
	return a
}

// ipStrings is a's IPs as sorted strings.
func ipStrings(a *Addr) []string {
	if a == nil {
		return nil
	}
	out := make([]string, 0, len(a.IPs))
	for _, ip := range a.IPs {
		out = append(out, ip.String())
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// sortedCopy returns a sorted copy of in.
func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sortStrings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// runChild re-executes the test binary for test alone with env added, so
// that a test can disturb process-wide state (stdin, the descriptor limit)
// in isolation, and returns the child's combined output.
func runChild(t testing.TB, test string, env ...string) (string, error) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("cannot locate the test binary: %v", err)
	}
	cmd := exec.Command(exe, "-test.run", "^"+test+"$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// getIntOpt reads an int socket option through rc.
func getIntOpt(t testing.TB, rc syscall.RawConn, level, opt int) int {
	t.Helper()
	var v int
	var err error
	rawFd(t, rc, func(fd int) { v, err = syscall.GetsockoptInt(fd, level, opt) })
	if err != nil {
		t.Fatalf("getsockopt(%d, %d): %v", level, opt, err)
	}
	return v
}

// getAssocValueOpt reads a struct sctp_assoc_value option for assoc.
func getAssocValueOpt(t testing.TB, rc syscall.RawConn, opt int, assoc AssocID) uint32 {
	t.Helper()
	var b [sizeAssocValue]byte
	binary.NativeEndian.PutUint32(b[assocValueAssocIDOff:], uint32(assoc))
	getRawOpt(t, rc, opt, b[:])
	return binary.NativeEndian.Uint32(b[assocValueValueOff:])
}

// getRawOpt reads SCTP option opt into b, which the caller has prepared.
func getRawOpt(t testing.TB, rc syscall.RawConn, opt int, b []byte) {
	t.Helper()
	var err error
	rawFd(t, rc, func(fd int) {
		l := uint32(len(b))
		err = rawGetsockopt(fd, ipprotoSCTP, opt, unsafe.Pointer(&b[0]), &l)
	})
	if err != nil {
		t.Fatalf("getsockopt(IPPROTO_SCTP, %d): %v", opt, err)
	}
}

// subscribedInKernel reads one SCTP_EVENT subscription through rc.
func subscribedInKernel(t testing.TB, rc syscall.RawConn, typ EventType) bool {
	t.Helper()
	var on bool
	var err error
	rawFd(t, rc, func(fd int) { on, err = getEvent(fd, typ) })
	if err != nil {
		t.Fatalf("SCTP_EVENT %v: %v", typ, err)
	}
	return on
}

// --- descriptor ownership ---------------------------------------------------

// TestSocketErrorReportsMissingSCTPAsUnsupported pins the mapping of
// socket(2)'s answer when the kernel has no SCTP: inet_create
// (net/ipv4/af_inet.c) answers EPROTONOSUPPORT, or ESOCKTNOSUPPORT, when
// it cannot load the module, and either must match both ErrUnsupported
// and the errno, while any other failure stays an *os.SyscallError. The
// kernel's own answer for a protocol it does not have is checked too,
// with a protocol number no kernel implements, since the SCTP module
// cannot be unloaded under a running suite.
func TestSocketErrorReportsMissingSCTPAsUnsupported(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EPROTONOSUPPORT, syscall.ESOCKTNOSUPPORT} {
		err := socketError(errno)
		if !errors.Is(err, ErrUnsupported) || !errors.Is(err, errors.ErrUnsupported) || !errors.Is(err, errno) {
			t.Errorf("socketError(%v) = %v, want it to match ErrUnsupported, errors.ErrUnsupported and %v", errno, err, errno)
		}
		opErr := opError("dial", "sctp", nil, nil, err)
		if !errors.Is(opErr, ErrUnsupported) || !errors.Is(opErr, errno) {
			t.Errorf("wrapped in *net.OpError: %v, want it to keep matching both", opErr)
		}
	}
	for _, errno := range []syscall.Errno{syscall.EMFILE, syscall.EAFNOSUPPORT} {
		err := socketError(errno)
		if errors.Is(err, ErrUnsupported) {
			t.Errorf("socketError(%v) = %v matches ErrUnsupported; only a missing protocol does", errno, err)
		}
		var se *os.SyscallError
		if !errors.As(err, &se) || se.Syscall != "socket" || !errors.Is(err, errno) {
			t.Errorf("socketError(%v) = %#v, want an *os.SyscallError for socket wrapping it", errno, err)
		}
	}

	// IPPROTO_RAW (255) is not a stream protocol anywhere; a stream socket
	// asking for it gets the same refusal a kernel without SCTP gives.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 255)
	if err == nil {
		_ = syscall.Close(fd)
		t.Fatal("socket(AF_INET, SOCK_STREAM, 255) succeeded")
	}
	if got := socketError(err); !errors.Is(got, ErrUnsupported) {
		t.Errorf("the kernel refused an unknown stream protocol with %v, which socketError maps to %v; want ErrUnsupported", err, got)
	}
}

// TestSocketFamilyChoice pins which family each network and address
// combination opens: "sctp4" AF_INET, "sctp6" AF_INET6 (IPv4 addresses
// included), "sctp" AF_INET6 dual-stack for a wildcard local address and
// otherwise the family the addresses need.
func TestSocketFamilyChoice(t *testing.T) {
	v4 := addrOf(9, "127.0.0.1")
	v6 := addrOf(9, "::1")
	wild := &Addr{Port: 9}
	anyV4 := addrOf(9, "0.0.0.0")
	dual := afInet6
	if ipv6Unavailable() {
		dual = afInet
	}
	for _, tc := range []struct {
		name         string
		network      string
		laddr, raddr *Addr
		want         int
		wantErr      bool
	}{
		{"sctp4 listen wildcard", "sctp4", nil, nil, afInet, false},
		{"sctp4 dial", "sctp4", nil, v4, afInet, false},
		{"sctp4 refuses IPv6", "sctp4", nil, v6, 0, true},
		{"sctp6 IPv4 peer", "sctp6", nil, v4, afInet6, false},
		{"sctp6 IPv4 local", "sctp6", v4, nil, afInet6, false},
		{"sctp listen nil", "sctp", nil, nil, dual, false},
		{"sctp listen wildcard port", "sctp", wild, nil, dual, false},
		{"sctp listen 0.0.0.0", "sctp", anyV4, nil, dual, false},
		{"empty network is sctp", "", nil, nil, dual, false},
		{"sctp dial wildcard to IPv4", "sctp", nil, v4, dual, false},
		{"sctp bound IPv4 to IPv4", "sctp", v4, v4, afInet, false},
		{"sctp bound IPv4 to IPv6", "sctp", v4, v6, afInet6, false},
		{"sctp listen IPv4", "sctp", v4, nil, afInet, false},
		{"sctp listen IPv6", "sctp", v6, nil, afInet6, false},
		{"unknown network", "tcp", nil, v4, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := socketFamily(tc.network, tc.laddr, tc.raddr)
			if tc.wantErr {
				if !errors.Is(err, syscall.EINVAL) {
					t.Fatalf("socketFamily = %d, %v; want an error matching EINVAL", got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("socketFamily = %d, %v; want %d", got, err, tc.want)
			}
		})
	}
}

// TestIsNonblockingDetectsBothStates checks the helper the descriptor-mode
// assertions rest on: it must tell both states apart, follow a change, and
// never report non-blocking for a descriptor it cannot query.
func TestIsNonblockingDetectsBothStates(t *testing.T) {
	fds := socketpair(t)
	if !isNonblocking(fds[0]) {
		t.Error("isNonblocking = false for a SOCK_NONBLOCK socket")
	}
	if err := syscall.SetNonblock(fds[0], false); err != nil {
		t.Fatalf("SetNonblock(false): %v", err)
	}
	if isNonblocking(fds[0]) {
		t.Error("isNonblocking = true after clearing O_NONBLOCK")
	}
	if isNonblocking(-1) {
		t.Error("isNonblocking = true for an invalid descriptor")
	}
}

// TestDescriptorsAreNonBlockingAndCloseOnExec checks every way the package
// comes to own a descriptor, listen, dial, accept and the two adoptions:
// each is close-on-exec, so no child a fork starts inherits it, and
// non-blocking, so every wait is a runtime poller wait that a deadline or
// Close can end.
func TestDescriptorsAreNonBlockingAndCloseOnExec(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	client, server := dialAccept(t, nil, l)

	check := func(name string, rc syscall.RawConn, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s SyscallConn: %v", name, err)
		}
		rawFd(t, rc, func(fd int) {
			if !isCloseOnExec(fd) {
				t.Errorf("%s: descriptor %d is not close-on-exec", name, fd)
			}
			if !isNonblocking(fd) {
				t.Errorf("%s: descriptor %d is blocking", name, fd)
			}
		})
	}
	rc, err := l.SyscallConn()
	check("listener", rc, err)
	rc, err = client.SyscallConn()
	check("dialed", rc, err)
	rc, err = server.SyscallConn()
	check("accepted", rc, err)

	// A blocking, inheritable duplicate of the client's socket, as a
	// parent process might pass one on.
	var dup int
	rawFd(t, mustSyscallConn(t, client), func(fd int) {
		var derr error
		dup, derr = syscall.Dup(fd)
		if derr != nil {
			t.Fatalf("dup: %v", derr)
		}
	})
	if err := syscall.SetNonblock(dup, false); err != nil {
		t.Fatalf("SetNonblock(false): %v", err)
	}
	f := os.NewFile(uintptr(dup), "inherited")
	t.Cleanup(func() { _ = f.Close() })
	adopted, err := FileConn(f)
	if err != nil {
		t.Fatalf("FileConn: %v", err)
	}
	t.Cleanup(func() { _ = adopted.Abort() })
	rc, err = adopted.SyscallConn()
	check("FileConn", rc, err)

	lf := listenerFile(t, l)
	adoptedL, err := FileListener(lf)
	if err != nil {
		t.Fatalf("FileListener: %v", err)
	}
	t.Cleanup(func() { _ = adoptedL.Close() })
	rc, err = adoptedL.SyscallConn()
	check("FileListener", rc, err)
}

// mustSyscallConn is c.SyscallConn that fails the test on an error.
func mustSyscallConn(t testing.TB, c *Conn) syscall.RawConn {
	t.Helper()
	rc, err := c.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	return rc
}

// listenerFile duplicates l's descriptor into an *os.File of its own, as
// socket activation hands one over; it is closed on cleanup.
func listenerFile(t testing.TB, l *Listener) *os.File {
	t.Helper()
	rc, err := l.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var f *os.File
	rawFd(t, rc, func(fd int) {
		dup, err := syscall.Dup(fd)
		if err != nil {
			t.Fatalf("dup: %v", err)
		}
		f = os.NewFile(uintptr(dup), "listener")
	})
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// TestSetupFailureReleasesDescriptor checks that a constructor failing
// after its socket exists still releases it: the failed call returns no
// Listener or Conn, so a descriptor it kept would be unreachable. Control
// runs after the socket is created and before it is bound, so an error
// from it fails the setup with a live descriptor.
func TestSetupFailureReleasesDescriptor(t *testing.T) {
	errForced := errors.New("forced setup failure")
	cfg := &Config{Control: func(string, string, syscall.RawConn) error { return errForced }}
	calls := map[string]func() error{
		"Listen": func() error {
			l, err := cfg.Listen("sctp4", loopback4(0))
			if l != nil {
				_ = l.Close()
				return errors.New("Listen unexpectedly succeeded")
			}
			return err
		},
		"Dial": func() error {
			c, err := cfg.Dial(context.Background(), "sctp4", nil, loopback4(9))
			if c != nil {
				_ = c.Abort()
				return errors.New("Dial unexpectedly succeeded")
			}
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			for range 20 { // warm up: the first calls may open descriptors that are then reused
				if err := call(); !errors.Is(err, errForced) {
					t.Fatalf("want the forced failure, got %v", err)
				}
			}
			before := openFds(t)
			const iterations = 200
			for i := range iterations {
				err := call()
				if !errors.Is(err, errForced) {
					t.Fatalf("iteration %d: want the forced failure, got %v", i, err)
				}
				var opErr *net.OpError
				if !errors.As(err, &opErr) || opErr.Op != strings.ToLower(name) {
					t.Fatalf("iteration %d: err = %#v, want a *net.OpError with Op %q", i, err, strings.ToLower(name))
				}
			}
			if after := openFds(t); after-before > 10 {
				t.Errorf("descriptor count grew from %d to %d over %d failing %s calls", before, after, iterations, name)
			}
		})
	}
}

// TestListenSuccessDoesNotReleaseDescriptor is the other side: a cleanup
// that ran on success too would pass every leak check while closing the
// listener it just made. A dial that completes proves it is still open.
func TestListenSuccessDoesNotReleaseDescriptor(t *testing.T) {
	l := mustListen(t, &Config{}, "sctp4", loopback4(0))
	c, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, listenerAddr(t, l))
	if err != nil {
		t.Fatalf("dial a listener that was set up successfully: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestExplicitNetworkRejectsTheOtherAddressFamily pins the family rules
// of the constructors: an IPv6 address on "sctp4" is refused before any
// socket exists, while an IPv4 address on "sctp6" is accepted and used in
// IPv4-mapped form, since an AF_INET6 socket carries both families.
func TestExplicitNetworkRejectsTheOtherAddressFamily(t *testing.T) {
	before := openFds(t)
	l, err := Listen("sctp4", addrOf(0, "::1"))
	if l != nil {
		_ = l.Close()
	}
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Listen(sctp4, ::1) = %v, want an error matching EINVAL", err)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "listen" {
		t.Fatalf("Listen(sctp4, ::1) error = %#v, want a *net.OpError with Op listen", err)
	}
	if _, err := Dial(context.Background(), "sctp4", nil, addrOf(9, "::1")); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Dial(sctp4, ::1) = %v, want an error matching EINVAL", err)
	}
	if after := openFds(t); after != before {
		t.Errorf("descriptor count went %d -> %d for refused addresses", before, after)
	}

	l6 := mustListen(t, nil, "sctp6", addrOf(0, "127.0.0.1"))
	a := listenerAddr(t, l6)
	if got := ipStrings(a); !equalStrings(got, []string{"127.0.0.1"}) {
		t.Errorf("sctp6 listener on 127.0.0.1 reports %v, want [127.0.0.1] in plain IPv4 form", got)
	}
	// The sctp6 endpoint is bound to 127.0.0.1 alone, so that is its whole
	// side of the association, reported in plain form on both ends.
	client, server := dialAccept(t, nil, l6)
	if got := ipStrings(server.LocalAddr().(*Addr)); !equalStrings(got, []string{"127.0.0.1"}) {
		t.Errorf("accepted sctp6 connection's local addresses = %v, want [127.0.0.1]", got)
	}
	if got := ipStrings(client.RemoteAddr().(*Addr)); !equalStrings(got, []string{"127.0.0.1"}) {
		t.Errorf("sctp4 client of the sctp6 listener sees peer %v, want [127.0.0.1]", got)
	}
}

// TestNilPublicReceiversReturnErrors checks that a nil *Conn or *Listener
// reports a closed socket instead of panicking.
func TestNilPublicReceiversReturnErrors(t *testing.T) {
	var c *Conn
	if c.LocalAddr() != nil || c.RemoteAddr() != nil || c.AssocID() != 0 {
		t.Fatal("a nil *Conn reported an address or an association id")
	}
	ip := netip.MustParseAddr("127.0.0.1")
	for name, call := range map[string]func() error{
		"Close":            c.Close,
		"CloseWithTimeout": func() error { return c.CloseWithTimeout(time.Second) },
		"Abort":            c.Abort,
		"Shutdown":         c.Shutdown,
		"SetDeadline":      func() error { return c.SetDeadline(time.Now()) },
		"SetReadDeadline":  func() error { return c.SetReadDeadline(time.Now()) },
		"SetWriteDeadline": func() error { return c.SetWriteDeadline(time.Now()) },
		"LocalAddrs":       func() error { _, err := c.LocalAddrs(); return err },
		"PeerAddrs":        func() error { _, err := c.PeerAddrs(); return err },
		"BindAdd":          func() error { return c.BindAdd(ip) },
		"BindRemove":       func() error { return c.BindRemove(ip) },
		"SyscallConn":      func() error { _, err := c.SyscallConn(); return err },
	} {
		if err := call(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("nil Conn.%s = %v, want an error matching net.ErrClosed", name, err)
		}
	}

	var l *Listener
	if l.Addr() != nil {
		t.Fatal("a nil *Listener reported an address")
	}
	for name, call := range map[string]func() error{
		"AcceptSCTP":  func() error { _, err := l.AcceptSCTP(); return err },
		"Close":       l.Close,
		"SetDeadline": func() error { return l.SetDeadline(time.Now()) },
		"BindAdd":     func() error { return l.BindAdd(ip) },
		"BindRemove":  func() error { return l.BindRemove(ip) },
		"SyscallConn": func() error { _, err := l.SyscallConn(); return err },
	} {
		if err := call(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("nil Listener.%s = %v, want an error matching net.ErrClosed", name, err)
		}
	}
}

// TestNilAddressesReturnErrors checks the missing-address refusals: a Dial
// with no remote address, or one with no IP, and a BindAdd or BindRemove
// with no address, all match syscall.EINVAL before any system call.
func TestNilAddressesReturnErrors(t *testing.T) {
	for name, raddr := range map[string]*Addr{"nil": nil, "no IPs": {Port: 9}} {
		if _, err := Dial(context.Background(), "sctp4", nil, raddr); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("Dial with a %s remote address = %v, want EINVAL", name, err)
		}
	}
	l := mustListen(t, nil, "sctp4", loopback4(0))
	if err := l.BindAdd(); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("Listener.BindAdd() = %v, want EINVAL", err)
	}
	if err := l.BindRemove(netip.Addr{}); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("Listener.BindRemove(zero netip.Addr) = %v, want EINVAL", err)
	}
	client, _ := dialAccept(t, nil, l)
	if err := client.BindAdd(); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("Conn.BindAdd() = %v, want EINVAL", err)
	}
	if err := client.BindAdd(netip.Addr{}); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("Conn.BindAdd(zero netip.Addr) = %v, want EINVAL", err)
	}
}

// TestNilDialContextReturnsEINVAL checks that a nil context is refused,
// with no socket opened, from both entry points.
func TestNilDialContextReturnsEINVAL(t *testing.T) {
	var nilCtx context.Context
	var nilCfg *Config
	for name, dial := range map[string]func() (*Conn, error){
		"Dial":        func() (*Conn, error) { return Dial(nilCtx, "sctp4", nil, loopback4(9)) },
		"Config.Dial": func() (*Conn, error) { return (&Config{}).Dial(nilCtx, "sctp4", nil, loopback4(9)) },
		"nil Config":  func() (*Conn, error) { return nilCfg.Dial(nilCtx, "sctp4", nil, loopback4(9)) },
	} {
		c, err := dial()
		if c != nil || !errors.Is(err, syscall.EINVAL) {
			t.Errorf("%s with a nil context = (%v, %v), want (nil, EINVAL)", name, c, err)
		}
	}
}

// TestDoubleCloseRegression is georgeyanev/go-sctp PR #7's failure mode: a
// failed dial that closed its descriptor twice, the second close landing
// on whatever the kernel had reused the number for. A port nobody listens
// on is dialed 200 times, each attempt failing with the peer's ABORT,
// while other goroutines keep opening, using and closing pipes, whose
// descriptor numbers the kernel hands out from the same table. A second
// close would show as a pipe that stops working under its owner.
func TestDoubleCloseRegression(t *testing.T) {
	l, err := Listen("sctp4", loopback4(0))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	dead := listenerAddr(t, l)
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	stop := make(chan struct{})
	var (
		wg        sync.WaitGroup
		pipeFault atomic.Value
		rounds    atomic.Int64
	)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 1)
			for {
				select {
				case <-stop:
					return
				default:
				}
				r, w, err := os.Pipe()
				if err != nil {
					pipeFault.Store(fmt.Sprintf("pipe: %v", err))
					return
				}
				for i := range 8 {
					if _, err := w.Write([]byte{byte(i)}); err != nil {
						pipeFault.Store(fmt.Sprintf("write to a pipe its owner still holds: %v", err))
					} else if _, err := io.ReadFull(r, buf); err != nil || buf[0] != byte(i) {
						pipeFault.Store(fmt.Sprintf("read from a pipe its owner still holds: %v (byte %d)", err, buf[0]))
					}
				}
				if err := r.Close(); err != nil {
					pipeFault.Store(fmt.Sprintf("close of a pipe's read end: %v", err))
				}
				if err := w.Close(); err != nil {
					pipeFault.Store(fmt.Sprintf("close of a pipe's write end: %v", err))
				}
				rounds.Add(1)
			}
		}()
	}

	for range 200 {
		c, err := Dial(testContext(t, 5*time.Second), "sctp4", nil, dead)
		if err == nil {
			// A connection to itself, which Dial refuses, or a socket that
			// took the port since.
			close(stop)
			wg.Wait()
			explainDeadPortDial(t, c, dead)
		}
	}
	close(stop)
	wg.Wait()
	if f := pipeFault.Load(); f != nil {
		t.Fatalf("a pipe was disturbed under its owner while failed dials released their sockets: %s", f)
	}
	if rounds.Load() == 0 {
		t.Fatal("no pipe completed a round while the failed dials ran, so nothing was exposed to a stray close")
	}
}

// TestDescriptorExhaustion runs Dial and Accept with the descriptor limit
// lowered to the descriptors in use plus three, in a child process so the
// limit does not disturb the rest of the suite. Both must fail with an
// error matching EMFILE inside a *net.OpError, and once the limit is
// restored and everything closed, the descriptor count must be back where
// it started: nothing leaked, and nothing was closed twice.
func TestDescriptorExhaustion(t *testing.T) {
	if os.Getenv("SCTP_EXHAUSTION_CHILD") == "1" {
		descriptorExhaustionChild(t)
		return
	}
	out, err := runChild(t, "TestDescriptorExhaustion", "SCTP_EXHAUSTION_CHILD=1")
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	if !strings.Contains(out, "exhaustion checks done") {
		t.Fatalf("child did not run the checks:\n%s", out)
	}
}

func descriptorExhaustionChild(t *testing.T) {
	l := mustListen(t, nil, "sctp4", loopback4(0))
	raddr := listenerAddr(t, l)
	baseline := openFds(t)

	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatalf("getrlimit: %v", err)
	}
	// The limit bounds the next descriptor number, and the lowest free
	// number is used first, so the highest number in use sets the floor.
	high := 0
	ents, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	for _, e := range ents {
		if n, err := strconv.Atoi(e.Name()); err == nil && n > high {
			high = n
		}
	}
	lowered := lim
	lowered.Cur = uint64(high + 1 + 3)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lowered); err != nil {
		t.Fatalf("setrlimit: %v", err)
	}

	var conns []*Conn
	var dialErr error
	for range 16 {
		c, err := Dial(context.Background(), "sctp4", nil, raddr)
		if err != nil {
			dialErr = err
			break
		}
		conns = append(conns, c)
	}
	var opErr *net.OpError
	if !errors.Is(dialErr, syscall.EMFILE) || !errors.As(dialErr, &opErr) || opErr.Op != "dial" {
		t.Errorf("Dial at the descriptor limit = %#v, want a *net.OpError with Op dial matching EMFILE", dialErr)
	}

	// Every descriptor is in use; the queued associations are waiting.
	_, acceptErr := l.AcceptSCTP()
	if !errors.Is(acceptErr, syscall.EMFILE) || !errors.As(acceptErr, &opErr) || opErr.Op != "accept" {
		t.Errorf("AcceptSCTP at the descriptor limit = %#v, want a *net.OpError with Op accept matching EMFILE", acceptErr)
	}

	// Free one descriptor: the next Accept must work again.
	if len(conns) > 0 {
		if err := conns[0].Abort(); err != nil {
			t.Errorf("Abort: %v", err)
		}
		conns = conns[1:]
		s, err := l.AcceptSCTP()
		if err != nil {
			t.Errorf("AcceptSCTP after a descriptor was released: %v", err)
		} else if err := s.Abort(); err != nil {
			t.Errorf("Abort of the accepted connection: %v", err)
		}
	}

	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		t.Fatalf("restoring the limit: %v", err)
	}
	for _, c := range conns {
		if err := c.Abort(); err != nil {
			t.Errorf("Abort: %v", err)
		}
		if err := c.Abort(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("second Abort = %v, want net.ErrClosed", err)
		}
	}
	// Drain what the listener still holds queued, so that its accepted
	// descriptors are counted and released too.
	if err := l.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	for {
		s, err := l.AcceptSCTP()
		if err != nil {
			break
		}
		_ = s.Abort()
	}
	if after := openFds(t); after != baseline {
		t.Errorf("descriptor count went %d -> %d across the exhaustion", baseline, after)
	}
	fmt.Println("exhaustion checks done")
}

// TestSctp6CarriesIPv4WhateverBindv6only: "sctp" and "sctp6" sockets carry
// IPv4 peers, in IPv4-mapped form, even where net.ipv6.bindv6only is 1,
// which would otherwise start every AF_INET6 socket IPv6-only
// (net/ipv6/af_inet6.c: inet6_create). The test sets the sysctl, which the
// Linux suite's privileged container allows, and restores it.
func TestSctp6CarriesIPv4WhateverBindv6only(t *testing.T) {
	const knob = "/proc/sys/net/ipv6/bindv6only"
	old, err := os.ReadFile(knob)
	if err != nil {
		t.Skipf("cannot read %s: %v", knob, err)
	}
	if err := os.WriteFile(knob, []byte("1"), 0o644); err != nil {
		t.Skipf("cannot set %s (the Linux suite's privileged container can): %v", knob, err)
	}
	t.Cleanup(func() { _ = os.WriteFile(knob, old, 0o644) })

	for _, network := range []string{"sctp", "sctp6"} {
		t.Run(network, func(t *testing.T) {
			l := mustListen(t, nil, network, &Addr{})
			rc, err := l.SyscallConn()
			if err != nil {
				t.Fatalf("SyscallConn: %v", err)
			}
			if v := getIntOpt(t, rc, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY); v != 0 {
				t.Errorf("IPV6_V6ONLY = %d on a %s listener, want 0", v, network)
			}
			c, err := Dial(testContext(t, 10*time.Second), "sctp4", nil, loopback4(listenerAddr(t, l).Port))
			if err != nil {
				t.Fatalf("an IPv4 dial to a wildcard %s listener with bindv6only=1: %v", network, err)
			}
			_ = c.Abort()
		})
	}
}
