// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// This file includes modifications by gomaja.

package main

import (
	"bufio"
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gomaja/go-sctp"
)

// runMainEnv, when set in the environment, makes the test binary run the
// program itself instead of the tests, with the arguments in runArgsEnv
// (one per line). TestServerAndClientProcesses starts the server and the
// client that way, as two processes, the way a user runs them.
const (
	runMainEnv = "SCTP_EXAMPLE_RUN_MAIN"
	runArgsEnv = "SCTP_EXAMPLE_ARGS"
)

func TestMain(m *testing.M) {
	if os.Getenv(runMainEnv) == "1" {
		os.Args = append([]string{"example"}, strings.Split(os.Getenv(runArgsEnv), "\n")...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestParseIPs(t *testing.T) {
	got, err := parseIPs(" 10.10.0.1, fe80::1%eth0 ,,10.20.0.1")
	if err != nil {
		t.Fatalf("parseIPs: %v", err)
	}
	want := []netip.Addr{
		netip.MustParseAddr("10.10.0.1"),
		netip.MustParseAddr("fe80::1%eth0"),
		netip.MustParseAddr("10.20.0.1"),
	}
	if len(got) != len(want) {
		t.Fatalf("parseIPs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("address %d = %v, want %v", i, got[i], want[i])
		}
	}
	if got, err := parseIPs(""); err != nil || len(got) != 0 {
		t.Errorf("parseIPs(\"\") = %v, %v; want no address and no error", got, err)
	}
	if _, err := parseIPs("10.0.0.1,not-an-address"); err == nil {
		t.Error("parseIPs accepted an invalid address")
	}
}

// TestNewConfigSetsRequestedBuffers: a non-zero size becomes the Config's
// buffer setting, applied before the socket connects or listens.
func TestNewConfigSetsRequestedBuffers(t *testing.T) {
	cfg := newConfig(333, 444)
	if cfg.WriteBuffer == nil || *cfg.WriteBuffer != 333 {
		t.Errorf("WriteBuffer = %v, want 333", cfg.WriteBuffer)
	}
	if cfg.ReadBuffer == nil || *cfg.ReadBuffer != 444 {
		t.Errorf("ReadBuffer = %v, want 444", cfg.ReadBuffer)
	}
}

// TestNewConfigLeavesZeroRequestsUnset: a size of 0 leaves the setting nil,
// so the kernel's default stands.
func TestNewConfigLeavesZeroRequestsUnset(t *testing.T) {
	cfg := newConfig(0, 0)
	if cfg.WriteBuffer != nil || cfg.ReadBuffer != nil {
		t.Errorf("buffers = (%v, %v), want both nil", cfg.WriteBuffer, cfg.ReadBuffer)
	}
}

type fakeBufferReporter struct {
	calls []string
	errs  map[string]error
}

func (f *fakeBufferReporter) WriteBuffer() (int, error) {
	f.calls = append(f.calls, "write")
	return 111, f.errs["write"]
}

func (f *fakeBufferReporter) ReadBuffer() (int, error) {
	f.calls = append(f.calls, "read")
	return 222, f.errs["read"]
}

// TestBufferSizesStopsAtEachError: bufferSizes reads the send buffer, then
// the receive buffer, and stops at the first error, which it wraps.
func TestBufferSizesStopsAtEachError(t *testing.T) {
	boom := errors.New("boom")
	for _, tc := range []struct {
		fail  string
		calls string
	}{
		{"", "write read"},
		{"write", "write"},
		{"read", "write read"},
	} {
		f := &fakeBufferReporter{errs: map[string]error{tc.fail: boom}}
		send, receive, err := bufferSizes(f)
		if got := strings.Join(f.calls, " "); got != tc.calls {
			t.Errorf("failing %q: calls = %q, want %q", tc.fail, got, tc.calls)
		}
		if tc.fail == "" {
			if err != nil || send != 111 || receive != 222 {
				t.Errorf("no failure: bufferSizes = %d, %d, %v; want 111, 222, nil", send, receive, err)
			}
			continue
		}
		if !errors.Is(err, boom) {
			t.Errorf("failing %q: err = %v, want it to wrap %v", tc.fail, err, boom)
		}
	}
}

// requireSCTP skips the test where the package has no SCTP sockets: on
// every platform but Linux. testdata/docker/linux-suite.sh runs it against
// a Linux kernel.
func requireSCTP(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("SCTP sockets exist only on Linux, not %s; run testdata/docker/linux-suite.sh", runtime.GOOS)
	}
}

// TestServerAndClientProcesses runs the program as a user does: the server
// in one process, listening on a port the kernel chooses, which it logs,
// and the client in another, sending three messages of 512 bytes with
// requested buffer sizes and checking each echo.
func TestServerAndClientProcesses(t *testing.T) {
	requireSCTP(t)

	server := exec.Command(os.Args[0])
	server.Env = append(os.Environ(), runMainEnv+"=1",
		runArgsEnv+"=-server\n-ip\n127.0.0.1\n-port\n0\n-bufsize\n512")
	logs, err := server.StderrPipe()
	if err != nil {
		t.Fatalf("StderrPipe: %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("starting the server: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Process.Kill()
		_ = server.Wait()
	})

	// The server logs "listening on 127.0.0.1:port" once it listens.
	listening := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(logs)
		for sc.Scan() {
			line := sc.Text()
			t.Logf("server: %s", line)
			if _, addr, ok := strings.Cut(line, "listening on "); ok {
				select {
				case listening <- addr:
				default:
				}
			}
		}
	}()
	var addr *sctp.Addr
	select {
	case s := <-listening:
		if addr, err = sctp.ResolveAddr("sctp", s); err != nil {
			t.Fatalf("the server's address %q: %v", s, err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the server did not report its address within 30 s")
	}

	client := exec.Command(os.Args[0])
	client.Env = append(os.Environ(), runMainEnv+"=1", runArgsEnv+"=-ip\n127.0.0.1\n-port\n"+
		strconv.Itoa(int(addr.Port))+"\n-bufsize\n512\n-count\n3\n-interval\n0s\n-sndbuf\n65536\n-rcvbuf\n65536")
	out, err := client.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			t.Fatalf("client: %v\n%s", err, exit.Stderr)
		}
		t.Fatalf("client: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	want := []string{
		"message 0: 512 bytes echoed on stream 0, PPID 0",
		"message 1: 512 bytes echoed on stream 1, PPID 1",
		"message 2: 512 bytes echoed on stream 2, PPID 2",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("client output:\n%s\nwant:\n%s", out, strings.Join(want, "\n"))
	}
}

// TestBufferSizesFollowTheConfig: a connection set up with requested buffer
// sizes reports them as Linux keeps them: capped by net.core.wmem_max and
// net.core.rmem_max, then doubled for the kernel's own bookkeeping
// (net/core/sock.c: __sock_set_sndbuf, __sock_set_rcvbuf). The sizes asked
// for differ from any default, so a Config that was not applied fails.
func TestBufferSizesFollowTheConfig(t *testing.T) {
	requireSCTP(t)
	const sndbuf, rcvbuf = 40000, 50000
	wantSend := 2 * min(sndbuf, sysctlInt(t, "/proc/sys/net/core/wmem_max"))
	wantReceive := 2 * min(rcvbuf, sysctlInt(t, "/proc/sys/net/core/rmem_max"))
	cfg := newConfig(sndbuf, rcvbuf)
	l, err := cfg.Listen("sctp4", &sctp.Addr{IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}})
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	accepted := make(chan *sctp.Conn, 1)
	go func() {
		c, err := l.AcceptSCTP()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := cfg.Dial(ctx, "sctp4", nil, l.Addr().(*sctp.Addr))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Abort() })
	if s := <-accepted; s != nil {
		t.Cleanup(func() { _ = s.Abort() })
	}
	send, receive, err := bufferSizes(c)
	if err != nil {
		t.Fatalf("bufferSizes: %v", err)
	}
	if send != wantSend || receive != wantReceive {
		t.Errorf("buffers = %d send, %d receive; want %d and %d", send, receive, wantSend, wantReceive)
	}
}

// sysctlInt reads an integer sysctl from its /proc/sys file.
func sysctlInt(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return n
}
