<!-- Copyright 2026 gomaja. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- This file includes modifications by gomaja. -->

# go-sctp

SCTP sockets for Go on Linux: a binding for the kernel's implementation of
the Stream Control Transmission Protocol ([RFC 9260](https://www.rfc-editor.org/rfc/rfc9260.html))
and of its sockets API ([RFC 6458](https://www.rfc-editor.org/rfc/rfc6458.html)).

The package does not implement SCTP. The kernel owns the protocol: the
association state machine, chunks, retransmission, congestion control, path
management and checksums. The package owns the Go API around it: `net.Conn`
and `net.Listener` implementations over one-to-one sockets, a one-to-many
`Endpoint`, message metadata, typed socket options, parsed notifications,
`net/netip` addresses and a uniform error contract.

The package documentation is the reference for every call:
[pkg.go.dev/github.com/gomaja/go-sctp](https://pkg.go.dev/github.com/gomaja/go-sctp).

## Installing

```
go get github.com/gomaja/go-sctp@main
```

The package needs Go 1.26 or later. Its send lock uses
[go-ctxsync](https://github.com/gomaja/go-ctxsync); all other dependencies are
from the standard library.

There are no releases and no tags: the module is followed on its `main`
branch, and Go records each commit you get as a `v0.0.0-…` pseudo-version.
The API documented here replaced v1 (v1.0.0 to v1.0.6) under the same module
path, with no compatibility layer; [MIGRATION.md](MIGRATION.md) maps every
v1 identifier to its successor. Because both APIs share one module path, and
a build uses one version of a module, every module in a build must move to
the current API together.

Every version published so far, v1.0.0 to v1.1.1, is retracted; v1.1.1 was
published only to carry the retraction in its `go.mod`, because Go reads
retractions from the newest version. With no version left to choose, `go get
github.com/gomaja/go-sctp`, `@latest` and `go get -u` resolve to the newest
commit on `main`, as `@main` does. A module that still requires a retracted
version, or a pseudo-version recorded for a `main` commit before the
retraction (`v1.1.1-0.…`), gets a retraction warning from `go get` and
`go list -m -u`. Those versions sort above every `v0.0.0-…` pseudo-version,
so `go get -u` leaves such a module where it is; `go get
github.com/gomaja/go-sctp@main` moves it to `main`, and every other module
in the build that requires an old version has to move with it.

## Quick start

A server that echoes every message, and a client, over one-to-one sockets
used as `net.Listener` and `net.Conn`:

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"syscall"
	"time"

	"github.com/gomaja/go-sctp"
)

func main() {
	laddr, err := sctp.ResolveAddr("sctp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	ln, err := sctp.Listen("sctp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				if errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
					errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ENOMEM) {
					time.Sleep(100 * time.Millisecond)
					continue
				}
				log.Printf("accept: %v", err)
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 64<<10)
				for {
					n, err := conn.Read(buf) // one message, or its first part
					if err != nil {
						return
					}
					if _, err := conn.Write(buf[:n]); err != nil { // one message
						return
					}
				}
			}()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := sctp.Dial(ctx, "sctp", nil, ln.Addr().(*sctp.Addr))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// SendMsg and RecvMsg carry the SCTP metadata: the stream, the payload
	// protocol identifier (PPID), and whether a read ended the message.
	opts := sctp.SendOptions{Info: &sctp.SndInfo{Stream: 0, PPID: 46}}
	if _, err := conn.SendMsg([]byte("hello"), opts); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 64<<10)
	n, info, err := conn.RecvMsg(buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%q, stream %d, complete %v\n", buf[:n], info.Rcv.Stream, info.EOR)
}
```

[`example/`](example) is a complete echo server and client, with
multi-homing, streams, buffer sizes and notifications.

For a hostname, use `ResolveAddrContext(ctx, "sctp", "peer.example:3868")`
and pass the resulting `*Addr` and the same context to `Dial` or
`Config.Dial`. That bounds both name resolution and association setup.
`ResolveAddr` uses a background context. Both forms resolve every hostname
in a multi-homed address; literals and the wildcard need no lookup and
still parse when the context is cancelled. Socket constructors take
already-resolved addresses and never resolve hostnames themselves.

## Overview

- **One-to-one sockets.** `Dial` sets up an association and returns a
  `*Conn`; `Listen` returns a `*Listener`. `*Conn` implements `net.Conn`,
  where each `Write` sends one message.
- **One-to-many sockets.** `ListenEndpoint` and `OpenEndpoint` return an
  `*Endpoint` carrying many associations, each named by an `AssocID`, and
  `Endpoint.PeelOff` moves one onto a `*Conn` of its own.
- **Configuration.** Everything decided before an association exists, the
  streams and extensions offered in the INIT, socket buffers, defaults and
  notification subscriptions, is a field of `Config`, whose methods are the
  constructors. Optional settings are pointers: `NoDelay: new(true)`.
  `Config.SetupRTOInitial` raises or lowers RTO.Initial only while `Dial`
  sets up the association: a value beyond the dial deadline sends a single
  INIT within it, and the association gets the lasting RTO.Initial back once
  it is established. Its documentation says what Linux keeps of the setup
  value.
- **Messages.** `SendMsg` takes a `SendOptions`: stream, PPID and flags,
  a PR-SCTP policy, an AUTH key, the peer address to send to, and a
  single-attempt mode (`NoWait`). `SendMsgContext` is `SendMsg` with a
  context that can end its waits; a successful send queues the whole
  message, a failed one none of it.
  `RecvMsg` reports each read's metadata and `ReadMsg` reassembles whole
  messages. An uncontended successful `SendMsg` with no `Path` zone or a
  numeric zone, and a `RecvMsg` or `Read` of data, make no allocation.
  Send-lock contention can allocate its lazy queue or pooled waiters on
  first use, higher peak contention or pool refill.
  A zone given by interface name allocates only when the
  package reads the host's interface table again (at most once a minute,
  or for a name it has not seen).
- **Notifications.** Subscribe with `Config.Notifications` or
  `Conn.Subscribe`; a `NotificationHandler` receives parsed values such as
  `*AssocChange` and `*SendFailed`. Every notification record's framing is
  checked against its header (RFC 6458 §6.1), including a record the reader
  does not deliver: a malformed one fails the read with
  `ErrShortNotification` or `ErrNotificationTooLong`, and the message after
  it stays queued.
- **The end of an association.** Reads end with `io.EOF` after a graceful
  end on every kind of connection, except that a record consumed through
  `SyscallConn` is never seen by the package. After a failure every read
  and send returns the same error (`ECONNRESET`, `ETIMEDOUT` or
  `ECONNABORTED`) instead of hanging.
- **Queue reporting.** `Conn.SendBacklog` and `Endpoint.SendBacklog`
  report the socket's send-buffer memory charge and limit. The charge
  includes chunk overhead and DATA retained until freed, including unsent,
  in-flight, retransmitted, gap-acknowledged and abandoned chunks; it can
  exceed the limit. An endpoint's charge covers every association together.
  `Conn.AssocQueues` and `Endpoint.AssocQueues(id)` report one association's
  send and receive charges, never-transmitted chunk count and payload bytes
  in flight on its primary path. Use these for monitoring; `SendBacklog`
  is the cheaper query. `Status.Pending` counts missing receive-side DATA
  chunks, and `Status.Unacked` can be just one window probe despite a large
  unsent backlog. Linux exposes no exact queued-payload byte count.
- **Errors.** The errors of socket calls are `*net.OpError` values that
  name the call; test them with `errors.Is`. A refused argument normally
  matches `syscall.EINVAL` and names the field. `InterleaveStreams` matches
  `sctp.ErrUnsupported` because Linux cannot retain that valid API level.
  An option the kernel lacks matches `syscall.ENOPROTOOPT`.

## IPv6 sockets

`"sctp6"` selects an AF_INET6 **dual-stack** socket: IPv4 peers are accepted.
A wildcard `Listen("sctp4", :p)` and `Listen("sctp6", :p)` therefore collide
with `EADDRINUSE`. v1 set `IPV6_V6ONLY` for `"sctp6"`; this version clears it.
To listen only on IPv6, set it again through `Config.Control`, which runs
after the package clears the option:

```go
cfg := &sctp.Config{
    Control: func(_, _ string, raw syscall.RawConn) error {
        var setErr error
        err := raw.Control(func(fd uintptr) {
            setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
        })
        if err != nil {
            return err
        }
        return setErr
    },
}
listener, err := cfg.Listen("sctp6", &sctp.Addr{Port: port})
```

The same callback applies to `Dial`, `ListenEndpoint` and `OpenEndpoint`.

## Kernel requirements

The package needs Linux 5.0 or later: every constructor subscribes to
association changes with `SCTP_EVENT`, first in 5.0, and a kernel without
it refuses the constructor with an error matching `syscall.ENOPROTOOPT`.
Every facility of earlier releases is therefore always present. A few
features need a newer kernel. The package never checks a version number:
a call that needs a facility the kernel lacks returns the kernel's own
error for that call, and nothing else is affected. Each row gives the
first upstream Linux release whose UAPI header defines the facility
(checked against the headers of every release up to 6.12; no facility
disappears in a later release):

| Upstream Linux | Facility | API that needs it |
|---|---|---|
| **5.0** | `SCTP_EVENT`, and everything earlier releases define: `SCTP_SOCKOPT_CONNECTX3`, the RFC 6458 options, the `SNDINFO`/`RCVINFO`/`NXTINFO` messages, PR-SCTP, stream reconfiguration, `SCTP_SOCKOPT_PEELOFF_FLAGS`, the FCFS, priority and round-robin schedulers, message interleaving, `SCTP_REUSE_PORT` and `MSG_MORE` | **every socket**, and every API not listed below |
| 5.1 | `SO_BINDTOIFINDEX` | `Conn.AssocQueues`, `Endpoint.AssocQueues` |
| 5.4 | `SCTP_ASCONF_SUPPORTED`, `SCTP_AUTH_SUPPORTED`, `SCTP_ECN_SUPPORTED` | `Config.DynamicAddressReconfiguration`, `Config.Authentication`, `Config.ExperimentalECN`, their getters, and `InstallAuthKey`/`ActivateAuthKey` |
| 5.5 | `SCTP_PEER_ADDR_THLDS_V2`, `SCTP_EXPOSE_POTENTIALLY_FAILED_STATE`, `SCTP_SEND_FAILED_EVENT` | `PathThresholds`, `PFExposure`, `AddrPotentiallyFailed`, `EventSendFailed` |
| 5.11 | `SCTP_REMOTE_UDP_ENCAPS_PORT` | `RemoteUDPEncapsPort` |
| 5.14 | `SCTP_PLPMTUD_PROBE_INTERVAL` | `PLPMTUDProbeInterval` |
| 6.4 | the FC and WFQ stream schedulers (`SCTP_SS_FC`, `SCTP_SS_WFQ`) | `SchedFC`, `SchedWFQ` |

Before 5.5 there is no send-failure notification at all, since the package
does not use the deprecated `SCTP_SEND_FAILED`, and `SchedFC` and
`SchedWFQ` are the only facilities that need a kernel newer than 5.14.

Vendor kernels count by facility, not by version number. The Rocky Linux 9
(RHEL 9) kernel is 5.14; its 5.14.0-687.52.1.el9_8 headers define every
facility above, the FC and WFQ schedulers included. On RHEL-family
distributions the SCTP module ships in `kernel-modules-extra` and is
blacklisted by default (`/etc/modprobe.d/sctp-blacklist.conf`): install
the package, remove or override the blacklist entry, and load the module
(`modprobe sctp`) before opening a socket. Until then every constructor
fails with an error matching `ErrUnsupported`.

`AssocQueues` also needs the `sctp_diag` module
(`CONFIG_INET_SCTP_DIAG`). It loads on demand without special privileges
when available; an unavailable module gives an error matching
`ErrUnsupported` that names `sctp_diag`. Rocky Linux 9 and 10 ship it in
`kernel-modules-extra`, blacklisted in
`/etc/modprobe.d/sctp_diag-blacklist.conf`: load it with
`modprobe sctp_diag` or remove the blacklist entry to allow on-demand
loading. `SendBacklog` uses `SO_MEMINFO` and needs no diagnostics module.
On Linux 6.18 (and back to 5.14, and on current mainline), `AssocQueues` can
intermittently return `ENOENT` for a live IPv6 link-local association:
`net/sctp/diag.c: sctp_diag_dump_one` leaves the lookup addresses' scope ids
uninitialized ([sctp/lksctp-tools#82](https://github.com/sctp/lksctp-tools/issues/82)).
`SendBacklog`, and `AssocQueues` on global and loopback associations, are
unaffected.

## Platforms

Sockets work on Linux, on every architecture Go supports, and on Android,
which Go builds with the `linux` tag. On `linux/386` the socket calls go
through `socketcall(2)`, and a 32-bit program on a 64-bit kernel uses the
kernel's 64-bit layout for the options whose layout depends on the word
size.

On the other platforms, the BSDs, macOS, Windows, Solaris, illumos and AIX
among them, the package compiles, `ResolveAddr`, `ResolveAddrContext` and
`ParseNotification` work, and the constructors return a `*net.OpError` that
wraps `sctp.ErrUnsupported`, which wraps `errors.ErrUnsupported`:

```go
if errors.Is(err, sctp.ErrUnsupported) {
	// no SCTP on this platform
}
```

Use `sctp.ErrUnsupported` specifically: `errors.ErrUnsupported` is too broad,
since it also matches `ENOSYS`, `ENOTSUP` and `EOPNOTSUPP` from a working
stack. Even `sctp.ErrUnsupported` has documented exceptions on a working
stack; see its API documentation, including the deliberate refusal of
`InterleaveStreams` in `Config.FragmentInterleave` and `SetFragmentInterleave`.

`js/wasm` and `wasip1/wasm` compile the same way. `plan9` does not: its
`syscall` package has no `Errno` type.

What continuous integration runs on each target:

| Target | What runs |
|---|---|
| `linux/amd64` | The whole suite against the runner's SCTP stack, with Go 1.26 and the latest Go, in both sysctl states (below); again under `-race`, and under `-gcflags=all=-d=checkptr` |
| `linux/arm64` | The whole suite against the arm64 runner's SCTP stack, with the latest Go and both SCTP sysctls enabled |
| `linux/386` | The root package suite on the x86_64 runner: the `socketcall` path and compat layouts against a 64-bit kernel, with `TestStorageLayoutOnThisKernel` checking the 64-bit layout reported by `uname -m`; the example package is covered by the other Linux jobs. Only `TestRawRecvmsgStackStorage` and `TestRawSockoptStackStorage` run again with the goroutine stack moved at every function call. Native 32-bit kernels are not exercised |
| `linux/s390x` | The root and `example` package suites against a pinned Debian big-endian kernel under qemu-system, in both sysctl states; `TestCrossCompileSmoke` and architecture-independent `TestExportedAPI` are covered separately. The portable tests and fuzz seeds also run under the faster qemu-user job, which cannot exercise SCTP socket options |
| `linux/arm`, `linux/mips`, `linux/386`, `linux/s390x` | `go vet` |
| 13 targets across Linux, Android, macOS, Windows, FreeBSD and AIX | A build of each (`TestCrossCompileSmoke`) |
| `darwin`, `windows` | The tests, with `-short` |
| Two Linux hosts | The wire harness (below) |

## Testing

```
go test ./...
```

On a machine without SCTP, such as macOS, this runs only the tests that
need no socket: the socket-backed ones, in the `*_linux_test.go` files, are
not built there, and a green run proves nothing about them. On Linux, the
root test package first probes for SCTP and fails immediately when the kernel
lacks it. Try `modprobe sctp`; on RHEL-family systems, install the matching
`kernel-modules-extra` package and check the SCTP module blacklist. Run the
socket suite against a Linux kernel in Docker:

```
testdata/docker/linux-suite.sh [-race] [-sysctl on|off] [-run REGEX]
```

It runs the whole suite in a privileged `golang:1.26.5-bookworm` container,
with the environment the tests need: extra loopback addresses, a dummy link
that silently drops packets to one address, a link with known link-local
addresses, and the SCTP sysctls. Run it in both sysctl states, `-sysctl on`
and `-sysctl off` (`net.sctp.auth_enable` and `net.sctp.intl_enable`
together), since some tests need each; a test that needs the other state
skips and says so. [testdata/docker/README.md](testdata/docker/README.md)
explains each step. CI builds the same environment with the same script,
`testdata/docker/setup-env.sh`.

The same socket suite runs against a big-endian s390x guest kernel:

```
testdata/bigendian/run.sh
```

It needs Docker and Go, boots with full-system emulation, checks the
guest's architecture, byte order, SCTP stack, kernel and source revision,
and runs the root and `example` packages in both sysctl states. This
qualifies one s390x kernel; other big-endian architectures and two-host
wire claims need their own runtime evidence. See
[testdata/bigendian/README.md](testdata/bigendian/README.md).

Some claims can only be proven between two hosts, from the packets
themselves: that an `Abort` puts an ABORT chunk on the wire at once, that
`SendSACKImmediately` sets the I bit, that a refused `NoWait` send leaves no
DATA behind. The wire harness runs the package's own test binary in two
privileged containers joined by two networks, captures the traffic with
`tshark`, and checks every claim from the capture:

```
testdata/wire/run.sh [-race] [-run REGEX] [-only wire|twohost]
```

It needs only Docker, runs unattended, and its exit status is the verdict.
CI runs it too; see [testdata/wire/README.md](testdata/wire/README.md).

## Standards

The package follows RFC 9260 and RFC 6458 with their verified errata, and
the extensions Linux implements: RFC 3758, 4895, 5061, 6525, 6951 (updated
by RFC 8899), 7496, 7829, 8260 and 8899. Each call's documentation names the
section it implements. [STANDARDS.md](STANDARDS.md) records the status of
each document in the RFC Editor and the IETF Datatracker, its errata and how
each is treated, the Internet-Drafts in progress, and where Linux differs
from the documents. Among those differences:

- Linux stores `SCTP_FRAGMENT_INTERLEAVE` as a boolean, so RFC 6458 §8.1.20's
  level 2 (`InterleaveStreams`) cannot be kept; the package refuses it with
  an error matching `ErrUnsupported`.
- Linux has no socket option for RFC 9653's zero checksum, nor for choosing
  a congestion-control algorithm, so the package offers neither.
- `Config.ExperimentalECN` is a Linux option: RFC 9260 §1.7 removed SCTP's
  ECN appendix, and no current RFC specifies it.
- RFC 9260 §6.2 caps the delayed-SACK timer at 500 ms, which the package
  enforces, and recommends 200 ms and a SACK for at least every second
  packet; a longer setting departs from that recommendation.

[ECOSYSTEM.md](ECOSYSTEM.md) records the survey of other SCTP libraries and
their issue trackers that shaped this API, and what was adopted from it.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). Copyright in
gomaja's contributions belongs to gomaja. Parts of the package are derived
from Wataru Ishida's go-sctp; the files concerned keep his copyright notice,
and [NOTICE](NOTICE) lists them. [GO_LICENSE](GO_LICENSE), the BSD 3-Clause
license of the Go standard library, is kept for code derived from it, which
NOTICE names when there is any.
