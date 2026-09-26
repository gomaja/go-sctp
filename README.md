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

The package needs Go 1.26 or later, and uses the standard library only.

There are no releases: the module is followed on its `main` branch, and Go
records each commit you get as a pseudo-version. The API documented here
replaced v1 (v1.0.0 to v1.0.6) under the same module path, with no
compatibility layer; [MIGRATION.md](MIGRATION.md) maps every v1 identifier
to its successor. Because both APIs share one module path, and a build uses
one version of a module, every module in a build must move to the current
API together.

Use `@main`, not `@latest`, to get the package and to update it. One tag
above v1.0.6, made on the commit where the current API reached `main`, holds
the retraction of v1.0.0 to v1.0.6 in its `go.mod` (Go reads retractions
only from the newest version) and keeps `main`'s pseudo-versions sorting
above every v1 version; no other tag follows it. Once that tag exists,
`@latest`, and any tool that follows releases, resolves to it, the commit
where the current API landed, and v1.0.0 to v1.0.6 show as retracted;
before it exists, `@latest` resolves to v1.0.6, the old API. Later commits
are reached only with `@main` or a commit hash, and `go get -u` does not
move a module from one `main` commit to a newer one.

## Quick start

A server that echoes every message, and a client, over one-to-one sockets
used as `net.Listener` and `net.Conn`:

```go
package main

import (
	"context"
	"fmt"
	"log"
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
- **Messages.** `SendMsg` takes a `SendOptions`: stream, PPID and flags,
  a PR-SCTP policy, an AUTH key, the peer address to send to, and a
  single-attempt mode (`NoWait`). `RecvMsg` reports each read's metadata,
  and `ReadMsg` reassembles whole messages. A successful `SendMsg`, and a
  `RecvMsg` or `Read` of data, make no allocation.
- **Notifications.** Subscribe with `Config.Notifications` or
  `Conn.Subscribe`; a `NotificationHandler` receives parsed values such as
  `*AssocChange` and `*SendFailed`.
- **The end of an association.** Reads end with `io.EOF` after a graceful
  end on every kind of connection, and after a failure every read and send
  returns the same error (`ECONNRESET`, `ETIMEDOUT` or `ECONNABORTED`)
  instead of hanging.
- **Errors.** The errors of socket calls are `*net.OpError` values that
  name the call; test them with `errors.Is`. A refused argument matches `syscall.EINVAL` and
  names the field, and an option the kernel lacks matches
  `syscall.ENOPROTOOPT`.

## Kernel requirements

The package never checks a kernel version. It uses an option when a call
needs it, and a kernel without the option returns its own error for that
call; nothing else is affected. Each row gives the first upstream Linux
release whose UAPI header defines the facility (from the headers of every
release from 2.6.31 to 6.12; no facility disappears in a later release):

| Upstream Linux | Facility | API that needs it |
|---|---|---|
| 2.6.31 | `SCTP_SOCKOPT_CONNECTX3` and the base RFC 6458 options | `Dial`, `Listen`, and every option not listed below |
| 2.6.33 | `SCTP_SACK_IMMEDIATELY` | `SendSACKImmediately` |
| 3.0 | `SCTP_GET_ASSOC_ID_LIST`, `SCTP_SENDER_DRY_EVENT` | `Endpoint.AssocIDs`, `EventSenderDry` |
| 3.1 | `SCTP_AUTO_ASCONF` | `AutoASCONF`, `SetAutoASCONF` |
| 3.8 | `SCTP_GET_ASSOC_STATS` | `Stats` |
| 3.17 | `SCTP_RECVRCVINFO`, `SCTP_RECVNXTINFO`, `SCTP_DEFAULT_SNDINFO`, the `SNDINFO`/`RCVINFO`/`NXTINFO` messages | every socket: receive metadata is always on |
| 4.8 | `SCTP_PR_SUPPORTED`, `SCTP_DEFAULT_PRINFO`, `SCTP_PR_ASSOC_STATUS` | `Config.PartialReliability`, `PRSupported`, `DefaultPrInfo`, `PRAssocStatus` |
| 4.11 | `MSG_MORE` for SCTP | `SendOptions.More` |
| 4.11 | `SCTP_ENABLE_STREAM_RESET`, `SCTP_RESET_STREAMS`, `SCTP_RESET_ASSOC`, `SCTP_ADD_STREAMS`, `SCTP_STREAM_RESET_EVENT` | stream reconfiguration, `EventStreamReset` |
| 4.12 | `SCTP_RECONFIG_SUPPORTED`, `SCTP_PR_STREAM_STATUS`, the association-reset and stream-change events | `Config.StreamReconfiguration`, `ReconfigSupported`, `PRStreamStatus`, `EventAssocReset`, `EventStreamChange` |
| 4.13 | `SCTP_SOCKOPT_PEELOFF_FLAGS` | `Endpoint.PeelOff` |
| 4.15 | `SCTP_STREAM_SCHEDULER`, `SCTP_STREAM_SCHEDULER_VALUE` (FCFS, priority, round-robin) | `StreamScheduler`, `SchedFCFS`, `SchedPrio`, `SchedRR` |
| 4.16 | `SCTP_INTERLEAVING_SUPPORTED` | `Config.MessageInterleaving`, `InterleavingSupported` |
| 4.17 | `SCTP_AUTH_DEACTIVATE_KEY`, the per-message `PRINFO` and `AUTHINFO` messages | `DeactivateAuthKey`, `SendOptions.PR`, `SendOptions.AuthKey` |
| 4.19 | `SCTP_REUSE_PORT` | `Config.ReusePort` |
| **5.0** | `SCTP_EVENT` | **every socket**: the package subscribes to `EventAssocChange` on each, which is how it sees an association end; `Config.Notifications`, `Subscribe`, `Subscribed` |
| 5.4 | `SCTP_ASCONF_SUPPORTED`, `SCTP_AUTH_SUPPORTED`, `SCTP_ECN_SUPPORTED` | `Config.DynamicAddressReconfiguration`, `Config.Authentication`, `Config.ExperimentalECN`, their getters, and `InstallAuthKey`/`ActivateAuthKey` |
| 5.5 | `SCTP_PEER_ADDR_THLDS_V2`, `SCTP_EXPOSE_POTENTIALLY_FAILED_STATE`, `SCTP_SEND_FAILED_EVENT` | `PathThresholds`, `PFExposure`, `AddrPotentiallyFailed`, `EventSendFailed` |
| 5.11 | `SCTP_REMOTE_UDP_ENCAPS_PORT` | `RemoteUDPEncapsPort` |
| 5.14 | `SCTP_PLPMTUD_PROBE_INTERVAL` | `PLPMTUDProbeInterval` |
| 6.4 | the FC and WFQ stream schedulers (`SCTP_SS_FC`, `SCTP_SS_WFQ`) | `SchedFC`, `SchedWFQ` |

In practice: 5.0 for any socket, since every constructor subscribes with
`SCTP_EVENT`, and a kernel without it refuses the constructor with an error
matching `syscall.ENOPROTOOPT`.
Before 5.5 there is no send-failure notification at all, since the package
does not use the deprecated `SCTP_SEND_FAILED`, and `SchedFC` and `SchedWFQ`
are the only facilities that need a kernel newer than 5.14.

Vendor kernels count by facility, not by version number. The RHEL 8 kernel
is 4.18; the CentOS Stream 8 source at 4.18.0-448.el8 (January 2023) has
every facility above except the FC and WFQ schedulers, including the
backported `SCTP_EVENT`, `SCTP_PEER_ADDR_THLDS_V2` and
`SCTP_SEND_FAILED_EVENT`. Earlier RHEL 8 kernels were not checked.

Some behaviour also depends on `net.sctp` sysctls, and the calls concerned
say so: `MessageInterleaving` needs `net.sctp.intl_enable`, PR-SCTP is
offered only while `net.sctp.prsctp_enable` is on, and UDP encapsulation
needs `net.sctp.udp_port`. Where SCTP is a module, the kernel loads it on
the first SCTP socket; where it is absent and cannot be loaded, the
constructors fail with an error matching both `sctp.ErrUnsupported` and the
kernel's `EPROTONOSUPPORT` (or `ESOCKTNOSUPPORT`).

## Platforms

Sockets work on Linux, on every architecture Go supports, and on Android,
which Go builds with the `linux` tag. On `linux/386` the socket calls go
through `socketcall(2)`, and a 32-bit program on a 64-bit kernel uses the
kernel's 64-bit layout for the options whose layout depends on the word
size.

On the other platforms, the BSDs, macOS, Windows, Solaris, illumos and AIX
among them, the package compiles, `ResolveAddr` and `ParseNotification` work,
and the constructors return a `*net.OpError` that wraps `sctp.ErrUnsupported`,
which wraps `errors.ErrUnsupported`:

```go
if errors.Is(err, errors.ErrUnsupported) {
	// no SCTP on this platform
}
```

`js/wasm` and `wasip1/wasm` compile the same way. `plan9` does not: its
`syscall` package has no `Errno` type.

What continuous integration runs on each target:

| Target | What runs |
|---|---|
| `linux/amd64` | The whole suite against the runner's SCTP stack, with Go 1.26 and the latest Go, in both sysctl states (below); again under `-race`, and under `-gcflags=all=-d=checkptr` |
| `linux/386` | The whole suite, natively on the x86_64 runner, so the `socketcall` path and the 32-bit layouts run against a real kernel; and the raw system-call tests again with the goroutine stack moved at every function call |
| `linux/s390x` | The tests that need no socket, under qemu: byte order, structure layouts, control messages and addresses on a big-endian machine. qemu's user-mode emulation cannot pass SCTP socket options through, so the socket tests cannot run there |
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
not built there, and a green run proves nothing about them. They run
against a Linux kernel in Docker:

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
