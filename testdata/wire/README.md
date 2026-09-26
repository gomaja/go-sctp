# Two-host and wire tests

Some SCTP behaviour can only be proven between two hosts, and some only from
the packets themselves: that an `Abort` puts an ABORT chunk on the wire at
once, that `SendSACKImmediately` sets the I bit, that a refused `NoWait` send
leaves no DATA behind. An in-process assertion can only show what the API
returned; a capture shows what the kernel sent. `run.sh` runs the package's
own test binary on two Linux hosts, captures on the one that sends, and
proves each wire claim from the capture with `analyze`.

```sh
testdata/wire/run.sh [-race] [-run REGEX] [-only wire|twohost]
```

- `-race` builds the test binary with the race detector.
- `-run REGEX` selects cases (subtests of `TestWire` and `TestTwoHost`) and
  the claims of the same names. The capture sentinel (below) always runs.
- `-only wire` or `-only twohost` runs one of the two phases.
- `WIRE_OUT` names the artifact directory (default: a new temporary one);
  `WIRE_GO_IMAGE` the Go image the harness image is built from (default
  `golang:1.26.5-bookworm`).

It needs only Docker, with privileged containers allowed, on Linux or Docker
Desktop, runs unattended, and its exit status is the verdict: 0 only when
every test on both hosts passed, none skipped, and every claim held. It
removes every container, network and image tag it creates, also when it is
interrupted (INT or TERM end it after the cleanup).

## What runs where

`run.sh` builds an image from the Go image plus `tshark`, `dumpcap`,
`iptables`, `iproute2` and `ethtool`; builds the package's test binary
(`go test -c`), the analyzer and `testdata/docker/summarize.go` once, for the
Docker host's architecture; and vets and tests the analyzer, which
`go vet ./...` does not reach under `testdata/`. It then starts two
`--privileged` containers, a client and a server, joined by two Docker
networks, A and B, so that each host has an address on two separate paths.

Each container runs the same test binary with:

| Variable | Value |
| --- | --- |
| `SCTP_WIRE_ROLE` | `client` or `server` |
| `SCTP_WIRE_PEER` | the other host's addresses on networks A and B, separated by `/` |
| `SCTP_WIRE_FACTS` | a file where the test records, per case, the ports, API call times and counts the analyzer checks |

Without `SCTP_WIRE_ROLE`, `TestWire` and `TestTwoHost` skip and say why, so
an ordinary `go test` run, including `testdata/docker/linux-suite.sh`, lists
them as two skips naming this script. They are compiled into every Linux
test build, so the standard `go vet`, `staticcheck` and `golangci-lint`
runs check them.

Both processes run the same cases in the same order. For each case they meet
over a TCP connection to the server (port 7411), which also carries the
case's steps: "ready", "silent", "closing" and so on. SCTP is never used for
the coordination, so a case can drop every SCTP packet of an association
without cutting its own control path.

The run has two phases. **Wire**: the capture runs, `TestWire` runs on both
hosts, the capture stops, and `analyze` checks it. **Two-host**: `TestTwoHost`
runs on both hosts; its cases need a second host but no capture, and their
own assertions are the verdict.

## Loss, capture and the traps they avoid

- **Loopback cannot stand in for a path.** Traffic on `lo` bypasses the
  queueing layer, so `netem` attached to it affects nothing, and a peer on
  loopback has every local address in scope. Every case that needs loss, or
  a peer at a private address, runs between the two containers.
- **Drop on the receiver's INPUT, capture on the sender.** The capture runs
  on the client, the sending host of every wire claim, on both of its
  interfaces. Where a case needs loss, the receiving host installs an
  `iptables` rule on its own INPUT hook (`-p sctp -m sctp --dport|--sport
  PORT [--chunk-types any TYPE]`). A drop on the sender's OUTPUT would
  discard the packet before the sender's capture point and hide exactly
  what the claim is about. Every rule carries a comment naming its case, and
  the case reads the rule's packet counter before removing it: a rule that
  matched nothing never made the loss the case depends on, and fails it.
- **Offloads off.** Segmentation offload lets the kernel hand the device one
  super-packet that the device splits later, so the capture would not show
  the packets on the wire. `run.sh` turns GSO, TSO, GRO and SCTP segmentation
  off on every interface, and `analyze` refuses any frame larger than the
  interfaces' MTU allows.
- **The capture is proven complete.** The capture socket hands packets over
  in blocks, each once it is full or its timeout passes, so packets at the
  very end are lost if the capture is stopped at once. The last case,
  `capture-sentinel`, sends an INIT to a closed port on each network, and
  `analyze` requires both: a capture holds each interface's packets in the
  order they crossed it, so every packet before a sentinel is in it. Every
  claim that rests on the absence of a packet, such as "no ABORT at the
  grace expiry", is checked only up to the earlier sentinel. `run.sh` waits
  two seconds before stopping the capture, and fails if `dumpcap` reports a
  dropped packet on either interface.
- **Kernel settings.** Both hosts run with `net.sctp.prsctp_enable=1`
  (RFC 3758) and `net.sctp.intl_enable=0`, so messages travel in DATA
  chunks rather than I-DATA chunks (RFC 8260).
- **No port can stand for two associations.** A case's packets are found by
  its server port, in both directions: frames the client sends to it and
  frames the server sends from it. The analyzer never matches a port alone,
  and `run.sh` sets `net.ipv4.ip_local_port_range` to 49152-60999 on both
  hosts (the dynamic range of RFC 6335 §6), so that no dialer's own
  ephemeral port can equal a case port (41001-41109) or the control port;
  the tests refuse to run when a case port lies in the range.

## Timing

Both containers run on the Docker host's kernel and read one clock: the test
processes through `time.Now` (`CLOCK_REALTIME`) and the capture through the
kernel's packet timestamps. A case records the wall-clock time just before
and just after the call being timed, and `analyze` compares those with the
frames' timestamps. The capture's timestamps have microsecond resolution;
comparisons allow 1 ms for that and for the instant between reading the
clock and making the call. "ABORT less than 100 ms after `Abort`" means the
ABORT frame's timestamp is at most 1 ms before, and less than 100 ms after,
the time recorded just before the call.

## Wire claims

Each is one case of `TestWire` (`wire_linux_test.go`) and one check in
`analyze/claims.go`, found in the capture by the server port the case uses.

| Claim | The case | The capture must show |
| --- | --- | --- |
| `abandon-abort-cookie-wait` | `Dial` with `AbandonAbort`, a 500 ms context, the server dropping every packet of the setup | INIT, nothing from the server, then exactly one ABORT, carrying the User-Initiated Abort cause (RFC 9260 §3.3.10.12), between the context's deadline and `Dial`'s return, and nothing after it |
| `abandon-quiet-cookie-wait` | the same with `AbandonQuiet` | INIT, nothing from the server, and nothing at all from the client from the deadline on |
| `abandon-abort-cookie-echoed` | `AbandonAbort`, the server dropping only the COOKIE ECHO | INIT, INIT ACK, COOKIE ECHO before the deadline, no COOKIE ACK, then exactly one ABORT, as above (RFC 9260 §§5.1, 9.1) |
| `abandon-quiet-cookie-echoed` | the same with `AbandonQuiet` | INIT, INIT ACK, COOKIE ECHO, no COOKIE ACK, and nothing from the client from the deadline on |
| `abort-during-close` | `Close` with a 3 s grace while the server drops everything, `Abort` 500 ms later | the SHUTDOWN before the `Abort`, exactly one ABORT, with the User-Initiated Abort cause, within 100 ms of the call, nothing after it up to the sentinel, past the grace expiry (RFC 9260 §§9.1, 9.2) |
| `abort-during-peeled-close` | the same on a connection peeled off an `Endpoint` | the same |
| `abort-during-endpoint-close` | the same with `Endpoint.Close` and two associations | the same on both associations |
| `peeled-close-full-buffer` | a peeled connection fills its send buffer against a closed window, calls `Close`; the server reads a second later | every queued message acknowledged only after `Close` and the SHUTDOWN only after the server starts reading and after the last acknowledgement, then SHUTDOWN ACK and SHUTDOWN COMPLETE, no ABORT; the server reads every message, then `io.EOF` |
| `endpoint-close-full-buffers` | the same with `Endpoint.Close` and two associations | the same on both associations |
| `sack-immediately` | one message without and one with `SendSACKImmediately` | I bit clear, then set (RFC 9260 §§3.3.1, 11.1.5) |
| `unordered` | `SendUnordered` per message; an explicit `SndInfo` without it; a send with only `PR` and a default `SndInfo` that sets it | U bit set, clear, set |
| `request-heartbeat` | two-homed association, periodic heartbeats off: a quiet window, `RequestHeartbeat` for network B's address, then for the zero address | no HEARTBEAT, then exactly one to network B's address, then exactly one to each address (RFC 9260 §8.3) |
| `nowait-refusal` | fill the send buffer, one more `NoWait` send refused with `EAGAIN` | no DATA with the refused message's PPID anywhere in the capture; every queued message, and the one sent after, on the wire |
| `path` | two-homed association: messages with and without `SendOptions.Path` set to network B's address | every DATA chunk with `Path` to network B, every other one to the primary, network A |
| `more` | `NoDelay` on: two small messages, then two more with `More` on the first | two packets of one DATA chunk, then one packet holding both |
| `ppid-byte-order` | PPIDs `0x01020304`, `0x11223344`, `0x89abcdef`, `0xfedcba98` through an explicit `SndInfo`, `Write` with a `Config` default, and a PR-only send with a default set by `SetDefaultSndInfo` | each DATA chunk's PPID field equals the value given (network byte order, RFC 9260 §3.3.1), the server's `RcvInfo.PPID` equals it too, and no DATA chunk carries a byte-swapped one |
| `close-after-burst` | 100 messages against a window the server opens only after the `Close` call | DATA of the burst after the `Close` call, every message on the wire and acknowledged before the SHUTDOWN, then SHUTDOWN ACK, SHUTDOWN COMPLETE, no ABORT; the server reads all 100, then `io.EOF` (RFC 9260 §9.2) |
| `simultaneous-close` | both ends call `Close` at one instant while each drops the other's SHUTDOWN; the drops are lifted 300 ms later | both SHUTDOWNs before any SHUTDOWN ACK, so both ends were in SHUTDOWN-SENT at once, then SHUTDOWN COMPLETE and no ABORT either way (RFC 9260 §9.2) |
| `pr-rtx-limit` | one message with a `PRRtx` limit of 2 while the server drops everything | the message's TSN exactly three times, then a FORWARD TSN past it (RFC 3758 §3.5), the next message after it; `PRStreamStatus` and `PRAssocStatus` report it abandoned after being sent, and the server never receives it (RFC 7496 §4) |
| `graceful-close` | `Close` after one message | SHUTDOWN, SHUTDOWN ACK, SHUTDOWN COMPLETE in that order, no DATA after the SHUTDOWN, no ABORT; `io.EOF` on the server |
| `graceful-peeled-close` | the same on a peeled connection | the same |

## Two-host cases

`TestTwoHost` (`twohost_linux_test.go`); each passes only when both hosts'
halves pass.

| Case | What it proves |
| --- | --- |
| `local-addrs-wildcard-sctp4`, `-sctp` | a wildcard-bound client dialing a private address: the endpoint's address set (`SCTP_GET_LOCAL_ADDRS` with id 0) holds 127.0.0.1, `LocalAddrs` and `LocalAddr` hold the association's set, which does not (RFC 6458 §9.5; the association's set is restricted to the peer's scope) |
| `etimedout-dialed`, `-accepted`, `-peeled` | the peer drops everything, a message is outstanding, `AssocInfo.MaxRetrans` is 2 (RFC 9260 §8.1): a reader parked before the failure and every later read and send return `ETIMEDOUT`, with no further `sendmsg` |
| `pr-default-ttl-config`, `-setters`, `-endpoint` | default `SndInfo` and a default `PrInfo` with a 1 ms `PRTTL`, set through `Config`, through the setters with the `SndInfo` last, or on an `Endpoint`; one message for each combination of `SendOptions.Info` and `PR` while the peer drops them: `PRAssocStatus(PRTTL)` counts exactly the messages that carry the default policy, and the peer receives exactly the others |
| `eshutdown-while-blocked` | the server calls `Shutdown`; the client drops the SHUTDOWN COMPLETE, so it stays in SHUTDOWN-ACK-SENT: every send fails with `ESHUTDOWN` for a second, and with `EPIPE` once the drop is lifted and the association ends, without `SIGPIPE` |

## Failure semantics

`analyze` checks each claim's packets before the facts that cross-check
them (counts the server saw, PR status, the drop counters), so a claim
whose test half failed early still reports what the capture shows.

`analyze` fails closed. A missing or empty capture, a `tshark` that lacks a
field it reads (checked with `tshark -G fields`), a malformed field, DATA,
SACK or FORWARD TSN fields that do not line up with the chunk types, a frame
from an unknown host or larger than the MTU allows, a missing sentinel, a
fact recorded twice, facts for a case no claim checks, a claim without facts
or without a single frame on its port: each is a failure, never a skip. Its
own tests (`go test ./testdata/wire/analyze`, which `run.sh` runs) pin those
rules and each claim's pass and fail cases on synthetic captures.

## Versions

The image installs `tshark`, `dumpcap` and the other tools from the Go
image's Debian release without pinning versions, since pinned packages
disappear when mirrors move on. Instead, every run records what it used in
`environment.txt`: the kernel and architecture, Go, `tshark` and `dumpcap`
versions, the MTU, the `net.sctp` settings and the ephemeral port range.
Whatever `tshark` a run gets, `analyze` first checks with `tshark -G fields`
that it knows every field a claim reads, and refuses to run otherwise.

## Artifacts and the committed evidence

The artifact directory holds the capture (`sender.pcapng`), `dumpcap`'s log,
each host's test2json stream and readable log with its summary, the facts,
`wire-report.txt`, and `environment.txt`.

`expected/` holds the text evidence of the run that qualified the current
code, never a capture: `wire-summary.txt`, the analyzer's report, claim by
claim with the frames and fields that prove it; `twohost-summary.txt`, each
host's case results and recorded facts; and `environment.txt`, the versions
and settings of that run. Addresses
appear as `client-a`, `server-b` and so on, and nothing in them names the
machine. To refresh them, run `run.sh` and copy the `expected/` directory of
its artifacts over this one; frame numbers, TSNs and times change from run
to run.
