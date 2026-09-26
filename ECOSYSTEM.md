<!-- Copyright 2026 gomaja. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- This file includes modifications by gomaja. -->

# Go SCTP ecosystem audit

This document records what other SCTP libraries, and their issue trackers,
taught this package: the defects they hit, the features their users asked
for, and what was adopted here, tested here, or deliberately left out. It is
an engineering record, not a standards hierarchy: the standards baseline is
[STANDARDS.md](STANDARDS.md), and no other implementation is taken as proof
of conformance.

It holds three surveys, newest first: the research behind the current API,
a refresh of the direct comparators, and the original survey of every Go
SCTP implementation. Each is a point-in-time record; the counts are those
of the trackers when the survey was made.
The research recorded counts per source, without per-repository snapshot
revisions.

## API redesign research

The current API was shaped by a survey of the issues and pull requests of
the other SCTP bindings, in Go and in other languages, made in September
2026 while the API was being designed. Every claim about kernel behaviour
that changed the API was checked in the Linux 6.12 source before it was
accepted.

### Sources

- **Go kernel bindings**, 115 issue and pull-request records in all:
  ishidawataru/sctp, free5gc/sctp, georgeyanev/go-sctp, thebagchi/sctp-go,
  loxilb-io/sctp, fkgi/extnet, M1tsumi/Go5GSCTP and 3vilM33pl3/go-sctp. A
  search for new Go bindings found one, gnalloy/transport-sctp, whose
  tracker was empty.
- **pion/sctp**, the user-space engine, 511 records.
- **Other languages**: the Java SCTP API (`com.sun.nio.sctp`) and its
  OpenJDK bugs, Erlang/OTP's `gen_sctp`, the Rust, Python (pysctp) and C
  (lksctp-tools) bindings, and golang/go's own tracker.

### Adopted into the API

| Change | Evidence | Kernel check |
|---|---|---|
| No end-of-association send flag (`SCTP_EOF`) | Java and Erlang model shutdown as a call, not a flag | `sctp_sendmsg_parse` refuses `SCTP_EOF` and `SCTP_ABORT` on one-to-one sockets, and `SCTP_EOF` with a payload; where it accepts them they do what `Endpoint.CloseAssoc` and `Close` do |
| `InstallAuthKey` and `ActivateAuthKey` switch AUTH on first | lksctp-tools #69 | `net/sctp/auth.c` refuses every key operation with `EACCES` while the endpoint's AUTH is off; `SCTP_AUTH_SUPPORTED` turns it on |
| `SendFailed` per DATA chunk, with the chunk's own bits | The Java and Erlang notification models | `net/sctp/chunk.c` emits one event per chunk; `net/sctp/ulpevent.c` copies the chunk's flags into `snd_flags` |
| Peeled-off connections end with `io.EOF` after a graceful end, and inherit the endpoint's settings | lksctp-tools #70; erlang/otp PRs #8804 and #11007 | `sctp_cmd_new_state` marks only one-to-one sockets shut for reading |
| `SendOptions.Path`, on connections from `Dial`, `Accept` and `FileConn` | Java's `MessageInfo.createOutgoing(address)`, Erlang's `addr_over` | `sctp_sendmsg` sends a one-to-one socket's message on `msg_name`'s path; a peeled socket ignores it (`sctp_sendmsg_get_daddr`) |
| `SendOptions.More` | Batching requests in other bindings | `asoc->force_delay` follows `MSG_MORE`, since Linux 4.11 |
| `ErrUnsupported` for Linux without SCTP too | JDK-8267938 | `inet_create` returns `EPROTONOSUPPORT` once loading the module fails |
| A typed `AddrChangeReason` | Review of the UAPI | `enum sctp_sn_error`; Linux also sends 0 for "no reason" (`sm_sideeffect.c`) |
| Kernel requirements stated per facility, and the RHEL 8 claim corrected | The UAPI headers of every release from 2.6.31 to 6.12 | CentOS Stream 8 lacks `SCTP_SS_FC` and `SCTP_SS_WFQ` |
| Documented: association-id reuse, the ABORT cause needing a subscription, `EINPROGRESS` during stream reconfiguration, a multi-address `Listener.Addr`, and what Linux does not provide | Java's `Association` documentation; pion #486/#487, #508/#509, #59/#316/#369/#490; golang/go #9334 | `idr_alloc_cyclic`; `strreset_outstanding` in `net/sctp/stream.c`; `sctp_ioctl` has no `SIOCOUTQ` |

### Adopted as tests

| Record | What it showed | Test |
|---|---|---|
| georgeyanev/go-sctp PR #7 | A descriptor closed twice closes an unrelated file that reused its number | `TestDoubleCloseRegression` |
| thebagchi/sctp-go #5 | Address lists that mix IPv4 and IPv6 entries were decoded with one stride | `TestDecodeAddrsMixedFamilies`, also under `-d=checkptr` in CI |
| pion/sctp #361 | Data queued before a close was lost | wire claim `close-after-burst`: every queued message is on the wire before the SHUTDOWN |
| pion/sctp #469, #480-#483 | Both ends closing at once | wire claim `simultaneous-close`: a graceful end with no ABORT |
| pion/sctp #374, #504, #505 | Partial reliability limits | wire claim `pr-rtx-limit`: a `PRRtx` limit abandons the message after exactly that many retransmissions, and `PRStreamStatus` counts it |
| pion/sctp #470 | An unassigned cause code in an ERROR | `TestParseNotificationRemoteErrorUnassignedCause` |
| pion/sctp #508, #509 | A second stream reset while one is outstanding | `TestReconfigurationRequestInProgress`: `EINPROGRESS` |
| JDK-8067846 | A notification larger than a fixed struct was rejected | `TestParseNotificationLongerThanAnyFixedStruct` |
| JDK-8261601 | A receive path leaked the buffer it allocated for an oversized notification | `TestNotificationAccumulator`: reassembly storage is bounded between notifications |
| erlang/otp #4334 | Association id 0 in an association change | `TestParseNotificationAssocChangeAssocIDZero` |
| erlang/otp PR #1592 | A non-blocking connect on a one-to-many socket has an id already | `TestEndpointConnectReturnsTheIDWhileSetupIsInProgress` |
| lksctp-tools #32, pysctp #30 | Binding IPv4 and IPv6 addresses together on an IPv6 socket | `TestEndpointBindAddMixedFamilies` |
| lksctp-tools #68 | A control buffer too small for every record of one send | `TestAppendSendCmsgsAllThreeFitsSndCmsgSpaceExactly` |
| lksctp-tools #69 | AUTH key calls fail while `net.sctp.auth_enable` is off | `TestAuthHelpersWithSysctlOff` |
| lksctp-tools #70 | Peeled-off connections never see a graceful end | `TestGracefulEndReachesEOF` and `TestAssociationErrorSticky`, on dialed, accepted and peeled connections |
| pysctp #46, #48 | PPID byte order | wire claim `ppid-byte-order`: network order on the wire, host order in the API |
| pysctp #54, #55 | Integer width in a binding's glue code | `TestReadMsgMemoryFollowsMessage`, with `ReadMsg(1<<24-1)`, also on linux/386 in CI |

The wire claims are checked from packet captures between two hosts by
`testdata/wire/run.sh`.

### Considered and not adopted

| Proposal | Reason |
|---|---|
| A logging hook (pion #31) | The package holds almost no protocol state to log; the kernel does. One unmerged 2019 pull request was the only demand |
| A handler result that makes a read return at once (Java's `HandlerResult.RETURN`) | A handler that returns an error already ends the read, and `errors.Is` identifies it; a second mechanism would do the same |
| Delivering `EventAssocChange` records to callers who did not subscribe | Simple callers would get records they never asked for. The package keeps the subscription in the kernel for its own use, and delivers the records only on request |
| The number of bytes still queued to send | Linux does not report it (no `SIOCOUTQ` for SCTP), and counting it in Go would bring back the queue-bookkeeping defects pion documents |
| Congestion-control selection, RFC 9653 zero checksum, out-of-band association tokens | Linux has no interface for them |
| `SendOptions.Path` on an `Endpoint` | The kernel would find the association by the address, not by the given id, which can send a message on the wrong association. It could be added later, with that check, without breaking anything |
| Tests of kernel protocol behaviour (pion #106, #445, #493, #495, and INIT, SACK and FORWARD-TSN edge cases) | The kernel owns that behaviour; they belong in a kernel qualification, not in the package's suite |
| pion's races on per-stream objects (about 24 records) | The package has no per-stream objects |

## Focused direct-comparator refresh (2026-08-26)

The direct kernel-binding comparators were rechecked on **2026-08-26**. This
refresh records only the changes that could affect this package; the
aggregate counts are the 2026-08-01 survey's.

| Repository | Default branch revision | Issues | Pull requests |
| --- | --- | ---: | ---: |
| [gomaja/go-sctp](https://github.com/gomaja/go-sctp) | `main` at [`5a28aca1fcd0`](https://github.com/gomaja/go-sctp/commit/5a28aca1fcd039e7b7d41283c238bd12994cce67) | 0 | 3, 1 open |
| Legacy kernel-wrapper corpus | `master` at `19ddcbc6aae2` | 37, 23 open | 55, 6 open |
| [free5gc/sctp](https://github.com/free5gc/sctp) | `main` at [`e86160f55c75`](https://github.com/free5gc/sctp/commit/e86160f55c756c02d7bdd1ab7c852fc3676c6dbd) | 0 | 8, 1 open |
| [georgeyanev/go-sctp](https://github.com/georgeyanev/go-sctp) | `master` at [`5ffbc5b0c8e7`](https://github.com/georgeyanev/go-sctp/commit/5ffbc5b0c8e75d28da356f4c725af18d285ccf32) | 0 | 6 |

The legacy default branch and the georgeyanev revision were unchanged. Two
new legacy pull requests, #91 and #92, proposed listener and connection
deadlines through `SO_RCVTIMEO` and `SO_SNDTIMEO`. They confirm that
deadlines and close wakeups remain open defects in the ecosystem, but their
per-system-call timeouts do not meet Go's deadline contract: changing a
deadline does not reliably interrupt a call already blocked. This package
waits in Go's runtime poller instead, where a deadline applies to pending
and future calls, can be moved or cleared, belongs to one descriptor, and
does not pass from a listener to an accepted connection.

[free5gc/sctp PR #8](https://github.com/free5gc/sctp/pull/8) merged as the
lightweight tag `v1.2.0`. Its locking of close against I/O, its nil-address
validation and its added error context confirm those defect classes. Its
code was not taken: it wraps raw descriptor helpers as well as high-level
calls, with an error package of its own. Here every call on a socket
returns a `*net.OpError` naming the call, from which `errors.Is` and
`errors.As` reach the cause.

That release also failed to build on Darwin and Windows, because shared calls
no longer matched its platform stubs; its PR #3 was the pending fix. This
package's API is the same on every platform, with the constructors returning
`ErrUnsupported` where there is no SCTP, and CI builds it for thirteen
targets. free5gc's [`setInitOpts` comment](https://github.com/free5gc/sctp/blob/e86160f55c756c02d7bdd1ab7c852fc3676c6dbd/sctp.go#L255-L257)
still cited the obsolete RFC 4960; the current base is RFC 9260.

## Original survey (2026-08-01)

### Scope and method

The survey looked for importable Go libraries, Linux SCTP socket bindings,
user-space SCTP protocol engines, Go runtime integrations, and repositories
whose names or descriptions made them plausible candidates. For each, it
inspected the default branch, its exact revision, the repository contents,
and the issue and pull-request history. Issues and pull requests were
counted separately.

The result was 20 repositories and 596 issue or pull-request records:

- 151 issues, 56 of them open;
- 445 pull requests, 31 of them open; and
- 87 open records in all.

Each record was classified by whether it showed a transferable defect, an
API or ABI gap, a protocol-algorithm concern, project-specific behaviour, or
administrative work. The tables below name every repository. The findings
section records every theme that led to a local action; the other records
were support questions, dependency and CI maintenance, project
administration, features outside this package's boundary, or fixes with no
counterpart here.

### Direct implementations and architectural comparators

| Repository | Pinned default branch revision | Classification | Issues | Pull requests |
| --- | --- | --- | ---: | ---: |
| [gomaja/go-sctp](https://github.com/gomaja/go-sctp) | `main` at [`eba003e63e6e`](https://github.com/gomaja/go-sctp/commit/eba003e63e6e183df2a209746665fa3252a0fbeb) | This repository; Linux kernel socket binding | 0 | 0 |
| Legacy kernel-wrapper corpus | `master` at `19ddcbc6aae2` | Maintained source lineage and primary wrapper issue corpus | 37, 23 open | 53, 4 open |
| [free5gc/sctp](https://github.com/free5gc/sctp) | `main` at [`d88ea73eeeb1`](https://github.com/free5gc/sctp/commit/d88ea73eeeb1cc25a9bff6ea2b146e59be505ef5) | Maintained derivative of an earlier kernel wrapper | 0 | 8, 2 open |
| [georgeyanev/go-sctp](https://github.com/georgeyanev/go-sctp) | `master` at [`5ffbc5b0c8e7`](https://github.com/georgeyanev/go-sctp/commit/5ffbc5b0c8e75d28da356f4c725af18d285ccf32) | Independent Linux wrapper; runtime-poller and socket-option comparator | 0 | 6 |
| [loxilb-io/sctp](https://github.com/loxilb-io/sctp) | `master` at [`2c12de5f2b3e`](https://github.com/loxilb-io/sctp/commit/2c12de5f2b3e6fe6eb334d019dd79e3b5db3ba9c) | GitHub fork and older derivative of an earlier kernel wrapper | 0 | 1 |
| [pion/sctp](https://github.com/pion/sctp) | `main` at [`37fef17855bc`](https://github.com/pion/sctp/commit/37fef17855bc720b31c09e8c8643aa67122aff7e) | User-space SCTP protocol engine; parser, state-machine, and concurrency corpus | 106, 30 open | 373, 23 open |
| [thebagchi/sctp-go](https://github.com/thebagchi/sctp-go) | `master` at [`a870aadd46af`](https://github.com/thebagchi/sctp-go/commit/a870aadd46afb95334f74c462ba20da1b594295e) | Independent Linux wrapper; one-to-many and unsafe-ABI comparator | 5 | 1 |
| [fkgi/extnet](https://github.com/fkgi/extnet) | `master` at [`d1c0d7238f6c`](https://github.com/fkgi/extnet/commit/d1c0d7238f6ca1250e2c61e3f874ba4c68cca6f6) | Older wrapper; association multiplexing and notification-error corpus | 1, 1 open | 0 |
| [3vilM33pl3/go-sctp](https://github.com/3vilM33pl3/go-sctp) | `main` at [`9e952b78d047`](https://github.com/3vilM33pl3/go-sctp/commit/9e952b78d047742bc66d41957c281fcb7f42edc5) | Full Go toolchain fork with SCTP integrated into `net` and the runtime poller | 0 | 1, merged |
| [M1tsumi/Go5GSCTP](https://github.com/M1tsumi/Go5GSCTP) | `main` at [`83947455a46b`](https://github.com/M1tsumi/Go5GSCTP/commit/83947455a46b346c2c2a3e59c8683c4b0a093293) | High-level 5G/NGAP adapter over a Linux SCTP wrapper, not a socket implementation | 0 | 2, both automation and open |

These ten repositories account for 594 of the 596 records.

### Screened candidates that are not independent comparators

| Repository | Pinned default branch revision | Classification | Issues | Pull requests |
| --- | --- | --- | ---: | ---: |
| [jamesruan/sctp](https://github.com/jamesruan/sctp) | `master` at [`b64095ee4250`](https://github.com/jamesruan/sctp/commit/b64095ee42502e8e8c36b20e9c6fdb51c144d996) | Incomplete user-space packet-format skeleton; no association engine | 0 | 0 |
| [ilya-a-sergeyev/go-sctp-linux](https://github.com/ilya-a-sergeyev/go-sctp-linux) | `master` at [`1ece7ee5fa01`](https://github.com/ilya-a-sergeyev/go-sctp-linux/commit/1ece7ee5fa01a0159a6bae027856d2939e0aad29) | 2017 source overlay for Go's `net` and `syscall` trees, not an importable module | 2, both open | 0 |
| [qmwd2006/go-sctp](https://github.com/qmwd2006/go-sctp) | `master` at [`51e3ea3ed528`](https://github.com/qmwd2006/go-sctp/commit/51e3ea3ed5288d3aac63a75770a7dc213773ddc7) | Old Go source-tree snapshot; no SCTP transport implementation was present | 0 | 0 |
| [javen-yan/sctp](https://github.com/javen-yan/sctp) | `listener` at [`8b53eeb5e314`](https://github.com/javen-yan/sctp/commit/8b53eeb5e314911cdfbaa073d0540674410c62f4) | 2020 copy of Pion SCTP under a different module path | 0 | 0 |
| [herugen/sctp](https://github.com/herugen/sctp) | `master` at [`d072acdaadc0`](https://github.com/herugen/sctp/commit/d072acdaadc0ad8232528bca872fd51892f4584b) | Stale derivative of an earlier kernel wrapper | 0 | 0 |
| [meng72/sctp](https://github.com/meng72/sctp) | `main` at [`4a58d42d1b71`](https://github.com/meng72/sctp/commit/4a58d42d1b71cdcc90eef20e8bb57557d8bbf28a) | Stale wrapper derivative with no independent tracker evidence | 0 | 0 |
| [lakshya-chopra/sctp](https://github.com/lakshya-chopra/sctp) | `master` at [`ce3b2e26c3ca`](https://github.com/lakshya-chopra/sctp/commit/ce3b2e26c3caf6daf2a2a73e23d5034083847a95) | Small earlier-lineage copy without a Go module | 0 | 0 |
| [Vineet0197/sctp](https://github.com/Vineet0197/sctp) | `master` at [`cf08ef10a984`](https://github.com/Vineet0197/sctp/commit/cf08ef10a98471d3500220ae4fe45c46801dd5d7) | Incomplete wrapper scaffold, not a usable transport | 0 | 0 |
| [krsnucc21/sctp-go](https://github.com/krsnucc21/sctp-go) | `master` at [`25e9628482ef`](https://github.com/krsnucc21/sctp-go/commit/25e9628482ef78d031dccbddcfcf678947a6ee54) | Copy retaining an earlier SCTP wrapper as its module identity | 0 | 0 |
| [ducnm23/go-sctp](https://github.com/ducnm23/go-sctp) | `master` at [`12e0881eb3d5`](https://github.com/ducnm23/go-sctp/commit/12e0881eb3d5e553924b4cc40da73e5c645c017c) | Client/server demonstration using Pion SCTP, not an implementation | 0 | 0 |

The two open records outside the direct-comparator table are
[ilya-a-sergeyev/go-sctp-linux #1](https://github.com/ilya-a-sergeyev/go-sctp-linux/issues/1),
about an `SCTP_INITMSG` socket-option test, and
[#2](https://github.com/ilya-a-sergeyev/go-sctp-linux/issues/2), a request to
package the source changes as a patch. Neither affects this package.

### Implementation boundaries

The surveyed projects fall into three different models:

1. **Kernel socket bindings**, including this package, the legacy wrapper
   corpus, free5gc, georgeyanev, loxilb, thebagchi and fkgi. Linux owns the
   association state, chunks, retransmission, congestion control, path
   management, SACK generation and checksums. The Go package owns descriptor
   lifetime, the socket-option and ancillary-data ABI, address encoding,
   message framing and the `net` interfaces.
2. **User-space protocol engines**, principally Pion, which own protocol
   state and wire encoding over a transport such as DTLS. Their parser and
   algorithm failures are valuable hostile test cases, but their
   implementation choices cannot establish the correctness of a kernel
   binding.
3. **Go runtime integrations**, 3vilM33pl3 and the older ilya overlay. They
   show how SCTP can join Go's network poller, but they need a custom
   toolchain and cannot be imported.

So **Pion is not a compliance oracle for a kernel binding**. A Pion issue
about a malformed chunk, a retransmission timer, a congestion controller or
a SACK algorithm becomes, here, a wire observation of the kernel or a kernel
qualification, never a reason to copy user-space protocol code. Pion's
defects in buffers, deadlines, close wakeups, parsers and concurrency often
do transfer, because those are Go API contracts, not protocol choices.

### Obsolete standards references found upstream

RFC 4960 is obsolete; RFC 9260 replaced it, incorporating the I bit and
earlier updates, with its own errata. At the pinned revisions, the legacy
wrapper corpus, free5gc, loxilb, herugen, meng72, lakshya-chopra and
krsnucc21 kept the same RFC 4960 comment from their shared lineage;
georgeyanev cited RFC 4960 in notification documentation; jamesruan
described its unfinished implementation as RFC 4960; javen-yan, an older
Pion copy, cited RFC 4960; and Pion's README described a subset of RFC 4960,
while [issue #402](https://github.com/pion/sctp/issues/402) tracks its
migration to RFC 9260.

Those citations are not kept here as current, nor silently renumbered:
every behaviour this package takes from a standard cites RFC 9260, its
verified errata, RFC 6458 or the Linux UAPI, as [STANDARDS.md](STANDARDS.md)
requires. The legacy wrapper's issue #45, "Compliance to RFC 4960", is
answered by that baseline rather than adopted as written.

### Findings and what the package does about them

**Descriptor ownership, close and polling.** The legacy wrapper history has
a descriptor leak on a failed bind (issue #49, PR #53), the addition of
`SyscallConn` (issue #76, PRs #77 and #79), close racing accept (PR #89), and
unblocking a read on close (PR #4); Pion hit the same class in
[issue #65](https://github.com/pion/sctp/issues/65) and
[PR #80](https://github.com/pion/sctp/pull/80). georgeyanev and the two
toolchain integrations show the positive design: non-blocking,
close-on-exec descriptors owned by the runtime's poller, with raw callbacks
pinning the descriptor for the call. loxilb supplies a negative case: its
non-blocking dial could wait successfully, return a connection with a nil
error, and still close the descriptor in a deferred cleanup keyed on a
stale error
([`sctp_linux.go`](https://github.com/loxilb-io/sctp/blob/2c12de5f2b3e6fe6eb334d019dd79e3b5db3ba9c/sctp_linux.go#L376-L439)).
*Here*: every descriptor has one owner, its `*os.File`, and is closed once;
every system call goes through the runtime poller's raw connection; close
and deadlines release waiting calls; a closed socket reports
`net.ErrClosed`. `TestCloseReleasesParkedReaderAndWriter`,
`TestSyscallConnAfterCloseReturnsNetErrClosed`,
`TestCloseDoesNotLeakDescriptors` and `TestDoubleCloseRegression` pin it.

**Blocking writes and deadlines.** Pion's
[issue #77](https://github.com/pion/sctp/issues/77),
[PR #356](https://github.com/pion/sctp/pull/356) and
[PR #465](https://github.com/pion/sctp/pull/465) show that a blocking write
must also wake on close, and its stale-deadline failure
([issue #296](https://github.com/pion/sctp/issues/296),
[PR #290](https://github.com/pion/sctp/pull/290)) that moving a deadline must
reach a pending call. Legacy PR #90 approaches the same send queue from the
other side, proposing a non-blocking `SCTPWrite`. *Here*: `Write` and
`SendMsg` both wait for buffer space, obey deadlines and wake on close, and
not waiting is a per-message choice, `SendOptions.NoWait`, whose refusal
queues nothing (`TestNoWaitRefusalQueuesNothing`,
`TestNoWaitWaitsBehindParkedSend`, `TestPendingReadObservesLaterDeadline`).

**Addresses and the control hook.** Legacy issue #81 asks to cache local
and remote addresses; [free5gc PR #1](https://github.com/free5gc/sctp/pull/1)
fixes nil `LocalAddr` and `RemoteAddr` results; and an audit of this
package's own history found a dial control hook given the local address
where Go's `net.Dialer.Control` passes the remote one. *Here*: address
snapshots are taken when the association is set up, replaced whole, and
copied on every call, so they stay readable after close and cannot be
changed through a returned value (`TestNetConnAfterClose`). `Config.Control`
receives the remote address when dialing and the local one when listening
(`TestSocketConfigDialContext`,
`TestSocketConfigListenControlWithoutLocalAddress`). A refused address is an
error matching `syscall.EINVAL`, never a panic or a truncation
(`TestNilAddressesReturnErrors`).

**ABI widths, alignment and byte order.** The legacy corpus exposed
big-endian `socklen_t` handling (issue #54, PR #62) and PPID byte order in
control messages (issues #35 and #66, PR #72); thebagchi adds PPID encoding
([issue #2](https://github.com/thebagchi/sctp-go/issues/2)), an unsafe
pointer spanning allocations
([issue #5](https://github.com/thebagchi/sctp-go/issues/5)), and a wrong
event-subscription layout
([issue #6](https://github.com/thebagchi/sctp-go/issues/6)). *Here*: every
kernel structure is encoded and decoded field by field at explicit offsets,
pinned by layout tests on 32- and 64-bit and on a big-endian machine; every
PPID in the API is in host byte order, converted at the kernel boundary
(wire claim `ppid-byte-order`); and address lists are decoded entry by
entry with bounds checked first (`TestDecodeAddrsMixedFamilies`,
`FuzzDecodeAddrs`).

**Message boundaries, ancillary data and notifications.** Pion lost data
on a short buffer ([issue #50](https://github.com/pion/sctp/issues/50),
[PR #51](https://github.com/pion/sctp/pull/51),
[PR #365](https://github.com/pion/sctp/pull/365)); georgeyanev
[PR #1](https://github.com/georgeyanev/go-sctp/pull/1) returns extended
receive metadata to the caller; and fkgi's one issue is a panic on a newer
notification type ([issue #1](https://github.com/fkgi/extnet/issues/1)).
*Here*: `RecvMsg` reports whether a read ended the message; `ReadMsg`
reassembles whole messages up to a limit and drains the rest of a longer
one, so the next read starts at the next message; `Read` never returns
notification bytes; a truncated control buffer is reported as
`ErrControlTruncated` rather than trusted; notifications are reassembled
within a bound and parsed without panicking, and an unknown kind arrives as
`UnknownNotification` (`TestReadMsgSkipsNotifications`,
`TestRecvMsgReportsTruncation`, `FuzzParseNotification`,
`FuzzNotificationAccumulator`, `FuzzReadMsg`).

**Fuzzing and hostile input.** Pion's
[issue #124](https://github.com/pion/sctp/issues/124) and
[PR #340](https://github.com/pion/sctp/pull/340) argue for treating every
decoder as an untrusted-input boundary. *Here*: address resolution and
decoding, notification parsing and reassembly, control-message parsing,
`Config` validation, association-id lists, receive metadata, close
concurrency and message reassembly each have a fuzz target.

**Protocol-engine findings.** Pion's tracker holds a large RFC 9260
migration: [issue #402](https://github.com/pion/sctp/issues/402) with work on
timers, packets, streams, reassembly, error causes, shutdown, delayed
acknowledgement, stream reset and interleaving across issues and PRs #403 to
#443, among them [issue #405](https://github.com/pion/sctp/issues/405) and
[PR #406](https://github.com/pion/sctp/pull/406) for RFC 9653 zero checksum,
[issue #434](https://github.com/pion/sctp/issues/434) for the I bit,
[issue #435](https://github.com/pion/sctp/issues/435) and
[PR #443](https://github.com/pion/sctp/pull/443) for RFC 8260 interleaving,
and [PR #441](https://github.com/pion/sctp/pull/441) for an abort deadlock.
[Issue #461](https://github.com/pion/sctp/issues/461) is a delayed-SACK
regression scenario argued from the obsolete RFC 4960; RFC 9260 §6.2
distinguishes packets from DATA chunks and has both an every-second-packet
and a 200 ms recommendation. *Here*, these are kernel behaviour:

| Theme | What the package does |
|---|---|
| INIT, COOKIE, retransmission, shutdown, SACK, congestion control, stream reset and interleaving algorithms | Nothing of Pion's is copied. Claims about them name the kernel, and the wire harness observes what the kernel does |
| Delayed SACK and the I bit | The package exposes the socket options (`Config.DelayedSACK`, `SendSACKImmediately`); the wire harness shows the I bit on the wire |
| RFC 9653 zero checksum | Not offered: Linux has no `SCTP_ACCEPT_ZERO_CHECKSUM` |
| RFC 6458 fragment interleave and RFC 8260 schedulers and interleaving | Only the values in Linux's UAPI are exposed (`SCTP_SS_FC`, not RFC 8260's inconsistent `SCTP_SS_FB`), and level 2, which Linux cannot keep, is refused with `ErrUnsupported` |
| RFC 9438 CUBIC | Not offered: Linux SCTP cannot select a congestion controller, and RFC 9438 does not update RFC 9260 |
| Malformed chunks and packets | The kernel parses chunks. The package fuzzes what it parses itself: notifications, control messages and addresses |

## Checking again

This record ages. Before a significant change to polling, ancillary data,
addresses, multi-homing, authentication, reconfiguration, interleaving,
delayed SACK or checksums:

1. recheck the standards as [STANDARDS.md](STANDARDS.md) describes;
2. refresh the direct comparators' revisions and their issue and
   pull-request records;
3. search again for new Go implementations, and for renamed or archived
   ones;
4. classify each new failure as the kernel's, the binding's or a user-space
   engine's; and
5. reproduce each binding defect that applies here with a failing unit,
   fuzz, race, Linux socket or wire test before fixing it.

An upstream fix is evidence of a class of defect, not code to transplant.
