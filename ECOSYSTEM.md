# Go SCTP ecosystem audit

This document records the Go SCTP implementation survey used to harden this
repository. The snapshot was taken on **2026-08-01**. Repository heads and
tracker counts are pinned so that later changes in an upstream project do not
silently change the evidence behind a local decision.

This is an engineering comparison, not a standards hierarchy. The current
standards baseline is maintained in [STANDARDS.md](STANDARDS.md), and the RFC
Editor, the IETF Datatracker, applicable updates, and errata remain the
authorities. No peer implementation is treated as proof of conformance.

## Scope and method

The survey searched for importable Go libraries, Linux SCTP socket wrappers,
user-space SCTP protocol engines, Go runtime integrations, and repositories
whose names or descriptions made them plausible candidates. For every
candidate, the default branch, exact head revision, repository contents, issue
history, and pull-request history were inspected. Issues and pull requests were
counted separately; the issue count does not include pull requests.

The result was 20 repositories and 596 issue or pull-request records:

- 151 issues, of which 56 were open at the snapshot;
- 445 pull requests, of which 31 were open at the snapshot; and
- 87 open records in total.

The review classified each record by whether it exposed a transferable defect,
an API or ABI gap, a protocol-algorithm concern, project-specific behavior, or
administrative work. The tables below name every repository. The issue section
records every theme that produced a local action; the remaining records were
support questions, dependency and CI maintenance, project administration,
features outside this package's implementation boundary, or fixes with no
corresponding local code path.

## Direct implementations and architectural comparators

| Repository | Pinned default branch revision | Classification | Issues | Pull requests |
| --- | --- | --- | ---: | ---: |
| [gomaja/go-sctp](https://github.com/gomaja/go-sctp) | `main` at [`eba003e63e6e`](https://github.com/gomaja/go-sctp/commit/eba003e63e6e183df2a209746665fa3252a0fbeb) | Target repository; Linux kernel socket binding | 0 | 0 |
| Legacy kernel-wrapper corpus | `master` at `19ddcbc6aae2` | Maintained source lineage and primary wrapper issue corpus | 37, 23 open | 53, 4 open |
| [free5gc/sctp](https://github.com/free5gc/sctp) | `main` at [`d88ea73eeeb1`](https://github.com/free5gc/sctp/commit/d88ea73eeeb1cc25a9bff6ea2b146e59be505ef5) | Maintained derivative of an earlier kernel wrapper | 0 | 8, 2 open |
| [georgeyanev/go-sctp](https://github.com/georgeyanev/go-sctp) | `master` at [`5ffbc5b0c8e7`](https://github.com/georgeyanev/go-sctp/commit/5ffbc5b0c8e75d28da356f4c725af18d285ccf32) | Independent Linux wrapper; runtime-poller and socket-option comparator | 0 | 6 |
| [loxilb-io/sctp](https://github.com/loxilb-io/sctp) | `master` at [`2c12de5f2b3e`](https://github.com/loxilb-io/sctp/commit/2c12de5f2b3e6fe6eb334d019dd79e3b5db3ba9c) | GitHub fork and older derivative of an earlier kernel wrapper | 0 | 1 |
| [pion/sctp](https://github.com/pion/sctp) | `main` at [`37fef17855bc`](https://github.com/pion/sctp/commit/37fef17855bc720b31c09e8c8643aa67122aff7e) | User-space SCTP protocol engine; parser, state-machine, and concurrency corpus | 106, 30 open | 373, 23 open |
| [thebagchi/sctp-go](https://github.com/thebagchi/sctp-go) | `master` at [`a870aadd46af`](https://github.com/thebagchi/sctp-go/commit/a870aadd46afb95334f74c462ba20da1b594295e) | Independent Linux wrapper; one-to-many and unsafe-ABI comparator | 5 | 1 |
| [fkgi/extnet](https://github.com/fkgi/extnet) | `master` at [`d1c0d7238f6c`](https://github.com/fkgi/extnet/commit/d1c0d7238f6ca1250e2c61e3f874ba4c68cca6f6) | Older wrapper; association multiplexing and notification-error corpus | 1, 1 open | 0 |
| [3vilM33pl3/go-sctp](https://github.com/3vilM33pl3/go-sctp) | `main` at [`9e952b78d047`](https://github.com/3vilM33pl3/go-sctp/commit/9e952b78d047742bc66d41957c281fcb7f42edc5) | Full Go toolchain fork with SCTP integrated into `net` and the runtime poller | 0 | 1, merged |
| [M1tsumi/Go5GSCTP](https://github.com/M1tsumi/Go5GSCTP) | `main` at [`83947455a46b`](https://github.com/M1tsumi/Go5GSCTP/commit/83947455a46b346c2c2a3e59c8683c4b0a093293) | High-level 5G/NGAP adapter over a Linux SCTP wrapper, not a socket implementation | 0 | 2, both automation and open |

These ten repositories account for 594 of the 596 reviewed records.

## Screened candidates that are not independent comparators

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
package the source changes as a patch. Neither changes this repository's API or
implementation plan.

## Implementation boundaries

The surveyed projects fall into three materially different models:

1. **Kernel socket bindings**, including this repository, the legacy wrapper
   corpus, free5gc, georgeyanev, loxilb, thebagchi, and fkgi. Linux owns association
   state, chunks, retransmission, congestion control, path management, SACK
   generation, and checksums. The Go package owns descriptor lifetime,
   socket-option and ancillary-data ABI, address encoding, message framing, and
   the `net` interfaces.
2. **User-space protocol engines**, principally Pion. Pion owns protocol state
   and wire encoding itself over a supplied transport such as DTLS. Its
   algorithm and parser failures are valuable hostile test cases, but its
   implementation choices cannot establish the correctness of a Linux socket
   binding.
3. **Go runtime integrations**, represented by 3vilM33pl3 and the older ilya
   overlay. They demonstrate how SCTP can participate in Go's network poller,
   but they require a custom toolchain and are not dependencies this module can
   import.

Accordingly, **Pion is not a kernel-wrapper compliance oracle**. A Pion issue
about a malformed chunk, retransmission timer, congestion controller, or SACK
algorithm becomes either a Linux wire-observation test or a kernel-version
qualification here. It does not justify copying user-space protocol code into
the wrapper. Conversely, Pion defects involving buffers, deadlines, close
unblocking, parsers, and concurrency often do transfer because those are Go API
contracts rather than SCTP state-machine choices.

## Obsolete standards references found upstream

RFC 4960 is obsolete; RFC 9260 replaced it. This changes the base document,
incorporates the I-bit and earlier updates, and carries a different current
errata set. A reference to RFC 4960 cannot be used as current conformance
evidence.

At the pinned revisions:

- the legacy wrapper corpus, free5gc, loxilb, herugen, meng72,
  lakshya-chopra, and krsnucc21 retain the same historical RFC 4960 comment in their wrapper
  lineage;
- georgeyanev retains RFC 4960 references in notification documentation;
- jamesruan explicitly describes its unfinished implementation as RFC 4960;
- javen-yan is an older Pion copy with RFC 4960 citations; and
- Pion's README still describes a subset of RFC 4960, while
  [issue #402](https://github.com/pion/sctp/issues/402) tracks migration to
  RFC 9260 and several source comments remain on the old section numbers.

The local disposition is explicit: do not preserve those citations as current,
and do not silently renumber them. Each affected local behavior must be checked
against RFC 9260, its verified errata, and RFC 6458 or Linux UAPI where the
claim is a socket-API claim. The migration impact is primarily a citation and
requirement audit for kernel wrappers; it is algorithmic for a user-space engine
such as Pion. The incomplete jamesruan skeleton has no reusable association
engine to migrate.

Legacy wrapper issue #45, "Compliance to RFC 4960", is therefore not adopted
as written. Its valid intent is covered by the current baseline in
[STANDARDS.md](STANDARDS.md).

## Transferable issue and pull-request findings

### Descriptor ownership, close, and polling

The legacy wrapper history contains a descriptor leak on bind failure
(issue #49, PR #53), the addition of
`SyscallConn`
(issue #76, PR #77, PR #79), close-versus-accept races (PR #89), and earlier
work to unblock a read on close (PR #4). Pion independently hit
the same API class in
[issue #65](https://github.com/pion/sctp/issues/65) and
[PR #80](https://github.com/pion/sctp/pull/80).

Georgeyanev and the two toolchain integrations provide the strongest positive
architecture: nonblocking close-on-exec descriptors owned through `os.File` or
the runtime, with readiness handled by Go's poller and raw callbacks pinning a
descriptor during a syscall. This design informed the local descriptor-lifetime
work. Its unsafe control-message casts, mutable address caches, and close paths
were not adopted.

The loxilb derivative supplies a useful negative test. Its nonblocking dial can
observe `EINPROGRESS`, wait successfully, return a connection with a nil error,
and still have its deferred error cleanup close the descriptor because the
local `err` remains non-nil. The relevant pinned path is
[`sctp_linux.go`](https://github.com/loxilb-io/sctp/blob/2c12de5f2b3e6fe6eb334d019dd79e3b5db3ba9c/sctp_linux.go#L376-L439).
That ownership pattern is explicitly rejected.

**Local disposition: implemented and retained as a release gate.** Every connection and
listener descriptor must have one owner, every syscall on an owned descriptor
must be pinned, pending I/O and accept calls must unblock on close or a newly
set deadline, and repeated close must report the ordinary closed-network error.
The contract is exercised in
[`sctp_netconn_contract_test.go`](sctp_netconn_contract_test.go),
[`sctp_rawconn_test.go`](sctp_rawconn_test.go), and the descriptor-leak tests.

### Blocking writes and deadlines

Pion's open
[issue #77](https://github.com/pion/sctp/issues/77),
[PR #356](https://github.com/pion/sctp/pull/356), and
[PR #465](https://github.com/pion/sctp/pull/465) show that a blocking write mode
must also unblock correctly on close. Its stale-deadline failure
([issue #296](https://github.com/pion/sctp/issues/296),
[PR #290](https://github.com/pion/sctp/pull/290)) shows that cancelling or
moving a deadline must affect an already pending operation. Legacy wrapper PR
#90 reaches the same send queue from the opposite API choice by proposing a
nonblocking `SCTPWrite`.

**Local disposition: implemented with an intentional API distinction.** Ordinary
`net.Conn.Write` must wait for the whole payload or return the payload count and
an error, and must obey deadlines and close. The SCTP-specific send API may
retain immediate `EAGAIN` behavior when no write deadline is configured, but
that behavior must be documented and must not leak into `net.Conn.Write`.
Deadline setters must affect pending operations and return `net.ErrClosed`
after close.

### Addresses and control-hook semantics

Legacy wrapper issue #81 asks to cache local and remote addresses instead of
issuing a socket query on every call. [free5gc PR #1](https://github.com/free5gc/sctp/pull/1) fixes nil
`LocalAddr` and `RemoteAddr` results. The local audit also found that a dial
control hook was given the local address string where Go's `net.Dialer.Control`
contract calls for the remote address.

**Local disposition: implemented and retained as a release gate.** Connection and
listener addresses are cached as deep copies so they remain stable after close
and cannot be mutated through a returned slice. The dial control hook must be
tested with and receive the remote address; the listen hook receives the local
address. Address marshalling now rejects nil entries, invalid ports, and
invalid zones rather than truncating values or panicking. Explicit `sctp4` and
`sctp6` operations also reject addresses from the other family; generic `sctp`
deliberately permits mixed IPv4/IPv6 lists on a dual-stack socket.

### ABI widths, alignment, and byte order

The legacy wrapper corpus exposed big-endian `socklen_t` handling
(issue #54, PR #62) and PPID/control-message
byte order
(issue #35, issue #66, PR #72). Thebagchi's tracker
adds PPID encoding
([issue #2](https://github.com/thebagchi/sctp-go/issues/2)), an unsafe pointer
spanning allocations
([issue #5](https://github.com/thebagchi/sctp-go/issues/5)), and an incorrect
event-subscription pointer shape
([issue #6](https://github.com/thebagchi/sctp-go/issues/6)).

**Local disposition: implemented and retained as a release gate.** Linux
`socklen_t` storage is explicitly 32 bits, `SCTP_NODELAY`
uses Linux `int` width, packed wrapper headers are decoded without unaligned
struct casts, and address decoding is bounded before allocation. PPID must have
one documented public byte-order convention, with explicit conversion helpers
where the Linux ABI requires network order; the legacy and modern ancillary
paths must not expose different conventions.

### Message boundaries, ancillary data, and notifications

Pion lost data on a short application buffer
([issue #50](https://github.com/pion/sctp/issues/50),
[PR #51](https://github.com/pion/sctp/pull/51), and the later
[PR #365](https://github.com/pion/sctp/pull/365)). Georgeyanev
[PR #1](https://github.com/georgeyanev/go-sctp/pull/1) demonstrates an API that
returns caller-visible extended receive metadata. Fkgi's sole issue reports a
panic on a newer notification type
([issue #1](https://github.com/fkgi/extnet/issues/1)).

The corresponding local hazards are broader: an oversized `ReadMsg` must drain
the remainder of that SCTP message before returning, ordinary `net.Conn.Read`
must not inject SCTP notifications into application bytes, and `MSG_CTRUNC`
must not silently authorize incomplete stream, PPID, association, or
next-message metadata. A low-level receive API also needs a caller-controlled
out-of-band buffer so future ancillary records are observable rather than
discarded by a fixed internal parser.

**Local disposition: implemented and retained as a release gate.** `ReadMsg` is
bounded and preserves the next message boundary, configured handlers reassemble
one complete notification independently of the application buffer, automatic
notification buffering has a documented ceiling and drains malformed records,
raw reads retain fragment and `MSG_EOR` visibility, notification parsing
returns errors instead of panicking, control truncation is reported as
`ErrControlTruncated`, and the raw-OOB contract is covered by Linux socket
tests.

### Fuzzing and hostile inputs

Pion's [issue #124](https://github.com/pion/sctp/issues/124) and
[PR #340](https://github.com/pion/sctp/pull/340) reinforce the value of treating
every packet and ancillary decoder as an untrusted-input boundary.

**Local disposition: adopted.** Address marshalling and raw-address decoding,
notification and cause parsing, control-message parsing, close concurrency, and
message reassembly are fuzz or mutation targets. A successful parse must be
bounded, non-panicking, independent of source-buffer reuse, and round-trip safe
where the ABI has an encoder.

## Protocol-engine findings and local wire dispositions

Pion's current tracker contains a substantial RFC migration effort. The
umbrella [issue #402](https://github.com/pion/sctp/issues/402) is accompanied by
work on retransmission timers, packets, streams, reassembly, error causes,
shutdown, delayed acknowledgements, stream reset, and interleaving across the
issue and PR range from #403 through #443. Representative records include
[issue #405](https://github.com/pion/sctp/issues/405) and
[PR #406](https://github.com/pion/sctp/pull/406) for RFC 9653 zero checksum,
[issue #434](https://github.com/pion/sctp/issues/434) for the I-bit,
[issue #435](https://github.com/pion/sctp/issues/435) and
[PR #443](https://github.com/pion/sctp/pull/443) for RFC 8260 interleaving, and
[PR #441](https://github.com/pion/sctp/pull/441) for an abort deadlock.

[Pion issue #461](https://github.com/pion/sctp/issues/461) is a useful delayed
SACK regression scenario, but its standards discussion relies on obsolete RFC
4960. The scenario is retained; its interpretation is redone against RFC 9260
section 6.2 and current errata. The current requirements distinguish packets
from DATA chunks and include both the every-second-packet recommendation and
the 200 ms timer recommendation.

The local disposition follows the kernel-wrapper boundary:

| Pion or protocol-engine theme | Local disposition |
| --- | --- |
| INIT, COOKIE, retransmission, shutdown, SACK, congestion control, stream reset, and interleaving algorithms | Do not copy. Qualify the Linux kernel version and configuration before making claims about behavior owned by the kernel. |
| Delayed SACK and I-bit | Treat as kernel behavior. The wrapper exposes the relevant socket boundary but does not implement the packet scheduler or acknowledgement algorithm. |
| RFC 9653 zero checksum | Do not invent a socket-option number. The current Linux UAPI has no `SCTP_ACCEPT_ZERO_CHECKSUM` facility; document it as kernel-unsupported until an ABI exists. |
| RFC 6458 fragmentation and RFC 8260 scheduling/interleaving | Expose only names and values present in the verified Linux UAPI and account for the RFC 8260 `SCTP_SS_FC`/`SCTP_SS_FB` inconsistency. Linux stores `SCTP_FRAGMENT_INTERLEAVE` as a boolean, so a requested RFC 6458 level 2 that reads back as level 1 fails closed with `errors.ErrUnsupported`; I-DATA negotiation is separate and does not restore level-2 semantics. |
| RFC 9438 CUBIC discussion | Do not claim wrapper support. Linux SCTP exposes no congestion-controller selection API, and RFC 9438 does not formally update RFC 9260. |
| Packet parsers and malformed chunks | Translate into hostile ancillary, notification, address, and message-framing tests only where the wrapper parses corresponding kernel data. |

## Local disposition ledger

This ledger is the release-facing result of the survey. “Release gate” means
the implemented behavior remains mandatory before a release is published.

| Area | Status | Required local result |
| --- | --- | --- |
| Module identity and installation | Implemented and validated | The module and examples import `github.com/gomaja/go-sctp`, with a stated and tested minimum Go version. |
| Example buffer configuration | Implemented and validated | Read-buffer reporting uses `GetReadBuffer`; zero-value requests and every getter/setter error are tested. |
| Address validation and decoder allocation | Implemented and validated | Invalid ports, families, zones, and nil addresses return errors; peer-controlled counts cannot cause unbounded allocation. |
| Linux ABI widths and unaligned wrapper decoding | Implemented and validated | `socklen_t`, Linux `int`, and struct offsets are explicit and cross-architecture tested; packed input is decoded by fields. |
| Descriptor lifetime, polling, close, and stable addresses | Implemented; release gate | Runtime-poller I/O, pinned raw syscalls, single ownership, close/deadline wakeups, deep address copies, and no descriptor reuse races. |
| `net.Conn.Write` and write deadlines | Implemented; release gate | Full blocking-write semantics, accurate payload counts, later-deadline updates, timeout identity, and close unblocking. |
| Message framing, notifications, and control truncation | Implemented; release gate | Drain oversized messages, preserve the next boundary, hide notifications from ordinary reads, and expose truncation/raw OOB safely. |
| PPID byte-order contract | Implemented; release gate | One host-order public convention across legacy and modern send/receive APIs, with mutation and round-trip coverage. |
| `SocketConfig.Control` address | Implemented; release gate | Dial passes the remote address, listen passes the local address, and callback errors never leak a descriptor. |
| `EALREADY` during connect | Covered; retain regression suite | Blocking connect must confirm establishment; a nonblocking raw caller still observes an in-progress error. |
| One-to-many public API, dynamic bind/unbind, and typed pre-association options | Implemented and validated | `SCTPEndpoint` has an explicit concurrency and ownership model, per-association lifecycle and peeloff, typed bindx, portable prevalidation, Linux option/readback tests, and fail-closed unsupported handling. |
| `linux/386` | Implemented and cross-validated | Linux socket operations use the `socketcall` ABI where Go exposes no separate syscall; 386 builds, ABI tests, and cross-compilation remain release gates. |
| Delayed-SACK and I-bit behavior | Implemented; kernel departures explicit | The wrapper exposes Linux delayed-SACK and I-bit controls without claiming ownership of the kernel packet timeline. |
| Kernel protocol algorithms | Outside wrapper implementation boundary | State the kernel version and never claim that this Go package implements the RFC state machine. |

## Re-audit policy

This is a point-in-time baseline. Before a material revisit of polling,
ancillary data, addresses, multihoming, authentication, reconfiguration,
interleaving, delayed SACK, or checksum handling:

1. recheck the RFC Editor and Datatracker relationships and errata described in
   [STANDARDS.md](STANDARDS.md);
2. refresh the default-branch revisions and all issue and pull-request records
   for the direct comparators;
3. search again for new Go implementations and renamed or archived projects;
4. classify each new failure by kernel, wrapper, or user-space-engine ownership;
5. reproduce applicable wrapper defects with a failing unit, fuzz, mutation,
   race, or Linux socket test.

An upstream fix is evidence of a defect class, not permission to transplant
code. Local changes remain governed by this package's API contract, the current
standards baseline, the current Linux UAPI, and independently reproducible
tests.
