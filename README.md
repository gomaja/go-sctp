Stream Control Transmission Protocol (SCTP)
----

A Go binding for the Linux kernel's SCTP stack.

This package does not implement SCTP. Chunk handling, association setup,
retransmission, congestion control, path management and checksums are all the
kernel's; what is here is the socket API around them — `net.Conn` and
`net.Listener` implementations, the `sctp_*` socket options, ancillary data, and
the notifications the kernel delivers on the data stream.

Installing
----

The package requires Go 1.21 or newer:

```
go get github.com/gomaja/go-sctp
```

Standards and kernel boundary
----

[RFC 9260](https://www.rfc-editor.org/rfc/rfc9260.html) is the current SCTP
base protocol. It obsoletes RFC 4960 and the changes formerly published as
RFCs 4460, 6096, 7053 and 8540. [RFC 6458](https://www.rfc-editor.org/rfc/rfc6458.html)
is the current sockets API. Neither document, by itself, is the complete
baseline: applicable extension RFCs, updates and errata are recorded in
[STANDARDS.md](STANDARDS.md), together with links to both the RFC Editor and
the IETF Datatracker. Recheck those authorities before changing a
standards-governed subsystem.

This distinction matters for conformance claims. The package owns the Go API,
Linux socket ABI, ancillary-data encoding and notification parsing. The Linux
kernel owns the RFC 9260 state machine and wire protocol. Tests can therefore
prove that the wrapper requests an option correctly and that a particular
kernel produces the expected packets; they cannot make a non-conforming kernel
conform or establish that every supported kernel implements every extension.

Four current limitations are explicit:

- RFC 9653 §7.1 names `SCTP_ACCEPT_ZERO_CHECKSUM`. Current Linux UAPI does
  not expose that option or the Error Detection Method identifiers, so the
  package does not invent an option number. RFC 9653 zero-checksum negotiation
  is unsupported until the kernel publishes an ABI for it.
- Linux exposes `SCTP_ECN_SUPPORTED`, but RFC 9260 §1.7 records that the old
  SCTP ECN specification was removed. The option is Linux-specific and
  experimental, not evidence of support for a current SCTP ECN standard.
- RFC 6458 §8.1.20 defines a distinct fragment-interleave level 2. Current
  Linux stores this option as a boolean and reads a level-2 request back as
  level 1. The wrapper detects that clamp and returns an error matching
  `errors.ErrUnsupported`; RFC 8260 I-DATA negotiation does not restore the
  missing receive semantics.
- RFC 9260 §6.2 recommends a SACK for at least every second SCTP packet and
  within 200 ms of unacknowledged DATA; a configured delay must not exceed
  500 ms. `SackTimer` exposes the Linux setting; changing it can deliberately
  depart from an RFC `SHOULD`, which applications should document.

Platforms
----

This package provides a socket-backed SCTP implementation on targets selected
by Go's `linux` build tag, including Android and Linux/386. The 386 build uses
Linux's `socketcall` ABI for the socket operations that Go's `syscall` package
does not expose as separate calls there. On other targets with a real `syscall`
package — the BSDs, darwin, windows, solaris, illumos and aix — the package
still compiles, and entry points that need an SCTP socket return
`ErrUnsupported`, which wraps `errors.ErrUnsupported`:

```go
if errors.Is(err, errors.ErrUnsupported) {
        // no SCTP on this platform
}
```

Two qualifications, both measured rather than assumed.

`plan9`, `js/wasm` and `wasip1/wasm` do **not** compile: their `syscall`
packages have no `RawSockaddrInet4`, which address marshalling needs. They have
no sockets to speak of either, so this is a statement of scope rather than a
plan.

Not every entry point is socket-bound. `ResolveSCTPAddr` is pure Go, compiles
everywhere, and does its ordinary job, so the `errors.Is` gate above does not
apply to address resolution.

`TestCrossCompileSmoke` samples the relevant syscall, word-size, byte-order and
Linux-build-tag axes during the ordinary suite.

Examples
----

See `example/sctp.go`

```go
$ cd example
$ go build
$ # run example SCTP server
$ ./example -server -port 1000 -ip 10.10.0.1,10.20.0.1
$ # run example SCTP client
$ ./example -port 1000 -ip 10.10.0.1,10.20.0.1
```

Reading messages
----

SCTP is message-oriented, so a read returns either a whole message or part of
one, and `SCTPRead` gives no way to tell those apart — a message larger than the
buffer is split, and the remainder arrives looking like a fresh message. Use
either

- `ReadMsg`, which reassembles a whole message, or
- `SCTPReadFlags`, testing the returned flags for `MSG_EOR`.

With no `NotificationHandler`, `SCTPReadFlags` also reports
`MSG_NOTIFICATION`, which distinguishes an event from application data. A
configured handler consumes notifications before that method returns. Ordinary
`Read` and `ReadMsg` always skip them. Handler reassembly and notifications
queued while `ReadMsg` finishes an application record are bounded by
`NotificationReassemblyLimit`; malformed or oversized events are drained to a
record boundary and reported. `SCTPReadMsg` performs one raw `recvmsg` and
exposes payload, caller-sized ancillary data, `MSG_CTRUNC`, framing flags, and
notifications without applying package policy.

Connection semantics
----

`SCTPConn` implements Go's [`net.Conn`](https://pkg.go.dev/net#Conn) contract.
Multiple goroutines may invoke its methods concurrently. Ordinary `Read` and
`Write`, and listener `Accept`, use Go's runtime network poller:

- `Write` applies backpressure until the complete SCTP message is accepted or
  an error occurs. `SCTPWrite` and `SCTPWriteInfo` are message-oriented escape
  hatches: with no write deadline they retain their non-blocking `EAGAIN`
  behaviour when the send buffer is full; with a deadline they wait through the
  runtime poller until the message is accepted or the deadline expires.
- Deadlines are absolute, apply to pending as well as future operations, and
  may be moved or cleared by another goroutine. Timeout errors satisfy
  `errors.Is(err, os.ErrDeadlineExceeded)`.
- `Close` interrupts blocked reads and writes. Operations after close return an
  error satisfying `errors.Is(err, net.ErrClosed)`.
- `LocalAddr`, `RemoteAddr` and listener `Addr` remain available after close
  and return independent snapshots.
- A connection's `SyscallConn` pins the descriptor only for the duration of
  each `Control`, `Read` or `Write` callback. A listener's raw connection is
  Control-only; its `Read` and `Write` return `EINVAL`. No callback may retain
  the numeric descriptor.

`SCTPListener.SetDeadline` provides the corresponding deadline for pending and
future `Accept` calls, and listener `Close` interrupts a blocked `Accept`.

Pre-association socket configuration
----

`SocketConfig.WithPreAssociation` snapshots typed SCTP options that are applied
after `Control` and `InitMsg`, but before bind, connect, or listen. The
configuration is validated before a descriptor is opened, so a dependency or
range error does not call `Control` and cannot leak a socket. A nil
`*SocketConfig` is safe and behaves like its zero value.

Boolean options use `SocketOptionDefault`, `SocketOptionEnable`, and
`SocketOptionDisable`; zero therefore means "leave the kernel default alone",
not "disable". Numeric options carry an explicit `Set` bit, and delayed SACK
uses a pointer so nil is unambiguously unset:

```go
socketConfig := sctp.SocketConfig{
        InitMsg: sctp.InitMsg{NumOstreams: 32, MaxInstreams: 32},
}
cfg := socketConfig.WithPreAssociation(sctp.PreAssociationConfig{
                PartialReliability:    sctp.SocketOptionEnable,
                StreamReconfiguration: sctp.SocketOptionEnable,
                StreamResetMask: sctp.OptionalUint32{
                        Set: true,
                        Value: sctp.SCTPEnableResetStreamReq |
                                sctp.SCTPEnableChangeAssocReq,
                },
                Authentication: sctp.SocketOptionEnable,
                HMACIdentifiers: []uint16{
                        sctp.SCTPAuthHmacIDSHA256,
                        sctp.SCTPAuthHmacIDSHA1, // mandatory in RFC 4895
                },
                AuthenticatedChunks: []uint8{0}, // DATA
                FragmentInterleave: sctp.OptionalInt{
                        Set: true, Value: sctp.SCTPFragmentInterleaveOther,
                },
                ReceiveRcvInfo: sctp.SocketOptionEnable,
                RTOInfo: &sctp.RtoInfo{
                        Initial: 500, Max: 2000, Min: 200,
                },
                DelayedSACK: &sctp.DelayedSACKConfig{
                        Delay: 200, Frequency: 2,
                },
                Notifications: []sctp.NotificationSubscription{{
                        Type: sctp.SCTP_ASSOC_CHANGE,
                        State: sctp.SocketOptionEnable,
                }},
})
conn, err := cfg.DialContext(ctx, "sctp4", nil, peer)
```

Dependencies fail before socket creation: ASCONF requires AUTH; a non-zero
stream-reset mask requires stream reconfiguration; HMAC identifiers and
authenticated chunks require AUTH; and RFC 6458 fragment-interleave level 2
requires `SCTP_RCVINFO` or the deprecated data-I/O event. HMAC lists must
include SHA-1, and RFC 4895 forbids INIT, INIT-ACK, SHUTDOWN-COMPLETE, and AUTH
in the authenticated-chunk list. Shared-key bytes and active-key selection stay
in `Control`, avoiding long-lived secrets in a reusable configuration value.

`RTOInfo` maps to `SCTP_RTOINFO` for `SCTP_FUTURE_ASSOC` (RFC 6458 §8.1.1).
It lets callers set initial retransmission timeout policy before an
association exists without wrapping or retaining the raw descriptor. The
`AssocID` field must be zero or `SCTP_FUTURE_ASSOC`; the kernel interprets
zero `Initial`, `Max`, or `Min` fields as "leave unchanged".

Current Linux stores `SCTP_FRAGMENT_INTERLEAVE` as a boolean. Requests for
levels 0 and 1 read back exactly; level 2 reads back as 1, so both
`PreAssociationConfig` and `SetFragmentInterleave` return an error satisfying
`errors.Is(err, errors.ErrUnsupported)` instead of claiming level-2 semantics.
RFC 8260 I-DATA negotiation is separate: `MessageInterleaving` requires a
non-zero fragment level and the `net.sctp.intl_enable` sysctl, but it does not
turn a level-1 readback into RFC 6458 level 2.

`DelayedSACKConfig.Delay` is milliseconds. RFC 9260 §6.2 says an implementation
MUST NOT allow its maximum configured delay to exceed 500 ms, so larger values
are rejected before a descriptor is opened. That RFC separately recommends no
more than 200 ms and an acknowledgement for at least every second packet;
values from 201 through 500 or a frequency above 2 remain available as explicit,
documented departures from those `SHOULD` recommendations. Every non-zero
requested delayed-SACK field is read back and must match.

One-to-many endpoints add two invariants to the zero value: they enable
`SCTP_RCVINFO` and RFC 6458 §8.1.20's recommended fragment-interleave level 1
before associations can exist. They also subscribe to `SCTP_ASSOC_CHANGE`.
Explicit fragment level 0 or 1 wins; disabling RCVINFO or association-change
events, or setting one-to-one-only `SCTP_REUSE_PORT`, is rejected.

One-to-many endpoints
----

`SCTPEndpoint` is the typed `SOCK_SEQPACKET` surface from RFC 6458 §3.1. It is
intentionally neither a `net.Conn` nor a `net.Listener`: one descriptor owns
many associations, there is no single remote address, and complete message
boundaries and association metadata are part of every operation.

```go
server, err := sctp.ListenSCTPEndpoint("sctp4", local)
if err != nil {
        return err
}
defer server.Close()

buf := make([]byte, 64<<10)
n, info, flags, err := server.Receive(buf)
if err != nil {
        return err
}
if flags&sctp.MSG_NOTIFICATION != 0 {
        note, err := sctp.ParseNotification(buf[:n])
        // Association changes carry the endpoint-local association id.
        _ = note
        return err
}
if flags&sctp.MSG_EOR == 0 {
        // This is one fragment; continue receiving until MSG_EOR.
}

_, err = server.Send(buf[:n], &sctp.SndInfo{
        SID:     info.SID,
        PPID:    info.PPID,
        AssocID: int32(info.AssocID),
}, nil, nil)
```

`OpenSCTPEndpoint` creates an active-only endpoint. Its `Connect` can be called
for several peers and returns the endpoint-local association id. Because the
descriptor is non-blocking, a nil error means setup was started; the
automatically enabled `SCTP_ASSOC_CHANGE` notification reports `SCTP_COMM_UP`
or `SCTP_CANT_STR_ASSOC`, following RFC 6458 §3.2 and Verified Erratum 6112.
`Connect` preserves `EALREADY` and `EISCONN` instead of returning the reserved
id zero as though another association had been created.

`Receive` automatically requires the non-deprecated `SCTP_RCVINFO` from RFC
6458 §5.3.5; application data without it returns `ErrMissingReceiveInfo` rather
than becoming an unrouteable message. `Send` uses `SCTP_SNDINFO` (§5.3.4),
requires a real association id, and rejects the `FUTURE`, `CURRENT`, and `ALL`
scope selectors. PPIDs are host-order in both methods and converted at the
kernel boundary. Linux exposes neither Verified Erratum 6111's `SCTP_EOR` nor
the `SCTP_EXPLICIT_EOR` option, so every `Send` call is one complete record;
explicit record assembly across several sends is unavailable.

`AssociationCount` and `AssociationIDs` provide the RFC 6458 §8.2.5-§8.2.6
snapshots without trusting a kernel count as an unbounded allocation size.
`LocalAddrs` and `PeerAddrs` query one real association, while `BindAdd` and
`BindRemove` change the endpoint-wide local address set. `SetAutoClose` and
`GetAutoClose` expose the one-to-many idle timeout from §8.1.8. Auto-close
makes terminated association ids eligible for reuse, so applications must
retire them on the mandatory association-change notification rather than use
an old id as a permanent peer identity.

Endpoint construction sets fragmented interleave level 1, the one-to-many
default recommended by RFC 6458 §8.1.20, so a partial delivery from one peer
does not block every other association. An explicit
`PreAssociation.FragmentInterleave` level 0 or 1 overrides that default.
Current Linux stores this option as a boolean and silently reads level 2 back
as level 1; construction detects that mismatch and reports unsupported instead
of claiming the distinct level-2 semantics.

Use `CloseAssociation` for a graceful zero-data `SCTP_EOF` shutdown and
`AbortAssociation` for an immediate `SCTP_ABORT` with optional user cause data
(RFC 6458 §3.1.5). Both affect only the selected association; `Close` and
`Abort` still terminate every association owned by the endpoint. `Send`
rejects these lifecycle flags so a data send cannot accidentally tear down an
association.

All methods are safe to call concurrently, but all receives consume one shared
queue and readiness is endpoint-wide rather than association-specific. A
message split across buffers must be reassembled by one dispatcher, and an
association needing independent readiness or sustained backpressure should be
split out with `PeelOff` (RFC 6458 §9.2). The returned `SCTPConn` owns its own
close-on-exec descriptor; closing the original endpoint does not affect it.

`SocketConfig.OpenEndpoint` and `SocketConfig.ListenEndpoint` provide the same
pre-bind `Control`, `InitMsg`, `PreAssociation`, and `NotificationHandler`
configuration surface as one-to-one sockets. The callback's numeric descriptor
is borrowed only for the callback. Endpoint construction and `PeelOff` keep
ownership inside the package, so no `NewSCTPConn` wrapper around a borrowed
descriptor is needed.
`SyscallConn` provides the same callback-scoped escape after construction;
the descriptor must not be retained, closed, or wrapped. `Network` reports the
canonical `sctp`, `sctp4`, or `sctp6` family and `Addr` returns a copy of the
current endpoint-wide local address set.

Dynamic local addresses
----

`BindAdd` and `BindRemove` are typed wrappers around `sctp_bindx` for
`SCTPConn`, `SCTPListener`, and `SCTPEndpoint`:

```go
extra := &sctp.SCTPAddr{
        IPAddrs: []net.IPAddr{{IP: net.ParseIP("192.0.2.20")}},
        Port:    0, // inherit the endpoint's bound port
}
if err := conn.BindAdd(extra); err != nil {
        return err
}
defer conn.BindRemove(extra)
```

The operation is atomic across every address in the value, does not mutate the
value passed by the caller, and refreshes the endpoint's cached `LocalAddr` or
`Addr` from the kernel. RFC 6458 §9.1 permits port zero or the existing bound
port; another port is rejected with `EINVAL`. It also requires `EINVAL` when an
operation would remove the last address. Linux reports `EBUSY` for that case,
so the typed methods enforce the RFC result before the syscall. The lower-level
`SCTPBind` function continues to expose the kernel errno unchanged.

Changing a listener changes the addresses inherited by future associations.
Changing an established connection can additionally invoke RFC 5061 dynamic
address reconfiguration, which is optional and must be negotiated before INIT;
set `PreAssociation.Authentication` and
`PreAssociation.DynamicAddressReconfiguration` to `SocketOptionEnable` on the
`SocketConfig` used to dial or listen. A successful local bindx call does not
mean that the peer has acknowledged the change: RFC 5061 §5.3 defines the
ASCONF-ACK boundary. RFC 6458 Erratum 4921's IPv4/IPv6 wording remains Held for
Document Update, so it is reported in `STANDARDS.md` but is not applied as a
normative correction.

Testing
----

The package includes Go tests for the public API, Linux socket behavior that is
reachable from ordinary Go code, parser boundaries and portable build behavior.
Socket-backed tests need a Linux SCTP stack and skip when the required operating
system support is unavailable.
