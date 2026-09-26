<!-- Copyright 2026 gomaja. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Migrating from v1

This guide is for code written against v1 of this package, the releases
v1.0.0 to v1.0.6. The current API replaces it in one step: it drops every
name kept for compatibility, every mechanism RFC 6458 deprecates and every
fallback for old kernels, and it renames the rest to idiomatic Go. Nothing
of v1 remains alongside it.

The module path does not change: `github.com/gomaja/go-sctp`, package
`sctp`. Get it with

```
go get github.com/gomaja/go-sctp@main
```

and see [README.md](README.md#installing) for why it is followed on `main`.
Because both APIs share one module path, and a build uses one version of a
module, every module in a build must move together: a program cannot use a
library still written against v1 and this API at the same time.

The current API needs Go 1.26 or later (its optional settings are pointers,
which Go 1.26's `new(expr)` makes easy to write: `NoDelay: new(true)`), and
on Linux, a kernel that has the facilities the program uses: 5.0 for any
socket, and later releases for some options ([README.md](README.md#kernel-requirements)).

## In short

- `SCTPConn`, `SCTPListener`, `SCTPEndpoint`, `SCTPAddr` and `SCTPAssocID`
  are `Conn`, `Listener`, `Endpoint`, `Addr` and `AssocID`. Getters lose
  their `Get` prefix.
- One `Config` replaces `SocketConfig`, `PreAssociationConfig`,
  `PreconfiguredSocket` and the `...Ext` and `...WithAbandonPolicy` entry
  points. Its methods are the constructors; `Dial`, `Listen`,
  `ListenEndpoint` and `OpenEndpoint` use a zero `Config`. `Dial` takes a
  context.
- `SendMsg(b, SendOptions)` replaces `SCTPWrite` and `SCTPWriteInfo`, and
  `RecvMsg(b)` replaces `SCTPRead`, `SCTPReadFlags` and `SCTPReadNextInfo`.
  `ReadMsg` returns an `RcvInfo` value.
- Addresses are `netip.Addr` values: `Addr.IPs`, and a single path is named
  by the peer's IP. Durations are `time.Duration`. Enumerations are typed.
- A `NotificationHandler` receives parsed values, which it may keep.
- The raw socket-option numbers and `Getsockopt`/`Setsockopt` are gone;
  every option has a typed method, and `SyscallConn` remains for anything
  else, with `syscall.IPPROTO_SCTP` as the option level.

## Before and after

v1:

```go
conn, err := sctp.DialSCTPExt("sctp", nil, raddr,
	sctp.InitMsg{NumOstreams: 16, MaxInstreams: 16})
if err != nil {
	return err
}
if err := conn.SubscribeEvent(sctp.SCTP_ASSOC_CHANGE, true); err != nil {
	return err
}
_, err = conn.SCTPWriteInfo(msg, &sctp.SndInfo{SID: 1, PPID: 46}, nil, nil)
// ...
n, info, flags, err := conn.SCTPReadFlags(buf)
if flags&sctp.MSG_NOTIFICATION != 0 {
	note, err := sctp.ParseNotification(buf[:n])
	// ...
}
complete := flags&sctp.MSG_EOR != 0
stream, ppid := info.Stream, info.PPID
```

Now:

```go
cfg := &sctp.Config{
	InitMsg:       sctp.InitMsg{OutStreams: 16, MaxInStreams: 16},
	Notifications: []sctp.EventType{sctp.EventAssocChange},
}
conn, err := cfg.Dial(ctx, "sctp", nil, raddr)
if err != nil {
	return err
}
_, err = conn.SendMsg(msg, sctp.SendOptions{
	Info: &sctp.SndInfo{Stream: 1, PPID: 46},
})
// ...
n, info, err := conn.RecvMsg(buf)
if info.Notification {
	note, err := sctp.ParseNotification(buf[:n])
	// note is a *sctp.AssocChange, among others
}
complete := info.EOR
stream, ppid := info.Rcv.Stream, info.Rcv.PPID
```

A one-to-many endpoint changes the same way: `SCTPEndpoint.Send(b, info,
pr, auth)` is `Endpoint.SendMsg(id, b, SendOptions)`, with the association
id as an argument of its own, and `SCTPEndpoint.Receive(b)` is
`Endpoint.RecvMsg(b)`, which names every message's association in
`MsgInfo.Rcv.AssocID`.

Settings that v1 applied with a setter after connecting and that only take
effect before the association exists are `Config` fields now:

| v1, after connecting | Now, in `Config` |
|---|---|
| `SetInitMsg` | `InitMsg` |
| `SetAdaptationLayer` | `AdaptationLayer` |
| `SetPrSupported`, `SetReconfigSupported`, `SetAsconfSupported`, `SetAuthSupported`, `SetEcnSupported`, `SetInterleavingSupported` | `PartialReliability`, `StreamReconfiguration`, `DynamicAddressReconfiguration`, `Authentication`, `ExperimentalECN`, `MessageInterleaving` |
| `SetHmacIdent`, `SetAuthChunk` | `HMACIdentifiers`, `AuthChunks` |
| `SetReusePort` | `ReusePort` |
| `SetReadBuffer`, `SetWriteBuffer`, to size the receive window and the send buffer from the start | `ReadBuffer`, `WriteBuffer` (the `Conn` setters remain for a live socket) |

Shared AUTH keys, which v1 installed from `Control` with a raw socket
option, are installed there with `InstallAuthKey` and `ActivateAuthKey`,
so that key material never sits in a reusable `Config`.

## Behaviour that changes

Beyond the names, these behaviours differ from v1.

1. **Sends wait for buffer space, and not waiting is a per-message choice.**
   `SendMsg` waits like `Write`, on `Conn` and `Endpoint` alike, until the
   write deadline. `SendOptions.NoWait` makes one attempt instead, and a
   refusal, an error matching `syscall.EAGAIN`, queues nothing. In v1,
   `SCTPWrite`, `SCTPWriteInfo` and `SCTPEndpoint.Send` returned `EAGAIN` at
   once on a full send buffer whenever no write deadline was set: set
   `NoWait` for that behaviour.
   `NoWait` still takes the send lock, so it waits behind a send that is
   waiting for space.
2. **`Dial` takes a context**, which bounds the setup. Without a deadline
   the kernel retransmits its INIT for about 333 s on Linux's defaults, as
   v1's `DialSCTP` did. A context that ends first abandons the setup the way
   `Config.AbandonPolicy` says, with an ABORT by default.
3. **Receive metadata is always on.** Every socket enables `SCTP_RCVINFO`
   when it is created; `SCTP_SNDRCV` is used in neither direction.
4. **Settings that must precede the association exist only in `Config`.**
   v1's setters for them succeeded on an established association and did
   nothing.
5. **Paths are named by IP address.** `PathInfo`, `SetPathParams`,
   `SetPrimaryAddr` and the other path calls take a `netip.Addr`, and
   `BindAdd` and `BindRemove` take IP addresses; the port is always the
   socket's. The zero `netip.Addr` means the association as a whole where
   Linux allows it, and every path for `RequestHeartbeat`.
6. **A notification handler receives parsed values**, one of the types
   that implement `Notification`, and a kind the package does not decode
   arrives as `UnknownNotification` rather than being dropped. Its byte
   slices belong to the handler, which may keep them; v1's handler got raw
   bytes valid only during the call.
7. **Durations are exact.** A duration that is not a whole number of the
   kernel's unit, milliseconds, or seconds for `SetAutoClose`, is refused
   rather than rounded.
8. **Kernel fallbacks are gone.** `SCTP_SOCKOPT_CONNECTX`, the legacy
   peel-off option and the two-field thresholds option are no longer tried.
   On a kernel without an option, the calls that need it return the
   kernel's error, typically one matching `syscall.ENOPROTOOPT`.
9. **`Abort` overtakes a pending `Close`.** It makes the waiting `Close`
   send its ABORT at once, and both return nil; in v1 the `Abort` failed.
10. **Socket buffer sizes are set in `Config`**, before the association
    exists: Linux sets the association's receive window from the receive
    buffer when the association is created. `SetReadBuffer` on a live
    connection never makes the window larger.
11. **`SendMsg`, `RecvMsg` and `Read` make no allocation per call**, and
    `SendMsg` keeps nothing of its arguments.
12. **`LocalAddr` and `LocalAddrs` report the association's own
    addresses.** v1 asked for association 0 and got the endpoint's bound
    set, which for a wildcard bind is every address in the network
    namespace.
13. **IPv4 addresses are never reported IPv4-mapped**, even on `sctp6`
    sockets, and `MappedV4Addr` is gone. Inputs may use either form.
14. **The concurrency contract is written down**, including the
    per-connection send lock and the receive lock, which is released before
    a notification handler runs.
15. **Message calls wrap their errors.** `SendMsg`, `RecvMsg` and `ReadMsg`
    return a `*net.OpError`, as `Read` and `Write` already did in v1.0.6;
    v1's `SCTPWrite` and `SCTPRead` family returned the bare cause.
    `errors.Is`, and a `net.Error` type assertion, work on both, and
    `io.EOF` stays unwrapped.
16. **There is no `SCTP_EOF` send flag.** Linux refuses it on one-to-one
    sockets; where it accepts it, it does what `Endpoint.CloseAssoc` and
    `Close` do. `SCTP_ABORT` is `Endpoint.AbortAssoc` and `Abort`.
17. **`SendFailed` is reported per DATA chunk.** A fragmented message
    produces one event per fragment, each with its own payload and the
    chunk's own bits, and `Error` is an `ErrorCause`. The name now means
    `SCTP_SEND_FAILED_EVENT`; the deprecated `SCTP_SEND_FAILED` is gone.
18. **Every connection ends with `io.EOF`** after a graceful end, whichever
    side started it, on accepted, dialed and peeled-off connections alike.
    With Linux alone, a peeled-off connection, or one whose shutdown this
    side started, leaves a reader waiting; v1 did.
19. **Per-message path selection and bundling are new**: `SendOptions.Path`
    sends one message to a chosen peer address, and `SendOptions.More`
    (`MSG_MORE`) lets the kernel bundle it with the next.
20. **A nil `SendOptions.Info` or `SendOptions.PR` always means the
    socket's default**, on `Conn` and `Endpoint` alike. With Linux alone,
    setting one of the two dropped the other's default, and a send that
    names its association, as every endpoint send does, got no default at
    all.
21. **A failed association's error is sticky, and reads never hang on
    it.** After an ABORT or a failure, every read, once the queued data is
    delivered, and every send return `ECONNRESET`, `ETIMEDOUT` or
    `ECONNABORTED`. In v1 only the first call got it, and a later read
    waited forever.
22. **Errors are uniform.** A refused `Config` field, `SendOptions` field or
    argument matches `syscall.EINVAL` and names what was refused. Option
    methods return a `*net.OpError` with `Op` `"get"` or `"set"` around an
    `*os.SyscallError`, as `net`'s own setters do; v1 returned the bare
    errno. The `Endpoint` constructors return a `*net.OpError` like the
    others, and so does every constructor on a platform without SCTP.
23. **Notification values own their bytes**: nothing the package returns
    aliases its buffers.
24. **`Close`'s grace period is configurable** with `Config.CloseTimeout`,
    also for connections held only as a `net.Conn`, such as accepted ones.
    It is 3 s by default, as in v1.
25. **Adopted descriptors are checked.** `FileConn` and `FileListener`
    refuse anything but a one-to-one SCTP socket in the right state, and
    their `Config` forms give the connection a handler, which v1's
    `NewSCTPConn` took as an argument.
26. **`Shutdown` starts a graceful shutdown and keeps reading**, so that the
    last messages the peer sends are still delivered, and reads end with
    `io.EOF`.
27. **The smoothed RTT and the largest observed RTO are kernel ticks**,
    `PathInfo.SRTTTicks` and `AssocStats.MaxRTOTicks`, because that is how
    Linux reports them; v1 exposed them as unlabelled integers.
28. **`Config.DefaultPrInfo`** sets the default PR-SCTP policy before the
    first association, so that accepted connections inherit it, as they
    inherit `Config.DefaultSndInfo`.
29. **`Dial` never returns a connection to itself.** When the kernel picks
    the very port being dialed on a local address, with nothing listening
    there, the setup completes with itself; `Dial` detects that, retries
    with a new socket, and fails with an error matching
    `syscall.ECONNREFUSED` if it cannot avoid it.
30. **A link-local path given without a zone is completed** from the
    association's own addresses where exactly one zone applies, in
    `SendOptions.Path` and the path options.

## Capabilities with no replacement

Four v1 capabilities have no counterpart. Each could be added back without
breaking anything if it is needed:

- adopting a one-to-many descriptor created outside the package (v1:
  `NewSCTPConn` followed by `PeelOff`); `FileConn` adopts one-to-one sockets
  only;
- `SCTP_SENDALL`, which sends one message on every association of an
  endpoint;
- an ABORT carrying caller-supplied cause data on a `Conn`;
  `Endpoint.AbortAssoc` keeps it;
- the `sockaddr` encoder (`MarshalSockaddr`, `ToRawSockAddrBuf`), for
  callers building raw socket options through `SyscallConn`.

These were never available from Linux, and the package does not imitate
them:

| Capability | Why not |
|---|---|
| Bytes still queued to send | Linux SCTP implements `SIOCINQ` but not `SIOCOUTQ` (`sctp_ioctl`, `net/sctp/socket.c`), and neither `SCTP_STATUS` nor `SCTP_GET_ASSOC_STATS` counts bytes. `Status().Pending` and `Unacked` count chunks, and `EventSenderDry` reports an empty queue |
| Congestion-control selection | No SCTP socket option selects an algorithm |
| RFC 9653 zero checksum | Linux defines no `SCTP_ACCEPT_ZERO_CHECKSUM` |
| Explicit end of record (`SCTP_EOR`, RFC 6458 Verified Erratum 6111) | Not defined by Linux; every send is one whole message |
| RFC 6458 §6.1.1's feature list in `AssocCommUp` | Not filled in by Linux; use the capability getters (`PRSupported`, `AuthSupported`, ...) |

## Struct fields

Fields of the types that remain, or that have one successor, with their
new names. A field not listed keeps its name.

| v1 | Now |
|---|---|
| `SCTPAddr.IPAddrs []net.IPAddr`, `Port int` | `Addr.IPs []netip.Addr`, `Port uint16` |
| `AdaptationIndication.AdaptationInd` | `AdaptationIndication.Indication` |
| `AssocChange.OutboundStreams`, `InboundStreams`; `Error uint16` | `OutStreams`, `InStreams`; `Error ErrorCause` |
| `AssocInfo.AsocMaxRxt`, `NumberPeerDestinations`; `CookieLife` (ms); `AssocID` | `MaxRetrans`, `PeerDestinations`; `CookieLife time.Duration`; removed |
| `AssocReset` flags | `Denied`, `Failed` |
| `AssocStats.MaxRto`, `ObsRtoIPAddr` | `MaxRTOTicks`, `MaxRTOAddr netip.AddrPort` |
| `AssocStats.ISacks`, `OSacks`, `IPackets`, `OPackets` | `SACKsIn`, `SACKsOut`, `PacketsIn`, `PacketsOut` |
| `AssocStats.RtxChunks`, `OutOfSeqTsns`, `IDupChunks`, `GapCnt` | `RetransChunks`, `OutOfSeqTSNs`, `DupChunksIn`, `GapAcksIn` |
| `AssocStats.IUodChunks`, `OUodChunks`, `IOdChunks`, `OOdChunks`, `ICtrlChunks`, `OCtrlChunks` | `UnorderedChunksIn`, `UnorderedChunksOut`, `OrderedChunksIn`, `OrderedChunksOut`, `ControlChunksIn`, `ControlChunksOut` |
| `AuthKeyEvent.KeyNumber`, `AltKeyNumber` | `AuthEvent.Key`, `AltKey` |
| `DelayedSACKConfig.Delay` (ms), `SackTimer.SackDelay`, `SackFrequency` | `DelayedSACK.Delay time.Duration`, `Frequency` |
| `InitMsg.NumOstreams`, `MaxInstreams`; `MaxInitTimeout` (ms) | `OutStreams`, `MaxInStreams`; `MaxInitTimeout time.Duration` |
| `NxtInfo.SID`, `Flags` | `Stream`, `Unordered` and `Notification` |
| `PartialDelivery.StreamID`, `Indication` | `Stream`; removed, and `Unordered` added |
| `PeerAddrChange.Addr [128]byte`, `State uint32`, `Error uint32` | `Addr netip.AddrPort`, `State AddrChangeState`, `Reason AddrChangeReason` |
| `PeerAddrinfo.Address`, `CWND`, `SRTT`, `RTO` (ms) | `PathInfo.Addr netip.AddrPort`, `Cwnd`, `SRTTTicks`, `RTO time.Duration` |
| `PeerAddrParams.Address`, `AssocID` | the `path netip.Addr` argument of `PathParams` and `SetPathParams` |
| `PeerAddrParams.Flags` (`SPP_*`) | `PathParams.Heartbeat`, `PMTUD`, `DelayedSACK`; `RequestHeartbeat` for `SPP_HB_DEMAND` |
| `PeerAddrParams.HBInterval`, `PathMaxRxt`, `SackDelay` | `HeartbeatInterval`, `PathMaxRetrans`, `SACKDelay`, all pointers, durations as `time.Duration` |
| `PeerAddrThldsV2.PathMaxRxt`, `PathPfThld`, `PathCpThld`; `Address`, `AssocID` | `PathThresholds.PathMaxRetrans`, `PFThreshold`, `PrimarySwitchover`; the `path` argument |
| `PrInfo.Value` for `SCTP_PR_SCTP_TTL`; `DefaultPrInfo.AssocID` | `PrInfo.TTL time.Duration`; removed |
| `PrStatus.SID`, `Policy`, `AssocID` | arguments of `PRStreamStatus` and `PRAssocStatus` |
| `PreAssociationConfig.AuthenticatedChunks`, `DisableFragments` | `Config.AuthChunks`, `FragmentsDisabled` |
| `PreAssociationConfig.ReceiveRcvInfo`, `MappedV4Address` | removed: always on; IPv4 is always reported plainly |
| `RcvInfo.SID`, `Flags` | `Stream`, `Unordered` |
| `RtoInfo.Initial`, `Max`, `Min` (ms); `AssocID` | `RTOInfo` fields as `time.Duration`; removed |
| `SendFailedEvent.Info` | `SendFailed.Stream`, `PPID`, `Context`, and the chunk's `Unordered`, `FirstFragment`, `LastFragment` |
| `SendFailedEvent` flags | `SendFailed.Sent` |
| `SndInfo.SID`, `Flags uint16`, `AssocID` | `Stream`, `Flags SendFlags`; the `id` argument of `Endpoint.SendMsg` |
| `Status.RWND`, `Unackdata`, `Penddata`, `Instreams`, `Ostreams`, `PrimaryPeerAddr` | `PeerRwnd`, `Unacked`, `Pending`, `InStreams`, `OutStreams`, `Primary` |
| `Status.AssocID` | `Conn.AssocID()` |
| `StreamChange.InboundStreams`, `OutboundStreams`; flags | `InStreams`, `OutStreams`, the streams the request added; `Denied`, `Failed` |
| `StreamReset` flags | `Incoming`, `Outgoing`, `Denied`, `Failed` |

## Every v1 identifier

Every identifier v1.0.6 exported, 533 in all: types, functions, variables,
constants, and methods on exported types. "removed" means there is no
successor; the text after it names what to use instead.

### Types (61)

| v1 | Now |
|---|---|
| `AdaptationIndication` | `AdaptationIndication` (`AdaptationInd` → `Indication`) |
| `AddStreamsReq` | removed — ABI mirror; `Conn.AddStreams` |
| `AssocChange` | `AssocChange` (`OutboundStreams`/`InboundStreams` → `OutStreams`/`InStreams`, `Error` is `ErrorCause`) |
| `AssocInfo` | `AssocInfo` (`AsocMaxRxt` → `MaxRetrans`, `NumberPeerDestinations` → `PeerDestinations`, `CookieLife` is `time.Duration`, no `AssocID`) |
| `AssocReset` | `AssocReset` (flags → `Denied`/`Failed`) |
| `AssocStats` | `AssocStats` (fields renamed; `MaxRTOTicks` keeps the kernel's tick unit; `MaxRTOAddr` is `netip.AddrPort`) |
| `AssocValue` | removed — ABI mirror |
| `AuthInfo` | `SendOptions.AuthKey` |
| `AuthKeyEvent` | `AuthEvent` (`KeyNumber`/`AltKeyNumber` → `Key`/`AltKey`, `Indication` is `AuthIndication`) |
| `AuthKeyID` | removed — ABI mirror |
| `DefaultPrInfo` | `PrInfo` |
| `DelayedSACKConfig` | `DelayedSACK` |
| `DialAbandonPolicy` | `AbandonPolicy` |
| `Event` | removed — ABI mirror; `Conn.Subscribe` |
| `EventSubscribe` | removed — RFC 6458 §6.2.1 deprecated; `Conn.Subscribe`, `Config.Notifications` |
| `GetAddrsOld` | removed — ABI mirror |
| `InitMsg` | `InitMsg` (`NumOstreams` → `OutStreams`, `MaxInstreams` → `MaxInStreams`, `MaxInitTimeout` is `time.Duration`) |
| `Notification` | `Notification` (only `Type()`; `Flags`/`Length` replaced by typed fields) |
| `NotificationHandler` | `NotificationHandler` (`func(Notification) error`) |
| `NotificationHeader` | removed — ABI mirror |
| `NotificationSubscription` | `Config.Notifications` (`[]EventType`) |
| `NxtInfo` | `NxtInfo` (`SID` → `Stream`, `Flags` → `Unordered`/`Notification`; carried by value in `MsgInfo.Nxt` with `HasNxt`) |
| `OptionalInt` | removed — pointer fields with `new(expr)` |
| `OptionalUint32` | removed — pointer fields with `new(expr)` |
| `PartialDelivery` | `PartialDelivery` (`StreamID` → `Stream`; `Indication` dropped, it has one value; `Unordered` added; `Stream` and `SeqNum` are filled in only under I-DATA) |
| `PeerAddrChange` | `PeerAddrChange` (`Addr` is `netip.AddrPort`, `State` is `AddrChangeState`, `Error` → `Reason`, an `AddrChangeReason`) |
| `PeerAddrParams` | `PathParams` + `path netip.Addr` argument |
| `PeerAddrThlds` | removed — Linux's legacy two-field option; `PathThresholds` |
| `PeerAddrThldsV2` | `PathThresholds` + `path netip.Addr` argument |
| `PeerAddrinfo` | `PathInfo` (`SRTT` → `SRTTTicks`, still in kernel ticks; `RTO` becomes a `time.Duration`) |
| `PeerState` | `PathState` |
| `PrInfo` | `PrInfo` (`TTL` is `time.Duration`; `Value` for `PRRtx`/`PRPrio`) |
| `PrStatus` | `PRStatus` (stream and policy are method arguments) |
| `PreAssociationConfig` | `Config` (fields merged; `MappedV4Address` removed) |
| `PreconfiguredSocket` | `Config` |
| `ProbeInterval` | removed — `Conn.PLPMTUDProbeInterval(path)` |
| `RcvInfo` | `RcvInfo` (`SID` → `Stream`, `Flags` → `Unordered`) |
| `RemoteError` | `RemoteError` (`Error` is `ErrorCause`) |
| `RtoInfo` | `RTOInfo` (`time.Duration` fields, no `AssocID`) |
| `SCTPAddr` | `Addr` (`IPs []netip.Addr`, `Port uint16`) |
| `SCTPAssocID` | `AssocID` |
| `SCTPConn` | `Conn` |
| `SCTPEndpoint` | `Endpoint` |
| `SCTPListener` | `Listener` |
| `SCTPNotificationType` | `EventType` |
| `SCTPSndRcvInfoWrappedConn` | removed — built on deprecated `SCTP_SNDRCV` |
| `SCTPState` | `AssocChangeState` |
| `SackTimer` | `DelayedSACK` |
| `SendFailed` | removed — legacy `SCTP_SEND_FAILED`, RFC 6458 §6.1.4 deprecated (the name now means `SCTP_SEND_FAILED_EVENT`) |
| `SendFailedEvent` | `SendFailed` (one event per DATA fragment; `Error` is an `ErrorCause`; `Info` → `Stream`/`PPID`/`Context` plus the chunk's own bits; flags → `Sent`) |
| `SenderDry` | `SenderDry` |
| `Shutdown` | `Shutdown` |
| `SndInfo` | `SndInfo` (`SID` → `Stream`, `Flags` is `SendFlags`, `AssocID` → `Endpoint.SendMsg` argument) |
| `SndRcvInfo` | removed — RFC 6458 §5.3.2 deprecated; `SndInfo` / `RcvInfo` |
| `SocketConfig` | `Config` |
| `SocketOptionState` | removed — `*bool` |
| `Status` | `Status` (`State` is `AssocState`, `RWND` → `PeerRwnd`, `Unackdata` → `Unacked`, `Penddata` → `Pending`, `Instreams`/`Ostreams` → `InStreams`/`OutStreams`, `PrimaryPeerAddr` → `Primary`, `AssocID` → `Conn.AssocID()`) |
| `StatusState` | `AssocState` |
| `StreamChange` | `StreamChange` (`InboundStreams`/`OutboundStreams` → `InStreams`/`OutStreams`, flags → `Denied`/`Failed`) |
| `StreamReset` | `StreamReset` (flags → `Incoming`/`Outgoing`/`Denied`/`Failed`) |
| `UDPEncaps` | removed — `Conn.RemoteUDPEncapsPort(path)` |

### Functions (16)

| v1 | Now |
|---|---|
| `DialSCTP` | `Dial(ctx, ...)` — a context is now required |
| `DialSCTPContext` | `Dial`, or `Config.Dial` with `Config.InitMsg` |
| `DialSCTPContextWithAbandonPolicy` | `Config.Dial` with `Config.AbandonPolicy` |
| `DialSCTPExt` | `Config.Dial` with `Config.InitMsg` |
| `ErrorCauseString` | `ErrorCause.String` |
| `FileListener` | `FileListener`, or `Config.FileListener` to give accepted connections a handler |
| `ListenSCTP` | `Listen` |
| `ListenSCTPEndpoint` | `ListenEndpoint` |
| `ListenSCTPExt` | `Config.Listen` with `Config.InitMsg` |
| `NewSCTPConn` | removed — use `FileConn`, or `Config.FileConn` for a handler; `Endpoint` for one-to-many sockets |
| `NewSCTPSndRcvInfoWrappedConn` | removed — built on deprecated `SCTP_SNDRCV` |
| `OpenSCTPEndpoint` | `OpenEndpoint` |
| `ParseNotification` | `ParseNotification` (returns typed values) |
| `ResolveSCTPAddr` | `ResolveAddr` |
| `SCTPBind` | removed — descriptor-level; `Config.Control` or `BindAdd` |
| `SCTPConnect` | removed — descriptor-level; `Dial` or `Endpoint.Connect` |

### Variables (10)

| v1 | Now |
|---|---|
| `ErrAssociationListTooLarge` | `ErrAssocListTooLarge` |
| `ErrControlTruncated` | `ErrControlTruncated` |
| `ErrInvalidAssociationList` | `ErrInvalidAssocList` |
| `ErrInvalidReceiveInfo` | `ErrInvalidRcvInfo` |
| `ErrMessageInterrupted` | `ErrMessageInterrupted` |
| `ErrMissingReceiveInfo` | `ErrMissingRcvInfo` |
| `ErrMsgTooLong` | `ErrMessageTooLong` |
| `ErrNotificationTooLong` | `ErrNotificationTooLong` |
| `ErrShortNotification` | `ErrShortNotification` |
| `ErrUnsupported` | `ErrUnsupported` |

### Methods (223)

| v1 | Now |
|---|---|
| `AdaptationIndication.Flags` | removed — typed fields |
| `AdaptationIndication.Length` | removed — events arrive reassembled |
| `AdaptationIndication.Type` | `Type() EventType` |
| `AssocChange.Flags` | removed — typed fields |
| `AssocChange.Length` | removed — events arrive reassembled |
| `AssocChange.Type` | `Type() EventType` |
| `AssocReset.Flags` | removed — typed fields |
| `AssocReset.Length` | removed — events arrive reassembled |
| `AssocReset.Type` | `Type() EventType` |
| `AuthKeyEvent.Flags` | removed — typed fields |
| `AuthKeyEvent.Length` | removed — events arrive reassembled |
| `AuthKeyEvent.Type` | `Type() EventType` |
| `PartialDelivery.Flags` | removed — typed fields |
| `PartialDelivery.Length` | removed — events arrive reassembled |
| `PartialDelivery.Type` | `Type() EventType` |
| `PeerAddrChange.Flags` | removed — typed fields |
| `PeerAddrChange.Length` | removed — events arrive reassembled |
| `PeerAddrChange.Type` | `Type() EventType` |
| `PreconfiguredSocket.Dial` | `Config.Dial(ctx, ...)` |
| `PreconfiguredSocket.DialContext` | `Config.Dial` |
| `PreconfiguredSocket.DialContextWithAbandonPolicy` | `Config.Dial` with `Config.AbandonPolicy` |
| `PreconfiguredSocket.Listen` | `Config.Listen` |
| `PreconfiguredSocket.ListenEndpoint` | `Config.ListenEndpoint` |
| `PreconfiguredSocket.OpenEndpoint` | `Config.OpenEndpoint` |
| `RemoteError.Flags` | removed — typed fields |
| `RemoteError.Length` | removed — events arrive reassembled |
| `RemoteError.Type` | `Type() EventType` |
| `SCTPAddr.MarshalSockaddr` | removed — no raw `sockaddr` bytes remain in the API (see "Capabilities with no replacement") |
| `SCTPAddr.Network` | `Addr.Network` |
| `SCTPAddr.String` | `Addr.String` |
| `SCTPAddr.ToRawSockAddrBuf` | removed |
| `SCTPAddr.Validate` | removed — errors surface from the call that uses the address |
| `SCTPConn.Abort` | `Conn.Abort` |
| `SCTPConn.AddStreams` | `Conn.AddStreams` |
| `SCTPConn.AsconfSupported` | `Conn.ASCONFSupported` |
| `SCTPConn.AuthActiveKey` | `Conn.ActiveAuthKey` |
| `SCTPConn.AuthSupported` | `Conn.AuthSupported` |
| `SCTPConn.AutoAsconf` | `Conn.AutoASCONF` |
| `SCTPConn.BindAdd` | `Conn.BindAdd(ips ...netip.Addr)` |
| `SCTPConn.BindRemove` | `Conn.BindRemove(ips ...netip.Addr)` |
| `SCTPConn.Close` | `Conn.Close` |
| `SCTPConn.CloseWithTimeout` | `Conn.CloseWithTimeout` |
| `SCTPConn.DeactivateAuthKey` | `Conn.DeactivateAuthKey` |
| `SCTPConn.DeleteAuthKey` | `Conn.DeleteAuthKey` |
| `SCTPConn.DisableFragments` | `Conn.FragmentsDisabled` |
| `SCTPConn.EcnSupported` | `Conn.ECNSupported` |
| `SCTPConn.EnableStreamReset` | `Conn.StreamResetMask` |
| `SCTPConn.EventSubscribed` | `Conn.Subscribed` |
| `SCTPConn.ExposePotentiallyFailed` | `Conn.PFExposure` |
| `SCTPConn.GetAdaptationLayer` | `Conn.AdaptationLayer` |
| `SCTPConn.GetAssocInfo` | `Conn.AssocInfo` |
| `SCTPConn.GetAssocStats` | `Conn.Stats` |
| `SCTPConn.GetContext` | `Conn.DefaultContext` |
| `SCTPConn.GetDefaultPrInfo` | `Conn.DefaultPrInfo` (returns `*PrInfo`) |
| `SCTPConn.GetDefaultSentParam` | removed — RFC 6458 §8.1.13 deprecated; `Conn.DefaultSndInfo` |
| `SCTPConn.GetDefaultSndInfo` | `Conn.DefaultSndInfo` |
| `SCTPConn.GetFragmentInterleave` | `Conn.FragmentInterleave` |
| `SCTPConn.GetInitMsg` | `Conn.InitMsg` |
| `SCTPConn.GetMaxBurst` | `Conn.MaxBurst` |
| `SCTPConn.GetMaxSegSize` | `Conn.MaxSeg` |
| `SCTPConn.GetNoDelay` | `Conn.NoDelay` (`bool`) |
| `SCTPConn.GetPartialDeliveryPoint` | `Conn.PartialDeliveryPoint` |
| `SCTPConn.GetPeerAddrInfo` | `Conn.PathInfo(path)` |
| `SCTPConn.GetPeerAddrParams` | `Conn.PathParams(path)` |
| `SCTPConn.GetPeerAddrThlds` | removed — legacy option; `Conn.PathThresholds` |
| `SCTPConn.GetPeerAddrThldsV2` | `Conn.PathThresholds(path)` |
| `SCTPConn.GetPrAssocStatus` | `Conn.PRAssocStatus` |
| `SCTPConn.GetPrStreamStatus` | `Conn.PRStreamStatus` |
| `SCTPConn.GetProbeInterval` | `Conn.PLPMTUDProbeInterval(path)` |
| `SCTPConn.GetReadBuffer` | `Conn.ReadBuffer` |
| `SCTPConn.GetRemoteUDPEncapsPort` | `Conn.RemoteUDPEncapsPort(path)` |
| `SCTPConn.GetReusePort` | removed — fixed by `Config.ReusePort` before bind |
| `SCTPConn.GetRtoInfo` | `Conn.RTOInfo` |
| `SCTPConn.GetSackTimer` | `Conn.DelayedSACK` |
| `SCTPConn.GetStatus` | `Conn.Status`; the association id is `Conn.AssocID()` |
| `SCTPConn.GetStreamSchedulerValue` | `Conn.StreamSchedulerValue` |
| `SCTPConn.GetWriteBuffer` | `Conn.WriteBuffer` |
| `SCTPConn.Getsockopt` | removed — `SyscallConn` |
| `SCTPConn.HmacIdent` | `Conn.HMACIdentifiers` |
| `SCTPConn.InterleavingSupported` | `Conn.InterleavingSupported` |
| `SCTPConn.LocalAddr` | `Conn.LocalAddr` — now the association's addresses, not the endpoint's bound set |
| `SCTPConn.LocalAuthChunks` | `Conn.LocalAuthChunks` |
| `SCTPConn.MappedV4Addr` | removed — IPv4 addresses are always reported in plain form |
| `SCTPConn.PeelOff` | removed — only worked on one-to-many sockets; `Endpoint.PeelOff` |
| `SCTPConn.PeerAuthChunks` | `Conn.PeerAuthChunks` |
| `SCTPConn.PrSupported` | `Conn.PRSupported` |
| `SCTPConn.Read` | `Conn.Read` |
| `SCTPConn.ReadMsg` | `Conn.ReadMsg` (returns `RcvInfo`) |
| `SCTPConn.ReconfigSupported` | `Conn.ReconfigSupported` |
| `SCTPConn.RemoteAddr` | `Conn.RemoteAddr` |
| `SCTPConn.ResetAssoc` | `Conn.ResetAssoc` |
| `SCTPConn.ResetStreams` | `Conn.ResetStreams(ResetDirection, ...)` |
| `SCTPConn.SCTPGetPrimaryPeerAddr` | `Conn.PrimaryAddr` |
| `SCTPConn.SCTPLocalAddr` | `Conn.LocalAddrs` — the association's addresses; v1's `SCTPLocalAddr(0)` returned the endpoint's bound set |
| `SCTPConn.SCTPRead` | removed — `Conn.RecvMsg` |
| `SCTPConn.SCTPReadFlags` | removed — `Conn.RecvMsg` |
| `SCTPConn.SCTPReadMsg` | removed — `SyscallConn` |
| `SCTPConn.SCTPReadNextInfo` | removed — `Conn.RecvMsg` (`MsgInfo.Nxt`, `MsgInfo.HasNxt`) |
| `SCTPConn.SCTPRemoteAddr` | `Conn.PeerAddrs` |
| `SCTPConn.SCTPWrite` | removed — RFC 6458 §5.3.2 deprecated; `Conn.SendMsg` (with `NoWait` for v1's behaviour without a write deadline) |
| `SCTPConn.SCTPWriteInfo` | `Conn.SendMsg(b, SendOptions)`; set `NoWait` for v1's behaviour without a write deadline |
| `SCTPConn.SetAdaptationLayer` | removed — only effective before the INIT; `Config.AdaptationLayer` |
| `SCTPConn.SetAsconfSupported` | removed — only effective before the INIT; `Config.DynamicAddressReconfiguration` |
| `SCTPConn.SetAssocInfo` | `Conn.SetAssocInfo` |
| `SCTPConn.SetAuthActiveKey` | `Conn.SetActiveAuthKey` |
| `SCTPConn.SetAuthChunk` | removed — only affects future associations; `Config.AuthChunks` |
| `SCTPConn.SetAuthKey` | `Conn.SetAuthKey` |
| `SCTPConn.SetAuthSupported` | removed — only effective before the INIT; `Config.Authentication` |
| `SCTPConn.SetAutoAsconf` | `Conn.SetAutoASCONF` |
| `SCTPConn.SetContext` | `Conn.SetDefaultContext` |
| `SCTPConn.SetDeadline` | `Conn.SetDeadline` |
| `SCTPConn.SetDefaultPrInfo` | `Conn.SetDefaultPrInfo(*PrInfo)` |
| `SCTPConn.SetDefaultSentParam` | removed — RFC 6458 §8.1.13 deprecated; `Conn.SetDefaultSndInfo` |
| `SCTPConn.SetDefaultSndInfo` | `Conn.SetDefaultSndInfo`, or `Config.DefaultSndInfo` |
| `SCTPConn.SetDisableFragments` | `Conn.SetFragmentsDisabled` |
| `SCTPConn.SetEcnSupported` | removed — only effective before the INIT; `Config.ExperimentalECN` |
| `SCTPConn.SetEnableStreamReset` | `Conn.SetStreamResetMask` |
| `SCTPConn.SetExposePotentiallyFailed` | `Conn.SetPFExposure` |
| `SCTPConn.SetFragmentInterleave` | `Conn.SetFragmentInterleave(FragmentInterleave)` |
| `SCTPConn.SetHmacIdent` | removed — only effective before the INIT; `Config.HMACIdentifiers` |
| `SCTPConn.SetInitMsg` | removed — only effective before the INIT; `Config.InitMsg` |
| `SCTPConn.SetInterleavingSupported` | removed — only effective before the INIT; `Config.MessageInterleaving` |
| `SCTPConn.SetMappedV4Addr` | removed — IPv4 addresses are always reported in plain form |
| `SCTPConn.SetMaxBurst` | `Conn.SetMaxBurst` |
| `SCTPConn.SetMaxSegSize` | `Conn.SetMaxSeg` |
| `SCTPConn.SetNoDelay` | `Conn.SetNoDelay(bool)`, or `Config.NoDelay` |
| `SCTPConn.SetPartialDeliveryPoint` | `Conn.SetPartialDeliveryPoint` |
| `SCTPConn.SetPeerAddrParams` | `Conn.SetPathParams(path, *PathParams)` |
| `SCTPConn.SetPeerAddrThlds` | removed — legacy option; `Conn.SetPathThresholds` |
| `SCTPConn.SetPeerAddrThldsV2` | `Conn.SetPathThresholds(path, *PathThresholds)` |
| `SCTPConn.SetPeerPrimaryAddr` | `Conn.RequestPeerPrimary(local)` |
| `SCTPConn.SetPrSupported` | removed — only effective before the INIT; `Config.PartialReliability` |
| `SCTPConn.SetPrimaryPeerAddr` | `Conn.SetPrimaryAddr(path)` |
| `SCTPConn.SetProbeInterval` | `Conn.SetPLPMTUDProbeInterval(path, d)` |
| `SCTPConn.SetReadBuffer` | `Conn.SetReadBuffer` |
| `SCTPConn.SetReadDeadline` | `Conn.SetReadDeadline` |
| `SCTPConn.SetReconfigSupported` | removed — only effective before the INIT; `Config.StreamReconfiguration` |
| `SCTPConn.SetRecvNxtInfo` | `Conn.SetReceiveNxtInfo` (and the new getter `Conn.ReceiveNxtInfo`) |
| `SCTPConn.SetRecvRcvInfo` | removed — always on |
| `SCTPConn.SetRemoteUDPEncapsPort` | `Conn.SetRemoteUDPEncapsPort(path, port)` |
| `SCTPConn.SetReusePort` | removed — must precede bind; `Config.ReusePort` |
| `SCTPConn.SetRtoInfo` | `Conn.SetRTOInfo` |
| `SCTPConn.SetSackTimer` | `Conn.SetDelayedSACK` |
| `SCTPConn.SetStreamScheduler` | `Conn.SetStreamScheduler(Scheduler)` |
| `SCTPConn.SetStreamSchedulerValue` | `Conn.SetStreamSchedulerValue` |
| `SCTPConn.SetWriteBuffer` | `Conn.SetWriteBuffer` |
| `SCTPConn.SetWriteDeadline` | `Conn.SetWriteDeadline` |
| `SCTPConn.Setsockopt` | removed — `SyscallConn` |
| `SCTPConn.StreamScheduler` | `Conn.StreamScheduler` (returns `Scheduler`) |
| `SCTPConn.SubscribeEvent` | `Conn.Subscribe` |
| `SCTPConn.SubscribeEvents` | removed — RFC 6458 §8.1.14 deprecated; `Conn.Subscribe` |
| `SCTPConn.SubscribedEvents` | removed — RFC 6458 §8.1.14 deprecated; `Conn.Subscribed` |
| `SCTPConn.SyscallConn` | `Conn.SyscallConn` |
| `SCTPConn.Write` | `Conn.Write` |
| `SCTPEndpoint.Abort` | `Endpoint.Abort` |
| `SCTPEndpoint.AbortAssociation` | `Endpoint.AbortAssoc` |
| `SCTPEndpoint.Addr` | `Endpoint.Addr` |
| `SCTPEndpoint.AssociationCount` | `Endpoint.AssocCount` (returns `int`) |
| `SCTPEndpoint.AssociationIDs` | `Endpoint.AssocIDs` |
| `SCTPEndpoint.BindAdd` | `Endpoint.BindAdd(ips ...netip.Addr)` |
| `SCTPEndpoint.BindRemove` | `Endpoint.BindRemove(ips ...netip.Addr)` |
| `SCTPEndpoint.Close` | `Endpoint.Close` |
| `SCTPEndpoint.CloseAssociation` | `Endpoint.CloseAssoc` |
| `SCTPEndpoint.Connect` | `Endpoint.Connect` |
| `SCTPEndpoint.GetAutoClose` | `Endpoint.AutoClose` (`time.Duration`) |
| `SCTPEndpoint.LocalAddrs` | `Endpoint.LocalAddrs` |
| `SCTPEndpoint.Network` | `Endpoint.Network` |
| `SCTPEndpoint.PeelOff` | `Endpoint.PeelOff` (reads now end with `io.EOF` after a graceful end, and with the association's error after an ABORT or failure, instead of waiting) |
| `SCTPEndpoint.PeerAddrs` | `Endpoint.PeerAddrs` |
| `SCTPEndpoint.Receive` | `Endpoint.RecvMsg` |
| `SCTPEndpoint.Send` | `Endpoint.SendMsg(id, b, SendOptions)`; set `NoWait` for v1's behaviour without a write deadline |
| `SCTPEndpoint.SetAutoClose` | `Endpoint.SetAutoClose(time.Duration)` |
| `SCTPEndpoint.SetDeadline` | `Endpoint.SetDeadline` |
| `SCTPEndpoint.SetReadDeadline` | `Endpoint.SetReadDeadline` |
| `SCTPEndpoint.SetWriteDeadline` | `Endpoint.SetWriteDeadline` |
| `SCTPEndpoint.SyscallConn` | `Endpoint.SyscallConn` |
| `SCTPListener.Accept` | `Listener.Accept` |
| `SCTPListener.AcceptSCTP` | `Listener.AcceptSCTP` |
| `SCTPListener.Addr` | `Listener.Addr` |
| `SCTPListener.BindAdd` | `Listener.BindAdd(ips ...netip.Addr)` |
| `SCTPListener.BindRemove` | `Listener.BindRemove(ips ...netip.Addr)` |
| `SCTPListener.Close` | `Listener.Close` |
| `SCTPListener.SetDeadline` | `Listener.SetDeadline` |
| `SCTPListener.SyscallConn` | `Listener.SyscallConn` |
| `SCTPSndRcvInfoWrappedConn.Close` | removed — type removed |
| `SCTPSndRcvInfoWrappedConn.GetReadBuffer` | removed — type removed |
| `SCTPSndRcvInfoWrappedConn.GetWriteBuffer` | removed — type removed |
| `SCTPSndRcvInfoWrappedConn.LocalAddr` | removed — type removed |
| `SCTPSndRcvInfoWrappedConn.Read` | removed — type removed |
| `SCTPSndRcvInfoWrappedConn.RemoteAddr` | removed — type removed |
| `SCTPSndRcvInfoWrappedConn.SetDeadline` | removed — type removed |
| `SCTPSndRcvInfoWrappedConn.SetReadBuffer` | removed — type removed |
| `SCTPSndRcvInfoWrappedConn.SetReadDeadline` | removed — type removed |
| `SCTPSndRcvInfoWrappedConn.SetWriteBuffer` | removed — type removed |
| `SCTPSndRcvInfoWrappedConn.SetWriteDeadline` | removed — type removed |
| `SCTPSndRcvInfoWrappedConn.Write` | removed — type removed |
| `SCTPState.String` | `AssocChangeState.String` |
| `SendFailed.Flags` | removed — legacy event |
| `SendFailed.Length` | removed — legacy event |
| `SendFailed.Type` | removed — legacy event |
| `SendFailedEvent.Flags` | removed — typed fields |
| `SendFailedEvent.Length` | removed — events arrive reassembled |
| `SendFailedEvent.Type` | `Type() EventType` |
| `SenderDry.Flags` | removed — typed fields |
| `SenderDry.Length` | removed — events arrive reassembled |
| `SenderDry.Type` | `Type() EventType` |
| `Shutdown.Flags` | removed — typed fields |
| `Shutdown.Length` | removed — events arrive reassembled |
| `Shutdown.Type` | `Type() EventType` |
| `SocketConfig.Dial` | `Config.Dial(ctx, ...)` |
| `SocketConfig.DialContext` | `Config.Dial` |
| `SocketConfig.DialContextWithAbandonPolicy` | `Config.Dial` with `Config.AbandonPolicy` |
| `SocketConfig.Listen` | `Config.Listen` |
| `SocketConfig.ListenEndpoint` | `Config.ListenEndpoint` |
| `SocketConfig.OpenEndpoint` | `Config.OpenEndpoint` |
| `SocketConfig.WithPreAssociation` | removed — set the fields on `Config` |
| `SocketOptionState.String` | removed |
| `StreamChange.Flags` | removed — typed fields |
| `StreamChange.Length` | removed — events arrive reassembled |
| `StreamChange.Type` | `Type() EventType` |
| `StreamReset.Flags` | removed — typed fields |
| `StreamReset.Length` | removed — events arrive reassembled |
| `StreamReset.Type` | `Type() EventType` |

### Constants (223)

| v1 | Now |
|---|---|
| `DialAbandonAbort` | `AbandonAbort` |
| `DialAbandonQuiet` | `AbandonQuiet` |
| `MSG_EOR` | `MsgInfo.EOR` |
| `MSG_NOTIFICATION` | `MsgInfo.Notification` |
| `NotificationMaxSize` | `NotificationMaxSize` (unchanged) |
| `NotificationReassemblyLimit` | `NotificationReassemblyLimit` (unchanged) |
| `SCTPAuthHmacIDSHA1` | `HMACSHA1` |
| `SCTPAuthHmacIDSHA256` | `HMACSHA256` |
| `SCTPEnableChangeAssocReq` | `EnableChangeAssocReq` |
| `SCTPEnableResetAssocReq` | `EnableResetAssocReq` |
| `SCTPEnableResetStreamReq` | `EnableResetStreamReq` |
| `SCTPFragmentInterleaveNone` | `InterleaveNone` |
| `SCTPFragmentInterleaveOther` | `InterleaveAssocs` |
| `SCTPFragmentInterleaveStreams` | `InterleaveStreams` |
| `SCTPPFStateDisabled` | `PFExposeDisabled` |
| `SCTPPFStateEnabled` | `PFExposeEnabled` |
| `SCTPPFStateUnset` | `PFExposeUnset` |
| `SCTPPrPolicyNone` | `PRNone` |
| `SCTPPrPolicyPrio` | `PRPrio` |
| `SCTPPrPolicyRtx` | `PRRtx` |
| `SCTPPrPolicyTTL` | `PRTTL` |
| `SCTPSchedFC` | `SchedFC` |
| `SCTPSchedFCFS` | `SchedFCFS` |
| `SCTPSchedPrio` | `SchedPrio` |
| `SCTPSchedRR` | `SchedRR` |
| `SCTPSchedWFQ` | `SchedWFQ` |
| `SCTPStreamResetIncoming` | `ResetIncoming` |
| `SCTPStreamResetOutgoing` | `ResetOutgoing` |
| `SCTP_ABORT` | removed — `Conn.Abort`, `Endpoint.AbortAssoc` |
| `SCTP_ACTIVE` | `PathActive` |
| `SCTP_ADAPTATION_INDICATION` | `EventAdaptationIndication` |
| `SCTP_ADAPTATION_LAYER` | `Config.AdaptationLayer`, `Conn.AdaptationLayer` |
| `SCTP_ADDR_ADDED` | `AddrAdded` |
| `SCTP_ADDR_AVAILABLE` | `AddrAvailable` |
| `SCTP_ADDR_CONFIRMED` | `AddrConfirmed` |
| `SCTP_ADDR_MADE_PRIM` | `AddrMadePrimary` |
| `SCTP_ADDR_OVER` | `SendOptions.Path` |
| `SCTP_ADDR_POTENTIALLY_FAILED` | `AddrPotentiallyFailed` |
| `SCTP_ADDR_REMOVED` | `AddrRemoved` |
| `SCTP_ADDR_UNREACHABLE` | `AddrUnreachable` |
| `SCTP_ADD_STREAMS` | `Conn.AddStreams` |
| `SCTP_ALL_ASSOC` | removed — no public struct carries an association scope |
| `SCTP_ASCONF_SUPPORTED` | `Config.DynamicAddressReconfiguration`, `Conn.ASCONFSupported` |
| `SCTP_ASSOCINFO` | `Conn.AssocInfo` / `SetAssocInfo` |
| `SCTP_ASSOC_CHANGE` | `EventAssocChange` |
| `SCTP_ASSOC_RESET_DENIED` | `AssocReset.Denied` |
| `SCTP_ASSOC_RESET_EVENT` | `EventAssocReset` |
| `SCTP_ASSOC_RESET_FAILED` | `AssocReset.Failed` |
| `SCTP_AUTHENTICATION_EVENT` | `EventAuthentication` |
| `SCTP_AUTHENTICATION_INDICATION` | `EventAuthentication` |
| `SCTP_AUTH_ACTIVE_KEY` | `Conn.ActiveAuthKey` / `SetActiveAuthKey` |
| `SCTP_AUTH_CHUNK` | `Config.AuthChunks` |
| `SCTP_AUTH_DEACTIVATE_KEY` | `Conn.DeactivateAuthKey` |
| `SCTP_AUTH_DELETE_KEY` | `Conn.DeleteAuthKey` |
| `SCTP_AUTH_FREE_KEY` | `AuthFreeKey` |
| `SCTP_AUTH_KEY` | `Conn.SetAuthKey` |
| `SCTP_AUTH_NEW_KEY` | `AuthNewKey` |
| `SCTP_AUTH_NO_AUTH` | `AuthNoAuth` |
| `SCTP_AUTH_SUPPORTED` | `Config.Authentication`, `Conn.AuthSupported` |
| `SCTP_AUTOCLOSE` | `Endpoint.AutoClose` / `SetAutoClose` |
| `SCTP_AUTO_ASCONF` | `Conn.AutoASCONF` / `SetAutoASCONF` |
| `SCTP_BINDX_ADD_ADDR` | `BindAdd` |
| `SCTP_BINDX_REM_ADDR` | `BindRemove` |
| `SCTP_CANT_STR_ASSOC` | `AssocCantStart` |
| `SCTP_CLOSED` | `StateClosed` |
| `SCTP_CMSG_AUTHINFO` | `SendOptions.AuthKey` |
| `SCTP_CMSG_DSTADDRV4` | removed — implicit association setup is not offered |
| `SCTP_CMSG_DSTADDRV6` | removed — implicit association setup is not offered |
| `SCTP_CMSG_INIT` | removed — implicit association setup is not offered; `Config.InitMsg` |
| `SCTP_CMSG_NXTINFO` | `MsgInfo.Nxt` |
| `SCTP_CMSG_PRINFO` | `SendOptions.PR` |
| `SCTP_CMSG_RCVINFO` | `MsgInfo.Rcv` |
| `SCTP_CMSG_SNDINFO` | `SendOptions.Info` |
| `SCTP_CMSG_SNDRCV` | removed — RFC 6458 §5.3.2 deprecated |
| `SCTP_COMM_LOST` | `AssocCommLost` |
| `SCTP_COMM_UP` | `AssocCommUp` |
| `SCTP_CONTEXT` | `Conn.DefaultContext` / `SetDefaultContext` |
| `SCTP_COOKIE_ECHOED` | `StateCookieEchoed` |
| `SCTP_COOKIE_WAIT` | `StateCookieWait` |
| `SCTP_CURRENT_ASSOC` | removed — no public struct carries an association scope |
| `SCTP_DATA_IO_EVENT` | removed — only enables the deprecated `SCTP_SNDRCV` data |
| `SCTP_DATA_SENT` | `SendFailed.Sent` true |
| `SCTP_DATA_UNSENT` | `SendFailed.Sent` false |
| `SCTP_DEFAULT_PRINFO` | `Conn.DefaultPrInfo` / `SetDefaultPrInfo` |
| `SCTP_DEFAULT_SEND_PARAM` | removed — RFC 6458 §8.1.13 deprecated; `Conn.SetDefaultSndInfo` |
| `SCTP_DEFAULT_SENT_PARAM` | removed — misspelled alias of a deprecated option |
| `SCTP_DEFAULT_SNDINFO` | `Conn.DefaultSndInfo` / `SetDefaultSndInfo`, `Config.DefaultSndInfo` |
| `SCTP_DELAYED_ACK` | removed — alias; see `SCTP_DELAYED_ACK_TIME` |
| `SCTP_DELAYED_ACK_TIME` | `Conn.DelayedSACK` / `SetDelayedSACK`, `Config.DelayedSACK` |
| `SCTP_DELAYED_SACK` | removed — alias; see `SCTP_DELAYED_ACK_TIME` |
| `SCTP_DISABLE_FRAGMENTS` | `Conn.FragmentsDisabled` / `SetFragmentsDisabled`, `Config.FragmentsDisabled` |
| `SCTP_ECN_SUPPORTED` | `Config.ExperimentalECN`, `Conn.ECNSupported` |
| `SCTP_EMPTY` | `StateEmpty` |
| `SCTP_ENABLE_STREAM_RESET` | `Conn.StreamResetMask` / `SetStreamResetMask`, `Config.StreamResetMask` |
| `SCTP_EOF` | removed — Linux rejects it on one-to-one sockets and with a payload; elsewhere it is what `Endpoint.CloseAssoc` does; use that or `Close` |
| `SCTP_ERROR_ASCONF_ACK` | `CauseIllegalASCONFAck` |
| `SCTP_ERROR_COOKIE_IN_SHUTDOWN` | `CauseCookieInShutdown` |
| `SCTP_ERROR_DEL_LAST_IP` | `CauseDeleteLastAddr` |
| `SCTP_ERROR_DEL_SRC_IP` | `CauseDeleteSourceAddr` |
| `SCTP_ERROR_DNS_FAILED` | `CauseUnresolvableAddr` |
| `SCTP_ERROR_INV_PARAM` | `CauseInvalidParam` |
| `SCTP_ERROR_INV_STRM` | `CauseInvalidStream` |
| `SCTP_ERROR_MISS_PARAM` | `CauseMissingParam` |
| `SCTP_ERROR_NEW_ENCAP_PORT` | `CauseRestartNewEncapPort` |
| `SCTP_ERROR_NO_DATA` | `CauseNoUserData` |
| `SCTP_ERROR_NO_ERROR` | `CauseNone` |
| `SCTP_ERROR_NO_RESOURCE` | `CauseOutOfResource` |
| `SCTP_ERROR_PROTO_VIOLATION` | `CauseProtocolViolation` |
| `SCTP_ERROR_REQ_REFUSED` | `CauseRequestRefused` |
| `SCTP_ERROR_RESTART` | `CauseRestartNewAddrs` |
| `SCTP_ERROR_RSRC_LOW` | `CauseResourceShortage` |
| `SCTP_ERROR_STALE_COOKIE` | `CauseStaleCookie` |
| `SCTP_ERROR_UNKNOWN_CHUNK` | `CauseUnrecognizedChunk` |
| `SCTP_ERROR_UNKNOWN_PARAM` | `CauseUnrecognizedParams` |
| `SCTP_ERROR_UNSUP_HMAC` | `CauseUnsupportedHMAC` |
| `SCTP_ERROR_USER_ABORT` | `CauseUserAbort` |
| `SCTP_ESTABLISHED` | `StateEstablished` |
| `SCTP_EVENT` | `Conn.Subscribe` / `Subscribed`, `Config.Notifications` |
| `SCTP_EVENTS` | removed — RFC 6458 §8.1.14 deprecated; `Conn.Subscribe` |
| `SCTP_EVENT_ADAPTATION_LAYER` | removed — `SCTP_EVENTS` bitmask, deprecated; `EventType` with `Conn.Subscribe` |
| `SCTP_EVENT_ADDRESS` | removed — `SCTP_EVENTS` bitmask, deprecated; `EventType` with `Conn.Subscribe` |
| `SCTP_EVENT_ALL` | removed — `SCTP_EVENTS` bitmask, deprecated; `EventType` with `Conn.Subscribe` |
| `SCTP_EVENT_ASSOCIATION` | removed — `SCTP_EVENTS` bitmask, deprecated; `EventType` with `Conn.Subscribe` |
| `SCTP_EVENT_AUTHENTICATION` | removed — `SCTP_EVENTS` bitmask, deprecated; `EventType` with `Conn.Subscribe` |
| `SCTP_EVENT_DATA_IO` | removed — `SCTP_EVENTS` bitmask, deprecated; `EventType` with `Conn.Subscribe` |
| `SCTP_EVENT_PARTIAL_DELIVERY` | removed — `SCTP_EVENTS` bitmask, deprecated; `EventType` with `Conn.Subscribe` |
| `SCTP_EVENT_PEER_ERROR` | removed — `SCTP_EVENTS` bitmask, deprecated; `EventType` with `Conn.Subscribe` |
| `SCTP_EVENT_SENDER_DRY` | removed — `SCTP_EVENTS` bitmask, deprecated; `EventType` with `Conn.Subscribe` |
| `SCTP_EVENT_SEND_FAILURE` | removed — `SCTP_EVENTS` bitmask, deprecated; `EventType` with `Conn.Subscribe` |
| `SCTP_EVENT_SHUTDOWN` | removed — `SCTP_EVENTS` bitmask, deprecated; `EventType` with `Conn.Subscribe` |
| `SCTP_EXPOSE_PF_STATE` | removed — alias; `Conn.PFExposure` |
| `SCTP_EXPOSE_POTENTIALLY_FAILED_STATE` | `Conn.PFExposure` / `SetPFExposure` |
| `SCTP_FRAGMENT_INTERLEAVE` | `Conn.FragmentInterleave` / `SetFragmentInterleave`, `Config.FragmentInterleave` |
| `SCTP_FUTURE_ASSOC` | removed — no public struct carries an association scope |
| `SCTP_GET_ASSOC_ID_LIST` | `Endpoint.AssocIDs` |
| `SCTP_GET_ASSOC_NUMBER` | `Endpoint.AssocCount` |
| `SCTP_GET_ASSOC_STATS` | `Conn.Stats` |
| `SCTP_GET_LOCAL_ADDRS` | `LocalAddrs` |
| `SCTP_GET_PEER_ADDRS` | `PeerAddrs` |
| `SCTP_GET_PEER_ADDR_INFO` | `Conn.PathInfo` |
| `SCTP_HMAC_IDENT` | `Config.HMACIdentifiers`, `Conn.HMACIdentifiers` |
| `SCTP_INACTIVE` | `PathInactive` |
| `SCTP_INITMSG` | `Config.InitMsg`, `Conn.InitMsg` |
| `SCTP_INTERLEAVING_SUPPORTED` | `Config.MessageInterleaving`, `Conn.InterleavingSupported` |
| `SCTP_I_WANT_MAPPED_V4_ADDR` | removed — the package decodes both kernel forms and always reports IPv4 plainly, so setting it from `Control` changes nothing the API returns |
| `SCTP_LOCAL_AUTH_CHUNKS` | `Conn.LocalAuthChunks` |
| `SCTP_MAXSEG` | `Conn.MaxSeg` / `SetMaxSeg` |
| `SCTP_MAX_BURST` | `Conn.MaxBurst` / `SetMaxBurst` |
| `SCTP_MAX_STREAM` | removed |
| `SCTP_NODELAY` | `Conn.NoDelay` / `SetNoDelay`, `Config.NoDelay` |
| `SCTP_NOTIFICATION` | removed — not a send flag; `MsgInfo.Notification` |
| `SCTP_PARTIAL_DELIVERY_EVENT` | `EventPartialDelivery` |
| `SCTP_PARTIAL_DELIVERY_POINT` | `Conn.PartialDeliveryPoint` / `SetPartialDeliveryPoint` |
| `SCTP_PEER_ADDR_CHANGE` | `EventPeerAddrChange` |
| `SCTP_PEER_ADDR_PARAMS` | `Conn.PathParams` / `SetPathParams` |
| `SCTP_PEER_ADDR_THLDS` | removed — Linux's legacy two-field option; `Conn.PathThresholds` |
| `SCTP_PEER_ADDR_THLDS_V2` | `Conn.PathThresholds` / `SetPathThresholds` |
| `SCTP_PEER_AUTH_CHUNKS` | `Conn.PeerAuthChunks` |
| `SCTP_PF` | `PathPotentiallyFailed` |
| `SCTP_PLPMTUD_PROBE_INTERVAL` | `Conn.PLPMTUDProbeInterval` / `SetPLPMTUDProbeInterval` |
| `SCTP_POTENTIALLY_FAILED` | `PathPotentiallyFailed` |
| `SCTP_PRIMARY_ADDR` | `Conn.PrimaryAddr` / `SetPrimaryAddr` |
| `SCTP_PR_ASSOC_STATUS` | `Conn.PRAssocStatus` |
| `SCTP_PR_SCTP_ALL` | `PRAll` |
| `SCTP_PR_STREAM_STATUS` | `Conn.PRStreamStatus` |
| `SCTP_PR_SUPPORTED` | `Config.PartialReliability`, `Conn.PRSupported` |
| `SCTP_RECONFIG_SUPPORTED` | `Config.StreamReconfiguration`, `Conn.ReconfigSupported` |
| `SCTP_RECVNXTINFO` | `Conn.SetReceiveNxtInfo`, `Config.ReceiveNxtInfo` |
| `SCTP_RECVRCVINFO` | always on; `MsgInfo.Rcv` |
| `SCTP_REMOTE_ERROR` | `EventRemoteError` |
| `SCTP_REMOTE_UDP_ENCAPS_PORT` | `Conn.RemoteUDPEncapsPort` / `SetRemoteUDPEncapsPort` |
| `SCTP_RESET_ASSOC` | `Conn.ResetAssoc` |
| `SCTP_RESET_STREAMS` | `Conn.ResetStreams` |
| `SCTP_RESTART` | `AssocRestart` |
| `SCTP_REUSE_PORT` | `Config.ReusePort` |
| `SCTP_RTOINFO` | `Conn.RTOInfo` / `SetRTOInfo`, `Config.RTOInfo` |
| `SCTP_SACK_IMMEDIATELY` | `SendSACKImmediately` |
| `SCTP_SENDALL` | removed — see "Capabilities with no replacement" |
| `SCTP_SENDER_DRY_EVENT` | `EventSenderDry` |
| `SCTP_SEND_FAILED` | removed — RFC 6458 §6.1.4 deprecated; `EventSendFailed` |
| `SCTP_SEND_FAILED_EVENT` | `EventSendFailed` |
| `SCTP_SET_PEER_PRIMARY_ADDR` | `Conn.RequestPeerPrimary` |
| `SCTP_SHUTDOWN_ACK_SENT` | `StateShutdownAckSent` |
| `SCTP_SHUTDOWN_COMP` | `AssocShutdownComplete` |
| `SCTP_SHUTDOWN_EVENT` | `EventShutdown` |
| `SCTP_SHUTDOWN_PENDING` | `StateShutdownPending` |
| `SCTP_SHUTDOWN_RECEIVED` | `StateShutdownReceived` |
| `SCTP_SHUTDOWN_SENT` | `StateShutdownSent` |
| `SCTP_SN_TYPE_BASE` | removed — only enables the deprecated `SCTP_SNDRCV` data |
| `SCTP_SOCKOPT_BINDX_ADD` | `BindAdd` |
| `SCTP_SOCKOPT_BINDX_REM` | `BindRemove` |
| `SCTP_SOCKOPT_CONNECTX` | removed — pre-2.6.31 fallback; `Dial`, `Endpoint.Connect` |
| `SCTP_SOCKOPT_CONNECTX3` | `Dial`, `Endpoint.Connect` |
| `SCTP_SOCKOPT_PEELOFF` | `Endpoint.PeelOff` |
| `SCTP_SOCKOPT_PEELOFF_FLAGS` | `Endpoint.PeelOff` |
| `SCTP_STATUS` | `Conn.Status` |
| `SCTP_STREAM_CHANGE_DENIED` | `StreamChange.Denied` |
| `SCTP_STREAM_CHANGE_EVENT` | `EventStreamChange` |
| `SCTP_STREAM_CHANGE_FAILED` | `StreamChange.Failed` |
| `SCTP_STREAM_RESET_DENIED` | `StreamReset.Denied` |
| `SCTP_STREAM_RESET_EVENT` | `EventStreamReset` |
| `SCTP_STREAM_RESET_FAILED` | `StreamReset.Failed` |
| `SCTP_STREAM_RESET_INCOMING_SSN` | `StreamReset.Incoming` |
| `SCTP_STREAM_RESET_OUTGOING_SSN` | `StreamReset.Outgoing` |
| `SCTP_STREAM_SCHEDULER` | `Conn.StreamScheduler` / `SetStreamScheduler` |
| `SCTP_STREAM_SCHEDULER_VALUE` | `Conn.StreamSchedulerValue` / `SetStreamSchedulerValue` |
| `SCTP_UNCONFIRMED` | `PathUnconfirmed` |
| `SCTP_UNKNOWN` | `PathUnknown` |
| `SCTP_UNORDERED` | `SendUnordered` |
| `SOL_SCTP` | removed — `syscall.IPPROTO_SCTP` with `SyscallConn` |
| `SPP_DSCP` | `PathParams.DSCP` set |
| `SPP_HB_DEMAND` | `Conn.RequestHeartbeat` |
| `SPP_HB_DISABLE` | `PathParams.Heartbeat` = false |
| `SPP_HB_ENABLE` | `PathParams.Heartbeat` = true |
| `SPP_HB_TIME_IS_ZERO` | `PathParams.HeartbeatInterval` = 0 |
| `SPP_IPV6_FLOWLABEL` | `PathParams.IPv6FlowLabel` set |
| `SPP_PMTUD_DISABLE` | `PathParams.PMTUD` = false |
| `SPP_PMTUD_ENABLE` | `PathParams.PMTUD` = true |
| `SPP_SACKDELAY_DISABLE` | `PathParams.DelayedSACK` = false |
| `SPP_SACKDELAY_ENABLE` | `PathParams.DelayedSACK` = true |
| `SocketOptionDefault` | removed — `nil` |
| `SocketOptionDisable` | removed — `new(false)` |
| `SocketOptionEnable` | removed — `new(true)` |
