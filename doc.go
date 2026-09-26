// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package sctp provides SCTP sockets on Linux: a Go binding for the kernel's
// implementation of the Stream Control Transmission Protocol (RFC 9260)
// and of its sockets API (RFC 6458).
//
// The package does not implement SCTP. The kernel owns the protocol: the
// association state machine, chunks, retransmission, congestion control,
// path management and checksums. The package owns the Go API around it:
// descriptors and the runtime poller, message framing, ancillary data,
// socket options, notifications, addresses and errors.
//
// # Sockets
//
// A one-to-one socket carries one association (RFC 6458 §4). [Dial] sets
// one up and returns a [*Conn]. [Listen] returns a [*Listener], whose
// Accept and AcceptSCTP return a [*Conn] for each association a peer sets
// up. *Conn implements [net.Conn] and *Listener implements [net.Listener],
// with one difference from TCP: SCTP carries messages, not a byte stream,
// and each Write is one message.
//
// A one-to-many socket carries many associations (RFC 6458 §3).
// [ListenEndpoint] and [OpenEndpoint] return an [*Endpoint], whose methods
// take the association they act on as an [AssocID]. Associations start with
// [Endpoint.Connect] or at a peer's request, and the Endpoint reports each
// one's start and end with an [AssocChange] notification.
// [Endpoint.PeelOff] moves one association onto a *Conn of its own (RFC
// 6458 §9.2). Linux moves the association before it allocates the new
// descriptor, and loses the association when no descriptor can be
// allocated; PeelOff checks the process's limit first, but neither a
// descriptor another goroutine takes meanwhile nor the system-wide limit
// can be ruled out.
//
// Everything that has to be decided before an association exists is a
// field of [Config]: the streams and extensions offered in the INIT,
// socket buffers, socket defaults and notification subscriptions. Its
// methods [Config.Dial], [Config.Listen], [Config.ListenEndpoint],
// [Config.OpenEndpoint], [Config.FileConn] and [Config.FileListener] are
// the constructors, and the package-level functions of the same names use a
// zero Config. A Config is checked before any socket is created. Optional
// settings are pointers, and nil leaves the kernel's default:
//
//	cfg := &sctp.Config{
//		InitMsg:       sctp.InitMsg{OutStreams: 16, MaxInStreams: 16},
//		NoDelay:       new(true),
//		Notifications: []sctp.EventType{sctp.EventAssocChange},
//	}
//	conn, err := cfg.Dial(ctx, "sctp", nil, raddr)
//
// [FileConn] and [FileListener] adopt a descriptor inherited from another
// process.
//
// An [*Addr] is one port and one or more IP addresses ([netip.Addr]), for a
// multi-homed endpoint, and [ResolveAddr] parses "host1/host2:port". One
// path of an association is named by the peer's IP address alone. IPv4
// addresses are always reported in plain form, never IPv4-mapped, whatever
// the socket's family.
//
// # Reading
//
// [Conn.RecvMsg] reads with one recvmsg(2), and returns in a [MsgInfo] what
// the kernel reports about the bytes: whether they end a message (EOR),
// whether they are a notification, and the message's [RcvInfo], its stream,
// payload protocol identifier (PPID) and TSN among them. A message longer
// than the buffer arrives over several reads. [Conn.ReadMsg] reassembles
// one whole message, up to a size limit, and [Conn.Read] returns message
// bytes without framing, as a net.Conn does. A read of data makes no
// allocation.
//
// Notifications (RFC 6458 §6) share the receive queue with data. The caller
// chooses the kinds it receives with [Config.Notifications] and
// [Conn.Subscribe]. With a [NotificationHandler] in the Config, reads hand
// each notification to the handler, reassembled and parsed into one of the
// types that implement [Notification], and go on reading. Without one,
// RecvMsg returns a notification's bytes with MsgInfo.Notification set, for
// [ParseNotification], and Read and ReadMsg skip it. The package itself
// keeps [EventAssocChange] subscribed in the kernel on every socket (see
// "The end of an association" below), and delivers those records to a Conn's
// caller only when the caller subscribed to them; an Endpoint always
// delivers them.
//
// # Writing
//
// [Conn.SendMsg] sends one message with the per-message parameters of
// [SendOptions]: the stream, flags, PPID and context in a [SndInfo], a
// PR-SCTP policy in a [PrInfo], an AUTH key, the peer address to send to
// (Path), and two ways of sending (More and NoWait). A nil Info or PR means
// the socket's default, set with [Config.DefaultSndInfo] and
// [Config.DefaultPrInfo] or the Conn's setters, in every combination and on
// an Endpoint too: where Linux would not apply a default itself, the package
// sends it. [Conn.Write] is SendMsg with no options.
//
// A send waits for send-buffer space in the runtime poller, until the write
// deadline passes or the socket is closed. With NoWait it makes one attempt
// instead, and a refusal queues nothing of the message. More tells the
// kernel that more messages follow at once, so that it may bundle them
// (MSG_MORE). A successful SendMsg makes no allocation and keeps nothing of
// its arguments.
//
// # Concurrency
//
// Every method may be called from several goroutines at once, as net.Conn
// requires. The sends on one socket are serialized by a send lock, which a
// send waiting for buffer space holds, so a NoWait send issued meanwhile
// waits behind it. The reads are serialized by a receive lock, which is
// released before a NotificationHandler runs, so that a handler may call
// back into the connection; ReadMsg holds it from the first piece of a
// message to the last. A deadline, Close and Abort release the calls
// waiting on the socket. Readiness and deadlines on an Endpoint are the
// endpoint's, whichever association a call is for.
//
// # Errors
//
// The errors of the constructors and of the methods of Conn, Listener and
// Endpoint are *net.OpError values whose Op names the call: "dial" for Dial
// and Endpoint.Connect, "listen" for Listen, ListenEndpoint and
// OpenEndpoint, "accept", "file" for FileConn and FileListener, "read",
// "write", "close" for Close, CloseWithTimeout, Abort, Shutdown and the
// Endpoint's CloseAssoc and AbortAssoc, "get" and "set" for options,
// "bindx" for BindAdd and BindRemove, and "peeloff". ResolveAddr,
// ParseNotification, InstallAuthKey and ActivateAuthKey return their causes
// as they are. Test a cause with errors.Is:
//
//   - io.EOF is returned unwrapped, so that err == io.EOF works: the
//     association ended gracefully, and every message has been read.
//   - An argument the package refuses, a Config field, a SendOptions field
//     or a method argument, matches syscall.EINVAL, and the message names
//     it. Nothing reaches the kernel then.
//   - A passed deadline matches os.ErrDeadlineExceeded, and a closed socket
//     net.ErrClosed.
//   - An option call wraps an *os.SyscallError that names getsockopt or
//     setsockopt and holds the kernel's errno, so that
//     errors.Is(err, syscall.ENOPROTOOPT) detects an option the running
//     kernel does not have.
//   - A NoWait send that finds no space matches syscall.EAGAIN, and a
//     message larger than the send buffer syscall.EMSGSIZE.
//   - [ErrUnsupported], and so errors.ErrUnsupported, reports a platform
//     without SCTP: any GOOS but Linux, and Linux whose SCTP module is
//     absent, where the error also matches the kernel's errno.
//
// The Timeout method of net.Error reports true for a passed deadline, and
// also for syscall.EAGAIN and syscall.ETIMEDOUT, as syscall.Errno's own
// Timeout does: a NoWait refusal, and an association whose retransmissions
// ran out, look like timeouts to it. Test for a deadline with
// errors.Is(err, os.ErrDeadlineExceeded) instead.
//
// # The end of an association
//
// After a graceful end, started by either side, reads return the messages
// still queued and then io.EOF, on every kind of Conn. Sends fail with an
// error matching syscall.ESHUTDOWN while the shutdown is in progress, and
// with syscall.EPIPE once the association is gone.
//
// After an association fails, reads first return what the peer sent before
// the failure, and then every read and every send returns the error Linux
// reported for it: syscall.ECONNRESET after the peer's ABORT,
// syscall.ETIMEDOUT when retransmissions ran out, and syscall.ECONNABORTED
// when this side aborted it. Linux reports that error to one call only,
// after which a non-blocking socket never becomes readable again; the
// package's own EventAssocChange subscription wakes a waiting reader, and
// the package keeps the error for every later call. Where Linux's error is
// out of the package's reach, taken through SyscallConn or left on the
// listening socket by an association that failed before Accept, reads
// return an error matching syscall.ENOTCONN instead. An Endpoint has neither
// an end of stream nor a lasting error: each association's end is its
// AssocChange notification.
//
// [Conn.Close] shuts the association down gracefully, waits for the
// SHUTDOWN handshake for up to [Config.CloseTimeout], 3 s by default, and
// aborts the association if the peer has not completed it by then.
// [Conn.Abort] sends an ABORT at once, and makes a Close that is still
// waiting send it too.
//
// # Receive window and buffers
//
// The receive window belongs to the kernel. Linux sets an association's
// window from the socket's receive buffer when the association is created,
// and announces it in the INIT or INIT ACK, so the buffer is sized with
// [Config.ReadBuffer], before the association exists. A later
// [Conn.SetReadBuffer] only moves the point at which a full buffer closes
// the window; it never makes the window larger. Linux caps a buffer size at
// net.core.rmem_max or net.core.wmem_max and doubles it for its own
// bookkeeping, and ReadBuffer and WriteBuffer report the doubled size.
//
// The package does not pace a sender. A producer that bursts faster than
// its peer reads fills the peer's window, and SCTP then lets the sender
// send no new DATA beyond zero-window probes (RFC 9260 §6.1); a receiver
// whose buffer is full drops new DATA, and the sender's loss recovery
// retransmits it (RFC 9260 §6.2). Size the receiver's buffer for the bursts
// the application produces, or pace the producer.
//
// # Platforms
//
// Sockets work on Linux, on every architecture Go supports and on Android;
// on linux/386 the socket calls go through socketcall(2). The package never
// checks a kernel version. Each facility needs the upstream release that
// introduced it, or a vendor kernel that carries it: 5.0 for any socket,
// since every socket carries the package's own EventAssocChange
// subscription, set with SCTP_EVENT, and up to 6.4 for the FC and WFQ stream
// schedulers. On a kernel without a facility, the calls that need it return
// the kernel's own error. The package's README.md lists the release for
// every facility.
//
// On every other platform but plan9 the package compiles, ResolveAddr and
// ParseNotification work, and the constructors return a *net.OpError that
// wraps ErrUnsupported.
//
// # Standards
//
// The package follows RFC 9260, with its Verified Errata 7147, 7148, 7387,
// 7852 and 8402, and RFC 6458, with its Verified Errata 6111, 6112, 6115,
// 6980, 7547 and 7548; and the extensions Linux implements: RFC 3758
// (partial reliability), RFC 4895 (authenticated chunks), RFC 5061 (dynamic
// address reconfiguration), RFC 6525 (stream reconfiguration), RFC 6951
// (UDP encapsulation, updated by RFC 8899), RFC 7496 (additional PR-SCTP
// policies), RFC 7829 (the Potentially Failed path state), RFC 8260 (message
// interleaving and stream schedulers) and RFC 8899 (packetization layer
// path MTU discovery). The documentation of each call names the section it
// implements, and where Linux departs from the RFC. STANDARDS.md records the
// status of every document and its errata, and how they were checked.
package sctp
