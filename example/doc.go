// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Command example is an SCTP echo server and client built on
// github.com/gomaja/go-sctp.
//
// Start the server, then the client, with the same address list:
//
//	example -server -ip 10.10.0.1,10.20.0.1 -port 9899
//	example -ip 10.10.0.1,10.20.0.1 -port 9899
//
// -ip lists the addresses of a multi-homed endpoint: the ones the server
// binds, or the peer addresses the client sets up its association with.
// An empty -ip makes the server listen on every address.
//
// The server echoes every message on the stream and with the payload
// protocol identifier (PPID) it arrived with. The client sends one message
// a second, cycling through the outgoing streams the association
// negotiated, with the stream number as the PPID, reads the echo and
// checks it. -count stops the client after that many messages; without it
// the client runs until interrupted. Both sides log the association and
// path changes the kernel reports.
package main
