// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"encoding/binary"
	"fmt"
	"slices"
	"syscall"
	"testing"
	"time"
)

// TestRestartAnswersFromTheSocketsOwnEndpoint pins how Linux answers the
// INIT that restarts an association (RFC 9260 §5.2.2) on a socket that
// accept(2) or a peel-off created. Such a socket gets an endpoint of its
// own, whose negotiation switches start from the namespace's sysctls and
// whose AUTH lists start from the kernel's defaults, rather than from the
// socket it came from (net/sctp/endpointola.c: sctp_endpoint_new,
// sctp_endpoint_init), and the INIT is answered from that endpoint
// (net/sctp/sm_statefuns.c: sctp_sf_do_unexpected_init). So the handshake
// follows the Config, the restart follows the namespace, and an Endpoint's
// own associations follow its Config throughout.
//
// Each switch is configured opposite to its sysctl, and the AUTH lists
// differ from the defaults, so that the two answers differ. The Listener
// and PeelOff documentation describe this limit; once Linux carries the
// settings over, this test fails and both documents change with it.
func TestRestartAnswersFromTheSocketsOwnEndpoint(t *testing.T) {
	namespace := namespaceOffer(t)
	hmacs, chunks := []HMACID{HMACSHA256, HMACSHA1}, []uint8{0} // DATA
	configured := negotiationOffer{
		PR:     !namespace.PR,
		ECN:    !namespace.ECN,
		Reconf: !namespace.Reconf,
		Auth:   authOffer(hmacs, append(asconfChunks(t), chunks...)),
	}
	if configured.PR == namespace.PR || configured.ECN == namespace.ECN ||
		configured.Reconf == namespace.Reconf || configured.Auth == namespace.Auth {
		t.Fatalf("Config %+v must differ from the namespace %+v in every setting, or the two answers cannot be told apart", configured, namespace)
	}
	cfg := &Config{
		PartialReliability:    new(configured.PR),
		ExperimentalECN:       new(configured.ECN),
		StreamReconfiguration: new(configured.Reconf),
		Authentication:        new(true),
		HMACIdentifiers:       hmacs,
		AuthChunks:            chunks,
	}
	offerAll := &Config{
		PartialReliability:    new(true),
		ExperimentalECN:       new(true),
		StreamReconfiguration: new(true),
		Authentication:        new(true),
	}

	for _, tc := range []struct {
		kind    string
		restart negotiationOffer
	}{
		{"accepted", namespace},
		{"peeled-off", namespace},
		{"endpoint", configured},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			raw := openRawSCTP(t, [4]byte{127, 0, 0, 1})
			var server *Addr
			var client *Conn
			dial := func() {
				t.Helper()
				c, err := offerAll.Dial(testContext(t, 3*time.Second), "sctp4", nil, server)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = c.Abort() })
				client = c
			}
			switch tc.kind {
			case "accepted":
				l := mustListen(t, cfg, "sctp4", loopback4(0))
				server = listenerAddr(t, l)
				dial()
				if err := l.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
					t.Fatal(err)
				}
				a, err := l.AcceptSCTP()
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = a.Abort() })
				if pr, err := a.PRSupported(); err != nil || pr != configured.PR {
					t.Fatalf("accepted PRSupported = %t, %v; want the Config's %t", pr, err, configured.PR)
				}
			default:
				e, err := cfg.ListenEndpoint("sctp4", loopback4(0))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = e.Abort() })
				server = endpointAddr(t, e)
				dial()
				id := awaitCommUp(t, e).AssocID
				if tc.kind == "peeled-off" {
					c, err := e.PeelOff(id)
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = c.Abort() })
				}
			}
			clientPort := client.LocalAddr().(*Addr).Port

			first := initAckOffer(awaitChunkBetween(t, raw, server.Port, clientPort, nil, 2))
			if first != configured {
				t.Fatalf("handshake INIT ACK accepts %+v; want the Config's %+v", first, configured)
			}

			// An INIT from the client's address and port with a new initiate
			// tag is answered as the start of a restart (RFC 9260 §5.2.2).
			// Without the COOKIE ECHO that completes one (§5.2.4), neither
			// side changes.
			const tag = 0x5A5A0002
			packet := sctpPacket(clientPort, server.Port, 0, restartInit(tag))
			if err := syscall.Sendto(raw, packet, 0, &syscall.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
				t.Fatal(err)
			}
			want := uint32(tag)
			restart := initAckOffer(awaitChunkBetween(t, raw, server.Port, clientPort, &want, 2))
			if restart == tc.restart {
				return
			}
			if tc.restart == namespace && restart == configured {
				t.Fatalf("the restart INIT ACK now follows the Config (%+v), not the namespace (%+v): "+
					"Linux carries the settings into this socket, so the Listener and PeelOff documentation and this test need updating",
					configured, namespace)
			}
			t.Fatalf("restart INIT ACK accepts %+v; want %+v (Config %+v, namespace %+v)", restart, tc.restart, configured, namespace)
		})
	}
}

// negotiationOffer is what an INIT ACK accepts of the extensions restartInit
// offers: a parameter that appears in its own right, rather than reported
// back inside an Unrecognized Parameter, or a chunk type its Supported
// Extensions parameter lists.
type negotiationOffer struct {
	PR     bool   // Forward-TSN-Supported (0xC000), RFC 3758 §3.1
	ECN    bool   // ECN Capable (0x8000), reserved by RFC 9260 (§§1.7, 3.3.2); Linux still negotiates it
	Reconf bool   // RE-CONFIG (130, RFC 6525 §3.1) in Supported Extensions (RFC 5061 §4.2.7)
	Auth   string // the HMAC-ALGO and Chunk List parameters (RFC 4895 §§3.2-3.3), as authOffer; "" without them
}

// namespaceOffer is what an endpoint created in this network namespace
// accepts: its switches start from these sysctls, and its AUTH lists from
// the kernel's defaults, HMAC-SHA-1 alone and asconfChunks
// (net/sctp/endpointola.c: sctp_endpoint_init; net/sctp/auth.c:
// sctp_auth_init).
func namespaceOffer(t *testing.T) negotiationOffer {
	t.Helper()
	o := negotiationOffer{
		PR:     readSysctl(t, "prsctp_enable") != "0",
		ECN:    readSysctl(t, "ecn_enable") != "0",
		Reconf: readSysctl(t, "reconf_enable") != "0",
	}
	if readSysctl(t, "auth_enable") != "0" {
		o.Auth = authOffer([]HMACID{HMACSHA1}, asconfChunks(t))
	}
	return o
}

// asconfChunks is what Linux puts on an endpoint's Chunk List of its own
// accord: ASCONF and ASCONF-ACK, once AUTH is on, when ASCONF starts on
// (net.sctp.addip_enable). It does so for a socket that turns AUTH on too,
// before any chunk type the socket adds (net/sctp/socket.c:
// sctp_setsockopt_auth_supported).
func asconfChunks(t *testing.T) []uint8 {
	t.Helper()
	if readSysctl(t, "addip_enable") != "0" {
		return []uint8{0xc1, 0x80}
	}
	return nil
}

// authOffer describes AUTH lists for comparison: HMAC identifiers in order of
// preference, and the chunk types to authenticate.
func authOffer(hmacs []HMACID, chunks []uint8) string {
	return fmt.Sprintf("HMAC-ALGO %v, Chunk List %v", hmacs, chunks)
}

// initAckOffer reads which of the extensions restartInit offers an INIT ACK
// chunk accepts.
func initAckOffer(chunk []byte) negotiationOffer {
	var o negotiationOffer
	var hmacs []HMACID
	var chunks []uint8
	auth := false
	end := min(int(binary.BigEndian.Uint16(chunk[2:])), len(chunk))
	for off := 20; off+4 <= end; {
		kind, length := binary.BigEndian.Uint16(chunk[off:]), int(binary.BigEndian.Uint16(chunk[off+2:]))
		if length < 4 || off+length > end {
			break
		}
		switch kind {
		case 0xc000:
			o.PR = true
		case 0x8000:
			o.ECN = true
		case 0x8008:
			o.Reconf = slices.Contains(chunk[off+4:off+length], 130)
		case 0x8004: // HMAC-ALGO
			auth = true
			for i := off + 4; i+2 <= off+length; i += 2 {
				hmacs = append(hmacs, HMACID(binary.BigEndian.Uint16(chunk[i:])))
			}
		case 0x8003: // Chunk List
			auth = true
			chunks = append(chunks, chunk[off+4:off+length]...)
		}
		off += (length + 3) &^ 3
	}
	if auth {
		o.Auth = authOffer(hmacs, chunks)
	}
	return o
}

// restartInit is an INIT chunk with initiate tag tag that offers every
// extension negotiationOffer covers.
func restartInit(tag uint32) []byte {
	init := binary.BigEndian.AppendUint32([]byte{1, 0, 0, 0}, tag)
	init = binary.BigEndian.AppendUint32(init, 1<<20)      // a_rwnd
	init = append(init, 0, 10, 0, 10)                      // streams, out and in
	init = binary.BigEndian.AppendUint32(init, 1)          // initial TSN
	init = append(init, 0xc0, 0x00, 0, 4)                  // Forward-TSN-Supported
	init = append(init, 0x80, 0x00, 0, 4)                  // ECN Capable
	init = append(init, 0x80, 0x08, 0, 6, 130, 0x0f, 0, 0) // Supported Extensions: RE-CONFIG, AUTH
	init = append(init, 0x80, 0x02, 0, 36)                 // Random, RFC 4895 §3.1
	init = append(init, make([]byte, 32)...)
	init = append(init, 0x80, 0x04, 0, 6, 0, 1, 0, 0) // HMAC-ALGO: SHA-1, RFC 4895 §3.3
	init = append(init, 0x80, 0x03, 0, 4)             // Chunk List: none, RFC 4895 §3.2
	binary.BigEndian.PutUint16(init[2:], uint16(len(init)))
	return init
}
