<!-- Copyright 2026 gomaja. All rights reserved. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- This file includes modifications by gomaja. -->

# SCTP standards and conformance baseline

This document records which standards the package follows, their status,
their errata and how each erratum is treated, where Linux departs from them,
and how all of this was checked. It is a record of one check, not a
substitute for checking again: RFCs are obsoleted and errata filed long after
code is written. The procedure at the end says how, and when.

## Verification record

Checked on **2026-09-26** (16:09 to 16:35 UTC). For every RFC named in this
document, 46 in all, the four records below were fetched and compared:

- the RFC Editor record,
  `https://www.rfc-editor.org/rfc/rfcNNNN.json`: `status`, `obsoletes`,
  `obsoleted_by`, `updates` and `updated_by`;
- the IETF Datatracker's incoming relationships,
  `https://datatracker.ietf.org/api/v1/doc/relateddocument/?target__name=rfcNNNN&relationship__slug__in=obs,updates&format=json`,
  filtered on the server to obsoleting and updating documents (an
  unfiltered query returns every citation and stops at its page limit, so
  for a much-cited RFC the relationships can fall off the page and read as
  none);
- the Datatracker document record,
  `https://datatracker.ietf.org/api/v1/doc/document/rfcNNNN/?format=json`,
  for the maturity level (`std_level`);
- the errata list,
  `https://errata.rfc-editor.org/search/?rfc_number=NNNN&presentation=records`,
  one record per erratum with its status and type. (The older
  `https://www.rfc-editor.org/errata/rfcNNNN`, which the RFC Editor JSON
  gives as `errata_url`, answers with an empty redirect, which a client
  that does not follow redirects reads as no errata.)

The RFC Editor and the Datatracker agreed on every status and every
obsoleting or updating relationship, for all 46 RFCs. The baseline's
statuses and errata are unchanged since the previous check recorded here
(2026-08-01, and 2026-08-26 for RFC 9260 and 6458). Outside the baseline,
RFC 9907 has a new erratum, 9134, still Reported, which does not concern
SCTP. One earlier finding no longer holds: the Datatracker's relationship
API used to omit RFC 9907's update of RFC 8126, and now reports it, in
agreement with the RFC Editor.

The Internet-Drafts below were checked the same day in the Datatracker
(`https://datatracker.ietf.org/api/v1/doc/document/<draft>/?format=json`,
and the relationship API with `source__name=<draft>`), on the
[TSVWG documents page](https://datatracker.ietf.org/wg/tsvwg/documents/),
and in the [RFC Editor queue](https://queue.rfc-editor.org/api/v1/queue/index.json),
whose snapshot of 2026-09-26T11:39:07Z held 147 documents, none about SCTP.
The [IANA SCTP Parameters registry](https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xml)
was read the same day.

## Conformance boundary

The package is a Go binding to the SCTP implementation in the Linux kernel.
The kernel owns the protocol and the bytes on the wire:

- association setup, restart, shutdown and verification tags;
- chunk parsing and generation;
- retransmission, congestion control, path management and PMTU discovery;
- delayed acknowledgement and SACK generation; and
- CRC32c computation and validation.

The package owns the socket API: option and ancillary-data encoding,
structure layouts, notification parsing, addresses, error reporting and the
Go API. It can therefore claim that it drives a kernel facility faithfully,
and the wire harness (`testdata/wire`) proves from packet captures what a
given kernel does; it cannot claim to implement an RFC 9260 algorithm, or
make a kernel that departs from one conform. A conformance statement names
all three layers: the RFC requirement with its errata, the kernel and its
configuration, and the package call that requests or observes the
behaviour.

## Baseline

| Document | Role and status | Relationships | Errata |
|---|---|---|---|
| [RFC 9260](https://www.rfc-editor.org/rfc/rfc9260.html) | SCTP, the base protocol. Proposed Standard | Obsoletes RFC 4460, 4960, 6096, 7053 and 8540. Neither obsoleted nor updated | 5 Verified, 1 Held, 3 Rejected (below) |
| [RFC 6458](https://www.rfc-editor.org/rfc/rfc6458.html) | The sockets API. Informational | Neither obsoleted nor updated. Later RFCs add socket API sections without formally updating it | 6 Verified, 4 Held, 4 Rejected (below) |
| [RFC 3758](https://www.rfc-editor.org/rfc/rfc3758.html) | Partial reliability (PR-SCTP). Proposed Standard | None | None |
| [RFC 4895](https://www.rfc-editor.org/rfc/rfc4895.html) | Authenticated chunks (AUTH). Proposed Standard | None | 1 Held (below) |
| [RFC 5061](https://www.rfc-editor.org/rfc/rfc5061.html) | Dynamic address reconfiguration (ASCONF). Proposed Standard | None | None |
| [RFC 6525](https://www.rfc-editor.org/rfc/rfc6525.html) | Stream reconfiguration. Proposed Standard | None | None |
| [RFC 6951](https://www.rfc-editor.org/rfc/rfc6951.html) | UDP encapsulation. Proposed Standard | Updated by RFC 8899 | None |
| [RFC 7496](https://www.rfc-editor.org/rfc/rfc7496.html) | Additional PR-SCTP policies. Proposed Standard | None | None |
| [RFC 7829](https://www.rfc-editor.org/rfc/rfc7829.html) | The Potentially Failed path state. Proposed Standard | None | None |
| [RFC 8260](https://www.rfc-editor.org/rfc/rfc8260.html) | Message interleaving (I-DATA) and stream schedulers. Proposed Standard | None | None |
| [RFC 8899](https://www.rfc-editor.org/rfc/rfc8899.html) | Datagram packetization layer PMTU discovery. Proposed Standard | Updates RFC 4821, 4960, 6951, 8085 and 8261; RFC 9260 §7.3 applies it to the current base. Neither obsoleted nor updated | None |

"None" in the last two columns means the RFC Editor and the Datatracker
both report no obsoleting or updating document, and the errata search
reports "No matching errata found".

## Errata and how each is treated

A Verified erratum is part of the document: technical ones change what is
followed, editorial ones how it reads. A Held for Document Update erratum
is not a correction; it is listed, and followed only where this says so. A
Rejected erratum is never followed. A Reported erratum would be reported to
the maintainer before any action; there is none in the baseline.

### RFC 9260

- **Verified 7148** (technical, §3.3.3): an INIT ACK whose a_rwnd is below
  1500 is handled by state; in COOKIE-WAIT the endpoint destroys the TCB and
  should send an ABORT. Kernel behaviour. `Config.ReadBuffer`'s
  documentation cites it for why Linux never announces a window below 1500
  bytes.
- **Verified 7387** (technical, §5.2.4.1): the restart diagram uses
  T1-cookie for COOKIE ECHO. Kernel behaviour.
- **Verified 8402** (technical, §5.1.6): INIT is retransmitted on T1-init
  and COOKIE ECHO on T1-cookie. Kernel behaviour.
- **Verified 7147** (editorial, §3.2) and **7852** (editorial, §8.5: the
  verification tag is checked before any chunk is processed). Kernel
  behaviour.
- **Held 8772** (editorial, §3.3.4): an explicit SACK chunk length
  description. Touches nothing in the package; not followed.
- **Rejected 7988, 8387, 8774**: not followed.

### RFC 6458

- **Verified 6111** (technical, §§5.3.2, 5.3.4, 8.1.13, 8.1.31): adds
  `SCTP_EOR` for explicit end-of-record marking. Linux defines neither
  `SCTP_EOR` nor `SCTP_EXPLICIT_EOR`, so every send is one whole message;
  `SndInfo`'s documentation says so.
- **Verified 6115** (technical, §8.2.1): removes `SCTP_BOUND` from the
  association states. `AssocState` follows Linux's enumeration, which has no
  such state and otherwise differs from the RFC's too.
- **Verified 6112** (editorial, §3.2): `SCTP_CANT_START_ASSOC` is
  `SCTP_CANT_STR_ASSOC`, the name Linux uses; the package calls it
  `AssocCantStart`.
- **Verified 6980** (editorial, §8): `SCTP_MAX_SEG` is `SCTP_MAXSEG`
  (`MaxSeg`, `SetMaxSeg`).
- **Verified 7547 and 7548** (editorial, §§9.12 and 9.1): `info_type` is
  `infotype` in the `sctp_sendv` and `sctp_recvv` text. `SendOptions` and
  `MsgInfo` follow those two functions' structures; nothing depends on the
  name.
- **Held 4921** (technical, §9.1): IPv4 addresses on IPv6 sockets in
  IPv4-mapped form. Followed by choice: the package passes IPv4 addresses
  IPv4-mapped on an `AF_INET6` socket, which Linux accepts in either form,
  and reports every IPv4 address in plain form.
- **Held 6114** (editorial, §9.5): writes the association id 0 of
  `sctp_getladdrs` as `SCTP_FUTURE_ASSOC`. It describes what Linux does, and
  `Endpoint.LocalAddrs` cites it for refusing that id.
- **Held 6116** (technical, §6.1.2): adds `SCTP_ADDR_CONFIRMED`. Linux
  reports it, and `AddrChangeState`'s documentation cites the erratum for
  `AddrConfirmed`.
- **Held 6113** (editorial, §6.1.1): `sac_info` would also carry the ABORT
  for `SCTP_CANT_STR_ASSOC`. Linux does not do that, and
  `AssocChange.Info`'s documentation says so.
- **Rejected 6081, 6131, 6132, 6133**: alternative proposals around explicit
  end-of-record marking; not followed.

### Other documents

- **RFC 4895 Held 995** (editorial, §11): removes an unused MD5 reference.
  Touches nothing; not followed.
- RFC 3758, 5061, 6525, 6951, 7496, 7829, 8260 and 8899 have no errata.

## Obsolete documents, for history only

These may be cited only as history; the current text is RFC 9260's.

| Document | Status |
|---|---|
| RFC 2960 | Obsoleted by RFC 4960; it had been updated by RFC 3309 (CRC32c). Rejected Erratum 3317 |
| RFC 3309 | Obsoleted by RFC 4960 |
| RFC 4960 | Obsoleted by RFC 9260; it had been updated by RFC 6096, 6335, 7053 and 8899 |
| RFC 4460, RFC 8540 | Informational errata and issues documents, obsoleted by RFC 9260 |
| RFC 6096, RFC 7053 | Obsoleted by RFC 9260, which incorporates the chunk flags registry and the I bit |
| RFC 8312 | CUBIC, obsoleted by RFC 9438 |

Code, tests and documentation cite RFC 9260 for current behaviour: the I
bit is RFC 9260 §§3.3.1, 6.1, 6.2 and 11.1.5, not RFC 7053, and the CRC32c
requirements are RFC 9260 §§3.1 and 6.8 and Appendix A, not RFC 3309. The
Linux sources still cite RFC 2960 and 4960 in comments; those describe the
kernel's history, not current requirements. RFC 8899 remains in force
through RFC 9260 §7.3.

## Related documents outside the baseline

Checked like the baseline, and relevant to it, but not implemented by the
package:

| Document | Status and relationships | Why it is outside the baseline |
|---|---|---|
| [RFC 9653](https://www.rfc-editor.org/rfc/rfc9653.html) | Zero checksum. Proposed Standard; none; no errata | Its socket option, `SCTP_ACCEPT_ZERO_CHECKSUM` (§7.1), is not in the Linux UAPI, and the package does not invent a number for it |
| [RFC 7765](https://www.rfc-editor.org/rfc/rfc7765.html) | RTO restart. Experimental; none; no errata | Its `SCTP_RTO_RESTART` option (§7.2) has no Linux number |
| [RFC 4820](https://www.rfc-editor.org/rfc/rfc4820.html) | The PAD chunk. Proposed Standard; none; Rejected Erratum 897 | Used by the kernel's PLPMTUD (RFC 8899); no socket API |
| [RFC 9438](https://www.rfc-editor.org/rfc/rfc9438.html) | CUBIC. Proposed Standard; obsoletes RFC 8312; Rejected Erratum 7806 | It does not update RFC 9260, and Linux SCTP has no way to select a congestion controller (below) |
| [RFC 6083](https://www.rfc-editor.org/rfc/rfc6083.html) | DTLS over SCTP. Proposed Standard; updated by RFC 8996; Held Erratum 5744, Rejected Erratum 6323 | A protocol above SCTP; an active draft would obsolete it (below) |
| [RFC 8261](https://www.rfc-editor.org/rfc/rfc8261.html) | SCTP over DTLS. Proposed Standard; updated by RFC 8899 and 8996; no errata | An encapsulation used by user-space SCTP, as in WebRTC, not kernel SCTP over IP |
| [RFC 3436](https://www.rfc-editor.org/rfc/rfc3436.html) | TLS over SCTP. Proposed Standard; updated by RFC 8996; no errata | A protocol above SCTP |
| [RFC 8996](https://www.rfc-editor.org/rfc/rfc8996.html) | Deprecating TLS 1.0 and 1.1. Best Current Practice; Verified Errata 7103 and 7796 (editorial), Held Erratum 7769 | Updates the TLS and DTLS profiles above |
| RFC 3257, 3286 | SCTP applicability statement and introduction. Informational; none; no errata | Deployment guidance |
| RFC 3554, 3873 | IPsec with SCTP, and the SCTP MIB. Proposed Standard; none; no errata | Owned by the IPsec stack and by SNMP |
| RFC 5043 | DDP over SCTP. Proposed Standard; updated by RFC 6581 and 7146; no errata | An application protocol; the package carries its adaptation code and PPIDs as opaque values |
| RFC 5062 | Security attacks on SCTP. Informational; none; no errata | Kernel and deployment context |
| RFC 3708, 5827 | Experimental; none; no errata | Sender-side algorithms the kernel owns |
| RFC 4138 | F-RTO. Experimental; updated by RFC 5682; no errata | RFC 5682 §1 leaves its SCTP procedure Experimental |
| RFC 5682 | Proposed Standard; none; no errata | See RFC 4138 |
| RFC 6056, 6335, 7605 | Transport port guidance. Best Current Practice; none. RFC 6056: Verified 2750, 7873 (editorial), Rejected 3739. RFC 6335: Verified 3814, Held 4999. RFC 7605: Verified 4437, Held 5592 | Port selection and registry policy, which the package does not implement |
| RFC 8126 | IANA considerations. Best Current Practice; updated by RFC 9907; Held Erratum 5772, Rejected Erratum 6522 | The IANA registry rules; RFC 9907 changes them for YANG modules only (its Verified Errata 8872 and 8880 are editorial; Erratum 9134 is Reported) |

## Where Linux differs from the documents

The package follows Linux where the two differ, and says so rather than
claiming the RFC's behaviour:

- **Explicit end of record.** Linux implements neither Verified Erratum
  6111's `SCTP_EOR` nor `SCTP_EXPLICIT_EOR`.
- **Notifications stopped.** RFC 6458 §6.1.10's
  `SCTP_NOTIFICATIONS_STOPPED_EVENT` is not in Linux's `enum sctp_sn_type`,
  which goes from `SCTP_SENDER_DRY_EVENT` straight to
  `SCTP_STREAM_RESET_EVENT`. No `EventType` is guessed for it; a type the
  package does not know arrives as `UnknownNotification`.
- **Association states.** Linux's `enum sctp_sstat_state`, which
  `AssocState` follows, differs from RFC 6458 §8.2.1's list, including the
  correction of Verified Erratum 6115.
- **Partial delivery.** Linux's `struct sctp_pdapi_event` orders its fields
  differently from RFC 6458 §6.1.7, and fills in the stream and sequence
  number only under I-DATA; `PartialDelivery` follows the kernel.
- **Default PR-SCTP policy.** Linux's `struct sctp_default_prinfo` is
  association id, value, policy; RFC 6458 §8.1.32 lists policy, value,
  association id. The package encodes Linux's layout.
- **Path parameters.** Linux's `struct sctp_paddrparams` adds
  `spp_sackdelay` and the `SPP_SACKDELAY_*` flags to RFC 6458 §8.1.12's
  structure; `PathParams.DelayedSACK` and `SACKDelay` expose them as the
  Linux extension they are.
- **Fragment interleave.** RFC 6458 §8.1.20 defines three levels. Linux
  keeps the option as a boolean (`sctp_setsockopt_fragment_interleave`
  stores `!!val`), so level 2 would read back as level 1. The package
  refuses `InterleaveStreams`, in `Config.FragmentInterleave` and in
  `SetFragmentInterleave`, with an error matching `ErrUnsupported`, before
  any system call. RFC 8260's I-DATA (`Config.MessageInterleaving`) is a
  separate facility and does not provide level 2 either. An `Endpoint`
  defaults to level 1 (`InterleaveAssocs`), as §8.1.20 recommends for
  one-to-many sockets.
- **Path thresholds.** RFC 7829 §7.2 specifies one three-threshold
  structure. Linux keeps a legacy two-threshold option and exposes the
  complete one as `SCTP_PEER_ADDR_THLDS_V2`, which `PathThresholds` uses.
- **UDP encapsulation.** RFC 6951 §6.1 says a wildcard address changes only
  future paths; Linux also changes every current one, and
  `SetRemoteUDPEncapsPort`'s documentation says so. The port is in host byte
  order in the API and network byte order in the option, as §6.1 specifies.
- **PLPMTUD.** `SCTP_PLPMTUD_PROBE_INTERVAL` is a Linux option for RFC
  8899's procedure, which defines no socket interface.
- **Stream change.** RFC 6525 §6.1.3 describes the stream counts as the new
  totals; Linux reports the streams added, and `StreamChange` says so.
- **Fair-capacity scheduler.** RFC 8260 names it `SCTP_SS_FC` in §3.5 and
  `SCTP_SS_FB` in §4.3.2, with no erratum. Linux uses `SCTP_SS_FC`, and the
  package follows it (`SchedFC`).
- **ECN.** Linux has `SCTP_ECN_SUPPORTED`, but RFC 9260 §1.7 records that
  the ECN appendix was removed, and no current RFC specifies SCTP ECN.
  `Config.ExperimentalECN` is named for what it is.
- **Delayed SACK.** RFC 9260 §6.2 recommends a SACK for at least every
  second packet and within 200 ms, and forbids a configured delay above
  500 ms. `Config.DelayedSACK`, `SetDelayedSACK` and `SetPathParams` refuse
  more than 500 ms; a setting above 200 ms, or a frequency above 2, is a
  documented departure from the recommendation, and the kernel's timing is
  its own.
- **Zero checksum and RTO restart.** RFC 9653's and RFC 7765's socket
  options have no Linux number, and the package offers neither.
- **Congestion control.** Linux SCTP has a fixed Reno-style controller and no
  socket option or sysctl to select another; its CUBIC is TCP's only. RFC
  9438 says CUBIC can be used by SCTP, but does not update RFC 9260, whose
  §7.2.2 still bounds cwnd growth per RTT.
- **Timers in ticks.** RFC 6458 §8.2.2 gives `spinfo_srtt` in
  milliseconds; Linux reports it, and `sas_maxrto`, in kernel ticks, so the
  package names them `PathInfo.SRTTTicks` and `AssocStats.MaxRTOTicks`.

## Package conventions over the ABI

These are the package's choices, not RFC text:

- **PPID byte order.** RFC 6458 §§5.3.4-5.3.6 label the PPID fields
  network byte order and say the stack does not convert them. Every PPID in
  the API is in host byte order, and the package converts at the kernel
  boundary, on sends, receives, defaults and notifications alike.
- **Endpoint invariants.** RFC 6458 §3.1.3 recommends enabling
  `SCTP_ASSOC_CHANGE` on one-to-many sockets. An `Endpoint` always enables
  it, and `SCTP_RECVRCVINFO`, which `RecvMsg` needs to name each message's
  association; neither can be switched off through the API.
- **The association's end on every Conn.** Every one-to-one and peeled-off
  socket keeps `SCTP_ASSOC_CHANGE` subscribed for the package's own use,
  delivering the records only to a caller who subscribed to them, so that
  the end of an association reaches its readers (the package documentation,
  "The end of an association").
- **Settings before the INIT.** RFC 6458 §8.3.2 says an `SCTP_AUTH_CHUNK`
  change affects future associations only, and RFC 4895 §6.1 carries the
  list in the INIT; the same holds for the extensions negotiated there. Such
  settings are `Config` fields only, never setters on an established
  connection.

## IANA registry

The [SCTP Parameters registry](https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml),
last updated 2026-08-13 when read, agrees with the values the package uses.

- `ErrorCause` names the causes of IANA's "SCTP Error Cause Codes" registry
  by its names, except two: `CauseNone` (0), which IANA does not list and
  which the package uses for an association failure without a cause, and
  `CauseRestartNewEncapPort` (14), in a range IANA lists as unassigned, which
  Linux sends (`sctp_sf_new_encap_port`) after an expired Internet-Draft.
- IANA registered four temporary error causes, 100 to 103, on 2026-08-13,
  expiring on 2027-08-13, for `draft-ietf-tsvwg-sctp-dtls-chunk-04`. The
  package does not name them; they print as `ErrorCause(100)` and so on.
- The temporary chunk type 65 and parameter type 32774 (0x8006), registered
  on 2026-02-20 and expiring on 2027-02-20, still cite
  `draft-ietf-tsvwg-sctp-dtls-chunk-01`, while the working group's current
  revision is -04. Neither is used by the package.
- Parameter type 32773 (0x8005), Padding, has no reference in the registry;
  RFC 4820 §4 defines it.

## Work in progress at the IETF

Internet-Drafts are not normative, and the package implements none. They
are recorded because they may change the baseline:

| Draft | State on 2026-09-26 | What it would do |
|---|---|---|
| [`draft-ietf-tsvwg-sctp-dtls-chunk`](https://datatracker.ietf.org/doc/draft-ietf-tsvwg-sctp-dtls-chunk/) | Active working group document, revision -04, expires 2027-01-07 | A DTLS chunk protecting SCTP payloads. Its header says it obsoletes RFC 6083 and updates RFC 5061 if approved; the Datatracker records no relationship yet |
| [`draft-ietf-tsvwg-dtls-chunk-key-management`](https://datatracker.ietf.org/doc/draft-ietf-tsvwg-dtls-chunk-key-management/) | Expired working group document, revision -01, expired 2026-09-03 | Key management for the DTLS chunk |
| [`draft-ietf-tsvwg-dtls-over-sctp-bis`](https://datatracker.ietf.org/doc/draft-ietf-tsvwg-dtls-over-sctp-bis/) | Expired working group document, revision -08, expired 2024-11-04 | A revision of RFC 6083 |
| [`draft-ietf-tsvwg-rfc4895-bis`](https://datatracker.ietf.org/doc/draft-ietf-tsvwg-rfc4895-bis/) | Expired working group document, revision -05, expired 2025-10-23 | A revision of RFC 4895 |

None of the four has an obsoleting or updating relationship in the
Datatracker. The TSVWG page also lists five active individual drafts about
SCTP, with no working group standing: `draft-dreibholz-tsvwg-sctp-nextgen-ideas`,
`draft-dreibholz-tsvwg-sctpsocket-multipath`,
`draft-dreibholz-tsvwg-sctpsocket-sqinfo`,
`draft-porfiri-tsvwg-sctp-dtls-handshake` and
`draft-tuexen-tsvwg-sctp-multipath`. No document in the RFC Editor queue
concerns SCTP.

## Checking again

Check again before changing or reviewing anything a standard governs, and
at every significant revision of the package:

1. For every RFC in this document, fetch
   `https://www.rfc-editor.org/rfc/rfcNNNN.json` and read `status`,
   `obsoleted_by` and `updated_by`.
2. Query the Datatracker's relationships, filtered on the server:
   `https://datatracker.ietf.org/api/v1/doc/relateddocument/?target__name=rfcNNNN&relationship__slug__in=obs,updates&format=json`.
   Use `target__name=`, not `target=`. If an unfiltered query is ever
   needed, compare `meta.total_count` with the rows returned.
3. Compare the two. A disagreement is a finding to record here, not to
   settle by picking one.
4. Read the errata at
   `https://errata.rfc-editor.org/search/?rfc_number=NNNN&presentation=records`,
   and classify each as Verified, Held for Document Update, Rejected or
   Reported. A new Verified erratum is a correction to apply; a new Held,
   Rejected or Reported one is recorded with how it is treated.
5. Check the [TSVWG documents](https://datatracker.ietf.org/wg/tsvwg/documents/)
   and the [RFC Editor queue](https://queue.rfc-editor.org/api/v1/queue/index.json)
   for work that would obsolete or update the baseline, and search the
   [RFC index](https://www.rfc-editor.org/rfc-index.xml) for new SCTP
   documents rather than relying on this list being complete.
6. Read the IANA registry for new or expiring assignments.
7. Update this record, with the date, only after the two authorities agree
   or the disagreement is written down. If a baseline document has been
   obsoleted or updated, the code, tests and documentation that cite it are
   reviewed before anything else changes.
