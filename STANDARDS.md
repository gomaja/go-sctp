# SCTP standards and conformance baseline

This document records the standards baseline for this repository. It was last
verified on **2026-08-01** against both the RFC Editor and the IETF
Datatracker. It is a point-in-time record, not a substitute for rechecking the
authorities before changing a standards-governed subsystem.

## Conformance boundary

This repository is a Go binding to the SCTP implementation in the operating
system. On Linux, the kernel owns the protocol state machine and the bytes sent
on the wire, including:

- association setup, restart, shutdown, and verification-tag processing;
- chunk parsing and generation;
- retransmission, congestion control, path management, and PMTU discovery;
- delayed acknowledgements and SACK generation; and
- CRC32c computation and validation.

The Go package owns the socket ABI: constants, structure layouts, ancillary
data, socket-option encoding, notification parsing, error propagation, and the
public API. Consequently, the package can claim that a binding is faithful to
a particular kernel ABI and can prove the kernel's observed wire behavior. It
must not claim that Go code implements every RFC 9260 algorithm, or imply that
it can correct non-conforming kernel wire behavior.

Conformance statements therefore need to identify all three layers:

1. the RFC requirement and applicable errata;
2. the kernel version, configuration, and observed behavior; and
3. the wrapper API and ABI used to request or observe that behavior.

## Authority audit coverage

The 2026-08-01 refresh did not start from a remembered list of SCTP RFCs. It
used the current [RFC Editor index](https://www.rfc-editor.org/rfc-index.xml)
to sweep titles, keywords, and abstracts for SCTP, then classified each result
as transport protocol, socket API, implementation algorithm, security or
encapsulation profile, management document, or ULP/application mapping. The
current [IANA SCTP Parameters registry](https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml)
was independently used to find every published document or draft referenced
by a wire registry other than application Payload Protocol Identifiers.

For RFCs 2960, 3257, 3286, 3309, 3436, 3554, 3708, 3758, 3873, 4138, 4460,
4820, 4895, 4960, 5043, 5061, 5062, 5682, 5827, 6056, 6083, 6096, 6335, 6458, 6525,
6951, 7053, 7496, 7605, 7765, 7829, 8260, 8261, 8540, 8899, 8996, 9260,
9438, and 9653, the refresh called all of the following applicable authority
records rather than inferring status from citations in another RFC:

- the RFC Editor JSON record and advertised errata record;
- the Datatracker human document page and machine-readable document record;
  and
- the Datatracker incoming-related-document API, filtering formal
  `obs` and `updates` relationships from published RFCs.

The RFC Editor and Datatracker agreed on every published status and formal
update or obsoletion relationship in that SCTP-document set. The wider IANA
policy and work-in-progress cross-check found three metadata issues, recorded
below; none changes a published SCTP protocol value or promotes an
Internet-Draft to a standard.

## Current published specifications

The relationship fields below were cross-checked in the RFC Editor JSON record
and the Datatracker document and related-document records.

RFC 9260, RFC 6458, and the extension rows through RFC 4820 form the published
protocol and socket-API baseline applicable to a native Linux SCTP binding.
RFC 9438 is included as qualified congestion-control context only; it does not
formally update RFC 9260 or expand this wrapper's conformance boundary.

| Document | Current role and relationship | Authoritative records |
| --- | --- | --- |
| RFC 9260 | Current SCTP base protocol, Proposed Standard. Obsoletes RFCs 4460, 4960, 6096, 7053, and 8540. No document currently updates or obsoletes it. | [RFC Editor](https://www.rfc-editor.org/rfc/rfc9260.json), [Datatracker](https://datatracker.ietf.org/doc/rfc9260/), [errata](https://www.rfc-editor.org/errata/rfc9260) |
| RFC 6458 | Current sockets API, Informational. It has no formal update or obsoletion relationship. Later SCTP RFCs contain informational Socket API Considerations but do not formally update RFC 6458. | [RFC Editor](https://www.rfc-editor.org/rfc/rfc6458.json), [Datatracker](https://datatracker.ietf.org/doc/rfc6458/), [errata](https://www.rfc-editor.org/errata/rfc6458) |
| RFC 3758 | Partial Reliability SCTP base extension, Proposed Standard. | [RFC Editor](https://www.rfc-editor.org/rfc/rfc3758.json), [Datatracker](https://datatracker.ietf.org/doc/rfc3758/), [errata](https://www.rfc-editor.org/errata/rfc3758) |
| RFC 4895 | SCTP Authentication, Proposed Standard. | [RFC Editor](https://www.rfc-editor.org/rfc/rfc4895.json), [Datatracker](https://datatracker.ietf.org/doc/rfc4895/), [errata](https://www.rfc-editor.org/errata/rfc4895) |
| RFC 5061 | Dynamic Address Reconfiguration (ASCONF), Proposed Standard. | [RFC Editor](https://www.rfc-editor.org/rfc/rfc5061.json), [Datatracker](https://datatracker.ietf.org/doc/rfc5061/), [errata](https://www.rfc-editor.org/errata/rfc5061) |
| RFC 6525 | Stream Reconfiguration, Proposed Standard. | [RFC Editor](https://www.rfc-editor.org/rfc/rfc6525.json), [Datatracker](https://datatracker.ietf.org/doc/rfc6525/), [errata](https://www.rfc-editor.org/errata/rfc6525) |
| RFC 6951 | UDP encapsulation of SCTP, Proposed Standard. Formally updated by RFC 8899. | [RFC Editor](https://www.rfc-editor.org/rfc/rfc6951.json), [Datatracker](https://datatracker.ietf.org/doc/rfc6951/), [errata](https://www.rfc-editor.org/errata/rfc6951) |
| RFC 7496 | Additional PR-SCTP policies and socket API, Proposed Standard. | [RFC Editor](https://www.rfc-editor.org/rfc/rfc7496.json), [Datatracker](https://datatracker.ietf.org/doc/rfc7496/), [errata](https://www.rfc-editor.org/errata/rfc7496) |
| RFC 7829 | Potentially Failed destination state, Proposed Standard. | [RFC Editor](https://www.rfc-editor.org/rfc/rfc7829.json), [Datatracker](https://datatracker.ietf.org/doc/rfc7829/), [errata](https://www.rfc-editor.org/errata/rfc7829) |
| RFC 8260 | User-message interleaving and stream schedulers, Proposed Standard. | [RFC Editor](https://www.rfc-editor.org/rfc/rfc8260.json), [Datatracker](https://datatracker.ietf.org/doc/rfc8260/), [errata](https://www.rfc-editor.org/errata/rfc8260) |
| RFC 8899 | Datagram PLPMTUD, Proposed Standard. Formally updates RFCs 4821, 4960, 6951, 8085, and 8261. RFC 9260 section 7.3 applies it to the current SCTP base. | [RFC Editor](https://www.rfc-editor.org/rfc/rfc8899.json), [Datatracker](https://datatracker.ietf.org/doc/rfc8899/), [errata](https://www.rfc-editor.org/errata/rfc8899) |
| RFC 9653 | Zero Checksum for SCTP, Proposed Standard. It has no formal update or obsoletion relationship. | [RFC Editor](https://www.rfc-editor.org/rfc/rfc9653.json), [Datatracker](https://datatracker.ietf.org/doc/rfc9653/), [errata](https://www.rfc-editor.org/errata/rfc9653) |
| RFC 4820 | SCTP PAD chunk, Proposed Standard. It is used by the RFC 8899 PLPMTUD procedures. | [RFC Editor](https://www.rfc-editor.org/rfc/rfc4820.json), [Datatracker](https://datatracker.ietf.org/doc/rfc4820/), [errata](https://www.rfc-editor.org/errata/rfc4820) |
| RFC 9438 | CUBIC, Proposed Standard. Obsoletes RFC 8312 and updates RFC 5681, but does not formally update RFC 9260. Its qualified SCTP applicability is discussed below. | [RFC Editor](https://www.rfc-editor.org/rfc/rfc9438.json), [Datatracker](https://datatracker.ietf.org/doc/rfc9438/), [errata](https://www.rfc-editor.org/errata/rfc9438) |

### Adjacent published documents and explicit exclusions

The following published documents are relevant context, but do not define a
generic native SCTP socket binding. Keeping them out of the conformance
baseline is deliberate, not an omission.

| Document | Current status and relationship | Why it is adjacent or out of scope |
| --- | --- | --- |
| [RFC 3257](https://www.rfc-editor.org/rfc/rfc3257.json) | Informational; no formal update or obsoletion relationship. | The SCTP Applicability Statement is deployment guidance based on the original protocol generation, not socket ABI or a wire extension. |
| [RFC 3286](https://www.rfc-editor.org/rfc/rfc3286.json) | Informational; no formal update or obsoletion relationship. | It is an introductory overview and predates the current base specification. |
| [RFC 3436](https://www.rfc-editor.org/rfc/rfc3436.json) | Proposed Standard; formally updated by [RFC 8996 section 1.1](https://www.rfc-editor.org/rfc/rfc8996.html#section-1.1). | TLS over SCTP is an upper-layer usage profile. RFC 8996 prohibits fallback to TLS 1.0/1.1 and requires at least TLS 1.2; the Go socket wrapper does not implement TLS. |
| [RFC 3554](https://www.rfc-editor.org/rfc/rfc3554.json) | Proposed Standard; no formal update or obsoletion relationship. | Its IPsec/IKE integration requirements belong to the IPsec stack and key manager. |
| [RFC 3873](https://www.rfc-editor.org/rfc/rfc3873.json) | Proposed Standard; no formal update or obsoletion relationship. | It defines an SNMP MIB. Linux kernel statistics and a Go socket API are not an implementation of that MIB. |
| [RFC 5043](https://www.rfc-editor.org/rfc/rfc5043.json) | Proposed Standard; formally updated by RFCs 6581 and 7146. | [RFC 5043 sections 5.1, 5.2, and 12](https://www.rfc-editor.org/rfc/rfc5043.html#section-5.1) define the DDP adaptation profile, including Adaptation Code Point 1 and PPIDs 16 and 17. The wrapper transports adaptation codes and PPIDs as opaque application values; it does not implement DDP/RDMA. The later updates change DDP/RDMA connection establishment and block-storage security requirements, not the generic SCTP socket ABI. |
| [RFC 5062](https://www.rfc-editor.org/rfc/rfc5062.json) | Informational; no formal update or obsoletion relationship. | Its attack analysis is security and kernel-implementation context for RFC 9260 and RFC 4895, not an additional socket API. |
| [RFC 6083](https://www.rfc-editor.org/rfc/rfc6083.json) | Proposed Standard; formally updated by RFC 8996 section 1.1. | DTLS over SCTP protects ULP messages above SCTP and is not implemented by this package. Its applicable errata are inventoried below. |
| [RFC 8261](https://www.rfc-editor.org/rfc/rfc8261.json) | Proposed Standard; formally updated by RFCs 8899 and 8996. | SCTP-over-DTLS is a below-SCTP encapsulation profile used by user-space deployments such as WebRTC, not native Linux SCTP over IP. |

The RFC Editor index and IANA Payload Protocol Identifier sweep also returns
many signaling adaptation layers, application transports, WebRTC/SDP data
channel profiles, and other ULP mappings. Those documents consume SCTP
streams, PPIDs, ports, or adaptation codes but do not modify SCTP transport or
the generic socket API. This package must carry their opaque application
values correctly, but implementing those application protocols is out of
scope.

[RFC 6335](https://www.rfc-editor.org/rfc/rfc6335.json) is relevant only to the
historical relationship graph: it formally updated RFC 4960's IANA
port-registration procedures before RFC 4960 was obsoleted.
[RFC 6056](https://www.rfc-editor.org/rfc/rfc6056.json), RFC 6335, and
[RFC 7605](https://www.rfc-editor.org/rfc/rfc7605.json) provide current general
transport-port and IANA guidance; ephemeral-port selection and registry policy
are not implemented by this wrapper. RFC 6056 Verified Errata 2750 and 7873
are editorial and Erratum 3739 is Rejected; RFC 6335 Verified Erratum 3814 and
Held Erratum 4999 are technical; RFC 7605 Verified Erratum 4437 and Held
Erratum 5592 are editorial. The Held errata are reported here, not applied as
corrections, and none creates a generic SCTP socket ABI.

### Experimental SCTP algorithms

Experimental RFCs are not part of the Proposed Standard baseline. They are
nevertheless important when evaluating the Linux protocol engine, and one of
them specifies a socket option that must not be guessed:

| Document | Current relationship and exact SCTP scope | Wrapper impact |
| --- | --- | --- |
| [RFC 3708](https://www.rfc-editor.org/rfc/rfc3708.json) | Experimental; no formal update or obsoletion relationship. [Sections 2 and 3](https://www.rfc-editor.org/rfc/rfc3708.html#section-2) describe using SCTP Duplicate TSN reports to count and disambiguate spurious retransmissions. | Sender loss-recovery logic is kernel-owned; the RFC defines no generic socket option for this wrapper. |
| [RFC 4138](https://www.rfc-editor.org/rfc/rfc4138.json) | Experimental; formally updated by RFC 5682. [Section 5](https://www.rfc-editor.org/rfc/rfc4138.html#section-5) describes applying F-RTO to SCTP, including multihoming and bundled retransmission considerations. | F-RTO is kernel-owned and RFC 4138 defines no SCTP socket API. |
| [RFC 5682](https://www.rfc-editor.org/rfc/rfc5682.json) | Proposed Standard and formally updates RFC 4138, but [section 1](https://www.rfc-editor.org/rfc/rfc5682.html#section-1) explicitly removes SCTP from the Standards Track update and leaves RFC 4138's SCTP procedure Experimental. | It must not be cited as promoting SCTP F-RTO to Proposed Standard. |
| [RFC 5827](https://www.rfc-editor.org/rfc/rfc5827.json) | Experimental; no formal update or obsoletion relationship. [Sections 3 and 4](https://www.rfc-editor.org/rfc/rfc5827.html#section-3) define and qualify Early Retransmit for both TCP and SCTP. | Sender loss recovery is kernel-owned; no socket ABI is defined. |
| [RFC 7765](https://www.rfc-editor.org/rfc/rfc7765.json) | Experimental; no formal update or obsoletion relationship. [Section 4](https://www.rfc-editor.org/rfc/rfc7765.html#section-4) defines RTO Restart for SCTP and TCP; [section 7](https://www.rfc-editor.org/rfc/rfc7765.html#section-7) extends RFC 6458 with `SCTP_RTO_RESTART`. | Current upstream Linux UAPI does not define `SCTP_RTO_RESTART`. The wrapper must not invent a number or claim this Experimental option until Linux provides an ABI. |

RFCs 3708, 4138, 5682, 5827, and 7765 had no errata when checked. RFC 9438 is
the separate current Proposed Standard congestion-control context discussed
below; it does not turn any of these Experimental SCTP algorithms into the
base conformance requirement.

## Obsolete documents are historical only

The following references may be useful for history but are not the current
normative base:

- **RFC 2960** was updated by the CRC32c change in RFC 3309. RFC 4960 then
  obsoleted both documents, and RFC 9260 subsequently obsoleted RFC 4960.
- **RFC 4960** was updated by RFCs 6096, 6335, 7053, and 8899 before RFC 9260
  obsoleted it. RFC 8899 remains applicable through RFC 9260 section 7.3;
  RFC 6335 concerned IANA port-registration procedures rather than the SCTP
  state machine.
- **RFC 4460**, **RFC 6096**, **RFC 7053**, and **RFC 8540** were incorporated
  into or superseded by RFC 9260 and are explicitly obsoleted by it.
- **RFC 8312** was obsoleted by RFC 9438 for CUBIC. Neither document formally
  updates RFC 9260.

Code, tests, and documentation must cite the corresponding RFC 9260 section for
current behavior. An obsolete number may remain only when clearly labeled as a
historical source. Upstream Linux SCTP source still contains comments citing
RFCs 2960 and 4960; those comments describe implementation history and are not
current standards evidence.

RFC 9260 section 1 explicitly incorporates the RFC 7053 I-bit specification.
Current citations for that facility are RFC 9260 sections 3.3.1, 6.1, 6.2, and
11.1.5, not RFC 7053.

The current CRC32c wire requirements formerly split between RFCs 2960 and 3309
are RFC 9260 sections 3.1 and 6.8 and Appendix A. No code migration is needed
merely because an old implementation comment names RFC 3309, but a current
conformance claim must cite RFC 9260.

## Errata policy and inventory

Verified technical errata are part of this conformance baseline. Verified
editorial errata govern wording and interpretation. An erratum marked Held for
Document Update is reported here but is not applied as a normative correction.
A Rejected erratum must not be implemented as a correction.

### RFC 9260

The complete current inventory is five Verified, one Held for Document Update,
and three Rejected errata:

- **Verified Erratum 7148**, technical, RFC 9260 section 3.3.3: handling an
  INIT ACK whose `a_rwnd` is less than 1500 depends on association state; in
  COOKIE-WAIT the endpoint destroys the TCB and should send ABORT.
- **Verified Erratum 7387**, technical, section 5.2.4.1: COOKIE ECHO and COOKIE
  ACK in the restart diagram use T1-cookie, not T1-init.
- **Verified Erratum 8402**, technical, section 5.1.6: INIT retransmission uses
  T1-init and COOKIE ECHO retransmission uses T1-cookie.
- **Verified Erratum 7147**, editorial, section 3.2: quotation-mark correction.
- **Verified Erratum 7852**, editorial, section 8.5: the verification tag is
  checked before processing any chunks or changing association state.
- **Held Erratum 8772**, editorial, section 3.3.4: proposes an explicit missing
  SACK Chunk Length definition. Do not treat it as normative while Held.
- **Rejected Erratum 7988**, technical, section 3.3.2: proposed INIT source
  address clarification.
- **Rejected Erratum 8387**, technical, section 3.3.10.6: proposed requiring
  the complete Chunk Value in an Unrecognized Chunk error cause.
- **Rejected Erratum 8774**, editorial, sections 3.3.2, 3.3.3, 3.3.9, and
  3.3.12: proposed repeated Chunk Length descriptions.

### RFC 6458

The complete current inventory is six Verified, four Held for Document Update,
and four Rejected errata:

- **Verified Erratum 6111**, technical, sections 5.3.2, 5.3.4, 8.1.13, and
  8.1.31: adds `SCTP_EOR` when explicit end-of-record marking is enabled.
  Linux exposes neither `SCTP_EOR` nor `SCTP_EXPLICIT_EOR`.
- **Verified Erratum 6115**, technical, section 8.2.1: removes `SCTP_BOUND`
  from the association states. Linux's state enumeration differs further.
- **Verified Erratum 6112**, editorial, section 3.2:
  `SCTP_CANT_START_ASSOC` is corrected to `SCTP_CANT_STR_ASSOC`.
- **Verified Erratum 6980**, editorial, section 8: `SCTP_MAX_SEG` is corrected
  to `SCTP_MAXSEG`.
- **Verified Errata 7547 and 7548**, editorial, sections 9.12 and 9.1:
  `info_type` is corrected to `infotype` in the sendv/recvv API text.
- **Held Erratum 4921**, technical, section 9.1: IPv6 sockets and IPv4-mapped
  address handling.
- **Held Erratum 6116**, technical, section 6.1.2: proposes
  `SCTP_ADDR_CONFIRMED`.
- **Held Erratum 6113**, editorial, section 6.1.1: `sac_info` also applies to
  `SCTP_CANT_STR_ASSOC`.
- **Held Erratum 6114**, editorial, section 9.5: uses the symbolic
  `SCTP_FUTURE_ASSOC` value instead of an unexplained zero.
- **Rejected Errata 6081, 6131, 6132, and 6133** are alternate or duplicate
  proposals around explicit end-of-record handling and are not corrections.

### Other applicable documents

- **RFC 4895 Held Erratum 995**, editorial, section 11, proposes removing an
  unused MD5 reference. It is not normative while Held.
- **RFC 4820 Rejected Erratum 897**, technical, section 3, proposed a different
  maximum PAD chunk size. It must not be applied.
- **RFC 6083 Held Erratum 5744**, technical, section 4.8, concerns key-switch
  timing; **Rejected Erratum 6323**, technical, section 1.1, concerns a DTLS
  user-message limit. These matter only to RFC 6083 implementations.
- **RFC 8996 Verified Errata 7103 and 7796** are editorial corrections to an
  RFC link and an author's name. **Held Erratum 7769** is an editorial
  capitalization proposal in section 1.1. None changes RFC 8996 section 1.1's
  prohibition on falling back to TLS 1.0/1.1 or DTLS 1.0.
- **RFC 9438 Rejected Erratum 7806**, technical, section 4.1.2, proposed using
  Flight Size for `cwnd_prior`; the verifier found section 4.6 sufficient.
- RFCs 3758, 5061, 6525, 6951, 7496, 7829, 8260, 8899, and 9653 had no errata
  when checked.
- The adjacent RFCs 3257, 3286, 3436, 3554, 3873, 5043, 5062, and 8261 had no
  errata when checked. The Experimental algorithm inventory records its
  no-errata result in that section.

## Published inconsistencies and unsupported facilities

### RFC 6458 notifications-stopped event

[RFC 6458 section 6.1.10](https://www.rfc-editor.org/rfc/rfc6458.html#section-6.1.10)
defines the non-deprecated `SCTP_NOTIFICATIONS_STOPPED_EVENT`. It uses only the
generic `sctp_tlv` notification header and is automatically subscribed when an
application subscribes to any event other than the data-I/O event. None of the
current RFC 6458 errata changes that section.

Current upstream
[`include/uapi/linux/sctp.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/linux/sctp.h)
omits `SCTP_NOTIFICATIONS_STOPPED_EVENT` from `enum sctp_sn_type`; the enum
advances directly from `SCTP_SENDER_DRY_EVENT` to `SCTP_STREAM_RESET_EVENT`.
The wrapper must not guess a sequential value, because doing so would
misidentify Linux's stream-reset notification. Until Linux defines an ABI, the
RFC 6458 event is an explicitly unsupported kernel facility and no public
notification type or subscription constant can be added safely.

### RFC 8260 fair-capacity scheduler name

RFC 8260 is internally inconsistent and has no erratum for the inconsistency:

- section 3.5 names Fair Capacity `SCTP_SS_FC`;
- section 4.3.2 and its table use `SCTP_SS_FB`.

Linux UAPI uses `SCTP_SS_FC`. This package follows that ABI and the defining
text in RFC 8260 section 3.5. `SCTP_SS_FB` must not be introduced silently. A
future RFC erratum or kernel ABI change requires an explicit reassessment.

### RFC 6458 fragment-interleave level 2 on Linux

[RFC 6458 section 8.1.20](https://www.rfc-editor.org/rfc/rfc6458.html#section-8.1.20)
defines three distinct `SCTP_FRAGMENT_INTERLEAVE` levels. Level 2 permits
interleaving between streams within one association and requires receive
metadata that identifies the stream. Level 1 permits interleaving only between
associations and is therefore not an equivalent fallback.

Current upstream Linux
[`sctp_setsockopt_fragment_interleave`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/sctp/socket.c)
stores `!!*val` and the getter returns that boolean. A request for level 2 is
therefore accepted but reads back as level 1. RFC 8260 I-DATA negotiation uses
the separate `SCTP_INTERLEAVING_SUPPORTED` option and does not restore or report
RFC 6458 level-2 receive semantics.

Portable validation accepts levels 0, 1, and 2 and enforces level 2's receive
metadata prerequisite. On Linux, the wrapper then sets and reads back the
option. In typed pre-association construction, a level-2 request that reads back
as level 1 closes the descriptor and returns an error satisfying
`errors.Is(err, errors.ErrUnsupported)` before bind, connect, or listen; no
usable socket escapes. `SetFragmentInterleave` performs the same readback on an
existing socket and returns the same unsupported identity. Levels 0 and 1 must
read back exactly. One-to-many endpoints default to level 1 as recommended by
RFC 6458 rather than silently claiming level 2.

### RFC 9653 zero checksum

The published socket option is **`SCTP_ACCEPT_ZERO_CHECKSUM`** in RFC 9653
section 7.1. `SCTP_ZERO_CHECKSUM` is not its name.

Current upstream Linux UAPI exposes neither `SCTP_ACCEPT_ZERO_CHECKSUM` nor the
RFC 9653 Error Detection Method identifiers. The wrapper must not invent an
option number. Until Linux adds the API, RFC 9653 is an explicitly unsupported
kernel facility.

A correctly computed CRC32c value of zero is valid without this extension.
RFC 9653 instead permits an intentionally incorrect zero checksum only after
directional negotiation and only when the selected alternate error-detection
method satisfies section 3. INIT, COOKIE ECHO, ASCONF, and out-of-the-blue
response packets still require a correct CRC32c checksum under section 5.2.

### RFC 7765 RTO Restart

RFC 7765 is Experimental, not part of the RFC 9260 Proposed Standard baseline.
Its [section 7.2](https://www.rfc-editor.org/rfc/rfc7765.html#section-7.2)
assigns the symbolic socket-option name `SCTP_RTO_RESTART`, but does not assign
a Linux numeric ABI value. Current upstream
[`include/uapi/linux/sctp.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/plain/include/uapi/linux/sctp.h)
exposes no option with that name. This wrapper must not infer a number from
another operating system or expose an option that the Linux kernel cannot
accept. The RFC can be reconsidered only if Linux adds a UAPI, at which point
both getsockopt and setsockopt behavior need ABI tests.

### Linux ECN option

Linux exposes `SCTP_ECN_SUPPORTED`, but current RFC 9260 only reserves the ECN
parameter and chunks and notes the removal of the old ECN appendix in section
1.7. No current RFC specifies SCTP ECN operation. This option is Linux-specific
and experimental, not evidence of current standards support.

## RFC 9438 CUBIC and SCTP

RFC 9438 is a current Proposed Standard for CUBIC. It obsoletes RFC 8312,
updates RFC 5681, and has no incoming update or obsoletion relationship. Its
section 1 says CUBIC can be used by SCTP and identifies SCTP as a Reno-style
transport affected by poor high-bandwidth-delay-product utilization.

That statement does not formally update RFC 9260: RFC 9260 is an informative
reference in RFC 9438, and RFC 9260 section 7.2.2 still says SCTP MUST NOT
increase `cwnd` by more than one PMDCS per RTT. RFC 9438 also does not specify
the SCTP mapping for per-destination congestion windows, multihoming, SACK
accounting, Fast Recovery, or PMDCS versus SMSS.

Current upstream Linux implements a fixed Reno-style SCTP congestion-control
path. Its CUBIC implementation is registered only through TCP's
`tcp_congestion_ops`; SCTP has no controller-selection socket option, UAPI, or
sysctl. This wrapper therefore cannot select or expose CUBIC. CUBIC for SCTP is
an optional research and kernel-development direction, not a missing wrapper
constant and not an RFC 9260 conformance fix.

Sources: [RFC 9438](https://www.rfc-editor.org/rfc/rfc9438.html),
[RFC 9438 Datatracker record](https://datatracker.ietf.org/doc/rfc9438/),
[RFC 9260 section 7.2.2](https://www.rfc-editor.org/rfc/rfc9260.html#section-7.2.2),
[Linux SCTP congestion control](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/sctp/transport.c),
and [Linux TCP CUBIC](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/tcp_cubic.c).

## Delayed SACK and the I-bit

[RFC 9260 section 6.2](https://www.rfc-editor.org/rfc/rfc9260.html#section-6.2)
contains two independent delayed-acknowledgement recommendations:

- an acknowledgement SHOULD be generated for at least every second SCTP
  packet, not every second DATA chunk; and
- it SHOULD be generated within 200 ms of any unacknowledged DATA chunk.

An implementation can depart from a SHOULD only for a valid, understood, and
documented reason. Satisfying the 200 ms recommendation alone does not satisfy
the every-second-packet recommendation. Separately, configured `SACK.Delay`
MUST NOT exceed 500 ms, and a receiver MUST NOT generate more than one SACK per
incoming packet except for receive-window updates.

The 500 ms rule constrains the maximum value an implementation permits an
administrator to configure; it does not replace or relax the independent
200 ms delayed-acknowledgement `SHOULD`. `PreAssociation.DelayedSACK` rejects a
delay above 500 before opening a descriptor and reads back every requested
non-zero delay or frequency. A mismatched Linux readback fails closed instead
of claiming that the requested policy was applied.

RFC 9260 sections 3.3.1 and 6.1 define the DATA I-bit. Under section 6.2, a
receiver of a packet containing DATA with I set SHOULD immediately send the
corresponding SACK. Section 11.1.5 exposes the ULP `sack-immediately` request;
for a fragmented user message, it sets I only on the final DATA chunk.

The Go wrapper owns socket-option boundaries, readback behavior, bounds,
byte-order conversions, cross-architecture layouts, and Linux-versus-RFC
compatibility notes. Kernel algorithm claims remain outside the wrapper
implementation boundary unless they are checked against the current Linux
version and the current RFC/errata baseline.

## Known Linux-versus-document differences

These differences must remain explicit compatibility notes rather than being
hidden behind an unqualified compliance claim:

- Linux implements neither RFC 6458 Verified Erratum 6111's `SCTP_EOR` nor
  the associated `SCTP_EXPLICIT_EOR` option.
- Linux omits RFC 6458 section 6.1.10's
  `SCTP_NOTIFICATIONS_STOPPED_EVENT`; no numeric type may be inferred.
- Linux's association-state enumeration differs from RFC 6458, including the
  correction in Verified Erratum 6115.
- Linux's partial-delivery notification field layout differs from the RFC 6458
  structure order; the wrapper follows the kernel ABI.
- Linux's `sctp_default_prinfo` field order is association id, value, policy;
  RFC 6458 section 8.1.32 specifies policy, value, association id. The Go
  structure follows Linux because that is the memory layout passed to the
  socket option.
- Linux's `sctp_paddrparams` inserts `spp_sackdelay` and adds
  `SPP_SACKDELAY_ENABLE` and `SPP_SACKDELAY_DISABLE`; that field and those
  bits are not in RFC 6458 section 8.1.12. `SPP_HB_TIME_IS_ZERO` is part of
  the RFC structure and is not a Linux extension.
- Linux stores `SCTP_FRAGMENT_INTERLEAVE` as a boolean, so RFC 6458 level 2 is
  silently clamped to level 1 by the kernel; the wrapper detects the readback
  mismatch and returns `errors.ErrUnsupported`.
- RFC 7829 section 7.2 specifies one three-threshold `sctp_paddrthlds`
  structure. Linux retains a legacy two-threshold option and exposes the
  RFC-complete shape as `SCTP_PEER_ADDR_THLDS_V2`; the V2 number is a Linux ABI
  compatibility device, not an extra non-RFC threshold.
- RFC 6951 section 6.1 says a wildcard `sue_address` changes only future paths.
  Linux additionally updates every current transport when the wildcard remote
  encapsulation option is set. The wrapper documents that broader Linux effect
  rather than presenting it as RFC behavior.
- `SCTP_PLPMTUD_PROBE_INTERVAL` and `struct sctp_probeinterval` are Linux UAPI
  controls related to the RFC 8899 DPLPMTUD procedure. RFC 8899 defines neither
  socket interface.
- RFC 6525 section 6.1.3 describes Stream Change counts as the new total stream
  width, while Linux reports the number added. Callers need status data for the
  resulting total.
- Linux delayed-SACK behavior can differ from RFC 9260 section 6.2's 200 ms
  `SHOULD` even when the socket option reads back as 200 ms.
- RFC 9653's socket option is not present in current Linux UAPI.
- SCTP CUBIC selection is not present in current Linux.

### Wrapper byte-order and endpoint invariants

The exported Go API uses host byte order for every numeric PPID. RFC 6458
sections 5.3.2, 5.3.4, and 5.3.5 label the ancillary fields network byte order
and also state that the SCTP stack performs no byte-order modification. Send,
receive, default-option, endpoint, and notification paths therefore apply
`htonl` or `ntohl` at the kernel boundary. This is a package convention over
the raw ABI, not a claim that the SCTP stack translates PPIDs.

`UDPEncaps.Port` likewise uses host byte order in Go. RFC 6951 section 6.1
defines `sue_port` in network byte order, so its marshaller and unmarshaller
perform an explicit big-endian conversion. A unit assertion pins 9899 as bytes
`26 ab`; getter round-trip alone is not accepted as full evidence.

RFC 6458 section 3.1.3 says applications using association identifiers should
ensure `SCTP_ASSOC_CHANGE` is enabled. It does not impose a universal mandatory
subscription. `SCTPEndpoint` deliberately makes that recommendation a
fail-closed package invariant so association-id lifecycle events cannot be
disabled. It separately requires `SCTP_RECVRCVINFO` because `Receive` needs the
section 5.3.5 metadata to route each message; that second requirement is also a
package contract, not RFC wording.

`SCTP_AUTH_CHUNK` is also timing-sensitive but not a kernel departure. RFC 6458
section 8.3.2 says changes affect future associations only, and RFC 4895 section
6.1 defines the CHUNKS parameter carried in INIT and INIT ACK. Linux therefore
accepts `SetAuthChunk` after an association exists while leaving that current
peer's negotiated CHUNKS list unchanged. A connected-call test compares the
peer list before and after so success cannot be misreported as a retrofit.

## IANA registry cross-check

The [current SCTP Parameters registry](https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml),
last updated 2026-02-20 when checked, agrees with the published numeric values
used by the base and extension RFCs in this document. In particular, its
protocol-value entries outside the application PPID registry point to RFCs
3758, 4820, 4895, 5061, 6525, 8260, 9260, and 9653. RFC 5043 appears only for
DDP Adaptation Code Point 1; that adjacent ULP profile is classified above.
The registry-allocation rules also cite
[RFC 8126](https://www.rfc-editor.org/rfc/rfc8126.json).
[RFC 9907 section 4.30.3](https://www.rfc-editor.org/rfc/rfc9907.html#section-4.30.3)
formally updates RFC 8126 only for IANA-maintained YANG modules and does not
change the SCTP registry. The RFC Editor JSON records and the
[Datatracker human RFC 8126 page](https://datatracker.ietf.org/doc/rfc8126/)
show that update, but the
[Datatracker incoming-related-document API](https://datatracker.ietf.org/api/v1/doc/relateddocument/?target__name=rfc8126&limit=500&format=json)
omits it. That is a Datatracker API metadata disagreement; RFC 9907's published
text controls. RFC 8126 Erratum 5772 is Held and editorial; Erratum 6522 is
Rejected and must not change the registry policy. RFC 9907 Verified Errata
8872 and 8880 are editorial YANG-example/template corrections and likewise do
not affect SCTP.

Two additional IANA metadata findings require explicit treatment:

- Temporary chunk type 65 and parameter 32774 (`0x8006`) are scheduled to
  expire on 2027-02-20. IANA still cites
  `draft-ietf-tsvwg-sctp-dtls-chunk-01`, while the Datatracker's active Working
  Group revision is `draft-ietf-tsvwg-sctp-dtls-chunk-04`. The allocated
  values and expiry come from IANA; the newer draft content comes from the
  Datatracker. The reference-version lag does not make either draft normative.
- Parameter 32773 (`0x8005`) is named Padding but has a blank IANA Reference
  cell. RFC 4820 section 4 defines that exact type and section 5 records its
  IANA assignment. This is a registry citation omission, not an unassigned
  value. RFC 4820 Erratum 897 is Rejected and must not change the parameter.

## Work in progress at the IETF

Internet-Drafts are not normative. As of 2026-08-01, the active TSVWG SCTP work
was:

- [`draft-ietf-tsvwg-sctp-dtls-chunk-04`](https://datatracker.ietf.org/doc/draft-ietf-tsvwg-sctp-dtls-chunk/),
  an active Working Group document expiring 2027-01-07. If published as
  proposed, it would obsolete RFC 6083 and update RFC 5061. It is incompatible
  with RFC 4895 AUTH on the same association and defines additional socket API
  facilities.
- [`draft-ietf-tsvwg-dtls-chunk-key-management-01`](https://datatracker.ietf.org/doc/draft-ietf-tsvwg-dtls-chunk-key-management/),
  an active Working Group document expiring 2026-09-03, paired with the DTLS
  chunk work for DTLS 1.3 key management.

Two expired Working Group documents still had future milestones and are worth
tracking, but must not be implemented as standards:

- [`draft-ietf-tsvwg-rfc4895-bis-05`](https://datatracker.ietf.org/doc/draft-ietf-tsvwg-rfc4895-bis/),
  intended to obsolete RFC 4895; and
- [`draft-ietf-tsvwg-dtls-over-sctp-bis-08`](https://datatracker.ietf.org/doc/draft-ietf-tsvwg-dtls-over-sctp-bis/),
  alternative revision work around RFC 6083.

The expired AUTH-bis draft proposed parameter `0x8006` for ALL CHUNKS. The
current [IANA SCTP Parameters registry](https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml)
temporarily assigns `0x8006` to DTLS Key Management for the active DTLS chunk
work. When checked, temporary chunk type 65 and parameter 32774 (`0x8006`) were
scheduled to expire on 2027-02-20; published RFC 9653 parameter 32769
(`0x8001`) was permanent. The expired AUTH-bis proposal must not be
implemented or reserved locally.

The following active individual documents had no Working Group or normative
standing:

- [`draft-dreibholz-tsvwg-sctp-nextgen-ideas-23`](https://datatracker.ietf.org/doc/draft-dreibholz-tsvwg-sctp-nextgen-ideas/);
- [`draft-dreibholz-tsvwg-sctpsocket-multipath-32`](https://datatracker.ietf.org/doc/draft-dreibholz-tsvwg-sctpsocket-multipath/);
- [`draft-dreibholz-tsvwg-sctpsocket-sqinfo-32`](https://datatracker.ietf.org/doc/draft-dreibholz-tsvwg-sctpsocket-sqinfo/);
- [`draft-hohendorf-secure-sctp-41`](https://datatracker.ietf.org/doc/draft-hohendorf-secure-sctp/);
- [`draft-porfiri-tsvwg-sctp-dtls-handshake-01`](https://datatracker.ietf.org/doc/draft-porfiri-tsvwg-sctp-dtls-handshake/); and
- [`draft-tuexen-tsvwg-sctp-multipath-31`](https://datatracker.ietf.org/doc/draft-tuexen-tsvwg-sctp-multipath/).

The active individual
[`draft-dreibholz-rserpool-applic-mobility-39`](https://datatracker.ietf.org/doc/draft-dreibholz-rserpool-applic-mobility/)
also contains SCTP in its title, but is a Reliable Server Pooling application
and mobility profile rather than an SCTP protocol or socket-API revision.

No active document replaces RFC 9260 or RFC 6458, and the
[RFC Editor queue JSON](https://queue.rfc-editor.org/api/v1/queue/index.json)
snapshot timestamped 2026-08-01T03:39:06.510Z contained 142 items and no
document whose name or title contained SCTP or Stream Control Transmission
Protocol. The human [queue page](https://queue.rfc-editor.org/) and the
Datatracker TSVWG page therefore agreed that no SCTP document was in the RFC
Editor queue.

The live source for this section is the
[TSVWG documents page](https://datatracker.ietf.org/wg/tsvwg/documents/). Draft
version numbers, expiry dates, intended relationships, and IANA temporary
allocations must be rechecked rather than copied forward.

## Refresh procedure

Before changing or reviewing a standards-governed subsystem:

1. Sweep `https://www.rfc-editor.org/rfc-index.xml` for new SCTP protocol,
   socket-API, algorithm, and deployment documents. Do not rely on this file's
   existing number list to remain complete.
2. Fetch `https://www.rfc-editor.org/rfc/rfcNNNN.json` and inspect `status`,
   `obsoletes`, `obsoleted_by`, `updates`, `updated_by`, and `errata_url`.
3. Fetch `https://www.rfc-editor.org/errata/rfcNNNN` and classify every entry as
   Verified, Held for Document Update, Rejected, or Reported.
4. Cross-check the human Datatracker page and
   `https://datatracker.ietf.org/api/v1/doc/document/rfcNNNN/?format=json`.
5. Query
   `https://datatracker.ietf.org/api/v1/doc/relateddocument/?target__name=rfcNNNN&limit=500&format=json`
   for incoming relationships. A smaller limit can omit relationships for
   heavily referenced RFCs.
6. Check the TSVWG documents page,
   `https://queue.rfc-editor.org/api/v1/queue/index.json`, and both the HTML and
   XML forms of the IANA SCTP registry for active work, publication-queue
   documents, temporary assignments, and missing or stale registry references.
7. Update the verification date and this inventory only after both authorities
   agree. Record any disagreement as a finding rather than choosing one source
   silently.
