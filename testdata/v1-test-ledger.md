# v1 test ledger

Every `Test`, `Fuzz`, `Benchmark` and `Example` function that existed in v1,
at commit b6f3db1 (the last commit before v1 was removed), in the root
`*_test.go` files and in `example/*_test.go`. Generated before that
removal so it stays reproducible straight from that commit at any later
point.

Whatever later change ports or retires a row updates its `status` column
to either `ported → <new test name>` or `retired: <reason the property no
longer exists>`. A row stays `pending` until something touches it.

## Generator

Run from the repository root, on a checkout that still has commit
b6f3db1:

```sh
for f in $(git ls-tree -r --name-only b6f3db1 \
             | grep -E '^[^/]*_test\.go$|^example/[^/]*_test\.go$' | sort); do
  git show b6f3db1:"$f" \
    | grep -n '^func \(Test\|Fuzz\|Benchmark\|Example\)' \
    | while IFS=: read -r ln rest; do
        name=$(echo "$rest" | sed -E 's/^func ([A-Za-z0-9_]+).*/\1/')
        printf '| %s | %s | pending |\n' "$f" "$name"
      done
done
```

This walks every root-level `*_test.go` and every `example/*_test.go` blob
as they existed at commit b6f3db1, in file order, and lists each top-level
`Test…`, `Fuzz…`, `Benchmark…` or `Example…` function as one row, in the
order it appears in its file.

## Totals (v1, commit b6f3db1)

| kind | count |
|---|---|
| Test | 482 |
| Fuzz | 14 |
| Benchmark | 13 |
| Example | 0 |
| **files** | **71** (70 root + `example/sctp_test.go`) |
| **total rows** | **509** |

## Rows

| file | function | status |
|---|---|---|
| example/sctp_test.go | TestConfigureBuffersReadsEachConfiguredBuffer | pending |
| example/sctp_test.go | TestConfigureBuffersLeavesZeroRequestsUnchanged | pending |
| example/sctp_test.go | TestConfigureBuffersStopsAtEachError | pending |
| sctp_already_test.go | TestSCTPConnectEALREADYOnNonblockingSocket | ported → TestConnectxReportsEALREADYWhileSetupInFlight (dial_linux_test.go): on the non-blocking socket Dial uses, a second CONNECTX3 to a setup in flight answers EALREADY, never success |
| sctp_already_test.go | TestSCTPConnectEISCONNOnBlockingSocket | retired: the package no longer connects blocking sockets or exports SCTPConnect; Dial always sets up through a non-blocking CONNECTX3 and confirms establishment itself, so no connect result is ever converted into success |
| sctp_already_test.go | TestSCTPConnectEALREADYOnBlockingSocketMidHandshake | retired: as above, there is no blocking connect whose EALREADY could be mistaken for an established association |
| sctp_already_test.go | TestIsNonblockingDetectsBothStates | ported → TestIsNonblockingDetectsBothStates (socket_linux_test.go); the helper now backs the descriptor-mode assertions (TestDescriptorsAreNonBlockingAndCloseOnExec, TestDialContextReturnsPollableDescriptor) and reports false, failing those assertions, for a descriptor it cannot query |
| sctp_backlog_test.go | TestListenBacklogUsesKernelMaximum | ported → TestListenBacklogUsesKernelMaximum (listener_linux_test.go) |
| sctp_backlog_test.go | TestReadSomaxconnMatchesProc | ported → TestReadSomaxconnMatchesProc (listener_linux_test.go) |
| sctp_bench_test.go | BenchmarkSCTPWrite | ported → BenchmarkSendMsg (send_linux_test.go), against a helper-process peer so that allocs/op counts the sender alone; sends now wait for buffer space, so v1's EAGAIN retry accounting is gone |
| sctp_bench_test.go | BenchmarkSCTPWriteNoInfo | ported → BenchmarkWrite (send_linux_test.go) |
| sctp_bench_test.go | BenchmarkSCTPWriteInfo | ported → BenchmarkSendMsg, BenchmarkSendMsgInfoPR (send_linux_test.go) |
| sctp_bench_test.go | BenchmarkSCTPRead | pending |
| sctp_bench_test.go | BenchmarkBuildSndRcvCmsg | ported → BenchmarkAppendSendCmsgs (msginfo_test.go): the control message is now encoded into the connection's own buffer, SNDINFO in place of the deprecated SCTP_SNDRCV |
| sctp_bench_test.go | BenchmarkToBuf | retired: toBuf, the binary.Write-based struct serialiser v1's send path used, no longer exists; every record is written field by field at abi.go's offsets, and BenchmarkAppendSendCmsgs measures the encoder that replaced it |
| sctp_bench_test.go | BenchmarkParseSndRcvInfo | pending |
| sctp_bench_test.go | BenchmarkResolveSCTPAddr | pending |
| sctp_bench_test.go | BenchmarkToRawSockAddrBuf | pending |
| sctp_bench_test.go | BenchmarkDial | pending |
| sctp_bench_test.go | BenchmarkTransportEcho | pending |
| sctp_bench_test.go | BenchmarkConcurrentEcho | pending |
| sctp_bindx_test.go | TestNormalizeDynamicBindAddr | retired: BindAdd and BindRemove take netip.Addr values and always use the bound port (packed with port 0, which Linux reads as the bound port), so there is no caller port to normalise or compare; the argument refusals that remain (no address, the zero netip.Addr, the wrong family) are pinned by TestNilAddressesReturnErrors and TestListenerBindAddRemoveRefreshesAddr |
| sctp_bindx_test.go | TestRemovesEveryLocalAddress | ported → TestRemovesEveryLocalAddress (listener_linux_test.go), over netip.Addr: IPv4 in mapped and plain form compares equal, zones stay distinct, and the unspecified address counts as every address |
| sctp_bindx_test.go | FuzzDynamicBindAddressPreparation | ported → FuzzBindxAddrs (listener_linux_test.go): arbitrary addresses are refused with EINVAL or packed as whole entries with port 0, and the set comparison accepts anything |
| sctp_bindx_test.go | TestListenerBindAddRemoveRefreshesAddr | ported → TestListenerBindAddRemoveRefreshesAddr (listener_linux_test.go) |
| sctp_bindx_test.go | TestSCTPConnBindAddRemoveRefreshesLocalAddr | ported → TestConnectedBindAddRemoveUpdatesPeerAddressReadback (listener_linux_test.go): a Conn is always connected now, and its LocalAddr snapshot is association-scoped, so the refresh is asserted on an ASCONF association, where a BindAdd reaches the association |
| sctp_bindx_test.go | TestConcurrentListenerBindAddKeepsCacheInSync | ported → TestConcurrentListenerBindAddKeepsCacheInSync (listener_linux_test.go) |
| sctp_bindx_test.go | TestConnectedBindAddRemoveUpdatesPeerAddressReadback | ported → TestConnectedBindAddRemoveUpdatesPeerAddressReadback (listener_linux_test.go) |
| sctp_cause_test.go | TestAssocChangeErrorIsDecodedFromNetworkOrder | ported → TestAssocChangeErrorIsDecodedFromNetworkOrder (notification_test.go), unchanged in substance: sac_error is still read big-endian, only the decoded field's type changed (raw uint16 → ErrorCause) |
| sctp_cause_test.go | TestRemoteErrorErrorIsDecodedFromNetworkOrder | ported → TestRemoteErrorErrorIsDecodedFromNetworkOrder (notification_test.go), same property (sre_error read big-endian) |
| sctp_cause_test.go | TestSendFailedErrorIsDecodedFromNetworkOrder | ported → TestSendFailedErrorIsDecodedFromNetworkOrder (notification_test.go); the fixture now targets ssf_error of struct sctp_send_failed_event (v2's SendFailed, RFC 6458 §6.1.11), not the legacy struct sctp_send_failed this package does not decode, but causeFromU32's promotion-and-swap behaviour is identical |
| sctp_cause_test.go | TestPeerAddrChangeErrorStaysHostOrder | ported → TestAddrChangeReasonDecoding (notification_test.go); v1 asserted the raw spc_error stayed host-order and unconverted, v2 additionally decodes it into a named AddrChangeReason, which the new test's table covers, spc_error's own host-order-ness among them |
| sctp_cause_test.go | TestErrorCauseStringNamesTheRFCCauses | ported → TestErrorCauseIANANames (enums_test.go); the expected names changed from v1's own SCTP_ERROR_* constant spelling to the IANA "SCTP Error Cause Codes" registry names |
| sctp_cause_test.go | TestAbortReportsTheUserAbortCause | pending: exercises a live association (Abort + a real SCTP_COMM_LOST read) and so is not a portable test; the property (a real ABORT's cause decodes correctly end to end) is left for whichever task ports v1's live-kernel notification tests or adds wire-level proof of cause decoding |
| sctp_cause_test.go | TestParsesTheEventsStreamReconfigurationNeeds | ported → TestParseNotificationStreamReset, TestParseNotificationAssocReset, TestParseNotificationStreamChange, TestParseNotificationSendFailed, TestParseNotificationAuthEvent (notification_test.go), split one per event type instead of one table of subtests |
| sctp_cause_test.go | TestNewNotificationsRejectTruncation | ported → folded into TestParseNotificationRejectsTruncated (notification_test.go), which now covers all twelve notification types in one table instead of two overlapping tests |
| sctp_cause_test.go | TestNotificationTypeNumbersMatchTheKernel | ported → TestEnumerationValues (its EventType rows; enums_test.go); its SCTP_SN_TYPE_BASE row retired: 0x8000 is never a real notification on the wire (it is SCTP_DATA_IO_EVENT, a subscription-only pseudo-type from the deprecated EventSubscribe bitmask), so EventType names nothing at it |
| sctp_cause_test.go | TestNotificationPPIDIsConvertedToHostOrder | ported → TestNotificationPPIDIsConvertedToHostOrder (notification_test.go); only the SendFailed (formerly SendFailedEvent) case remains, since v2 does not implement the legacy SCTP_SEND_FAILED/SndRcvInfo path the other v1 subtest covered |
| sctp_cause_test.go | TestParseNotificationRejectsADeclaredLengthItDoesNotHave | ported → TestParseNotificationBoundsByDeclaredLength (notification_test.go), same subtests (declared longer than present, a variable tail that did not all arrive, declared exactly what is present, declared shorter than present) plus one more for the NotificationReassemblyLimit bound |
| sctp_close_fuzz_test.go | FuzzCloseWithTimeout | ported → FuzzLifecycleClose (close_test.go) for the state machine: for every grace period, including zero, negative and sub-microsecond ones, close returns, releases the descriptor exactly once and leaves every later call reporting net.ErrClosed, now also with scripted status polls, failing steps and an Abort during the wait; the half that needs a live socket (checking that the descriptor is really closed) stays pending until the Linux close path exists |
| sctp_close_fuzz_test.go | TestCloseTimeoutZeroIsImmediate | ported → TestLifecycleCloseNonPositiveGraceAborts (close_test.go) for the state machine: a zero or negative grace goes straight to the abortive close, with no SHUTDOWN, poll or wait; the half that needs a live socket stays pending until the Linux close path exists |
| sctp_close_fuzz_test.go | TestCloseSubMicrosecondTimeout | ported → TestLifecycleCloseSubMicrosecondGrace (close_test.go); the timeval conversion it guarded no longer exists (the wait is a timer), so the property is that a grace below the first 200 µs backoff step still bounds the one wait and ends in the abortive close |
| sctp_close_fuzz_test.go | TestCloseChurnUnderLoad | pending |
| sctp_close_fuzz_test.go | TestCloseRacesWithReadAndWrite | pending |
| sctp_close_fuzz_test.go | TestAbortDoesNotWait | ported → TestLifecycleAbortFromOpenDoesNotWait (close_test.go) for the state machine: an Abort from open starts no SHUTDOWN, polls nothing and never waits; the half that needs a live socket (against an already aborted peer) stays pending until the Linux close path exists |
| sctp_close_fuzz_test.go | TestPeelOffRacesWithClose | pending |
| sctp_close_fuzz_test.go | TestClosingAPeeledConnectionShutsDownGracefully | pending |
| sctp_close_fuzz_test.go | TestClosingBackpressuredPeeledConnectionRetriesEOF | pending |
| sctp_close_test.go | TestDialUnderChurnReportsEISCONN | ported → TestRapidDialAbortCyclesSucceed (dial_linux_test.go), with a changed invariant: a fresh non-blocking socket never reports EISCONN, so no dial may fail except with ECONNREFUSED (a full backlog) or ECONNRESET (the listener's ABORT arriving before the dial looked), which are counted and logged |
| sctp_close_test.go | TestCloseReleasesFdZero | ported → TestCloseReleasesFdZero (close_linux_test.go) |
| sctp_close_test.go | TestAbortReleasesFdZero | ported → TestAbortReleasesFdZero (close_linux_test.go) |
| sctp_close_test.go | TestCloseDoesNotLeakDescriptors | ported → TestCloseDoesNotLeakDescriptors (close_linux_test.go) |
| sctp_close_test.go | TestCloseReleasesPortForRebind | ported → TestCloseReleasesPortForRebind (close_linux_test.go) |
| sctp_close_test.go | TestCloseWithUnreachablePeerReturnsWithinTimeout | ported → TestCloseWithUnreachablePeerReturnsWithinTimeout (close_linux_test.go) |
| sctp_close_test.go | TestDoubleCloseReturnsNetErrClosed | ported → TestLifecycleClosedAfterRelease (close_test.go) for the state machine, after every path that releases the descriptor, Shutdown included; the socket half is now ported → TestDoubleCloseReturnsNetErrClosed (close_linux_test.go) |
| sctp_close_test.go | TestCloseOnNilConn | ported → TestNilPublicReceiversReturnErrors (socket_linux_test.go), which covers Close, Abort and every other method on a nil *Conn |
| sctp_close_test.go | TestConcurrentCloseAndAbort | ported → TestLifecycleConcurrentCloseAndAbort (close_test.go), with a changed invariant: an Abort that arrives while a Close waits now overtakes it and both return nil, so "exactly one caller succeeds" became "the descriptor is released exactly once, at most one Close succeeds, and if none does exactly one Abort did"; TestLifecycleConcurrentClose, TestLifecycleConcurrentAbortsDuringClose and TestLifecycleAbortiveCloseIsExclusive cover the other pairings; the socket half is now ported → TestConcurrentCloseAndAbort (close_linux_test.go), with the same changed invariant |
| sctp_close_test.go | TestCloseDuringBlockedRead | ported → TestCloseReleasesParkedReaderAndWriter (close_linux_test.go), which now asserts the outcome (net.ErrClosed within a second of Close returning, on dialed and accepted connections) instead of only that the read returned |
| sctp_close_test.go | TestCloseDuringWrite | ported → TestCloseReleasesParkedReaderAndWriter (close_linux_test.go), with the writer parked on a full send buffer |
| sctp_close_test.go | TestCloseAfterCompletedHandshakeGivesPeerEOF | ported → TestCloseAfterCompletedHandshakeGivesPeerEOF (close_linux_test.go) |
| sctp_cmsgbuild_test.go | TestBuildSndRcvCmsgMatchesLegacy | retired: it pinned buildSndRcvCmsg's bytes against the deprecated SCTP_SNDRCV struct (struct sctp_sndrcvinfo), which the package no longer builds at all — SendOptions encodes only SCTP_SNDINFO, SCTP_PRINFO and SCTP_AUTHINFO (RFC 6458 §5.3.2 deprecates SCTP_SNDRCV in favor of them) |
| sctp_cmsgbuild_test.go | TestBuildSndRcvCmsgHeader | ported → TestAppendSendCmsgsEncodesSndInfo, TestAppendSendCmsgsAllThreeFitsSndCmsgSpaceExactly (msginfo_test.go), for SCTP_SNDINFO's own cmsg_level/cmsg_type in place of the retired SCTP_SNDRCV's |
| sctp_cmsgbuild_test.go | TestBuildSndRcvCmsgOffsetsMatchStruct | ported → TestCmsgStructLayouts (abi_test.go, pinning sndInfoStreamOff etc. directly) and TestAppendSendCmsgsAllThreeFitsSndCmsgSpaceExactly, TestCmsgFormulaAcrossWordSizes (msginfo_test.go, pinning the CMSG_SPACE total), for the SNDINFO/PRINFO/AUTHINFO layout in place of SndRcvInfo's |
| sctp_cmsgbuild_test.go | TestBuildSndRcvCmsgRoundTripsThroughParser | retired: the deprecated SCTP_SNDRCV cmsg it round-tripped served both directions at once; the non-deprecated API splits that into SCTP_SNDINFO (send) and SCTP_RCVINFO (receive), two distinct wire records with no shared struct to round-trip through one parser — TestAppendSendCmsgsEncodesSndInfo and TestParseRecvCmsgsFillsRcvInfo (msginfo_test.go) pin each direction's own byte layout separately |
| sctp_cmsgbuild_test.go | TestParseSndRcvInfoDoesNotAliasInput | retired: it guarded against parseSndRcvInfo returning a *SndRcvInfo that aliased the read buffer. RcvInfo and NxtInfo are returned by value inside MsgInfo, not by a pointer into the read buffer, so a decoded record cannot alias its source buffer by construction — the same reasoning that retired TestResolveFromRawAddrDoesNotAliasBuffer for netip.Addr |
| sctp_cmsgbuild_test.go | TestAncillaryParsersIgnoreShortSCTPPayloads | ported → TestParseRecvCmsgsIgnoresShortPayloads (msginfo_test.go), for RCVINFO/NXTINFO in place of the retired SCTP_SNDRCV/RCVINFO/NXTINFO trio |
| sctp_cmsgbuild_test.go | FuzzAncillaryParsers | ported → FuzzParseRecvCmsgs (msginfo_test.go), for RCVINFO/NXTINFO; SCTP_SNDRCV is retired and appendSendCmsgs is an encoder with a fixed-size destination, not a decoder of untrusted bytes, so it is not itself a fuzz target |
| sctp_cmsgbuild_test.go | TestParseSndRcvInfoPrefersSndRcvOverRcvInfo | retired: it pinned that the deprecated SCTP_SNDRCV wins when both it and SCTP_RCVINFO are present in one buffer. SCTP_SNDRCV is retired, so SCTP_RCVINFO is the only per-message receive-info record parseRecvCmsgs looks for and there is no precedence left to test |
| sctp_cmsgbuild_test.go | TestSCTPReadInfoSurvivesLaterReads | retired: it guarded against a pooled oob buffer clobbering an earlier read's *SndRcvInfo. RcvInfo/NxtInfo are copied by value into the caller's own MsgInfo on every call, not referenced by a pointer into a reused buffer, so there is nothing later reuse could clobber |
| sctp_cmsgbuild_test.go | TestSCTPWriteDoesNotMutateInfo | ported → TestAppendSendCmsgsDoesNotMutateInputs (msginfo_test.go), for SndInfo/PrInfo/AuthKey in place of SndRcvInfo |
| sctp_cmsgbuild_test.go | TestSCTPWriteConcurrentSharedInfo | ported → TestAppendSendCmsgsConcurrentSharedInputs (msginfo_test.go), for SndInfo/PrInfo/AuthKey in place of SndRcvInfo |
| sctp_connect_test.go | TestDialUnderChurnSucceeds | ported → TestDialUnderChurnSucceeds (dial_linux_test.go), each dial bounded by a context |
| sctp_contract_test.go | TestReadWithZeroLengthBufferConsumesNothing | pending |
| sctp_contract_test.go | TestReadIntoFullBufferTailIsNotAConsumingRead | pending |
| sctp_contract_test.go | TestAcceptDoesNotReturnATypedNilConn | pending |
| sctp_contract_test.go | TestAcceptedConnDoesNotInheritTheAcceptDeadline | pending |
| sctp_contract_test.go | TestAbortWakesAParkedReader | pending |
| sctp_contract_test.go | TestErrorsAfterCloseWrapNetErrClosed | ported → TestSendErrorsCarryConnectionContext (send_linux_test.go) for Write and SendMsg; the read calls stay pending until Read, RecvMsg and ReadMsg exist |
| sctp_contract_test.go | TestWriteWithZeroLengthBufferIsANoOp | retired: Write no longer answers (0, nil) for an empty buffer; an SCTP message has at least one byte (RFC 9260 §6.2), so Write refuses it with EINVAL like SendMsg, pinned by TestSendEmptyRefused (send_linux_test.go) |
| sctp_contract_test.go | TestPrimaryAddrSettersRejectMultipleAddresses | pending |
| sctp_contract_test.go | TestIPv6AssociationRoundTrip | pending |
| sctp_contract_test.go | TestSetSelectReadFDUsesNativeWordSize | pending |
| sctp_crosscompile_test.go | TestCrossCompileSmoke | pending |
| sctp_deadline_test.go | TestReadDeadlineExpires | pending |
| sctp_deadline_test.go | TestReadDeadlineInThePast | pending |
| sctp_deadline_test.go | TestReadDeadlineCleared | pending |
| sctp_deadline_test.go | TestReadDeadlineDoesNotTruncateData | pending |
| sctp_deadline_test.go | TestReadMsgDeadlineBoundsWholeCall | pending |
| sctp_deadline_test.go | TestWriteDeadlineInThePast | ported → TestWriteDeadlineInThePast (send_linux_test.go), for Write, SendMsg and a NoWait send, with no sendmsg call made |
| sctp_deadline_test.go | TestSetDeadlineSetsBoth | ported → TestSetDeadlineSetsBoth (send_linux_test.go); its read half reads through SyscallConn until Read exists |
| sctp_deadline_test.go | TestDeadlineSetFromAnotherGoroutine | pending |
| sctp_deadline_test.go | TestWriteDeadlineStateIsAtomicWithPollerUpdate | retired: v1 kept a write-deadline flag that decided whether SCTPWrite waited for buffer space; every send now waits unless SendOptions.NoWait is set, and the deadline lives only in the runtime poller, so there is no state to publish |
| sctp_deadline_test.go | TestWriteDeadlineStateConcurrentSetters | retired: the write-deadline flag it raced no longer exists (see TestWriteDeadlineStateIsAtomicWithPollerUpdate) |
| sctp_dialcontext_test.go | TestDialContextAlreadyCancelledOpensNoSocket | ported → TestDialContextAlreadyCancelledOpensNoSocket (dial_linux_test.go) |
| sctp_dialcontext_test.go | TestDialContextTimeoutAbandonsTheAttempt | ported → TestDialContextTimeoutAbandonsTheAttempt (dial_linux_test.go) |
| sctp_dialcontext_test.go | TestDialContextCancelDuringDial | ported → TestDialContextCancelDuringDial (dial_linux_test.go) |
| sctp_dialcontext_test.go | TestDialContextQuietAbandonPolicyReleasesAttempt | ported → TestDialContextQuietAbandonPolicyReleasesAttempt (dial_linux_test.go), with Config.AbandonPolicy |
| sctp_dialcontext_test.go | TestDialContextQuietAbandonPolicyCancelDuringDial | ported → TestDialContextQuietAbandonPolicyCancelDuringDial (dial_linux_test.go) |
| sctp_dialcontext_test.go | TestDialContextInvalidAbandonPolicyOpensNoSocket | ported → TestDialContextInvalidAbandonPolicyOpensNoSocket (dial_linux_test.go); the refusal now also names Config.AbandonPolicy |
| sctp_dialcontext_test.go | TestDialContextAbandonedAttemptsLeakNothing | ported → TestDialContextAbandonedAttemptsLeakNothing (dial_linux_test.go) |
| sctp_dialcontext_test.go | TestDialContextSucceeds | ported → TestDialContextSucceeds (dial_linux_test.go) |
| sctp_dialcontext_test.go | TestDialContextReturnsPollableDescriptor | ported → TestDialContextReturnsPollableDescriptor (dial_linux_test.go), which also checks that the dial's context left no deadline on the socket |
| sctp_dialcontext_test.go | TestDialContextRefusedPeerReportsTheError | ported → TestDialContextRefusedPeerReportsTheError (dial_linux_test.go), now asserting ECONNREFUSED inside a *net.OpError with Op dial |
| sctp_dialcontext_test.go | TestSocketConfigDialContext | ported → TestSocketConfigDialContext (dial_linux_test.go), with Config.Control |
| sctp_dialpolicy_test.go | TestAbandonDialSocketUsesPolicy | ported → TestAbandonDialUsesPolicy (dial_linux_test.go), against closeOps; the out-of-range policy case moved to validation (TestDialContextInvalidAbandonPolicyOpensNoSocket, and prepare's own tests) |
| sctp_eintr_test.go | TestReadSurvivesSignals | pending |
| sctp_eintr_test.go | TestAcceptSurvivesSignals | pending |
| sctp_eintr_test.go | TestGracefulCloseSurvivesSignals | pending |
| sctp_eintr_test.go | TestDialNeverReturnsAnUnestablishedAssociation | ported → TestDialNeverReturnsAnUnestablishedAssociation (send_linux_test.go), with Write as the probe and SCTP_STATUS read directly; EINTR on sends is pinned by TestSendRetriesEINTR and TestSendSurvivesSignals |
| sctp_eintr_test.go | TestSCTPReadRetriesEINTRDeterministically | pending |
| sctp_eintr_test.go | TestSCTPReadRetriesEINTRUnderLoad | pending |
| sctp_eintr_test.go | TestCloseTerminatesPromptlyUnderSignals | pending |
| sctp_endpoint_linux_test.go | TestSCTPEndpointSetDeadlineAppliesToReceiveAndSend | pending |
| sctp_endpoint_linux_test.go | TestSCTPEndpointRejectsZeroLengthMessagesWithAncillaryData | pending |
| sctp_endpoint_linux_test.go | TestSCTPEndpointRoundTripAndPeelOffOwnership | pending |
| sctp_endpoint_linux_test.go | TestSCTPEndpointCreatesAndRoutesMultipleAssociations | pending |
| sctp_endpoint_linux_test.go | TestSCTPEndpointAssociationIDsGrowsItsBoundedBuffer | pending |
| sctp_endpoint_linux_test.go | TestSCTPEndpointErrorsDeadlinesAndCloseWakeup | pending |
| sctp_endpoint_linux_test.go | TestSCTPEndpointControlFailureReleasesOwnedDescriptor | pending |
| sctp_endpoint_linux_test.go | TestSCTPEndpointRawAccessDynamicBindAndEndpointOptions | pending |
| sctp_endpoint_linux_test.go | TestSCTPEndpointAssociationLifecycleLeavesOtherAssociationsOpen | pending |
| sctp_endpoint_linux_test.go | TestSCTPEndpointCloseGracefullyTerminatesEveryAssociation | pending |
| sctp_endpoint_linux_test.go | TestNilSCTPEndpointMethodsReportClosed | pending |
| sctp_endpoint_linux_test.go | TestSCTPEndpointDuplicateConnectIsNotReportedAsANewAssociation | pending |
| sctp_endpoint_linux_test.go | TestSocketConfigEndpointOrderAndRequiredMetadata | pending |
| sctp_endpoint_linux_test.go | TestSCTPEndpointFragmentsHandlerReentryAndMissingMetadata | pending |
| sctp_endpoint_linux_test.go | TestSCTPEndpointHandlerReassemblesNotificationWithTinyBuffer | pending |
| sctp_endpoint_portable_test.go | TestErrUnsupportedWrapsStdlibSentinel | ported → TestErrUnsupportedMatchesStdlib (errors_test.go) |
| sctp_endpoint_portable_test.go | TestAssociationIDFromIntRejectsWidthAliasing | pending |
| sctp_endpoint_portable_test.go | TestValidEndpointAssociationID | pending |
| sctp_endpoint_portable_test.go | TestSCTPEndpointNetwork | pending |
| sctp_endpoint_portable_test.go | TestDecodeRcvInfoPayloadCopiesAndConvertsEveryField | pending |
| sctp_endpoint_portable_test.go | TestDecodeRcvInfoPayloadBoundaries | pending |
| sctp_endpoint_portable_test.go | FuzzDecodeRcvInfoPayload | pending |
| sctp_endpoint_portable_test.go | TestDecodeAssociationIDsPayload | pending |
| sctp_endpoint_portable_test.go | TestDecodeAssociationIDsPayloadRejectsMalformedLists | pending |
| sctp_endpoint_portable_test.go | FuzzDecodeAssociationIDsPayload | pending |
| sctp_endpoint_test.go | TestParseRcvInfoEnvelopeAndPayloadBoundaries | pending |
| sctp_endpoint_test.go | TestParseRcvInfoRejectsDuplicateItems | pending |
| sctp_endpoint_test.go | TestParseRcvInfoRejectsReservedAssociationIDs | pending |
| sctp_endpoint_test.go | FuzzParseRcvInfo | pending |
| sctp_eor_test.go | TestSCTPReadFlagsReportsTruncation | pending |
| sctp_eor_test.go | TestSCTPReadLosesTruncationSignal | pending |
| sctp_eor_test.go | TestReadMsgReassembles | pending |
| sctp_eor_test.go | TestReadMsgRespectsMax | pending |
| sctp_eor_test.go | TestReadMsgRejectsNonPositiveMax | pending |
| sctp_eor_test.go | TestMsgEORMatchesKernel | pending |
| sctp_eor_test.go | TestWrappedConnZeroesInfoWhenAbsent | pending |
| sctp_eor_test.go | TestEverySendIsACompleteRecord | pending |
| sctp_error_contract_linux_test.go | TestDialErrorCarriesOperationAndAddresses | pending |
| sctp_error_contract_linux_test.go | TestDialWrapsForeignOperationError | pending |
| sctp_error_contract_linux_test.go | TestDialPreservesMatchingOperationError | pending |
| sctp_error_contract_linux_test.go | TestListenErrorCarriesOperationAndAddress | pending |
| sctp_error_contract_linux_test.go | TestDialContextErrorCarriesOperationAndAddresses | pending |
| sctp_error_contract_linux_test.go | TestAcceptErrorCarriesListenerContext | pending |
| sctp_error_contract_linux_test.go | TestNetConnIOErrorsCarryConnectionContext | ported → TestSendErrorsCarryConnectionContext (send_linux_test.go) for the write half; the read half stays pending until Read exists |
| sctp_error_contract_linux_test.go | TestNetConnIOErrorsPreserveExplicitNetwork | ported → TestSendErrorsCarryConnectionContext/sctp4 (send_linux_test.go) for the write half; the read half stays pending until Read exists |
| sctp_error_contract_linux_test.go | TestClosedNetConnErrorsRetainConnectionContext | ported → TestSendErrorsCarryConnectionContext (send_linux_test.go) for the write half; the read half stays pending until Read exists |
| sctp_error_contract_linux_test.go | TestNetConnGracefulCloseReturnsDirectEOF | pending |
| sctp_error_contract_linux_test.go | TestClosedListenerAcceptErrorRetainsListenerContext | pending |
| sctp_error_contract_linux_test.go | TestRawConnectErrorRemainsUnwrapped | pending |
| sctp_error_contract_test.go | TestClosedOperationErrorRetainsNetErrorContract | pending |
| sctp_event_test.go | TestEventStructMatchesKernel | pending |
| sctp_event_test.go | TestSubscribeEventRoundTrip | pending |
| sctp_event_test.go | TestSubscribeEventScopeOnConnectedSocket | pending |
| sctp_event_test.go | TestSubscribeEventVisibleInBulkBeforeConnect | pending |
| sctp_event_test.go | TestSubscribeEventRejectsUnknownType | pending |
| sctp_event_test.go | TestSubscribeEventOnClosedConn | pending |
| sctp_event_test.go | TestSetRecvInfoOptions | pending |
| sctp_extensions_test.go | TestDefaultSndInfoRoundTrip | ported → TestDefaultInfoRoundTrip (send_linux_test.go) |
| sctp_extensions_test.go | TestDefaultSndInfoRejectsShortOption | ported → TestDefaultInfoRoundTrip (send_linux_test.go): a 12-byte SCTP_DEFAULT_SNDINFO is still refused with EINVAL |
| sctp_extensions_test.go | TestAutoAsconfNeedsBoundSocket | pending |
| sctp_extensions_test.go | TestPrSupportedFollowsSysctl | pending |
| sctp_extensions_test.go | TestDefaultPrInfoRoundTrip | ported → TestDefaultInfoRoundTrip (send_linux_test.go) |
| sctp_extensions_test.go | TestPrPolicyConstantValues | ported → TestEnumerationValues (its PR-policy, stream-reset-mask and HMAC rows; enums_test.go); its SCTP_ENABLE_STRRESET_MASK completeness check has no v2 row of its own — StreamResetMask only names the three bits the mask actually carries |
| sctp_extensions_test.go | TestOptionNumbersMatchHeader | ported → TestOptionNumbers (abi_test.go); its SCTP_PEER_ADDR_THLDS, SCTP_SOCKOPT_PEELOFF and SCTP_SOCKOPT_CONNECTX rows retired: v2 uses only SCTP_PEER_ADDR_THLDS_V2, SCTP_SOCKOPT_PEELOFF_FLAGS and SCTP_SOCKOPT_CONNECTX3, so the superseded option numbers are never defined |
| sctp_extensions_test.go | TestAssocIDAndSinfoConstantsMatchHeader | ported → TestAssocScopeSelectors (abi_test.go); its SCTP_NOTIFICATION == MSG_NOTIFICATION row has no v2 counterpart, see TestAssocScopeSelectors's doc comment |
| sctp_extensions_test.go | TestDefaultPrInfoRejectsUnknownPolicy | ported → TestDefaultInfoRoundTrip (send_linux_test.go): the package now refuses the policy before any system call |
| sctp_extensions_test.go | TestPrStreamStatusNeedsAssociation | pending |
| sctp_extensions_test.go | TestPrAssocStatus | pending |
| sctp_extensions_test.go | TestPeerAddrThldsV2RoundTrip | pending |
| sctp_extensions_test.go | TestReconfigSupportedNegotiates | pending |
| sctp_extensions_test.go | TestEnableStreamResetRoundTrip | pending |
| sctp_extensions_test.go | TestAddStreams | pending |
| sctp_extensions_test.go | TestPeerAddrThldsRoundTrip | pending |
| sctp_extensions_test.go | TestAssocStatsCountsTraffic | pending |
| sctp_extensions_test.go | TestAssocStatsNeedsAssociation | pending |
| sctp_extensions_test.go | TestAuthDisabledReportsEACCES | pending |
| sctp_extensions_test.go | TestAuthEnabledRoundTrip | pending |
| sctp_extensions_test.go | TestParseHmacIdents | pending |
| sctp_extensions_test.go | TestParseAuthChunks | pending |
| sctp_extensions_test.go | TestPeerAuthChunksNeedsAssociation | pending |
| sctp_fdleak_test.go | TestSetupFailureReleasesDescriptor | ported → TestSetupFailureReleasesDescriptor (socket_linux_test.go) |
| sctp_fdleak_test.go | TestListenSuccessDoesNotReleaseDescriptor | ported → TestListenSuccessDoesNotReleaseDescriptor (socket_linux_test.go) |
| sctp_fdleak_test.go | TestFileListenerDoesNotLeakDescriptors | ported → TestFileListenerDoesNotLeakDescriptors (file_linux_test.go) |
| sctp_fragment_test.go | TestMessagesAcrossTheFragmentationPoint | pending |
| sctp_fragment_test.go | TestFragmentedMessageReportsEORCorrectly | pending |
| sctp_hardening_test.go | TestAcceptedAssociationIsCloseOnExec | pending |
| sctp_hardening_test.go | TestListenDoesNotMutateItsAddr | pending |
| sctp_hardening_test.go | TestDialDoesNotMutateItsAddr | pending |
| sctp_hardening_test.go | TestUnknownNetworkIsRejected | pending |
| sctp_hardening_test.go | TestEmptyNetworkDoesNotPanic | pending |
| sctp_hardening_test.go | TestUnknownNetworkErrorIsTheStandardType | pending |
| sctp_hardening_test.go | TestReadMsgSkipsNotifications | pending |
| sctp_hardening_test.go | TestReadWithoutDeadlineWaitsForData | pending |
| sctp_hardening_test.go | TestReadWithDeadlineStillReportsTheDeadline | pending |
| sctp_kernelpaths_test.go | TestNxtInfoLayoutMatchesKernel | pending |
| sctp_kernelpaths_test.go | TestSCTPReadNextInfoReportsTheQueuedMessage | pending |
| sctp_kernelpaths_test.go | TestSCTPReadNextInfoIsNilWithoutTheOption | pending |
| sctp_kernelpaths_test.go | TestSetPrimaryPeerAddrSelectsThePath | pending |
| sctp_kernelpaths_test.go | TestSetPeerPrimaryAddrNeedsAsconf | pending |
| sctp_kernelpaths_test.go | TestPeelOffSucceedsOnAOneToManySocket | pending |
| sctp_kernelpaths_test.go | TestReconfigurationEventsDecodeFromKernelBytes | pending |
| sctp_kernelpaths_test.go | TestStreamChangeReportsAddedStreamsNotTheNewWidth | pending |
| sctp_kernelpaths_test.go | TestStreamChangeReportsDeniedWhenThePeerRefuses | pending |
| sctp_layout_test.go | TestStructLayoutsMatchKernel | ported → TestCmsgStructLayouts, TestOptionStructLayouts, TestSockaddrStorageOptionLayouts, TestKernel64Layouts, TestSockaddrStorageLayoutFormula (abi_test.go); its EventSubscribe subtest retired: this package does not implement SCTP_EVENTS, the deprecated RFC 6458 mechanism it configures. Its AssocStats subtest is only half covered by that port: the layout-pinning half (assocStatsCounters, assocStatsSize) moved to TestSockaddrStorageOptionLayouts/TestKernel64Layouts, but the decoding half (AssocStats.unmarshal against a hand-built buffer) stays pending until the exported AssocStats type and its unmarshal method exist |
| sctp_linux_test.go | TestNotificationHandlerAssignmentOnDialing | pending |
| sctp_linux_test.go | TestNotificationHandlerAssignmentOnListening | pending |
| sctp_linux_test.go | TestDialUseControlFuncWithoutLocalAddress | pending |
| sctp_linux_test.go | TestListenUseControlFuncWithoutLocalAddress | pending |
| sctp_linux_test.go | TestSyscallConn | pending |
| sctp_linux_test.go | TestSCTPListenerNameFromFd | pending |
| sctp_linux_test.go | TestListenerSurvivesGCAfterFileListener | pending |
| sctp_listener_test.go | TestListenerDoubleCloseDoesNotCloseRecycledFd | ported → TestListenerDoubleCloseDoesNotCloseRecycledFd (listener_linux_test.go) |
| sctp_listener_test.go | TestListenerCloseIsIdempotent | ported → TestListenerCloseIsIdempotent (listener_linux_test.go) |
| sctp_listener_test.go | TestListenerConcurrentClose | ported → TestListenerConcurrentClose (listener_linux_test.go) |
| sctp_listener_test.go | TestListenerCloseUnblocksAccept | ported → TestListenerCloseUnblocksAccept (listener_linux_test.go) |
| sctp_listener_test.go | TestListenerAcceptAfterCloseFails | ported → TestListenerAcceptAfterCloseFails (listener_linux_test.go) |
| sctp_maxseg_test.go | TestAssocValueLayoutMatchesKernel | pending |
| sctp_maxseg_test.go | TestMaxSegSizeRoundTrip | pending |
| sctp_maxseg_test.go | TestMaxSegSizeRejectsOutOfRange | pending |
| sctp_maxseg_test.go | TestMaxSegSizeRejectsClosedConn | pending |
| sctp_multiclient_test.go | TestManyClientsConcurrentEcho | pending |
| sctp_multiclient_test.go | TestManyClientsHeldOpenSimultaneously | pending |
| sctp_multiclient_test.go | TestManyClientsDistinctAssociationIDs | pending |
| sctp_multiclient_test.go | TestManyClientsPerConnectionDeadlineIsolation | pending |
| sctp_multiclient_test.go | TestManyClientsStreamsStayPerAssociation | pending |
| sctp_multiclient_test.go | TestManyClientsCloseDoesNotDisturbPeers | pending |
| sctp_multiclient_test.go | TestManyClientsNotificationsCarryAssociationID | pending |
| sctp_multiclient_test.go | TestDoubleCloseDoesNotReleaseAReusedDescriptor | pending |
| sctp_multihome_test.go | TestMultihomedAssociationExchangesAddresses | ported → TestMultihomedAssociationExchangesAddresses (listener_linux_test.go), checking the live queries and the snapshots |
| sctp_multihome_test.go | TestMultihomedListenerAcceptsEveryBoundAddress | ported → TestMultihomedListenerAcceptsEveryBoundAddress (listener_linux_test.go) |
| sctp_multihome_test.go | TestMultihomedListenerServesManyPeers | ported → TestMultihomedListenerServesManyPeers (listener_linux_test.go) |
| sctp_multihome_test.go | TestMultihomedBindRejectsAnUnusableAddress | ported → TestMultihomedBindRejectsAnUnusableAddress (listener_linux_test.go) |
| sctp_netconn_contract_test.go | TestNetConnPendingReadObservesLaterDeadline | pending |
| sctp_netconn_contract_test.go | TestSCTPListenerPendingAcceptObservesLaterDeadline | pending |
| sctp_netconn_contract_test.go | TestNetConnWriteWaitsForBufferSpace | ported → TestSendWaitsForBufferSpace (send_linux_test.go): "deadline set while waiting" and "Close" |
| sctp_netconn_contract_test.go | TestNetConnDeadlineSettersAfterClose | pending |
| sctp_netconn_contract_test.go | TestNetConnAddressesRemainStableAfterClose | pending |
| sctp_netconn_contract_test.go | TestNetConnZeroLengthClosedParity | pending |
| sctp_nil_linux_test.go | TestFileListenerRejectsNilFile | ported → TestFileListenerRejectsNilFile (file_linux_test.go), now an error matching EINVAL |
| sctp_nil_linux_test.go | TestZeroValueConnectionNeverOwnsDescriptorZero | ported → TestZeroValueConnectionNeverOwnsDescriptorZero (close_linux_test.go); a zero Conn reports net.ErrClosed without touching descriptor 0, in-process since nothing in it can close stdin; the owned-descriptor-0 half is TestCloseReleasesFdZero and TestAbortReleasesFdZero, since NewSCTPConn(fd) no longer exists |
| sctp_nil_linux_test.go | TestNewSCTPConnSetsCloseOnExec | ported → TestDescriptorsAreNonBlockingAndCloseOnExec (socket_linux_test.go), over every way the package comes to own a descriptor: listen, dial, accept, FileConn and FileListener |
| sctp_nil_linux_test.go | TestCloseOnExecRunsUnderForkLock | retired: every descriptor the package owns is created close-on-exec atomically (socket and accept4 with SOCK_CLOEXEC, F_DUPFD_CLOEXEC for adoption), so there is no window for a ForkLock to close and closeOnExecUnderForkLock no longer exists; TestDescriptorsAreNonBlockingAndCloseOnExec pins the flag itself |
| sctp_nil_test.go | TestNilPublicReceiversReturnErrors | ported → TestNilPublicReceiversReturnErrors (socket_linux_test.go) for the methods that exist so far; Read and Write join it with the send and receive paths |
| sctp_nil_test.go | TestNilWrappedConnDoesNotPanic | retired: SCTPSndRcvInfoWrappedConn does not exist in the redesigned API |
| sctp_nil_test.go | TestNilSocketOptionArgumentsReturnEINVAL | pending |
| sctp_nil_test.go | TestNilAddressesReturnErrors | ported → TestNilAddressesReturnErrors (socket_linux_test.go): Dial without a remote address or without an IP, and BindAdd/BindRemove with no or a zero address, refused with EINVAL |
| sctp_nil_test.go | TestNilDialContextReturnsEINVAL | ported → TestNilDialContextReturnsEINVAL (socket_linux_test.go) |
| sctp_notification_kernel_test.go | TestParseNotificationAgainstKernel | pending |
| sctp_notification_kernel_test.go | TestNotificationHandlerReassemblesKernelNotification | pending |
| sctp_notification_kernel_test.go | TestRawNotificationReadPreservesFragments | pending |
| sctp_notification_kernel_test.go | TestSendFailedEventExceedsNotificationMaxSize | pending |
| sctp_notification_test.go | TestTypedNilNotificationAccessorsReturnZero | ported → TestUnknownNotificationTypeNilReceiver (notification_test.go), narrowed to the one type it still matters for: v2 drops v1's Flags()/Length() accessors, and twelve of the thirteen concrete types' Type methods return a fixed constant without ever touching the receiver, so a typed nil is safe by construction and needs no test; UnknownNotification is the exception, since its Type reads the notification type out of Data itself, so it is the one that needs, and gets, an explicit nil guard |
| sctp_notification_test.go | TestNotificationSizesMatchKernel | ported → TestNotificationStructLayouts (abi_test.go); its legacy sctp_send_failed (SndRcvInfo-based) row has no v2 counterpart — this package does not implement the deprecated SCTP_SEND_FAILED, replaced by SendFailed (RFC 6458 §6.1.11's SCTP_SEND_FAILED_EVENT) |
| sctp_notification_test.go | TestNotificationMaxSizeHoldsEveryFixedNotification | ported → TestNotificationMaxSizeHoldsEveryFixedNotification (notification_test.go), same name and property |
| sctp_notification_test.go | TestNotificationAccumulator | ported → TestNotificationAccumulator (notification_test.go), same name; adds a byte-at-a-time fragmentation subtest and a reuse-across-records subtest (JDK-8261601) |
| sctp_notification_test.go | FuzzNotificationAccumulator | ported → FuzzNotificationAccumulator (notification_test.go), same name and property |
| sctp_notification_test.go | TestParseNotificationRejectsTruncated | ported → TestParseNotificationRejectsTruncated (notification_test.go), extended to all twelve notification types (see sctp_cause_test.go's TestNewNotificationsRejectTruncation row) |
| sctp_notification_test.go | TestParseNotificationBoundsByDeclaredLength | ported → TestParseNotificationBoundsByDeclaredLength (notification_test.go), same name and subtests, plus the NotificationReassemblyLimit bound |
| sctp_notification_test.go | TestParseNotificationAssocChange | ported → TestParseNotificationAssocChange (notification_test.go), same name and property |
| sctp_notification_test.go | TestParseNotificationCopiesTrailingData | ported → TestParseNotificationCopies (notification_test.go); the required v2 ownership test name, generalised from AssocChange.Info alone to every byte-slice field every type carries (RemoteError.Data, SendFailed.Data, UnknownNotification.Data) plus StreamReset.Streams |
| sctp_notification_test.go | TestParseNotificationPartialDeliveryFieldOrder | ported → TestParseNotificationPartialDeliveryFieldOrder (notification_test.go), same name and property; its Indication assertion has no v2 counterpart since PartialDelivery no longer carries that field (the kernel defines only one indication value, SCTP_PARTIAL_DELIVERY_ABORTED) |
| sctp_notification_test.go | TestParseNotificationPeerAddrChange | ported → TestParseNotificationPeerAddrChange (notification_test.go), extended with AF_INET, mapped-AF_INET6 and genuine-AF_INET6 subtests through sockaddr.go's decodeAddr; the raw Addr/State/Error fields are now netip.AddrPort/AddrChangeState/AddrChangeReason, covered together with TestAddrChangeReasonDecoding |
| sctp_notification_test.go | TestParseNotificationUnknownType | ported → TestParseNotificationUnknownType (notification_test.go); v2's behaviour is the opposite of v1's — an unknown type now decodes to *UnknownNotification carrying a copy of the whole record, instead of (nil, nil), so a kernel addition is never dropped silently |
| sctp_notification_test.go | FuzzParseNotification | ported → FuzzParseNotification (notification_fuzz_test.go), same name and property, extended to check the result never aliases the input for every type that carries a byte-slice field |
| sctp_oobpool_test.go | TestPooledOobDoesNotCrossAssociations | pending |
| sctp_oobpool_test.go | TestPooledOobHoldsEveryInfoCmsgAtOnce | pending |
| sctp_oobpool_test.go | TestPooledOobSurvivesReuse | pending |
| sctp_options_test.go | TestPublicRawSockoptRoundTripAndLifecycle | pending |
| sctp_options_test.go | TestInterleavingSupportedDirectAccessors | pending |
| sctp_options_test.go | TestNoDelayValueMatchesLinuxInt | pending |
| sctp_options_test.go | TestPeerAddrParamsLayoutMatchesKernel | ported → TestOptionStructLayouts (its sctp_paddrparams/sizePathParams rows; abi_test.go) |
| sctp_options_test.go | TestPeerAddrParamsRoundTripsThroughItsPackedForm | pending |
| sctp_options_test.go | TestPeerAddrParamsRoundTripsThroughTheKernel | pending |
| sctp_options_test.go | TestGetPeerAddrInfoReportsThePath | pending |
| sctp_options_test.go | TestFeatureNegotiationOptionsRoundTrip | pending |
| sctp_options_test.go | TestAuthSupportedDoesNotNeedTheSysctl | pending |
| sctp_options_test.go | TestExposePotentiallyFailedRoundTrips | pending |
| sctp_options_test.go | TestStreamSchedulerRoundTrips | pending |
| sctp_options_test.go | TestEveryStreamSchedulerIsSelectable | pending |
| sctp_options_test.go | TestOnlyPrioAndWFQKeepAStreamValue | pending |
| sctp_options_test.go | TestBooleanSockoptsRoundTrip | pending |
| sctp_options_test.go | TestAdaptationLayerRoundTrips | pending |
| sctp_options_test.go | TestGetInitMsgReadsBackWhatWasSet | pending |
| sctp_options_test.go | TestSetInitMsgRejectsOutOfRangeValues | pending |
| sctp_options_test.go | TestPeelOffArgMatchesTheKernelABI | ported → TestOptionStructLayouts (its sctp_peeloff_flags_arg_t/sizePeeloffFlagsArg rows; abi_test.go); v2 pins the modern _FLAGS variant (associd, sd, flags) rather than v1's plain sctp_peeloff_arg_t (associd, sd), since PeelOff uses SCTP_SOCKOPT_PEELOFF_FLAGS, not the legacy SCTP_SOCKOPT_PEELOFF |
| sctp_options_test.go | TestLegacyPeelOffFDClosesOnExecBeforeReleasingForkLock | pending |
| sctp_options_test.go | TestLegacyPeelOffFDReleasesForkLockOnFailure | pending |
| sctp_options_test.go | TestPeelOffRejectsAOneToOneSocket | pending |
| sctp_options_test.go | TestSendFlagsMatchTheKernel | split and ported → TestSendFlagBits + TestPRPolicyBitsDoNotOverlapSendFlags (abi_test.go) |
| sctp_options_test.go | TestSockaddrStorageOptionLayouts | ported → TestSockaddrStorageOptionLayouts (abi_test.go, same name and structure: sctp_udpencaps, sctp_probeinterval, sctp_paddrthlds_v2 sizes now include sctp_assoc_stats' header offset too) |
| sctp_options_test.go | TestSockaddrStorageLayoutFormula | ported → TestSockaddrStorageLayoutFormula (abi_test.go, same name) |
| sctp_options_test.go | TestPeerThresholdKernelCompatLayout | pending |
| sctp_options_test.go | TestSockaddrStorageOptionsRoundTripThroughBytes | pending |
| sctp_options_test.go | TestUDPEncapsPort9899UsesNetworkByteOrder | pending |
| sctp_options_test.go | TestUDPEncapsAndProbeIntervalRoundTrip | pending |
| sctp_options_test.go | TestExposePotentiallyFailedHasNoLockedState | pending |
| sctp_options_test.go | TestWFQReordersRelativeToFCFS | pending |
| sctp_pathfailure_test.go | TestRtoInfoLayoutMatchesKernel | pending |
| sctp_pathfailure_test.go | TestAssocInfoLayoutMatchesKernel | pending |
| sctp_pathfailure_test.go | TestRtoInfoRoundTrip | pending |
| sctp_pathfailure_test.go | TestAssocInfoRoundTrip | pending |
| sctp_pathfailure_test.go | TestAssocInfoRejectsClosedConn | pending |
| sctp_pathfailure_test.go | TestUnackdataRevealsStalledSend | pending |
| sctp_preassociation_linux_test.go | TestSocketConfigPreAssociationListenerReadback | ported → TestConfigListenerReadback (listener_linux_test.go), with Config's typed fields and raw getsockopt readback; SCTP_I_WANT_MAPPED_V4_ADDR and SCTP_RECVRCVINFO are no longer Config fields (the first is left alone, the second always on, and read back as such) |
| sctp_preassociation_linux_test.go | TestSocketConfigPreAssociationRTOInfoOnDialPaths | ported → TestConfigRTOInfoOnDial (listener_linux_test.go), one dial entry point now, under both abandon policies |
| sctp_preassociation_linux_test.go | TestSocketConfigPreAssociationNegotiatesOnDialPaths | ported → TestConfigNegotiatesOnDial (listener_linux_test.go), reading each negotiated value for the association's id; message interleaving is included when net.sctp.intl_enable allows it |
| sctp_preassociation_linux_test.go | TestSocketConfigPreAssociationDelayedSACKOnEndpoints | pending |
| sctp_preassociation_linux_test.go | TestSocketConfigPreAssociationValidationPrecedesSocketAndControl | ported → TestConfigValidationPrecedesSocketAndControl (listener_linux_test.go) for Listen and Dial; the endpoint constructors join it with Endpoint |
| sctp_preassociation_linux_test.go | TestSocketConfigPreAssociationLevelTwoFailsClosedOnOneToOne | ported → TestConfigLevelTwoFailsClosedOnOneToOne (listener_linux_test.go) |
| sctp_preassociation_portable_test.go | TestWithPreAssociationSnapshotsAllMutableInputs | ported → TestPrepareCopiesSlices (config_test.go), adapted: v2's Config has no separate WithPreAssociation builder to snapshot away from — prepare itself is the single point that copies every slice field, so the test drives prepare directly and mutates the source Config afterward |
| sctp_preassociation_portable_test.go | TestWithPreAssociationPreservesNilAndEmptySlices | ported → TestPrepareFileStyleRejectsEveryOtherField, TestPrepareRejectsInvalidConfiguration, TestPrepareAcceptsEmptyNonNilAuthChunksWithAuthentication (config_test.go), adapted: v2 has no builder to preserve nil-vs-empty shape through; the nil/non-nil distinction itself is still pinned two ways — an empty-but-non-nil HMACIdentifiers/AuthChunks/Notifications is refused on styleFile precisely because it is "set" (TestPrepareFileStyleRejectsEveryOtherField), and on the ordinary styles an empty non-nil list is confirmed treated as set, not as nil, for both fields: HMACIdentifiers both with and without Authentication (TestPrepareRejectsInvalidConfiguration's two "empty non-nil HMACIdentifiers" cases — refused either way, since Authentication is required first and an empty list is still missing HMACSHA1), and AuthChunks with and without Authentication too, but with different outcomes — refused without Authentication (TestPrepareRejectsInvalidConfiguration's "empty non-nil AuthChunks without Authentication"), accepted with it, since AuthChunks has no "must include" rule (TestPrepareAcceptsEmptyNonNilAuthChunksWithAuthentication) |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationZeroValue | ported → TestPrepareZeroConfigDial, TestPrepareZeroConfigListen, TestPrepareZeroConfigEndpointDefaultsFragmentInterleave, TestPrepareZeroConfigFile (config_test.go) |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationExplicitFragmentInterleaveWins | ported → TestPrepareZeroConfigEndpointDefaultsFragmentInterleave, TestMessageInterleavingRequiresFragmentInterleave (config_test.go); level 2 (InterleaveStreams) no longer "wins" when explicit — v2 refuses it outright (TestInterleaveStreamsUnsupported), a deliberate behaviour change from v1, because Linux stores SCTP_FRAGMENT_INTERLEAVE as a plain boolean and cannot actually deliver level 2 |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationOrderAndValues | ported → TestPrepareOrderAndValues (config_test.go) |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationRejectsInvalidConfiguration | ported → TestPrepareRejectsInvalidConfiguration, TestInterleaveStreamsUnsupported (config_test.go); the MappedV4Address, ReceiveRcvInfo and SCTP_DATA_IO_EVENT sub-cases retired: v2's Config has no MappedV4Address field at all (SCTP_I_WANT_MAPPED_V4_ADDR is set through Control instead) and no ReceiveRcvInfo field either (this package always enables SCTP_RECVRCVINFO itself, unconditionally, on every socket it creates or adopts — it is not a caller-settable Config field), and SCTP_DATA_IO_EVENT is the deprecated RFC 6458 mechanism v2 does not implement |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationEndpointInterleavingUsesRFCDefault | ported → TestPrepareZeroConfigEndpointDefaultsFragmentInterleave, TestMessageInterleavingRequiresFragmentInterleave (config_test.go) |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationEndpointLevelTwoEnablesRcvInfoFirst | retired: pinned an ordering between enabling SCTP_RECVRCVINFO and applying FragmentInterleave level 2. v2 refuses level 2 (InterleaveStreams) outright (TestInterleaveStreamsUnsupported): Linux stores SCTP_FRAGMENT_INTERLEAVE as a plain boolean and cannot deliver it, so there is no longer a level-2 case for that ordering to matter to |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationLevelTwoAcceptsDataIOEventFirst | retired: same reason as the row above, compounded by SCTP_DATA_IO_EVENT itself being the deprecated RFC 6458 mechanism v2 does not implement |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationDelayedSACKBoundaries | ported → TestPrepareRejectsInvalidConfiguration/DelayedSACK.Delay_above_500ms, TestPrepareOrderAndValues (config_test.go) |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationRTOInfoBoundaries | ported → TestPrepareRejectsInvalidConfiguration/RTOInfo_non-millisecond_value, TestDurationToMillisRefusesFractional, TestDurationToMillisRefusesHugeDuration, TestDurationToMillisRefusesOverflowingWholeValue (config_test.go); the AssocID-selector sub-cases retired: v2's RTOInfo has no AssocID field — Config.RTOInfo always targets the pre-association default, so there is no scope selector left to validate |
| sctp_preassociation_portable_test.go | TestSetSackTimerPrevalidatesProtocolMaximum | ported → TestPrepareRejectsInvalidConfiguration/DelayedSACK.Delay_above_500ms (config_test.go) |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationSnapshotsSlices | ported → TestPrepareCopiesSlices (config_test.go) |
| sctp_preassociation_portable_test.go | TestNilSocketConfigMethodsDoNotPanic | pending: pinned nil-receiver safety on SocketConfig's Listen/Dial/DialContext/OpenEndpoint/ListenEndpoint methods, none of which exist in this file — Config.Dial, Config.Listen, Config.ListenEndpoint and Config.OpenEndpoint are added by later work. The underlying property is live in v2 too, and this file now defines its own half of it: (*Config).prepare treats a nil receiver the same as the zero Config rather than panicking (TestPrepareNilConfigMatchesZeroConfig, config_test.go). The row stays pending because the actual v1 property — calling the nil-receiver *constructors* — has no v2 target to port to yet; whichever task adds Dial/Listen/ListenEndpoint/OpenEndpoint should port it then, building on prepare's own nil handling |
| sctp_preassociation_portable_test.go | FuzzPreparePreAssociationConfig | ported → FuzzPrepareConfig (config_test.go); same property (prepare is a pure function: two calls on the same fuzzed Config produce the same result or the same error text), rebuilt against v2's Config shape |
| sctp_preassociation_unsupported_test.go | TestSocketConfigPreAssociationUnsupportedParity | pending: exercises Listen/Dial/DialContext/OpenEndpoint/ListenEndpoint on `!linux`, checking that a valid Config reaches ErrUnsupported while an invalid one is refused portably first. Those constructors do not exist yet — config.go only produces prepare's validated snapshot — so this waits for the task that adds them and unsupported.go's `!linux` implementations |
| sctp_rawconn_test.go | TestSyscallConnReadSharesReceiveSerialization | pending |
| sctp_rawconn_test.go | TestPollConstantsMatchKernel | retired: the package no longer calls ppoll(2); its only use was waiting for a peeled socket's SCTP_EOF send to find buffer space, and that send never waits (net/sctp/socket.c: sctp_sendmsg_check_sflags starts the SHUTDOWN primitive before sctp_sendmsg_to_asoc, the only path that waits) |
| sctp_rawconn_test.go | TestPollFdLayoutMatchesKernel | retired: as TestPollConstantsMatchKernel, struct pollfd is no longer used |
| sctp_rawconn_test.go | TestPollWaitReportsTimeout | retired: as TestPollConstantsMatchKernel, the ppoll helper no longer exists |
| sctp_rawconn_test.go | TestPollWaitReportsWritable | retired: as TestPollConstantsMatchKernel, the ppoll helper no longer exists |
| sctp_rawconn_test.go | TestSyscallConnWriteWaitsForWritability | ported → TestSyscallConnWriteWaitsForWritability (close_linux_test.go) |
| sctp_rawconn_test.go | TestSyscallConnReadWaitsForData | ported → TestSyscallConnReadWaitsForData (close_linux_test.go) |
| sctp_rawconn_test.go | TestSyscallConnStopsWhenDone | ported → TestSyscallConnStopsWhenDone (close_linux_test.go) |
| sctp_rawconn_test.go | TestSyscallConnHonoursDeadline | ported → TestSyscallConnHonoursDeadline (close_linux_test.go), now also asserting the timeout *net.OpError (raw-read, raw-write) |
| sctp_rawconn_test.go | TestSyscallConnAfterCloseReturnsNetErrClosed | ported → TestSyscallConnAfterCloseReturnsNetErrClosed (close_linux_test.go) |
| sctp_rawconn_test.go | TestListenerSyscallConnReadWriteReturnEINVAL | ported → TestListenerSyscallConnReadWriteReturnEINVAL (listener_linux_test.go) |
| sctp_rawconn_test.go | TestListenerRawConnAfterCloseDoesNotUseRecycledFD | ported → TestListenerRawConnAfterCloseDoesNotUseRecycledFD (listener_linux_test.go) |
| sctp_rawconn_test.go | TestSCTPWriteWithoutDeadlineReturnsEAGAIN | ported → TestNoWaitRefusalQueuesNothing (send_linux_test.go): a single attempt is now SendOptions.NoWait, not the absence of a write deadline |
| sctp_rawconn_test.go | TestSCTPWriteWithDeadlineWaitsForSpace | ported → TestSendWaitsForBufferSpace/drain (send_linux_test.go): every send waits, with or without a deadline |
| sctp_rawconn_test.go | TestSCTPWriteDeadlineExpiresWhileSendBufferFull | ported → TestSendWaitsForBufferSpace/deadline_set_before and /deadline_set_while_waiting (send_linux_test.go) |
| sctp_rawconn_test.go | TestSCTPWriteDeadlineInThePastDoesNotWait | ported → TestWriteDeadlineInThePast (send_linux_test.go) |
| sctp_rawconn_test.go | TestSyscallConnDoesNotSpinWhenReadyButNotDone | ported → TestSyscallConnDoesNotSpinWhenReadyButNotDone (close_linux_test.go) |
| sctp_rawconn_test.go | TestSyscallConnCloseUnblocksWait | ported → TestSyscallConnCloseUnblocksWait (close_linux_test.go) |
| sctp_rawconn_test.go | TestSyscallConnAbortUnblocksWait | ported → TestSyscallConnAbortUnblocksWait (close_linux_test.go) |
| sctp_rawconn_test.go | TestSocketConfigRawConnReadWriteReturnEINVAL | ported → TestSocketConfigRawConnReadWriteReturnEINVAL (listener_linux_test.go) |
| sctp_rawconn_test.go | TestSyscallConnConcurrent | ported → TestSyscallConnConcurrent (close_linux_test.go) |
| sctp_readmsg_alloc_test.go | TestReadMsgAllocationBudget | pending |
| sctp_readmsg_alloc_test.go | BenchmarkReadMsgAssembly | pending |
| sctp_readmsg_buffer_test.go | TestReadMsgBufferCacheExclusiveAndBounded | pending |
| sctp_readmsg_buffer_test.go | TestReadMsgBufferCacheConcurrent | pending |
| sctp_readmsg_contract_test.go | TestReadMsgDocumentedAllocationContract | pending |
| sctp_readmsg_events_test.go | TestInterruptedNotificationFailsConnectionClosed | pending |
| sctp_readmsg_events_test.go | TestRecvmsgNotificationInterruptionAlwaysFailsClosed | pending |
| sctp_readmsg_events_test.go | TestReadMsgNotificationInterruptionAlwaysFailsClosed | pending |
| sctp_readmsg_events_test.go | TestReadMsgApplicationInterruptionAlwaysFailsClosed | pending |
| sctp_readmsg_events_test.go | TestReadMsgHandlerReassemblesNotification | pending |
| sctp_readmsg_events_test.go | TestReadMsgNotificationHandlerMayReenterRead | pending |
| sctp_readmsg_events_test.go | TestReadMsgWithNotificationsSubscribed | pending |
| sctp_readmsg_events_test.go | TestReadMsgPeerAbortMidMessage | pending |
| sctp_readmsg_events_test.go | TestReadMsgAfterPeerClose | pending |
| sctp_readmsg_events_test.go | TestReadMsgOnClosedConn | pending |
| sctp_readmsg_large_test.go | TestReadMsgLargeMixedResultsRemainOwned | pending |
| sctp_readmsg_large_test.go | TestReadMsgLargeRejectedPrefixSurvivesNextRecord | pending |
| sctp_readmsg_large_test.go | TestReadMsgLargeNestedCacheExhaustion | pending |
| sctp_readmsg_large_test.go | TestReadMsgLargeInterleavedNotificationReentry | pending |
| sctp_readmsg_large_test.go | TestReadMsgLargeControlTruncationRetainsPayload | pending |
| sctp_readmsg_large_test.go | TestReadMsgLargeInterruptedPrefix | pending |
| sctp_readmsg_large_test.go | TestReadMsgLargePollInterruptionRetainsPrefix | pending |
| sctp_readmsg_large_test.go | TestReadMsgLargeHandlerPanicReleasesScratch | pending |
| sctp_readmsg_large_test.go | TestReadMsgLargeConcurrentMixedRecords | pending |
| sctp_readmsg_ownership_test.go | TestReadMsgResultsSurviveInterleavedNotificationReentry | pending |
| sctp_readmsg_ownership_test.go | TestReadMsgLaterFragmentControlTruncationPreservesFirstInfo | pending |
| sctp_readmsg_ownership_test.go | TestReadMsgMalformedFirstControlDoesNotLosePayload | pending |
| sctp_readmsg_ownership_test.go | TestReadMsgBoundsQueuedNotificationRetention | pending |
| sctp_readmsg_ownership_test.go | TestConcurrentReadMsgResultsRemainIndependent | pending |
| sctp_readmsg_ownership_test.go | FuzzReadMsgScriptedOwnership | pending |
| sctp_readmsg_raw_test.go | TestSCTPReadMsgExposesControlTruncation | pending |
| sctp_readmsg_raw_test.go | TestSCTPReadMsgReturnsParseableControlData | pending |
| sctp_readmsg_raw_test.go | TestSCTPReadFlagsReportsControlTruncation | pending |
| sctp_readmsg_raw_test.go | TestReadMsgReportsControlTruncation | pending |
| sctp_readmsg_test.go | TestReadMsgSizeMaxMatrix | pending |
| sctp_readmsg_test.go | TestReadMsgExactMaxIsComplete | pending |
| sctp_readmsg_test.go | TestReadMsgOneOverMax | pending |
| sctp_readmsg_test.go | TestReadMsgTooLongDrainsRemainder | pending |
| sctp_readmsg_test.go | TestZeroLengthSendIsRefusedByTheKernel | ported → TestSendEmptyRefused (send_linux_test.go): the package now refuses an empty message with EINVAL before any system call, for every combination of options, and rawSendmsg still never substitutes a byte of its own; the peer then receives the next real message first |
| sctp_readmsg_test.go | FuzzReadMsg | pending |
| sctp_resolve_linux_test.go | TestExplicitNetworkRejectsTheOtherAddressFamily | ported → TestExplicitNetworkRejectsTheOtherAddressFamily (socket_linux_test.go), with a changed invariant: an IPv6 address on sctp4 is still refused (now EINVAL, before any socket exists), but an IPv4 address on sctp6 is accepted and used in IPv4-mapped form, since an AF_INET6 socket carries both families |
| sctp_resolve_portable_test.go | TestNilSCTPAddrString | ported → TestNilAddrString (addr_test.go) |
| sctp_resolve_portable_test.go | TestDirectSCTPAddrValuesAreValidated | ported → its zone and empty-address validation moved into the sockaddr codec: TestEncodeAddrRejectsTheZeroAddr, TestEncodeAddrRejectsZoneOnIPv4, TestEncodeAddrRejectsNonLinkLocalZone, TestEncodeAddrRejectsUnknownZone (sockaddr_test.go); its "malformed IP length" case has no counterpart — netip.Addr admits no such value — and its SCTPBind/SCTPConnect/SetPrimaryPeerAddr call sites stay pending for whichever task ports those calls |
| sctp_resolve_portable_test.go | TestSCTPBindRejectsUnknownFlagsBeforeTouchingTheAddress | pending |
| sctp_resolve_portable_test.go | TestResolveSCTPAddrRejectsMalformedInput | ported → TestResolveAddrRejectsMalformedInput (addr_test.go); a bare ":port" stays the wildcard, as in v1, but any other empty element in a multi-address list is still refused |
| sctp_resolve_portable_test.go | TestResolveSCTPAddrAcceptsTheDocumentedForms | ported → TestResolveAddrAcceptsTheDocumentedForms (addr_test.go), including its "bare port is the wildcard" row, unchanged from v1 |
| sctp_resolve_portable_test.go | TestResolveSCTPAddrNeverReturnsANilAddress | ported → TestResolveAddrNeverReturnsANilAddress (addr_test.go) |
| sctp_resolve_portable_test.go | FuzzResolveSCTPAddr | ported → FuzzResolveAddr (addr_test.go) |
| sctp_resolve_portable_test.go | FuzzSCTPAddrMarshal | retired: it fuzzed SCTPAddr's raw net.IP/Zone fields for a malformed value MarshalSockaddr must catch (a bad IP length, an invalid zone string). netip.Addr, encodeAddr's argument type, admits no such malformed value by construction — every netip.Addr is either the invalid zero value (TestEncodeAddrRejectsTheZeroAddr) or a well-formed address — so the field-level fuzz surface this test exercised no longer exists; FuzzDecodeAddrs (sockaddr_fuzz_test.go) covers the remaining untrusted-bytes surface, the decode direction |
| sctp_resolveraw_kernel_test.go | TestKernelAddrsRoundTrip | pending |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrMixedFamilies | ported → TestDecodeAddrsMixedFamilies/v4_first (sockaddr_test.go) |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrV6First | ported → TestDecodeAddrsMixedFamilies/v6_first (sockaddr_test.go) |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrUnknownFamilyIsRejected | ported → TestDecodeAddrsRejectsUnknownFamily (sockaddr_test.go) |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrZeroCount | ported → TestDecodeAddrsZeroCount (sockaddr_test.go) |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrRespectsBuffer | ported → TestDecodeAddrsRejectsTruncatedEntries (sockaddr_test.go); decodeAddrs takes a real []byte bounded by len(b), so the separate limit==0 "unbounded" mode this test also covered has no v2 counterpart |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrRejectsImpossibleCountBeforeWalking | ported → TestDecodeAddrsRejectsImpossibleCount and TestDecodeAddrsAllocatesNothingOnError (sockaddr_test.go); the latter tightens the property to cover an unknown family and a truncated entry too, not just an oversized count, each proven zero-allocation with testing.AllocsPerRun |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrNegativeCount | ported → TestDecodeAddrsNegativeCount (sockaddr_test.go) |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrPortFromLaterEntriesIgnored | ported → TestDecodeAddrsPortFromFirstEntryOnly (sockaddr_test.go) |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrPortFromFirstEntry | ported → TestDecodeAddrsPortFromFirstEntryOnly (sockaddr_test.go), which covers both directions of the rule in one test |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrDoesNotAliasBuffer | retired: it guarded against net.IP's slice header aliasing the kernel's reply buffer once copied out carelessly. netip.Addr is an immutable value type built from a fixed-size array (netip.AddrFrom4/AddrFrom16), never a slice into the source, so a decoded address cannot alias b by construction — the class of bug this test caught cannot be reintroduced |
| sctp_resolveraw_portable_test.go | FuzzResolveFromRawAddr | ported → FuzzDecodeAddrs (sockaddr_fuzz_test.go) |
| sctp_shutdownwait_test.go | TestAssocQueryAnswersForALiveAssociation | ported → TestAssocQueryAnswersForALiveAssociation (close_linux_test.go) |
| sctp_shutdownwait_test.go | TestWaitAssocGoneDoesNotTreatProbeFailureAsCompletion | ported → TestLifecycleCloseProbeFailureAborts (close_test.go), same property; the failed query now leads to the abortive close in the same call, which reports the query's error joined with the abortive close's |
| sctp_shutdownwait_test.go | TestShutdownViaEOFRetriesInterruptAndBackpressure | retired: the SCTP_EOF send never waits and is made once (net/sctp/socket.c: sctp_sendmsg_check_sflags issues the SHUTDOWN primitive before sctp_sendmsg_to_asoc, the only path that waits for buffer space), so the EAGAIN retry loop this pinned no longer exists; an error from it means the association is gone or already shutting down, which the status poll then finds |
| sctp_shutdownwait_test.go | TestShutdownViaEOFBackpressureHonorsDeadline | retired: as TestShutdownViaEOFRetriesInterruptAndBackpressure, there is no backpressure wait |
| sctp_shutdownwait_test.go | TestShutdownViaEOFPropagatesWaitAndSendErrors | retired: as TestShutdownViaEOFRetriesInterruptAndBackpressure, there is no wait whose errors could propagate; a send error is the association's state, which the close then reads |
| sctp_shutdownwait_test.go | TestCloseTimeoutBoundsTheShutdownWait | ported → TestLifecycleCloseGraceExpiry (close_test.go) for the state machine: the whole grace period is spent on the backoff schedule, then the abortive close; the socket half is now ported → TestCloseTimeoutBoundsTheShutdownWait (close_linux_test.go) |
| sctp_shutdownwait_test.go | TestCloseWithRespondingPeerReturnsPromptly | ported → TestLifecycleCloseGraceful (close_test.go) for the state machine: close stops at the first poll that finds the association gone; the socket half is now ported → TestCloseWithRespondingPeerReturnsPromptly (close_linux_test.go) |
| sctp_shutdownwait_test.go | TestCloseReleasesPortAfterUnresponsivePeer | ported → TestCloseReleasesPortAfterUnresponsivePeer (close_linux_test.go) |
| sctp_shutdownwait_test.go | TestListenerAcceptDeadline | ported → TestListenerAcceptDeadline (listener_linux_test.go), also asserting a net.Error with Timeout() true |
| sctp_shutdownwait_test.go | TestRawSocketTimeoutDoesNotBecomeListenerDeadline | ported → TestRawSocketTimeoutDoesNotBecomeListenerDeadline (listener_linux_test.go) |
| sctp_shutdownwait_test.go | TestListenerDeadlineInThePast | ported → TestListenerDeadlineInThePast (listener_linux_test.go) |
| sctp_shutdownwait_test.go | TestSendDoesNotRaiseSIGPIPE | ported → TestSendAfterPeerShutdown and TestSendAfterPeerAbortIsSticky (send_linux_test.go) |
| sctp_shutdownwait_test.go | TestRawWaitTerminatesOnAbortedAssociation | ported → TestRawWaitTerminatesOnAbortedAssociation (close_linux_test.go) |
| sctp_sndinfo_test.go | TestSCTPWriteInfoCarriesStreamAndPPID | ported → TestAppendSendCmsgsEncodesSndInfo (msginfo_test.go) for the SNDINFO byte encoding, including the PPID conversion, and TestSendMsgDeliversStreamAndPPID (send_linux_test.go) for the live socket |
| sctp_sndinfo_test.go | TestSCTPWriteInfoNilInfoUsesDefaults | ported → TestSendDefaultsAllCombinations (send_linux_test.go), for every combination of a nil Info and a nil PR |
| sctp_sndinfo_test.go | TestSCTPWriteInfoWithPrInfo | ported → TestAppendSendCmsgsEncodesPrInfoWhenSet, TestAppendSendCmsgsPRTTLConvertsToMilliseconds (msginfo_test.go) for the PRINFO byte encoding, and TestSendMsgWithPrInfo (send_linux_test.go) for the live socket |
| sctp_sndinfo_test.go | TestSCTPWriteInfoCmsgPadding | ported → TestAppendSendCmsgsAllThreeFitsSndCmsgSpaceExactly, TestAppendSendCmsgsZeroesPaddingGaps (msginfo_test.go) for the inter-cmsg alignment padding, and TestSendMsgWithAuthKey (send_linux_test.go) for a live send carrying all three records |
| sctp_sndinfo_test.go | TestCmsgPaddingIsObservable | ported → TestCmsgLenIsExactNotAligned, TestCmsgFormulaAcrossWordSizes (msginfo_test.go), pinning the same CMSG_LEN-vs-CMSG_SPACE gap for AUTHINFO directly from the word-size formula instead of syscall.CmsgLen/CmsgSpace |
| sctp_sndinfo_test.go | TestSCTPWriteInfoRejectsBadPrPolicy | ported → TestValidateSendOptionsRefusesUnknownPRPolicyBits (msginfo_test.go) and TestSendMsgRefusesBadPrPolicy (send_linux_test.go): the package runs the same SCTP_PR_SCTP_MASK check itself before any syscall |
| sctp_sndinfo_test.go | TestSCTPWriteInfoInteropWithSCTPWrite | retired: it pinned that the deprecated SCTP_SNDRCV send path (SCTPWrite) and the non-deprecated one (SCTPWriteInfo) interoperate on one association. v2 has a single send path (SendMsg/Write, where Write is SendMsg with no control records), not two different wire formats to interoperate between |
| sctp_sndinfo_test.go | TestSCTPWriteInfoHonoursWriteDeadline | ported → TestWriteDeadlineInThePast (send_linux_test.go) |
| sctp_sndinfo_test.go | TestSCTPWriteInfoWithAuthInfo | ported → TestAppendSendCmsgsEncodesAuthInfoWhenKeySet (msginfo_test.go) for the AUTHINFO byte encoding, and TestSendMsgWithAuthKey (send_linux_test.go) for the live socket, with AUTH on through Config.Authentication and DATA authenticated, so an unknown key is refused |
| sctp_sockopt_stack_test.go | TestSubscribedEventsSurvivesStackGrowth | pending |
| sctp_sockopt_stack_test.go | TestRawGetsockoptSurvivesStackGrowth | ported → TestRawSockoptStackStorage (syscall_linux_test.go); the wrapper it exercised, SCTPConn.Getsockopt, has no v2 equivalent (raw option access is SyscallConn), so this now proves the same stack-growth-survives-a-syscall property directly against rawSetsockopt/rawGetsockopt, the layer that wrapper used to sit on |
| sctp_sockopt_stack_test.go | TestInternalRawGetsockoptSurvivesStackGrowth | pending: exercised SCTPConn.getsockoptRaw, an internal helper tied to the x86_64 compat-layout retry for the peer-address-threshold options; not yet implemented |
| sctp_sockopt_stack_test.go | TestSubscribeEventsSurvivesStackGrowth | pending |
| sctp_sockopt_stack_test.go | TestSetRtoInfoKeepsOptionAlive | pending |
| sctp_sockopt_stack_test.go | TestRawSetsockoptKeepsOptionAlive | ported → TestRawSockoptStackStorage (syscall_linux_test.go); same reasoning as TestRawGetsockoptSurvivesStackGrowth above — SCTPConn.Setsockopt has no v2 equivalent, and the property now lives directly on rawSetsockopt/rawGetsockopt |
| sctp_sockopt_test.go | TestFragmentInterleaveRoundTrip | pending |
| sctp_sockopt_test.go | TestFragmentInterleaveRejectsOutOfRange | pending |
| sctp_sockopt_test.go | TestPartialDeliveryPointRoundTrip | pending |
| sctp_sockopt_test.go | TestMaxBurstRoundTrip | pending |
| sctp_sockopt_test.go | TestContextRoundTrip | pending |
| sctp_sockopt_test.go | TestReusePortBeforeBind | pending |
| sctp_sockopt_test.go | TestSockoptsOnClosedConn | pending |
| sctp_sockopt_test.go | TestRcvInfoAndSndRcvBothParsed | pending |
| sctp_state_test.go | TestStatusStateMatchesKernel | pending |
| sctp_state_test.go | TestPeerStateMatchesKernel | pending |
| sctp_state_test.go | TestGetStatusReportsEstablished | pending |
| sctp_state_test.go | TestGetStatusAfterShutdown | pending |
| sctp_streams_test.go | TestStreams | ported → TestStreams (send_linux_test.go); the echo reads through SyscallConn until RecvMsg exists |
| sctp_syscall_linux_test.go | TestRawSockoptSyscalls | ported → TestRawSockoptRoundTrip (syscall_linux_test.go); exercises a real SCTP socket and SCTP_NODELAY instead of an AF_UNIX pair and SO_PASSCRED, per the new rawSetsockopt/rawGetsockopt signature (unsafe.Pointer instead of a caller-converted uintptr) |
| sctp_syscall_linux_test.go | TestRawMessageSyscalls | ported → TestRawMessageSyscalls (syscall_linux_test.go), unchanged in substance (an AF_UNIX pair; the syscalls do not care what kind of socket they are handed) |
| sctp_syscall_linux_test.go | TestRawRecvmsgStackStorage | ported → TestRawRecvmsgStackStorage (syscall_linux_test.go), unchanged in substance; still the regression test for the 386 storage fix (commit b6f3db1) |
| sctp_test.go | TestSCTPAddrString | pending |
| sctp_test.go | TestResolveSCTPAddr | pending |
| sctp_test.go | TestSCTPListenerName | pending |
| sctp_test.go | TestSCTPConcurrentAccept | pending |
| sctp_test.go | TestSCTPCloseRecv | pending |
| sctp_test.go | TestGetStatus | pending |
| sctp_test.go | TestGetStatusUsage | pending |
| sctp_tobuf_test.go | TestToBufSerialisesFixedSizeStructs | retired: toBuf and the syscall.RawSockaddrInet4/6 and SndRcvInfo struct-to-bytes marshalling it served are gone; the package now writes and reads every kernel structure byte-wise at offsets abi.go pins and abi_test.go's layout tests check directly, so there is no generic struct serialiser left to size-check |
| sctp_tobuf_test.go | TestToBufPanicsOnUnserialisableType | retired: same reason — there is no toBuf, so there is nothing that can be handed a type it cannot serialise |
| sctp_unsupported_test.go | TestUnsupportedHighLevelErrorsCarryOperationContext | pending |
| sctp_unsupported_test.go | TestUnsupportedRawConnectErrorRemainsUnwrapped | pending |
| sctp_unsupported_test.go | TestNewSCTPConnClosesOwnedDescriptorOnUnsupportedPlatform | pending |
| sctp_unsupported_test.go | TestDialContextWithAbandonPolicyValidatesPolicyOnUnsupportedPlatform | pending |
| sctp_unsupported_test.go | TestDynamicBindEntryPointsReportUnsupported | pending |
| sctp_unsupported_test.go | TestUnsupportedEntryPointsReportTheSentinel | ported → TestUnsupportedEntryPointsReportTheSentinel (unsupported_test.go), same mechanism (calls every case in the stub manifest, requires ErrUnsupported and errors.ErrUnsupported); the manifest itself is empty for now, since unsupported.go declares no stubs until a later task adds a Linux constructor or method for it to stand in for |
| sctp_unsupported_test.go | TestUnsupportedStubManifestIsComplete | ported → TestUnsupportedStubManifestIsComplete (unsupported_test.go), same mechanism (parses unsupported.go with go/ast and requires its declarations to match the manifest by name exactly) |
| sctp_untested_test.go | TestSubscribedEventsReportsEachFlagIndependently | pending |
| sctp_untested_test.go | TestSubscribedEventsRoundTripsTheWholeSet | pending |
| sctp_untested_test.go | TestSackTimerLayoutAndRoundTrip | pending |
| sctp_untested_test.go | TestSackTimerZeroFieldMeansUnchanged | pending |
| sctp_untested_test.go | TestNoDelayRoundTrips | pending |
| sctp_untested_test.go | TestDefaultSentParamRoundTrips | pending |
| sctp_untested_test.go | TestSetDefaultSentParamRejectsNil | pending |
| sctp_untested_test.go | TestSCTPBindRemoveAndInvalidFlags | pending |
| sctp_untested_test.go | TestToRawSockAddrBufEncodesEachFamily | pending |
| sctp_untested_test.go | TestLocalAndRemoteAddrReportTheAssociation | pending |
| sctp_untested_test.go | TestGetReadBufferReportsTheBuffer | pending |
| sctp_untested_test.go | TestBindxFamilyRulesFollowV6Only | pending |
| sctp_varlen_test.go | TestResetStreams | pending |
| sctp_varlen_test.go | TestResetStreamsRejectsBadDirection | pending |
| sctp_varlen_test.go | TestResetStreamsNeedsExtension | pending |
| sctp_varlen_test.go | TestResetAssoc | pending |
| sctp_varlen_test.go | TestResetStreamsRejectsTooManyStreams | pending |
| sctp_varlen_test.go | TestResetStreamsWireLayout | pending |
| sctp_varlen_test.go | TestBuildersMatchKernelLayout | pending |
| sctp_varlen_test.go | TestAuthKeyManagement | pending |
| sctp_varlen_test.go | TestSetAuthKeyRejectsEmpty | pending |
| sctp_varlen_test.go | TestSetAuthKeyValidatesLength | pending |
| sctp_varlen_test.go | TestSetHmacIdent | pending |
| sctp_varlen_test.go | TestSetAuthChunk | pending |
| sctp_varlen_test.go | TestAuthOptionsWithoutSysctl | pending |
| sctp_wrappedconn_test.go | TestWrappedConnReportsSubscribeFailure | pending |
| sctp_wrappedconn_test.go | TestWrappedConnWorksWhenSubscribed | pending |
| sctp_wrappedconn_test.go | TestWrappedConnWriteDoesNotCountAnUnsentHeader | pending |
| sctp_wrappedconn_test.go | TestWrappedConnPartialResultsKeepTheInlineHeaderInTheCount | pending |
| sctp_wrappedconn_test.go | TestDecodeWrappedSndRcvInfoDoesNotRequireAlignment | pending |
