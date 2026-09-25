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
| sctp_already_test.go | TestSCTPConnectEALREADYOnNonblockingSocket | pending |
| sctp_already_test.go | TestSCTPConnectEISCONNOnBlockingSocket | pending |
| sctp_already_test.go | TestSCTPConnectEALREADYOnBlockingSocketMidHandshake | pending |
| sctp_already_test.go | TestIsNonblockingDetectsBothStates | pending |
| sctp_backlog_test.go | TestListenBacklogUsesKernelMaximum | pending |
| sctp_backlog_test.go | TestReadSomaxconnMatchesProc | pending |
| sctp_bench_test.go | BenchmarkSCTPWrite | pending |
| sctp_bench_test.go | BenchmarkSCTPWriteNoInfo | pending |
| sctp_bench_test.go | BenchmarkSCTPWriteInfo | pending |
| sctp_bench_test.go | BenchmarkSCTPRead | pending |
| sctp_bench_test.go | BenchmarkBuildSndRcvCmsg | pending |
| sctp_bench_test.go | BenchmarkToBuf | pending |
| sctp_bench_test.go | BenchmarkParseSndRcvInfo | pending |
| sctp_bench_test.go | BenchmarkResolveSCTPAddr | pending |
| sctp_bench_test.go | BenchmarkToRawSockAddrBuf | pending |
| sctp_bench_test.go | BenchmarkDial | pending |
| sctp_bench_test.go | BenchmarkTransportEcho | pending |
| sctp_bench_test.go | BenchmarkConcurrentEcho | pending |
| sctp_bindx_test.go | TestNormalizeDynamicBindAddr | pending |
| sctp_bindx_test.go | TestRemovesEveryLocalAddress | pending |
| sctp_bindx_test.go | FuzzDynamicBindAddressPreparation | pending |
| sctp_bindx_test.go | TestListenerBindAddRemoveRefreshesAddr | pending |
| sctp_bindx_test.go | TestSCTPConnBindAddRemoveRefreshesLocalAddr | pending |
| sctp_bindx_test.go | TestConcurrentListenerBindAddKeepsCacheInSync | pending |
| sctp_bindx_test.go | TestConnectedBindAddRemoveUpdatesPeerAddressReadback | pending |
| sctp_cause_test.go | TestAssocChangeErrorIsDecodedFromNetworkOrder | pending |
| sctp_cause_test.go | TestRemoteErrorErrorIsDecodedFromNetworkOrder | pending |
| sctp_cause_test.go | TestSendFailedErrorIsDecodedFromNetworkOrder | pending |
| sctp_cause_test.go | TestPeerAddrChangeErrorStaysHostOrder | pending |
| sctp_cause_test.go | TestErrorCauseStringNamesTheRFCCauses | ported → TestErrorCauseIANANames (enums_test.go); the expected names changed from v1's own SCTP_ERROR_* constant spelling to the IANA "SCTP Error Cause Codes" registry names |
| sctp_cause_test.go | TestAbortReportsTheUserAbortCause | pending |
| sctp_cause_test.go | TestParsesTheEventsStreamReconfigurationNeeds | pending |
| sctp_cause_test.go | TestNewNotificationsRejectTruncation | pending |
| sctp_cause_test.go | TestNotificationTypeNumbersMatchTheKernel | ported → TestEnumerationValues (its EventType rows; enums_test.go); its SCTP_SN_TYPE_BASE row retired: 0x8000 is never a real notification on the wire (it is SCTP_DATA_IO_EVENT, a subscription-only pseudo-type from the deprecated EventSubscribe bitmask), so EventType names nothing at it |
| sctp_cause_test.go | TestNotificationPPIDIsConvertedToHostOrder | pending |
| sctp_cause_test.go | TestParseNotificationRejectsADeclaredLengthItDoesNotHave | pending |
| sctp_close_fuzz_test.go | FuzzCloseWithTimeout | pending |
| sctp_close_fuzz_test.go | TestCloseTimeoutZeroIsImmediate | pending |
| sctp_close_fuzz_test.go | TestCloseSubMicrosecondTimeout | pending |
| sctp_close_fuzz_test.go | TestCloseChurnUnderLoad | pending |
| sctp_close_fuzz_test.go | TestCloseRacesWithReadAndWrite | pending |
| sctp_close_fuzz_test.go | TestAbortDoesNotWait | pending |
| sctp_close_fuzz_test.go | TestPeelOffRacesWithClose | pending |
| sctp_close_fuzz_test.go | TestClosingAPeeledConnectionShutsDownGracefully | pending |
| sctp_close_fuzz_test.go | TestClosingBackpressuredPeeledConnectionRetriesEOF | pending |
| sctp_close_test.go | TestDialUnderChurnReportsEISCONN | pending |
| sctp_close_test.go | TestCloseReleasesFdZero | pending |
| sctp_close_test.go | TestAbortReleasesFdZero | pending |
| sctp_close_test.go | TestCloseDoesNotLeakDescriptors | pending |
| sctp_close_test.go | TestCloseReleasesPortForRebind | pending |
| sctp_close_test.go | TestCloseWithUnreachablePeerReturnsWithinTimeout | pending |
| sctp_close_test.go | TestDoubleCloseReturnsNetErrClosed | pending |
| sctp_close_test.go | TestCloseOnNilConn | pending |
| sctp_close_test.go | TestConcurrentCloseAndAbort | pending |
| sctp_close_test.go | TestCloseDuringBlockedRead | pending |
| sctp_close_test.go | TestCloseDuringWrite | pending |
| sctp_close_test.go | TestCloseAfterCompletedHandshakeGivesPeerEOF | pending |
| sctp_cmsgbuild_test.go | TestBuildSndRcvCmsgMatchesLegacy | pending |
| sctp_cmsgbuild_test.go | TestBuildSndRcvCmsgHeader | pending |
| sctp_cmsgbuild_test.go | TestBuildSndRcvCmsgOffsetsMatchStruct | pending |
| sctp_cmsgbuild_test.go | TestBuildSndRcvCmsgRoundTripsThroughParser | pending |
| sctp_cmsgbuild_test.go | TestParseSndRcvInfoDoesNotAliasInput | pending |
| sctp_cmsgbuild_test.go | TestAncillaryParsersIgnoreShortSCTPPayloads | pending |
| sctp_cmsgbuild_test.go | FuzzAncillaryParsers | pending |
| sctp_cmsgbuild_test.go | TestParseSndRcvInfoPrefersSndRcvOverRcvInfo | pending |
| sctp_cmsgbuild_test.go | TestSCTPReadInfoSurvivesLaterReads | pending |
| sctp_cmsgbuild_test.go | TestSCTPWriteDoesNotMutateInfo | pending |
| sctp_cmsgbuild_test.go | TestSCTPWriteConcurrentSharedInfo | pending |
| sctp_connect_test.go | TestDialUnderChurnSucceeds | pending |
| sctp_contract_test.go | TestReadWithZeroLengthBufferConsumesNothing | pending |
| sctp_contract_test.go | TestReadIntoFullBufferTailIsNotAConsumingRead | pending |
| sctp_contract_test.go | TestAcceptDoesNotReturnATypedNilConn | pending |
| sctp_contract_test.go | TestAcceptedConnDoesNotInheritTheAcceptDeadline | pending |
| sctp_contract_test.go | TestAbortWakesAParkedReader | pending |
| sctp_contract_test.go | TestErrorsAfterCloseWrapNetErrClosed | pending |
| sctp_contract_test.go | TestWriteWithZeroLengthBufferIsANoOp | pending |
| sctp_contract_test.go | TestPrimaryAddrSettersRejectMultipleAddresses | pending |
| sctp_contract_test.go | TestIPv6AssociationRoundTrip | pending |
| sctp_contract_test.go | TestSetSelectReadFDUsesNativeWordSize | pending |
| sctp_crosscompile_test.go | TestCrossCompileSmoke | pending |
| sctp_deadline_test.go | TestReadDeadlineExpires | pending |
| sctp_deadline_test.go | TestReadDeadlineInThePast | pending |
| sctp_deadline_test.go | TestReadDeadlineCleared | pending |
| sctp_deadline_test.go | TestReadDeadlineDoesNotTruncateData | pending |
| sctp_deadline_test.go | TestReadMsgDeadlineBoundsWholeCall | pending |
| sctp_deadline_test.go | TestWriteDeadlineInThePast | pending |
| sctp_deadline_test.go | TestSetDeadlineSetsBoth | pending |
| sctp_deadline_test.go | TestDeadlineSetFromAnotherGoroutine | pending |
| sctp_deadline_test.go | TestWriteDeadlineStateIsAtomicWithPollerUpdate | pending |
| sctp_deadline_test.go | TestWriteDeadlineStateConcurrentSetters | pending |
| sctp_dialcontext_test.go | TestDialContextAlreadyCancelledOpensNoSocket | pending |
| sctp_dialcontext_test.go | TestDialContextTimeoutAbandonsTheAttempt | pending |
| sctp_dialcontext_test.go | TestDialContextCancelDuringDial | pending |
| sctp_dialcontext_test.go | TestDialContextQuietAbandonPolicyReleasesAttempt | pending |
| sctp_dialcontext_test.go | TestDialContextQuietAbandonPolicyCancelDuringDial | pending |
| sctp_dialcontext_test.go | TestDialContextInvalidAbandonPolicyOpensNoSocket | pending |
| sctp_dialcontext_test.go | TestDialContextAbandonedAttemptsLeakNothing | pending |
| sctp_dialcontext_test.go | TestDialContextSucceeds | pending |
| sctp_dialcontext_test.go | TestDialContextReturnsPollableDescriptor | pending |
| sctp_dialcontext_test.go | TestDialContextRefusedPeerReportsTheError | pending |
| sctp_dialcontext_test.go | TestSocketConfigDialContext | pending |
| sctp_dialpolicy_test.go | TestAbandonDialSocketUsesPolicy | pending |
| sctp_eintr_test.go | TestReadSurvivesSignals | pending |
| sctp_eintr_test.go | TestAcceptSurvivesSignals | pending |
| sctp_eintr_test.go | TestGracefulCloseSurvivesSignals | pending |
| sctp_eintr_test.go | TestDialNeverReturnsAnUnestablishedAssociation | pending |
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
| sctp_error_contract_linux_test.go | TestNetConnIOErrorsCarryConnectionContext | pending |
| sctp_error_contract_linux_test.go | TestNetConnIOErrorsPreserveExplicitNetwork | pending |
| sctp_error_contract_linux_test.go | TestClosedNetConnErrorsRetainConnectionContext | pending |
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
| sctp_extensions_test.go | TestDefaultSndInfoRoundTrip | pending |
| sctp_extensions_test.go | TestDefaultSndInfoRejectsShortOption | pending |
| sctp_extensions_test.go | TestAutoAsconfNeedsBoundSocket | pending |
| sctp_extensions_test.go | TestPrSupportedFollowsSysctl | pending |
| sctp_extensions_test.go | TestDefaultPrInfoRoundTrip | pending |
| sctp_extensions_test.go | TestPrPolicyConstantValues | ported → TestEnumerationValues (its PR-policy, stream-reset-mask and HMAC rows; enums_test.go); its SCTP_ENABLE_STRRESET_MASK completeness check has no v2 row of its own — StreamResetMask only names the three bits the mask actually carries |
| sctp_extensions_test.go | TestOptionNumbersMatchHeader | ported → TestOptionNumbers (abi_test.go); its SCTP_PEER_ADDR_THLDS, SCTP_SOCKOPT_PEELOFF and SCTP_SOCKOPT_CONNECTX rows retired: v2 uses only SCTP_PEER_ADDR_THLDS_V2, SCTP_SOCKOPT_PEELOFF_FLAGS and SCTP_SOCKOPT_CONNECTX3, so the superseded option numbers are never defined |
| sctp_extensions_test.go | TestAssocIDAndSinfoConstantsMatchHeader | ported → TestAssocScopeSelectors (abi_test.go); its SCTP_NOTIFICATION == MSG_NOTIFICATION row has no v2 counterpart, see TestAssocScopeSelectors's doc comment |
| sctp_extensions_test.go | TestDefaultPrInfoRejectsUnknownPolicy | pending |
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
| sctp_fdleak_test.go | TestSetupFailureReleasesDescriptor | pending |
| sctp_fdleak_test.go | TestListenSuccessDoesNotReleaseDescriptor | pending |
| sctp_fdleak_test.go | TestFileListenerDoesNotLeakDescriptors | pending |
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
| sctp_listener_test.go | TestListenerDoubleCloseDoesNotCloseRecycledFd | pending |
| sctp_listener_test.go | TestListenerCloseIsIdempotent | pending |
| sctp_listener_test.go | TestListenerConcurrentClose | pending |
| sctp_listener_test.go | TestListenerCloseUnblocksAccept | pending |
| sctp_listener_test.go | TestListenerAcceptAfterCloseFails | pending |
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
| sctp_multihome_test.go | TestMultihomedAssociationExchangesAddresses | pending |
| sctp_multihome_test.go | TestMultihomedListenerAcceptsEveryBoundAddress | pending |
| sctp_multihome_test.go | TestMultihomedListenerServesManyPeers | pending |
| sctp_multihome_test.go | TestMultihomedBindRejectsAnUnusableAddress | pending |
| sctp_netconn_contract_test.go | TestNetConnPendingReadObservesLaterDeadline | pending |
| sctp_netconn_contract_test.go | TestSCTPListenerPendingAcceptObservesLaterDeadline | pending |
| sctp_netconn_contract_test.go | TestNetConnWriteWaitsForBufferSpace | pending |
| sctp_netconn_contract_test.go | TestNetConnDeadlineSettersAfterClose | pending |
| sctp_netconn_contract_test.go | TestNetConnAddressesRemainStableAfterClose | pending |
| sctp_netconn_contract_test.go | TestNetConnZeroLengthClosedParity | pending |
| sctp_nil_linux_test.go | TestFileListenerRejectsNilFile | pending |
| sctp_nil_linux_test.go | TestZeroValueConnectionNeverOwnsDescriptorZero | pending |
| sctp_nil_linux_test.go | TestNewSCTPConnSetsCloseOnExec | pending |
| sctp_nil_linux_test.go | TestCloseOnExecRunsUnderForkLock | pending |
| sctp_nil_test.go | TestNilPublicReceiversReturnErrors | pending |
| sctp_nil_test.go | TestNilWrappedConnDoesNotPanic | pending |
| sctp_nil_test.go | TestNilSocketOptionArgumentsReturnEINVAL | pending |
| sctp_nil_test.go | TestNilAddressesReturnErrors | pending |
| sctp_nil_test.go | TestNilDialContextReturnsEINVAL | pending |
| sctp_notification_kernel_test.go | TestParseNotificationAgainstKernel | pending |
| sctp_notification_kernel_test.go | TestNotificationHandlerReassemblesKernelNotification | pending |
| sctp_notification_kernel_test.go | TestRawNotificationReadPreservesFragments | pending |
| sctp_notification_kernel_test.go | TestSendFailedEventExceedsNotificationMaxSize | pending |
| sctp_notification_test.go | TestTypedNilNotificationAccessorsReturnZero | pending |
| sctp_notification_test.go | TestNotificationSizesMatchKernel | pending |
| sctp_notification_test.go | TestNotificationMaxSizeHoldsEveryFixedNotification | pending |
| sctp_notification_test.go | TestNotificationAccumulator | pending |
| sctp_notification_test.go | FuzzNotificationAccumulator | pending |
| sctp_notification_test.go | TestParseNotificationRejectsTruncated | pending |
| sctp_notification_test.go | TestParseNotificationBoundsByDeclaredLength | pending |
| sctp_notification_test.go | TestParseNotificationAssocChange | pending |
| sctp_notification_test.go | TestParseNotificationCopiesTrailingData | pending |
| sctp_notification_test.go | TestParseNotificationPartialDeliveryFieldOrder | pending |
| sctp_notification_test.go | TestParseNotificationPeerAddrChange | pending |
| sctp_notification_test.go | TestParseNotificationUnknownType | pending |
| sctp_notification_test.go | FuzzParseNotification | pending |
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
| sctp_preassociation_linux_test.go | TestSocketConfigPreAssociationListenerReadback | pending |
| sctp_preassociation_linux_test.go | TestSocketConfigPreAssociationRTOInfoOnDialPaths | pending |
| sctp_preassociation_linux_test.go | TestSocketConfigPreAssociationNegotiatesOnDialPaths | pending |
| sctp_preassociation_linux_test.go | TestSocketConfigPreAssociationDelayedSACKOnEndpoints | pending |
| sctp_preassociation_linux_test.go | TestSocketConfigPreAssociationValidationPrecedesSocketAndControl | pending |
| sctp_preassociation_linux_test.go | TestSocketConfigPreAssociationLevelTwoFailsClosedOnOneToOne | pending |
| sctp_preassociation_portable_test.go | TestWithPreAssociationSnapshotsAllMutableInputs | pending |
| sctp_preassociation_portable_test.go | TestWithPreAssociationPreservesNilAndEmptySlices | pending |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationZeroValue | pending |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationExplicitFragmentInterleaveWins | pending |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationOrderAndValues | pending |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationRejectsInvalidConfiguration | pending |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationEndpointInterleavingUsesRFCDefault | pending |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationEndpointLevelTwoEnablesRcvInfoFirst | pending |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationLevelTwoAcceptsDataIOEventFirst | pending |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationDelayedSACKBoundaries | pending |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationRTOInfoBoundaries | pending |
| sctp_preassociation_portable_test.go | TestSetSackTimerPrevalidatesProtocolMaximum | pending |
| sctp_preassociation_portable_test.go | TestPreparePreAssociationSnapshotsSlices | pending |
| sctp_preassociation_portable_test.go | TestNilSocketConfigMethodsDoNotPanic | pending |
| sctp_preassociation_portable_test.go | FuzzPreparePreAssociationConfig | pending |
| sctp_preassociation_unsupported_test.go | TestSocketConfigPreAssociationUnsupportedParity | pending |
| sctp_rawconn_test.go | TestSyscallConnReadSharesReceiveSerialization | pending |
| sctp_rawconn_test.go | TestPollConstantsMatchKernel | pending |
| sctp_rawconn_test.go | TestPollFdLayoutMatchesKernel | pending |
| sctp_rawconn_test.go | TestPollWaitReportsTimeout | pending |
| sctp_rawconn_test.go | TestPollWaitReportsWritable | pending |
| sctp_rawconn_test.go | TestSyscallConnWriteWaitsForWritability | pending |
| sctp_rawconn_test.go | TestSyscallConnReadWaitsForData | pending |
| sctp_rawconn_test.go | TestSyscallConnStopsWhenDone | pending |
| sctp_rawconn_test.go | TestSyscallConnHonoursDeadline | pending |
| sctp_rawconn_test.go | TestSyscallConnAfterCloseReturnsNetErrClosed | pending |
| sctp_rawconn_test.go | TestListenerSyscallConnReadWriteReturnEINVAL | pending |
| sctp_rawconn_test.go | TestListenerRawConnAfterCloseDoesNotUseRecycledFD | pending |
| sctp_rawconn_test.go | TestSCTPWriteWithoutDeadlineReturnsEAGAIN | pending |
| sctp_rawconn_test.go | TestSCTPWriteWithDeadlineWaitsForSpace | pending |
| sctp_rawconn_test.go | TestSCTPWriteDeadlineExpiresWhileSendBufferFull | pending |
| sctp_rawconn_test.go | TestSCTPWriteDeadlineInThePastDoesNotWait | pending |
| sctp_rawconn_test.go | TestSyscallConnDoesNotSpinWhenReadyButNotDone | pending |
| sctp_rawconn_test.go | TestSyscallConnCloseUnblocksWait | pending |
| sctp_rawconn_test.go | TestSyscallConnAbortUnblocksWait | pending |
| sctp_rawconn_test.go | TestSocketConfigRawConnReadWriteReturnEINVAL | pending |
| sctp_rawconn_test.go | TestSyscallConnConcurrent | pending |
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
| sctp_readmsg_test.go | TestZeroLengthSendIsRefusedByTheKernel | pending |
| sctp_readmsg_test.go | FuzzReadMsg | pending |
| sctp_resolve_linux_test.go | TestExplicitNetworkRejectsTheOtherAddressFamily | pending |
| sctp_resolve_portable_test.go | TestNilSCTPAddrString | pending |
| sctp_resolve_portable_test.go | TestDirectSCTPAddrValuesAreValidated | pending |
| sctp_resolve_portable_test.go | TestSCTPBindRejectsUnknownFlagsBeforeTouchingTheAddress | pending |
| sctp_resolve_portable_test.go | TestResolveSCTPAddrRejectsMalformedInput | pending |
| sctp_resolve_portable_test.go | TestResolveSCTPAddrAcceptsTheDocumentedForms | pending |
| sctp_resolve_portable_test.go | TestResolveSCTPAddrNeverReturnsANilAddress | pending |
| sctp_resolve_portable_test.go | FuzzResolveSCTPAddr | pending |
| sctp_resolve_portable_test.go | FuzzSCTPAddrMarshal | pending |
| sctp_resolveraw_kernel_test.go | TestKernelAddrsRoundTrip | pending |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrMixedFamilies | pending |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrV6First | pending |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrUnknownFamilyIsRejected | pending |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrZeroCount | pending |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrRespectsBuffer | pending |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrRejectsImpossibleCountBeforeWalking | pending |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrNegativeCount | pending |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrPortFromLaterEntriesIgnored | pending |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrPortFromFirstEntry | pending |
| sctp_resolveraw_portable_test.go | TestResolveFromRawAddrDoesNotAliasBuffer | pending |
| sctp_resolveraw_portable_test.go | FuzzResolveFromRawAddr | pending |
| sctp_shutdownwait_test.go | TestAssocQueryAnswersForALiveAssociation | pending |
| sctp_shutdownwait_test.go | TestWaitAssocGoneDoesNotTreatProbeFailureAsCompletion | pending |
| sctp_shutdownwait_test.go | TestShutdownViaEOFRetriesInterruptAndBackpressure | pending |
| sctp_shutdownwait_test.go | TestShutdownViaEOFBackpressureHonorsDeadline | pending |
| sctp_shutdownwait_test.go | TestShutdownViaEOFPropagatesWaitAndSendErrors | pending |
| sctp_shutdownwait_test.go | TestCloseTimeoutBoundsTheShutdownWait | pending |
| sctp_shutdownwait_test.go | TestCloseWithRespondingPeerReturnsPromptly | pending |
| sctp_shutdownwait_test.go | TestCloseReleasesPortAfterUnresponsivePeer | pending |
| sctp_shutdownwait_test.go | TestListenerAcceptDeadline | pending |
| sctp_shutdownwait_test.go | TestRawSocketTimeoutDoesNotBecomeListenerDeadline | pending |
| sctp_shutdownwait_test.go | TestListenerDeadlineInThePast | pending |
| sctp_shutdownwait_test.go | TestSendDoesNotRaiseSIGPIPE | pending |
| sctp_shutdownwait_test.go | TestRawWaitTerminatesOnAbortedAssociation | pending |
| sctp_sndinfo_test.go | TestSCTPWriteInfoCarriesStreamAndPPID | pending |
| sctp_sndinfo_test.go | TestSCTPWriteInfoNilInfoUsesDefaults | pending |
| sctp_sndinfo_test.go | TestSCTPWriteInfoWithPrInfo | pending |
| sctp_sndinfo_test.go | TestSCTPWriteInfoCmsgPadding | pending |
| sctp_sndinfo_test.go | TestCmsgPaddingIsObservable | pending |
| sctp_sndinfo_test.go | TestSCTPWriteInfoRejectsBadPrPolicy | pending |
| sctp_sndinfo_test.go | TestSCTPWriteInfoInteropWithSCTPWrite | pending |
| sctp_sndinfo_test.go | TestSCTPWriteInfoHonoursWriteDeadline | pending |
| sctp_sndinfo_test.go | TestSCTPWriteInfoWithAuthInfo | pending |
| sctp_sockopt_stack_test.go | TestSubscribedEventsSurvivesStackGrowth | pending |
| sctp_sockopt_stack_test.go | TestRawGetsockoptSurvivesStackGrowth | pending |
| sctp_sockopt_stack_test.go | TestInternalRawGetsockoptSurvivesStackGrowth | pending |
| sctp_sockopt_stack_test.go | TestSubscribeEventsSurvivesStackGrowth | pending |
| sctp_sockopt_stack_test.go | TestSetRtoInfoKeepsOptionAlive | pending |
| sctp_sockopt_stack_test.go | TestRawSetsockoptKeepsOptionAlive | pending |
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
| sctp_streams_test.go | TestStreams | pending |
| sctp_syscall_linux_test.go | TestRawSockoptSyscalls | pending |
| sctp_syscall_linux_test.go | TestRawMessageSyscalls | pending |
| sctp_syscall_linux_test.go | TestRawRecvmsgStackStorage | pending |
| sctp_test.go | TestSCTPAddrString | pending |
| sctp_test.go | TestResolveSCTPAddr | pending |
| sctp_test.go | TestSCTPListenerName | pending |
| sctp_test.go | TestSCTPConcurrentAccept | pending |
| sctp_test.go | TestSCTPCloseRecv | pending |
| sctp_test.go | TestGetStatus | pending |
| sctp_test.go | TestGetStatusUsage | pending |
| sctp_tobuf_test.go | TestToBufSerialisesFixedSizeStructs | pending |
| sctp_tobuf_test.go | TestToBufPanicsOnUnserialisableType | pending |
| sctp_unsupported_test.go | TestUnsupportedHighLevelErrorsCarryOperationContext | pending |
| sctp_unsupported_test.go | TestUnsupportedRawConnectErrorRemainsUnwrapped | pending |
| sctp_unsupported_test.go | TestNewSCTPConnClosesOwnedDescriptorOnUnsupportedPlatform | pending |
| sctp_unsupported_test.go | TestDialContextWithAbandonPolicyValidatesPolicyOnUnsupportedPlatform | pending |
| sctp_unsupported_test.go | TestDynamicBindEntryPointsReportUnsupported | pending |
| sctp_unsupported_test.go | TestUnsupportedEntryPointsReportTheSentinel | pending |
| sctp_unsupported_test.go | TestUnsupportedStubManifestIsComplete | pending |
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
