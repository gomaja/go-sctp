package sctp

import "fmt"

// SocketOptionState controls an optional boolean socket setting without making
// the zero value mean "disabled". SocketOptionDefault leaves the setting alone,
// so a zero-valued PreAssociationConfig preserves the kernel default.
type SocketOptionState uint8

const (
	// SocketOptionDefault leaves the socket option unchanged.
	SocketOptionDefault SocketOptionState = iota
	// SocketOptionEnable writes an enabled value to the socket option.
	SocketOptionEnable
	// SocketOptionDisable writes a disabled value to the socket option.
	SocketOptionDisable
)

// String returns the configuration name used in validation errors.
func (state SocketOptionState) String() string {
	switch state {
	case SocketOptionDefault:
		return "default"
	case SocketOptionEnable:
		return "enable"
	case SocketOptionDisable:
		return "disable"
	default:
		return fmt.Sprintf("SocketOptionState(%d)", state)
	}
}

// OptionalUint32 distinguishes an explicit zero from an unset uint32 option.
// Value must be zero when Set is false; rejecting an otherwise ignored value
// catches incomplete configurations before a descriptor is opened.
type OptionalUint32 struct {
	Set   bool
	Value uint32
}

// OptionalInt distinguishes an explicit zero from an unset int option. Value
// must be zero when Set is false; each field using this type documents its own
// accepted range.
type OptionalInt struct {
	Set   bool
	Value int
}

// DelayedSACKConfig configures the delayed acknowledgement policy for future
// associations (RFC 6458 §8.1.19 and RFC 9260 §6.2). A zero field leaves
// that field unchanged. Delay is milliseconds; values above 500 are rejected
// before a descriptor is opened because RFC 9260 says an implementation MUST
// NOT allow a larger SACK.Delay.
//
// RFC 9260 also says an acknowledgement SHOULD be generated within 200 ms and
// for at least every second packet. Delay values from 201 through 500 and
// Frequency values above 2 are accepted because those are recommendations, not
// prohibitions; using a non-nil config makes that deliberate departure explicit.
type DelayedSACKConfig struct {
	Delay     uint32
	Frequency uint32
}

// NotificationSubscription configures one modern SCTP_EVENT subscription from
// RFC 6458 §6.2.2 for future associations. State must be SocketOptionEnable or
// SocketOptionDisable; omit an entry instead of using SocketOptionDefault.
//
// Linux does not expose RFC 6458 §6.1.10's
// SCTP_NOTIFICATIONS_STOPPED_EVENT. This type accepts only notification values
// represented by this package and never guesses the missing kernel value.
type NotificationSubscription struct {
	Type  SCTPNotificationType
	State SocketOptionState
}

// PreAssociationConfig is the typed socket configuration applied after
// SocketConfig.Control and InitMsg, but before bind, connect, or listen. It is
// snapshotted and validated before a descriptor is opened. Typed settings take
// precedence over overlapping writes made by Control.
//
// The zero value is safe. Boolean settings use an explicit three-state value,
// while numeric settings use OptionalUint32 or OptionalInt so an intentional
// zero is distinguishable from the default.
//
// Authentication key bytes and active-key selection deliberately remain in
// Control. RFC 4895 §6.1 permits endpoint-pair keys to be established by an
// external mechanism, and retaining secret material in a reusable SocketConfig
// would extend its lifetime unnecessarily. The non-secret INIT state is exposed
// by Authentication, HMACIdentifiers, and AuthenticatedChunks.
type PreAssociationConfig struct {
	// PartialReliability negotiates PR-SCTP (RFC 7496 §4.5).
	PartialReliability SocketOptionState
	// StreamReconfiguration controls Linux's negotiation switch for RFC 6525.
	// RFC 6525 §6.3 defines StreamResetMask, but does not define this Linux
	// support switch.
	StreamReconfiguration SocketOptionState
	// DynamicAddressReconfiguration negotiates ASCONF (RFC 5061). Enabling it
	// requires Authentication to be explicitly enabled because RFC 5061
	// §§4.1.1 and 4.1.2 require ASCONF and ASCONF-ACK to be authenticated.
	DynamicAddressReconfiguration SocketOptionState
	// Authentication negotiates SCTP-AUTH (RFC 4895).
	Authentication SocketOptionState
	// MessageInterleaving negotiates I-DATA user-message interleaving
	// (RFC 8260). Linux also requires a non-zero fragment-interleave level.
	MessageInterleaving SocketOptionState
	// ExperimentalECN controls Linux's SCTP_ECN_SUPPORTED option. RFC 9260
	// §1.7 removed the earlier SCTP ECN specification, so enabling this is an
	// explicitly experimental kernel choice, not standards compliance.
	ExperimentalECN SocketOptionState

	// ReusePort is SCTP_REUSE_PORT (RFC 6458 §8.1.27). RFC 6458 limits it to
	// one-to-one sockets, so any non-default value is rejected for SCTPEndpoint.
	ReusePort SocketOptionState
	// MappedV4Address is SCTP_I_WANT_MAPPED_V4_ADDR (RFC 6458 §8.1.15).
	MappedV4Address SocketOptionState
	// DisableFragments is SCTP_DISABLE_FRAGMENTS (RFC 6458 §8.1.11).
	DisableFragments SocketOptionState
	// ReceiveRcvInfo enables SCTP_RCVINFO (RFC 6458 §§5.3.5 and 8.1.29).
	// SCTPEndpoint requires it and rejects an explicit disable.
	ReceiveRcvInfo SocketOptionState
	// ReceiveNxtInfo enables SCTP_NXTINFO (RFC 6458 §§5.3.6 and 8.1.30).
	ReceiveNxtInfo SocketOptionState

	// AdaptationLayer announces an adaptation indication in INIT
	// (RFC 6458 §8.1.10). Zero is a valid explicit indication.
	AdaptationLayer OptionalUint32
	// FragmentInterleave is the level from RFC 6458 §8.1.20. Values 0, 1,
	// and 2 are accepted by portable validation. Current Linux stores this as a
	// boolean, so applying level 2 returns an error wrapping
	// errors.ErrUnsupported instead of silently degrading to level 1. When it
	// is unset, one-to-one sockets preserve the kernel default, while one-to-many
	// SCTPEndpoint sockets apply level 1 as that section's SHOULD default.
	// Explicit level 0, 1, or 2 always wins portable validation.
	FragmentInterleave OptionalInt
	// StreamResetMask selects the RFC 6525 §6.3 requests this endpoint permits.
	// It is a combination of the SCTPEnableReset constants; zero explicitly
	// permits none.
	StreamResetMask OptionalUint32
	// RTOInfo applies retransmission timeout parameters to SCTP_FUTURE_ASSOC
	// before connect, bind, or listen (RFC 6458 §8.1.1, SCTP_RTOINFO). Nil
	// leaves the kernel defaults unchanged. Non-zero fields set milliseconds;
	// zero fields leave those values unchanged. AssocID must be
	// SCTP_FUTURE_ASSOC.
	RTOInfo *RtoInfo
	// DelayedSACK applies Delay and Frequency to SCTP_FUTURE_ASSOC. Nil leaves
	// the kernel defaults unchanged. The pointed-to value is snapshotted before
	// SocketConfig opens a descriptor or invokes Control.
	DelayedSACK *DelayedSACKConfig

	// HMACIdentifiers is the preference-ordered HMAC-ALGO list sent in INIT
	// (RFC 4895 §§3.3 and 6.1). Nil leaves the kernel list unchanged. A
	// non-nil list must include mandatory SHA-1, contain only assigned package
	// identifiers, and requires Authentication to be explicitly enabled.
	HMACIdentifiers []uint16
	// AuthenticatedChunks is the additive CHUNKS list sent in INIT
	// (RFC 4895 §§3.2 and 6.1). Nil adds nothing. A non-nil list must be
	// non-empty and unique, cannot contain INIT, INIT-ACK, SHUTDOWN-COMPLETE,
	// or AUTH, and requires Authentication to be explicitly enabled.
	AuthenticatedChunks []uint8

	// Notifications configures future-association subscriptions with the
	// non-deprecated SCTP_EVENT option (RFC 6458 §6.2.2). Duplicate types are
	// rejected. SCTPEndpoint requires SCTP_ASSOC_CHANGE and rejects disabling
	// it as a package invariant, following RFC 6458 §3.1.3's recommendation to
	// ensure the event is enabled when association ids are used.
	Notifications []NotificationSubscription
}

func clonePreAssociationConfig(cfg PreAssociationConfig) PreAssociationConfig {
	cloned := cfg
	if cfg.DelayedSACK != nil {
		delayed := *cfg.DelayedSACK
		cloned.DelayedSACK = &delayed
	}
	if cfg.RTOInfo != nil {
		info := *cfg.RTOInfo
		cloned.RTOInfo = &info
	}
	if cfg.HMACIdentifiers != nil {
		cloned.HMACIdentifiers = append([]uint16{}, cfg.HMACIdentifiers...)
	}
	if cfg.AuthenticatedChunks != nil {
		cloned.AuthenticatedChunks = append([]uint8{}, cfg.AuthenticatedChunks...)
	}
	if cfg.Notifications != nil {
		cloned.Notifications = append([]NotificationSubscription{}, cfg.Notifications...)
	}
	return cloned
}

type preAssociationSocketStyle uint8

const (
	preAssociationOneToOne preAssociationSocketStyle = iota
	preAssociationOneToMany
)

func (style preAssociationSocketStyle) String() string {
	switch style {
	case preAssociationOneToOne:
		return "one-to-one"
	case preAssociationOneToMany:
		return "one-to-many"
	default:
		return fmt.Sprintf("preAssociationSocketStyle(%d)", style)
	}
}

type preAssociationOption uint8

const (
	preAssociationFragmentInterleave preAssociationOption = iota
	preAssociationAuthentication
	preAssociationHMACIdentifiers
	preAssociationAuthenticatedChunk
	preAssociationDynamicAddressReconfiguration
	preAssociationPartialReliability
	preAssociationStreamReconfiguration
	preAssociationStreamResetMask
	preAssociationMessageInterleaving
	preAssociationExperimentalECN
	preAssociationAdaptationLayer
	preAssociationRTOInfo
	preAssociationDelayedSACK
	preAssociationMappedV4Address
	preAssociationDisableFragments
	preAssociationReusePort
	preAssociationReceiveRcvInfo
	preAssociationReceiveNxtInfo
	preAssociationNotification
)

func (option preAssociationOption) String() string {
	switch option {
	case preAssociationFragmentInterleave:
		return "FragmentInterleave"
	case preAssociationAuthentication:
		return "Authentication"
	case preAssociationHMACIdentifiers:
		return "HMACIdentifiers"
	case preAssociationAuthenticatedChunk:
		return "AuthenticatedChunks"
	case preAssociationDynamicAddressReconfiguration:
		return "DynamicAddressReconfiguration"
	case preAssociationPartialReliability:
		return "PartialReliability"
	case preAssociationStreamReconfiguration:
		return "StreamReconfiguration"
	case preAssociationStreamResetMask:
		return "StreamResetMask"
	case preAssociationMessageInterleaving:
		return "MessageInterleaving"
	case preAssociationExperimentalECN:
		return "ExperimentalECN"
	case preAssociationAdaptationLayer:
		return "AdaptationLayer"
	case preAssociationRTOInfo:
		return "RTOInfo"
	case preAssociationDelayedSACK:
		return "DelayedSACK"
	case preAssociationMappedV4Address:
		return "MappedV4Address"
	case preAssociationDisableFragments:
		return "DisableFragments"
	case preAssociationReusePort:
		return "ReusePort"
	case preAssociationReceiveRcvInfo:
		return "ReceiveRcvInfo"
	case preAssociationReceiveNxtInfo:
		return "ReceiveNxtInfo"
	case preAssociationNotification:
		return "Notifications"
	default:
		return fmt.Sprintf("preAssociationOption(%d)", option)
	}
}

// preAssociationOperation is an immutable socket-option write. Slices are
// copied while preparing the plan so Control cannot mutate already validated
// input through a shared backing array.
type preAssociationOperation struct {
	kind             preAssociationOption
	value            uint32
	secondaryValue   uint32
	notificationType SCTPNotificationType
	hmacIdentifiers  []uint16
	rtoInfo          RtoInfo
}

type preparedPreAssociationConfig struct {
	operations []preAssociationOperation
}

func preparePreAssociationConfig(cfg PreAssociationConfig, style preAssociationSocketStyle) (preparedPreAssociationConfig, error) {
	if style != preAssociationOneToOne && style != preAssociationOneToMany {
		return preparedPreAssociationConfig{}, fmt.Errorf("sctp: invalid pre-association socket style %d", style)
	}

	states := []struct {
		name  string
		state SocketOptionState
	}{
		{"PartialReliability", cfg.PartialReliability},
		{"StreamReconfiguration", cfg.StreamReconfiguration},
		{"DynamicAddressReconfiguration", cfg.DynamicAddressReconfiguration},
		{"Authentication", cfg.Authentication},
		{"MessageInterleaving", cfg.MessageInterleaving},
		{"ExperimentalECN", cfg.ExperimentalECN},
		{"ReusePort", cfg.ReusePort},
		{"MappedV4Address", cfg.MappedV4Address},
		{"DisableFragments", cfg.DisableFragments},
		{"ReceiveRcvInfo", cfg.ReceiveRcvInfo},
		{"ReceiveNxtInfo", cfg.ReceiveNxtInfo},
	}
	for _, item := range states {
		if item.state > SocketOptionDisable {
			return preparedPreAssociationConfig{}, fmt.Errorf(
				"sctp: PreAssociation.%s has invalid state %d", item.name, item.state)
		}
	}

	if !cfg.AdaptationLayer.Set && cfg.AdaptationLayer.Value != 0 {
		return preparedPreAssociationConfig{}, fmt.Errorf(
			"sctp: PreAssociation.AdaptationLayer has Value %d while Set is false",
			cfg.AdaptationLayer.Value)
	}
	if !cfg.FragmentInterleave.Set && cfg.FragmentInterleave.Value != 0 {
		return preparedPreAssociationConfig{}, fmt.Errorf(
			"sctp: PreAssociation.FragmentInterleave has Value %d while Set is false",
			cfg.FragmentInterleave.Value)
	}
	if cfg.FragmentInterleave.Set {
		switch cfg.FragmentInterleave.Value {
		case SCTPFragmentInterleaveNone, SCTPFragmentInterleaveOther,
			SCTPFragmentInterleaveStreams:
		default:
			return preparedPreAssociationConfig{}, fmt.Errorf(
				"sctp: PreAssociation.FragmentInterleave level %d is not one of 0, 1 or 2",
				cfg.FragmentInterleave.Value)
		}
	}
	if !cfg.StreamResetMask.Set && cfg.StreamResetMask.Value != 0 {
		return preparedPreAssociationConfig{}, fmt.Errorf(
			"sctp: PreAssociation.StreamResetMask has Value %#x while Set is false",
			cfg.StreamResetMask.Value)
	}
	allResetBits := uint32(SCTPEnableResetStreamReq | SCTPEnableResetAssocReq |
		SCTPEnableChangeAssocReq)
	if cfg.StreamResetMask.Set && cfg.StreamResetMask.Value&^allResetBits != 0 {
		return preparedPreAssociationConfig{}, fmt.Errorf(
			"sctp: PreAssociation.StreamResetMask %#x has unknown bits %#x",
			cfg.StreamResetMask.Value, cfg.StreamResetMask.Value&^allResetBits)
	}
	if cfg.DelayedSACK != nil && cfg.DelayedSACK.Delay > 500 {
		return preparedPreAssociationConfig{}, fmt.Errorf(
			"sctp: PreAssociation.DelayedSACK.Delay %d ms exceeds RFC 9260 §6.2's 500 ms maximum",
			cfg.DelayedSACK.Delay)
	}
	if cfg.RTOInfo != nil && cfg.RTOInfo.AssocID != SCTPAssocID(SCTP_FUTURE_ASSOC) {
		return preparedPreAssociationConfig{}, fmt.Errorf(
			"sctp: PreAssociation.RTOInfo.AssocID must be SCTP_FUTURE_ASSOC for pre-association SCTP_RTOINFO (RFC 6458 §8.1.1)")
	}

	if err := validatePreAssociationHMACIdentifiers(cfg.HMACIdentifiers); err != nil {
		return preparedPreAssociationConfig{}, err
	}
	if err := validatePreAssociationAuthenticatedChunks(cfg.AuthenticatedChunks); err != nil {
		return preparedPreAssociationConfig{}, err
	}
	if err := validatePreAssociationNotifications(cfg.Notifications, style); err != nil {
		return preparedPreAssociationConfig{}, err
	}

	if cfg.DynamicAddressReconfiguration == SocketOptionEnable &&
		cfg.Authentication != SocketOptionEnable {
		return preparedPreAssociationConfig{}, fmt.Errorf(
			"sctp: PreAssociation.DynamicAddressReconfiguration requires Authentication=enable (RFC 5061 §§4.1.1 and 4.1.2)")
	}
	if (cfg.HMACIdentifiers != nil || cfg.AuthenticatedChunks != nil) &&
		cfg.Authentication != SocketOptionEnable {
		return preparedPreAssociationConfig{}, fmt.Errorf(
			"sctp: PreAssociation.HMACIdentifiers and AuthenticatedChunks require Authentication=enable")
	}
	if cfg.StreamResetMask.Set && cfg.StreamResetMask.Value != 0 &&
		cfg.StreamReconfiguration != SocketOptionEnable {
		return preparedPreAssociationConfig{}, fmt.Errorf(
			"sctp: a non-zero PreAssociation.StreamResetMask requires StreamReconfiguration=enable")
	}

	effectiveFragmentLevel := SCTPFragmentInterleaveNone
	fragmentIsSet := cfg.FragmentInterleave.Set
	if fragmentIsSet {
		effectiveFragmentLevel = cfg.FragmentInterleave.Value
	} else if style == preAssociationOneToMany {
		// RFC 6458 §8.1.20 says one-to-many sockets SHOULD default to level 1.
		// Linux defaults both styles to zero, so endpoint construction corrects
		// only the one-to-many case.
		fragmentIsSet = true
		effectiveFragmentLevel = SCTPFragmentInterleaveOther
	}
	if cfg.MessageInterleaving == SocketOptionEnable &&
		(!fragmentIsSet || effectiveFragmentLevel == SCTPFragmentInterleaveNone) {
		return preparedPreAssociationConfig{}, fmt.Errorf(
			"sctp: PreAssociation.MessageInterleaving=enable requires a non-zero effective FragmentInterleave level")
	}
	if style == preAssociationOneToOne &&
		effectiveFragmentLevel == SCTPFragmentInterleaveStreams &&
		cfg.ReceiveRcvInfo != SocketOptionEnable &&
		!preAssociationDataIOEventEnabled(cfg.Notifications) {
		return preparedPreAssociationConfig{}, fmt.Errorf(
			"sctp: PreAssociation.FragmentInterleave level 2 requires ReceiveRcvInfo=enable or an enabled SCTP_DATA_IO_EVENT subscription (RFC 6458 §8.1.20)")
	}
	if style == preAssociationOneToMany && cfg.ReusePort != SocketOptionDefault {
		return preparedPreAssociationConfig{}, fmt.Errorf(
			"sctp: PreAssociation.ReusePort applies only to one-to-one sockets (RFC 6458 §8.1.27)")
	}
	if style == preAssociationOneToMany && cfg.ReceiveRcvInfo == SocketOptionDisable {
		return preparedPreAssociationConfig{}, fmt.Errorf(
			"sctp: PreAssociation.ReceiveRcvInfo cannot be disabled on SCTPEndpoint; the package requires RFC 6458 §5.3.5 association metadata to route one-to-many messages")
	}

	var operations []preAssociationOperation
	// RFC 6458 §8.1.20 says level 2 should be refused unless RCVINFO or the
	// deprecated data-I/O event supplies stream metadata. Apply either typed
	// prerequisite before the fragment level, not merely before bind.
	receiveRcvInfo := cfg.ReceiveRcvInfo
	if style == preAssociationOneToMany && receiveRcvInfo == SocketOptionDefault {
		// SCTPEndpoint routes every message by association id and therefore
		// cannot preserve the kernel default. Keeping the invariant in the plan
		// also guarantees it precedes FragmentInterleave level 2.
		receiveRcvInfo = SocketOptionEnable
	}
	operations = appendStateOperation(operations,
		preAssociationReceiveRcvInfo, receiveRcvInfo)
	for _, subscription := range cfg.Notifications {
		if subscription.Type == SCTP_DATA_IO_EVENT {
			operations = append(operations, preAssociationOperation{
				kind:             preAssociationNotification,
				value:            socketOptionStateValue(subscription.State),
				notificationType: subscription.Type,
			})
		}
	}
	if fragmentIsSet {
		operations = append(operations, preAssociationOperation{
			kind: preAssociationFragmentInterleave, value: uint32(effectiveFragmentLevel),
		})
	}
	operations = appendStateOperation(operations, preAssociationAuthentication, cfg.Authentication)
	if cfg.HMACIdentifiers != nil {
		operations = append(operations, preAssociationOperation{
			kind:            preAssociationHMACIdentifiers,
			hmacIdentifiers: append([]uint16(nil), cfg.HMACIdentifiers...),
		})
	}
	for _, chunkType := range cfg.AuthenticatedChunks {
		operations = append(operations, preAssociationOperation{
			kind: preAssociationAuthenticatedChunk, value: uint32(chunkType),
		})
	}
	operations = appendStateOperation(operations,
		preAssociationDynamicAddressReconfiguration, cfg.DynamicAddressReconfiguration)
	operations = appendStateOperation(operations,
		preAssociationPartialReliability, cfg.PartialReliability)
	operations = appendStateOperation(operations,
		preAssociationStreamReconfiguration, cfg.StreamReconfiguration)
	if cfg.StreamResetMask.Set {
		operations = append(operations, preAssociationOperation{
			kind: preAssociationStreamResetMask, value: cfg.StreamResetMask.Value,
		})
	}
	operations = appendStateOperation(operations,
		preAssociationMessageInterleaving, cfg.MessageInterleaving)
	operations = appendStateOperation(operations,
		preAssociationExperimentalECN, cfg.ExperimentalECN)
	if cfg.AdaptationLayer.Set {
		operations = append(operations, preAssociationOperation{
			kind: preAssociationAdaptationLayer, value: cfg.AdaptationLayer.Value,
		})
	}
	if cfg.RTOInfo != nil {
		info := *cfg.RTOInfo
		info.AssocID = SCTPAssocID(SCTP_FUTURE_ASSOC)
		operations = append(operations, preAssociationOperation{
			kind: preAssociationRTOInfo, rtoInfo: info,
		})
	}
	if cfg.DelayedSACK != nil {
		operations = append(operations, preAssociationOperation{
			kind:           preAssociationDelayedSACK,
			value:          cfg.DelayedSACK.Delay,
			secondaryValue: cfg.DelayedSACK.Frequency,
		})
	}
	operations = appendStateOperation(operations,
		preAssociationMappedV4Address, cfg.MappedV4Address)
	operations = appendStateOperation(operations,
		preAssociationDisableFragments, cfg.DisableFragments)
	operations = appendStateOperation(operations,
		preAssociationReusePort, cfg.ReusePort)
	operations = appendStateOperation(operations,
		preAssociationReceiveNxtInfo, cfg.ReceiveNxtInfo)
	for _, subscription := range cfg.Notifications {
		if subscription.Type == SCTP_DATA_IO_EVENT {
			continue
		}
		operations = append(operations, preAssociationOperation{
			kind:             preAssociationNotification,
			value:            socketOptionStateValue(subscription.State),
			notificationType: subscription.Type,
		})
	}

	return preparedPreAssociationConfig{operations: operations}, nil
}

func appendStateOperation(operations []preAssociationOperation, kind preAssociationOption, state SocketOptionState) []preAssociationOperation {
	if state == SocketOptionDefault {
		return operations
	}
	return append(operations, preAssociationOperation{
		kind: kind, value: socketOptionStateValue(state),
	})
}

func socketOptionStateValue(state SocketOptionState) uint32 {
	if state == SocketOptionEnable {
		return 1
	}
	return 0
}

func validatePreAssociationHMACIdentifiers(identifiers []uint16) error {
	if identifiers == nil {
		return nil
	}
	if len(identifiers) == 0 {
		return fmt.Errorf("sctp: PreAssociation.HMACIdentifiers is non-nil but empty")
	}
	if len(identifiers) > 2 {
		return fmt.Errorf("sctp: PreAssociation.HMACIdentifiers has %d entries; Linux and RFC 4895 define two assigned algorithms", len(identifiers))
	}

	seen := make(map[uint16]struct{}, len(identifiers))
	hasSHA1 := false
	for _, identifier := range identifiers {
		switch identifier {
		case SCTPAuthHmacIDSHA1:
			hasSHA1 = true
		case SCTPAuthHmacIDSHA256:
		default:
			return fmt.Errorf("sctp: PreAssociation.HMACIdentifiers contains unassigned identifier %d", identifier)
		}
		if _, duplicate := seen[identifier]; duplicate {
			return fmt.Errorf("sctp: PreAssociation.HMACIdentifiers contains duplicate identifier %d", identifier)
		}
		seen[identifier] = struct{}{}
	}
	if !hasSHA1 {
		return fmt.Errorf("sctp: PreAssociation.HMACIdentifiers must include SHA-1 identifier %d (RFC 4895 §§3.3 and 6.1)", SCTPAuthHmacIDSHA1)
	}
	return nil
}

func validatePreAssociationAuthenticatedChunks(chunkTypes []uint8) error {
	if chunkTypes == nil {
		return nil
	}
	if len(chunkTypes) == 0 {
		return fmt.Errorf("sctp: PreAssociation.AuthenticatedChunks is non-nil but empty")
	}

	seen := make(map[uint8]struct{}, len(chunkTypes))
	for _, chunkType := range chunkTypes {
		var forbiddenName string
		switch chunkType {
		case 1:
			forbiddenName = "INIT"
		case 2:
			forbiddenName = "INIT-ACK"
		case 14:
			forbiddenName = "SHUTDOWN-COMPLETE"
		case 15:
			forbiddenName = "AUTH"
		}
		if forbiddenName != "" {
			return fmt.Errorf("sctp: PreAssociation.AuthenticatedChunks contains %s (%d), which RFC 4895 §3.2 forbids", forbiddenName, chunkType)
		}
		if _, duplicate := seen[chunkType]; duplicate {
			return fmt.Errorf("sctp: PreAssociation.AuthenticatedChunks contains duplicate chunk type %d", chunkType)
		}
		seen[chunkType] = struct{}{}
	}
	return nil
}

func validatePreAssociationNotifications(subscriptions []NotificationSubscription, style preAssociationSocketStyle) error {
	seen := make(map[SCTPNotificationType]struct{}, len(subscriptions))
	for index, subscription := range subscriptions {
		if subscription.State != SocketOptionEnable &&
			subscription.State != SocketOptionDisable {
			return fmt.Errorf("sctp: PreAssociation.Notifications[%d] has state %s; use enable or disable, or omit the entry", index, subscription.State)
		}
		if !knownPreAssociationNotificationType(subscription.Type) {
			return fmt.Errorf("sctp: PreAssociation.Notifications[%d] has unknown notification type %#x", index, uint16(subscription.Type))
		}
		if _, duplicate := seen[subscription.Type]; duplicate {
			return fmt.Errorf("sctp: PreAssociation.Notifications contains duplicate type %#x", uint16(subscription.Type))
		}
		seen[subscription.Type] = struct{}{}
		if style == preAssociationOneToMany &&
			subscription.Type == SCTP_ASSOC_CHANGE &&
			subscription.State == SocketOptionDisable {
			return fmt.Errorf("sctp: PreAssociation.Notifications cannot disable SCTP_ASSOC_CHANGE on SCTPEndpoint; the endpoint requires it to track association ids as recommended by RFC 6458 §3.1.3")
		}
	}
	return nil
}

func knownPreAssociationNotificationType(eventType SCTPNotificationType) bool {
	switch eventType {
	case SCTP_DATA_IO_EVENT,
		SCTP_ASSOC_CHANGE,
		SCTP_PEER_ADDR_CHANGE,
		SCTP_SEND_FAILED,
		SCTP_REMOTE_ERROR,
		SCTP_SHUTDOWN_EVENT,
		SCTP_PARTIAL_DELIVERY_EVENT,
		SCTP_ADAPTATION_INDICATION,
		SCTP_AUTHENTICATION_INDICATION,
		SCTP_SENDER_DRY_EVENT,
		SCTP_STREAM_RESET_EVENT,
		SCTP_ASSOC_RESET_EVENT,
		SCTP_STREAM_CHANGE_EVENT,
		SCTP_SEND_FAILED_EVENT:
		return true
	default:
		return false
	}
}

func preAssociationDataIOEventEnabled(subscriptions []NotificationSubscription) bool {
	for _, subscription := range subscriptions {
		if subscription.Type == SCTP_DATA_IO_EVENT &&
			subscription.State == SocketOptionEnable {
			return true
		}
	}
	return false
}
