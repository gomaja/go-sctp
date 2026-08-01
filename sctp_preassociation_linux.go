//go:build linux
// +build linux

package sctp

import (
	"errors"
	"fmt"
	"unsafe"
)

func applyPreparedPreAssociationConfig(fd int, prepared preparedPreAssociationConfig) error {
	for _, operation := range prepared.operations {
		if err := applyPreAssociationOperation(fd, operation); err != nil {
			return fmt.Errorf("sctp: apply PreAssociation.%s: %w", operation.kind, err)
		}
	}
	return nil
}

func applyPreAssociationOperation(fd int, operation preAssociationOperation) error {
	on := operation.value != 0
	switch operation.kind {
	case preAssociationFragmentInterleave:
		if err := setsockoptInt32(fd, SCTP_FRAGMENT_INTERLEAVE, int32(operation.value)); err != nil {
			return err
		}
		applied, err := getsockoptInt32(fd, SCTP_FRAGMENT_INTERLEAVE)
		if err != nil {
			return err
		}
		if uint32(applied) != operation.value {
			return fmt.Errorf("linux applied fragment-interleave level %d after level %d was requested: %w",
				applied, operation.value, errors.ErrUnsupported)
		}
		return nil
	case preAssociationAuthentication:
		return setAssocValue(fd, SCTP_AUTH_SUPPORTED, operation.value)
	case preAssociationHMACIdentifiers:
		buf := buildHmacAlgo(operation.hmacIdentifiers)
		_, _, err := setsockopt(fd, SCTP_HMAC_IDENT,
			uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		return err
	case preAssociationAuthenticatedChunk:
		chunkType := uint8(operation.value)
		_, _, err := setsockopt(fd, SCTP_AUTH_CHUNK,
			uintptr(unsafe.Pointer(&chunkType)), unsafe.Sizeof(chunkType))
		return err
	case preAssociationDynamicAddressReconfiguration:
		return setAssocValue(fd, SCTP_ASCONF_SUPPORTED, operation.value)
	case preAssociationPartialReliability:
		return setAssocValue(fd, SCTP_PR_SUPPORTED, operation.value)
	case preAssociationStreamReconfiguration:
		return setAssocValue(fd, SCTP_RECONFIG_SUPPORTED, operation.value)
	case preAssociationStreamResetMask:
		return setAssocValue(fd, SCTP_ENABLE_STREAM_RESET, operation.value)
	case preAssociationMessageInterleaving:
		return setAssocValue(fd, SCTP_INTERLEAVING_SUPPORTED, operation.value)
	case preAssociationExperimentalECN:
		return setAssocValue(fd, SCTP_ECN_SUPPORTED, operation.value)
	case preAssociationAdaptationLayer:
		value := struct{ AdaptationInd uint32 }{operation.value}
		_, _, err := setsockopt(fd, SCTP_ADAPTATION_LAYER,
			uintptr(unsafe.Pointer(&value)), unsafe.Sizeof(value))
		return err
	case preAssociationRTOInfo:
		info := operation.rtoInfo
		info.AssocID = SCTPAssocID(SCTP_FUTURE_ASSOC)
		_, _, err := setsockopt(fd, SCTP_RTOINFO,
			uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
		return err
	case preAssociationDelayedSACK:
		timer := SackTimer{
			AssocID:       SCTPAssocID(SCTP_FUTURE_ASSOC),
			SackDelay:     operation.value,
			SackFrequency: operation.secondaryValue,
		}
		_, _, err := setsockopt(fd, SCTP_DELAYED_SACK,
			uintptr(unsafe.Pointer(&timer)), unsafe.Sizeof(timer))
		if err != nil {
			return err
		}
		applied := SackTimer{AssocID: SCTPAssocID(SCTP_FUTURE_ASSOC)}
		optlen := uint32(unsafe.Sizeof(applied))
		if _, _, err = getsockopt(fd, SCTP_DELAYED_SACK,
			uintptr(unsafe.Pointer(&applied)), &optlen); err != nil {
			return err
		}
		if operation.value != 0 && applied.SackDelay != operation.value {
			return fmt.Errorf("linux applied delayed-SACK delay %d ms after %d ms was requested: %w",
				applied.SackDelay, operation.value, errors.ErrUnsupported)
		}
		if operation.secondaryValue != 0 &&
			applied.SackFrequency != operation.secondaryValue {
			return fmt.Errorf("linux applied delayed-SACK frequency %d after %d was requested: %w",
				applied.SackFrequency, operation.secondaryValue, errors.ErrUnsupported)
		}
		return nil
	case preAssociationMappedV4Address:
		return setSockoptBool(fd, SCTP_I_WANT_MAPPED_V4_ADDR, on)
	case preAssociationDisableFragments:
		return setSockoptBool(fd, SCTP_DISABLE_FRAGMENTS, on)
	case preAssociationReusePort:
		return setsockoptInt(fd, SCTP_REUSE_PORT, on)
	case preAssociationReceiveRcvInfo:
		return setsockoptInt(fd, SCTP_RECVRCVINFO, on)
	case preAssociationReceiveNxtInfo:
		return setsockoptInt(fd, SCTP_RECVNXTINFO, on)
	case preAssociationNotification:
		event := Event{
			AssocID: SCTPAssocID(SCTP_FUTURE_ASSOC),
			Type:    uint16(operation.notificationType),
		}
		if on {
			event.On = 1
		}
		_, _, err := setsockopt(fd, SCTP_EVENT,
			uintptr(unsafe.Pointer(&event)), unsafe.Sizeof(event))
		return err
	default:
		return fmt.Errorf("unknown prepared operation %d", operation.kind)
	}
}
