// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// config_linux.go writes a prepared Config to a descriptor: one
// setsockopt per operation, in the order prepare produced them. Every
// value is already in the unit and width the kernel field takes, so the
// only work here is laying it out in the kernel's struct.
//
// Every association-scoped option below is written with association id 0,
// SCTP_FUTURE_ASSOC (RFC 6458 §7.2): the socket is set up before it has an
// association, and on a one-to-one socket the kernel applies the value to
// the endpoint, from which every association it creates takes its own copy
// (net/sctp/associola.c: sctp_association_init).

package sctp

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"syscall"
	"unsafe"
)

// field names the Config field an operation comes from, for the error a
// failing setsockopt returns.
func (op *configOp) field() string {
	switch op.kind {
	case opRecvRcvInfo:
		return "SCTP_RECVRCVINFO, which the package always enables"
	case opAssocChange:
		return "the SCTP_ASSOC_CHANGE subscription the package always keeps"
	case opReadBuffer:
		return "Config.ReadBuffer"
	case opWriteBuffer:
		return "Config.WriteBuffer"
	case opInitMsg:
		return "Config.InitMsg"
	case opFragmentInterleave:
		return "Config.FragmentInterleave"
	case opAuthentication:
		return "Config.Authentication"
	case opHMACIdentifiers:
		return "Config.HMACIdentifiers"
	case opAuthChunk:
		return fmt.Sprintf("Config.AuthChunks (chunk type %d)", op.chunk)
	case opDynamicAddressReconfiguration:
		return "Config.DynamicAddressReconfiguration"
	case opPartialReliability:
		return "Config.PartialReliability"
	case opStreamReconfiguration:
		return "Config.StreamReconfiguration"
	case opStreamResetMask:
		return "Config.StreamResetMask"
	case opMessageInterleaving:
		return "Config.MessageInterleaving"
	case opExperimentalECN:
		return "Config.ExperimentalECN"
	case opAdaptationLayer:
		return "Config.AdaptationLayer"
	case opRTOInfo:
		return "Config.RTOInfo"
	case opDelayedSACK:
		return "Config.DelayedSACK"
	case opFragmentsDisabled:
		return "Config.FragmentsDisabled"
	case opReusePort:
		return "Config.ReusePort"
	case opReceiveNxtInfo:
		return "Config.ReceiveNxtInfo"
	case opNoDelay:
		return "Config.NoDelay"
	case opDefaultSndInfo:
		return "Config.DefaultSndInfo"
	case opDefaultPrInfo:
		return "Config.DefaultPrInfo"
	case opNotification:
		return fmt.Sprintf("Config.Notifications (%v)", op.event)
	default:
		return fmt.Sprintf("configOpKind(%d)", op.kind)
	}
}

// applyConfig writes ops to s, in order, inside one raw.Control call. The
// first failure stops it, and its error names the Config field and wraps
// the kernel's errno in an *os.SyscallError, so that, for example, a
// MessageInterleaving refused because net.sctp.intl_enable is 0
// (net/sctp/socket.c: sctp_setsockopt_interleaving_supported) matches
// syscall.EPERM.
func applyConfig(s *socket, ops []configOp) error {
	return s.control(func(fd int) error {
		for i := range ops {
			if err := applyOp(fd, &ops[i]); err != nil {
				return fmt.Errorf("sctp: applying %s: %w", ops[i].field(), os.NewSyscallError("setsockopt", err))
			}
		}
		return nil
	})
}

// applyOp writes one operation to fd. The error is the bare errno.
func applyOp(fd int, op *configOp) error {
	switch op.kind {
	case opRecvRcvInfo:
		// RFC 6458 §8.1.29.
		return setIntOpt(fd, ipprotoSCTP, optRecvRcvInfo, 1)
	case opAssocChange:
		return setEvent(fd, EventAssocChange, true)
	case opReadBuffer:
		return setIntOpt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, op.bytes)
	case opWriteBuffer:
		return setIntOpt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, op.bytes)
	case opInitMsg:
		// struct sctp_initmsg, RFC 6458 §8.1.3.
		var b [sizeInitMsg]byte
		binary.NativeEndian.PutUint16(b[initMsgOutStreamsOff:], op.outStreams)
		binary.NativeEndian.PutUint16(b[initMsgMaxInStreamsOff:], op.maxInStreams)
		binary.NativeEndian.PutUint16(b[initMsgMaxAttemptsOff:], op.maxAttempts)
		binary.NativeEndian.PutUint16(b[initMsgMaxInitTimeoOff:], uint16(op.maxInitTimeoutMS))
		return rawSetsockopt(fd, ipprotoSCTP, optInitMsg, unsafe.Pointer(&b[0]), uintptr(len(b)))
	case opFragmentInterleave:
		// RFC 6458 §8.1.20.
		return setIntOpt(fd, ipprotoSCTP, optFragmentInterleave, int32(op.level))
	case opAuthentication:
		return setAssocValue(fd, optAuthSupported, boolValue(op.on))
	case opHMACIdentifiers:
		// struct sctp_hmacalgo, RFC 6458 §8.1.17.
		b := make([]byte, sizeHMACAlgo+2*len(op.hmacIdentifiers))
		binary.NativeEndian.PutUint32(b[hmacAlgoNumIdentsOff:], uint32(len(op.hmacIdentifiers)))
		for i, id := range op.hmacIdentifiers {
			binary.NativeEndian.PutUint16(b[hmacAlgoIdentsOff+2*i:], uint16(id))
		}
		return rawSetsockopt(fd, ipprotoSCTP, optHMACIdent, unsafe.Pointer(&b[0]), uintptr(len(b)))
	case opAuthChunk:
		// struct sctp_authchunk, RFC 6458 §8.3.2.
		b := [sizeAuthChunk]byte{op.chunk}
		return rawSetsockopt(fd, ipprotoSCTP, optAuthChunk, unsafe.Pointer(&b[0]), uintptr(len(b)))
	case opDynamicAddressReconfiguration:
		return setAssocValue(fd, optASCONFSupported, boolValue(op.on))
	case opPartialReliability:
		return setAssocValue(fd, optPRSupported, boolValue(op.on))
	case opStreamReconfiguration:
		return setAssocValue(fd, optReconfigSupported, boolValue(op.on))
	case opStreamResetMask:
		// RFC 6525 §6.3.1.
		return setAssocValue(fd, optEnableStreamReset, op.u32)
	case opMessageInterleaving:
		return setAssocValue(fd, optInterleavingSupported, boolValue(op.on))
	case opExperimentalECN:
		return setAssocValue(fd, optECNSupported, boolValue(op.on))
	case opAdaptationLayer:
		// struct sctp_setadaptation, RFC 6458 §8.1.10.
		var b [sizeSetAdaptation]byte
		binary.NativeEndian.PutUint32(b[:], op.u32)
		return rawSetsockopt(fd, ipprotoSCTP, optAdaptationLayer, unsafe.Pointer(&b[0]), uintptr(len(b)))
	case opRTOInfo:
		// struct sctp_rtoinfo, RFC 6458 §8.1.1.
		var b [sizeRTOInfo]byte
		binary.NativeEndian.PutUint32(b[rtoInfoInitialOff:], op.initialMS)
		binary.NativeEndian.PutUint32(b[rtoInfoMaxOff:], op.maxMS)
		binary.NativeEndian.PutUint32(b[rtoInfoMinOff:], op.minMS)
		return rawSetsockopt(fd, ipprotoSCTP, optRTOInfo, unsafe.Pointer(&b[0]), uintptr(len(b)))
	case opDelayedSACK:
		// struct sctp_sack_info, RFC 6458 §8.1.19.
		var b [sizeDelayedSACK]byte
		binary.NativeEndian.PutUint32(b[delayedSACKDelayOff:], op.delayMS)
		binary.NativeEndian.PutUint32(b[delayedSACKFrequencyOff:], op.frequency)
		return rawSetsockopt(fd, ipprotoSCTP, optDelayedAckTime, unsafe.Pointer(&b[0]), uintptr(len(b)))
	case opFragmentsDisabled:
		// RFC 6458 §8.1.11.
		return setIntOpt(fd, ipprotoSCTP, optDisableFragments, int32(boolValue(op.on)))
	case opReusePort:
		// RFC 6458 §8.1.27.
		return setIntOpt(fd, ipprotoSCTP, optReusePort, int32(boolValue(op.on)))
	case opReceiveNxtInfo:
		// RFC 6458 §8.1.30.
		return setIntOpt(fd, ipprotoSCTP, optRecvNxtInfo, int32(boolValue(op.on)))
	case opNoDelay:
		// RFC 6458 §8.1.5.
		return setIntOpt(fd, ipprotoSCTP, optNoDelay, int32(boolValue(op.on)))
	case opDefaultSndInfo:
		// struct sctp_sndinfo, RFC 6458 §8.1.31, set the way
		// Conn.SetDefaultSndInfo sets it, so that a PR default Control set
		// survives (send_linux.go). sndInfoPPID is already in the order the
		// kernel keeps (config.go, configOp.sndInfoPPID).
		return setDefaultSndInfo(fd, op.sndInfoStream, op.sndInfoFlags, op.sndInfoPPID, op.sndInfoContext)
	case opDefaultPrInfo:
		// struct sctp_default_prinfo, RFC 6458 §8.1.32.
		return setDefaultPrInfo(fd, op.prPolicy, op.prValue)
	case opNotification:
		return setEvent(fd, op.event, true)
	default:
		return syscall.EINVAL
	}
}

// boolValue is the 0 or 1 a boolean socket option carries.
func boolValue(on bool) uint32 {
	if on {
		return 1
	}
	return 0
}

// setIntOpt writes a plain C int option.
func setIntOpt(fd, level, opt int, v int32) error {
	var b [sizeInt]byte
	binary.NativeEndian.PutUint32(b[:], uint32(v))
	return rawSetsockopt(fd, level, opt, unsafe.Pointer(&b[0]), uintptr(len(b)))
}

// setAssocValue writes a struct sctp_assoc_value option for
// SCTP_FUTURE_ASSOC.
func setAssocValue(fd, opt int, v uint32) error {
	var b [sizeAssocValue]byte
	binary.NativeEndian.PutUint32(b[assocValueValueOff:], v)
	return rawSetsockopt(fd, ipprotoSCTP, opt, unsafe.Pointer(&b[0]), uintptr(len(b)))
}

// setEvent writes one SCTP_EVENT subscription (struct sctp_event, RFC 6458
// §§6.2.2, 8.1.28) with association id 0. On a one-to-one socket that has an
// association, the kernel applies it to the association's own copy of the
// subscriptions; on one that has none, to the endpoint's, from which every
// later association copies its own (net/sctp/socket.c:
// sctp_setsockopt_event, sctp_assoc_ulpevent_type_set; net/sctp/
// associola.c: sctp_association_init).
func setEvent(fd int, t EventType, on bool) error {
	var b [sizeEvent]byte
	binary.NativeEndian.PutUint16(b[eventTypeFieldOff:], uint16(t))
	if on {
		b[eventOnOff] = 1
	}
	return rawSetsockopt(fd, ipprotoSCTP, optEvent, unsafe.Pointer(&b[0]), uintptr(len(b)))
}

// getEvent reads one SCTP_EVENT subscription with association id 0: the
// association's own on a connected one-to-one socket, the endpoint's
// otherwise (net/sctp/socket.c: sctp_getsockopt_event).
func getEvent(fd int, t EventType) (bool, error) {
	var b [sizeEvent]byte
	binary.NativeEndian.PutUint16(b[eventTypeFieldOff:], uint16(t))
	l := uint32(len(b))
	if err := rawGetsockopt(fd, ipprotoSCTP, optEvent, unsafe.Pointer(&b[0]), &l); err != nil {
		return false, err
	}
	return b[eventOnOff] != 0, nil
}

// kernelSubscriptions reads which notification types the kernel delivers
// on s, for a descriptor the package adopted rather than set up: every
// type EventType names but EventAssocChange, whose delivery the package
// decides itself while keeping it subscribed in the kernel. A type the
// kernel does not know (net/sctp/socket.c: sctp_getsockopt_event refuses
// one above SCTP_SN_TYPE_MAX with EINVAL) counts as not subscribed.
func kernelSubscriptions(s *socket) (eventSet, error) {
	var set eventSet
	err := s.control(func(fd int) error {
		for t := range eventTypeNames {
			if t == EventAssocChange {
				continue
			}
			if on, err := getEvent(fd, t); err == nil && on {
				set |= eventBit(t)
			}
		}
		return nil
	})
	return set, err
}

// enableAuth switches AUTH on for the endpoint (SCTP_AUTH_SUPPORTED, RFC
// 4895), which works whatever net.sctp.auth_enable says
// (net/sctp/socket.c: sctp_setsockopt_auth_supported).
func enableAuth(fd int) error {
	if err := setAssocValue(fd, optAuthSupported, 1); err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

// InstallAuthKey installs key number key with the given secret (RFC 6458
// §8.3.3), for use inside Config.Control, before the association exists
// (RFC 6458 §§8.1.18, 8.3.3). Key material stays in the caller's closure
// and is never stored in a reusable Config. After setup, use the Conn
// methods instead.
//
// Linux refuses every key operation with EACCES while the endpoint's AUTH
// is off (net/sctp/auth.c), and Control runs before Config.Authentication
// is applied. So both helpers first switch AUTH on for the socket
// (SCTP_AUTH_SUPPORTED, Linux 5.4), then act. A Config.Authentication set
// explicitly to false is applied after Control and switches AUTH off again.
//
// The secret is copied into the setsockopt argument, which is cleared
// before InstallAuthKey returns. An empty secret, or one longer than
// the 65535 bytes struct sctp_authkey's sca_keylength can describe, is
// refused with an error matching syscall.EINVAL before any system call:
// Linux refuses the first (net/sctp/socket.c: sctp_setsockopt_auth_key
// requires an optlen larger than the header) and cannot express the
// second.
func InstallAuthKey(c syscall.RawConn, key uint16, secret []byte) error {
	if c == nil {
		return invalidArg("InstallAuthKey needs a non-nil syscall.RawConn")
	}
	if len(secret) == 0 {
		return invalidArg("InstallAuthKey secret is empty; Linux refuses a zero-length key (net/sctp/socket.c: sctp_setsockopt_auth_key)")
	}
	if len(secret) > math.MaxUint16 {
		return invalidArg("InstallAuthKey secret is %d bytes, more than the 65535 sca_keylength can describe", len(secret))
	}

	// struct sctp_authkey, RFC 6458 §8.3.3: the association id 0
	// (SCTP_FUTURE_ASSOC), the key number, the key length, then the key.
	b := make([]byte, sizeAuthKey+len(secret))
	defer clear(b)
	binary.NativeEndian.PutUint16(b[authKeyKeyNumberOff:], key)
	binary.NativeEndian.PutUint16(b[authKeyKeyLengthOff:], uint16(len(secret)))
	copy(b[authKeyKeyOff:], secret)

	var serr error
	if err := c.Control(func(fd uintptr) {
		if serr = enableAuth(int(fd)); serr != nil {
			return
		}
		if err := rawSetsockopt(int(fd), ipprotoSCTP, optAuthKey, unsafe.Pointer(&b[0]), uintptr(len(b))); err != nil {
			serr = os.NewSyscallError("setsockopt", err)
		}
	}); err != nil {
		return err
	}
	return serr
}

// ActivateAuthKey makes key number key the active key (RFC 6458 §8.1.18),
// for use inside Config.Control like InstallAuthKey, which it follows in
// switching AUTH on first.
func ActivateAuthKey(c syscall.RawConn, key uint16) error {
	if c == nil {
		return invalidArg("ActivateAuthKey needs a non-nil syscall.RawConn")
	}
	// struct sctp_authkeyid: the association id 0 (SCTP_FUTURE_ASSOC) and
	// the key number, padded to 8 bytes; the kernel requires exactly that
	// length (net/sctp/socket.c: sctp_setsockopt_active_key).
	var b [sizeAuthKeyID]byte
	binary.NativeEndian.PutUint16(b[authKeyIDKeyNumberOff:], key)

	var serr error
	if err := c.Control(func(fd uintptr) {
		if serr = enableAuth(int(fd)); serr != nil {
			return
		}
		if err := rawSetsockopt(int(fd), ipprotoSCTP, optAuthActiveKey, unsafe.Pointer(&b[0]), uintptr(len(b))); err != nil {
			serr = os.NewSyscallError("setsockopt", err)
		}
	}); err != nil {
		return err
	}
	return serr
}
