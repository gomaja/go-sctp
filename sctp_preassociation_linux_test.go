//go:build linux
// +build linux

package sctp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func getSackTimerFD(fd int) (SackTimer, error) {
	timer := SackTimer{AssocID: SCTPAssocID(SCTP_FUTURE_ASSOC)}
	optlen := uint32(unsafe.Sizeof(timer))
	_, _, err := getsockopt(fd, SCTP_DELAYED_SACK,
		uintptr(unsafe.Pointer(&timer)), &optlen)
	return timer, err
}

func getRTOInfoFD(fd int) (RtoInfo, error) {
	info := RtoInfo{AssocID: SCTPAssocID(SCTP_FUTURE_ASSOC)}
	optlen := uint32(unsafe.Sizeof(info))
	_, _, err := getsockopt(fd, SCTP_RTOINFO,
		uintptr(unsafe.Pointer(&info)), &optlen)
	return info, err
}

func getInitMsgFD(fd int) (InitMsg, error) {
	var init InitMsg
	optlen := uint32(unsafe.Sizeof(init))
	_, _, err := getsockopt(fd, SCTP_INITMSG,
		uintptr(unsafe.Pointer(&init)), &optlen)
	return init, err
}

func getAdaptationLayerFD(fd int) (uint32, error) {
	value := struct{ AdaptationInd uint32 }{}
	optlen := uint32(unsafe.Sizeof(value))
	_, _, err := getsockopt(fd, SCTP_ADAPTATION_LAYER,
		uintptr(unsafe.Pointer(&value)), &optlen)
	return value.AdaptationInd, err
}

func getEventFD(fd int, eventType SCTPNotificationType) (bool, error) {
	event := Event{AssocID: SCTPAssocID(SCTP_FUTURE_ASSOC), Type: uint16(eventType)}
	optlen := uint32(unsafe.Sizeof(event))
	_, _, err := getsockopt(fd, SCTP_EVENT,
		uintptr(unsafe.Pointer(&event)), &optlen)
	return event.On != 0, err
}

func getHMACIdentifiersFD(fd int) ([]uint16, error) {
	var buf [8]byte
	optlen := uint32(len(buf))
	_, _, err := getsockopt(fd, SCTP_HMAC_IDENT,
		uintptr(unsafe.Pointer(&buf[0])), &optlen)
	if err != nil {
		return nil, err
	}
	return parseHmacIdents(buf[:], int(optlen))
}

func getLocalAuthChunksFD(fd int) ([]uint8, error) {
	var buf [264]byte
	nativeEndian.PutUint32(buf[:4], uint32(SCTP_FUTURE_ASSOC))
	optlen := uint32(len(buf))
	_, _, err := getsockopt(fd, SCTP_LOCAL_AUTH_CHUNKS,
		uintptr(unsafe.Pointer(&buf[0])), &optlen)
	if err != nil {
		return nil, err
	}
	return parseAuthChunks(buf[:], int(optlen))
}

func containsUint8(values []uint8, want uint8) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestSocketConfigPreAssociationListenerReadback(t *testing.T) {
	const adaptation = 0x10203040
	const rtoInitial = 500
	const rtoMax = 2000
	const rtoMin = 200
	const sackDelay = 250
	const sackFrequency = 4
	resetMask := uint32(SCTPEnableResetStreamReq | SCTPEnableChangeAssocReq)

	var controlCalled atomic.Bool
	socketConfig := SocketConfig{
		InitMsg: InitMsg{
			NumOstreams:  11,
			MaxInstreams: 13,
			MaxAttempts:  3,
		},
		Control: func(_, _ string, raw syscall.RawConn) error {
			controlCalled.Store(true)
			var callbackErr error
			if err := raw.Control(func(fd uintptr) {
				if err := setSockoptBool(int(fd), SCTP_DISABLE_FRAGMENTS, false); err != nil {
					callbackErr = err
					return
				}
				if err := setsockoptInt32(int(fd), SCTP_FRAGMENT_INTERLEAVE,
					SCTPFragmentInterleaveNone); err != nil {
					callbackErr = err
					return
				}
				controlRTO := RtoInfo{
					AssocID: SCTPAssocID(SCTP_FUTURE_ASSOC),
					Initial: 1000,
					Max:     60000,
					Min:     1000,
				}
				_, _, callbackErr = setsockopt(int(fd), SCTP_RTOINFO,
					uintptr(unsafe.Pointer(&controlRTO)), unsafe.Sizeof(controlRTO))
				if callbackErr != nil {
					return
				}
				before := struct{ AdaptationInd uint32 }{0xdeadbeef}
				_, _, callbackErr = setsockopt(int(fd), SCTP_ADAPTATION_LAYER,
					uintptr(unsafe.Pointer(&before)), unsafe.Sizeof(before))
			}); err != nil {
				return err
			}
			return callbackErr
		},
	}
	cfg := socketConfig.WithPreAssociation(PreAssociationConfig{
		PartialReliability:            SocketOptionDisable,
		StreamReconfiguration:         SocketOptionEnable,
		DynamicAddressReconfiguration: SocketOptionEnable,
		Authentication:                SocketOptionEnable,
		ExperimentalECN:               SocketOptionDisable,
		ReusePort:                     SocketOptionEnable,
		MappedV4Address:               SocketOptionEnable,
		DisableFragments:              SocketOptionEnable,
		ReceiveRcvInfo:                SocketOptionEnable,
		ReceiveNxtInfo:                SocketOptionEnable,
		AdaptationLayer:               OptionalUint32{Set: true, Value: adaptation},
		FragmentInterleave:            OptionalInt{Set: true, Value: SCTPFragmentInterleaveOther},
		StreamResetMask:               OptionalUint32{Set: true, Value: resetMask},
		RTOInfo:                       &RtoInfo{Initial: rtoInitial, Max: rtoMax, Min: rtoMin},
		DelayedSACK:                   &DelayedSACKConfig{Delay: sackDelay, Frequency: sackFrequency},
		HMACIdentifiers: []uint16{
			SCTPAuthHmacIDSHA256,
			SCTPAuthHmacIDSHA1,
		},
		AuthenticatedChunks: []uint8{0}, // DATA, RFC 9260 §3.3.1.
		Notifications: []NotificationSubscription{
			{Type: SCTP_ASSOC_CHANGE, State: SocketOptionEnable},
			{Type: SCTP_SENDER_DRY_EVENT, State: SocketOptionDisable},
		},
	})

	listener, err := cfg.Listen("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("Listen with pre-association config: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if !controlCalled.Load() {
		t.Fatal("Control was not called")
	}

	raw, err := listener.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var checkErr error
	if err := raw.Control(func(rawFD uintptr) {
		fd := int(rawFD)
		check := func(name string, got, want uint32, err error) bool {
			if err != nil {
				checkErr = fmt.Errorf("%s readback: %w", name, err)
				return false
			}
			if got != want {
				checkErr = fmt.Errorf("%s readback = %d, want %d", name, got, want)
				return false
			}
			return true
		}

		init, err := getInitMsgFD(fd)
		if err != nil || init.NumOstreams != socketConfig.InitMsg.NumOstreams ||
			init.MaxInstreams != socketConfig.InitMsg.MaxInstreams ||
			init.MaxAttempts != socketConfig.InitMsg.MaxAttempts {
			checkErr = fmt.Errorf("InitMsg configured fields = %+v, %v; want %+v", init, err, socketConfig.InitMsg)
			return
		}
		fragment, err := getsockoptInt32(fd, SCTP_FRAGMENT_INTERLEAVE)
		if !check("FragmentInterleave", uint32(fragment), SCTPFragmentInterleaveOther, err) {
			return
		}
		for _, item := range []struct {
			name string
			opt  uintptr
			want uint32
		}{
			{"Authentication", SCTP_AUTH_SUPPORTED, 1},
			{"DynamicAddressReconfiguration", SCTP_ASCONF_SUPPORTED, 1},
			{"PartialReliability", SCTP_PR_SUPPORTED, 0},
			{"StreamReconfiguration", SCTP_RECONFIG_SUPPORTED, 1},
			{"StreamResetMask", SCTP_ENABLE_STREAM_RESET, resetMask},
			{"ExperimentalECN", SCTP_ECN_SUPPORTED, 0},
		} {
			got, err := getAssocValue(fd, item.opt)
			if !check(item.name, got, item.want, err) {
				return
			}
		}
		adaptationGot, err := getAdaptationLayerFD(fd)
		if !check("AdaptationLayer", adaptationGot, adaptation, err) {
			return
		}
		rto, err := getRTOInfoFD(fd)
		if err != nil || rto.Initial != rtoInitial || rto.Max != rtoMax ||
			rto.Min != rtoMin {
			checkErr = fmt.Errorf("RTOInfo readback = %+v, %v; want initial/max/min %d/%d/%d",
				rto, err, rtoInitial, rtoMax, rtoMin)
			return
		}
		for _, item := range []struct {
			name string
			opt  uintptr
			want uint32
		}{
			{"MappedV4Address", SCTP_I_WANT_MAPPED_V4_ADDR, 1},
			{"DisableFragments", SCTP_DISABLE_FRAGMENTS, 1},
			{"ReusePort", SCTP_REUSE_PORT, 1},
			{"ReceiveRcvInfo", SCTP_RECVRCVINFO, 1},
			{"ReceiveNxtInfo", SCTP_RECVNXTINFO, 1},
		} {
			got, err := getsockoptInt32(fd, item.opt)
			if !check(item.name, uint32(got), item.want, err) {
				return
			}
		}
		timer, err := getSackTimerFD(fd)
		if err != nil || timer.SackDelay != sackDelay || timer.SackFrequency != sackFrequency {
			checkErr = fmt.Errorf("DelayedSACK readback = %+v, %v; want delay/frequency %d/%d",
				timer, err, sackDelay, sackFrequency)
			return
		}
		hmacs, err := getHMACIdentifiersFD(fd)
		if err != nil || len(hmacs) != 2 ||
			hmacs[0] != SCTPAuthHmacIDSHA256 || hmacs[1] != SCTPAuthHmacIDSHA1 {
			checkErr = fmt.Errorf("HMACIdentifiers readback = %v, %v; want [%d %d]",
				hmacs, err, SCTPAuthHmacIDSHA256, SCTPAuthHmacIDSHA1)
			return
		}
		chunks, err := getLocalAuthChunksFD(fd)
		if err != nil || !containsUint8(chunks, 0) {
			checkErr = fmt.Errorf("AuthenticatedChunks readback = %v, %v; want DATA (0)", chunks, err)
			return
		}
		assoc, err := getEventFD(fd, SCTP_ASSOC_CHANGE)
		if err != nil || !assoc {
			checkErr = fmt.Errorf("SCTP_ASSOC_CHANGE subscription = %v, %v; want true", assoc, err)
			return
		}
		dry, err := getEventFD(fd, SCTP_SENDER_DRY_EVENT)
		if err != nil || dry {
			checkErr = fmt.Errorf("SCTP_SENDER_DRY_EVENT subscription = %v, %v; want false", dry, err)
		}
	}); err != nil {
		t.Fatalf("listener RawConn.Control: %v", err)
	}
	if checkErr != nil {
		t.Fatal(checkErr)
	}
}

func TestSocketConfigPreAssociationRTOInfoOnDialPaths(t *testing.T) {
	for _, tc := range []struct {
		name string
		dial func(*testing.T, *PreconfiguredSocket, *SCTPListener) (*SCTPConn, error)
	}{
		{
			name: "Dial",
			dial: func(t *testing.T, cfg *PreconfiguredSocket, listener *SCTPListener) (*SCTPConn, error) {
				t.Helper()
				return cfg.Dial("sctp4", nil, listenerAddr(t, listener))
			},
		},
		{
			name: "DialContext",
			dial: func(t *testing.T, cfg *PreconfiguredSocket, listener *SCTPListener) (*SCTPConn, error) {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				t.Cleanup(cancel)
				return cfg.DialContext(ctx, "sctp4", nil, listenerAddr(t, listener))
			},
		},
		{
			name: "DialContextWithQuietAbandonPolicy",
			dial: func(t *testing.T, cfg *PreconfiguredSocket, listener *SCTPListener) (*SCTPConn, error) {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				t.Cleanup(cancel)
				return cfg.DialContextWithAbandonPolicy(ctx, "sctp4", nil,
					listenerAddr(t, listener), DialAbandonQuiet)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const rtoInitial = 500
			const rtoMax = 2000
			const rtoMin = 200
			pre := PreAssociationConfig{
				RTOInfo: &RtoInfo{
					Initial: rtoInitial,
					Max:     rtoMax,
					Min:     rtoMin,
				},
			}
			listener, err := ListenSCTP("sctp4", loopbackAddr())
			if err != nil {
				t.Fatalf("ListenSCTP: %v", err)
			}
			t.Cleanup(func() { _ = listener.Close() })

			accepted := make(chan *SCTPConn, 1)
			acceptErr := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptSCTP()
				if err != nil {
					acceptErr <- err
					return
				}
				accepted <- conn
			}()

			cfg := new(SocketConfig).WithPreAssociation(pre)
			client, err := tc.dial(t, cfg, listener)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			t.Cleanup(func() { _ = client.Close() })

			select {
			case server := <-accepted:
				t.Cleanup(func() { _ = server.Close() })
			case err := <-acceptErr:
				t.Fatalf("AcceptSCTP: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("AcceptSCTP timed out")
			}

			info, err := client.GetRtoInfo()
			if err != nil || info.Initial != rtoInitial || info.Max != rtoMax ||
				info.Min != rtoMin {
				t.Fatalf("client RTOInfo = %+v, %v; want initial/max/min %d/%d/%d",
					info, err, rtoInitial, rtoMax, rtoMin)
			}
		})
	}
}

func TestSocketConfigPreAssociationNegotiatesOnDialPaths(t *testing.T) {
	for _, useContext := range []bool{false, true} {
		name := "Dial"
		if useContext {
			name = "DialContext"
		}
		t.Run(name, func(t *testing.T) {
			pre := PreAssociationConfig{
				PartialReliability:    SocketOptionEnable,
				StreamReconfiguration: SocketOptionEnable,
				Authentication:        SocketOptionEnable,
				MessageInterleaving:   SocketOptionEnable,
				AuthenticatedChunks:   []uint8{4, 5}, // HEARTBEAT and HEARTBEAT ACK.
				FragmentInterleave: OptionalInt{
					Set: true, Value: SCTPFragmentInterleaveOther,
				},
				StreamResetMask: OptionalUint32{
					Set: true, Value: SCTPEnableResetStreamReq,
				},
				DelayedSACK: &DelayedSACKConfig{Delay: 137, Frequency: 2},
			}
			serverConfig := new(SocketConfig).WithPreAssociation(pre)
			listener, err := serverConfig.Listen("sctp4", loopbackAddr())
			if err != nil {
				t.Fatalf("Listen: %v", err)
			}
			t.Cleanup(func() { _ = listener.Close() })

			accepted := make(chan *SCTPConn, 1)
			acceptErr := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptSCTP()
				if err != nil {
					acceptErr <- err
					return
				}
				accepted <- conn
			}()

			clientSocketConfig := SocketConfig{
				InitMsg: InitMsg{NumOstreams: 9, MaxInstreams: 10},
			}
			clientConfig := clientSocketConfig.WithPreAssociation(pre)
			var client *SCTPConn
			if useContext {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				client, err = clientConfig.DialContext(ctx, "sctp4", nil,
					listenerAddr(t, listener))
			} else {
				client, err = clientConfig.Dial("sctp4", nil, listenerAddr(t, listener))
			}
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			t.Cleanup(func() { _ = client.Close() })

			var server *SCTPConn
			select {
			case server = <-accepted:
				t.Cleanup(func() { _ = server.Close() })
			case err := <-acceptErr:
				t.Fatalf("AcceptSCTP: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("AcceptSCTP timed out")
			}

			for side, conn := range map[string]*SCTPConn{"client": client, "server": server} {
				pr, err := conn.PrSupported()
				if err != nil || !pr {
					t.Errorf("%s PR-SCTP negotiated = %v, %v; want true", side, pr, err)
				}
				reconfig, err := conn.ReconfigSupported()
				if err != nil || !reconfig {
					t.Errorf("%s stream reconfiguration negotiated = %v, %v; want true",
						side, reconfig, err)
				}
				auth, err := conn.AuthSupported()
				if err != nil || !auth {
					t.Errorf("%s AUTH negotiated = %v, %v; want true", side, auth, err)
				}
				interleaving, err := conn.InterleavingSupported()
				if err != nil || !interleaving {
					t.Errorf("%s RFC 8260 interleaving negotiated = %v, %v; want true",
						side, interleaving, err)
				}
				localChunks, err := conn.LocalAuthChunks()
				if err != nil || !reflect.DeepEqual(localChunks, []uint8{4, 5}) {
					t.Errorf("%s local authenticated chunks = %v, %v; want exactly [4 5]",
						side, localChunks, err)
				}
				peerChunks, err := conn.PeerAuthChunks()
				if err != nil || !reflect.DeepEqual(peerChunks, []uint8{4, 5}) {
					t.Errorf("%s peer authenticated chunks = %v, %v; want exactly [4 5]",
						side, peerChunks, err)
				}
				mask, err := conn.EnableStreamReset()
				if err != nil || mask != SCTPEnableResetStreamReq {
					t.Errorf("%s stream-reset mask = %#x, %v; want %#x",
						side, mask, err, SCTPEnableResetStreamReq)
				}
				timer, err := conn.GetSackTimer()
				if err != nil || timer.SackDelay != 137 || timer.SackFrequency != 2 {
					t.Errorf("%s delayed SACK = %+v, %v; want 137/2", side, timer, err)
				}
			}

			init, err := client.GetInitMsg()
			if err != nil || init.NumOstreams != clientSocketConfig.InitMsg.NumOstreams ||
				init.MaxInstreams != clientSocketConfig.InitMsg.MaxInstreams {
				t.Errorf("client InitMsg configured fields = %+v, %v; want %+v",
					init, err, clientSocketConfig.InitMsg)
			}
		})
	}
}

func TestSocketConfigPreAssociationDelayedSACKOnEndpoints(t *testing.T) {
	for _, listening := range []bool{false, true} {
		name := "OpenEndpoint"
		if listening {
			name = "ListenEndpoint"
		}
		t.Run(name, func(t *testing.T) {
			cfg := new(SocketConfig).WithPreAssociation(PreAssociationConfig{
				DelayedSACK: &DelayedSACKConfig{Delay: 149, Frequency: 5},
			})
			var endpoint *SCTPEndpoint
			var err error
			if listening {
				endpoint, err = cfg.ListenEndpoint("sctp4", loopbackAddr())
			} else {
				endpoint, err = cfg.OpenEndpoint("sctp4", loopbackAddr())
			}
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			t.Cleanup(func() { _ = endpoint.Close() })

			timer, err := endpoint.conn.GetSackTimer()
			if err != nil || timer.SackDelay != 149 || timer.SackFrequency != 5 {
				t.Fatalf("future-association delayed SACK = %+v, %v; want 149/5",
					timer, err)
			}
		})
	}
}

func TestSocketConfigPreAssociationValidationPrecedesSocketAndControl(t *testing.T) {
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}

	var controlCalls atomic.Int32
	socketConfig := SocketConfig{
		Control: func(_, _ string, _ syscall.RawConn) error {
			controlCalls.Add(1)
			return nil
		},
	}
	cfg := socketConfig.WithPreAssociation(PreAssociationConfig{
		DelayedSACK: &DelayedSACKConfig{Delay: 501, Frequency: 2},
	})
	remote := &SCTPAddr{IPAddrs: loopbackAddr().IPAddrs, Port: 9}
	calls := []struct {
		name string
		call func() error
	}{
		{"Listen", func() error { _, err := cfg.Listen("sctp4", loopbackAddr()); return err }},
		{"Dial", func() error { _, err := cfg.Dial("sctp4", nil, remote); return err }},
		{"DialContext", func() error {
			_, err := cfg.DialContext(context.Background(), "sctp4", nil, remote)
			return err
		}},
		{"OpenEndpoint", func() error { _, err := cfg.OpenEndpoint("sctp4", loopbackAddr()); return err }},
		{"ListenEndpoint", func() error { _, err := cfg.ListenEndpoint("sctp4", loopbackAddr()); return err }},
	}
	for _, call := range calls {
		err := call.call()
		if err == nil || !strings.Contains(err.Error(), "500 ms maximum") {
			t.Errorf("%s validation error = %v, want delayed-SACK maximum", call.name, err)
		}
	}
	if got := controlCalls.Load(); got != 0 {
		t.Fatalf("Control called %d times for configurations rejected before socket creation", got)
	}

	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd after validation: %v", err)
	}
	if len(after) != len(before) {
		t.Fatalf("descriptor count changed from %d to %d after prevalidation failures",
			len(before), len(after))
	}
}

func TestSocketConfigPreAssociationLevelTwoFailsClosedOnOneToOne(t *testing.T) {
	cfg := new(SocketConfig).WithPreAssociation(PreAssociationConfig{
		ReceiveRcvInfo: SocketOptionEnable,
		FragmentInterleave: OptionalInt{
			Set: true, Value: SCTPFragmentInterleaveStreams,
		},
	})
	listener, err := cfg.Listen("sctp4", loopbackAddr())
	if listener != nil || !errors.Is(err, errors.ErrUnsupported) {
		if listener != nil {
			_ = listener.Close()
		}
		t.Fatalf("Listen with fragment level 2 = (%v, %v), want (nil, errors.ErrUnsupported)",
			listener, err)
	}
}
