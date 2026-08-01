//go:build linux
// +build linux

package sctp

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

const endpointTestTimeout = 5 * time.Second

func endpointAddr(t *testing.T, ep *SCTPEndpoint) *SCTPAddr {
	t.Helper()
	addr, ok := ep.Addr().(*SCTPAddr)
	if !ok || addr == nil || addr.Port == 0 {
		t.Fatalf("endpoint address = %v, want a bound SCTP address", ep.Addr())
	}
	return addr
}

func endpointAssocChange(t *testing.T, ep *SCTPEndpoint) *AssocChange {
	t.Helper()
	change := endpointNextAssocChange(t, ep)
	if change.State != SCTP_COMM_UP {
		t.Fatalf("association state = %v, want SCTP_COMM_UP", change.State)
	}
	return change
}

func endpointNextAssocChange(t *testing.T, ep *SCTPEndpoint) *AssocChange {
	t.Helper()
	if err := ep.SetReadDeadline(time.Now().Add(endpointTestTimeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, NotificationMaxSize)
	for {
		n, info, flags, err := ep.Receive(buf)
		if err != nil {
			t.Fatalf("Receive association change: %v", err)
		}
		if flags&MSG_NOTIFICATION == 0 {
			t.Fatalf("received application data %q with info %+v before association change",
				buf[:n], info)
		}
		note, err := ParseNotification(buf[:n])
		if err != nil {
			t.Fatalf("ParseNotification: %v", err)
		}
		change, ok := note.(*AssocChange)
		if !ok {
			continue
		}
		if !validEndpointAssociationID(change.AssocID) {
			t.Fatalf("association id = %d, want a kernel-assigned id", change.AssocID)
		}
		return change
	}
}

func endpointWaitAssocState(t *testing.T, ep *SCTPEndpoint, id SCTPAssocID, state SCTPState) {
	t.Helper()
	for {
		change := endpointNextAssocChange(t, ep)
		if change.AssocID == id && change.State == state {
			return
		}
	}
}

func endpointAddrContainsIP(addr *SCTPAddr, want net.IP) bool {
	if addr == nil {
		return false
	}
	for _, ip := range addr.IPAddrs {
		if ip.IP.Equal(want) {
			return true
		}
	}
	return false
}

func endpointReceiveData(t *testing.T, ep *SCTPEndpoint) ([]byte, *RcvInfo, int) {
	t.Helper()
	if err := ep.SetReadDeadline(time.Now().Add(endpointTestTimeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 4096)
	for {
		n, info, flags, err := ep.Receive(buf)
		if err != nil {
			t.Fatalf("Receive data: %v", err)
		}
		if flags&MSG_NOTIFICATION != 0 {
			continue
		}
		return append([]byte(nil), buf[:n]...), info, flags
	}
}

func TestSCTPEndpointSetDeadlineAppliesToReceiveAndSend(t *testing.T) {
	server, err := ListenSCTPEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("ListenSCTPEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	client, err := OpenSCTPEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("OpenSCTPEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	id, err := client.Connect(endpointAddr(t, server))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	_ = endpointAssocChange(t, client)
	_ = endpointAssocChange(t, server)

	if err := client.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if _, _, _, err := client.Receive(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Receive after expired SetDeadline = %v, want os.ErrDeadlineExceeded", err)
	}
	if _, err := client.Send([]byte("expired"),
		&SndInfo{AssocID: int32(id)}, nil, nil); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Send after expired SetDeadline = %v, want os.ErrDeadlineExceeded", err)
	}

	if err := client.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("clear SetDeadline: %v", err)
	}
	want := []byte("after-deadline")
	if _, err := client.Send(want, &SndInfo{AssocID: int32(id)}, nil, nil); err != nil {
		t.Fatalf("Send after clearing deadline: %v", err)
	}
	if got, _, _ := endpointReceiveData(t, server); !bytes.Equal(got, want) {
		t.Fatalf("received %q, want %q", got, want)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := client.SetDeadline(time.Now()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("SetDeadline after Close = %v, want net.ErrClosed", err)
	}
}

// TestSCTPEndpointRejectsZeroLengthMessagesWithAncillaryData proves that the
// one-to-many send path preserves SCTP's message boundary when an empty payload
// carries control data. Go's syscall.SendmsgN otherwise substitutes a one-byte
// iovec on non-datagram sockets, queues an unexpected DATA chunk, and masks the
// write count back to zero.
func TestSCTPEndpointRejectsZeroLengthMessagesWithAncillaryData(t *testing.T) {
	server, err := ListenSCTPEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("ListenSCTPEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	client, err := OpenSCTPEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("OpenSCTPEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	clientID, err := client.Connect(endpointAddr(t, server))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	clientChange := endpointAssocChange(t, client)
	serverChange := endpointAssocChange(t, server)
	if clientChange.AssocID != clientID {
		t.Fatalf("client COMM_UP id = %d, Connect returned %d",
			clientChange.AssocID, clientID)
	}

	for _, tc := range []struct {
		name string
		pr   *PrInfo
		auth *AuthInfo
	}{
		{"SndInfo", nil, nil},
		{"SndInfo and PrInfo", &PrInfo{Policy: SCTPPrPolicyTTL, Value: 1000}, nil},
		{"SndInfo and AuthInfo", nil, &AuthInfo{KeyNumber: 0}},
		{"all ancillary types", &PrInfo{Policy: SCTPPrPolicyTTL, Value: 1000},
			&AuthInfo{KeyNumber: 0}},
	} {
		for _, payload := range []struct {
			name string
			data []byte
		}{
			{"nil", nil},
			{"empty", []byte{}},
		} {
			t.Run(tc.name+"/"+payload.name, func(t *testing.T) {
				n, err := client.Send(payload.data,
					&SndInfo{SID: 0, AssocID: int32(clientID)}, tc.pr, tc.auth)
				if !errors.Is(err, syscall.EINVAL) {
					t.Errorf("Send = (%d, %v), want EINVAL", n, err)
				}
				if n != 0 {
					t.Errorf("Send reported %d bytes", n)
				}
			})
		}
	}

	want := []byte("endpoint-after-empty")
	if _, err := client.Send(want, &SndInfo{SID: 0, AssocID: int32(clientID)}, nil, nil); err != nil {
		t.Fatalf("Send sentinel: %v", err)
	}
	got, info, _ := endpointReceiveData(t, server)
	if !bytes.Equal(got, want) {
		t.Fatalf("received %q, want sentinel %q; an empty send queued data", got, want)
	}
	if info == nil || SCTPAssocID(info.AssocID) != serverChange.AssocID {
		t.Fatalf("sentinel info = %+v, want association %d", info, serverChange.AssocID)
	}
}

func TestSCTPEndpointRoundTripAndPeelOffOwnership(t *testing.T) {
	server, err := ListenSCTPEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("ListenSCTPEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })

	client, err := OpenSCTPEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("OpenSCTPEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	if !isCloseOnExec(t, server.conn.fd()) || !isCloseOnExec(t, client.conn.fd()) {
		t.Fatal("an endpoint descriptor is not close-on-exec")
	}

	clientID, err := client.Connect(endpointAddr(t, server))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if !validEndpointAssociationID(clientID) {
		t.Fatalf("Connect id = %d, want a kernel-assigned id", clientID)
	}
	clientChange := endpointAssocChange(t, client)
	serverChange := endpointAssocChange(t, server)
	if clientChange.AssocID != clientID {
		t.Fatalf("client COMM_UP id = %d, Connect returned %d",
			clientChange.AssocID, clientID)
	}
	serverID := serverChange.AssocID

	clientLocal, err := client.LocalAddrs(clientID)
	if err != nil {
		t.Fatalf("client LocalAddrs(%d): %v", clientID, err)
	}
	clientPeer, err := client.PeerAddrs(clientID)
	if err != nil {
		t.Fatalf("client PeerAddrs(%d): %v", clientID, err)
	}
	serverLocal, err := server.LocalAddrs(serverID)
	if err != nil {
		t.Fatalf("server LocalAddrs(%d): %v", serverID, err)
	}
	serverPeer, err := server.PeerAddrs(serverID)
	if err != nil {
		t.Fatalf("server PeerAddrs(%d): %v", serverID, err)
	}
	if clientLocal.Port != endpointAddr(t, client).Port ||
		clientPeer.Port != endpointAddr(t, server).Port ||
		serverLocal.Port != endpointAddr(t, server).Port ||
		serverPeer.Port != endpointAddr(t, client).Port {
		t.Fatalf("association addresses: client local=%v peer=%v server local=%v peer=%v",
			clientLocal, clientPeer, serverLocal, serverPeer)
	}
	if !endpointAddrContainsIP(clientPeer, net.IPv4(127, 0, 0, 1)) ||
		!endpointAddrContainsIP(serverPeer, net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("peer addresses do not contain loopback: client=%v server=%v",
			clientPeer, serverPeer)
	}
	if len(clientPeer.IPAddrs) == 0 {
		t.Fatal("client peer address set is empty")
	}
	clientPeer.IPAddrs[0].IP[0] ^= 0xff
	freshPeer, err := client.PeerAddrs(clientID)
	if err != nil || !endpointAddrContainsIP(freshPeer, net.IPv4(127, 0, 0, 1)) {
		t.Fatalf("PeerAddrs aliases a previous result: fresh=%v err=%v", freshPeer, err)
	}

	request := []byte("one-to-many request")
	requestInfo := &SndInfo{
		SID: 3, PPID: 0x11223344, Context: 0x55667788, AssocID: int32(clientID),
	}
	if n, err := client.Send(request, requestInfo, nil, nil); err != nil || n != len(request) {
		t.Fatalf("Send = (%d, %v), want (%d, nil)", n, err, len(request))
	}
	got, gotInfo, flags := endpointReceiveData(t, server)
	if !bytes.Equal(got, request) {
		t.Fatalf("server payload = %q, want %q", got, request)
	}
	if flags&MSG_EOR == 0 {
		t.Fatalf("server flags = %#x, want MSG_EOR", flags)
	}
	if gotInfo == nil {
		t.Fatal("server received no SCTP_RCVINFO")
	}
	// RcvInfo.Context is the receiver's SCTP_CONTEXT socket option, not the
	// sender's SndInfo.Context. RFC 6458 §5.3.5 distinguishes those despite the
	// shared field name; the send context comes back only on send failure.
	if gotInfo.AssocID != serverID || gotInfo.SID != requestInfo.SID ||
		gotInfo.PPID != requestInfo.PPID || gotInfo.Context != 0 {
		t.Fatalf("server RcvInfo = %+v, want assoc=%d sid=%d ppid=%#x context=0",
			gotInfo, serverID, requestInfo.SID, requestInfo.PPID)
	}

	peeled, err := server.PeelOff(serverID)
	if err != nil {
		t.Fatalf("PeelOff(%d): %v", serverID, err)
	}
	t.Cleanup(func() { _ = peeled.Close() })
	if peeled.fd() <= 2 || !isCloseOnExec(t, peeled.fd()) {
		t.Fatalf("peeled descriptor = %d, want a package-owned close-on-exec descriptor", peeled.fd())
	}

	if _, err := server.Send([]byte("stale"), &SndInfo{AssocID: int32(serverID)}, nil, nil); !errors.Is(err, syscall.EPIPE) {
		t.Fatalf("Send on peeled association = %v, want EPIPE", err)
	}

	afterPeel := []byte("after peel")
	if _, err := client.Send(afterPeel, &SndInfo{AssocID: int32(clientID)}, nil, nil); err != nil {
		t.Fatalf("Send after peel: %v", err)
	}
	if err := peeled.SetReadDeadline(time.Now().Add(endpointTestTimeout)); err != nil {
		t.Fatalf("peeled SetReadDeadline: %v", err)
	}
	buf := make([]byte, 128)
	n, _, flags, err := peeled.SCTPReadFlags(buf)
	if err != nil {
		t.Fatalf("peeled SCTPReadFlags: %v", err)
	}
	if !bytes.Equal(buf[:n], afterPeel) || flags&MSG_EOR == 0 {
		t.Fatalf("peeled read = %q flags=%#x, want %q with EOR", buf[:n], flags, afterPeel)
	}

	if err := server.Close(); err != nil {
		t.Fatalf("server endpoint Close: %v", err)
	}
	stillPeeled := []byte("peeled survives endpoint close")
	if _, err := client.Send(stillPeeled, &SndInfo{AssocID: int32(clientID)}, nil, nil); err != nil {
		t.Fatalf("Send after original endpoint Close: %v", err)
	}
	n, _, _, err = peeled.SCTPReadFlags(buf)
	if err != nil {
		t.Fatalf("peeled read after endpoint Close: %v", err)
	}
	if !bytes.Equal(buf[:n], stillPeeled) {
		t.Fatalf("peeled payload = %q, want %q", buf[:n], stillPeeled)
	}
}

func TestSCTPEndpointCreatesAndRoutesMultipleAssociations(t *testing.T) {
	servers := make([]*SCTPEndpoint, 2)
	for i := range servers {
		var err error
		servers[i], err = ListenSCTPEndpoint("sctp4", loopbackAddr())
		if err != nil {
			t.Fatalf("ListenSCTPEndpoint %d: %v", i, err)
		}
		t.Cleanup(func() { _ = servers[i].Close() })
	}

	client, err := OpenSCTPEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("OpenSCTPEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	clientIDs := make([]SCTPAssocID, len(servers))
	serverIDs := make([]SCTPAssocID, len(servers))
	for i, server := range servers {
		clientIDs[i], err = client.Connect(endpointAddr(t, server))
		if err != nil {
			t.Fatalf("Connect %d: %v", i, err)
		}
		serverIDs[i] = endpointAssocChange(t, server).AssocID
	}

	seenClientIDs := make(map[SCTPAssocID]bool)
	for len(seenClientIDs) != len(servers) {
		seenClientIDs[endpointAssocChange(t, client).AssocID] = true
	}
	for i, id := range clientIDs {
		if !seenClientIDs[id] {
			t.Fatalf("Connect %d returned id %d but no matching COMM_UP arrived", i, id)
		}
	}
	if clientIDs[0] == clientIDs[1] || serverIDs[0] == serverIDs[1] {
		t.Fatalf("association ids were reused: client=%v server=%v", clientIDs, serverIDs)
	}
	count, err := client.AssociationCount()
	if err != nil || count != uint32(len(clientIDs)) {
		t.Fatalf("client AssociationCount = (%d, %v), want (%d, nil)",
			count, err, len(clientIDs))
	}
	listed, err := client.AssociationIDs()
	if err != nil {
		t.Fatalf("client AssociationIDs: %v", err)
	}
	listedSet := make(map[SCTPAssocID]bool, len(listed))
	for _, id := range listed {
		listedSet[id] = true
	}
	for _, id := range clientIDs {
		if !listedSet[id] {
			t.Fatalf("AssociationIDs = %v, missing Connect id %d", listed, id)
		}
	}
	if len(listed) != len(clientIDs) || len(listedSet) != len(clientIDs) {
		t.Fatalf("AssociationIDs = %v, want exactly %v", listed, clientIDs)
	}
	listed[0] = -1
	freshListed, err := client.AssociationIDs()
	if err != nil || len(freshListed) != len(clientIDs) || freshListed[0] == -1 {
		t.Fatalf("AssociationIDs aliases prior result: fresh=%v err=%v", freshListed, err)
	}
	for i, server := range servers {
		count, err := server.AssociationCount()
		if err != nil || count != 1 {
			t.Fatalf("server %d AssociationCount = (%d, %v), want (1, nil)", i, count, err)
		}
		ids, err := server.AssociationIDs()
		if err != nil || len(ids) != 1 || ids[0] != serverIDs[i] {
			t.Fatalf("server %d AssociationIDs = (%v, %v), want [%d]",
				i, ids, err, serverIDs[i])
		}
	}

	var wg sync.WaitGroup
	errCh := make(chan error, len(servers))
	for i, id := range clientIDs {
		wg.Add(1)
		go func(i int, id SCTPAssocID) {
			defer wg.Done()
			payload := []byte{byte('A' + i)}
			_, sendErr := client.Send(payload, &SndInfo{
				SID: uint16(i + 1), PPID: uint32(0x100 + i), AssocID: int32(id),
			}, nil, nil)
			errCh <- sendErr
		}(i, id)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent Send: %v", err)
		}
	}

	for i, server := range servers {
		payload, info, flags := endpointReceiveData(t, server)
		if len(payload) != 1 || payload[0] != byte('A'+i) {
			t.Fatalf("server %d payload = %q", i, payload)
		}
		if flags&MSG_EOR == 0 || info == nil || info.AssocID != serverIDs[i] ||
			info.SID != uint16(i+1) || info.PPID != uint32(0x100+i) {
			t.Fatalf("server %d info=%+v flags=%#x, assoc=%d", i, info, flags, serverIDs[i])
		}
	}
}

func TestSCTPEndpointAssociationIDsGrowsItsBoundedBuffer(t *testing.T) {
	// AssociationIDs starts with room for 16 ids. Seventeen live associations
	// force Linux to return EINVAL for that first SCTP_GET_ASSOC_ID_LIST call
	// and exercise the bounded retry with a larger package-owned buffer.
	const associations = 17
	client, err := OpenSCTPEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("OpenSCTPEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = client.Abort() })

	want := make(map[SCTPAssocID]struct{}, associations)
	for i := 0; i < associations; i++ {
		server, err := ListenSCTPEndpoint("sctp4", loopbackAddr())
		if err != nil {
			t.Fatalf("ListenSCTPEndpoint %d: %v", i, err)
		}
		t.Cleanup(func() { _ = server.Abort() })
		id, err := client.Connect(endpointAddr(t, server))
		if err != nil {
			t.Fatalf("Connect %d: %v", i, err)
		}
		_ = endpointAssocChange(t, server)
		change := endpointAssocChange(t, client)
		if change.AssocID != id {
			t.Fatalf("association %d COMM_UP id = %d, Connect returned %d", i, change.AssocID, id)
		}
		want[id] = struct{}{}
	}

	count, err := client.AssociationCount()
	if err != nil || count != associations {
		t.Fatalf("AssociationCount = (%d, %v), want (%d, nil)", count, err, associations)
	}
	ids, err := client.AssociationIDs()
	if err != nil {
		t.Fatalf("AssociationIDs after initial buffer overflow: %v", err)
	}
	if len(ids) != associations {
		t.Fatalf("AssociationIDs returned %d ids, want %d: %v", len(ids), associations, ids)
	}
	for _, id := range ids {
		if _, ok := want[id]; !ok {
			t.Fatalf("AssociationIDs returned unknown id %d; want set %v", id, want)
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatalf("AssociationIDs omitted ids: %v", want)
	}
}

func TestSCTPEndpointErrorsDeadlinesAndCloseWakeup(t *testing.T) {
	if ep, err := OpenSCTPEndpoint("udp", loopbackAddr()); err == nil {
		_ = ep.Close()
		t.Fatal("OpenSCTPEndpoint accepted a non-SCTP network")
	}

	ep, err := OpenSCTPEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("OpenSCTPEndpoint: %v", err)
	}
	if _, err := ep.Connect(nil); err == nil {
		t.Fatal("Connect(nil) returned nil")
	}
	if _, err := ep.Connect(&SCTPAddr{
		IPAddrs: []net.IPAddr{{IP: net.IPv6loopback}}, Port: 9,
	}); err == nil {
		t.Fatal("sctp4 Connect accepted an IPv6 address")
	}

	for _, id := range []SCTPAssocID{-1, SCTP_FUTURE_ASSOC, SCTP_CURRENT_ASSOC, SCTP_ALL_ASSOC} {
		if _, err := ep.Send([]byte("x"), &SndInfo{AssocID: int32(id)}, nil, nil); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("Send assoc %d = %v, want EINVAL", id, err)
		}
		if conn, err := ep.PeelOff(id); !errors.Is(err, syscall.EINVAL) {
			if conn != nil {
				_ = conn.Close()
			}
			t.Errorf("PeelOff(%d) = %v, want EINVAL", id, err)
		}
		if _, err := ep.LocalAddrs(id); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("LocalAddrs(%d) = %v, want EINVAL", id, err)
		}
		if _, err := ep.PeerAddrs(id); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("PeerAddrs(%d) = %v, want EINVAL", id, err)
		}
		if err := ep.CloseAssociation(id); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("CloseAssociation(%d) = %v, want EINVAL", id, err)
		}
		if err := ep.AbortAssociation(id, nil); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("AbortAssociation(%d) = %v, want EINVAL", id, err)
		}
	}
	if _, err := ep.Send([]byte("x"), nil, nil, nil); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("Send with nil SndInfo = %v, want EINVAL", err)
	}
	for _, flag := range []uint16{SCTP_EOF, SCTP_ABORT, SCTP_SENDALL} {
		if _, err := ep.Send(nil, &SndInfo{AssocID: 3, Flags: flag}, nil, nil); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("Send lifecycle flag %#x = %v, want EINVAL", flag, err)
		}
	}
	if conn, err := ep.PeelOff(SCTPAssocID(999999999)); !errors.Is(err, syscall.EINVAL) {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("PeelOff unknown association = %v, want EINVAL", err)
	}

	if err := ep.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 32)
	if _, _, _, err := ep.Receive(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Receive deadline = %v, want os.ErrDeadlineExceeded", err)
	}
	if err := ep.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear SetReadDeadline: %v", err)
	}

	started := make(chan struct{})
	readErr := make(chan error, 1)
	go func() {
		close(started)
		_, _, _, readErrValue := ep.Receive(buf)
		readErr <- readErrValue
	}()
	<-started
	time.Sleep(25 * time.Millisecond)
	if err := ep.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-readErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked Receive after Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(endpointTestTimeout):
		t.Fatal("Close did not wake a blocked Receive")
	}
	if err := ep.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close = %v, want net.ErrClosed", err)
	}
	if _, err := ep.Send([]byte("x"), &SndInfo{AssocID: 3}, nil, nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send after Close = %v, want net.ErrClosed", err)
	}
	if _, err := ep.Connect(loopbackAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Connect after Close = %v, want net.ErrClosed", err)
	}
	closedCalls := []struct {
		name string
		call func() error
	}{
		{"SyscallConn", func() error { _, err := ep.SyscallConn(); return err }},
		{"BindAdd", func() error { return ep.BindAdd(loopbackAddr()) }},
		{"BindRemove", func() error { return ep.BindRemove(loopbackAddr()) }},
		{"LocalAddrs", func() error { _, err := ep.LocalAddrs(3); return err }},
		{"PeerAddrs", func() error { _, err := ep.PeerAddrs(3); return err }},
		{"AssociationCount", func() error { _, err := ep.AssociationCount(); return err }},
		{"AssociationIDs", func() error { _, err := ep.AssociationIDs(); return err }},
		{"SetAutoClose", func() error { return ep.SetAutoClose(1) }},
		{"GetAutoClose", func() error { _, err := ep.GetAutoClose(); return err }},
		{"CloseAssociation", func() error { return ep.CloseAssociation(3) }},
		{"AbortAssociation", func() error { return ep.AbortAssociation(3, nil) }},
	}
	for _, tc := range closedCalls {
		if err := tc.call(); !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s after Close = %v, want net.ErrClosed", tc.name, err)
		}
	}
}

func TestSCTPEndpointControlFailureReleasesOwnedDescriptor(t *testing.T) {
	want := errors.New("control failed")
	borrowed := -1
	cfg := SocketConfig{
		Control: func(_ string, _ string, raw syscall.RawConn) error {
			if err := raw.Control(func(fd uintptr) { borrowed = int(fd) }); err != nil {
				return err
			}
			return want
		},
	}
	ep, err := cfg.OpenEndpoint("sctp4", loopbackAddr())
	if ep != nil || !errors.Is(err, want) {
		t.Fatalf("OpenEndpoint = (%v, %v), want (nil, control error)", ep, err)
	}
	if borrowed < 0 {
		t.Fatal("Control was not called")
	}
	_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(borrowed), syscall.F_GETFD, 0)
	if errno != syscall.EBADF {
		t.Fatalf("borrowed descriptor %d remains open after constructor failure: %v",
			borrowed, errno)
	}
}

func TestSCTPEndpointRawAccessDynamicBindAndEndpointOptions(t *testing.T) {
	available := requireLoopbacks(t, 2)
	ep, err := ListenSCTPEndpoint("sctp4", sctpAddr(available[:1], 0))
	if err != nil {
		t.Fatalf("ListenSCTPEndpoint: %v", err)
	}

	count, err := ep.AssociationCount()
	if err != nil || count != 0 {
		t.Fatalf("fresh AssociationCount = (%d, %v), want (0, nil)", count, err)
	}
	ids, err := ep.AssociationIDs()
	if err != nil || ids == nil || len(ids) != 0 {
		t.Fatalf("fresh AssociationIDs = (%v, %v), want non-nil empty slice", ids, err)
	}

	seconds, err := ep.GetAutoClose()
	if err != nil || seconds != 0 {
		t.Fatalf("default GetAutoClose = (%d, %v), want (0, nil)", seconds, err)
	}
	if err := ep.SetAutoClose(2); err != nil {
		t.Fatalf("SetAutoClose(2): %v", err)
	}
	seconds, err = ep.GetAutoClose()
	if err != nil || seconds != 2 {
		t.Fatalf("GetAutoClose after set = (%d, %v), want (2, nil)", seconds, err)
	}
	if err := ep.SetAutoClose(0); err != nil {
		t.Fatalf("SetAutoClose(0): %v", err)
	}

	raw, err := ep.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var callbackErr error
	if err := raw.Control(func(fd uintptr) {
		soType, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
		if err != nil {
			callbackErr = err
			return
		}
		if soType != syscall.SOCK_SEQPACKET {
			callbackErr = errors.New("endpoint descriptor is not SOCK_SEQPACKET")
			return
		}
		flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, syscall.F_GETFD, 0)
		if errno != 0 {
			callbackErr = errno
			return
		}
		if flags&syscall.FD_CLOEXEC == 0 {
			callbackErr = errors.New("endpoint descriptor is not close-on-exec")
		}
	}); err != nil || callbackErr != nil {
		t.Fatalf("RawConn.Control = %v, callback = %v", err, callbackErr)
	}

	initial := endpointAddr(t, ep)
	extra := sctpAddr(available[1:2], 0)
	if err := ep.BindAdd(extra); err != nil {
		t.Fatalf("BindAdd(%s): %v", available[1], err)
	}
	if extra.Port != 0 {
		t.Fatalf("BindAdd changed caller port to %d", extra.Port)
	}
	bound := endpointAddr(t, ep)
	if bound.Port != initial.Port ||
		!endpointAddrContainsIP(bound, net.ParseIP(available[0])) ||
		!endpointAddrContainsIP(bound, net.ParseIP(available[1])) {
		t.Fatalf("Addr after BindAdd = %v, want %v and %v on port %d",
			bound, available[0], available[1], initial.Port)
	}
	bound.IPAddrs[0].IP[0] ^= 0xff
	if fresh := endpointAddr(t, ep); !endpointAddrContainsIP(fresh, net.ParseIP(available[0])) {
		t.Fatalf("Addr aliases previous result: %v", fresh)
	}
	if err := ep.BindRemove(extra); err != nil {
		t.Fatalf("BindRemove(%s): %v", available[1], err)
	}
	bound = endpointAddr(t, ep)
	if !endpointAddrContainsIP(bound, net.ParseIP(available[0])) ||
		endpointAddrContainsIP(bound, net.ParseIP(available[1])) {
		t.Fatalf("Addr after BindRemove = %v, want only %v", bound, available[0])
	}

	if err := ep.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	calledAfterClose := false
	if err := raw.Control(func(uintptr) { calledAfterClose = true }); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("retained RawConn after endpoint Close = %v, want net.ErrClosed", err)
	}
	if calledAfterClose {
		t.Fatal("retained RawConn invoked its callback after endpoint Close")
	}
}

func TestSCTPEndpointAssociationLifecycleLeavesOtherAssociationsOpen(t *testing.T) {
	servers := make([]*SCTPEndpoint, 2)
	for i := range servers {
		var err error
		servers[i], err = ListenSCTPEndpoint("sctp4", loopbackAddr())
		if err != nil {
			t.Fatalf("ListenSCTPEndpoint %d: %v", i, err)
		}
		t.Cleanup(func() { _ = servers[i].Close() })
	}
	client, err := OpenSCTPEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("OpenSCTPEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	clientIDs := make([]SCTPAssocID, len(servers))
	serverIDs := make([]SCTPAssocID, len(servers))
	for i, server := range servers {
		clientIDs[i], err = client.Connect(endpointAddr(t, server))
		if err != nil {
			t.Fatalf("Connect %d: %v", i, err)
		}
		serverIDs[i] = endpointAssocChange(t, server).AssocID
	}
	seen := make(map[SCTPAssocID]bool)
	for len(seen) < len(clientIDs) {
		seen[endpointAssocChange(t, client).AssocID] = true
	}

	if err := client.CloseAssociation(clientIDs[0]); err != nil {
		t.Fatalf("CloseAssociation(%d): %v", clientIDs[0], err)
	}
	endpointWaitAssocState(t, client, clientIDs[0], SCTP_SHUTDOWN_COMP)
	endpointWaitAssocState(t, servers[0], serverIDs[0], SCTP_SHUTDOWN_COMP)

	survivor := []byte("second association remains open")
	if _, err := client.Send(survivor, &SndInfo{AssocID: int32(clientIDs[1])}, nil, nil); err != nil {
		t.Fatalf("Send on surviving association: %v", err)
	}
	got, info, flags := endpointReceiveData(t, servers[1])
	if !bytes.Equal(got, survivor) || info == nil || info.AssocID != serverIDs[1] || flags&MSG_EOR == 0 {
		t.Fatalf("surviving association receive = %q info=%+v flags=%#x", got, info, flags)
	}

	cause := []byte{0xde, 0xad, 0xbe, 0xef, 0x01}
	if err := client.AbortAssociation(clientIDs[1], cause); err != nil {
		t.Fatalf("AbortAssociation(%d): %v", clientIDs[1], err)
	}
	endpointWaitAssocState(t, servers[1], serverIDs[1], SCTP_COMM_LOST)

	deadline := time.Now().Add(endpointTestTimeout)
	for {
		count, err := client.AssociationCount()
		if err != nil {
			t.Fatalf("AssociationCount after termination: %v", err)
		}
		if count == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("client still owns %d associations after close and abort", count)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSCTPEndpointCloseGracefullyTerminatesEveryAssociation(t *testing.T) {
	servers := make([]*SCTPEndpoint, 2)
	for i := range servers {
		var err error
		servers[i], err = ListenSCTPEndpoint("sctp4", loopbackAddr())
		if err != nil {
			t.Fatalf("ListenSCTPEndpoint %d: %v", i, err)
		}
		t.Cleanup(func() { _ = servers[i].Close() })
	}
	client, err := OpenSCTPEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("OpenSCTPEndpoint: %v", err)
	}

	clientIDs := make([]SCTPAssocID, len(servers))
	serverIDs := make([]SCTPAssocID, len(servers))
	for i, server := range servers {
		clientIDs[i], err = client.Connect(endpointAddr(t, server))
		if err != nil {
			t.Fatalf("Connect %d: %v", i, err)
		}
		serverIDs[i] = endpointAssocChange(t, server).AssocID
	}
	seen := make(map[SCTPAssocID]bool, len(clientIDs))
	for len(seen) < len(clientIDs) {
		seen[endpointAssocChange(t, client).AssocID] = true
	}
	for _, id := range clientIDs {
		if !seen[id] {
			t.Fatalf("Connect id %d had no client COMM_UP; got %v", id, seen)
		}
	}

	start := time.Now()
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Close took %v with two responsive peers, want prompt return", elapsed)
	}
	for i, server := range servers {
		endpointWaitAssocState(t, server, serverIDs[i], SCTP_SHUTDOWN_COMP)
	}
	if err := client.Close(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second Close = %v, want net.ErrClosed", err)
	}
}

func TestNilSCTPEndpointMethodsReportClosed(t *testing.T) {
	var ep *SCTPEndpoint
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"SyscallConn", func() error { _, err := ep.SyscallConn(); return err }},
		{"BindAdd", func() error { return ep.BindAdd(nil) }},
		{"BindRemove", func() error { return ep.BindRemove(nil) }},
		{"LocalAddrs", func() error { _, err := ep.LocalAddrs(3); return err }},
		{"PeerAddrs", func() error { _, err := ep.PeerAddrs(3); return err }},
		{"AssociationCount", func() error { _, err := ep.AssociationCount(); return err }},
		{"AssociationIDs", func() error { _, err := ep.AssociationIDs(); return err }},
		{"SetAutoClose", func() error { return ep.SetAutoClose(1) }},
		{"GetAutoClose", func() error { _, err := ep.GetAutoClose(); return err }},
		{"CloseAssociation", func() error { return ep.CloseAssociation(3) }},
		{"AbortAssociation", func() error { return ep.AbortAssociation(3, nil) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, net.ErrClosed) {
				t.Errorf("error = %v, want net.ErrClosed", err)
			}
		})
	}
}

func TestSCTPEndpointDuplicateConnectIsNotReportedAsANewAssociation(t *testing.T) {
	server, err := ListenSCTPEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("ListenSCTPEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := OpenSCTPEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("OpenSCTPEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	addr := endpointAddr(t, server)
	if _, err := client.Connect(addr); err != nil {
		t.Fatalf("first Connect: %v", err)
	}
	_ = endpointAssocChange(t, client)
	_ = endpointAssocChange(t, server)

	id, err := client.Connect(addr)
	if id != 0 || !errors.Is(err, syscall.EISCONN) {
		t.Fatalf("duplicate Connect = (%d, %v), want (0, EISCONN)", id, err)
	}
}

func TestSocketConfigEndpointOrderAndRequiredMetadata(t *testing.T) {
	controlCalled := false
	cfg := SocketConfig{
		InitMsg: InitMsg{
			NumOstreams:    17,
			MaxInstreams:   19,
			MaxAttempts:    3,
			MaxInitTimeout: 800,
		},
		Control: func(network, address string, raw syscall.RawConn) error {
			controlCalled = true
			if network != "sctp4" {
				return errors.New("Control received the wrong network")
			}
			if address == "" {
				return errors.New("Control received no local address")
			}
			var callbackErr error
			if err := raw.Control(func(fd uintptr) {
				soType, err := syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_TYPE)
				if err != nil {
					callbackErr = err
					return
				}
				if soType != syscall.SOCK_SEQPACKET {
					callbackErr = errors.New("Control did not receive a SOCK_SEQPACKET descriptor")
					return
				}
				bound, err := syscall.Getsockname(int(fd))
				if err != nil {
					callbackErr = err
					return
				}
				if bound.(*syscall.SockaddrInet4).Port != 0 {
					callbackErr = errors.New("Control ran after bind")
					return
				}

				// Try to disable the two metadata channels. SCTPEndpoint applies
				// its mandatory routing invariants after Control returns.
				if err := setsockoptInt(int(fd), SCTP_RECVRCVINFO, false); err != nil {
					callbackErr = err
					return
				}
				if err := setsockoptInt32(int(fd), SCTP_FRAGMENT_INTERLEAVE,
					SCTPFragmentInterleaveNone); err != nil {
					callbackErr = err
					return
				}
				event := Event{Type: uint16(SCTP_ASSOC_CHANGE)}
				_, _, callbackErr = setsockopt(int(fd), SCTP_EVENT,
					uintptr(unsafe.Pointer(&event)), unsafe.Sizeof(event))
			}); err != nil {
				return err
			}
			return callbackErr
		},
	}

	ep, err := cfg.ListenEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("ListenEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = ep.Close() })
	if !controlCalled {
		t.Fatal("SocketConfig.Control was not called")
	}

	gotInit, err := ep.conn.GetInitMsg()
	if err != nil {
		t.Fatalf("GetInitMsg: %v", err)
	}
	if *gotInit != cfg.InitMsg {
		t.Fatalf("InitMsg = %+v, want %+v", *gotInit, cfg.InitMsg)
	}
	recvInfo, err := ep.conn.getSockoptBool(SCTP_RECVRCVINFO)
	if err != nil || !recvInfo {
		t.Fatalf("SCTP_RECVRCVINFO = %v, %v; endpoint must force it on", recvInfo, err)
	}
	assocEvents, err := ep.conn.EventSubscribed(SCTP_ASSOC_CHANGE)
	if err != nil || !assocEvents {
		t.Fatalf("SCTP_ASSOC_CHANGE subscribed = %v, %v; endpoint must force it on",
			assocEvents, err)
	}
	fragmentLevel, err := ep.conn.GetFragmentInterleave()
	if err != nil || fragmentLevel != SCTPFragmentInterleaveOther {
		t.Fatalf("default fragment interleave = (%d, %v), want level %d per RFC 6458 §8.1.20",
			fragmentLevel, err, SCTPFragmentInterleaveOther)
	}

	for _, level := range []int{SCTPFragmentInterleaveNone, SCTPFragmentInterleaveOther} {
		t.Run(fmt.Sprintf("explicit fragment level %d", level), func(t *testing.T) {
			configured, err := new(SocketConfig).WithPreAssociation(PreAssociationConfig{
				FragmentInterleave: OptionalInt{Set: true, Value: level},
			}).OpenEndpoint("sctp4", loopbackAddr())
			if err != nil {
				t.Fatalf("OpenEndpoint: %v", err)
			}
			t.Cleanup(func() { _ = configured.Close() })
			got, err := configured.conn.GetFragmentInterleave()
			if err != nil || got != level {
				t.Fatalf("fragment interleave = (%d, %v), want (%d, nil)", got, err, level)
			}
			rcvInfo, err := configured.conn.getSockoptBool(SCTP_RECVRCVINFO)
			if err != nil || !rcvInfo {
				t.Fatalf("RCVINFO with fragment level %d = (%v, %v), want (true, nil)",
					level, rcvInfo, err)
			}
		})
	}

	levelTwo, err := new(SocketConfig).WithPreAssociation(PreAssociationConfig{
		FragmentInterleave: OptionalInt{Set: true, Value: SCTPFragmentInterleaveStreams},
	}).OpenEndpoint("sctp4", loopbackAddr())
	if levelTwo != nil || !errors.Is(err, errors.ErrUnsupported) {
		if levelTwo != nil {
			_ = levelTwo.Close()
		}
		t.Fatalf("explicit fragment level 2 = (%v, %v), want (nil, errors.ErrUnsupported); "+
			"Linux collapses level 2 to level 1", levelTwo, err)
	}
}

func TestSCTPEndpointFragmentsHandlerReentryAndMissingMetadata(t *testing.T) {
	var server *SCTPEndpoint
	serverID := make(chan SCTPAssocID, 1)
	handler := func(b []byte) error {
		note, err := ParseNotification(b)
		if err != nil {
			return err
		}
		change, ok := note.(*AssocChange)
		if !ok || change.State != SCTP_COMM_UP {
			return nil
		}
		// Receive invokes handlers after recvmsg has released the runtime
		// poller's per-descriptor read lock, so endpoint methods may re-enter.
		if err := server.SetWriteDeadline(time.Time{}); err != nil {
			return err
		}
		select {
		case serverID <- change.AssocID:
		default:
		}
		return nil
	}

	cfg := SocketConfig{NotificationHandler: handler}
	var err error
	server, err = cfg.ListenEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("ListenEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	client, err := OpenSCTPEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("OpenSCTPEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	clientID, err := client.Connect(endpointAddr(t, server))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	_ = endpointAssocChange(t, client)

	want := bytes.Repeat([]byte("fragment"), 41)
	if _, err := client.Send(want, &SndInfo{
		SID: 5, PPID: 0xaabbccdd, AssocID: int32(clientID),
	}, nil, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(endpointTestTimeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	var (
		assembled []byte
		assocID   SCTPAssocID
		fragments int
	)
	buf := make([]byte, 31)
	for {
		n, info, flags, err := server.Receive(buf)
		if err != nil {
			t.Fatalf("Receive fragment %d: %v", fragments, err)
		}
		if flags&MSG_NOTIFICATION != 0 {
			t.Fatal("NotificationHandler left a notification in Receive")
		}
		if info == nil || info.SID != 5 || info.PPID != 0xaabbccdd {
			t.Fatalf("fragment %d info = %+v", fragments, info)
		}
		if fragments == 0 {
			assocID = info.AssocID
		} else if info.AssocID != assocID {
			t.Fatalf("fragment association changed from %d to %d", assocID, info.AssocID)
		}
		assembled = append(assembled, buf[:n]...)
		fragments++
		if flags&MSG_EOR != 0 {
			break
		}
	}
	if fragments < 2 {
		t.Fatalf("message fit in one %d-byte buffer; truncation contract was not exercised", len(buf))
	}
	if !bytes.Equal(assembled, want) {
		t.Fatalf("reassembled %d bytes, want %d", len(assembled), len(want))
	}
	select {
	case callbackID := <-serverID:
		if callbackID != assocID {
			t.Fatalf("handler association id = %d, RcvInfo id = %d", callbackID, assocID)
		}
	case <-time.After(endpointTestTimeout):
		t.Fatal("NotificationHandler did not receive SCTP_COMM_UP")
	}

	// The constructor prevents this through its public surface; disable it
	// internally to prove Receive fails closed if the invariant is ever lost.
	if err := server.conn.SetRecvRcvInfo(false); err != nil {
		t.Fatalf("disable SCTP_RECVRCVINFO: %v", err)
	}
	missing := []byte("metadata deliberately disabled")
	if _, err := client.Send(missing, &SndInfo{AssocID: int32(clientID)}, nil, nil); err != nil {
		t.Fatalf("Send without receive metadata: %v", err)
	}
	n, info, flags, err := server.Receive(buf)
	if !errors.Is(err, ErrMissingReceiveInfo) {
		t.Fatalf("Receive without RCVINFO = %v, want ErrMissingReceiveInfo", err)
	}
	if info != nil || flags&MSG_EOR == 0 || !bytes.Equal(buf[:n], missing) {
		t.Fatalf("missing-metadata receive = n=%d info=%+v flags=%#x payload=%q",
			n, info, flags, buf[:n])
	}
}

func TestSCTPEndpointHandlerReassemblesNotificationWithTinyBuffer(t *testing.T) {
	type handledAssocChange struct {
		id     SCTPAssocID
		length int
	}

	var server *SCTPEndpoint
	handled := make(chan handledAssocChange, 1)
	handler := func(b []byte) error {
		note, err := ParseNotification(b)
		if err != nil {
			return err
		}
		change, ok := note.(*AssocChange)
		if !ok || change.State != SCTP_COMM_UP {
			return nil
		}
		// A handler runs after the one RawConn read operation that owns every
		// fragment has released the runtime poller's read lock.
		if err := server.SetWriteDeadline(time.Time{}); err != nil {
			return err
		}
		handled <- handledAssocChange{id: change.AssocID, length: len(b)}
		return nil
	}

	var err error
	server, err = (&SocketConfig{NotificationHandler: handler}).ListenEndpoint(
		"sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("ListenEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = server.Abort() })
	client, err := OpenSCTPEndpoint("sctp4", loopbackAddr())
	if err != nil {
		t.Fatalf("OpenSCTPEndpoint: %v", err)
	}
	t.Cleanup(func() { _ = client.Abort() })

	clientID, err := client.Connect(endpointAddr(t, server))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	_ = endpointAssocChange(t, client)

	payload := []byte{'x'}
	if _, err := client.Send(payload, &SndInfo{AssocID: int32(clientID)}, nil, nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if err := server.SetReadDeadline(time.Now().Add(endpointTestTimeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	// A one-byte receive buffer necessarily splits the 20-byte COMM_UP event.
	// Receive must assemble it internally, invoke the handler exactly once with
	// the complete record, then return the following application message.
	buf := make([]byte, 1)
	n, info, flags, err := server.Receive(buf)
	if err != nil {
		t.Fatalf("Receive with one-byte buffer: %v", err)
	}
	if n != len(payload) || !bytes.Equal(buf[:n], payload) || info == nil ||
		flags&MSG_NOTIFICATION != 0 || flags&MSG_EOR == 0 {
		t.Fatalf("Receive = n=%d payload=%q info=%+v flags=%#x", n, buf[:n], info, flags)
	}

	select {
	case got := <-handled:
		if got.id != info.AssocID || got.length != assocChangeMinSize {
			t.Fatalf("handler got id=%d length=%d, want id=%d length=%d",
				got.id, got.length, info.AssocID, assocChangeMinSize)
		}
	case <-time.After(endpointTestTimeout):
		t.Fatal("NotificationHandler did not receive the reassembled COMM_UP event")
	}
	select {
	case got := <-handled:
		t.Fatalf("NotificationHandler was called again for a continuation fragment: %+v", got)
	default:
	}
}
