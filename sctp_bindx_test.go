//go:build linux
// +build linux

package sctp

import (
	"errors"
	"net"
	"reflect"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestNormalizeDynamicBindAddr(t *testing.T) {
	input := sctpAddr([]string{"127.0.0.2"}, 0)
	current := sctpAddr([]string{"127.0.0.1"}, 4242)

	got, err := normalizeDynamicBindAddr(input, current)
	if err != nil {
		t.Fatalf("normalize zero port: %v", err)
	}
	if got.Port != current.Port {
		t.Errorf("normalized port = %d, want bound port %d", got.Port, current.Port)
	}
	if input.Port != 0 {
		t.Errorf("normalization changed caller's port to %d", input.Port)
	}
	got.IPAddrs[0].IP[0] ^= 0xff
	if input.IPAddrs[0].IP.String() != "127.0.0.2" {
		t.Errorf("normalized address aliases caller's IP: %v", input.IPAddrs[0].IP)
	}

	t.Run("matching bound port", func(t *testing.T) {
		addr := sctpAddr([]string{"127.0.0.2"}, current.Port)
		if _, err := normalizeDynamicBindAddr(addr, current); err != nil {
			t.Errorf("matching port: %v", err)
		}
	})

	t.Run("different bound port", func(t *testing.T) {
		addr := sctpAddr([]string{"127.0.0.2"}, current.Port+1)
		if _, err := normalizeDynamicBindAddr(addr, current); !errors.Is(err, syscall.EINVAL) {
			t.Errorf("mismatched port error = %v, want EINVAL", err)
		}
	})

	t.Run("unbound zero stays zero", func(t *testing.T) {
		addr := sctpAddr([]string{"127.0.0.2"}, 0)
		got, err := normalizeDynamicBindAddr(addr, nil)
		if err != nil {
			t.Fatalf("unbound normalization: %v", err)
		}
		if got.Port != 0 {
			t.Errorf("unbound port = %d, want 0 for kernel assignment", got.Port)
		}
	})

	for _, tc := range []struct {
		name string
		addr *SCTPAddr
	}{
		{"nil", nil},
		{"negative port", sctpAddr([]string{"127.0.0.2"}, -1)},
		{"oversized port", sctpAddr([]string{"127.0.0.2"}, 65536)},
		{"empty IP", &SCTPAddr{IPAddrs: []net.IPAddr{{}}, Port: 0}},
		{"invalid IP", &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IP{1, 2, 3}}}, Port: 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := normalizeDynamicBindAddr(tc.addr, current); err == nil {
				t.Fatal("invalid address was accepted")
			}
		})
	}
}

func TestRemovesEveryLocalAddress(t *testing.T) {
	current := sctpAddr([]string{"127.0.0.1", "127.0.0.2"}, 4242)
	for _, tc := range []struct {
		name   string
		remove *SCTPAddr
		want   bool
	}{
		{"one remains", sctpAddr([]string{"127.0.0.2"}, 4242), false},
		{"same set", sctpAddr([]string{"127.0.0.2", "127.0.0.1"}, 4242), true},
		{"superset", sctpAddr([]string{"127.0.0.3", "127.0.0.1", "127.0.0.2"}, 4242), true},
		{"wildcard", &SCTPAddr{Port: 4242}, true},
		{"nil", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := removesEveryLocalAddress(current, tc.remove); got != tc.want {
				t.Errorf("removesEveryLocalAddress = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("IPv4 representation", func(t *testing.T) {
		fourByte := &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.IP{127, 0, 0, 1}}}}
		sixteenByte := &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}}
		if !removesEveryLocalAddress(fourByte, sixteenByte) {
			t.Error("equivalent 4-byte and 16-byte IPv4 forms did not match")
		}
	})

	t.Run("different IPv6 zones stay distinct", func(t *testing.T) {
		bound := &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("fe80::1"), Zone: "1"}}}
		remove := &SCTPAddr{IPAddrs: []net.IPAddr{{IP: net.ParseIP("fe80::1"), Zone: "2"}}}
		if removesEveryLocalAddress(bound, remove) {
			t.Error("addresses on different IPv6 scopes matched")
		}
	})
}

func FuzzDynamicBindAddressPreparation(f *testing.F) {
	f.Add([]byte{127, 0, 0, 2}, int32(0), int32(4242), false)
	f.Add([]byte(net.ParseIP("::1")), int32(4242), int32(4242), true)
	f.Add([]byte{1, 2, 3}, int32(-1), int32(0), false)

	f.Fuzz(func(t *testing.T, rawIP []byte, port, currentPort int32, zoned bool) {
		// Keep interface-name resolution deterministic: an empty zone or numeric
		// loopback scope exercises both branches without turning arbitrary fuzz
		// bytes into host-dependent interface lookups.
		zone := ""
		if zoned {
			zone = "1"
		}
		input := &SCTPAddr{
			IPAddrs: []net.IPAddr{{IP: append(net.IP(nil), rawIP...), Zone: zone}},
			Port:    int(port),
		}
		before := cloneSCTPAddr(input)
		current := &SCTPAddr{Port: int(currentPort)}

		target, err := normalizeDynamicBindAddr(input, current)
		if !reflect.DeepEqual(input, before) {
			t.Fatalf("normalization mutated input: before=%v after=%v", before, input)
		}
		if err != nil {
			return
		}
		if err := target.Validate(); err != nil {
			t.Fatalf("normalization returned an invalid address: %v", err)
		}
		if current.Port > 0 && input.Port == 0 && target.Port != current.Port {
			t.Fatalf("zero port became %d, want bound port %d", target.Port, current.Port)
		}
		if len(target.IPAddrs) != 1 || !slices.Equal(target.IPAddrs[0].IP, input.IPAddrs[0].IP) {
			t.Fatalf("normalization changed IP bytes: input=%v target=%v", input, target)
		}

		// The set comparison must accept every IP representation Validate accepts
		// without panicking, including the 4-byte and 16-byte IPv4 forms.
		_ = removesEveryLocalAddress(current, target)
	})
}

func TestListenerBindAddRemoveRefreshesAddr(t *testing.T) {
	available := requireLoopbacks(t, 2)
	base, extra := available[0], available[1]

	ln, err := ListenSCTP("sctp4", sctpAddr([]string{base}, 0))
	if err != nil {
		t.Fatalf("listen on %s: %v", base, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	initial := ln.Addr().(*SCTPAddr)
	if initial.Port == 0 {
		t.Fatal("listener retained port zero after bind")
	}

	add := sctpAddr([]string{extra}, 0)
	if err := ln.BindAdd(add); err != nil {
		t.Fatalf("BindAdd(%s): %v", extra, err)
	}
	if add.Port != 0 {
		t.Errorf("BindAdd changed the caller's port to %d", add.Port)
	}
	assertLocalAddressSet(t, ln.Addr(), initial.Port, base, extra)

	// Addr must remain an independent snapshot after the cache refresh, not a
	// view into either the kernel reply or the value passed to BindAdd.
	snapshot := ln.Addr().(*SCTPAddr)
	snapshot.IPAddrs[0].IP[0] ^= 0xff
	snapshot.Port = 1
	assertLocalAddressSet(t, ln.Addr(), initial.Port, base, extra)

	remove := sctpAddr([]string{extra}, 0)
	if err := ln.BindRemove(remove); err != nil {
		t.Fatalf("BindRemove(%s): %v", extra, err)
	}
	if remove.Port != 0 {
		t.Errorf("BindRemove changed the caller's port to %d", remove.Port)
	}
	assertLocalAddressSet(t, ln.Addr(), initial.Port, base)

	wrongPort := initial.Port + 1
	if wrongPort > 65535 {
		wrongPort = initial.Port - 1
	}
	if err := ln.BindAdd(sctpAddr([]string{extra}, wrongPort)); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("BindAdd with port %d on port %d listener = %v, want EINVAL",
			wrongPort, initial.Port, err)
	}
	assertLocalAddressSet(t, ln.Addr(), initial.Port, base)

	for name, addr := range map[string]*SCTPAddr{
		"nil":          nil,
		"invalid IP":   {IPAddrs: []net.IPAddr{{IP: net.IP{1, 2, 3}}}},
		"invalid port": sctpAddr([]string{extra}, 65536),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ln.BindAdd(addr); err == nil {
				t.Fatal("BindAdd accepted an invalid address")
			}
			assertLocalAddressSet(t, ln.Addr(), initial.Port, base)
		})
	}

	if err := ln.BindRemove(sctpAddr([]string{base}, 0)); !errors.Is(err, syscall.EINVAL) {
		t.Errorf("removing the listener's last address = %v, want EINVAL", err)
	}
	assertLocalAddressSet(t, ln.Addr(), initial.Port, base)

	if err := ln.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := ln.BindAdd(sctpAddr([]string{extra}, 0)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("BindAdd after Close = %v, want net.ErrClosed", err)
	}
	var nilListener *SCTPListener
	if err := nilListener.BindAdd(sctpAddr([]string{extra}, 0)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("BindAdd on nil listener = %v, want net.ErrClosed", err)
	}
}

func TestSCTPConnBindAddRemoveRefreshesLocalAddr(t *testing.T) {
	available := requireLoopbacks(t, 2)
	base, extra := available[0], available[1]

	fd, err := syscall.Socket(syscall.AF_INET,
		syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, syscall.IPPROTO_SCTP)
	if err != nil {
		t.Skipf("cannot create an SCTP socket: %v", err)
	}
	conn := NewSCTPConn(fd, nil)
	t.Cleanup(func() { _ = conn.CloseWithTimeout(0) })
	if conn.initErr != nil {
		t.Fatalf("NewSCTPConn: %v", conn.initErr)
	}

	first := sctpAddr([]string{base}, 0)
	if err := conn.BindAdd(first); err != nil {
		t.Fatalf("BindAdd on unbound connection: %v", err)
	}
	if first.Port != 0 {
		t.Errorf("first BindAdd changed the caller's port to %d", first.Port)
	}
	local := conn.LocalAddr().(*SCTPAddr)
	if local.Port == 0 {
		t.Fatal("kernel did not assign a port to the unbound endpoint")
	}
	assertLocalAddressSet(t, local, local.Port, base)

	if err := conn.BindAdd(sctpAddr([]string{extra}, 0)); err != nil {
		t.Fatalf("BindAdd second address: %v", err)
	}
	assertLocalAddressSet(t, conn.LocalAddr(), local.Port, base, extra)

	if err := conn.BindRemove(sctpAddr([]string{extra}, 0)); err != nil {
		t.Fatalf("BindRemove second address: %v", err)
	}
	assertLocalAddressSet(t, conn.LocalAddr(), local.Port, base)

	if err := conn.CloseWithTimeout(0); err != nil {
		t.Fatalf("CloseWithTimeout: %v", err)
	}
	if err := conn.BindRemove(sctpAddr([]string{base}, 0)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("BindRemove after Close = %v, want net.ErrClosed", err)
	}
	var nilConn *SCTPConn
	if err := nilConn.BindRemove(sctpAddr([]string{base}, 0)); !errors.Is(err, net.ErrClosed) {
		t.Errorf("BindRemove on nil connection = %v, want net.ErrClosed", err)
	}
}

func TestConcurrentListenerBindAddKeepsCacheInSync(t *testing.T) {
	available := requireLoopbacks(t, 3)
	base, additions := available[0], available[1:3]

	ln, err := ListenSCTP("sctp4", sctpAddr([]string{base}, 0))
	if err != nil {
		t.Fatalf("listen on %s: %v", base, err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var wg sync.WaitGroup
	errs := make(chan error, len(additions))
	for _, address := range additions {
		address := address
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- ln.BindAdd(sctpAddr([]string{address}, 0))
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent BindAdd: %v", err)
		}
	}

	cached := ln.Addr().(*SCTPAddr)
	assertLocalAddressSet(t, cached, cached.Port, base, additions[0], additions[1])

	// Compare the cache with an independent kernel read. Without bindMu an
	// older concurrent readback can be stored after a newer one and omit an
	// address even though both bindx calls succeeded.
	raw, err := ln.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var kernel *SCTPAddr
	var readErr error
	if err := raw.Control(func(fd uintptr) {
		kernel, readErr = sctpGetAddrs(int(fd), 0, SCTP_GET_LOCAL_ADDRS)
	}); err != nil {
		t.Fatalf("RawConn.Control: %v", err)
	}
	if readErr != nil {
		t.Fatalf("SCTP_GET_LOCAL_ADDRS: %v", readErr)
	}
	if got, want := ipStrings(cached), ipStrings(kernel); !equalStrings(got, want) {
		t.Errorf("cached addresses %v, kernel addresses %v", got, want)
	}
}

// TestConnectedBindAddRemoveUpdatesPeerAddressReadback proves both kernels
// agree on the address set after RFC 5061 was negotiated. It is deliberately
// not treated as protocol proof.
func TestConnectedBindAddRemoveUpdatesPeerAddressReadback(t *testing.T) {
	available := requireLoopbacks(t, 3)
	clientBase, added, serverBase := available[0], available[1], available[2]

	enableDynamicAddresses := func(network, address string, raw syscall.RawConn) error {
		var optionErr error
		if err := raw.Control(func(fd uintptr) {
			if optionErr = setAssocValueBool(int(fd), SCTP_AUTH_SUPPORTED, true); optionErr != nil {
				return
			}
			optionErr = setAssocValueBool(int(fd), SCTP_ASCONF_SUPPORTED, true)
		}); err != nil {
			return err
		}
		return optionErr
	}
	cfg := &SocketConfig{Control: enableDynamicAddresses}
	ln, err := cfg.Listen("sctp4", sctpAddr([]string{serverBase}, 0))
	if err != nil {
		t.Skipf("kernel cannot configure RFC 5061 on the listener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan *SCTPConn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		conn, err := ln.AcceptSCTP()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- conn
	}()

	client, err := cfg.Dial("sctp4", sctpAddr([]string{clientBase}, 0),
		ln.Addr().(*SCTPAddr))
	if err != nil {
		t.Skipf("kernel cannot establish an RFC 5061 association: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	var server *SCTPConn
	select {
	case server = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("AcceptSCTP: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the RFC 5061 association")
	}
	t.Cleanup(func() { _ = server.Close() })

	if supported, err := client.AsconfSupported(); err != nil {
		t.Fatalf("AsconfSupported: %v", err)
	} else if !supported {
		t.Skip("the kernel did not negotiate RFC 5061 despite the pre-bind request")
	}

	add := sctpAddr([]string{added}, 0)
	if err := client.BindAdd(add); err != nil {
		t.Fatalf("connected BindAdd(%s): %v", added, err)
	}
	if add.Port != 0 {
		t.Errorf("connected BindAdd changed the caller's port to %d", add.Port)
	}
	clientLocal := client.LocalAddr().(*SCTPAddr)
	assertLocalAddressSet(t, clientLocal, clientLocal.Port, clientBase, added)
	waitForPeerAddresses(t, server, clientBase, added)

	if err := client.BindRemove(sctpAddr([]string{added}, 0)); err != nil {
		t.Fatalf("connected BindRemove(%s): %v", added, err)
	}
	assertLocalAddressSet(t, client.LocalAddr(), clientLocal.Port, clientBase)
	waitForPeerAddresses(t, server, clientBase)
}

func assertLocalAddressSet(t *testing.T, address net.Addr, port int, want ...string) {
	t.Helper()
	got, ok := address.(*SCTPAddr)
	if !ok || got == nil {
		t.Fatalf("local address = %T %v, want *SCTPAddr", address, address)
	}
	if got.Port != port {
		t.Errorf("local port = %d, want %d", got.Port, port)
	}
	if actual, expected := ipStrings(got), sortedCopy(want); !equalStrings(actual, expected) {
		t.Errorf("local addresses = %v, want %v", actual, expected)
	}
}

func waitForPeerAddresses(t *testing.T, conn *SCTPConn, want ...string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last []string
	for time.Now().Before(deadline) {
		addr, err := conn.SCTPRemoteAddr(0)
		if err == nil {
			last = ipStrings(addr)
			if equalStrings(last, sortedCopy(want)) {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("peer addresses = %v, want %v after RFC 5061 ASCONF-ACK",
		last, sortedCopy(want))
}
