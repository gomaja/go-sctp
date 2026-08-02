//go:build !linux
// +build !linux

package sctp

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"syscall"
	"testing"
	"time"
)

type unsupportedStubCase struct {
	name string
	call func() error
}

func unsupportedStubCases() []unsupportedStubCase {
	var c *SCTPConn
	var ln *SCTPListener

	return []unsupportedStubCase{
		// Constructors and shared socket helpers.
		{"newSCTPConn", func() error { _, err := newSCTPConn(-1, nil); return err }},
		{"openSCTPEndpointConfig", func() error {
			_, err := openSCTPEndpointConfig("sctp", nil, false, InitMsg{}, nil, nil,
				PreAssociationConfig{})
			return err
		}},
		{"SCTPEndpoint.Connect", func() error { _, err := (*SCTPEndpoint)(nil).Connect(nil); return err }},
		{"SCTPEndpoint.Send", func() error {
			_, err := (*SCTPEndpoint)(nil).Send(nil, nil, nil, nil)
			return err
		}},
		{"SCTPEndpoint.Receive", func() error {
			_, _, _, err := (*SCTPEndpoint)(nil).Receive(nil)
			return err
		}},
		{"SCTPEndpoint.PeelOff", func() error {
			_, err := (*SCTPEndpoint)(nil).PeelOff(0)
			return err
		}},
		{"SCTPEndpoint.SyscallConn", func() error {
			_, err := (*SCTPEndpoint)(nil).SyscallConn()
			return err
		}},
		{"SCTPEndpoint.BindAdd", func() error {
			return (*SCTPEndpoint)(nil).BindAdd(nil)
		}},
		{"SCTPEndpoint.BindRemove", func() error {
			return (*SCTPEndpoint)(nil).BindRemove(nil)
		}},
		{"SCTPEndpoint.LocalAddrs", func() error {
			_, err := (*SCTPEndpoint)(nil).LocalAddrs(0)
			return err
		}},
		{"SCTPEndpoint.PeerAddrs", func() error {
			_, err := (*SCTPEndpoint)(nil).PeerAddrs(0)
			return err
		}},
		{"SCTPEndpoint.AssociationCount", func() error {
			_, err := (*SCTPEndpoint)(nil).AssociationCount()
			return err
		}},
		{"SCTPEndpoint.AssociationIDs", func() error {
			_, err := (*SCTPEndpoint)(nil).AssociationIDs()
			return err
		}},
		{"SCTPEndpoint.SetAutoClose", func() error {
			return (*SCTPEndpoint)(nil).SetAutoClose(0)
		}},
		{"SCTPEndpoint.GetAutoClose", func() error {
			_, err := (*SCTPEndpoint)(nil).GetAutoClose()
			return err
		}},
		{"SCTPEndpoint.CloseAssociation", func() error {
			return (*SCTPEndpoint)(nil).CloseAssociation(0)
		}},
		{"SCTPEndpoint.AbortAssociation", func() error {
			return (*SCTPEndpoint)(nil).AbortAssociation(0, nil)
		}},
		{"SCTPEndpoint.Close", func() error { return (*SCTPEndpoint)(nil).Close() }},
		{"SCTPEndpoint.Abort", func() error { return (*SCTPEndpoint)(nil).Abort() }},
		{"SCTPEndpoint.SetDeadline", func() error {
			return (*SCTPEndpoint)(nil).SetDeadline(time.Time{})
		}},
		{"SCTPEndpoint.SetReadDeadline", func() error {
			return (*SCTPEndpoint)(nil).SetReadDeadline(time.Time{})
		}},
		{"SCTPEndpoint.SetWriteDeadline", func() error {
			return (*SCTPEndpoint)(nil).SetWriteDeadline(time.Time{})
		}},
		{"SCTPConn.setsockopt", func() error { _, _, err := c.setsockopt(0, 0, 0); return err }},
		{"SCTPConn.getsockopt", func() error {
			var optlen uint32
			_, _, err := c.getsockopt(0, 0, &optlen)
			return err
		}},
		{"SCTPConn.getsockoptRaw", func() error { _, _, err := c.getsockoptRaw(0, 0, 0); return err }},
		{"SCTPConn.setInitOpts", func() error { return c.setInitOpts(InitMsg{}) }},
		{"SCTPConn.setsockoptInt", func() error { return c.setsockoptInt(0, false) }},
		{"SCTPConn.setsockoptInt32", func() error { return c.setsockoptInt32(0, 0) }},
		{"SCTPConn.getsockoptInt32", func() error { _, err := c.getsockoptInt32(0); return err }},
		{"SCTPConn.setSockoptBool", func() error { return c.setSockoptBool(0, false) }},
		{"SCTPConn.getSockoptBool", func() error { _, err := c.getSockoptBool(0); return err }},
		{"SCTPConn.setAssocValue", func() error { return c.setAssocValue(0, 0) }},
		{"SCTPConn.getAssocValue", func() error { _, err := c.getAssocValue(0); return err }},
		{"SCTPConn.setAssocValueBool", func() error { return c.setAssocValueBool(0, false) }},
		{"SCTPConn.getAddrs", func() error { _, err := c.getAddrs(0, 0); return err }},

		// Reads and writes.
		{"SCTPConn.SCTPWrite", func() error { _, err := c.SCTPWrite(nil, nil); return err }},
		{"SCTPConn.writeSndRcv", func() error { _, err := c.writeSndRcv(nil, nil, false); return err }},
		{"SCTPConn.write", func() error { _, err := c.write(nil); return err }},
		{"SCTPConn.SCTPWriteInfo", func() error { _, err := c.SCTPWriteInfo(nil, nil, nil, nil); return err }},
		{"SCTPConn.SCTPRead", func() error { _, _, err := c.SCTPRead(nil); return err }},
		{"SCTPConn.SCTPReadFlags", func() error { _, _, _, err := c.SCTPReadFlags(nil); return err }},
		{"SCTPConn.SCTPReadMsg", func() error { _, _, _, err := c.SCTPReadMsg(nil, nil); return err }},
		{"SCTPConn.SCTPReadNextInfo", func() error { _, _, _, _, err := c.SCTPReadNextInfo(nil); return err }},
		{"SCTPConn.ReadMsg", func() error { _, _, err := c.ReadMsg(1); return err }},

		// Lifecycle.
		{"SCTPConn.Close", func() error { return c.Close() }},
		{"SCTPConn.Abort", func() error { return c.Abort() }},
		{"SCTPConn.CloseWithTimeout", func() error { return c.CloseWithTimeout(0) }},
		{"SCTPConn.PeelOff", func() error { _, err := c.PeelOff(0); return err }},
		{"SCTPConn.SyscallConn", func() error { _, err := c.SyscallConn(); return err }},

		// Buffers.
		{"SCTPConn.SetWriteBuffer", func() error { return c.SetWriteBuffer(0) }},
		{"SCTPConn.GetWriteBuffer", func() error { _, err := c.GetWriteBuffer(); return err }},
		{"SCTPConn.SetReadBuffer", func() error { return c.SetReadBuffer(0) }},
		{"SCTPConn.GetReadBuffer", func() error { _, err := c.GetReadBuffer(); return err }},

		// Listeners.
		{"ListenSCTP", func() error { _, err := ListenSCTP("sctp", nil); return err }},
		{"ListenSCTPExt", func() error { _, err := ListenSCTPExt("sctp", nil, InitMsg{}); return err }},
		{"listenSCTPExtConfig", func() error {
			_, err := listenSCTPExtConfig("sctp", nil, InitMsg{}, nil, nil,
				PreAssociationConfig{})
			return err
		}},
		{"FileListener", func() error { _, err := FileListener(nil); return err }},
		{"SCTPListener.Accept", func() error { _, err := ln.Accept(); return err }},
		{"SCTPListener.AcceptSCTP", func() error {
			if _, err := ln.AcceptSCTP(); !errors.Is(err, ErrUnsupported) {
				return err
			}
			_, err := (&SCTPListener{}).AcceptSCTP()
			return err
		}},
		{"SCTPListener.Close", func() error { return ln.Close() }},
		{"SCTPListener.SyscallConn", func() error { _, err := ln.SyscallConn(); return err }},

		// Dialers.
		{"DialSCTP", func() error { _, err := DialSCTP("sctp", nil, nil); return err }},
		{"DialSCTPExt", func() error { _, err := DialSCTPExt("sctp", nil, nil, InitMsg{}); return err }},
		{"dialSCTPExtConfig", func() error {
			_, err := dialSCTPExtConfig("sctp", nil, nil, InitMsg{}, nil, nil,
				PreAssociationConfig{})
			return err
		}},
		{"DialSCTPContext", func() error {
			_, err := DialSCTPContext(context.Background(), "sctp", nil, nil, InitMsg{})
			return err
		}},
		{"DialSCTPContextWithAbandonPolicy", func() error {
			_, err := DialSCTPContextWithAbandonPolicy(context.Background(), "sctp",
				nil, nil, InitMsg{}, DialAbandonQuiet)
			return err
		}},
		{"dialSCTPExtConfigContext", func() error {
			_, err := dialSCTPExtConfigContext(context.Background(), "sctp", nil, nil,
				InitMsg{}, nil, nil, PreAssociationConfig{}, DialAbandonAbort)
			return err
		}},

		// The socket-option primitives every wrapper in sctp.go funnels into.
		{"setsockopt", func() error { _, _, err := setsockopt(0, 0, 0, 0); return err }},
		{"getsockopt", func() error {
			var optlen uint32
			_, _, err := getsockopt(0, 0, 0, &optlen)
			return err
		}},
		{"getsockoptRaw", func() error { _, _, err := getsockoptRaw(0, 0, 0, 0); return err }},
		{"sctpGetAddrs", func() error { _, err := sctpGetAddrs(0, 0, 0); return err }},
	}
}

// TestNewSCTPConnClosesOwnedDescriptorOnUnsupportedPlatform pins the ownership
// contract even where SCTP itself is unavailable. NewSCTPConn cannot return an
// initialization error, so losing the caller's descriptor without closing it
// would otherwise be an undetectable leak.
func TestNewSCTPConnClosesOwnedDescriptorOnUnsupportedPlatform(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "new-sctp-conn-owned-fd")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer func() { _ = file.Close() }()

	conn := NewSCTPConn(int(file.Fd()), nil)
	if conn == nil {
		t.Fatal("NewSCTPConn returned nil")
	}
	if !errors.Is(conn.initErr, ErrUnsupported) {
		t.Fatalf("initialization error = %v, want ErrUnsupported", conn.initErr)
	}

	if _, err := file.Stat(); err == nil {
		t.Error("owned descriptor remains usable after unsupported initialization")
	}
	if err := file.Close(); err == nil {
		t.Error("closing the original file succeeded; NewSCTPConn did not close its descriptor")
	}
}

func TestDialContextWithAbandonPolicyValidatesPolicyOnUnsupportedPlatform(t *testing.T) {
	_, err := DialSCTPContextWithAbandonPolicy(context.Background(), "sctp",
		nil, nil, InitMsg{}, DialAbandonPolicy(99))
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("DialSCTPContextWithAbandonPolicy err = %v, want syscall.EINVAL", err)
	}

	_, err = dialSCTPExtConfigContext(context.Background(), "sctp", nil, nil,
		InitMsg{}, nil, nil, PreAssociationConfig{}, DialAbandonPolicy(99))
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("dialSCTPExtConfigContext err = %v, want syscall.EINVAL", err)
	}
}

// TestDynamicBindEntryPointsReportUnsupported covers the methods implemented
// in the shared file. They are absent from the stub manifest because they do
// not need platform-specific declarations, but their valid-input path must
// still terminate at the platform SyscallConn stub rather than dereferencing a
// nil raw descriptor or reporting success.
func TestDynamicBindEntryPointsReportUnsupported(t *testing.T) {
	addr := &SCTPAddr{Port: 0}
	conn := &SCTPConn{}
	listener := &SCTPListener{}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"SCTPConn.BindAdd", func() error { return conn.BindAdd(addr) }},
		{"SCTPConn.BindRemove", func() error { return conn.BindRemove(addr) }},
		{"SCTPListener.BindAdd", func() error { return listener.BindAdd(addr) }},
		{"SCTPListener.BindRemove", func() error { return listener.BindRemove(addr) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, ErrUnsupported) {
				t.Errorf("error = %v, want ErrUnsupported", err)
			}
		})
	}
}

// TestUnsupportedEntryPointsReportTheSentinel calls every function stub in
// sctp_unsupported.go and requires the sentinel rather than a bare nil a caller
// would read as success.
//
// A missing row is not a silent coverage hole: TestUnsupportedStubManifestIsComplete
// parses the source and requires every function declaration to be represented
// exactly once. This is what catches the next platform method at the same change
// that adds it rather than after a consumer finds the mismatch.
//
// Cross-builds do not execute tests and go vet only type-checks them. The macOS
// unsupported-platform CI job is therefore the runtime guard for these return
// values.
func TestUnsupportedEntryPointsReportTheSentinel(t *testing.T) {
	for _, tc := range unsupportedStubCases() {
		err := tc.call()
		if err == nil {
			t.Errorf("%s returned a nil error on a platform without SCTP; "+
				"a caller checking err then uses a nil result", tc.name)
			continue
		}
		if !errors.Is(err, errors.ErrUnsupported) {
			t.Errorf("%s err = %v, want it to wrap errors.ErrUnsupported", tc.name, err)
		}
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s err = %v, want it to wrap sctp.ErrUnsupported", tc.name, err)
		}
	}
}

// TestUnsupportedStubManifestIsComplete prevents a new platform stub from
// compiling successfully while remaining absent from the runtime sentinel
// checks above. That exact omission happened when SCTPReadMsg was added.
func TestUnsupportedStubManifestIsComplete(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate the unsupported test file")
	}
	stubFile := filepath.Join(filepath.Dir(thisFile), "sctp_unsupported.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), stubFile, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", stubFile, err)
	}

	declared := make(map[string]struct{})
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		name := fn.Name.Name
		if fn.Recv != nil {
			name = receiverTypeName(t, fn.Recv.List[0].Type) + "." + name
		}
		declared[name] = struct{}{}
	}

	covered := make(map[string]struct{})
	for _, tc := range unsupportedStubCases() {
		if _, duplicate := covered[tc.name]; duplicate {
			t.Fatalf("unsupported stub manifest contains duplicate %q", tc.name)
		}
		covered[tc.name] = struct{}{}
	}

	var missing, stale []string
	for name := range declared {
		if _, ok := covered[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range covered {
		if _, ok := declared[name]; !ok {
			stale = append(stale, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) != 0 || len(stale) != 0 {
		t.Fatalf("unsupported stub manifest drift: missing=%v stale=%v", missing, stale)
	}
}

func receiverTypeName(t *testing.T, expr ast.Expr) string {
	t.Helper()
	switch expr := expr.(type) {
	case *ast.Ident:
		return expr.Name
	case *ast.StarExpr:
		return receiverTypeName(t, expr.X)
	default:
		t.Fatalf("unsupported receiver expression %T", expr)
		return ""
	}
}
