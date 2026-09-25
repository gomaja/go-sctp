// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sctp

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"testing"
)

// unsupportedStubCase is one function or method stubbed in unsupported.go,
// paired with a call that exercises it.
type unsupportedStubCase struct {
	name string
	call func() error
}

// unsupportedStubCases lists one case per function or method declared in
// unsupported.go, by the same name TestUnsupportedStubManifestIsComplete
// reads from that file's source (a bare function's own name, or
// "Receiver.Method" for a method). It is empty for now: unsupported.go
// declares nothing yet, and each stub a later change adds there adds its
// case here in the same change, so the two lists never drift apart for
// more than one commit.
func unsupportedStubCases() []unsupportedStubCase {
	return nil
}

// TestUnsupportedEntryPointsReportTheSentinel calls every case in
// unsupportedStubCases and requires it to return an error matching both
// ErrUnsupported and the standard library's errors.ErrUnsupported, rather
// than a bare nil a caller checking err would read as success.
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

// TestUnsupportedStubManifestIsComplete parses unsupported.go and requires
// every function and method it declares to appear, by exactly one name, in
// unsupportedStubCases — so a stub added to that file without a
// corresponding case here fails this test instead of silently compiling
// with no runtime check that it actually reports ErrUnsupported.
//
// It reads the source with os.ReadFile("unsupported.go") — a path relative
// to the package directory, which "go test" guarantees as the working
// directory — rather than locating the file through runtime.Caller. A
// caller-derived path is the absolute build-time location the compiler
// embedded, which a binary built with -trimpath does not carry at all and
// a binary run from anywhere other than where it was built cannot resolve,
// either way failing this test over where its own source happens to sit
// rather than over anything the test is meant to check.
func TestUnsupportedStubManifestIsComplete(t *testing.T) {
	const stubFile = "unsupported.go"
	src, err := os.ReadFile(stubFile)
	if err != nil {
		t.Fatalf("read %s: %v", stubFile, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), stubFile, src, 0)
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
