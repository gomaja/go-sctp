// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// TestExportedAPI pins the package's exported surface against
// testdata/api.golden, one name per line, sorted: every exported
// package-level type, func, const and var, and every exported method on
// an exported type, written "Type.Method". A method literally named
// "Type" (AssocChange.Type and its siblings among the notification
// types) is an ordinary entry here, counted like any other method name.
//
// Checked for linux/amd64, darwin/arm64 and windows/amd64, regardless of
// which platform is running this test: this package's exported names
// are meant to be the same everywhere (unsupported.go mirrors every
// Linux constructor and method the stub manifest lists, checked by
// TestUnsupportedStubManifestIsComplete), and checking only the
// GOOS/GOARCH pair the host happens to run this test under would let a
// stub added to one platform's build (a method that only compiles under
// a stray build tag, say) pass here while silently changing the API on
// another; checking all three, none of them assumed to be the host's
// own, is what actually proves the claim rather than assuming it.
//
// A diff between this and the golden file is reported with the missing
// and extra names, rather than one failure per name, so a review sees
// the whole shape of the difference at once.
func TestExportedAPI(t *testing.T) {
	want := readAPIGolden(t)

	for _, target := range [3]struct{ goos, goarch string }{
		{"linux", "amd64"},
		{"darwin", "arm64"},
		{"windows", "amd64"},
	} {
		t.Run(target.goos+"_"+target.goarch, func(t *testing.T) {
			got := exportedAPI(t, target.goos, target.goarch)
			if slices.Equal(got, want) {
				return
			}

			gotSet := make(map[string]bool, len(got))
			for _, n := range got {
				gotSet[n] = true
			}
			wantSet := make(map[string]bool, len(want))
			for _, n := range want {
				wantSet[n] = true
			}

			var missing, extra []string
			for _, n := range want {
				if !gotSet[n] {
					missing = append(missing, n)
				}
			}
			for _, n := range got {
				if !wantSet[n] {
					extra = append(extra, n)
				}
			}

			var b strings.Builder
			b.WriteString("exported API does not match testdata/api.golden\n")
			if len(missing) > 0 {
				b.WriteString("missing (golden has it, the package does not):\n")
				for _, n := range missing {
					b.WriteString("  - " + n + "\n")
				}
			}
			if len(extra) > 0 {
				b.WriteString("extra (the package has it, golden does not):\n")
				for _, n := range extra {
					b.WriteString("  + " + n + "\n")
				}
			}
			t.Error(b.String())
		})
	}
}

// readAPIGolden reads testdata/api.golden as one name per line, sorted.
// Line endings are read tolerantly ("\r\n" or "\n"): the file is meant to
// compare equal on every platform this test checks, Windows checkouts
// (CRLF, unless core.autocrlf or a .gitattributes override says
// otherwise) included, and a literal "\r" left on the end of every name
// would fail every comparison for a reason that has nothing to do with
// the API itself.
func readAPIGolden(t *testing.T) []string {
	t.Helper()
	want, err := os.ReadFile(filepath.Join("testdata", "api.golden"))
	if err != nil {
		t.Fatalf("read testdata/api.golden: %v", err)
	}
	normalized := strings.ReplaceAll(string(want), "\r\n", "\n")
	return strings.Split(strings.TrimRight(normalized, "\n"), "\n")
}

// exportedAPI parses and type-checks this package as go build would for
// goos/goarch, then returns every exported package-level name and every
// exported method on an exported named type, as "Type.Method", sorted.
func exportedAPI(t *testing.T, goos, goarch string) []string {
	t.Helper()

	// importer.ForCompiler's "source" mode resolves every import (syscall
	// among them) through the single shared build.Default context, not
	// through a context this function could pass it directly, so
	// build.Default itself is overridden for this test's duration and
	// restored after: otherwise the standard library the importer reads
	// is the host's, which for a target other than the host is missing
	// that target's own platform-specific names (Linux's MSG_NOSIGNAL,
	// SOCK_NONBLOCK and Accept4 among them) and this test would fail
	// checking any platform but the one running it.
	old := build.Default
	build.Default.GOOS = goos
	build.Default.GOARCH = goarch
	build.Default.CgoEnabled = false
	defer func() { build.Default = old }()

	bpkg, err := build.Default.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("build.Context.ImportDir: %v", err)
	}

	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range bpkg.GoFiles {
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, f)
	}

	conf := &types.Config{
		Importer: importer.ForCompiler(fset, "source", nil),
		Error:    func(err error) { t.Error(err) },
	}
	pkg, err := conf.Check(bpkg.ImportPath, fset, files, nil)
	if err != nil {
		t.Fatalf("type-check: %v", err)
	}

	var names []string
	scope := pkg.Scope()
	for _, name := range scope.Names() {
		if !token.IsExported(name) {
			continue
		}
		names = append(names, name)

		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok {
			continue // a func, const or var: no methods to add
		}
		named, ok := tn.Type().(*types.Named)
		if !ok {
			continue
		}
		if _, isInterface := named.Underlying().(*types.Interface); isInterface {
			// An interface's methods are its contract, already spelled
			// out inside its own declaration (Notification's Type()
			// among them); each concrete type that satisfies it, such as
			// AssocChange, contributes its own "Type.Type" entry
			// instead. The golden list follows that convention, so an
			// interface type contributes only its bare name here, never
			// "Interface.Method" entries.
			continue
		}
		names = append(names, exportedMethods(name, named)...)
	}

	sort.Strings(names)
	return names
}

// exportedMethods lists typeName+"."+M for every exported method M in
// either the value or the pointer method set of named, deduplicated by
// name: a value-receiver method appears in both sets, and this package
// declares no two methods on one type that differ only in receiver kind.
func exportedMethods(typeName string, named *types.Named) []string {
	seen := make(map[string]bool)
	var out []string
	for _, ms := range [2]*types.MethodSet{
		types.NewMethodSet(named),
		types.NewMethodSet(types.NewPointer(named)),
	} {
		for i := range ms.Len() {
			m := ms.At(i).Obj()
			if !m.Exported() || seen[m.Name()] {
				continue
			}
			seen[m.Name()] = true
			out = append(out, typeName+"."+m.Name())
		}
	}
	return out
}
