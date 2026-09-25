// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoVersionMarkedIdentifiers guards the redesign's naming rule: no
// directory name, no file name and no identifier, exported or not, may
// carry a version marker such as "V2" or "v2". Kernel names that
// legitimately contain one (for example SCTP_PEER_ADDR_THLDS_V2) may
// appear only in comments, which this test does not inspect.
func TestNoVersionMarkedIdentifiers(t *testing.T) {
	re := regexp.MustCompile(`[vV]2`)
	fset := token.NewFileSet()
	inspected := 0

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != "." && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata") {
				return filepath.SkipDir
			}
			if re.MatchString(name) {
				t.Errorf("directory name %s carries a version marker", path)
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		if re.MatchString(d.Name()) {
			t.Errorf("file name %s carries a version marker", path)
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		inspected++
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok && re.MatchString(id.Name) {
				t.Errorf("%s: identifier %q carries a version marker", fset.Position(id.Pos()), id.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if inspected == 0 {
		t.Fatal("no Go file was inspected; the walk is broken")
	}
}

// TestPackageCommentOnlyInDocGo guards the redesign's package-comment rule:
// only doc.go may carry the package comment — the leading comment block
// go/ast attaches to a file's *ast.File.Doc because nothing but blank
// lines separates it from "package sctp", and so the one go/doc and
// "go doc ." print for the whole package. Every other file's own leading
// comment describes that file instead, one blank line away from the
// package clause, which makes it an ordinary comment attached to nothing
// in particular rather than the package comment. parser.ParseComments is
// required for File.Doc to be populated at all; without it this test
// would pass vacuously, never finding a package comment anywhere,
// including in doc.go, which is why doc.go's own File.Doc is asserted
// non-nil below rather than only checking that no other file has one.
func TestPackageCommentOnlyInDocGo(t *testing.T) {
	fset := token.NewFileSet()
	sawDocGo := false
	inspected := 0

	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != "." && (strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.PackageClauseOnly)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		inspected++
		if d.Name() == "doc.go" {
			sawDocGo = true
			if f.Doc == nil {
				t.Errorf("%s: expected this to be the package comment, found none", path)
			}
			return nil
		}
		if f.Doc != nil {
			t.Errorf("%s: carries a package comment (%q); only doc.go may — separate this file's own leading comment from \"package sctp\" with a blank line",
				path, f.Doc.Text())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if inspected == 0 {
		t.Fatal("no Go file was inspected; the walk is broken")
	}
	if !sawDocGo {
		t.Fatal("doc.go was not found by the walk")
	}
}
