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
