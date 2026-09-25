// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Command summarize reads a "go test -json" event stream from stdin,
// echoes it back as the same human-readable text "go test -v" would have
// produced, and then prints a summary derived from the JSON actions rather
// than from scanning that text: PASS/FAIL/SKIP counts that include
// subtests (subtest lines are indented in the text form and would be
// missed by a prefix match on "--- PASS"/"--- FAIL"/"--- SKIP"), every
// skipped test with its skip message, and, since a build failure or a
// panic can end the run without producing a single test-level PASS/FAIL,
// any build failure and any "panic:" line found in the stream. It does
// not read or report the process exit status; the caller prints that
// itself once the "go test" command it piped from has actually exited.
//
// This program is a build/test helper, not part of the module's own
// package: it lives under testdata/, which "go build ./..." and friends
// skip by convention, and only imports the standard library.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// event mirrors the subset of the go test -json TestEvent fields this
// program uses. Fields absent from a given line (for example ImportPath,
// which only build-output/build-fail events carry) decode to their zero
// value and are simply not consulted for that event.
type event struct {
	Action      string  `json:"Action"`
	Package     string  `json:"Package"`
	Test        string  `json:"Test"`
	Output      string  `json:"Output"`
	ImportPath  string  `json:"ImportPath"`
	FailedBuild string  `json:"FailedBuild"`
	Elapsed     float64 `json:"Elapsed"`
}

// markerRE matches the verbose-mode lines go test prints around a test's
// own output ("=== RUN", "--- PASS: ...", and so on), so extractReason can
// tell them apart from the test's own logged skip message.
var markerRE = regexp.MustCompile(`^(=== RUN|=== PAUSE|=== CONT|=== NAME|--- PASS:|--- FAIL:|--- SKIP:|--- BENCH:)`)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	// A single Output field can carry a long line (a large diff, a hex
	// dump); the default 64KiB scanner buffer is not enough headroom.
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)

	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	type key struct{ pkg, test string }
	buffered := map[key][]string{}

	var passN, failN, skipN int
	var skips []string
	var failLines []string
	var buildFailures []string
	var panicLines []string

	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		var e event
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			// Not a JSON line. This should not happen with "go test
			// -json", but keep the line visible rather than dropping it.
			fmt.Fprintln(out, line)
			continue
		}

		if e.Output != "" {
			fmt.Fprint(out, e.Output)
			if e.Test != "" {
				k := key{e.Package, e.Test}
				buffered[k] = append(buffered[k], e.Output)
			}
			for _, l := range strings.Split(e.Output, "\n") {
				trimmed := strings.TrimSpace(l)
				if e.Test == "" && strings.HasPrefix(trimmed, "FAIL\t") {
					failLines = append(failLines, trimmed)
				}
				if strings.HasPrefix(trimmed, "panic:") {
					panicLines = append(panicLines, trimmed)
				}
			}
		}

		switch e.Action {
		case "pass":
			if e.Test != "" {
				passN++
			}
		case "fail":
			if e.Test != "" {
				failN++
			}
		case "skip":
			if e.Test != "" {
				skipN++
				k := key{e.Package, e.Test}
				skips = append(skips, fmt.Sprintf("%s %s: %s", e.Package, e.Test, extractReason(buffered[k])))
			}
		case "build-fail":
			ip := e.ImportPath
			if ip == "" {
				ip = e.FailedBuild
			}
			buildFailures = append(buildFailures, ip)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintf(out, "\n(summarize: error reading test output: %v)\n", err)
	}

	fmt.Fprintln(out)
	fmt.Fprintf(out, "SUMMARY: PASS=%d FAIL=%d SKIP=%d\n", passN, failN, skipN)
	if len(skips) > 0 {
		fmt.Fprintln(out, "SKIP list:")
		for _, s := range skips {
			fmt.Fprintln(out, "  "+s)
		}
	}
	if len(buildFailures) > 0 {
		fmt.Fprintln(out, "BUILD FAILURES:")
		for _, b := range buildFailures {
			fmt.Fprintln(out, "  "+b)
		}
	}
	if len(failLines) > 0 {
		fmt.Fprintln(out, "FAIL lines:")
		for _, f := range failLines {
			fmt.Fprintln(out, "  "+f)
		}
	}
	if len(panicLines) > 0 {
		fmt.Fprintln(out, "PANIC lines:")
		for _, p := range panicLines {
			fmt.Fprintln(out, "  "+p)
		}
	}
}

// extractReason turns the buffered Output lines logged against one test
// into its skip reason: everything except the verbose-mode marker lines,
// which carry no information beyond "this test ran" / "this test skipped".
func extractReason(lines []string) string {
	var parts []string
	for _, block := range lines {
		for _, l := range strings.Split(block, "\n") {
			t := strings.TrimSpace(l)
			if t == "" || markerRE.MatchString(t) {
				continue
			}
			parts = append(parts, t)
		}
	}
	if len(parts) == 0 {
		return "(no message)"
	}
	return strings.Join(parts, " / ")
}
