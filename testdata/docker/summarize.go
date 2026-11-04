// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Command summarize validates a go test -json stream and prints its output
// and test counts. Invalid or incomplete streams, failed packages, no selected
// tests, unexpected skips and missing required passes all return a failure.
// The caller must also check the producer's exit status with pipefail.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

type event struct {
	Action      string  `json:"Action"`
	Package     string  `json:"Package"`
	Test        string  `json:"Test"`
	Output      string  `json:"Output"`
	ImportPath  string  `json:"ImportPath"`
	FailedBuild string  `json:"FailedBuild"`
	Elapsed     float64 `json:"Elapsed"`
}

type key struct{ pkg, test string }

var markerRE = regexp.MustCompile(`^(=== RUN|=== PAUSE|=== CONT|=== NAME|--- PASS:|--- FAIL:|--- SKIP:|--- BENCH:)`)

type requiredTests []string

func (r *requiredTests) String() string { return strings.Join(*r, ", ") }
func (r *requiredTests) Set(s string) error {
	if len(strings.Fields(s)) != 2 {
		return fmt.Errorf("require needs package and test: %q", s)
	}
	*r = append(*r, s)
	return nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr)) }

func run(args []string, input io.Reader, output, stderr io.Writer) int {
	flags := flag.NewFlagSet("summarize", flag.ContinueOnError)
	flags.SetOutput(stderr)
	allowPath := flags.String("allow-skips", "", "file of allowed skips, one 'package test' per line")
	minTests := flags.Int("min-tests", 1, "minimum number of selected test runs")
	var required requiredTests
	flags.Var(&required, "require", "require a passing 'package test' (repeatable)")
	if err := flags.Parse(args); err != nil {
		return 1
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "summarize: unexpected arguments")
		return 1
	}
	if *minTests <= 0 {
		_, _ = fmt.Fprintln(stderr, "summarize: min-tests must be positive")
		return 1
	}
	allowed, err := readAllowlist(*allowPath)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "summarize: allowlist: %v\n", err)
		return 1
	}
	if err := summarize(input, output, allowed, required, *minTests); err != nil {
		_, _ = fmt.Fprintf(stderr, "summarize: %v\n", err)
		return 1
	}
	return 0
}

func readAllowlist(path string) (map[key]bool, error) {
	allowed := map[key]bool{}
	if path == "" {
		return allowed, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		s := strings.TrimSpace(sc.Text())
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		fields := strings.Fields(s)
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: need package and test", n)
		}
		k := key{fields[0], fields[1]}
		if allowed[k] {
			return nil, fmt.Errorf("line %d: duplicate %s %s", n, k.pkg, k.test)
		}
		allowed[k] = true
	}
	return allowed, sc.Err()
}

func summarize(input io.Reader, output io.Writer, allowed map[key]bool, required []string, minTests int) error {
	sc := bufio.NewScanner(input)
	sc.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	// bufio.Writer retains write errors; Flush below checks every buffered
	// diagnostic as well as the final summary.
	out := bufio.NewWriter(output)
	buffered := map[key][]string{}
	active := map[key]bool{}
	paused := map[key]bool{}
	packages := map[string]bool{}
	passed := map[key]int{}
	var passN, failN, skipN, runN int
	var skips, problems []string
	for n := 1; sc.Scan(); n++ {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		var e event
		if err := json.Unmarshal(line, &e); err != nil {
			problems = append(problems, fmt.Sprintf("line %d: invalid JSON: %v", n, err))
			continue
		}
		switch e.Action {
		case "build-output", "build-fail":
			if e.ImportPath == "" && e.Package == "" && e.FailedBuild == "" {
				problems = append(problems, "build event missing package")
			}
		case "start", "run", "pause", "cont", "output", "pass", "fail", "skip", "bench":
			if e.Package == "" {
				problems = append(problems, "event missing package")
				continue
			}
		default:
			problems = append(problems, fmt.Sprintf("line %d: unknown action %q", n, e.Action))
			continue
		}
		k := key{e.Package, e.Test}
		if e.Output != "" {
			_, _ = fmt.Fprint(out, e.Output)
			if e.Test != "" {
				buffered[k] = append(buffered[k], e.Output)
			}
		}
		switch e.Action {
		case "start":
			if e.Test != "" || packages[e.Package] {
				problems = append(problems, "invalid package start: "+e.Package)
			}
			packages[e.Package] = true
		case "run":
			if e.Test == "" || active[k] || !packages[e.Package] {
				problems = append(problems, "invalid test run: "+e.Package+" "+e.Test)
			}
			active[k] = true
			runN++
			delete(buffered, k)
		case "pause", "cont":
			if e.Test == "" || !packages[e.Package] || !active[k] || (e.Action == "pause" && paused[k]) || (e.Action == "cont" && !paused[k]) {
				problems = append(problems, "invalid test "+e.Action+": "+e.Package+" "+e.Test)
			}
			paused[k] = e.Action == "pause"
		case "pass", "fail", "skip", "bench":
			if e.Action == "bench" && e.Test == "" {
				problems = append(problems, "benchmark result missing test: "+e.Package)
				continue
			}
			if e.Test == "" {
				for test := range active {
					if test.pkg == e.Package {
						problems = append(problems, "package ended with active tests: "+e.Package)
						break
					}
				}
				if !packages[e.Package] {
					problems = append(problems, "package result without start: "+e.Package)
				}
				delete(packages, e.Package)
				if e.Action == "fail" {
					problems = append(problems, "package failed: "+e.Package)
				}
				continue
			}
			if !packages[e.Package] {
				problems = append(problems, "test result outside active package: "+e.Package+" "+e.Test)
			}
			if !active[k] {
				problems = append(problems, "test result without run: "+e.Package+" "+e.Test)
			}
			delete(active, k)
			delete(paused, k)
			switch e.Action {
			case "pass", "bench":
				// Successful benchmark log events terminate like passing tests (cmd/test2json).
				passN++
				passed[k]++
			case "fail":
				failN++
				problems = append(problems, "test failed: "+e.Package+" "+e.Test)
			case "skip":
				skipN++
				skips = append(skips, fmt.Sprintf("%s %s: %s", e.Package, e.Test, extractReason(buffered[k])))
				if !allowed[k] {
					problems = append(problems, "unexpected skip: "+e.Package+" "+e.Test)
				}
			}
		case "build-fail":
			problems = append(problems, "build failed: "+e.ImportPath+e.FailedBuild)
		}
	}
	if err := sc.Err(); err != nil {
		problems = append(problems, fmt.Sprintf("error reading test output: %v", err))
	}
	if runN == 0 {
		problems = append(problems, "no tests selected")
	} else if runN < minTests {
		problems = append(problems, fmt.Sprintf("selected %d tests; need at least %d", runN, minTests))
	}
	for k := range active {
		problems = append(problems, "unfinished test: "+k.pkg+" "+k.test)
	}
	for p := range packages {
		problems = append(problems, "unfinished package: "+p)
	}
	for _, s := range required {
		f := strings.Fields(s)
		if passed[key{f[0], f[1]}] == 0 {
			problems = append(problems, "required test did not pass: "+s)
		}
	}
	_, _ = fmt.Fprintf(out, "\nSUMMARY: PASS=%d FAIL=%d SKIP=%d\n", passN, failN, skipN)
	if len(skips) > 0 {
		_, _ = fmt.Fprintln(out, "SKIP list:")
		for _, s := range skips {
			_, _ = fmt.Fprintln(out, "  "+s)
		}
	}
	for _, p := range problems {
		_, _ = fmt.Fprintln(out, "ERROR: "+p)
	}
	if err := out.Flush(); err != nil {
		return fmt.Errorf("writing summary: %w", err)
	}
	if len(problems) > 0 {
		return fmt.Errorf("%d validation errors", len(problems))
	}
	return nil
}

func extractReason(lines []string) string {
	var parts []string
	for _, block := range lines {
		for _, l := range strings.Split(block, "\n") {
			t := strings.TrimSpace(l)
			if t != "" && !markerRE.MatchString(t) {
				parts = append(parts, t)
			}
		}
	}
	if len(parts) == 0 {
		return "(no message)"
	}
	return strings.Join(parts, " / ")
}
