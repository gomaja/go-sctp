// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Re-execute the test binary so exit codes and flag handling are exercised too.
func TestSummarizerProcess(t *testing.T) {
	if os.Getenv("SUMMARIZER_PROCESS") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{os.Args[0]}, os.Args[i+1:]...)
			break
		}
	}
	main()
	os.Exit(0)
}

func stream(events ...event) string {
	var b strings.Builder
	for _, e := range events {
		p, _ := json.Marshal(e)
		b.Write(p)
		b.WriteByte('\n')
	}
	return b.String()
}

func TestSummarizer(t *testing.T) {
	const pkg = "example.org/p"
	start := event{Action: "start", Package: pkg}
	run := event{Action: "run", Package: pkg, Test: "TestOne"}
	pass := event{Action: "pass", Package: pkg, Test: "TestOne"}
	end := event{Action: "pass", Package: pkg}
	good := stream(start, run, pass, end)
	skipped := stream(start, run, event{Action: "output", Package: pkg, Test: "TestOne", Output: "    x_test.go:3: feature disabled\n"}, event{Action: "skip", Package: pkg, Test: "TestOne"}, end)
	tests := []struct {
		name, input, allow string
		args               []string
		want               string
		fail               bool
	}{
		{name: "pass", input: good, want: "SUMMARY: PASS=1 FAIL=0 SKIP=0"},
		{name: "empty", want: "no tests", fail: true},
		{name: "zero selected", input: stream(start, end), want: "no tests", fail: true},
		{name: "malformed", input: good + "garbage\n", want: "invalid JSON", fail: true},
		{name: "truncated JSON", input: good + "{", want: "invalid JSON", fail: true},
		{name: "unknown action", input: good + stream(event{Action: "mystery", Package: pkg}), want: "unknown action", fail: true},
		{name: "empty object", input: good + "{}\n", want: "unknown action", fail: true},
		{name: "missing package", input: stream(event{Action: "start"}) + good, want: "package", fail: true},
		{name: "test failure", input: stream(start, run, event{Action: "fail", Package: pkg, Test: "TestOne"}, event{Action: "fail", Package: pkg}), want: "FAIL=1", fail: true},
		{name: "package failure", input: stream(start, run, pass, event{Action: "fail", Package: pkg}), want: "package failed", fail: true},
		{name: "build failure", input: stream(event{Action: "build-fail", ImportPath: pkg}), want: "build failed", fail: true},
		{name: "unfinished test", input: stream(start, run, end), want: "unfinished test", fail: true},
		{name: "unfinished package", input: stream(start, run, pass), want: "unfinished package", fail: true},
		{name: "result without run", input: stream(start, pass, end), want: "without run", fail: true},
		{name: "duplicate result", input: stream(start, run, pass, pass, end), want: "without run", fail: true},
		{name: "unapproved skip", input: skipped, want: "unexpected skip", fail: true},
		{name: "allowed skip", input: skipped, allow: pkg + " TestOne\n", want: "feature disabled"},
		{name: "wrong allowed test", input: skipped, allow: pkg + " TestOther\n", want: "unexpected skip", fail: true},
		{name: "wrong allowed package", input: skipped, allow: "other.org/p TestOne\n", want: "unexpected skip", fail: true},
		{name: "bad allowlist", input: good, allow: "one-field\n", want: "allowlist", fail: true},
		{name: "duplicate allowlist", input: good, allow: pkg + " TestOne\n" + pkg + " TestOne\n", want: "duplicate", fail: true},
		{name: "required passes", input: good, args: []string{"-require", pkg + " TestOne"}, want: "PASS=1"},
		{name: "required missing", input: good, args: []string{"-require", pkg + " TestMissing"}, want: "required test", fail: true},
		{name: "required skip", input: skipped, allow: pkg + " TestOne\n", args: []string{"-require", pkg + " TestOne"}, want: "required test", fail: true},
		{name: "required malformed", input: good, args: []string{"-require", "TestOne"}, want: "package and test", fail: true},
		{name: "bad flag", input: good, args: []string{"-unknown"}, want: "flag provided", fail: true},
		{name: "positional argument", input: good, args: []string{"garbage"}, want: "arguments", fail: true},
		{name: "long line", input: good + strings.Repeat("x", 10*1024*1024+1), want: "reading", fail: true},
		{name: "subtest skip", input: stream(start, run, event{Action: "run", Package: pkg, Test: "TestOne/sub"}, event{Action: "skip", Package: pkg, Test: "TestOne/sub"}, pass, end), want: "unexpected skip", fail: true},
		{name: "repeated test", input: stream(start, run, pass, run, pass, end), want: "PASS=2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := []string{"-test.run=^TestSummarizerProcess$", "--"}
			if tt.allow != "" {
				path := filepath.Join(t.TempDir(), "skips")
				if err := os.WriteFile(path, []byte(tt.allow), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-allow-skips", path)
			}
			args = append(args, tt.args...)
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, args...)
			cmd.Env = append(os.Environ(), "SUMMARIZER_PROCESS=1")
			cmd.Stdin = strings.NewReader(tt.input)
			out, err := cmd.CombinedOutput()
			if (err != nil) != tt.fail {
				t.Fatalf("exit=%v; want failure=%t; output:\n%s", err, tt.fail, out)
			}
			if !strings.Contains(string(out), tt.want) {
				t.Fatalf("missing %q in:\n%s", tt.want, out)
			}
		})
	}
}
