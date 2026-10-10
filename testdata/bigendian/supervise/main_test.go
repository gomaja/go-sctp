// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHashFiles(t *testing.T) {
	dir := t.TempDir()
	var paths []string
	for i, data := range []string{"a", "", "bc"} {
		path := filepath.Join(dir, fmt.Sprint(i))
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	got, err := hashFiles(paths)
	if err != nil {
		t.Fatal(err)
	}
	if want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; got != want {
		t.Fatalf("hash = %s, want %s", got, want)
	}
	if _, err := hashFiles(append(paths, filepath.Join(dir, "missing"))); err == nil {
		t.Fatal("accepted unreadable file")
	}
}

func supervisorFixture(t *testing.T, log, mode string) (supervisor, *bytes.Buffer) {
	t.Helper()
	t.Chdir("../../..")
	work := t.TempDir()
	log = strings.ReplaceAll(log, "BINARY=def", "BINARY=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	log = strings.ReplaceAll(log, "EXAMPLE-BINARY=ghi", "EXAMPLE-BINARY=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	files := map[string]string{"nonce": "abc\n", "states": "1 0\n", "metadata": proofMetadata, "sctp.test": "", "example.test": "abc", "kernel-release": "6.12.test\n", "fixture": log}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(work, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	docker := filepath.Join(work, "docker")
	script := "#!/bin/sh\ncase \"$1\" in\nrm) printf '%s\\n' \"$@\" > \"" + filepath.Join(work, "removed") + "\"; exit 0;;\nrun) cat \"" + filepath.Join(work, "fixture") + "\"; touch \"" + filepath.Join(work, "ready") + "\"; " + mode + ";;\nesac\n"
	if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	cfg := supervisor{work: work, image: "image", container: "test-container", goTool: goTool, platform: "linux/arm64", docker: docker, bootTimeout: 5 * time.Second, runTimeout: 10 * time.Second, removeTimeout: time.Second, stopTimeout: 100 * time.Millisecond, out: out, signals: make(chan os.Signal, 2)}
	return cfg, out
}

func assertRemoved(t *testing.T, cfg supervisor) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(cfg.work, "removed"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "rm\n-f\ntest-container\n" {
		t.Fatalf("cleanup arguments = %q", got)
	}
}

func TestSupervisorBothStateSummaries(t *testing.T) {
	cfg, out := supervisorFixture(t, consoleFixture("1", "0"), "exit 0")
	if err := cfg.run(); err != nil {
		t.Fatal(err)
	}
	assertRemoved(t, cfg)
	for _, state := range []string{"1", "0"} {
		for _, pkg := range []struct{ name, path string }{{"tests", "github.com/gomaja/go-sctp"}, {"example", "github.com/gomaja/go-sctp/example"}} {
			for _, ext := range []string{"log", "json"} {
				data, err := os.ReadFile(filepath.Join(cfg.work, pkg.name+"-"+state+"."+ext))
				if err != nil || len(data) == 0 {
					t.Fatalf("%s state %s %s: data=%q err=%v", pkg.name, state, ext, data, err)
				}
				if ext == "json" && !strings.Contains(string(data), `"Package":"`+pkg.path+`"`) {
					t.Fatalf("wrong package in events: %s", data)
				}
			}
		}
	}
	if strings.Count(out.String(), "SUMMARY: PASS=1 FAIL=0 SKIP=0") != 4 {
		t.Fatalf("missing summaries: %s", out)
	}
	if !strings.Contains(out.String(), "big-endian kernel suite: PASS;") {
		t.Fatalf("missing success: %s", out)
	}
}

func TestSupervisorRejectsExampleSuite(t *testing.T) {
	for _, tc := range []struct{ name, old, replacement string }{
		{"missing", exampleFixture("0"), ""},
		{"failed", "--- PASS: TestExampleSocket (0.01s)", "--- FAIL: TestExampleSocket (0.01s)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			log := strings.Replace(consoleFixture("1", "0"), tc.old, tc.replacement, 1)
			cfg, out := supervisorFixture(t, log, "exit 0")
			if err := cfg.run(); err == nil {
				t.Fatal("accepted missing or failed example suite")
			}
			assertRemoved(t, cfg)
			if !strings.Contains(out.String(), "SUMMARY: PASS=1 FAIL=0 SKIP=0") {
				t.Fatalf("root summary not printed: %s", out)
			}
			if tc.name == "failed" && !strings.Contains(out.String(), "SUMMARY: PASS=0 FAIL=1 SKIP=0") {
				t.Fatalf("failed example summary not printed: %s", out)
			}
		})
	}
}

func TestSupervisorRejectsExampleBinary(t *testing.T) {
	for _, mode := range []string{"missing", "incorrect"} {
		t.Run(mode, func(t *testing.T) {
			cfg, _ := supervisorFixture(t, consoleFixture("1", "0"), "exit 0")
			path := filepath.Join(cfg.work, "example.test")
			var err error
			if mode == "missing" {
				err = os.Remove(path)
			} else {
				err = os.WriteFile(path, []byte("wrong binary"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := cfg.run(); err == nil {
				t.Fatal("accepted missing or incorrect example binary")
			}
			assertRemoved(t, cfg)
		})
	}
}

func TestSupervisorTimeouts(t *testing.T) {
	for _, tc := range []struct{ name, log, want string }{{"boot", "booting\n", "guest boot timeout"}, {"run", proofPrefix + "BOOT\n", "guest run timeout"}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, out := supervisorFixture(t, tc.log, "trap '' TERM; exec sleep 30")
			cfg.bootTimeout = 300 * time.Millisecond
			cfg.runTimeout = 400 * time.Millisecond
			if tc.name == "boot" {
				cfg.bootTimeout = 100 * time.Millisecond
			}
			start := time.Now()
			err := cfg.run()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run error = %v, want %s", err, tc.want)
			}
			if time.Since(start) > 3*time.Second {
				t.Fatal("unbounded process teardown")
			}
			assertRemoved(t, cfg)
			if !strings.Contains(out.String(), "== last console lines ==") {
				t.Fatalf("missing failure tail: %s", out)
			}
		})
	}
}

func TestSupervisorSignals(t *testing.T) {
	for _, sig := range []os.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			cfg, _ := supervisorFixture(t, proofPrefix+"BOOT\n", "exec sleep 30")
			ready := make(chan struct{})
			go func() {
				defer close(ready)
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				timeout := time.NewTimer(3 * time.Second)
				defer timeout.Stop()
				for {
					if _, err := os.Stat(filepath.Join(cfg.work, "ready")); err == nil {
						cfg.signals <- sig
						return
					}
					select {
					case <-ticker.C:
					case <-timeout.C:
						return
					}
				}
			}()
			err := cfg.run()
			<-ready
			if err == nil || !strings.Contains(err.Error(), "interrupted by signal") {
				t.Fatalf("signal error = %v", err)
			}
			assertRemoved(t, cfg)
		})
	}
}

func TestSupervisorFailedConsoleTail(t *testing.T) {
	var log strings.Builder
	for i := 0; i < 250; i++ {
		fmt.Fprintf(&log, "line %03d\n", i)
	}
	cfg, out := supervisorFixture(t, log.String(), "exit 7")
	if err := cfg.run(); err == nil {
		t.Fatal("accepted failing container")
	}
	assertRemoved(t, cfg)
	_, tail, ok := strings.Cut(out.String(), "== last console lines ==\n")
	if !ok {
		t.Fatal("missing console tail")
	}
	lines := strings.Split(strings.TrimSuffix(tail, "\n"), "\n")
	if len(lines) != 200 || lines[0] != "line 050" || lines[199] != "line 249" {
		t.Fatalf("tail lines=%d first=%q last=%q", len(lines), lines[0], lines[len(lines)-1])
	}
	retained, err := os.ReadFile(filepath.Join(cfg.work, "console.log"))
	if err != nil || string(retained) != log.String() {
		t.Fatalf("console not retained: %v", err)
	}
}

func TestSupervisorContainerExit(t *testing.T) {
	cfg, out := supervisorFixture(t, consoleFixture("1", "0"), "exit 7")
	err := cfg.run()
	if err == nil || !strings.Contains(err.Error(), "exit status 7") {
		t.Fatalf("container exit = %v", err)
	}
	if strings.Count(out.String(), "SUMMARY: PASS=1 FAIL=0 SKIP=0") != 4 {
		t.Fatalf("missing failure summaries: %s", out)
	}
	assertRemoved(t, cfg)
}

func TestSupervisorBoundedRemoval(t *testing.T) {
	cfg, _ := supervisorFixture(t, "booting\n", "exec sleep 30")
	script, err := os.ReadFile(cfg.docker)
	if err != nil {
		t.Fatal(err)
	}
	script = bytes.Replace(script, []byte("; exit 0;;"), []byte("; trap '' TERM; exec sleep 30;;"), 1)
	if err := os.WriteFile(cfg.docker, script, 0700); err != nil {
		t.Fatal(err)
	}
	cfg.bootTimeout = 100 * time.Millisecond
	cfg.removeTimeout = 100 * time.Millisecond
	start := time.Now()
	if err := cfg.run(); err == nil {
		t.Fatal("accepted boot timeout")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("container removal was not bounded")
	}
	assertRemoved(t, cfg)
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatalf("missing fixture marker %s", path)
		}
	}
}

func TestSupervisorCancellationBeforeBlockedSummary(t *testing.T) {
	cfg, _ := supervisorFixture(t, proofPrefix+"BOOT\n"+proofPrefix+"TEST-BEGIN=1\n=== RUN   TestSocket\n", "exec sleep 30")
	reaped := filepath.Join(cfg.work, "reaped")
	script, err := os.ReadFile(cfg.docker)
	if err != nil {
		t.Fatal(err)
	}
	script = bytes.Replace(script, []byte("touch \""+filepath.Join(cfg.work, "ready")+"\"; exec sleep 30"), []byte("trap ': > \""+reaped+"\"; exit 0' TERM; : > \""+filepath.Join(cfg.work, "ready")+"\"; while :; do sleep 0.01; done"), 1)
	if err := os.WriteFile(cfg.docker, script, 0700); err != nil {
		t.Fatal(err)
	}
	cfg.summaryTimeout = 400 * time.Millisecond
	cfg.stopTimeout = 300 * time.Millisecond
	goTool := filepath.Join(cfg.work, "blocked-go")
	summaryStarted := filepath.Join(cfg.work, "summary-started")
	wrongOrder := filepath.Join(cfg.work, "wrong-order")
	script = []byte("#!/bin/sh\nif [ ! -f \"" + filepath.Join(cfg.work, "removed") + "\" ] || [ ! -f \"" + reaped + "\" ]; then : > \"" + wrongOrder + "\"; fi\n: > \"" + summaryStarted + "\"\nexec sleep 30\n")
	if err := os.WriteFile(goTool, script, 0700); err != nil {
		t.Fatal(err)
	}
	cfg.goTool = goTool
	done := make(chan error, 1)
	go func() { done <- cfg.run() }()
	waitForFile(t, filepath.Join(cfg.work, "ready"))
	started := time.Now()
	cfg.signals <- syscall.SIGTERM
	waitForFile(t, summaryStarted)
	if _, err := os.Stat(wrongOrder); err == nil {
		t.Error("summary started before guest removal and reaping")
	}
	var runErr error
	select {
	case runErr = <-done:
	case <-time.After(1400 * time.Millisecond):
		t.Error("first cancellation left blocked summary running")
		// Bound cleanup even when exercising the unfixed implementation.
		cfg.signals <- syscall.SIGTERM
		select {
		case runErr = <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("fixture teardown did not finish")
		}
	}
	if runErr == nil || !strings.Contains(runErr.Error(), "interrupted by signal") {
		t.Fatalf("cancellation error = %v", runErr)
	}
	if time.Since(started) > 2*time.Second {
		t.Error("post-cancellation summary was not tightly bounded")
	}
	assertRemoved(t, cfg)
}

func TestSupervisorFailureSummariesShareDeadline(t *testing.T) {
	cfg, out := supervisorFixture(t, consoleFixture("1", "0"), "exit 7")
	cfg.summaryTimeout = time.Second
	goTool := filepath.Join(cfg.work, "slow-go")
	calls := filepath.Join(cfg.work, "summary-calls")
	first := filepath.Join(cfg.work, "first-summary")
	script := "#!/bin/sh\nn=0\nif [ -f \"" + calls + "\" ]; then n=$(cat \"" + calls + "\"); fi\nn=$((n+1))\nprintf '%s\\n' \"$n\" > \"" + calls + "\"\ncase $n in\n1) : > \"" + first + "\"; sleep 0.2; printf '{\"Action\":\"pass\"}\\n';;\n2) sleep 0.2; printf 'completed summary\\n';;\n*) exec sleep 30;;\nesac\n"
	if err := os.WriteFile(goTool, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cfg.goTool = goTool
	err := cfg.run()
	if err == nil || !strings.Contains(err.Error(), "exit status 7") {
		t.Fatalf("run error = %v", err)
	}
	firstInfo, statErr := os.Stat(first)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if elapsed := time.Since(firstInfo.ModTime()); elapsed > 1250*time.Millisecond {
		t.Fatalf("summary deadline renewed between commands: %v", elapsed)
	}
	events, err := os.ReadFile(filepath.Join(cfg.work, "tests-1.json"))
	if err != nil || string(events) != "{\"Action\":\"pass\"}\n" {
		t.Fatalf("completed JSON not retained: %q %v", events, err)
	}
	if !strings.Contains(out.String(), "completed summary\n") {
		t.Fatalf("completed summary not printed: %s", out)
	}
	assertRemoved(t, cfg)
}

func TestSupervisorSignalDuringSummary(t *testing.T) {
	cfg, _ := supervisorFixture(t, consoleFixture("1", "0"), "exit 0")
	goTool := filepath.Join(cfg.work, "blocked-go")
	marker := filepath.Join(cfg.work, "summary-started")
	script := "#!/bin/sh\ntouch \"" + marker + "\"\nexec sleep 30\n"
	if err := os.WriteFile(goTool, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cfg.goTool = goTool
	done := make(chan error, 1)
	go func() { done <- cfg.run() }()
	waitForFile(t, marker)
	cfg.signals <- syscall.SIGINT
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "interrupted by signal") {
			t.Fatalf("summary cancellation = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("signal did not bound summary teardown")
	}
	assertRemoved(t, cfg)
}
