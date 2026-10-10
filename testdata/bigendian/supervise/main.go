// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Command supervise bounds the guest run and checks its console evidence.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type supervisor struct {
	work, image, container, goTool, platform, docker    string
	bootTimeout, runTimeout, removeTimeout, stopTimeout time.Duration
	summaryTimeout                                      time.Duration
	out                                                 io.Writer
	signals                                             chan os.Signal
}

func main() {
	if err := command(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "big-endian kernel suite:", err)
		os.Exit(1)
	}
}

func command(args []string) error {
	if len(args) >= 2 && args[0] == "hash" {
		sum, err := hashFiles(args[1:])
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(os.Stdout, sum)
		return err
	}
	if len(args) != 6 || args[0] != "run" {
		return fmt.Errorf("usage: supervise hash FILE... | supervise run WORK IMAGE CONTAINER GO PLATFORM")
	}
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	return (supervisor{work: args[1], image: args[2], container: args[3], goTool: args[4], platform: args[5], docker: "docker", bootTimeout: 180 * time.Second, runTimeout: 1800 * time.Second, removeTimeout: 15 * time.Second, stopTimeout: 10 * time.Second, summaryTimeout: 15 * time.Second, out: os.Stdout, signals: signals}).run()
}

// hashFiles hashes the concatenated bytes, in argument order, without buffering
// a test binary or environment archive in memory.
func hashFiles(paths []string) (string, error) {
	h := sha256.New()
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		_, copyErr := io.Copy(h, f)
		closeErr := f.Close()
		if copyErr != nil {
			return "", copyErr
		}
		if closeErr != nil {
			return "", closeErr
		}
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// capture retains the console as it arrives and reports the first boot marker.
// os/exec serializes writes when stdout and stderr share this writer; the mutex
// also protects reads during timeout and signal teardown.
type capture struct {
	mu     sync.Mutex
	log    bytes.Buffer
	file   *os.File
	prefix string
	boot   chan struct{}
	booted bool
}

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n, err := c.file.Write(p)
	_, _ = c.log.Write(p[:n])
	if !c.booted && strings.Contains(strings.ReplaceAll(c.log.String(), "\r", ""), c.prefix+"BOOT\n") {
		c.booted = true
		close(c.boot)
	}
	return n, err
}

func (c *capture) text() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return strings.ReplaceAll(strings.ToValidUTF8(c.log.String(), "\uFFFD"), "\r", "")
}

func (s supervisor) run() (result error) {
	nonce, err := os.ReadFile(filepath.Join(s.work, "nonce"))
	if err != nil {
		return err
	}
	stateData, err := os.ReadFile(filepath.Join(s.work, "states"))
	if err != nil {
		return err
	}
	states := strings.Fields(string(stateData))
	prefix := "SCTP-GUEST-" + strings.TrimSpace(string(nonce)) + " "
	console, err := os.Create(filepath.Join(s.work, "console.log"))
	if err != nil {
		return err
	}
	captured := &capture{file: console, prefix: prefix, boot: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	process := exec.CommandContext(ctx, s.docker, "run", "--rm", "--platform", s.platform, "--name", s.container, "--label", "harness="+s.container, "-v", s.work+":/work:ro", s.image, "1800")
	process.Stdout = captured
	process.Stderr = captured
	process.WaitDelay = s.stopTimeout
	process.Cancel = func() error { return process.Process.Signal(syscall.SIGTERM) }
	started := time.Now()
	done := make(chan error, 1)
	running := false
	cleaned := false
	cleanup := func() {
		if cleaned {
			return
		}
		cleaned = true
		// Signals stay subscribed while teardown runs, so a second cancellation
		// cannot interrupt removal or process reaping halfway through.
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), s.removeTimeout)
		remove := exec.CommandContext(cleanupCtx, s.docker, "rm", "-f", s.container)
		remove.WaitDelay = s.stopTimeout
		_ = remove.Run()
		cleanupCancel()
		cancel()
		if running {
			<-done
			running = false
		}
	}
	defer func() {
		cleanup()
		if result != nil {
			lines := strings.Split(strings.TrimSuffix(captured.text(), "\n"), "\n")
			if len(lines) > 200 {
				lines = lines[len(lines)-200:]
			}
			_, _ = fmt.Fprintln(s.out, "== last console lines ==")
			_, _ = fmt.Fprintln(s.out, strings.Join(lines, "\n"))
		}
		if err := console.Close(); result == nil && err != nil {
			result = err
		}
	}()
	if err := process.Start(); err != nil {
		return err
	}
	running = true
	go func() { done <- process.Wait() }()
	bootTimer := time.NewTimer(s.bootTimeout)
	defer bootTimer.Stop()
	runTimer := time.NewTimer(s.runTimeout)
	defer runTimer.Stop()
	boot := captured.boot
	var processErr, problem error
wait:
	for {
		select {
		case <-boot:
			boot = nil
			bootTimer.Stop()
		case <-bootTimer.C:
			problem = fmt.Errorf("guest boot timeout")
			break wait
		case <-runTimer.C:
			problem = fmt.Errorf("guest run timeout")
			break wait
		case sig := <-s.signals:
			problem = fmt.Errorf("interrupted by signal %s", sig)
			break wait
		case processErr = <-done:
			running = false
			break wait
		}
	}
	if problem != nil {
		cleanup()
	}
	text := captured.text()
	if problem == nil {
		problem = s.check(text, strings.TrimSpace(string(nonce)), states)
	}
	if problem == nil && processErr != nil {
		problem = fmt.Errorf("emulator/container exit: %w", processErr)
	}
	deadline := started.Add(s.runTimeout)
	if problem != nil {
		cleanup()
		// All packages and states share one short post-failure budget;
		// diagnostics must not keep a canceled guest alive or renew the deadline.
		budget := s.summaryTimeout
		if budget <= 0 {
			budget = 15 * time.Second
		}
		deadline = time.Now().Add(budget)
	}
	// Show the guest proof and emulator version even when validation fails.
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, prefix) || strings.HasPrefix(line, "QEMU emulator version") {
			if _, err := fmt.Fprintln(s.out, line); err != nil {
				return err
			}
		}
	}
	// Summarize complete and failed suites alike before returning an error.
	for _, state := range states {
		for _, pkg := range guestPackages {
			begin := prefix + pkg.marker + "-BEGIN=" + state + "\n"
			_, suite, ok := strings.Cut(text, begin)
			if !ok {
				continue
			}
			suite, _, _ = strings.Cut(suite, prefix)
			if err := os.WriteFile(filepath.Join(s.work, pkg.logName+"-"+state+".log"), []byte(suite), 0600); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(s.out, "== %s; sysctl %s %s ==\n", pkg.path, state, state); err != nil {
				return err
			}
			events, err := s.execute(deadline, suite, "tool", "test2json", "-p", pkg.path)
			if err != nil {
				if problem != nil {
					return problem
				}
				return err
			}
			if err := os.WriteFile(filepath.Join(s.work, pkg.logName+"-"+state+".json"), events, 0600); err != nil {
				return err
			}
			summary, err := s.execute(deadline, string(events), "run", "testdata/docker/summarize.go")
			if _, writeErr := s.out.Write(summary); writeErr != nil {
				return writeErr
			}
			if err != nil {
				if problem != nil {
					return problem
				}
				return err
			}
		}
	}
	if problem != nil {
		return problem
	}
	_, err = fmt.Fprintf(s.out, "big-endian kernel suite: PASS; elapsed %.1fs\n", time.Since(started).Seconds())
	return err
}

// check compares the guest's proof to the host artifacts before choosing the
// summary deadline. Completed output is summarized even when proof fails.
func (s supervisor) check(text, nonce string, states []string) error {
	metadata, err := os.ReadFile(filepath.Join(s.work, "metadata"))
	if err != nil {
		return err
	}
	binaryHash, err := hashFiles([]string{filepath.Join(s.work, "sctp.test")})
	if err != nil {
		return err
	}
	exampleHash, err := hashFiles([]string{filepath.Join(s.work, "example.test")})
	if err != nil {
		return err
	}
	kernel, err := os.ReadFile(filepath.Join(s.work, "kernel-release"))
	if err != nil {
		return err
	}
	_, err = validate(text, nonce, states, string(metadata), binaryHash, exampleHash, strings.TrimSpace(string(kernel)))
	return err
}

// execute shares the caller's absolute deadline across all summary commands
// and responds to signals while an external command is running.
func (s supervisor) execute(deadline time.Time, input string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("guest summary timeout: %w", err)
	}
	cmd := exec.CommandContext(ctx, s.goTool, args...)
	cmd.WaitDelay = s.stopTimeout
	cmd.Stdin = strings.NewReader(input)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = s.out
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if ctx.Err() != nil {
			return output.Bytes(), fmt.Errorf("guest summary timeout: %w", ctx.Err())
		}
		return output.Bytes(), err
	case sig := <-s.signals:
		cancel()
		<-done
		return output.Bytes(), fmt.Errorf("interrupted by signal %s", sig)
	}
}
