// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

var (
	panicRE    = regexp.MustCompile(`Kernel panic|Oops:|BUG:|panic:`)
	startedRE  = regexp.MustCompile(`(?m)^=== RUN   (Test|Fuzz)`)
	passedRE   = regexp.MustCompile(`(?m)^\s*--- PASS:`)
	failedRE   = regexp.MustCompile(`(?m)^\s*--- FAIL:`)
	completeRE = regexp.MustCompile(`(?m)^PASS$`)
)

var guestPackages = []struct{ path, marker, logName string }{
	{"github.com/gomaja/go-sctp", "TEST", "tests"},
	{"github.com/gomaja/go-sctp/example", "EXAMPLE", "example"},
}

// validate checks the guest's console evidence before accepting a test result.
func validate(log, nonce string, states []string, metadata, binaryHash, exampleHash, kernel string) (map[string]string, error) {
	prefix := "SCTP-GUEST-" + nonce + " "
	lines := strings.Split(log, "\n")
	require := func(proof string) error {
		count := 0
		for _, line := range lines {
			if line == prefix+proof {
				count++
			}
		}
		if count != 1 {
			return fmt.Errorf("missing, duplicate or incorrect guest proof: %s", proof)
		}
		field, _, _ := strings.Cut(proof, "=")
		marker := ""
		switch field {
		case "ARCH", "ORDER", "UID", "KERNEL", "BINARY", "EXAMPLE-BINARY", "EXIT":
			marker = prefix + field + "="
		case "TEST-END", "EXAMPLE-END":
			base, _, _ := strings.Cut(proof, " STATUS=")
			marker = prefix + base + " STATUS="
		}
		if marker != "" {
			count = 0
			for _, line := range lines {
				if strings.HasPrefix(line, marker) {
					count++
				}
			}
			if count != 1 {
				return fmt.Errorf("conflicting guest proof: %s", field)
			}
		}
		return nil
	}
	if panicRE.MatchString(log) {
		return nil, fmt.Errorf("kernel panic, oops, BUG or test panic in console")
	}
	for _, proof := range []string{"BOOT", "ARCH=s390x", "ORDER=258", "UID=0", "KERNEL=" + kernel, "BINARY=" + binaryHash, "EXAMPLE-BINARY=" + exampleHash, "METADATA-BEGIN", "METADATA-END", "EXIT=0"} {
		if err := require(proof); err != nil {
			return nil, err
		}
	}
	if !strings.Contains(log, prefix+"METADATA-BEGIN\n"+metadata+prefix+"METADATA-END\n") {
		return nil, fmt.Errorf("guest source revision/build metadata differs from host")
	}
	var recorded []string
	for _, line := range lines {
		if value, ok := strings.CutPrefix(line, prefix+"SCTP="); ok {
			recorded = append(recorded, value)
		}
	}
	if len(states) == 0 || !slices.Equal(recorded, states) {
		return nil, fmt.Errorf("missing, duplicate or unrequested sysctl state")
	}
	for _, pkg := range guestPackages {
		var begun, ended []string
		for _, line := range lines {
			if value, ok := strings.CutPrefix(line, prefix+pkg.marker+"-BEGIN="); ok {
				begun = append(begun, value)
			}
			if value, ok := strings.CutPrefix(line, prefix+pkg.marker+"-END="); ok {
				state, _, _ := strings.Cut(value, " STATUS=")
				ended = append(ended, state)
			}
		}
		if !slices.Equal(begun, states) || !slices.Equal(ended, states) {
			return nil, fmt.Errorf("missing, duplicate or unrequested suite for %s", pkg.path)
		}
	}
	suites := make(map[string]string, len(states)*len(guestPackages))
	lastEnd := 0
	for _, state := range states {
		if state != "0" && state != "1" {
			return nil, fmt.Errorf("invalid sysctl state %q", state)
		}
		if err := require("SCTP=" + state); err != nil {
			return nil, err
		}
		for _, pkg := range guestPackages {
			for _, proof := range []string{pkg.marker + "-BEGIN=" + state, pkg.marker + "-END=" + state + " STATUS=0"} {
				if err := require(proof); err != nil {
					return nil, err
				}
			}
			begin := prefix + pkg.marker + "-BEGIN=" + state + "\n"
			end := prefix + pkg.marker + "-END=" + state + " STATUS=0\n"
			start := strings.Index(log, begin)
			stop := strings.Index(log, end)
			if start < lastEnd || stop < start+len(begin) {
				return nil, fmt.Errorf("incorrect suite marker order for %s in sysctl state %s", pkg.path, state)
			}
			lastEnd = stop + len(end)
			// test2json's record separator is preserved by the serial console.
			suite := strings.ReplaceAll(log[start+len(begin):stop], "\x16", "")
			if !startedRE.MatchString(suite) {
				return nil, fmt.Errorf("no tests started for %s in sysctl state %s", pkg.path, state)
			}
			if !passedRE.MatchString(suite) {
				return nil, fmt.Errorf("zero passing tests for %s in sysctl state %s", pkg.path, state)
			}
			if failedRE.MatchString(suite) || !completeRE.MatchString(suite) {
				return nil, fmt.Errorf("incomplete or failed suite for %s in sysctl state %s", pkg.path, state)
			}
			if pkg.marker == "TEST" {
				for _, name := range []string{"TestCrossCompileSmoke", "TestExportedAPI"} {
					if strings.Contains(suite, "=== RUN   "+name) {
						return nil, fmt.Errorf("%s was not explicitly excluded", name)
					}
				}
			}
			suites[pkg.logName+"-"+state] = suite
		}
	}
	return suites, nil
}
