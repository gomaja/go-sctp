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

// validate checks the guest's console evidence before accepting a test result.
func validate(log, nonce string, states []string, metadata, binaryHash, kernel string) (map[string]string, error) {
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
		case "ARCH", "ORDER", "UID", "KERNEL", "BINARY", "EXIT":
			marker = prefix + field + "="
		case "TEST-END":
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
	for _, proof := range []string{"BOOT", "ARCH=s390x", "ORDER=258", "UID=0", "KERNEL=" + kernel, "BINARY=" + binaryHash, "METADATA-BEGIN", "METADATA-END", "EXIT=0"} {
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
	suites := make(map[string]string, len(states))
	for _, state := range states {
		if state != "0" && state != "1" {
			return nil, fmt.Errorf("invalid sysctl state %q", state)
		}
		for _, proof := range []string{"SCTP=" + state, "TEST-BEGIN=" + state, "TEST-END=" + state + " STATUS=0"} {
			if err := require(proof); err != nil {
				return nil, err
			}
		}
		begin := prefix + "TEST-BEGIN=" + state + "\n"
		end := prefix + "TEST-END=" + state + " STATUS=0\n"
		start := strings.Index(log, begin)
		stop := strings.Index(log, end)
		if start < 0 || stop < start+len(begin) {
			return nil, fmt.Errorf("incorrect suite marker order in sysctl state %s", state)
		}
		// test2json's record separator is preserved by the serial console.
		suite := strings.ReplaceAll(log[start+len(begin):stop], "\x16", "")
		if !startedRE.MatchString(suite) {
			return nil, fmt.Errorf("no tests started in sysctl state %s", state)
		}
		if !passedRE.MatchString(suite) {
			return nil, fmt.Errorf("zero passing tests in sysctl state %s", state)
		}
		if failedRE.MatchString(suite) || !completeRE.MatchString(suite) {
			return nil, fmt.Errorf("incomplete or failed suite in sysctl state %s", state)
		}
		for _, name := range []string{"TestCrossCompileSmoke", "TestExportedAPI"} {
			if strings.Contains(suite, "=== RUN   "+name) {
				return nil, fmt.Errorf("%s was not explicitly excluded", name)
			}
		}
		suites[state] = suite
	}
	return suites, nil
}
