// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"strings"
	"testing"
)

const proofPrefix = "SCTP-GUEST-abc "
const proofMetadata = "REVISION=123\nDIRTY=yes\nGo build info\n"

func consoleFixture(states ...string) string {
	lines := []string{"BOOT", "ARCH=s390x", "ORDER=258", "KERNEL=6.12.test", "UID=0", "BINARY=def", "METADATA-BEGIN"}
	log := proofPrefix + strings.Join(lines, "\n"+proofPrefix) + "\n"
	log += proofMetadata + proofPrefix + "METADATA-END\n"
	for _, state := range states {
		log += proofPrefix + "SCTP=" + state + "\n" + proofPrefix + "TEST-BEGIN=" + state + "\n"
		log += "=== RUN   TestSocket\n--- PASS: TestSocket (0.01s)\nPASS\n"
		log += proofPrefix + "TEST-END=" + state + " STATUS=0\n"
	}
	return log + proofPrefix + "EXIT=0\n"
}

func checkFixture(log string, states ...string) (map[string]string, error) {
	return validate(log, "abc", states, proofMetadata, "def", "6.12.test")
}

func TestValidConsole(t *testing.T) {
	for _, states := range [][]string{{"1"}, {"1", "0"}} {
		suites, err := checkFixture(consoleFixture(states...), states...)
		if err != nil {
			t.Fatal(err)
		}
		want := make(map[string]string)
		for _, state := range states {
			want[state] = "=== RUN   TestSocket\n--- PASS: TestSocket (0.01s)\nPASS\n"
		}
		if !reflect.DeepEqual(suites, want) {
			t.Fatalf("suites = %#v, want %#v", suites, want)
		}
	}
}

func TestMissingProofs(t *testing.T) {
	for _, field := range []string{"BOOT", "ARCH=s390x", "ORDER=258", "KERNEL=6.12.test", "UID=0", "BINARY=def", "METADATA-BEGIN", "METADATA-END", "SCTP=1", "TEST-BEGIN=1", "TEST-END=1 STATUS=0", "EXIT=0"} {
		t.Run(field, func(t *testing.T) {
			if _, err := checkFixture(strings.ReplaceAll(consoleFixture("1"), proofPrefix+field+"\n", ""), "1"); err == nil {
				t.Fatal("accepted missing proof")
			}
		})
	}
}

func TestWrongProofs(t *testing.T) {
	for _, pair := range [][2]string{{"ARCH=s390x", "ARCH=aarch64"}, {"ORDER=258", "ORDER=513"}, {"UID=0", "UID=1000"}, {"BINARY=def", "BINARY=bad"}, {"KERNEL=6.12.test", "KERNEL=other"}, {"REVISION=123", "REVISION=wrong"}, {"EXIT=0", "EXIT=1"}} {
		t.Run(pair[0], func(t *testing.T) {
			if _, err := checkFixture(strings.ReplaceAll(consoleFixture("1"), pair[0], pair[1]), "1"); err == nil {
				t.Fatal("accepted incorrect proof")
			}
		})
	}
}

func TestBadTestResults(t *testing.T) {
	for _, pair := range [][2]string{{"TEST-END=1 STATUS=0", "TEST-END=1 STATUS=1"}, {"--- PASS: TestSocket (0.01s)", "--- FAIL: TestSocket (0.01s)"}, {"=== RUN   TestSocket", ""}, {"--- PASS: TestSocket (0.01s)", ""}, {"\nPASS\n", "\nFAIL\n"}} {
		t.Run(pair[0], func(t *testing.T) {
			if _, err := checkFixture(strings.ReplaceAll(consoleFixture("1"), pair[0], pair[1]), "1"); err == nil {
				t.Fatal("accepted incomplete or failed suite")
			}
		})
	}
}

func TestPanicOopsAndDuplicateExit(t *testing.T) {
	for _, extra := range []string{"Kernel panic - not syncing", "Oops: 0001", "BUG: kernel fault", "panic: test timed out", proofPrefix + "EXIT=0", proofPrefix + "EXIT=1"} {
		t.Run(extra, func(t *testing.T) {
			if _, err := checkFixture(consoleFixture("1")+extra+"\n", "1"); err == nil {
				t.Fatal("accepted panic or duplicate exit")
			}
		})
	}
}

func TestConflictingDuplicateProofs(t *testing.T) {
	for _, extra := range []string{"BOOT", "ARCH=s390x", "ARCH=aarch64", "ORDER=513", "KERNEL=other", "UID=1000", "BINARY=bad", "METADATA-BEGIN", "METADATA-END", "TEST-BEGIN=1", "TEST-END=1 STATUS=0", "TEST-END=1 STATUS=1", "SCTP=0", "SCTP=1"} {
		t.Run(extra, func(t *testing.T) {
			if _, err := checkFixture(consoleFixture("1")+proofPrefix+extra+"\n", "1"); err == nil {
				t.Fatal("accepted conflicting or duplicate proof")
			}
		})
	}
}

func TestUnrequestedOrMissingState(t *testing.T) {
	for _, states := range [][]string{{"1", "0"}, {"0"}, {"1", "1"}, nil} {
		if _, err := checkFixture(consoleFixture("1"), states...); err == nil {
			t.Fatalf("accepted states %v", states)
		}
	}
	if _, err := checkFixture(consoleFixture("0", "1"), "1", "0"); err == nil {
		t.Fatal("accepted reversed states")
	}
}

func TestExcludedGuestTests(t *testing.T) {
	for _, name := range []string{"TestCrossCompileSmoke", "TestExportedAPI"} {
		t.Run(name, func(t *testing.T) {
			log := strings.ReplaceAll(consoleFixture("1"), "TestSocket", name)
			if _, err := checkFixture(log, "1"); err == nil {
				t.Fatalf("accepted excluded %s", name)
			}
		})
	}
}

func TestRecordSeparator(t *testing.T) {
	log := strings.ReplaceAll(consoleFixture("1"), "=== RUN", "\x16=== RUN")
	suites, err := checkFixture(log, "1")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(suites["1"], "\x16") {
		t.Fatal("record separator was not stripped")
	}
}
