// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import (
	"fmt"
	"os"
	"syscall"
	"testing"
)

func TestMain(m *testing.M) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_SCTP)
	if err != nil {
		if err == syscall.EPROTONOSUPPORT || err == syscall.ESOCKTNOSUPPORT {
			fmt.Fprintln(os.Stderr, "SCTP is unavailable: try modprobe sctp; on RHEL-family systems install the matching kernel-modules-extra package and check the SCTP module blacklist. Run the Linux socket suite with testdata/docker/linux-suite.sh.")
		} else {
			fmt.Fprintf(os.Stderr, "probing SCTP socket support: %v\n", err)
		}
		os.Exit(1)
	}
	if err := syscall.Close(fd); err != nil {
		fmt.Fprintf(os.Stderr, "closing SCTP probe: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}
