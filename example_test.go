// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp_test

import (
	"fmt"
	"log"

	"github.com/gomaja/go-sctp"
)

// A multi-homed address lists every IP before one port. ResolveAddr needs
// no socket, so it works on every platform.
func ExampleResolveAddr() {
	addr, err := sctp.ResolveAddr("sctp", "10.0.0.1/[2001:db8::1]:3868")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(addr.IPs, addr.Port)
	fmt.Println(addr)
	// Output:
	// [10.0.0.1 2001:db8::1] 3868
	// 10.0.0.1/[2001:db8::1]:3868
}
