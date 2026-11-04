// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sctp

import "slices"

// The same capture assertions as Abort during Close apply to an abortive
// CloseWithTimeout: the ABORT must precede the graceful close's expiry.
func init() {
	wireCases = slices.Insert(wireCases, len(wireCases)-1, twoHostCase{
		name: "abortive-close-during-close", port: 41030,
		server: silentServer(1), client: abortiveCloseDuringCloseClient,
	})
}

func abortiveCloseDuringCloseClient(s *hostStep) {
	s.expect("ready")
	c := s.dialA(&Config{CloseTimeout: wireGrace})
	s.send("silence")
	s.expect("silent")
	abortDuringClose(s, c.Close, func() error { return c.CloseWithTimeout(0) })
}
