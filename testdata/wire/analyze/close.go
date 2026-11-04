// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

func init() {
	claims = append(claims, claim{"abortive-close-during-close", 1, checkAbortDuringClose})
}
