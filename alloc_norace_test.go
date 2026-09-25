//go:build !race

// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

// underRaceDetector: see alloc_race_test.go.
const underRaceDetector = false
