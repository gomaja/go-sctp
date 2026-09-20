//go:build linux && race
// +build linux,race

// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// This file includes modifications by gomaja.

package sctp

// The race detector allocates on its own account, which moves every per-call
// allocation count. Tests that assert exact counts consult this and skip, so
// that a race run reports them as skipped rather than silently omitting them.
const raceDetectorEnabled = true
