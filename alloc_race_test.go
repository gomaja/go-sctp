//go:build race

// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package sctp

// underRaceDetector is true in the race-enabled test build. The race
// detector's own instrumentation allocates on its own account, which moves
// every testing.AllocsPerRun count, so an exact allocation assertion must
// report a visible SKIP under it rather than fail or, worse, silently pass
// for the wrong reason.
const underRaceDetector = true
