//go:build linux && race
// +build linux,race

package sctp

// The race detector allocates on its own account, which moves every per-call
// allocation count. Tests that assert exact counts consult this and skip, so
// that a race run reports them as skipped rather than silently omitting them.
const raceDetectorEnabled = true
