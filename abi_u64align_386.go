// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build 386

package sctp

// u64Align is a __u64 field's alignment requirement inside a Linux kernel
// struct on this GOARCH. The i386 SysV ABI aligns long long/__u64/uint64_t
// to 4 bytes, not 8 — the one place GOARCH=386 disagrees with every other
// 32-bit architecture Go and Linux SCTP both support (arm, mips, ...),
// where an 8-byte type keeps its natural 8-byte alignment. struct
// sctp_assoc_stats (abi.go) is the only kernel struct this package decodes
// whose layout depends on the difference: sizeAssocStatsHeader, below,
// rounds up to u64Align, giving 252 bytes total on this GOARCH rather than
// the 256 every other target uses. Split into this file and
// abi_u64align_other.go because abi.go itself carries no build tag.
const u64Align = 4
