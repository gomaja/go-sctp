// Copyright 2026 gomaja. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//go:build !386

package sctp

// u64Align is a __u64 field's alignment requirement inside a Linux kernel
// struct on this GOARCH: 8, its natural size, on every architecture except
// 386 (see abi_u64align_386.go, the other half of this pair).
const u64Align = 8
