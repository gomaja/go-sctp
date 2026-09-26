#!/usr/bin/env bash
# Copyright 2026 gomaja. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# setup-env.sh AUTH_ENABLE INTL_ENABLE
#
# Builds the network and sysctl environment the Linux socket-backed suite
# requires: the net.sctp sysctls at the state the caller asks for, three
# extra loopback addresses, a silently-routed peer and two link-local
# zones. linux-suite.sh and the CI workflow both call this one script, so
# the two environments cannot drift apart. See testdata/docker/README.md
# for why each step exists.
#
# Runs as whatever user invoked it: as root already (inside a Docker
# container) every command below runs directly; otherwise each one that
# needs root runs under sudo. It can run in a fresh or existing network
# namespace.
set -euo pipefail

if [ $# -ne 2 ]; then
	echo "usage: $0 AUTH_ENABLE INTL_ENABLE" >&2
	exit 2
fi
AUTH_ENABLE="$1"
INTL_ENABLE="$2"

SUDO=""
if [ "$(id -u)" != "0" ]; then
	SUDO="sudo"
fi

# The SCTP module is loadable on some kernels and built in on others; try
# to load it and otherwise carry on, but require the /proc entry it (or a
# built-in SCTP) leaves behind, since every test below needs a working
# SCTP stack to mean anything.
$SUDO modprobe sctp 2>/dev/null || true
if [ ! -e /proc/net/sctp/snmp ]; then
	echo "setup-env.sh: /proc/net/sctp/snmp is missing; this kernel has no SCTP support (modprobe sctp did not help)" >&2
	exit 1
fi

# iproute2 gives the "ip" command the rest of this script needs; the base
# golang:*-bookworm image has "sysctl" (from procps) but not "ip", while a
# GitHub-hosted runner already has both, so this is a no-op there.
if ! command -v ip >/dev/null 2>&1; then
	apt_log="$(mktemp)"
	if ! $SUDO apt-get -qq update >"$apt_log" 2>&1 || ! $SUDO apt-get -qq install -y iproute2 >>"$apt_log" 2>&1; then
		cat "$apt_log" >&2
		exit 1
	fi
fi

# AUTH (RFC 4895) and I-DATA / message interleaving (RFC 8260, "intl") are
# each required by some behaviour and forbidden by other behaviour: a
# MessageInterleaving option must fail with EPERM when intl_enable is 0,
# and the AUTH key helpers must still succeed when auth_enable is 0
# (lksctp-tools #69). A single fixed sysctl state would hide whichever
# half of that contract it doesn't exercise, so this environment is meant
# to be built once with both on and once with both off; a test that needs
# the other state skips itself, by design, and says why.
$SUDO sysctl -w net.sctp.auth_enable="$AUTH_ENABLE" net.sctp.intl_enable="$INTL_ENABLE"

# Loopback only carries 127.0.0.1 by default. Multihome tests, and a test
# that a wildcard-bound client's local address set equals the
# association's addresses and not the whole namespace's, both need more
# than one usable source address on the same host.
$SUDO ip addr replace 127.0.0.2/8 dev lo
$SUDO ip addr replace 127.0.0.3/8 dev lo
$SUDO ip addr replace 127.0.0.4/8 dev lo

# ensure_dummy creates the dummy link $1, or reuses it when a previous run
# created it. A link of that name that is not a dummy device belongs to
# something else: routing the tests through it would test the wrong
# topology and change a link this script does not own, so it stops instead.
ensure_dummy() {
	if ! ip link show "$1" >/dev/null 2>&1; then
		$SUDO ip link add "$1" type dummy
	elif ! ip -d link show "$1" | grep -qw dummy; then
		echo "setup-env.sh: $1 exists and is not a dummy link; refusing to reuse it" >&2
		exit 1
	fi
}

# A dummy-routed, unlistened peer: 192.0.2.1 (RFC 5737 TEST-NET-1) is
# routed out a dummy link with nothing behind it. A dummy interface has no
# peer to answer and raises no ICMP unreachable, so packets sent to it are
# silently dropped instead of provoking an immediate refusal the way an
# unused loopback port would. A dial-timeout or cancelled-context test
# needs that genuine silence: a fast, synthetic ECONNREFUSED would return
# before the timeout or cancellation ever had anything to interrupt, and
# the test would pass for the wrong reason.
ensure_dummy silent0
$SUDO ip link set silent0 up
$SUDO ip route replace 192.0.2.1/32 dev silent0
# fe80::9 is a known link-local address on silent0, which the link-local
# path tests bind, so that an association spans two links, and check for.
$SUDO ip -6 addr replace fe80::9/64 dev silent0 nodad

# A real interface literally named zone0 lets a zoned link-local address
# round trip (fe80::1%zone0) through address resolution, encoding,
# decoding and printing against a genuine kernel interface index, instead
# of skipping for want of a matching interface. fe80::3 on the same link
# lets two endpoints bind link-local addresses of that one link only, for
# the tests of link-local paths given without a zone.
ensure_dummy zone0
$SUDO ip link set zone0 up
$SUDO ip -6 addr replace fe80::1/64 dev zone0 nodad
$SUDO ip -6 addr replace fe80::3/64 dev zone0 nodad
