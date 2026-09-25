#!/usr/bin/env bash
# Copyright 2026 gomaja. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# linux-suite.sh [-race] [-sysctl on|off] [-run REGEX]
#
# Runs the package's Linux, socket-backed test suite inside a --privileged
# golang:bookworm container, with the network and sysctl setup the suite
# requires rebuilt fresh on every run. See README.md in this directory for
# what each setup step is for and how to read the summary this prints.
#
# SCTP does not exist on macOS, so this is the only way to exercise
# socket-backed tests from a macOS checkout; a green run on the host proves
# nothing about them.
set -euo pipefail

RACE=""
SYSCTL="on"
RUN=".*"

while [ $# -gt 0 ]; do
	case "$1" in
	-race)
		RACE="-race"
		shift
		;;
	-sysctl)
		SYSCTL="${2:?-sysctl needs an argument: on or off}"
		shift 2
		;;
	-run)
		RUN="${2:?-run needs a regexp argument}"
		shift 2
		;;
	*)
		echo "usage: $0 [-race] [-sysctl on|off] [-run REGEX]" >&2
		exit 2
		;;
	esac
done

case "$SYSCTL" in
on)
	AUTH_ENABLE=1
	INTL_ENABLE=1
	;;
off)
	AUTH_ENABLE=0
	INTL_ENABLE=0
	;;
*)
	echo "linux-suite.sh: -sysctl must be 'on' or 'off', got '$SYSCTL'" >&2
	exit 2
	;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

PREFERRED_IMAGE="golang:1.26.5-bookworm"

# resolve_image prints the image tag to run: the preferred one if it exists
# (checked locally first, then pulled), otherwise the newest
# golang:1.26.*-bookworm tag it can find, first from Docker Hub and then
# from images already pulled locally. It never silently substitutes an
# unrelated Go version.
resolve_image() {
	if docker image inspect "$PREFERRED_IMAGE" >/dev/null 2>&1; then
		echo "$PREFERRED_IMAGE"
		return 0
	fi

	local pull_err
	if pull_err="$(docker pull "$PREFERRED_IMAGE" 2>&1)"; then
		echo "$PREFERRED_IMAGE"
		return 0
	fi
	{
		echo "linux-suite.sh: docker pull $PREFERRED_IMAGE failed, falling back to the newest golang:1.26.*-bookworm tag:"
		echo "$pull_err" | sed 's/^/  /'
	} >&2

	local best=""
	if command -v curl >/dev/null 2>&1; then
		local tags
		tags="$(curl -fsSL 'https://registry.hub.docker.com/v2/repositories/library/golang/tags?name=1.26&page_size=100' 2>/dev/null |
			grep -o '"name":"[0-9][0-9a-zA-Z.-]*-bookworm"' |
			sed -E 's/"name":"([^"]+)"/\1/' |
			grep -E '^1\.26(\.[0-9]+)?-bookworm$' || true)"
		best="$(printf '%s\n' "$tags" | while read -r t; do
			[ -z "$t" ] && continue
			patch="$(echo "$t" | sed -E 's/^1\.26(\.([0-9]+))?-bookworm$/\2/')"
			[ -z "$patch" ] && patch=0
			printf '%s\t%s\n' "$patch" "$t"
		done | sort -n -k1,1 | tail -1 | cut -f2)"
		if [ -n "$best" ]; then
			local fallback_err
			if ! fallback_err="$(docker pull "golang:$best" 2>&1)"; then
				echo "linux-suite.sh: docker pull golang:$best also failed:" >&2
				echo "$fallback_err" | sed 's/^/  /' >&2
				best=""
			fi
		fi
	fi
	if [ -z "$best" ]; then
		best="$(docker images --format '{{.Repository}}:{{.Tag}}' |
			grep -E '^golang:1\.26(\.[0-9]+)?-bookworm$' |
			sed -E 's/^golang://' |
			while read -r t; do
				[ -z "$t" ] && continue
				patch="$(echo "$t" | sed -E 's/^1\.26(\.([0-9]+))?-bookworm$/\2/')"
				[ -z "$patch" ] && patch=0
				printf '%s\t%s\n' "$patch" "$t"
			done | sort -n -k1,1 | tail -1 | cut -f2)"
	fi
	if [ -z "$best" ]; then
		echo "linux-suite.sh: no $PREFERRED_IMAGE and no golang:1.26.*-bookworm tag found (remote or local)" >&2
		return 1
	fi
	echo "golang:$best"
}

IMAGE="$(resolve_image)"
echo "docker image: $IMAGE"

# The inner script runs as the container's entrypoint. It receives
# AUTH_ENABLE, INTL_ENABLE, RACE and RUN as positional arguments because a
# quoted heredoc (below) does not interpolate the outer script's variables.
read -r -d '' INNER_SCRIPT <<'EOF' || true
set -euo pipefail
AUTH_ENABLE="$1"
INTL_ENABLE="$2"
RACE="$3"
RUN="$4"

# apt-get's own chatter (including a harmless "delaying package
# configuration" debconf notice) is noise on a successful run; keep it in a
# log and only show it if the install actually fails.
apt_log="$(mktemp)"
if ! apt-get -qq update >"$apt_log" 2>&1 || ! apt-get -qq install -y iproute2 >>"$apt_log" 2>&1; then
	cat "$apt_log" >&2
	exit 1
fi

# AUTH (RFC 4895) and I-DATA / message interleaving (RFC 8260, "intl") are
# each required by some behaviour and forbidden by other behaviour: a
# MessageInterleaving option must fail with EPERM when intl_enable is 0,
# and the AUTH key helpers must still succeed when auth_enable is 0
# (lksctp-tools #69). A single fixed sysctl state would hide whichever half
# of that contract it doesn't exercise, so this suite is meant to be run
# once with both on and once with both off; a test that needs the other
# state skips itself, by design, and says why.
sysctl -w net.sctp.auth_enable="$AUTH_ENABLE" net.sctp.intl_enable="$INTL_ENABLE"

# Loopback only carries 127.0.0.1 by default. Multihome tests, and a test
# that a wildcard-bound client's local address set equals the
# association's addresses and not the whole namespace's, both need more
# than one usable source address on the same host.
ip addr add 127.0.0.2/8 dev lo
ip addr add 127.0.0.3/8 dev lo
ip addr add 127.0.0.4/8 dev lo

# A dummy-routed, unlistened peer: 192.0.2.1 (RFC 5737 TEST-NET-1) is
# routed out a dummy link with nothing behind it. A dummy interface has no
# peer to answer and raises no ICMP unreachable, so packets sent to it are
# silently dropped instead of provoking an immediate refusal the way an
# unused loopback port would. A dial-timeout or cancelled-context test
# needs that genuine silence: a fast, synthetic ECONNREFUSED would return
# before the timeout or cancellation ever had anything to interrupt, and
# the test would pass for the wrong reason.
ip link add silent0 type dummy
ip link set silent0 up
ip route add 192.0.2.1/32 dev silent0

# A real interface literally named zone0 lets a zoned link-local address
# round trip (fe80::1%zone0) through address resolution, encoding,
# decoding and printing against a genuine kernel interface index, instead
# of skipping for want of a matching interface.
ip link add zone0 type dummy
ip link set zone0 up
ip -6 addr add fe80::1/64 dev zone0 nodad

uname -r
go version

# Defensive, not required: Go 1.26 builds fine even with a git worktree's
# .git pointer file (it silently omits VCS stamping rather than failing),
# but this keeps the build from depending on that behaviour, or on VCS
# metadata resolved against the bind-mounted host state, at all.
export GOFLAGS=-buildvcs=false

# "go test -json" is used instead of scanning "-v" text output because
# text scanning misses two real failure shapes: go test -v indents subtest
# result lines ("    --- SKIP: TestX/sub"), so a plain "^--- SKIP" prefix
# match undercounts them and a parent whose only failing part is a
# subtest still prints "--- PASS" for itself; and a build failure or a
# panic can end the run with no "--- FAIL" line at all, so a FAIL count of
# zero does not mean nothing failed. testdata/docker/summarize.go reads
# the JSON action stream, reconstructs the same human-readable text "-v"
# would have printed, and reports PASS/FAIL/SKIP counts (including
# subtests), every skip with its message, any build failure, and any
# "panic:" line, all derived from the structured events rather than from
# text pattern matching.
set +e
go test ./... -count=1 -timeout 1200s -v $RACE -run "$RUN" -json 2>&1 |
	tee /tmp/out.json |
	go run testdata/docker/summarize.go |
	tee /tmp/out.log
status="${PIPESTATUS[0]}"
set -e

echo "EXIT=$status"
exit "$status"
EOF

docker run --rm --privileged \
	-v "$REPO_ROOT":/src \
	-w /src \
	"$IMAGE" \
	bash -c "$INNER_SCRIPT" bash "$AUTH_ENABLE" "$INTL_ENABLE" "$RACE" "$RUN"
