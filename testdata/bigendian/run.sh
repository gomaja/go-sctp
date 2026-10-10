#!/usr/bin/env bash
# Copyright 2026 gomaja. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# run.sh [-sysctl both|on|off]
# A real s390x Linux kernel, with the same setup as test-linux. Docker runs
# the host-native emulator, never the test binary through qemu-user.
set -euo pipefail
started=$SECONDS
states="1 0"
if [ $# -gt 0 ]; then
	if [ $# -ne 2 ] || [ "$1" != -sysctl ]; then
		echo "usage: $0 [-sysctl both|on|off]" >&2
		exit 2
	fi
	case "$2" in
	both) states="1 0" ;;
	on) states=1 ;;
	off) states=0 ;;
	*) echo "-sysctl must be both, on or off" >&2; exit 2 ;;
	esac
fi
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$root"
cache="${SCTP_BIGENDIAN_CACHE:-${TMPDIR:-/tmp}/go-sctp-bigendian-cache}"
go="${GO:-go}"
mkdir -p "$cache"
cache="$(cd "$cache" && pwd)"
work="$(mktemp -d "$cache/run.XXXXXXXX")"
echo "evidence directory: $work"
supervisor_pid=""
# Keep failed inputs for diagnosis; a successful run needs only its small
# evidence. Forward cancellation to the supervisor so it can remove Docker.
# shellcheck disable=SC2329
finish() {
	status=$?
	if [ "$status" -eq 0 ]; then
		rm -f "$work/sctp.test" "$work/example.test" "$work/source.tar.gz" "$work/supervise"
		echo "evidence kept in $work; successful run's binaries and source archive removed"
	else
		echo "run failed; all inputs and evidence kept in $work" >&2
	fi
}
# shellcheck disable=SC2329
cancel() {
	trap '' INT TERM
	if [ -n "$supervisor_pid" ]; then
		kill -TERM "$supervisor_pid" 2>/dev/null || true
		wait "$supervisor_pid" || true
	fi
	exit "$1"
}
trap finish EXIT
trap 'cancel 130' INT
trap 'cancel 143' TERM
# testdata/ is omitted by ./...; check this host program before any boot.
"$go" vet ./testdata/bigendian/...
"$go" test ./testdata/bigendian/... -count=1
"$go" build -o "$work/supervise" ./testdata/bigendian/supervise
nonce="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
printf '%s\n' "$nonce" > "$work/nonce"
printf '%s\n' "$states" > "$work/states"
cp testdata/bigendian/guest.sh "$work/guest.sh"
cp testdata/docker/setup-env.sh "$work/setup-env.sh"
COPYFILE_DISABLE=1 tar --no-xattrs -czf "$work/source.tar.gz" -- *.go go.mod example
revision="$(git rev-parse HEAD)"
dirty=no
if [ -n "$(git status --porcelain --untracked-files=all)" ]; then dirty=yes; fi
# Preserve the exact reviewed changes as well as HEAD: a dirty-tree run
# cannot be described as qualification of the clean revision alone.
git diff --binary HEAD > "$work/source.diff"
CGO_ENABLED=0 GOOS=linux GOARCH=s390x "$go" test -c -o "$work/sctp.test" .
CGO_ENABLED=0 GOOS=linux GOARCH=s390x "$go" test -c -o "$work/example.test" ./example
{
	echo "REVISION=$revision"
	echo "DIRTY=$dirty"
	echo "source.tar.gz SHA256=$("$work/supervise" hash "$work/source.tar.gz")"
	echo "sctp.test SHA256=$("$work/supervise" hash "$work/sctp.test")"
	"$go" version -m "$work/sctp.test"
	echo "example.test SHA256=$("$work/supervise" hash "$work/example.test")"
	"$go" version -m "$work/example.test"
} | tee "$work/metadata"
key="$("$work/supervise" hash testdata/bigendian/Dockerfile testdata/bigendian/boot.sh | cut -c1-24)"
arch="$(docker version --format '{{.Server.Arch}}')"
platform="linux/$arch"
key="$arch-$key"
image="gomaja-sctp-bigendian:$key"
if ! docker image inspect "$image" >/dev/null 2>&1; then
	if [ -f "$cache/$key.image.tar.gz" ]; then
		gzip -dc "$cache/$key.image.tar.gz" | docker load
	else
		docker build --platform "$platform" -t "$image" testdata/bigendian
		# Cache only pinned distribution artefacts, never a test binary or
		# source tree. Every invocation rebuilds its own test binary.
		archive="$(mktemp "$cache/$key.image.XXXXXXXX")"
		docker save "$image" | gzip -1 > "$archive"
		mv "$archive" "$cache/$key.image.tar.gz"
	fi
fi
if [ "$(docker image inspect --format '{{.Architecture}}' "$image")" != "$arch" ]; then
	echo "cached emulator image is not native to the Docker server" >&2
	exit 1
fi
docker run --rm --platform "$platform" --entrypoint bash "$image" -c \
	'printf "%s\n" /guest/lib/modules/* | sed "s,.*/,,"' > "$work/kernel-release"
"$work/supervise" run "$work" "$image" "sctp-bigendian-$nonce" "$go" "$platform" &
supervisor_pid=$!
wait "$supervisor_pid"
supervisor_pid=""
echo "whole harness: $((SECONDS - started))s"
