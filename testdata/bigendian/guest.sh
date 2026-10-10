#!/usr/bin/env bash
# Copyright 2026 gomaja. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# PID 1 in the initramfs. Report every exit, including a failed setup;
# the host still rejects a missing sentinel, panic, timeout or bad proof.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
exec </dev/console >/dev/console 2>&1
nonce="$(cat /nonce)"
# Called by the EXIT trap, including when setup fails.
# shellcheck disable=SC2329
finish() {
	status=$?
	echo "SCTP-GUEST-$nonce EXIT=$status"
	sync
	/usr/bin/busybox poweroff -f
}
trap finish EXIT
echo "SCTP-GUEST-$nonce BOOT"
echo "SCTP-GUEST-$nonce ARCH=$(uname -m)"
# Read a two-byte value in the guest's own native order, independently of
# the package's codecs or of what the cross compiler claims to target.
order="$(printf '\001\002' | od -An -tu2 | tr -d ' ')"
echo "SCTP-GUEST-$nonce ORDER=$order"
echo "SCTP-GUEST-$nonce KERNEL=$(uname -r)"
echo "SCTP-GUEST-$nonce UID=$(id -u)"
echo "SCTP-GUEST-$nonce BINARY=$(sha256sum /sctp.test | cut -d ' ' -f1)"
echo "SCTP-GUEST-$nonce EXAMPLE-BINARY=$(sha256sum /example.test | cut -d ' ' -f1)"
echo "SCTP-GUEST-$nonce METADATA-BEGIN"
cat /metadata
echo "SCTP-GUEST-$nonce METADATA-END"
ip link set lo up
modprobe dummy
# Docker and CI have an ordinary unicast source address in their network
# namespace. Without one, routing to the silent dummy peer returns
# ENETUNREACH before any SCTP handshake can start. Supply that same ambient
# condition without a host connection or an external peer.
ip link add uplink0 type dummy
ip addr add 198.18.0.1/24 dev uplink0
ip link set uplink0 up
result=0
read -r -a states < /states
cd /src
for state in "${states[@]}"; do
	/setup-env.sh "$state" "$state"
	test -e /proc/net/sctp/snmp
	echo "SCTP-GUEST-$nonce SCTP=$state"
	echo "SCTP-GUEST-$nonce TEST-BEGIN=$state"
	# TestCrossCompileSmoke needs a guest Go executable; cross-compile covers it.
	# TestExportedAPI's source import is architecture-independent; other jobs cover it.
	set +e
	/sctp.test -test.skip '^(TestCrossCompileSmoke|TestExportedAPI)$' -test.v=test2json \
		-test.count=1 -test.timeout=1200s
	status=$?
	set -e
	echo "SCTP-GUEST-$nonce TEST-END=$state STATUS=$status"
	if [ "$status" -ne 0 ]; then result="$status"; fi
	echo "SCTP-GUEST-$nonce EXAMPLE-BEGIN=$state"
	# Use the package directory and an absolute binary path so its subprocess
	# tests re-execute the same binary through os.Args[0].
	set +e
	(cd /src/example && /example.test -test.v=test2json -test.count=1 -test.timeout=1200s)
	status=$?
	set -e
	echo "SCTP-GUEST-$nonce EXAMPLE-END=$state STATUS=$status"
	if [ "$status" -ne 0 ]; then result="$status"; fi
done
exit "$result"
