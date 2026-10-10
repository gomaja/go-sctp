#!/usr/bin/env bash
# Copyright 2026 gomaja. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Runs natively in Docker; only qemu-system-s390x executes guest programs.
set -euo pipefail
cp /work/sctp.test /guest/sctp.test
cp /work/example.test /guest/example.test
cp /work/metadata /guest/metadata
cp /work/nonce /guest/nonce
cp /work/states /guest/states
cp /work/guest.sh /guest/init
cp /work/setup-env.sh /guest/setup-env.sh
mkdir -p /guest/src
tar -xzf /work/source.tar.gz -C /guest/src
printf '%s\n' '127.0.0.1 localhost' '::1 localhost' > /guest/etc/hosts
mkdir -p /guest/{proc,sys,dev,tmp,run}
chmod 1777 /guest/tmp
chmod +x /guest/init /guest/setup-env.sh
cd /guest
find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1 > /initrd.gz
qemu-system-s390x --version
cat /guest-packages.txt /guest-packages.sha256
# No guest network device is needed: setup-env.sh supplies the loopback
# and dummy interfaces. A fresh initramfs supplies a fresh kernel state.
exec timeout --signal=TERM --kill-after=10 "$1" \
	qemu-system-s390x -machine s390-ccw-virtio -accel tcg -smp 4 -m 2048 \
	-nographic -no-reboot -nic none -kernel /kernel -initrd /initrd.gz \
	-append 'console=ttysclp0 rdinit=/init panic=1 oops=panic'
