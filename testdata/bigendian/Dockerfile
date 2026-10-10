# Copyright 2026 gomaja. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# COPY from the foreign image only: no s390x program runs under qemu-user
# while building the guest. The emulator itself runs natively on the host.
FROM --platform=linux/s390x debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS guest
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

# Snapshot freezes every package version. APT checks the archive signature
# and each package's SHA256; only the snapshot's expiry check is disabled.
RUN rm /etc/apt/sources.list.d/debian.sources && \
    printf '%s\n' 'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261006T000000Z/ trixie main' > /etc/apt/sources.list && \
    apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates qemu-system-misc cpio kmod xz-utils && \
    dpkg-query -W > /native-packages.txt

COPY --from=guest / /guest/

# An empty status database resolves the complete s390x dependency closure,
# independently of the native packages above. Extract, never execute it.
RUN mkdir /debs && touch /empty-status && \
    apt-get -o APT::Architecture=s390x update && \
    apt-get -o APT::Architecture=s390x -o Dir::State::status=/empty-status \
        -o Dir::Cache::archives=/debs --download-only --no-install-recommends \
        install -y linux-image-s390x bash iproute2 procps kmod coreutils util-linux grep sed busybox-static && \
    for deb in /debs/*.deb; do \
        dpkg-deb -f "$deb" Package Version Architecture >> /guest-packages.txt; \
        sha256sum "$deb" >> /guest-packages.sha256; \
        dpkg-deb -x "$deb" /guest; \
    done && \
    for modules in /guest/lib/modules/*; do depmod -b /guest "${modules##*/}"; done && \
    cp /guest/boot/vmlinuz-* /kernel && \
    rm -rf /debs /var/lib/apt/lists/* /var/cache/apt/archives/* /guest/boot

COPY boot.sh /boot.sh
ENTRYPOINT ["/bin/bash", "/boot.sh"]
