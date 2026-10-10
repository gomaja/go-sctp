# Big-endian Linux socket test suite

`run.sh` runs the Linux socket suite as root against a Debian s390x kernel,
booted by `qemu-system-s390x` with TCG. Socket options, control messages and
notifications reach a real big-endian SCTP stack. The separate qemu-user
job still runs portable tests and fuzz seeds quickly; it cannot pass
`SOL_SCTP` options through.

## Usage

```sh
GO=~/go/bin/go1.26.5 testdata/bigendian/run.sh [-sysctl both|on|off]
```

Docker, Go and `tar` are required. Docker runs the native emulator; no host
root, privileged container or foreign user-mode execution is involved.

Both sysctl states (`auth_enable=1` / `intl_enable=1` and `0` / `0`) run by
default. The guest calls `testdata/docker/setup-env.sh` unchanged. A dummy
uplink supplies the unicast source address the silent-peer tests need,
without a host connection or external peer; `/etc/hosts` resolves localhost.

Every run crosscompiles a fresh binary with `CGO_ENABLED=0 GOOS=linux
GOARCH=s390x go test -c`. A small source archive supplies the source-reading
tests. Two tests are explicitly excluded by name, and the verifier rejects
either running:

- `TestCrossCompileSmoke` needs a guest Go executable; cross-compile CI covers it.
- `TestExportedAPI` imports source for three targets; its result is independent
  of the running architecture, and the other CI jobs cover it.

Every other test runs or reports its ordinary skip, with the reason printed
on the host. The two-host cases require the [wire harness](../wire/README.md).

## Guest

The Dockerfile pins Debian trixie-slim by image digest and packages to the
snapshot at `20261006T000000Z`. APT checks the archive signature and package
SHA256 hashes; only the snapshot's expiry check is disabled. The guest
packages are extracted without executing them, and native `depmod` builds
the module index. Each boot uses a fresh initramfs.

- `linux-image-s390x`: `6.12.107-1`.
- Kernel package: `linux-image-6.12.107+deb13-s390x`, `6.12.107-1`.
- QEMU: `10.0.13`, Debian `1:10.0.13+ds-0+deb13u1`.

The console records package versions and SHA256 hashes. The host verifies
guest architecture, independent native byte order, root UID, kernel release,
SCTP availability in each state, binary SHA256 and source/build metadata.
Metadata includes HEAD, dirty-tree status, source archive hash and
`go version -m`; a dirty run qualifies those inputs, not clean HEAD alone.

## Evidence and failures

The Go supervisor is vetted and tested before any guest boots. It rejects
missing, duplicate or conflicting proofs, nonzero or missing guest status,
panic/oops, empty or incomplete suites, and failed tests. A random per-run
sentinel carries each suite status and the final guest status. Boot is
bounded at 180 seconds, the emulator at 30 minutes, and each state's tests
at 20 minutes. INT and TERM remove the named emulator container too.

`SCTP_BIGENDIAN_CACHE` defaults to `${TMPDIR:-/tmp}/go-sctp-bigendian-cache`.
Each run prints its evidence directory. Success removes the test binary,
host supervisor binary and source archive, retaining console, metadata,
per-state text/JSON logs and `source.diff`. Failure retains all inputs and
prints the last 200 console lines. The host prints PASS/FAIL/SKIP summaries
through the same summarizer as the native Docker suite.

The compressed environment image is cached by native Docker architecture,
Dockerfile and boot script. CI persists that archive; a restored image must
still match the Docker server's architecture. Every run rebuilds its tests
and boots a fresh guest. Docker build layers may also be reused. The script
never prunes Docker or deletes another run's resources.

This qualifies the socket suite on one s390x distribution kernel. It does
not qualify other big-endian architectures, kernel versions, race behavior
or two-host wire claims. The [native Docker suite](../docker/README.md) and
wire harness supply their own evidence.

CI runs on push, pull request and manual dispatch, with a 35-minute limit.
A two-state run takes about four minutes on arm64 Docker Desktop. On a
hosted x86_64 runner the first run, which also built and cached the image,
took 8 minutes: 6 for the two suites, 1.5 for the image.

The supervisor's checks can run without Docker:

```sh
go vet ./testdata/bigendian/...
go test ./testdata/bigendian/... -count=1
```
