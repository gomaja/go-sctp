# Linux socket test suite (Docker)

SCTP does not exist on macOS: `sctp.ListenSCTP`-style calls fail with
"SCTP is unsupported on darwin/arm64", so every socket-backed test has to
run against a real Linux SCTP stack. `linux-suite.sh` runs the package's
tests inside a `--privileged` `golang:1.26.5-bookworm` container (falling
back to the newest `golang:1.26.*-bookworm` tag it can find if that exact
one is unavailable, and printing whichever image it used), with the
network and sysctl setup the suite requires.

## Usage

```sh
testdata/docker/linux-suite.sh [-race] [-sysctl on|off] [-run REGEX]
```

- `-race` also builds and runs the suite with the race detector.
- `-sysctl on|off` sets `net.sctp.auth_enable` and `net.sctp.intl_enable`
  together, both to `1` (`on`) or both to `0` (`off`). Defaults to `on`.
- `-run REGEX` is passed straight through to `go test -run`. Defaults to
  `.*` (everything).

Any Linux-only test added to the suite should be run through this script in
both sysctl states, and with `-race`, before it is committed.

## Why each setup step exists

Every step below lives in `setup-env.sh`, one script this suite and the CI
workflow (`.github/workflows/ci.yml`) both call, so the two environments
cannot drift apart: a fix or an addition made here reaches CI on the next
run, not only the next time someone remembers to update both.

- **`modprobe sctp`, then require `/proc/net/sctp/snmp`.** The SCTP module
  is loadable on some kernels and built in on others; the load is
  attempted and its failure ignored, but the `/proc` entry it (or a
  built-in SCTP) leaves behind is required, since every test below needs
  a working SCTP stack to mean anything.

- **`apt-get install iproute2`, only if `ip` is missing.** The base
  `golang:*-bookworm` image has `sysctl` (from `procps`) but not `ip`; the
  interface and route setup below needs it. A GitHub-hosted runner already
  has both, so this is a no-op there. Its output is logged and only shown
  if the install fails, since a successful run has nothing useful to say
  here.

- **`sysctl -w net.sctp.auth_enable=$A net.sctp.intl_enable=$I`, run in both
  states.** AUTH (RFC 4895) and I-DATA / message interleaving (RFC 8260,
  `intl_enable`) are each required by some behaviour and forbidden by other
  behaviour: a `MessageInterleaving` option must fail with `EPERM` when
  `intl_enable` is `0`, and the AUTH key helpers must still succeed when
  `auth_enable` is `0` (lksctp-tools #69). A single fixed sysctl state would
  hide whichever half of that contract it doesn't exercise, so the suite is
  meant to be run once with both on and once with both off; a test that
  needs the other state skips itself, by design, and says why.

- **`ip addr add 127.0.0.{2,3,4}/8 dev lo`.** Loopback only carries
  `127.0.0.1` by default. Multihome tests, and a test that a wildcard-bound
  client's local address set equals the association's addresses and not
  the whole namespace's, both need more than one usable source address on
  the same host, so three secondary loopback addresses are added before
  the suite runs.

- **`ip link add silent0 type dummy; ip link set silent0 up; ip route add
  192.0.2.1/32 dev silent0`.** `192.0.2.1` (RFC 5737 TEST-NET-1) is routed
  out a dummy link with nothing behind it. A dummy interface has no peer to
  answer and raises no ICMP unreachable, so packets sent to it are silently
  dropped instead of provoking an immediate refusal the way an unused
  loopback port would. A dial-timeout or cancelled-context test needs that
  genuine silence: a fast, synthetic `ECONNREFUSED` would return before the
  timeout or cancellation ever had anything to interrupt, and the test
  would pass for the wrong reason. `ip -6 addr add fe80::9/64 dev silent0
  nodad` gives the link a known link-local address, besides the one Linux
  generates for it, which the tests of link-local paths given without a
  zone bind, so that an association spans two links, and check for.

- **`ip link add zone0 type dummy; ip link set zone0 up; ip -6 addr add
  fe80::1/64 dev zone0 nodad`, and the same for `fe80::3`.**
  IPv6 link-local addresses carry a zone (scope) id tied to a real
  interface index; there is no way to fabricate one. A genuine interface
  named `zone0` carrying `fe80::1` lets a zoned link-local address
  (`fe80::1%zone0`) round-trip through address resolution, encoding,
  decoding and printing against a real kernel interface index, for the
  link-local zone tests. `fe80::3` lets a listener and a dialer bind
  link-local addresses of that one link only, so that the association
  runs over a single link, which the tests of link-local paths given
  without a zone need. `nodad` skips duplicate address detection,
  which would otherwise delay the addresses becoming usable on a freshly
  created dummy link for no benefit here.

- **`GOFLAGS=-buildvcs=false`.** Defensive, not required: Go 1.26 builds
  fine even with a git worktree's `.git` pointer file (it silently omits
  VCS stamping rather than failing). The flag just keeps the build from
  depending on that behaviour, or on VCS metadata resolved against the
  bind-mounted host state, at all.

- **Two containers, not one, for anything path-dependent.** This script
  covers everything that only needs sysctls, extra loopback addresses and
  two harmless dummy links. Tests that need real delay, loss, reordering or
  a path failure need `tc`/`netem` on a real path between two hosts:
  `netem` attached to `lo` affects nothing, because loopback traffic
  bypasses the qdisc layer entirely. Those need two containers on a Docker
  network instead, which is outside what this script sets up.

## Output and summary

The script prints `uname -r` and `go version` for the container it ran in,
then runs the suite with `go test -json` and pipes that event stream
through `summarize.go` (also in this directory), which:

1. echoes the events back as the same text `go test -v` would have printed
   (so the output reads exactly like a normal verbose run), and
2. prints a summary derived from the JSON actions themselves, not from
   scanning that text.

Scanning the text is not reliable enough on its own: `go test -v` indents
subtest lines (`    --- SKIP: TestX/sub`), so a prefix match on `--- SKIP`
undercounts them, and a parent test whose only failure is in a subtest
still prints `--- PASS` for itself; separately, a build failure, a
`-timeout` panic or an early panic can end the run without printing a
single `--- FAIL` line at all, so a `FAIL` count of zero would not mean
nothing failed. The JSON action stream carries pass/fail/skip for every
test and subtest individually, so the summary is:

```
SUMMARY: PASS=<n> FAIL=<n> SKIP=<n>
```

followed by, when applicable:

- `SKIP list:` — every skipped test (including subtests) with its skip
  message, one per line.
- `BUILD FAILURES:` — any package that failed to build, so a build
  failure is never mistaken for zero failures.
- `FAIL lines:` — any `FAIL\t<package>` summary line `go test` printed.
- `PANIC lines:` — any `panic:` line, since a panic can end the run before
  the failing test's own result is ever recorded.

Finally the script prints `EXIT=<status>`, the exit status `go test`
itself returned, and exits with that same status. A skip is not a pass:
every entry in `SKIP list:` needs its reason to be either a deliberate,
documented limitation or a bug to fix, and `EXIT`, `BUILD FAILURES` and
`PANIC lines` all being absent is what "the suite is actually green" means
here — `SUMMARY: PASS=... FAIL=0` alone is not sufficient proof of that.

The raw JSON stream is kept at `/tmp/out.json` and the reconstructed
human-readable log at `/tmp/out.log` inside the container, for anything
this summary doesn't already answer.
