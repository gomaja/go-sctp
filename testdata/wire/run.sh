#!/usr/bin/env bash
# Copyright 2026 gomaja. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# run.sh [-race] [-run REGEX] [-only wire|twohost]
#
# Proves the package's SCTP behaviour between two hosts: two --privileged
# containers joined by two Docker networks run the package's own test
# binary, one as the client and one as the server (TestWire, then
# TestTwoHost), while the client's host captures every SCTP packet it sends
# and receives. testdata/wire/analyze then proves each wire claim from that
# capture. See README.md in this directory.
#
# It runs unattended on any Linux or Docker Desktop host that allows
# privileged containers. The exit status is the verdict: 0 only when every
# test on both sides passed, none skipped, and every claim held.
#
# -run REGEX selects cases (the subtests of TestWire and TestTwoHost) and
# the claims of the same names. -only runs one phase. -race builds the test
# binary with the race detector.
#
# WIRE_OUT names the artifact directory (default: a new temporary one);
# WIRE_GO_IMAGE the Go image the harness image is built from (default
# golang:1.26.5-bookworm).
set -euo pipefail

RUN=""
ONLY=""
RACE=""
while [ $# -gt 0 ]; do
	case "$1" in
	-race)
		RACE="-race"
		shift
		;;
	-run)
		RUN="${2:?-run needs a regular expression}"
		shift 2
		;;
	-only)
		ONLY="${2:?-only needs wire or twohost}"
		shift 2
		;;
	*)
		echo "usage: $0 [-race] [-run REGEX] [-only wire|twohost]" >&2
		exit 2
		;;
	esac
done
case "$ONLY" in
"" | wire | twohost) ;;
*)
	echo "run.sh: -only must be wire or twohost, got '$ONLY'" >&2
	exit 2
	;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_IMAGE="${WIRE_GO_IMAGE:-golang:1.26.5-bookworm}"
RUN_ID="sctpwire-$$-$RANDOM"
IMAGE="go-sctp-wire:$RUN_ID"
NET_A="$RUN_ID-a"
NET_B="$RUN_ID-b"
SERVER="$RUN_ID-server"
CLIENT="$RUN_ID-client"
PKG="github.com/gomaja/go-sctp"
OUT="${WIRE_OUT:-$(mktemp -d "${TMPDIR:-/tmp}/go-sctp-wire.XXXXXX")}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
BUILD="$OUT/build"
mkdir -p "$BUILD" "$OUT/expected"

IMAGE_BUILT=0
CAPTURE_PID=""
CLEANED=0

# cleanup removes everything the run created. It runs once, on a normal
# exit or on the first INT or TERM, which then end the script.
cleanup() {
	if [ "$CLEANED" -eq 1 ]; then
		return 0
	fi
	CLEANED=1
	set +e
	if [ -n "$CAPTURE_PID" ]; then
		docker exec "$CLIENT" sh -c 'kill -INT "$(cat /tmp/dumpcap.pid)"' >/dev/null 2>&1
		wait "$CAPTURE_PID" >/dev/null 2>&1
	fi
	docker rm -f "$SERVER" "$CLIENT" >/dev/null 2>&1
	docker network rm "$NET_A" "$NET_B" >/dev/null 2>&1
	if [ "$IMAGE_BUILT" -eq 1 ]; then
		# On a native Linux host the files the containers wrote belong to
		# root; hand the artifact directory back to the caller.
		docker run --rm -v "$OUT:/out" "$IMAGE" chown -R "$(id -u):$(id -g)" /out >/dev/null 2>&1
		docker image rm "$IMAGE" >/dev/null 2>&1
	fi
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

die() {
	echo "run.sh: $*" >&2
	exit 1
}

echo "wire artifacts: $OUT"

# The harness image: the Go image, which builds the binaries and converts
# the test output (go tool test2json), plus tshark and dumpcap for the
# capture, iptables for the INPUT drops, iproute2 and ethtool for the
# interfaces. The tag is removed on exit; the build cache keeps the next
# build fast.
docker build -q -t "$IMAGE" --build-arg GO_IMAGE="$GO_IMAGE" - >/dev/null <<'EOF' || die "could not build the harness image from $GO_IMAGE"
ARG GO_IMAGE
FROM ${GO_IMAGE}
RUN apt-get update -qq \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      tshark iptables iproute2 ethtool >/dev/null \
 && rm -rf /var/lib/apt/lists/*
EOF
IMAGE_BUILT=1

# Everything is built once, for the Docker host's own architecture, and
# mounted read-only into both containers. The analyzer lives under
# testdata/, which "go vet ./..." skips, so it is vetted and tested here.
echo "building the test binary and the analyzer..."
docker run --rm -e GOFLAGS=-buildvcs=false -v "$ROOT:/src:ro" -v "$BUILD:/build" -w /src "$IMAGE" sh -c '
	set -e
	go vet ./testdata/wire/analyze
	if ! go test -count=1 ./testdata/wire/analyze >/tmp/analyze-test.log 2>&1; then
		cat /tmp/analyze-test.log >&2
		exit 1
	fi
	go build -o /build/wireanalyze ./testdata/wire/analyze
	go build -o /build/summarize ./testdata/docker/summarize.go
	go test -c $1 -o /build/sctp.test .
' _ "$RACE" || die "build failed"

docker network create "$NET_A" >/dev/null
docker network create "$NET_B" >/dev/null
for c in "$SERVER" "$CLIENT"; do
	docker run -d --name "$c" --privileged --network "$NET_A" \
		-v "$BUILD:/wire:ro" -v "$OUT:/out" "$IMAGE" sleep infinity >/dev/null
	docker network connect "$NET_B" "$c"
done

network_ip() {
	docker inspect -f "{{with index .NetworkSettings.Networks \"$2\"}}{{.IPAddress}}{{end}}" "$1"
}
interface_to() {
	docker exec "$1" ip route get "$2" | awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}'
}
SERVER_A="$(network_ip "$SERVER" "$NET_A")"
SERVER_B="$(network_ip "$SERVER" "$NET_B")"
CLIENT_A="$(network_ip "$CLIENT" "$NET_A")"
CLIENT_B="$(network_ip "$CLIENT" "$NET_B")"
[ -n "$SERVER_A" ] && [ -n "$SERVER_B" ] && [ -n "$CLIENT_A" ] && [ -n "$CLIENT_B" ] ||
	die "could not resolve the containers' addresses"
CLIENT_IF_A="$(interface_to "$CLIENT" "$SERVER_A")"
CLIENT_IF_B="$(interface_to "$CLIENT" "$SERVER_B")"
SERVER_IF_A="$(interface_to "$SERVER" "$CLIENT_A")"
SERVER_IF_B="$(interface_to "$SERVER" "$CLIENT_B")"
[ -n "$CLIENT_IF_A" ] && [ -n "$CLIENT_IF_B" ] && [ "$CLIENT_IF_A" != "$CLIENT_IF_B" ] ||
	die "the client does not reach the two networks through two interfaces"
[ -n "$SERVER_IF_A" ] && [ -n "$SERVER_IF_B" ] && [ "$SERVER_IF_A" != "$SERVER_IF_B" ] ||
	die "the server does not reach the two networks through two interfaces"
MTU="$(docker exec "$CLIENT" cat "/sys/class/net/$CLIENT_IF_A/mtu")"
[ "$MTU" = "$(docker exec "$CLIENT" cat "/sys/class/net/$CLIENT_IF_B/mtu")" ] ||
	die "the client's two interfaces have different MTUs"

prepare() {
	local c=$1
	shift
	# PR-SCTP on (RFC 3758), which the partial-reliability claims need;
	# I-DATA off (RFC 8260), so that messages travel in DATA chunks.
	docker exec "$c" sysctl -q -w net.sctp.prsctp_enable=1 net.sctp.intl_enable=0 ||
		die "$c: could not set the SCTP sysctls"
	# Ephemeral ports from 49152 up only (the IANA dynamic range, RFC 6335
	# §6), clear of the case ports (41001-41109) and the control port
	# (7411), so that no dialer's own port can equal a case's server port;
	# SCTP takes its ephemeral ports from this range (net/sctp/socket.c:
	# sctp_get_port_local), and the tests refuse to run otherwise.
	docker exec "$c" sysctl -q -w net.ipv4.ip_local_port_range="49152 60999" ||
		die "$c: could not set the ephemeral port range"
	# Segmentation and receive offloads off, so that the capture sees the
	# packets that cross the wire and not super-packets the kernel builds
	# for the device to split; the analyzer refuses any frame larger than
	# the MTU allows.
	for i in "$@"; do
		docker exec "$c" ethtool -K "$i" gso off tso off gro off tx-sctp-segmentation off >/dev/null 2>&1 ||
			die "$c: could not turn the offloads of $i off"
	done
	# The iptables sctp match, with the chunk-type option, is what the INPUT
	# drops use.
	docker exec "$c" sh -c '
		iptables -w 5 -I INPUT 1 -p sctp -m sctp --dport 9 --chunk-types any SHUTDOWN_COMPLETE -j DROP &&
		iptables -w 5 -D INPUT -p sctp -m sctp --dport 9 --chunk-types any SHUTDOWN_COMPLETE -j DROP' ||
		die "$c: iptables lacks the sctp match (xt_sctp) the INPUT drops need"
}
prepare "$SERVER" "$SERVER_IF_A" "$SERVER_IF_B"
prepare "$CLIENT" "$CLIENT_IF_A" "$CLIENT_IF_B"

{
	echo "go image: $GO_IMAGE"
	echo "kernel: $(docker exec "$CLIENT" uname -r) $(docker exec "$CLIENT" uname -m)"
	echo "go: $(docker exec "$CLIENT" go version)"
	echo "tshark: $(docker exec "$CLIENT" tshark --version 2>/dev/null | head -1)"
	echo "dumpcap: $(docker exec "$CLIENT" dumpcap --version 2>/dev/null | head -1)"
	echo "mtu: $MTU"
	for s in prsctp_enable intl_enable auth_enable addip_enable rto_initial rto_min rto_max \
		association_max_retrans path_max_retrans max_init_retransmits sndbuf_policy rcvbuf_policy; do
		echo "net.sctp.$s: $(docker exec "$CLIENT" cat "/proc/sys/net/sctp/$s")"
	done
	echo "net.ipv4.ip_local_port_range: $(docker exec "$CLIENT" cat /proc/sys/net/ipv4/ip_local_port_range | awk '{print $1 "-" $2}')"
} >"$OUT/environment.txt"
cp "$OUT/environment.txt" "$OUT/expected/environment.txt"
echo "client: $CLIENT_A ($CLIENT_IF_A), $CLIENT_B ($CLIENT_IF_B); server: $SERVER_A, $SERVER_B; MTU $MTU"

# run_roles PHASE TEST [SUBTESTS]: runs TEST, or the subtests of it that
# SUBTESTS matches, in both containers at once, the server's half and the
# client's, and writes each side's test2json stream, the readable log with
# its summary, and its facts under $OUT.
run_roles() {
	local phase=$1 test=$2 pattern
	pattern="^$test\$"
	if [ -n "${3:-}" ]; then
		# Parenthesised, because go test splits a pattern into alternatives
		# at any top-level "|" before it splits it at "/".
		pattern="$pattern/($3)"
	fi
	local pids=() role container peer
	for role in server client; do
		if [ "$role" = server ]; then
			container=$SERVER
			peer="$CLIENT_A/$CLIENT_B"
		else
			container=$CLIENT
			peer="$SERVER_A/$SERVER_B"
		fi
		rm -f "$OUT/facts.$phase.$role.txt"
		docker exec -w /tmp -e SCTP_WIRE_ROLE="$role" -e SCTP_WIRE_PEER="$peer" \
			-e SCTP_WIRE_FACTS="/out/facts.$phase.$role.txt" "$container" \
			go tool test2json -t -p "$PKG" /wire/sctp.test -test.v=test2json -test.count=1 \
			-test.timeout=20m -test.run "$pattern" \
			>"$OUT/$phase.$role.json" 2>"$OUT/$phase.$role.stderr" &
		pids+=("$!")
	done
	local failed=0 i=0
	for role in server client; do
		local status=0
		wait "${pids[$i]}" || status=$?
		i=$((i + 1))
		docker exec -i "$CLIENT" /wire/summarize <"$OUT/$phase.$role.json" >"$OUT/$phase.$role.log"
		local summary
		summary="$(grep '^SUMMARY:' "$OUT/$phase.$role.log" || true)"
		echo "$phase $role: $summary EXIT=$status"
		if [ "$status" -ne 0 ] || ! echo "$summary" | grep -Eq '^SUMMARY: PASS=[1-9][0-9]* FAIL=0 SKIP=0$'; then
			failed=1
			grep -E '^[[:space:]]*--- FAIL|^[[:space:]]+[a-z_]+_test\.go:[0-9]+:' "$OUT/$phase.$role.log" | head -40 | sed "s/^/  $role: /" >&2 || true
		fi
	done
	return "$failed"
}

VERDICT=0

if [ "$ONLY" != twohost ]; then
	# The capture runs on the client, the sending host of every wire claim,
	# on both of its interfaces. Where a claim needs loss, the receiving
	# host drops on its INPUT hook, past its own capture point and never
	# before the sender's.
	docker exec "$CLIENT" sh -c 'echo $$ >/tmp/dumpcap.pid; exec dumpcap -i "$1" -f sctp -i "$2" -f sctp -w /tmp/sender.pcapng' \
		_ "$CLIENT_IF_A" "$CLIENT_IF_B" >"$OUT/dumpcap.log" 2>&1 &
	CAPTURE_PID=$!
	for _ in $(seq 1 100); do
		if docker exec "$CLIENT" test -s /tmp/sender.pcapng; then
			break
		fi
		kill -0 "$CAPTURE_PID" 2>/dev/null || die "the capture did not start: $(cat "$OUT/dumpcap.log")"
		sleep 0.1
	done
	docker exec "$CLIENT" test -s /tmp/sender.pcapng || die "the capture did not start"

	echo "wire: running TestWire on both hosts..."
	# The last case sends the sentinels that prove the capture complete; it
	# runs whatever -run selects.
	subtests=""
	if [ -n "$RUN" ]; then
		subtests="($RUN)|^capture-sentinel\$"
	fi
	run_roles wire TestWire "$subtests" || VERDICT=1

	# The capture socket hands packets over in blocks, each once it is full
	# or its timeout has passed; stopping the capture at once would lose the
	# last block, sentinels included. Wait for it.
	sleep 2
	docker exec "$CLIENT" sh -c 'kill -INT "$(cat /tmp/dumpcap.pid)"'
	status=0
	wait "$CAPTURE_PID" || status=$?
	CAPTURE_PID=""
	[ "$status" -eq 0 ] || die "the capture exited with status $status: $(cat "$OUT/dumpcap.log")"
	# Every packet the interfaces saw is in the capture: dumpcap reports
	# none dropped on either.
	[ "$(grep -c 'Packets received/dropped on interface' "$OUT/dumpcap.log")" -eq 2 ] ||
		die "dumpcap reported no statistics for both interfaces: $(cat "$OUT/dumpcap.log")"
	if grep 'Packets received/dropped on interface' "$OUT/dumpcap.log" | grep -Evq ': [0-9]+/0 '; then
		die "the capture lost packets: $(grep 'Packets received/dropped' "$OUT/dumpcap.log")"
	fi
	docker cp "$CLIENT:/tmp/sender.pcapng" "$OUT/sender.pcapng" >/dev/null

	echo "wire: analyzing the capture..."
	analyze_args=(-capture /tmp/sender.pcapng -facts /out/facts.wire.client.txt -facts /out/facts.wire.server.txt
		-mtu "$MTU" -summary /out/expected/wire-summary.txt)
	if [ -n "$RUN" ]; then
		analyze_args+=(-run "$RUN")
	fi
	docker exec "$CLIENT" /wire/wireanalyze "${analyze_args[@]}" | tee "$OUT/wire-report.txt" || VERDICT=1
fi

if [ "$ONLY" != wire ]; then
	echo "twohost: running TestTwoHost on both hosts..."
	run_roles twohost TestTwoHost "$RUN" || VERDICT=1
	{
		for role in client server; do
			grep -E '^[[:space:]]*--- (PASS|FAIL|SKIP): TestTwoHost/' "$OUT/twohost.$role.log" |
				sed -E "s/^[[:space:]]*/$role: /; s/ \([0-9.]+s\)$//"
		done
		cat "$OUT/facts.twohost.client.txt" "$OUT/facts.twohost.server.txt" | grep -v '^setup ' | sort
	} | sed -e "s/$CLIENT_A/client-a/g; s/$CLIENT_B/client-b/g; s/$SERVER_A/server-a/g; s/$SERVER_B/server-b/g" \
		>"$OUT/expected/twohost-summary.txt"
fi

if [ "$VERDICT" -ne 0 ]; then
	echo "run.sh: FAIL (artifacts in $OUT)" >&2
	exit 1
fi
echo "run.sh: PASS (artifacts in $OUT)"
