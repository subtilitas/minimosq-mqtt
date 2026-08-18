#!/bin/sh
# End-to-end smoke test: run the tcp_broker example and talk to it with
# stock mosquitto clients. Exercises QoS 1 pub/sub, retained messages,
# and will delivery over a real TCP socket.
#
# Usage: tests/smoke_mosquitto.sh <path-to-tcp_broker> [port]
#
# Requires: mosquitto_pub, mosquitto_sub (package: mosquitto-clients)
#
# SPDX-License-Identifier: MIT
set -eu

BROKER_BIN="${1:?usage: smoke_mosquitto.sh <tcp_broker binary> [port]}"
PORT="${2:-18883}"
WORKDIR="$(mktemp -d)"
BROKER_PID=""
SUB_PID=""
VICTIM_PID=""

cleanup() {
    [ -n "$SUB_PID" ] && kill "$SUB_PID" 2>/dev/null || true
    [ -n "$VICTIM_PID" ] && kill "$VICTIM_PID" 2>/dev/null || true
    [ -n "$BROKER_PID" ] && kill "$BROKER_PID" 2>/dev/null || true
    rm -rf "$WORKDIR"
}

# Wait until a subscriber has actually connected before publishing to it.
# Sleeping a fixed amount instead is the classic way to get a test that
# passes locally and flakes on a loaded CI runner.
wait_for_subscription() {
    marker="$1"
    for _ in $(seq 1 100); do
        mosquitto_pub -p "$PORT" -t "$marker" -m probe 2>/dev/null || true
        if [ -s "$WORKDIR/ready.out" ]; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}
trap cleanup EXIT INT TERM

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

command -v mosquitto_pub >/dev/null || fail "mosquitto_pub not found"
command -v mosquitto_sub >/dev/null || fail "mosquitto_sub not found"

"$BROKER_BIN" "$PORT" &
BROKER_PID=$!

# Wait for the broker to accept connections.
ready=""
for _ in $(seq 1 50); do
    if mosquitto_pub -p "$PORT" -t smoke/probe -m up 2>/dev/null; then
        ready=1
        break
    fi
    sleep 0.1
done
[ -n "$ready" ] || fail "broker did not come up on port $PORT"

# --- 1. QoS 1 pub/sub round trip -------------------------------------
mosquitto_sub -p "$PORT" -q 1 -t 'smoke/t' -C 1 -W 10 > "$WORKDIR/sub.out" &
SUB_PID=$!
sleep 0.5
mosquitto_pub -p "$PORT" -q 1 -t smoke/t -m 'roundtrip'
wait "$SUB_PID" || fail "qos1 subscriber timed out"
SUB_PID=""
[ "$(cat "$WORKDIR/sub.out")" = "roundtrip" ] || fail "qos1 payload mismatch"
echo "ok: qos1 pub/sub round trip"

# --- 2. Retained message delivered to a late subscriber --------------
mosquitto_pub -p "$PORT" -q 1 -t smoke/retained -m 'sticky' -r
out="$(mosquitto_sub -p "$PORT" -t smoke/retained -C 1 -W 10)"
[ "$out" = "sticky" ] || fail "retained payload mismatch (got: $out)"
echo "ok: retained delivery"

# --- 3. Will fires when a client dies abruptly -----------------------
rm -f "$WORKDIR/ready.out"
mosquitto_sub -p "$PORT" -t 'smoke/ready2' -C 1 -W 10 > "$WORKDIR/ready.out" &
READY_PID=$!
mosquitto_sub -p "$PORT" -t 'smoke/will' -C 1 -W 10 > "$WORKDIR/will.out" &
SUB_PID=$!
wait_for_subscription smoke/ready2 || fail "will subscriber never connected"
wait "$READY_PID" 2>/dev/null || true

# The victim must be fully connected before it is killed, or there is no
# session for the broker to fire a will from.
rm -f "$WORKDIR/ready.out"
mosquitto_sub -p "$PORT" -t 'smoke/ready3' -C 1 -W 10 > "$WORKDIR/ready.out" &
READY_PID=$!
mosquitto_sub -p "$PORT" -t 'smoke/nothing' \
    --will-topic smoke/will --will-payload 'client-died' --will-qos 1 &
VICTIM_PID=$!
wait_for_subscription smoke/ready3 || fail "will victim never connected"
wait "$READY_PID" 2>/dev/null || true

kill -9 "$VICTIM_PID"
VICTIM_PID=""
wait "$SUB_PID" || fail "will subscriber timed out"
SUB_PID=""
[ "$(cat "$WORKDIR/will.out")" = "client-died" ] || fail "will payload mismatch"
echo "ok: will delivery on abrupt disconnect"

echo "PASS: all smoke checks succeeded"
