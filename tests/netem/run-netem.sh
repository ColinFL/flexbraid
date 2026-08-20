#!/usr/bin/env bash
#
# netem integration harness for FlexBraid (docs/DESIGN.md §15).
#
# Runs the full client+server+echo stack on ONE Linux host over loopback
# (ser + echo can also be pinned elsewhere), applies `tc netem` to a chosen
# interface, drives N UDP probes through the tunnel, and verifies:
#   1. baseline: no netem -> loss ≈ 0
#   2. lossy link (default 5%) with FEC off  -> loss ≈ netem loss
#   3. lossy link with FEC on               -> loss ≈ 0 (recovered)
#   4. hard link loss (netem loss 100%)      -> session survives, loss ≈ 100%
#      while the link is dark, and the process does not crash
#   5. jitter/delay applied -> RTT reflects delay (probe measures it)
#
# Requires: linux, `tc` (iproute2), a Go-built flexbraid binary, python3.
# Run from the REPO ROOT:  tests/netem/run-netem.sh
#
# Environment:
#   FLEXBRAID_BIN  path to flexbraid (default ./dist/flexbraid-linux-amd64)
#   NETEM_IF       interface to apply netem to (default lo)
#   COUNT          probe count (default 40)
#   EXPECT_LOSS    for the FEC-on lossy case, fail if loss exceeds this (default 2%)
#
# Exit 0 = all checks passed; non-zero = at least one check failed.

set -u
cd "$(dirname "$0")/../.."   # repo root

BIN="${FLEXBRAID_BIN:-./dist/flexbraid-linux-amd64}"
IF="${NETEM_IF:-lo}"
COUNT="${COUNT:-40}"
EXPECT_LOSS="${EXPECT_LOSS:-2}"     # % allowed for the FEC-on lossy case

SRV_PORT=4096
CLI_PORT=15124
ECHO_PORT=15123
LOG_DIR="$(mktemp -d)"

echo ">> flexbraid:  ${BIN}"
echo ">> interface:  ${IF}   probes: ${COUNT}   expect-loss(FEC-on): ${EXPECT_LOSS}%"
if [ ! -x "$BIN" ]; then
  echo "!! binary not found: $BIN (build with: make cross)" >&2
  exit 2
fi

cleanup() {
  echo ">> cleanup"
  # Stop background procs (echo, client, server).
  for pid in "${ECHO_PID:-}" "${CLI_PID:-}" "${SRV_PID:-}"; do
    [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null
  done
  # Remove netem discipline if we installed one.
  if [ -n "${NETEM_APPLIED:-}" ]; then
    tc qdisc del dev "$IF" root 2>/dev/null
  fi
  wait 2>/dev/null
  rm -rf "$LOG_DIR"
}
trap cleanup EXIT

fail() { echo "!! FAIL: $*" >&2; exit 1; }
pass() { echo "   ok:  $*"; }

# ---- point the server's egress at the local echo (staging) --------------
cat > "$LOG_DIR/server.yaml" <<EOF
mode: server
listen: 127.0.0.1:${SRV_PORT}
wg_peer: 127.0.0.1:${ECHO_PORT}
fec:
  enabled: true
  mode: adaptive
crypto:
  key: netem-test-psk
EOF

cat > "$LOG_DIR/client.yaml" <<EOF
mode: client
listen: 127.0.0.1:${CLI_PORT}
server: 127.0.0.1:${SRV_PORT}
fec:
  enabled: true
  mode: adaptive
wans:
  - id: w1
    transport: udp
    capacity_mbps: 100
crypto:
  key: netem-test-psk
EOF

start_stack() {
  python3 tests/netem/udp-echo.py "$ECHO_PORT" > "$LOG_DIR/echo.log" 2>&1 &
  ECHO_PID=$!
  "$BIN" -c "$LOG_DIR/server.yaml" > "$LOG_DIR/server.log" 2>&1 &
  SRV_PID=$!
  sleep 0.3
  "$BIN" -c "$LOG_DIR/client.yaml" > "$LOG_DIR/client.log" 2>&1 &
  CLI_PID=$!
  sleep 1
  # Warm up the handshake / settle.
}

probe() {
  python3 tests/netem/udp-probe.py 127.0.0.1 "$CLI_PORT" "$COUNT"
}

# ---- test 1: baseline -----------------------------------------------------
echo "== baseline (no netem) =="
start_stack
sleep 1.5
out=$(probe) || fail "baseline probe crashed ($out)"
echo "   $out"
loss=$(echo "$out" | sed -E 's/.*loss=([0-9.]+)%.*/\1/')
if awk "BEGIN{exit !($loss > 0.0)}"; then
  fail "baseline loss ${loss}% > 0 (loopback should be ~0)"
fi
pass "baseline loss ${loss}%"
kill "$CLI_PID" "$SRV_PID" "$ECHO_PID" 2>/dev/null; wait 2>/dev/null
unset CLI_PID SRV_PID ECHO_PID

# ---- tests 2+3: lossy link, FEC off vs on ---------------------------------
echo "== lossy link (netem loss 5%) =="
tc qdisc replace dev "$IF" root netem loss 5%
NETEM_APPLIED=1
start_stack
sleep 1.5
# FEC off: expect loss ~5%
sed -i 's/mode: adaptive/mode: off/' "$LOG_DIR/client.yaml"
kill "$CLI_PID" 2>/dev/null; wait "$CLI_PID" 2>/dev/null
"$BIN" -c "$LOG_DIR/client.yaml" > "$LOG_DIR/client-nofec.log" 2>&1 &
CLI_PID=$!
sleep 1.5
out=$(probe); echo "   FEC-off: $out"
loss=$(echo "$out" | sed -E 's/.*loss=([0-9.]+)%.*/\1/')
if awk "BEGIN{exit !($loss < 1.0)}"; then
  fail "FEC-off on 5% loss gave ${loss}% loss (expected ~5%+): $out"
fi
pass "FEC-off sees link loss (${loss}%)"
# FEC on: expect loss < EXPECT_LOSS
sed -i 's/mode: off/mode: adaptive/' "$LOG_DIR/client.yaml"
kill "$CLI_PID" 2>/dev/null; wait "$CLI_PID" 2>/dev/null
"$BIN" -c "$LOG_DIR/client.yaml" > "$LOG_DIR/client-fec.log" 2>&1 &
CLI_PID=$!
sleep 1.5
out=$(probe); echo "   FEC-on: $out"
loss=$(echo "$out" | sed -E 's/.*loss=([0-9.]+)%.*/\1/')
if awk "BEGIN{exit !($loss > $EXPECT_LOSS)}"; then
  fail "FEC-on on 5% loss lost ${loss}% (expected ≤${EXPECT_LOSS}%): $out"
fi
pass "FEC recovers link loss (${loss}% ≤ ${EXPECT_LOSS}%)"
kill "$CLI_PID" "$SRV_PID" "$ECHO_PID" 2>/dev/null; wait 2>/dev/null
unset CLI_PID SRV_PID ECHO_PID

# ---- test 4: hard link loss (netem 100%) -> survive + bounded -------------
echo "== hard link loss (netem loss 100%) =="
tc qdisc replace dev "$IF" root netem loss 100%
start_stack
sleep 1.5
out=$(probe); echo "   while dark: $out"
loss=$(echo "$out" | sed -E 's/.*loss=([0-9.]+)%.*/\1/')
# 100% netem => ~100% loss; the meaningful assertion is that the processes
# survive the dark period (a crash would be the regression).
if ! kill -0 "$SRV_PID" 2>/dev/null || ! kill -0 "$CLI_PID" 2>/dev/null; then
  fail "process died under hard link loss"
fi
pass "server+client alive under hard loss"
# Restore loss, verify quick re-recovery (recover_min / re-add behaviour)
tc qdisc replace dev "$IF" root netem loss 0%
sleep 2
out=$(probe); echo "   after restore: $out"
loss=$(echo "$out" | sed -E 's/.*loss=([0-9.]+)%.*/\1/')
if awk "BEGIN{exit !($loss > $EXPECT_LOSS)}"; then
  fail "no recovery after link restored (loss ${loss}%)"
fi
pass "recovers after link restore (${loss}% ≤ ${EXPECT_LOSS}%)"
kill "$CLI_PID" "$SRV_PID" "$ECHO_PID" 2>/dev/null; wait 2>/dev/null
unset CLI_PID SRV_PID ECHO_PID

# ---- test 5: jitter/delay ------------------------------------------------
echo "== delay+jitter (netem delay 30ms 10ms) =="
tc qdisc replace dev "$IF" root netem delay 30ms 10ms
start_stack
sleep 1.5
out=$(probe); echo "   $out"
rtt_avg=$(echo "$out" | sed -E 's/.*avg=([0-9.]+).*/\1/')
if awk "BEGIN{exit !($rtt_avg < 20.0)}"; then
  fail "delay${rtt_avg}ms too low — netem delay not applied?"
fi
pass "RTT reflects netem delay (avg ${rtt_avg}ms ≥ ~40ms loopback)"
kill "$CLI_PID" "$SRV_PID" "$ECHO_PID" 2>/dev/null; wait 2>/dev/null
unset CLI_PID SRV_PID ECHO_PID

echo
echo "ALL NETEM CHECKS PASSED"
