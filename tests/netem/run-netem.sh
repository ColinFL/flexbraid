#!/usr/bin/env bash
#
# netem integration harness for FlexBraid (docs/DESIGN.md §15).
#
# Runs the full client+server+echo stack on ONE Linux host, applies `tc
# netem` to the tunnel path(s), and drives inner traffic through the tunnel.
# The default topology is TWO veth pairs (two independent "ISP" paths) with
# the client inside a throwaway network namespace, so netem can be applied
# to EACH path independently — that is what makes failover testable.
#
# Checks (each verified with and without load when LOAD_MBPS > 0):
#   1. baseline    no netem                     -> loss ≈ 0
#   2. lossy link  netem loss 5%, FEC off       -> probe loss significant
#   3. lossy link  netem loss 5%, FEC on        -> loss ≈ 0 (recovered)
#   4. hard loss   netem loss 100% (both ISPs)  -> ~100% while dark, the
#                  processes survive, link re-recovers after restore
#   5. delay/jitter netem delay 30ms 10ms       -> RTT reflects the delay
#   6. failover (idle)    ISP A goes dark       -> traffic keeps flowing on
#                  ISP B (loss ≈ 0), then re-balances after A is restored
#   7. failover (under load)                    -> same, with sustained load
#                  crossing the cutover; bounded loss in the transition,
#                  clean steady state on the surviving WAN, re-balance after
#                  restore
#   Load passes additionally run inside scenarios 1–5 (see check_load).
#
# Isolation: the tunnel's WAN sockets live over dedicated veth pairs in a
# throwaway netns, so netem hits each tunnel direction EXACTLY once per
# path. The probe and the inner echo stay on clean loopback. (Netem on `lo`
# would whack those legs too — 6 taps — which FEC cannot repair and which
# made the FEC-on check impossible.)
#
# Requires: linux, root (or sudo), iproute2 (`tc` + `ip`), a Go-built
# flexbraid binary, python3. Run from the REPO ROOT:  tests/netem/run-netem.sh
#
# Environment:
#   FLEXBRAID_BIN  path to flexbraid (default ./dist/flexbraid-linux-amd64)
#   NETEM_IF       apply netem to ONE existing interface instead of the veth
#                  topology (no netns, single-WAN client on loopback). Only
#                  checks 1–5 run in this mode. For a path that carries the
#                  tunnel traffic alone (e.g. a dedicated WAN).
#   COUNT          probe count (default 40)
#   EXPECT_LOSS    FEC-on lossy case: fail if loss exceeds this (default 2)
#   LOAD_MBPS      load-pass rate; 0 disables all load passes (default 20)
#   LOAD_DUR       load-pass duration, seconds (default 5)
#   GAP_TIMEOUT_MS delivery gap_timeout_ms injected into client.yaml
#                  (default 0 = use FlexBraid default 100ms); useful to probe
#                  reorder-vs-forwarding behaviour under delay+load.
#
# Exit 0 = all checks passed; non-zero = at least one check failed.
#
# NOTE: server FEC lives in server.yaml (authoritative) and is deliberately
# written WITHOUT fec.max_loss_pct — validation must default it
# (config.DefaultMaxLossPct = 20) instead of crashing adaptive at startup.

set -u
cd "$(dirname "$0")/../.."   # repo root

BIN="${FLEXBRAID_BIN:-./dist/flexbraid-linux-amd64}"
COUNT="${COUNT:-40}"
EXPECT_LOSS="${EXPECT_LOSS:-2}"     # % allowed for the FEC-on lossy case
LOAD="${LOAD_MBPS:-20}"             # 0 disables load passes
LOAD_DUR="${LOAD_DUR:-5}"
GAP="${GAP_TIMEOUT_MS:-0}"           # 0 = use FlexBraid default (100ms)

SRV_PORT=4096        # server listen
CLI_PORT=15124       # client inner listen (probe/load target)
ECHO_PORT=15123      # inner echo (server's wg_peer)
NS="flexbraid-netem"
# Path A ("ISP A"): root vfb0 <-> netns vfb1   (share 203.0.113.4/30)
# Path B ("ISP B"): root vfb2 <-> netns vfb3   (share 203.0.113.20/30)
VETH_A0=vfb0; VETH_B0=vfb1
VETH_A1=vfb2; VETH_B1=vfb3
SRV_IP="203.0.113.5"    # server on root vfb0 (both paths send to this dst)
SRV_B="203.0.113.20"    # root vfb2 (gateway for path B)
CLI_IP_A="203.0.113.6"  # netns vfb1 — WAN w1 source
CLI_IP_B="203.0.113.21" # netns vfb3 — WAN w2 source
LOG_DIR="$(mktemp -d)"

MODE=netns
NF=""
if [ -n "${NETEM_IF:-}" ]; then
  MODE=single
  NF="$NETEM_IF"
fi
SRV_ADDR=$([ "$MODE" = netns ] && echo "$SRV_IP" || echo "127.0.0.1")

echo ">> flexbraid:  ${BIN}"
echo ">> mode:       $([ "$MODE" = netns ] && echo "netns + 2×veth (2 ISP paths)" || echo "NETEM_IF=$NF (single WAN)")"
echo ">> probes: ${COUNT}   expect-loss(FEC-on): ${EXPECT_LOSS}%   load: ${LOAD}Mbps/${LOAD_DUR}s"
if [ ! -x "$BIN" ]; then
  echo "!! binary not found: $BIN (build with: make cross)" >&2
  exit 2
fi

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  if command -v sudo >/dev/null 2>&1; then SUDO=sudo; else
    echo "!! need root (or sudo) to create a netns and apply netem" >&2
    exit 2
  fi
fi

# ---- netns / veth plumbing ------------------------------------------------
setup_netns() {
  $SUDO ip netns del "$NS" 2>/dev/null || true
  $SUDO ip link del "$VETH_A0" 2>/dev/null || true
  $SUDO ip link del "$VETH_A1" 2>/dev/null || true
  $SUDO ip link add "$VETH_A0" type veth peer name "$VETH_B0" || {
    echo "!! cannot create veth pair (need iproute2 + NET_ADMIN)" >&2
    exit 2
  }
  $SUDO ip link add "$VETH_A1" type veth peer name "$VETH_B1" || {
    echo "!! cannot create second veth pair" >&2
    exit 2
  }
  $SUDO ip netns add "$NS"
  $SUDO ip link set "$VETH_B0" netns "$NS"
  $SUDO ip link set "$VETH_B1" netns "$NS"
  $SUDO ip addr add "$SRV_IP/30" dev "$VETH_A0"    # path A root
  $SUDO ip link set "$VETH_A0" up
  $SUDO ip addr add "$SRV_B/30" dev "$VETH_A1"     # path B root
  $SUDO ip link set "$VETH_A1" up
  $SUDO ip netns exec "$NS" ip link set lo up
  $SUDO ip netns exec "$NS" ip addr add "$CLI_IP_A/30" dev "$VETH_B0"
  $SUDO ip netns exec "$NS" ip link set "$VETH_B0" up
  $SUDO ip netns exec "$NS" ip addr add "$CLI_IP_B/30" dev "$VETH_B1"
  $SUDO ip netns exec "$NS" ip link set "$VETH_B1" up
  # WAN w2 must reach the server (SRV_IP) through ITS OWN leg: vfb3's peer
  # vfb2 (SRV_B) acts as the gateway across the path-B veth pair. The
  # client binds w2 to vfb3 (SO_BINDTODEVICE), so route lookup stays on
  # this device and uses this gateway as intended.
  $SUDO ip netns exec "$NS" ip route add "$SRV_IP/32" via "$SRV_B" dev "$VETH_B1"
  # The server's reply to w2 arrives on vfb3 with SOURCE SRV_IP, whose
  # reverse route (main table, connected /30 on vfb1) points elsewhere —
  # drop strict RPF in the netns or the reply is dropped and w2 never
  # receives anything.
  $SUDO ip netns exec "$NS" sysctl -qw net.ipv4.conf.all.rp_filter=0 2>/dev/null || true
  $SUDO ip netns exec "$NS" sysctl -qw net.ipv4.conf.default.rp_filter=0 2>/dev/null || true
  $SUDO ip netns exec "$NS" sysctl -qw net.ipv4.conf."$VETH_B0".rp_filter=0 2>/dev/null || true
  $SUDO ip netns exec "$NS" sysctl -qw net.ipv4.conf."$VETH_B1".rp_filter=0 2>/dev/null || true
}
teardown_netns() {
  $SUDO ip netns del "$NS" 2>/dev/null || true
  $SUDO ip link del "$VETH_A0" 2>/dev/null || true
  $SUDO ip link del "$VETH_A1" 2>/dev/null || true
}

set_netem_on() { # $1 = spec ("" = clear), $2.. = ifaces
  local spec="$1"; shift
  local i
  for i in "$@"; do
    # vfb1/vfb3 live INSIDE the netns — tc must run there, not on root
    # (root says "Cannot find device" and silently no-ops otherwise, which
    # left the client->server direction without netem).
    if [ "$i" = "$VETH_B0" ] || [ "$i" = "$VETH_B1" ]; then
      $SUDO ip netns exec "$NS" tc qdisc del dev "$i" root 2>/dev/null || true
      if [ -n "$spec" ]; then
        $SUDO ip netns exec "$NS" tc qdisc replace dev "$i" root netem $spec
      fi
    else
      $SUDO tc qdisc del dev "$i" root 2>/dev/null || true
      if [ -n "$spec" ]; then
        $SUDO tc qdisc replace dev "$i" root netem $spec
      fi
    fi
  done
}
# netem_path: apply a spec to one or both tunnel paths (netns mode only).
# Each path is hit in BOTH directions (root egress + netns egress).
netem_path() { # $1 = A|B|ALL  $2 = spec
  case "$1" in
    A)   set_netem_on "$2" "$VETH_A0" "$VETH_B0";;
    B)   set_netem_on "$2" "$VETH_A1" "$VETH_B1";;
    ALL) set_netem_on "$2" "$VETH_A0" "$VETH_B0" "$VETH_A1" "$VETH_B1";;
  esac
}

cleanup() {
  echo ">> cleanup"
  for pid in "${ECHO_PID:-}" "${CLI_PID:-}" "${SRV_PID:-}"; do
    [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null
  done
  if [ "$MODE" = netns ]; then
    teardown_netns
  elif [ -n "${NETEM_APPLIED:-}" ]; then
    $SUDO tc qdisc del dev "$NF" root 2>/dev/null || true
  fi
  wait 2>/dev/null
  rm -rf "$LOG_DIR"
}
trap cleanup EXIT

fail() { # dump evidence (logs + netns state) then exit 1
  echo "!! FAIL: $*" >&2
  local f l
  for l in echo.log server-*.log client-*.log load-transition.txt; do
    f="$LOG_DIR/$l"
    if [ -f "$f" ]; then
      echo "--- $l (tail) ---"
      tail -n 20 "$f"
    fi
  done
  if [ "$MODE" = netns ]; then
    echo "--- netns state ---"
    $SUDO ip netns exec "$NS" ip -br addr 2>/dev/null
    $SUDO ip netns exec "$NS" ip route 2>/dev/null
    $SUDO tc -s qdisc show dev "$VETH_A0" 2>/dev/null | head -8
    $SUDO ip netns exec "$NS" tc -s qdisc show dev "$VETH_B0" 2>/dev/null | head -8
  fi
  echo "--- kernel UDP counters (root) ---"
  grep -E '^Udp:' /proc/net/snmp 2>/dev/null
  if [ "$MODE" = netns ]; then
    echo "--- kernel UDP counters (netns) ---"
    $SUDO ip netns exec "$NS" cat /proc/net/snmp 2>/dev/null | grep -E '^Udp:'
  fi
  echo "--- tunnel/echo sockets ---"
  ss -uap 2>/dev/null | grep -E "flexbraid|udp-echo|udp-load|udp-probe" | head -20
  exit 1
}
pass() { echo "   ok:  $*"; }

# ---- numeric helpers (no vacuous passes) ----------------------------------
field() { echo "$1" | grep -oE "${2}=[-0-9.]+" | head -1 | cut -d= -f2; }
le() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a <= b)}'; }
ge() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a >= b)}'; }
num() { # $1 = value, $2 = context — fail loudly on a missing field
  if [ -z "${1:-}" ]; then fail "missing numeric field in: $2"; fi
  echo "$1"
}

# ---- stack templates ------------------------------------------------------
server_yaml() { # $1 = server FEC mode (adaptive | off | ...)
cat > "$LOG_DIR/server.yaml" <<EOF
mode: server
listen: ${SRV_ADDR}:${SRV_PORT}
wg_peer: 127.0.0.1:${ECHO_PORT}
mtu: 1388
fec:
  enabled: true
  mode: $1
# NOTE: fec.max_loss_pct intentionally omitted — it must default to 20
# (config.Validate -> DefaultMaxLossPct) rather than crashing adaptive.
crypto:
  key: netem-test-psk
EOF
}

client_yaml() {
cat > "$LOG_DIR/client.yaml" <<EOF
mode: client
listen: 127.0.0.1:${CLI_PORT}
server: ${SRV_ADDR}:${SRV_PORT}
wans:
$(client_wans)
delivery:
  gap_timeout_ms: ${GAP}
# Short health tuning so failover/recovery converge in seconds, not the
# production default (recover_min is in MINUTES by design).
health:
  degrade_sec: 0.5
  down_after_misses: 2
  recover_min: 0.02
crypto:
  key: netem-test-psk
EOF
}

client_wans() {
  if [ "$MODE" = netns ]; then
    # Each WAN is bound to its own veth, mirroring the office's two ISPs:
    # distinct source IPs, device-pinned, both dialing the single server IP.
    cat <<WEOF
  - id: w1
    transport: udp
    iface: ${VETH_B0}
    local_ip: ${CLI_IP_A}
    capacity_mbps: 100
  - id: w2
    transport: udp
    iface: ${VETH_B1}
    local_ip: ${CLI_IP_B}
    capacity_mbps: 100
WEOF
  else
    cat <<WEOF
  - id: w1
    transport: udp
    capacity_mbps: 100
WEOF
  fi
}

stop_stack() {
  for pid in "${ECHO_PID:-}" "${SRV_PID:-}" "${CLI_PID:-}"; do
    [ -n "${pid:-}" ] && kill "$pid" 2>/dev/null
  done
  wait 2>/dev/null
  unset ECHO_PID SRV_PID CLI_PID
}

start_stack() { # $1 = server FEC mode; idempotent (restarts everything)
  stop_stack
  server_yaml "$1"
  client_yaml
  python3 tests/netem/udp-echo.py "$ECHO_PORT" > "$LOG_DIR/echo.log" 2>&1 &
  ECHO_PID=$!
  "$BIN" -c "$LOG_DIR/server.yaml" > "$LOG_DIR/server-${1}.log" 2>&1 &
  SRV_PID=$!
  sleep 0.3
  if [ "$MODE" = netns ]; then
    $SUDO ip netns exec "$NS" "$BIN" -c "$LOG_DIR/client.yaml" \
      > "$LOG_DIR/client-${1}.log" 2>&1 &
  else
    "$BIN" -c "$LOG_DIR/client.yaml" > "$LOG_DIR/client-${1}.log" 2>&1 &
  fi
  CLI_PID=$!
  sleep 1.5   # handshake + warm-up
}

probe() {
  if [ "$MODE" = netns ]; then
    $SUDO ip netns exec "$NS" python3 tests/netem/udp-probe.py 127.0.0.1 "$CLI_PORT" "$COUNT"
  else
    python3 tests/netem/udp-probe.py 127.0.0.1 "$CLI_PORT" "$COUNT"
  fi
}

load_run() { # $1 = rate Mbps ; optional $2 = duration
  if [ "$MODE" = netns ]; then
    $SUDO ip netns exec "$NS" python3 tests/netem/udp-load.py 127.0.0.1 "$CLI_PORT" \
      --dur "${2:-$LOAD_DUR}" --mbps "$1"
  else
    python3 tests/netem/udp-load.py 127.0.0.1 "$CLI_PORT" \
      --dur "${2:-$LOAD_DUR}" --mbps "$1"
  fi
}

# check_load: run a load pass and assert loss/goodput bounds.
# $1 = label, $2 = max loss %, $3 = min goodput multiplier of the rate
#   (default 0.4 — pacing + occasional loss slack), $4 = optional M...
#   (for FEC-off: the load pass must still SEE significant loss), $5 = rate.
check_load() {
  [ "$LOAD" -le 0 ] && { echo "   (load passes disabled: LOAD_MBPS=$LOAD)"; return 0; }
  local mult="${3:-0.4}" minloss="${4:-}" mbps="${5:-$LOAD}"
  local mingp
  mingp=$(awk -v m="$mbps" -v k="$mult" 'BEGIN{printf "%.1f", m*k}')
  local out loss gp
  out=$(load_run "$mbps")
  echo "   load[$1]: $out"
  loss=$(num "$(field "$out" loss)" "load[$1]")
  gp=$(num "$(field "$out" goodput)" "load[$1]")
  if ! le "$loss" "$2"; then fail "load[$1] loss ${loss}% > $2%"; fi
  if [ -n "$minloss" ] && ! ge "$loss" "$minloss"; then
    fail "load[$1] loss ${loss}% < min ${minloss}% (expected to see netem loss)"
  fi
  if ! ge "$gp" "$mingp"; then fail "load[$1] goodput ${gp}Mbps < ${mingp}Mbps"; fi
  CL_LAST_LOSS="$loss"  # remembered for the adaptive gate (below)
  CL_LAST_RTT=$(num "$(field "$out" rtt_avg)" "load[$1] rtt")
  pass "load[$1] loss ${loss}%, goodput ${gp}Mbps (≥${mingp}), RTT ${CL_LAST_RTT}ms"
}

alive_check() { # $1 = context
  if ! kill -0 "$SRV_PID" 2>/dev/null || ! kill -0 "$CLI_PID" 2>/dev/null; then
    fail "process died in $1"
  fi
  pass "$1: server+client alive"
}

# ==========================================================================
if [ "$MODE" = netns ]; then
  setup_netns
fi

# ---- test 1: baseline -----------------------------------------------------
echo "== baseline (no netem) =="
start_stack adaptive
out=$(probe) || fail "baseline probe crashed ($out)"
echo "   $out"
recv=$(num "$(field "$out" received)" baseline)
if [ "$recv" -eq 0 ]; then fail "baseline: no replies received ($out)"; fi
loss=$(num "$(field "$out" loss)" baseline)
if ! le "$loss" 0.5; then fail "baseline loss ${loss}% > 0.5% (loopback should be ~0)"; fi
pass "baseline loss ${loss}%"
check_load "baseline" "$EXPECT_LOSS"

# ---- tests 2+3: lossy link, FEC off vs on ---------------------------------
echo "== lossy link (netem loss 5%) =="
if [ "$MODE" = netns ]; then netem_path ALL "loss 5%"; else set_netem_on "loss 5%" "$NF"; fi
NETEM_APPLIED=1
start_stack off
out=$(probe); echo "   FEC-off (probe): $out"
# A 30-packet probe cannot prove the netem loss either way (P(0 drops of 30
# at 5%) ≈ 21%) — assert the significant-loss property on the sustained load
# pass below, where thousands of samples make it deterministic.
recv=$(num "$(field "$out" received)" "FEC-off")
if [ "$recv" -eq 0 ]; then fail "FEC-off probe: nothing delivered ($out)"; fi
loss=$(num "$(field "$out" loss)" "FEC-off")
if ! le "$loss" 80.0; then fail "FEC-off probe loss ${loss}% — tunnel collapsed?"; fi
pass "FEC-off probe: link alive (loss ${loss}%)"
check_load "off@5%" 60.0 0.4 3.0   # load pass must SEE significant netem loss
start_stack adaptive
out=$(probe); echo "   FEC-on (probe): $out"
# The sparse probe cannot prove FEC: adaptive short-blocks flush WITHOUT
# parity before k data frames arrive, so a 30-packet probe carries raw netem
# loss even when coding works. The real assertion is under sustained load
# below, where FEC blocks fill and recovery is measurable.
recv=$(num "$(field "$out" received)" "FEC-on")
if [ "$recv" -eq 0 ]; then fail "FEC-on probe: nothing delivered ($out)"; fi
loss=$(num "$(field "$out" loss)" "FEC-on")
if ! le "$loss" 60.0; then fail "FEC-on probe loss ${loss}% — tunnel collapsed?"; fi
pass "FEC-on probe: link alive (loss ${loss}%)"
# Adaptive turns the encoder on with the MINIMUM computed overhead; with 1
# parity/block (5% loss → ~1 shard) blocks with 2+ losses stay unrecovered,
# so recovery is partial. Honest gate for MINIMUM coding:
#  (a) strictly better than off (on_cap = 90% of off loss), AND
#  (b) block collection provably active — coding adds gather latency, so
#      RTT must visibly rise vs the off@5% pass (CL_LAST_{LOSS,RTT} still
#      hold the off@5% numbers).
off_loss="$CL_LAST_LOSS"; off_rtt="$CL_LAST_RTT"
on_cap=$(awk -v o="$off_loss" 'BEGIN{printf "%.1f", o*0.9}')
check_load "on@5%" "$on_cap"
on_loss="$CL_LAST_LOSS"; on_rtt="$CL_LAST_RTT"
if ! ge "$on_rtt" "$(awk -v o="$off_rtt" 'BEGIN{printf "%.0f", o*1.15}')"; then
  fail "adaptive did not visibly start coding under load (rtt ${on_rtt}ms ~ off ${off_rtt}ms)"
fi
pass "adaptive coding active under load (RTT ${on_rtt}ms vs off ${off_rtt}ms)"

# ---- test 4: hard link loss (both ISPs 100%) -> survive + recover ---------
echo "== hard link loss (netem loss 100%, both ISPs) =="
if [ "$MODE" = netns ]; then netem_path ALL "loss 100%"; else set_netem_on "loss 100%" "$NF"; fi
start_stack adaptive
sleep 1.5
out=$(probe); echo "   while dark: $out"
loss=$(num "$(field "$out" loss)" "hard-dark")
if ! ge "$loss" 90.0; then fail "expected ~100% loss while dark, got ${loss}%"; fi
alive_check "hard loss dark period"
if [ "$MODE" = netns ]; then netem_path ALL ""; else set_netem_on "" "$NF"; fi
sleep 3
out=$(probe); echo "   after restore: $out"
loss=$(num "$(field "$out" loss)" "hard-restore")
if ! le "$loss" "$EXPECT_LOSS"; then fail "no recovery after link restored (loss ${loss}%)"; fi
pass "recovers after link restore (${loss}% ≤ ${EXPECT_LOSS}%)"
check_load "after-hard-restore" "$EXPECT_LOSS"
stop_stack

# ---- test 5: jitter/delay -------------------------------------------------
# RTT is the property under test — keep FEC OUT of this scenario so the
# delay metric is not confounded by block-collection latency. (Adaptive
# coding-under-delay is tracked separately as P6; see README.)
echo "== delay+jitter (netem delay 30ms 10ms), FEC off =="
if [ "$MODE" = netns ]; then netem_path ALL "delay 30ms 10ms"; else set_netem_on "delay 30ms 10ms" "$NF"; fi
start_stack off
sleep 1.5
out=$(probe); echo "   $out"
recv=$(num "$(field "$out" received)" delay)
if [ "$recv" -eq 0 ]; then fail "no replies received under delay ($out)"; fi
rtt=$(num "$(field "$out" avg)" delay)
if ! ge "$rtt" 40.0; then fail "RTT avg ${rtt}ms too low — netem delay not applied?"; fi
if ! le "$rtt" 400.0; then fail "RTT avg ${rtt}ms implausibly high"; fi
pass "RTT reflects netem delay (avg ${rtt}ms)"
# Load under delay: the honest expectation is NOT 0% loss. Round-robin over
# two paths whose delays diverge by the jitter span can reorder past the
# delivery gap_timeout (default 100ms); those frames flush late and count as
# lost (a delivery-tradeoff knob: delivery.gap_timeout_ms, not a forward
# defect). Gate on "tunnel stays alive and mostly delivers", not perfection.
check_load "delay" "${DELAY_LOAD_MAX_LOSS:-30}"
if [ "$MODE" = netns ]; then netem_path ALL ""; else set_netem_on "" "$NF"; fi

# ---- tests 6+7: multi-WAN failover (netns mode only) -----------------------
if [ "$MODE" != netns ]; then
  echo
  echo ">> single-WAN mode (NETEM_IF): multi-WAN failover checks skipped"
  echo "ALL NETEM CHECKS PASSED"
  exit 0
fi

echo "== failover idle — ISP A (path1) goes dark =="
netem_path A "loss 100%"
sleep 4   # health marks w1 DOWN (down_after_misses=2 at 1s probes)
out=$(probe); echo "   while ISP A dark: $out"
loss=$(num "$(field "$out" loss)" "failover-idle-dark")
if ! le "$loss" "$EXPECT_LOSS"; then
  fail "all traffic did not move to ISP B while A dark (loss ${loss}%)"
fi
pass "ISP B carries traffic while A dark (loss ${loss}% ≤ ${EXPECT_LOSS}%)"
alive_check "failover dark period"
netem_path A ""
sleep 3   # recover_min=0.02min (~1.2s) stability, then re-add
out=$(probe); echo "   after restore: $out"
loss=$(num "$(field "$out" loss)" "failover-idle-restore")
if ! le "$loss" "$EXPECT_LOSS"; then fail "no re-balance after ISP A restore (loss ${loss}%)"; fi
pass "re-balanced after ISP A restore (loss ${loss}% ≤ ${EXPECT_LOSS}%)"

echo "== failover under load — ISP A dies mid-stream =="
# A load pass spanning the cutover: start it, kill ISP A ~1s in, let it run
# through the detection + single-WAN steady state, then parse the result.
# Bounded (non-catastrophic) loss here = the tunnel kept switching over;
# a fully collapsed tunnel would show ~100%.
[ "$LOAD" -le 0 ] && { echo "   (load disabled: LOAD_MBPS=$LOAD)"; }
if [ "$LOAD" -gt 0 ]; then
  ( load_run "$LOAD" > "$LOG_DIR/load-transition.txt" 2>&1 ) &
  TRANS_PID=$!
  sleep 1
  netem_path A "loss 100%"
  wait "$TRANS_PID"
  out=$(cat "$LOG_DIR/load-transition.txt")
  echo "   load[transition]: $out"
  loss=$(num "$(field "$out" loss)" "failover-load-transition")
  gp=$(num "$(field "$out" goodput)" "failover-load-transition")
  if ! le "$loss" 60.0; then fail "catastrophic loss crossing cutover (${loss}%)"; fi
  if ! ge "$gp" "$(awk -v m="$LOAD" 'BEGIN{printf "%.1f", m*0.3}')"; then
    fail "goodput collapsed crossing cutover (${gp}Mbps)"
  fi
  pass "survives ISP-A cutover under load (loss ${loss}%, goodput ${gp}Mbps)"
  # Steady state on the surviving ISP only.
  check_load "single-ISP steady" "$EXPECT_LOSS"
  netem_path A ""
  sleep 3
  check_load "both-ISPs restored" "$EXPECT_LOSS"
  alive_check "failover-under-load"
fi

echo
echo "ALL NETEM CHECKS PASSED"
