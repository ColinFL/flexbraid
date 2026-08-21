# netem integration harness

Linux-only test harness that realises the **Integration (Linux)** and
**Resilience** bullets of [docs/DESIGN.md §15](../../docs/DESIGN.md#15-testing-strategy):
`tc netem` simulates per-path loss / latency / jitter and hard link loss,
and the stack (server + client + local echo) runs on one box.

## Isolation (why not `lo`)

The harness puts the tunnel's WAN sockets on **two veth pairs inside a
throwaway network namespace** by default, so netem hits each tunnel direction
**exactly once per path** — and, crucially, each veth pair is an independent
"ISP" that can be degraded or killed on its own (that is what makes failover
testable). The probe/load generators and the inner echo stay on clean
loopback.

Applying netem to `lo` instead would whack the probe/echo legs too: a UDP
round trip crosses loopback up to 6 times (probe→client, client→server,
server→echo, echo→server, server→client, client→probe), so `loss 5%` becomes
≈26% end-to-end — and, worse, the losses on the probe/echo legs are **outside
the tunnel** and unrecoverable by FEC, which made the FEC-on check unpassable
no matter what the codec did.

Two-WAN topology (netns mode):

```
 root namespace                         netns "flexbraid-netem"
 ┌───────────────────────────┐          ┌─────────────────────────────┐
 │ server (listens .5:4096)  │  vfb0 ◄─► vfb1  (203.0.113.4/30, w1)   │
 │  wg_peer → 127.0.0.1:echo │  vfb2 ◄─► vfb3  (203.0.113.20/30, w2)  │
 │ probe/load run here for   │          │ client (2 WANs, loopback    │
 │ NETEM_IF mode             │          │  inner listen) + probe/load │
 └───────────────────────────┘          └─────────────────────────────┘
```

Each client WAN is pinned to its own veth (`iface` + `local_ip`, the same
mechanism a real multi-WAN client uses); w2 reaches the server via the
gateway on its own leg. The server's single `listen: 203.0.113.5:4096`
accepts both legs and replies per-path. `NETEM_IF=<real-interface>` runs a
simpler single-WAN topology (client on loopback, no netns) for a real
dedicated WAN; only checks 1–5 run there.

## What it checks

Every check below is run with its probe pass **and** (when `LOAD_MBPS > 0`, the
default) a **sustained-load pass** via `udp-load.py` that asserts low loss
*and* goodput ≥ 40% of the offered rate.

1. **Baseline** — no netem: loss ≈ 0 over the whole tunnel path.
2. **Lossy link, FEC off** — `netem loss 5%` per tunnel direction: probe loss
   is significant (≥3%, ~5–10% expected) — proves the link loss is visible
   end-to-end, not swallowed.
3. **Lossy link, FEC on** — same 5% with adaptive FEC: recovery to
   ≤ `EXPECT_LOSS` (default 2%) — the actual erasure-coding benefit.

> FEC mode is a **server** setting (`server.yaml` decides `fec.mode`); the
> harness restarts the stack with `mode: off` / `mode: adaptive` and the
> client adopts the announced parameters at connect — the same behaviour a
> real client shows. `server.yaml` deliberately omits `fec.max_loss_pct`:
> validation must default it (`DefaultMaxLossPct = 20`) rather than crash
> adaptive at startup.

### Known issue: adaptive FEC does not engage under sustained load (П5)

The harness's FEC-on load assertion (loss ≤ `EXPECT_LOSS`) **fails on the
current binary** for a real reason, not a harness bug. Measured on the VPS
field rig (netem `loss 5%` both directions, 20 Mbps load through two WANs):

| Server FEC mode | Load loss | RTT |
|---|---|---|
| `off` | 9.8% | ~52 ms |
| `adaptive` (idle 2–8 s first) | 9.7–9.9% | ~54 ms |
| `fixed` `fixed_overhead_pct: 50` | **0.6%** | ~86 ms |

So the RS codec and reconstruction are correct on the 2-WAN topology
(`fixed` recovers 5% loss to 0.6%), but `adaptive` never leaves
pass-through under load. Root cause (from code): the encoder's loss feed is
`wan.health.Loss()`, and both sources of that estimate are blind while
traffic flows — `keepaliveLoop` only counts a probe as missed when the path
is otherwise *silent* (liveness-by-traffic), and the FEC decoder's in-band
`TakeStreamStats` only reports loss at *coded-block* flushes (absent in
pass-through). The delivery buffer waits out the missing frames either way,
so FEC-on ≈ FEC-off until the loss estimate is allowed to come from real
traffic. **The FEC-on assertion is intentionally left at `EXPECT_LOSS` so
this stays a hard regression gate until the product is fixed.** Operational
mitigation: use `fec.mode: fixed` with a loss-appropriate overhead on lossy
links.
4. **Hard link loss** — `netem loss 100%` on **both** ISPs: tunnel goes dark
   (~100% probe loss), both processes survive (no crash under a dead path),
   and after the links are restored the tunnel re-recovers within a few
   seconds (the harness sets a short `recover_min` in `client.yaml` — the
   2-minute production default would make this check take too long).
5. **Delay / jitter** — `netem delay 30ms 10ms`: measured tunnel RTT
   reflects the applied delay (not hidden by buffering).
6. **Failover, idle** — ISP A (path 1) goes dark (`loss 100%` on its veth
   pair only): the health monitor marks w1 DOWN, the scheduler moves traffic
   to ISP B, probe loss stays ≈ 0; after A is restored the path re-enters
   rotation and load re-balances.
7. **Failover, under load** — a load pass crosses the cutover: loss through
   the transition is bounded (not catastrophic — the tunnel must keep
   switching, not collapse), the surviving single ISP then carries the full
   load loss-free, and after restore both ISPs are balanced again.

## Usage

Requires a Linux host with `tc` + `ip` (iproute2), `python3`, root (or
sudo), and a Go-built `flexbraid` binary. Run from the repo root:

```sh
# build the linux binary first
GOOS=linux GOARCH=amd64 go build -o dist/flexbraid-linux-amd64 ./cmd/flexbraid

# full run (default: veth+netns isolation, 40 probes)
tests/netem/run-netem.sh

# tune it; set LOAD_MBPS=0 to skip the sustained-load passes
FLEXBRAID_BIN=./dist/flexbraid-linux-amd64 \
COUNT=100 \
EXPECT_LOSS=1 \
LOAD_MBPS=0 \
tests/netem/run-netem.sh
```

Env knobs: `FLEXBRAID_BIN`, `COUNT`, `EXPECT_LOSS` (FEC-on ceiling, %),
`LOAD_MBPS` (load-pass rate; 0 disables load), `LOAD_DUR` (load-pass
seconds), `NETEM_IF` (real interface instead of the veth topology).

Exit code 0 = all checks passed; the script cleans up its own netns / veth /
netem discipline and background processes (including on failure, via a trap).

## Files

| File | Purpose |
|---|---|
| `run-netem.sh` | The harness: 2-WAN stack + netem + 7 checks (± load) + cleanup |
| `udp-probe.py` | Sends N UDP probes into the client's ingress socket and reports delivered / loss / min-avg-max RTT |
| `udp-load.py` | Sustained, paced UDP load into the same ingress socket; reports loss / RTT / goodput under load |
| `udp-echo.py` | Local echo the server's `wg_peer` points at (staging target, same pattern as docs/DEPLOY_OPNSENSE.md §6) |

## Failover semantics

The two veth pairs model two independent ISPs, each with its own loss / RTT
profile. "ISP A goes dark" is `netem loss 100%` on path A's pair only (both
directions). The client's per-WAN health monitor detects the silence
(`down_after_misses: 2` probes), the scheduler drops the dead WAN, and the
session — keyed by session ID, not source address — keeps flowing on ISP B.
Because the session is address-agnostic, the cutover never tears the tunnel;
the measured loss is only the in-flight traffic on the dead path during
detection.

## Observed behaviour worth knowing

- **Failover under load is real**: a 20 Mbps load crossing an ISP cutover
  loses only the in-flight share (~37% through the ~2.5 s detection window),
  then runs clean (0.8%) on the surviving single ISP and 0.0% after restore.
- **Delay/jitter at load vs the delivery buffer**: under a pure
  `delay 30ms 10ms` (no loss), a 20 Mbps load measured ~15% inner loss —
  the two paths' ~40 ms RTT spread exceeds `delivery.gap_timeout_ms`, so
  legitimately-reordered frames are released late and counted lost. Idle
  probes see 0%. This is the buffer's latency-vs-completeness tradeoff; a
  larger `gap_timeout_ms` trades latency for completeness where jittery
  multi-path links matter.
