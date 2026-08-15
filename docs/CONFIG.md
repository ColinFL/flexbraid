# FlexBraid — Configuration Reference

FlexBraid is configured with a single YAML file, passed with `-c path.yaml`.
Every setting has a sane default; you only need to write what differs.
Unknown keys are a hard error (`KnownFields`), so a typo never silently
disables a feature.

> **Status:** M3 (multi-WAN scheduler + health) implemented, including the
> M3.1 hardening: per-WAN socket binding, in-band loss telemetry, silence
> watchdog, configurable delivery window and FEC geometry.

---

## Root keys

```yaml
mode: client          # "client" | "server"
listen: 0.0.0.0:51820 # client: where inner traffic (WireGuard) points at.
                      # server: where FlexBraid clients connect.
server: 203.0.113.1:4096   # (client only) server address:port
wg_peer: 127.0.0.1:51821   # (server only) inner WireGuard peer (egress target)
session_id: auto      # "auto" (random) | <hex>. Server keys sessions by this,
                      # NOT by source IP — this is what makes failover seamless.
mtu: 1390             # inner MTU. With FEC on: 1500 − 44 (frame+AEAD) − 66
                      # (parity sub-header, k=10) = 1390; 1420 only with FEC
                      # off. Validated at startup.
scheduler: {...}
fec: {...}
wans: [ ... ]
delivery: {...}
health: {...}
crypto: {...}
log: {...}
```

---

## `scheduler`

```yaml
scheduler:
  mode: lb              # "lb" (active load balance, default) | "standby"
  affinity: packet      # "packet" (per-frame, default) | "flow" (per-connection)
  balance_by: capacity  # lb only: "capacity" | "fec" | "roundrobin"
  capacity_cap_mbps: 0  # (server only) clamp on client-declared capacity
```

- `mode: lb` — spread frames across all healthy WANs, weighted by capacity.
- `mode: standby` — one WAN hot, the rest warm standbys (near-zero-loss
  failover, no load splitting). **The standby abandons a DEGRADED active
  path immediately** (loss beyond what FEC can repair) — it does not wait
  for a hard failure. Hierarchy: HEALTHY > DEGRADED > DOWN.
- `affinity`:
  - `packet` *(default)* — distribute packet-by-packet (aggregate
    throughput; needs the delivery buffer). With a single inner WireGuard
    flow this is the only mode that actually load-balances.
  - `flow` — each inner flow sticks to one WAN (no intra-connection
    reordering). With WireGuard inside, everything hashes to one WAN by
    design; useful for many independent inner flows (e.g. OpenVPN).
- `balance_by`:
  - `capacity` *(default)* — weight each WAN by its declared `capacity_mbps`.
  - `fec` — like `capacity` but subtract per-path FEC overhead first.
  - `roundrobin` — ignore weights, rotate evenly.
- `capacity_cap_mbps` — **server-side trust boundary**: the capacity a
  client declares in its handshake is untrusted input; the server clamps it
  to this value before weighting its own scheduling. `0` = trust the
  client (not recommended on shared servers).

---

## `fec` (forward error correction — **can be fully disabled**)

```yaml
fec:
  enabled: true        # false disables erasure coding entirely
  mode: adaptive       # "adaptive" | "fixed" | "off" | "crosspath"(M4)
  data_shards: 10      # data frames per RS block (2–64)
  max_loss_pct: 20     # compensable random-loss % per path (0–90)
  block_timeout_ms: 8  # block collection window; adds latency
  fixed_overhead_pct: 25  # used only when mode: fixed
```

- `enabled: false` or `mode: off` — no parity frames; the link's raw loss
  is accepted (useful on clean lines / latency-critical use). With FEC
  disabled the health monitor's degrade threshold drops to a 1% noise
  floor: **any** sustained loss degrades the path.
- `adaptive` *(default)* — redundancy computed once from `max_loss_pct`
  (live adaptation from measured loss is TODO(M4)).
- `fixed` — constant `fixed_overhead_pct` redundancy.
- `crosspath` — code erasure blocks across all WANs to survive a whole-WAN
  loss (costs capacity). **Requires `scheduler.affinity: packet`. Not
  implemented until M4.**
- `data_shards` — block size. Sparse traffic (games ~50–200 pps) rarely
  fills a 10-frame block within 8 ms, so blocks flush short without parity
  and FEC stays idle. For interactive traffic use `data_shards: 4` and
  `block_timeout_ms: 10–15` (adds ~10–15 ms latency, but parity actually
  flies). Constraint: `data_shards + parity ≤ 256` (RS field bound).

Compensable-loss math (random loss within a working path):

| max_loss_pct | RS approx | overhead |
|---:|---:|---:|
| 5  | 19:1 | ~5.3% |
| 10 | 9:1  | ~11%  |
| 20 | 4:1  | ~25%  |
| 30 | 7:3  | ~43%  |

> FEC repairs **random loss within a working path**; it cannot survive a
> full WAN cutover by itself (see cross-path FEC in
> [DESIGN.md §6.4](DESIGN.md#64-optional-cross-path-fec)).

---

## `wans` — one entry per physical uplink (any number)

```yaml
wans:
  - id: w1
    transport: udp      # "udp" (M3) | "faketcp" | "icmp" (M4)
    iface: igc1         # bind device (SO_BINDTODEVICE / IP_BOUND_IF)
    local_ip: 192.0.2.10  # bind source address (fallback)
    capacity_mbps: 300  # declared bandwidth → drives capacity-weighted balancing
    weight: 1.0         # manual multiplier (default 1.0)
    fec_max_loss_pct: 20  # optional per-path FEC override
  - id: w2
    transport: udp
    iface: igc0
    capacity_mbps: 100
```

- **Socket binding is mandatory for multi-WAN to work at all**: without it
  the kernel routes every socket through the default route and all WANs
  collapse onto one uplink. Two mechanisms, tried in order:
  1. `iface` — pin the socket to the device: `SO_BINDTODEVICE` (Linux) /
     `IP_BOUND_IF` (FreeBSD). Requires root / `CAP_NET_RAW`.
  2. `local_ip` — bind the source address instead (no privileges). Used as
     the automatic fallback when the device bind is denied; requires the
     address to be assigned to the box and OS policy routing to return
     traffic the same way.
  If `iface` is set but denied and `local_ip` is empty, startup fails with
  an explanatory error rather than silently degrading to single-WAN.
- **`capacity_mbps`** — how much FlexBraid trusts this WAN to carry. With
  `balance_by: capacity`, a 300 Mbps WAN gets ~3× the share of a 100 Mbps
  one. The server clamps it to `scheduler.capacity_cap_mbps` (see above).
- `transport` — wire format on this WAN. `faketcp`/`icmp` arrive in M4.
- `fec_max_loss_pct` overrides the global FEC cap per path (e.g. a flaky
  LTE link can carry more redundancy).

---

## `delivery` — in-order reassembly window (client side)

```yaml
delivery:
  gap_timeout_ms: 100   # max head-of-line blocking on a missing frame
  max_pending: 4096     # reorder-buffer bound (BDP guard)
```

With packet-level scheduling, frames arrive interleaved across paths; the
delivery buffer restores global order. A missing sequence stalls delivery
for at most `gap_timeout_ms`, then the hole is skipped (WireGuard and inner
TCP tolerate the resulting reorder far better than a stalled stream).

- `gap_timeout_ms` — must cover the **RTT skew between paths**. Cable
  (10 ms) + LTE (80 ms) mixes routinely need 100 ms+; a too-small window
  systematically drops the slow path's frames even with zero real loss.
  Trade-off: larger window = more added latency on gaps. Range 10–5000.
- `max_pending` — the buffer is bounded (BDP guard): beyond it the
  longest-waiting frame is dropped, so a stalled path cannot grow memory
  without bound. Range 64–1 048 576.

---

## `health` — monitoring & circuit breaker

```yaml
health:
  loss_alpha_fast: 0.4  # fast-rise EWMA weight (reacts to spikes instantly)
  loss_alpha_slow: 0.03 # slow-decay EWMA weight (settles down slowly)
  jitter_alpha: 0.1     # jitter EWMA weight
  degrade_sec: 3        # sustained loss above FEC cap → DEGRADED
  down_after_misses: 3  # consecutive unanswered probes → DOWN
  down_grace_sec: 1     # debounce before DOWN (anti-flap); 0 = immediate
  recover_min: 2        # stability window before a path is restored
  probe_interval: 1     # keepalive probe period (s)
```

Loss is measured from **two independent signals**:

1. **In-band** — the FEC decoder counts unrecovered loss on each path from
   real traffic. Two consecutive windows whose loss exceeds the FEC
   capacity force an instant DEGRADED — no probe latency. This is the
   primary signal under load.
2. **Probes** — keepalives every `probe_interval` (secondary; matters on
   idle links). A probe counts as missed only while the path is otherwise
   silent — a delayed PONG on a busy path is jitter, not loss, and must not
   trip the breaker. Total silence for ~3 intervals trips DOWN via the
   silence watchdog (works even when nothing at all arrives).

`down_grace_sec` debounces the DOWN transition (anti-flap on jittery
links): once the missed-probe threshold is reached, DOWN fires immediately
(0) or after the grace window — an answered probe cancels the pending
transition.

---

## `crypto`

```yaml
crypto:
  key: "change-me"            # shared PSK (REQUIRED); AEAD keys derived from it
  cipher: chacha20poly1305    # "chacha20poly1305" | "aes256gcm"
```

The tunnel always authenticates its own frames (header + payload) with an
AEAD — integrity-only shortcuts were removed in M3.1: WireGuard already
encrypts the inner payload, but the tunnel's own headers still need
authenticated integrity and anti-replay.

---

## `log`

```yaml
log:
  level: info   # debug | info | warn | error
  file: ""      # empty = stderr
```

---

## Reserved (parsed, not yet used)

- `session_id` — the client currently always generates a random session ID;
  pinning a fixed ID is for M4+ (multi-client / stable NAT identity).
- `mtu` — used since M2 for startup validation (parity-frame headroom) and
  defense-in-depth drops of oversized inner datagrams. The admin still sets
  the WireGuard interface MTU manually to the same value.
