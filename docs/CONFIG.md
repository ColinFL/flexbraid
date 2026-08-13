# FlexBraid — Configuration Reference

FlexBraid is configured with a single YAML file, passed with `-c path.yaml`.
Every setting has a sane default; you only need to write what differs.

> ⚠️ **WIP:** config parsing/validation are implemented. The data-path settings
> below take effect as milestones land (see [Roadmap](DESIGN.md#14-roadmap)).

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
mtu: 1420             # inner MTU advertised to WireGuard (default 1420)
scheduler: {...}
fec: {...}
wans: [ ... ]
health: {...}
crypto: {...}
log: {...}
```

---

## `scheduler`

```yaml
scheduler:
  mode: lb            # "lb" (active load balance, default) | "standby" (warm standby)
  affinity: flow      # "flow" (per-connection, default) | "packet" (per-frame)
  balance_by: capacity  # lb only: "capacity" | "fec" | "roundrobin"
  queue:
    max_pkts: 1024      # bounded per-WAN send queue depth (BDP-aware)
    rate_limit_mbps: 0  # 0 = use each WAN's capacity_mbps
    drop: drop-oldest   # on overflow: "drop-oldest" (TCP) | "drop-newest" (games)
```

- `mode: lb` — spread frames across all healthy WANs.
- `mode: standby` — one WAN hot, the rest warm standbys (near-zero-loss
  failover, no load splitting).
- `affinity`:
  - `flow` *(default)* — each inner flow sticks to one WAN; no intra-connection
    reordering; per-WAN FEC is coherent.
  - `packet` — distribute packet-by-packet (aggregate throughput; needs the
    delivery buffer; required for `fec.mode: crosspath`).
- `balance_by`:
  - `capacity` *(default)* — weight each WAN by its declared `capacity_mbps`.
  - `fec` — like `capacity` but subtract per-path adaptive FEC overhead first.
  - `roundrobin` — ignore weights, rotate evenly.
- `queue` — per-WAN send queue discipline (§7.6 of the design): bounded depth,
  optional explicit rate limit, and overflow drop policy.

---

## `fec` (forward error correction — **can be fully disabled**)

```yaml
fec:
  enabled: true        # false disables erasure coding entirely
  mode: adaptive       # "adaptive" | "fixed" | "off" | "crosspath"
  max_loss_pct: 20     # compensable random-loss % per path (0–90)
  block_timeout_ms: 8  # block collection window; larger n = more latency
  fixed_overhead_pct: 25  # used only when mode: fixed
```

- `enabled: false` or `mode: off` — no parity frames; the link's raw loss is
  accepted (useful on clean lines / latency-critical low-bandwidth use).
- `adaptive` *(recommended)* — redundancy follows measured loss; a clean WAN
  carries near-zero overhead.
- `fixed` — constant `fixed_overhead_pct` redundancy.
- `crosspath` — code erasure blocks across all WANs to survive a whole-WAN
  loss (costs capacity). **Requires `scheduler.affinity: packet`.**

> FEC repairs **random loss within a working path**; it cannot survive a full
> WAN cutover by itself unless `mode: crosspath` is used (see
> [DESIGN.md §6](DESIGN.md#6-forward-error-correction-adaptive-optional)).

Compensable-loss math:

| max_loss_pct | RS approx | overhead |
|---:|---:|---:|
| 5  | 19:1 | ~5.3% |
| 10 | 9:1  | ~11%  |
| 20 | 4:1  | ~25%  |
| 30 | 7:3  | ~43%  |

> FEC repairs **random loss within a working path**; it cannot survive a full
> WAN cutover by itself (see cross-path FEC in [DESIGN.md §6.4](DESIGN.md#64-optional-cross-path-fec)).

---

## `wans` — one entry per physical uplink (any number)

```yaml
wans:
  - id: w1
    transport: faketcp   # "udp" | "faketcp" | "icmp"
    iface: igc1          # bind device (optional, improves perf)
    capacity_mbps: 300   # declared bandwidth → drives capacity-weighted balancing
    weight: 1.0          # manual multiplier (default 1.0)
    fec_max_loss_pct: 20 # optional per-path FEC override (default: global)
  - id: w2
    transport: udp
    iface: igc0
    capacity_mbps: 100
```

- **`capacity_mbps`** — how much FlexBraid trusts this WAN to carry. With
  `balance_by: capacity`, a 300 Mbps WAN gets ~3× the share of a 100 Mbps one.
- **`transport`** — wire format on this WAN. `faketcp`/`icmp` useful where
  UDP is blocked/QoS'd.
- `fec_max_loss_pct` overrides the global FEC cap per path (e.g. a flaky LTE
  link can carry more redundancy).

---

## `health` — monitoring & circuit breaker

```yaml
health:
  loss_alpha_fast: 0.4  # fast-rise EWMA weight (reacts to spikes instantly)
  loss_alpha_slow: 0.03 # slow-decay EWMA weight (settles down slowly)
  jitter_alpha: 0.1     # jitter EWMA weight
  degrade_sec: 3        # sustained loss above FEC cap → DEGRADED
  down_grace_sec: 1     # drain window before hard disable
  recover_min: 2        # stability window before a path is restored
  probe_interval: 5     # active keepalive period while DOWN
```

The effective loss score is `max(L̂_fast, L̂_slow)` → jumps up on a burst but
takes a while to declare a path healthy again. This is the
"exponential weight" that prevents flip-flopping.

---

## `crypto`

```yaml
crypto:
  key: "change-me"            # shared PSK (REQUIRED); AEAD keys derived from it
  cipher: chacha20poly1305    # "chacha20poly1305" | "aes256gcm"
  integrity_only: false       # true = Poly1305 MAC only (WG already encrypts inner data)
```

---

## `log`

```yaml
log:
  level: info   # debug | info | warn | error
  file: ""      # empty = stderr
```
