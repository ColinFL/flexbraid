# FlexBraid — Configuration Reference

FlexBraid is configured with a single YAML file, passed with `-c path.yaml`.
Every setting has a sane default; you only need to write what differs.
Unknown keys are a hard error (`KnownFields`), so a typo never silently
disables a feature.

> **Status:** M4.1 (cross-path FEC) and M4.2a (FakeTCP transport)
> implemented on top of M3 (multi-WAN scheduler + health): per-WAN socket
> binding, in-band loss telemetry, silence watchdog, live-adaptive and
> cross-path FEC, `udp` + `faketcp` wire formats.

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
mtu: 1388             # inner MTU. With FEC on: 1500 − 44 (frame+AEAD) − 68
                      # (parity sub-header, k=10) = 1388; 1420 only with FEC
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
  mode: adaptive       # "adaptive" | "fixed" | "off" | "crosspath"
  data_shards: 10      # data frames per RS block (2–64)
  max_loss_pct: 20     # compensable random-loss % per path (0–90)
  block_timeout_ms: 8  # block collection window; adds latency
  fixed_overhead_pct: 25  # used only when mode: fixed
```

- `enabled: false` or `mode: off` — no parity frames; the link's raw loss
  is accepted (useful on clean lines / latency-critical use). With FEC
  disabled the health monitor's degrade threshold drops to a 1% noise
  floor: **any** sustained loss degrades the path.
- `adaptive` *(default)* — **live-adaptive FEC**: the encoder measures the
  path's loss (keepalive + in-band telemetry) and only codes when there is
  something to repair:
  - loss below `adapt_min_loss_pct` → **pass-through**: zero latency, zero
    overhead (a clean link runs exactly like `fec.enabled: false`);
  - loss at/above the threshold → coding turns on with redundancy sized to
    the current loss (theoretical L/(1−L) × 1.3 safety margin), capped by
    `max_loss_pct`;
  - `adapt_hold_sec` prevents flapping (once coding is on, it stays on for
    at least that long); `adapt_resume_pct` is the lower bound to switch
    back off.
  Parity frames are self-describing, so both ends interleave pass-through
  frames and coded blocks without negotiation.
- `fixed` — constant `fixed_overhead_pct` redundancy, always on.
- `crosspath` — code erasure blocks across **all** WANs: the sender spreads
  each block's frames over every live path (smooth weighted round-robin), so
  a whole-WAN failure costs only its share of every block — recoverable via
  the parity when the redundancy covers it. **Requires
  `scheduler.affinity: packet`.** Costs capacity proportional to
  `protection_level`: 1.0 survives losing one whole WAN in a 2-WAN setup
  (2× wire traffic); 0.5 → ≥ ceil(k·0.5) parity per block (survives one of
  three WANs). Coding is always ON in this mode (pass-through would make a
  WAN loss unrecoverable); parity may grow further with measured loss.
  `protection_level` default: 0.5. **Implemented since M4.1.**
- `data_shards` — block size. When coding is active, sparse traffic (games
  ~50–200 pps) rarely fills a 10-frame block within `block_timeout_ms`, so
  blocks flush short without parity and FEC stays idle. For interactive
  traffic use `data_shards: 4` and `block_timeout_ms: 10–15` (adds ~10–15
  ms latency only while coding is actually on). Constraint:
  `data_shards + parity ≤ 256` (RS field bound).

Adaptive thresholds (defaults): `adapt_min_loss_pct: 2`, `adapt_resume_pct: 0.5`,
`adapt_hold_sec: 10`.

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
    transport: udp      # "udp" | "faketcp" (raw TCP disguise, root+RST
                        # suppression) | "icmp" (ping disguise, root, pull-mode)
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
- `transport` — wire format on this WAN. `udp` (default) or `faketcp`
  (server mode: the top-level `transport:` key). **`faketcp`** disguises the
  tunnel as TCP: IPv4+TCP segments with a simulated 3-way handshake and
  seq/ack walk (derived from udp2raw), for links that block or throttle
  UDP. Requirements:
  - **root / `CAP_NET_RAW`** on both ends (raw sockets, IPv4 only);
  - **RST suppression on BOTH ends** — the kernel answers the fake
    handshake with RST on the closed port, and NAT boxes tear down their
    mapping on RST. Linux:
    `iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP` (or the
    equivalent nftables rule); FreeBSD: `pf` — `pass out proto tcp flags RST`
    or a matching `block` rule;
  - the listen/connect port must not be used by a real TCP listener.
- **`icmp`** — the last-resort wire format: data rides in ICMP echo
  request/reply payloads, so a link that blocks UDP and TCP still carries
  the tunnel (DPI sees ordinary ping). **Pull model by nature**: a host may
  only send echo *replies*, so server→client data waits for the client's
  next request — with FlexBraid's keepalive probes flowing every
  `probe_interval` that is ≤1 s of added latency in the server→client
  direction. Requires root/`CAP_NET_RAW` (raw ICMP sockets), IPv4. The
  client's echo identifier is random per run.
  **Kernel-echo suppression (checksum marker):** a kernel answers every
  *well-formed* echo request, and the server's kernel would answer our own
  requests — indistinguishable from the flexbraid server's reply (same id,
  same source). The client therefore sends requests with a deliberately
  **corrupt ICMP checksum**: the server kernel stays silent (it requires a
  valid checksum), while the flexbraid server treats the corrupt checksum
  as the marker of an authentic client and answers it; replies carry a
  proper checksum. Honest ping traffic (valid checksum) is served by the
  kernel as usual and never answered by the flexbraid server. A middlebox
  that "fixes" ICMP checksums would break the marker — the link degrades to
  silent rather than to wrong data.
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

## `telemetry` (M5.1)

Both knobs default to **off** — a firewall box stays quiet unless you opt in.

```yaml
telemetry:
  listen: "127.0.0.1:9080"  # empty = off (no HTTP endpoint)
  path: /stats               # HTTP path for the JSON snapshot (default /stats)
  interval_sec: 0            # >0: periodic JSON snapshot via structured log
```

- The HTTP endpoint has **no auth** — bind it to loopback or a management
  network, never to an unbounded public address.
- The snapshot shape (JSON field names) is pinned by tests
  (`internal/tunnel/stats_test.go`): `mode`, `uptime_sec`, `wans[]`
  (id/transport/state/loss_pct/rtt_ms/jitter_ms/capacity_mbps/frames_sent/
  pongs/missed_probes/last_rx_age_ms), `fec` (cross_path/data_shards/
  blocks_sent/frames_lost/recovered/coding_on), `delivery` (pending/
  max_pending/drops). Server snapshots add `sessions`.

---

## `queue` (M5.3, §7.6)

Bounded per-WAN send queue + token-bucket rate limiter on the **client**
(the office box paces its multiple uplinks). WireGuard has no congestion
control, so without this a fast WAN can bufferbloat a slow one and memory
grows without bound.

```yaml
queue:
  enabled: true       # false disables the queue + rate limiter entirely
  max_bytes: 262144   # per-WAN outbound queue bound (BDP-ish memory guard)
  drop: oldest        # overflow policy: "oldest" | "newest"
  rate_limit: true    # pace each WAN to wans[].capacity_mbps (token bucket)
```

- Producers (ingress, FEC tick) are **non-blocking** — they only enqueue.
  A consumer goroutine per WAN owns the actual transport write.
- See `queue_drops` in the telemetry snapshot to watch overflow.

---

## Runtime reload (M5.2)

Send **SIGHUP** to a running `flexbraid` to re-read the config file. The
following are applied **live**:

- `scheduler` capacities (`wans[].capacity_mbps`) — reweights load balancing
- `delivery.gap_timeout_ms`, `delivery.max_pending`
- the whole `health` section (EWMA weights, thresholds, probe counts)
- `log.level`

Changes that would rebind sockets or renegotiate crypto are **rejected**
with `reload: change requires restart` and the process keeps its previous
settings: `listen`, `server`, `wg_peer`, `session_id`, `mtu`, `transport`,
`crypto`, the WAN **topology** (ids/transports/interfaces), FEC mode
(crosspath vs per-WAN) and scheduler mode/affinity/balance_by. Apply those
by restarting.

On a firewall you enable the service with the reload trigger via:
`kill -HUP $(cat /var/run/flexbraid.pid)` (rc.d) or
`systemctl kill -s HUP flexbraid` (Debian).

---

## Reserved (parsed, not yet used)

- `session_id` — the client currently always generates a random session ID;
  pinning a fixed ID is for M4+ (multi-client / stable NAT identity).
- `mtu` — used since M2 for startup validation (parity-frame headroom) and
  defense-in-depth drops of oversized inner datagrams. The admin still sets
  the WireGuard interface MTU manually to the same value.
