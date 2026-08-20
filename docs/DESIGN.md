# FlexBraid — Design Document

> **Status:** Draft v0.2 (design decisions incorporated) · **Author:** ColinFL · **License:** MIT
> Companion documents: [ARCHITECTURE.md](ARCHITECTURE.md) · [PROTOCOL.md](PROTOCOL.md) · [CONFIG.md](CONFIG.md)

---

## 1. Vision

**FlexBraid is a user-space, multi-WAN bonding tunnel.** It weaves several
physically independent uplinks ("WANs") into a **single logical link**, so that
anything layered on top — most importantly **WireGuard**, but also raw game UDP
or TCP — experiences *one stable, loss-corrected, in-order connection*.

When any WAN degrades or dies, FlexBraid detects it itself (it does **not**
depend on OPNsense `WANFAIL`, `dpinger`, or any external monitor), shifts the
load to the surviving uplinks with **minimal packet loss**, and keeps every
inner connection alive. When the dead WAN stabilises again, FlexBraid
gracefully brings it back.

FlexBraid is inspired by — but is a clean reimplementation of the ideas behind —
[`udp2raw-tunnel`](https://github.com/wangyu-/udp2raw-tunnel) (transport
obfuscation, connection recovery, FakeTCP) and
[`UDPspeeder`](https://github.com/wangyu-/UDPspeeder) (Reed–Solomon FEC).

```
  WAN 1 ──┐
  WAN 2 ──┼──► FlexBraid client ──► (internet) ──► FlexBraid server ──► WG peer / internet
  WAN N ──┘        │  weave into one link           │
                   └────────────► one UDP socket ◄──┘
                                   for WireGuard
```

---

## 2. Goals & Non-Goals

### Goals
1. **Connection preservation.** A hard WAN cutover must not reset inner TCP
   sessions or game UDP sessions. Switch is fast enough to stay inside session
   timeouts (TCP: seconds; games: typically tens of seconds).
2. **Self-contained WAN health.** FlexBraid measures per-path RTT / loss /
   jitter from its own traffic and acts on them with a hysteresis
   (circuit-breaker) state machine. No reliance on OPNsense.
3. **Active load balancing, optionally warm standby.** Default scheduler is
   `lb` (spread traffic across WANs, weighted by declared bandwidth). `standby`
   mode keeps one WAN hot and the rest as warm standbys for near-zero-loss
   failover.
4. **Adaptive forward error correction, fully disable-able.** Reed–Solomon
   redundancy adapts to measured loss. FEC can be switched off completely.
5. **Cross-platform:** FreeBSD (OPNsense) **and** Linux (Debian) for both
   client and server.
6. **Configurable and observable.** Number of WANs, per-WAN bandwidth and
   transport, FEC % per channel, scheduler policy, and health thresholds are
   all tunable via a single YAML file, plus runtime control via signals/FIFO
   and per-path telemetry.

### Non-Goals (for now)
- Not a full router/firewall; FlexBraid is a **tunnel transport**, not a
  replacement for OPNsense routing.
- No built-in TCP congestion control — the inner protocol (WG, TCP, games)
  owns congestion behaviour.
- No kernel modules (user-space only; raw sockets used only where a transport
  mode requires them, e.g. FakeTCP).

---

## 3. Core Principle: "WireGuard sees one link"

The contract FlexBraid presents to the inner layer is the key design decision:

> **From the inner layer's perspective, FlexBraid is one reliable-ish UDP
> connection to one fixed endpoint.** The multi-WAN machinery is invisible.

To honour this, the FlexBraid data path guarantees the inner layer:
- **bounded loss** — erased/repaired by FEC;
- **in-order delivery** — enforced by a single *delivery buffer* (reorder +
  jitter in one window) on the server side;
- **bounded jitter** — the delivery buffer's tunable window absorbs the switch;
- **stable session identity** — sessions are keyed by a random `session_id`,
  **not** by the client's source IP, so moving between WANs (which changes the
  NAT mapping) does not tear the session down;
- **per-path endpoints** — in load-balance mode the server tracks a return
  address per WAN and answers on the same path, so several uplinks can be
  active at once (§9).

This is what lets WireGuard sit on top unchanged: WG keeps one peer, one
handshake, one endpoint — FlexBraid handles everything underneath.

### 3.1 Deployment topology
Two supported topologies:
- **(a) Co-located egress (recommended):** the WireGuard peer lives on the
  same host as the FlexBraid server (e.g. on the VPS); FlexBraid delivers
  reordered inner datagrams to WG over loopback, WG egresses to the internet.
  Simple, lowest latency, and matches the "office egresses via VPS" use case.
- **(b) Relay:** the FlexBraid server forwards inner datagrams to a WG peer
  elsewhere. Possible, but the inner path is no longer loopback; the design
  does not optimise for this initially.

### 3.2 Latency & reliability budget
Explicit targets that sizing must respect:
| Parameter | Budget |
|---|---|
| WAN failover (detect → switch) | **< 300 ms** (sub-second, inside TCP RTO and game session timeouts) |
| Delivery-buffer window | ~10 ms of buffering (tunable), sized ≥ inter-path latency skew + jitter |
| FEC `block_timeout_ms` | default 8 ms (adds at most this much latency) |
| Whole-WAN zero-loss survival | only via optional cross-path FEC, at capacity cost (never free) |

---

## 4. High-Level Architecture

```
                         FLEXBRAID CLIENT                          FLEXBRAID SERVER
┌───────────────────────────────────────────┐      ┌──────────────────────────────────────────┐
│  WireGuard / inner traffic (UDP)          │      │                                          │
│           │                               │      │                                          │
│           ▼                               │      │                                          │
│  ┌────────────────────┐                   │      │                   ┌────────────────────┐ │
│  │  Ingress listener  │                   │      │                   │  Egress / WG peer  │ │
│  │  (one UDP socket)  │                   │      │                   │  (one UDP socket)  │ │
│  └─────────┬──────────┘                   │      │                   └─────────▲──────────┘ │
│            │ sequence                     │      │                            │ in-order    │
│            ▼                              │      │                            ▼             │
│  ┌────────────────────┐   ┌───────────┐   │      │  ┌───────────────┐  ┌──────────────────┐ │
│  │   FEC encoder (RS) │──►│ scheduler │   │      │  │ reorder buffer│◄─┤  FEC decoder (RS)│ │
│  └────────────────────┘   └─────┬─────┘   │      │  └───────▲───────┘  └──────────────────┘ │
│                                 │         │      │          │                 ▲             │
│                ┌────────────────┼─────────┼──────┼──────────┼─────────────────┘             │
│                ▼                ▼         │      │          ▼                               │
│        ┌────────────┐   ┌────────────┐    │      │  ┌────────────────┐                      │
│        │ transport  │   │ transport  │    │      │  │ session manager│                      │
│        │udp/faketcp/│   │ udp        │    │      │  │ (session_id)   │                      │
│        │  icmp      │   │            │    │      │  └────────────────┘                      │
│        └─────┬──────┘   └─────┬──────┘    │      │                    ▲                     │
│              │  WAN 1         │  WAN 2    │      │                    │                     │
└──────────────┼───────────────┼────────────┘      └────────────────────┼─────────────────────┘
               ▼               ▼                                        │
          (internet path 1) (internet path 2) ──────── (internet) ──────┘

  Health monitor (client) observes every transport socket:
  EWMA loss / RTT / jitter → circuit-breaker state machine → scheduler + telemetry.
```

### Component responsibilities
| Component | Responsibility |
|---|---|
| **Ingress listener** | One UDP socket the inner layer points at. |
| **Sequence / session** | Assigns a monotonically increasing sequence number and the stable `session_id` to every frame. |
| **FEC encoder / decoder** | Reed–Solomon erasure coding over **per-WAN** blocks of frames (see §6). |
| **Scheduler** | Splits the coded frame stream across healthy WANs (see §7). |
| **Transport (per WAN)** | Pluggable wire format: `udp`, `faketcp`, `icmp`; handles encryption/auth per frame; owns the per-WAN socket and its send queue. |
| **Delivery buffer** | One combined reorder + jitter buffer on the server that restores global `seq` order and smooths latency before egress. |
| **Session manager** | Keys sessions by `session_id`; maintains **per-path endpoints**; survives endpoint changes. |
| **Health monitor** | Per-path loss/RTT/jitter estimation + circuit-breaker state machine (see §8). |
| **Telemetry / control** | Per-path stats, logging, runtime reconfiguration (SIGUSR1 reload, FIFO). |

---

## 5. Protocol & Packet Framing

A full wire-protocol spec lives in [PROTOCOL.md](PROTOCOL.md). Summary of the
frame layout (client → server and server → client are symmetric):

```
┌──────────┬────────────┬─────────────┬───────────┬─────────────────┬───────────┐
│  magic   │  version   │  session_id │  seq (u32)│payload len (u16)│  flags    │
│  (u32)   │  (u8)      │  (u64)      │           │                 │  (u8)     │
├──────────┴────────────┴─────────────┴───────────┴─────────────────┴───────────┤
│                     payload (inner data + FEC parity)                         │
├───────────────────────────────────────────────────────────────────────────────┤
│                     auth tag (Poly1305, over the header+payload)              │
└───────────────────────────────────────────────────────────────────────────────┘
```

- **`session_id`** — random 64-bit value chosen by the client at connect. The
  server uses it as the *only* identity for the tunnel. Source IP/port changes
  are ignored for session lookup → endpoint migration is seamless.
- **`seq`** — global, monotonically increasing across all WANs. Used by the
  delivery (reorder) buffer to restore order at the server.
- **`flags`** — bit 0: `FEC_PARITY` (this frame is a parity frame, not inner
  data); bit 1: `KEEPALIVE`; bit 2: `CONTROL` (control/RTT channel).
- **FEC blocks are built per WAN** — each path encodes *its own* frames into
  self-contained RS blocks (data + parity on the same path). This keeps
  within-path FEC coherent regardless of scheduler; cross-path FEC is a
  separate optional layer (§6.4). Within a block, `n` total frames of which
  `n−k` are parity; the block is recoverable if at least `k` arrive.
- **Anti-replay window ≥ delivery-buffer window** — a hard invariant so the
  replay filter never drops legitimate frames that the multi-path delivery
  deliberately reordered. Window is sized to the delivery buffer plus margin.
- **Control/RTT frames bypass FEC** — `CONTROL`/`KEEPALIVE` frames are sent
  directly on the path (not erasure-coded), so keepalive round-trip time is a
  clean RTT sample rather than one gated behind block decoding.

---

## 6. Forward Error Correction (adaptive, optional)

### 6.1 Why
Real uplinks drop packets. Without FEC a single dropped frame either loses
inner data or (for TCP inside) triggers a retransmission round-trip. FEC trades
a little bandwidth to remove most of that.

### 6.2 Model
Reed–Solomon **erasure code** RS(`n`, `k`): `k` data frames + `n−k` parity
frames per block. A block is fully recoverable if **at most `n−k` frames are
lost**. This is the same code family UDPspeeder uses.

**Blocks are constructed per WAN.** Each path's transport encodes *its own*
outbound frames into self-contained blocks (data + parity travel on the same
WAN). This is the fix for the FEC↔scheduler coupling (see §7.4): within-path
FEC is always coherent, no matter how the scheduler spreads frames. The
scheduler only ever hands frames to the FEC encoder of the chosen WAN.

Maximum compensable random loss rate:
```
L_max = (n − k) / n
```
Required redundancy overhead for a target loss rate `L`:
```
overhead = L / (1 − L)
```

| Target random loss `L` | RS config | Redundancy overhead |
|-----|-------:|-------:|
| 5%  | 19:1   | ~5.3%  |
| 10% | 9:1    | ~11%   |
| 20% | 4:1    | ~25%   |
| 30% | 7:3    | ~43%   |
| 50% | 1:1    | 100% (duplication) |
| 100% (whole WAN) | cross-path only | ∞ without cross-path FEC |

**Hard limits to design for:**
1. **Per-WAN FEC fixes random loss *within* a working path — it does not survive
   a full path cutover.** Because blocks are per-WAN, when a WAN dies its data
   *and* its parity die together. Surviving a whole-WAN loss with zero drop
   requires **cross-path erasure coding** (code across the aggregate so any
   surviving subset of WANs can reconstruct). This is an **optional advanced
   mode** (§6.4) that costs capacity proportional to the share you want to
   protect.
2. **FEC adds latency.** A block is only coded once `k` frames are collected
   (`block_timeout_ms`, default 8 ms). Larger `n` ⇒ more latency and more
   resilience to jitter.
3. **FEC is per-path tunable.** Different WANs may have different quality.

### 6.3 Adaptive redundancy
**M3.1 status: implemented.** In `mode: adaptive` the encoder is fed the
path's measured loss estimate (health monitor: keepalive EWMA + in-band
telemetry) via `Encoder.SetLossRate` and decides per period:

- loss below `adapt_min_loss_pct` (default 2%) → **pass-through**: frames
  leave immediately with `block_seq=0`, zero latency, zero overhead — a
  clean link costs nothing;
- loss at/above the threshold → coding on, redundancy sized live as

```
target_overhead = clamp( L̂ / (1 − L̂) * safety_margin,
                         ≥ 1 parity, max_loss_pct ceiling )
```

- `safety_margin` (1.3) keeps headroom above the measured loss;
- `adapt_hold_sec` (default 10 s) prevents flapping: once coding is on it
  stays on for at least that long even if loss vanishes;
- `adapt_resume_pct` (default 0.5%) is the lower bound to switch back off.

Transitions are safe on the wire: pass-through frames and coded blocks
interleave freely (parity sub-headers are self-describing, `block_seq=0`
delivers immediately — mixed-FEC decoder support). If the measured loss
exceeds what the configured FEC can compensate, the circuit breaker pulls
that WAN out of service (the FEC "limps along" first; the breaker handles
sustained overload).

### 6.4 Optional: cross-path FEC
A mode where RS blocks are spread across **all** WANs such that the block is
recoverable as long as a sufficient *fraction* of WANs survive. This is the
only way to reach true zero-loss on whole-WAN cutover, and it costs capacity
proportional to the share you protect. **It requires packet-level scheduling**
(§7.2) — flow-affine scheduling would defeat it, since each flow's data must
span multiple paths. Exposed as a knob: `fec.mode: crosspath` with a
`protection_level` (0.0 = none … 1.0 = full single-WAN protection).
**Default: off** — the common case (random loss + fast failover) needs only
per-WAN FEC plus the sub-second failover.

### 6.5 Disabling FEC entirely
`fec.enabled: false` (or `fec.mode: off`) turns off all erasure coding. Frames
then carry no parity; the scheduler still works; failover still preserves
connections; you simply accept the link's raw loss. Useful on clean links or
for latency-critical low-bandwidth use.

### 6.6 MTU & fragmentation
FlexBraid uses a **fixed inner MTU** with headroom for every per-frame cost.
The largest frame on the wire is a **parity frame**: payload + self-describing
parity sub-header + frame header + AEAD tag, and it must fit the path MTU
without IP fragmentation (a lost fragment would defeat FEC entirely):
```
inner_mtu = min_path_mtu − frame_header(28) − auth_tag(16) − parity_subheader(k)
parity_subheader(k) = 8 + 4k + 2k      # k = data shards (default 10 → 68 B)
```
- On a 1500-byte path with k=10: `1500 − 44 − 68 = 1388`. With FEC off the
  parity sub-header disappears: `1500 − 44 = 1456` (1420 stays a safe default).
- **M2 status:** enforced at startup — config validation rejects an `mtu` whose
  parity frames would exceed the 1500-byte path MTU, and oversized inner
  datagrams are dropped (defense-in-depth).
- The `DF` bit is set; FlexBraid **never fragments** coded frames in the
  tunnel. Inner PMTUD (WireGuard handles this) adapts to the advertised MTU.
- Per-path PMTU discovery is a future refinement (§10) for heterogeneous paths;
  v1 uses a conservative fixed value (`mtu` config, default 1420 without FEC).

---

## 7. Packet Scheduler (load balancer)

Two independent axes control how traffic is spread:
- **`scheduler.mode`** — *how many* WANs carry data: `lb` (all healthy, default)
  or `standby` (one hot, rest warm).
- **`scheduler.affinity`** — *granularity*: `flow` (default) or `packet`.

### 7.1 `mode: lb` + `affinity: flow` (default)
Inner flows (TCP 4-tuples, per-game-session UDP) are hashed onto a WAN via
consistent hashing, so a connection sticks to one path while healthy (no
intra-connection reordering). Shares are weighted by `balance_by`:
- **`capacity` (default)** — `share_i = weight_i * capacity_i / Σ(weight_j * capacity_j)`
  (bandwidth-aware: a 300 Mbps WAN carries ~3× a 100 Mbps one).
- **`fec`** — subtract each path's adaptive FEC overhead before weighting
  (heavy-FEC paths get a smaller share).
- **`roundrobin`** — ignore weights, rotate evenly.

When a WAN is pulled, only its flows move; consistent hashing keeps the
reshuffle minimal. Because flows stay on one path, **per-WAN FEC blocks fully
protect each flow's random loss** (§6.2).

### 7.2 `mode: lb` + `affinity: packet`
Frames are distributed packet-by-packet across healthy WANs — the best profile
for aggregate throughput of a few fat flows. Requires the server's delivery
buffer to restore order. **Cross-path FEC (§6.4) is only meaningful in this
mode**, because blocks span multiple paths.

### 7.3 `mode: standby` — warm standby
One WAN active (highest priority/weight); the rest kept **warm** (transport up,
keepalives flowing, FEC live) but idle. On failure the scheduler switches to
the next warm standby — a near-instant data-plane change, no cold handshake.
The server keeps a per-path endpoint, so the switch needs no re-handshake.
This is the "minimal loss, no load splitting" profile.

### 7.4 FEC ↔ scheduler coupling (invariant)
Within-path FEC is coherent only when a block stays on one path. Enforcement:
- `affinity: flow` → **per-WAN FEC blocks** (data + parity on the same path).
  Always coherent.
- `affinity: packet` + `fec.mode: crosspath` → blocks are **spread across
  paths by design** (smooth weighted round-robin, §6.4); the receiver keys
  blocks by session, so per-frame path choice is invisible to reassembly.
- `affinity: packet` + per-WAN FEC → per-WAN FEC is meaningless; use
  **cross-path FEC** (§6.4) instead.
The scheduler never splits a per-WAN FEC block across paths — it hands complete
blocks to the chosen WAN's encoder. Cross-path mode is the explicit exception:
it hands *individual frames* of a block to the WRR picker.

### 7.5 Graceful drain
Before a degraded WAN is disabled, stop scheduling new flows onto it and let
in-flight frames drain. Reduces loss versus an abrupt cut. In `lb` mode a
DEGRADED path keeps a token weight (0.2) so in-flight work finishes; in
`standby` mode the scheduler switches to the next HEALTHY path immediately.
`health.down_grace_sec` additionally debounces the DOWN transition itself
(anti-flap), so a flapping link does not slam the scheduler between states.

### 7.6 Queueing & backpressure (M5.3)
WireGuard has no congestion control, so FlexBraid owns the queue
discipline (**implemented on the client** — the office box paces its
uplinks):
- **Bounded per-WAN send queue**, sized by `queue.max_bytes` (BDP-ish),
  never unbounded.
- **Rate limiter** per WAN at its declared `capacity_mbps` (token bucket)
  so a fast WAN cannot bufferbloat a slow one.
- **Drop policy on overflow:** `drop-oldest` for TCP-ish flows,
  `drop-newest` for real-time UDP (games want the latest state).
- **No full backpressure to the ingress:** WG/UDP cannot be throttled
  upstream, so producers only enqueue; drops happen at the queue bound.

The server side (a single shared trunk) is not rate-paced yet; the
delivery buffer's `max_pending` bound provides its memory guard.

---

## 8. Health Monitoring & Circuit Breaker

The health monitor is the "self-contained WANFAIL" — FlexBraid decides link
state from its **own** traffic, no OPNsense dependency.

### 8.1 Per-path metrics
- **Loss** — derived from gaps in the received `seq` stream (passive) and from
  keepalive echoes (active).
- **RTT** — from timestamps echoed in `CONTROL`/`KEEPALIVE` frames, which are
  sent **directly on the path and bypass FEC** (§5), so the sample is a clean
  round-trip time, not one gated behind block decoding.
- **Jitter** — EWMA of inter-arrival time variance (games die on jitter before
  loss).

### 8.2 Exponential weighting ("fast rise, slow decay")
Two EWMA filters per path:
```
L̂_fast = α_fast·L + (1−α_fast)·L̂_fast     # α_fast ~ 0.4  — reacts to spikes instantly
L̂_slow = α_slow·L + (1−α_slow)·L̂_slow     # α_slow ~ 0.03 — settles down slowly
```
The effective score is the **max** of the two, giving the desired behaviour:
jump up immediately on a burst, but take a while to declare a path healthy
again after recovery. This is the formalisation of an "exponential weight"
that refuses to flip-flop.

### 8.3 State machine
```
                    L̂ > FEC_cap·(1+margin)  sustained for degrade_sec
  HEALTHY ───────────────────────────────────────────────────────────► DEGRADED
     ▲                                                                 │
     │  L̂ < FEC_cap·0.5  sustained for recover_min                     │  L̂ > FEC_cap·(1+margin)·2
     │                                                                    ▼
     └──────────────────────────────────────────────────────────────  DOWN (disabled)
                         (probe every probe_interval;                ▲
                          re-check on each probe)                    │
                                                                     │  stable for recover_min
                                                                     └───────────────────────► HEALTHY
```
- **HEALTHY → DEGRADED**: loss exceeds what FEC can compensate (with margin)
  for `degrade_sec`. Scheduler stops sending *new* flows, drains in-flight.
- **DEGRADED → DOWN**: loss exceeds ~2× the FEC cap. WAN disabled entirely,
  its transport kept up only for probing.
- **DOWN → HEALTHY**: while DOWN, the monitor sends keepalives every
  `probe_interval`. If the path stays stable (loss < 50% of FEC cap) for
  `recover_min` minutes, it is restored. This is the "occasionally monitor the
  dead one, bring it back after N minutes of stability" behaviour.

---

## 9. Connection Preservation (the core value)

Why inner connections survive a WAN cutover:
1. **Stable egress IP.** In the primary deployment the office egresses through
   a VPS, so all *inner* connections already present a fixed IP to the
   internet. Only the office↔VPS tunnel segment is at risk.
2. **Session keyed by `session_id`, not source IP.** The server keeps the
   session across endpoint changes and tracks a **per-path endpoint** per WAN
   (§9 below), so it can answer each uplink on the same path it arrived on.
3. **Fast data-plane switch.** Standby warm path / graceful drain keeps the
   switch inside session timeouts (TCP: seconds; games: tens of seconds),
   well under the < 300 ms failover budget (§3.2).
4. **The delivery buffer** (reorder + jitter in one window) smooths the
   transition so the inner layer sees in-order, low-jitter delivery instead of
   a burst.
5. **TCP self-heals the residual gap.** Any frames lost at the exact cutover
   instant are recovered by TCP retransmission; games tolerate a sub-second
   blip via prediction.

### 9.1 Per-path endpoints (session model)
In `lb` mode the server may simultaneously receive a session's frames from
several source addresses (one per WAN). The session tracks `map[pathID]net.Addr`
and routes each reply back over the same path it came from. In `standby` mode
only one entry is active at a time; switching just changes which entry is used
— no re-handshake, no session reset.

---

## 10. Transport Modes (per WAN)

Pluggable wire formats, configured per WAN (`wan.transport`):

| Mode | Use case | Status |
|---|---|---|
| `udp` | Default. Encrypted UDP tunnel. | done |
| `faketcp` | Disguises the tunnel as TCP (3-way handshake + seq/ack simulation) to bypass UDP blocking/QoS. Derived from udp2raw's FakeTCP. Requires raw-socket + RST-suppression (iptables/nftables on Linux, pf on FreeBSD). | **M4.2a done** |
| `icmp` | Last-resort tunnel over ICMP echo for UDP-blocked links (pull model: server data rides echo replies to the client's requests). Kernel-echo suppression via a deliberately corrupt request checksum — the marker of an authentic flexbraid client; honest pings keep their valid checksum and are served by the kernel. | **M4.2b done** |

Each transport is a self-contained `Transport` interface (open/close/send/recv)
so new wire formats are drop-in.

---

## 11. Security

- **Cipher:** ChaCha20-Poly1305 (AEAD, constant-time, fast on CPUs without
  AES-NI, matches WireGuard's own primitives). AES-256-GCM available.
  *(Upgrade over udp2raw's AES-CBC + HMAC-SHA1.)*
- **Keying: a shared pre-shared key (PSK) from config (`crypto.key`) is the
  authenticator; the per-session AEAD key comes from an ephemeral X25519
  key exchange (M5.5), so the tunnel has **perfect forward secrecy**:
  1. The handshake (`FIRST`/KEX_REQ and `KEX_ACK`) is sealed with the base
     key derived from the PSK alone — only a party holding the PSK can
     complete it (mutual authentication).
  2. Each side generates an ephemeral X25519 keypair; the ephemeral public
     keys travel inside the handshake frames (client's in KEX_REQ, server's
     in KEX_ACK), encrypted/authenticated under the base key.
  3. Both sides compute `shared = X25519(priv_own, pub_peer)` and derive
     `session = HKDF(shared, psk-as-salt, "pfs-session:<id>")`.
  4. All data frames after the handshake use the **session** key, so a
     nonce is never reused across sessions — and because the ephemeral
     secrets are discarded at process exit, a later PSK compromise cannot
     decrypt past sessions (forward secrecy).
  There is **no unauthenticated \"ephemeral key from server\" path**: the
  PSK binding in the HKDF salt and the base-key-sealed handshake are what
  stop a MITM impersonating either side.
- **Authentication / integrity:** the AEAD tag over header+payload
  authenticates the `session_id`, so a forged or hijacked session cannot inject
  frames without the key. The anti-replay sliding window rejects replayed
  `seq`s and is sized **≥ the delivery-buffer window** (§5) so it never drops
  legitimate frames that multi-path delivery reordered. Frames are
  **authenticated before** the replay window is touched, so an unauthenticated
  attacker cannot poison it (window poisoning would be a permanent DoS).
  Handshakes (`FIRST`) additionally pass a per-ID replay window *before* any
  session state is created, so a replay loop cannot grow the session table
  (socket/memory DoS).
- **No integrity-only mode:** the M3.1 config surface removed
  `crypto.integrity_only` — the tunnel always uses full AEAD. WireGuard
  already encrypts the inner data, but the tunnel's own headers still need
  authenticated integrity; the CPU saving of MAC-only was negligible.
- **Note:** inner traffic is additionally encrypted by WireGuard, but the
  tunnel layer must still authenticate/integrity-protect to stop an attacker
  from injecting frames into the tunnel.

---

## 12. Cross-Platform Strategy

- **Language:** Go (user-space). `GOOS=freebsd` and `GOOS=linux` build static
  binaries; goroutines map naturally to per-WAN event loops; mature
  `klauspost/reed-solomon` for RS.
- **Platform-specific bits are isolated** behind the `Transport` interface:
  - Linux: raw sockets + `nftables`/`iptables` rules for FakeTCP RST
    suppression.
  - FreeBSD: raw sockets + `pf` equivalent.
- **Deployment:** OPNsense (FreeBSD) as client, Debian server (VPS), or either
  role on either OS. Ships `rc.d`/`systemd` units and a config example.

---

## 13. Configuration Reference (summary)

Full reference in [CONFIG.md](CONFIG.md). Highlights:
- `wans[].capacity_mbps` — declared bandwidth, drives capacity-weighted balancing.
- `fec.enabled`, `fec.mode` (`adaptive`/`fixed`/`off`/`crosspath`),
  `fec.max_loss_pct` (redundancy ceiling), `fec.data_shards`,
  `fec.block_timeout_ms`, `fec.adapt_*` (live adaptation thresholds) —
  per-link FEC; can be disabled entirely.
- `scheduler.mode` (`lb`/`standby`), `scheduler.affinity` (`flow`/`packet`),
  `scheduler.balance_by` (`capacity`/`fec`/`roundrobin`),
  `scheduler.capacity_cap_mbps` (server-side clamp on declared capacity).
- `wans[].iface` / `wans[].local_ip` — per-WAN socket binding (§12).
- `delivery.gap_timeout_ms`, `delivery.max_pending` — reorder window (§5).
- `fec.data_shards` — RS block size (games: 4–6).
- `health.*` — EWMA weights, `degrade_sec`, `down_after_misses`,
  `down_grace_sec`, `recover_min`, `probe_interval`.
- `crypto.cipher`, `crypto.key`.

---

## 14. Roadmap

- **M0 — Foundation** *(this repo):* repo, docs, config package + validation,
  build system, CI.
- **M1 — Data path:** session, sequence, frame framing, crypto (ChaCha20-Poly1305,
  shared-PSK auth), UDP transport, one-WAN client/server that passes WireGuard
  traffic.
- **M2 — FEC** *(done, M2):* per-WAN RS encoder/decoder (self-describing
  parity), `adaptive`/`fixed`/`off`, short-block flush; verified end-to-end
  against 25% frame loss.
- **M3 — Scheduler + health** *(done)*: `lb` (packet-affine, capacity-weighted)
  and `standby` modes (standby abandons DEGRADED paths, not just dead ones),
  EWMA monitoring, circuit breaker with in-band loss telemetry + silence
  watchdog, delivery buffer (reorder+jitter, configurable window), per-WAN
  socket binding (`iface`/`local_ip`). Per-WAN queues/rate-limit moved to M5.
- **M4 — Multi-WAN resilience:** *(done)* — cross-path FEC (blocks spread
  across all WANs via smooth WRR, parity floor via `protection_level`,
  whole-WAN loss survivable at capacity cost); FakeTCP wire format (raw
  IPv4/TCP disguise); ICMP wire format (ping disguise, pull model);
  live-adaptive FEC (redundancy sized to measured loss, pass-through on
  clean links).
- **M5 — Ops:** *(done)* — telemetry (HTTP JSON snapshot + periodic log),
  SIGHUP runtime reload (live subset; structural changes rejected), per-WAN
  bounded send queue + token-bucket rate limiter (§7.6), OPNsense rc.d +
  Debian .deb packaging, and authenticated key-exchange with **perfect
  forward secrecy** (ephemeral X25519 + HKDF, PSK demoted to authenticator).

---

## 15. Testing Strategy

- **Unit:** FEC against scripted loss patterns (per-WAN and cross-path); the
  delivery (reorder+jitter) buffer; EWMA + state-machine transitions;
  scheduler weighting and affinity math; config validation. Assert the
  invariants: replay window ≥ delivery window, per-WAN FEC blocks never split
  across paths, per-path endpoint routing.
- **Integration (Linux):** `tc netem` to simulate per-path loss/latency/jitter
  and hard link loss; verify WireGuard traffic flows end-to-end and that a WAN
  cutover preserves an in-flight TCP session (`ss` / `nethogs` / throughput
  tests).
- **Resilience:** kill a path mid-transfer, assert bounded packet loss and
  session survival; assert `recover_min` re-add behaviour; assert a
  load-balanced session keeps both WAN endpoints active and answers on the
  correct path.
