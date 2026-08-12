# FlexBraid — Design Document

> **Status:** Draft v0.1 · **Author:** ColinFL · **License:** MIT
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
- **in-order delivery** — enforced by a reorder buffer on the server side;
- **bounded jitter** — a configurable jitter buffer absorbs the switch;
- **stable session identity** — sessions are keyed by a random `session_id`,
  **not** by the client's source IP, so moving between WANs (which changes the
  NAT mapping) does not tear the session down.

This is what lets WireGuard sit on top unchanged: WG keeps one peer, one
handshake, one endpoint — FlexBraid handles everything underneath.

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
| **FEC encoder / decoder** | Reed–Solomon erasure coding across a block of frames (see §6). |
| **Scheduler** | Splits the coded frame stream across healthy WANs (see §7). |
| **Transport (per WAN)** | Pluggable wire format: `udp`, `faketcp`, `icmp`; handles encryption/auth per frame; owns the per-WAN socket. |
| **Reorder buffer** | On the server, restores order from the interleaved multi-path stream. |
| **Jitter buffer** | Smooths delivery latency for latency-sensitive inner traffic. |
| **Session manager** | Keys sessions by `session_id`; survives endpoint changes. |
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
  reorder buffer and by FEC block grouping.
- **`flags`** — bit 0: `FEC_PARITY` (this frame is a parity frame, not inner
  data); bit 1: `KEEPALIVE`; bit 2: `CONTROL` (telemetry/control channel).
- FEC operates on a **block** of consecutive `seq`s. With `n` total frames per
  block and `n−k` parity, the block is recoverable if at least `k` of the `n`
  frames arrive.

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
1. **FEC fixes random loss *within* a working path — it does not survive a full
   path cutover.** When a WAN dies, its data *and* its parity die together.
   Surviving a whole-WAN loss with zero drop requires **cross-path erasure
   coding** (code across the aggregate so any surviving subset of WANs can
   reconstruct). This is an **optional advanced mode** (§6.4) that costs
   capacity proportional to the share you want to protect.
2. **FEC adds latency.** A block is only coded once `k` frames are collected
   (`block_timeout_ms`, default 8 ms). Larger `n` ⇒ more latency and more
   resilience to jitter.
3. **FEC is per-path tunable.** Different WANs may have different quality.

### 6.3 Adaptive redundancy
Instead of a fixed `-f 20:10` (UDPspeeder's model), the client computes the
desired redundancy from the health monitor's loss estimate each interval:

```
target_overhead = clamp( L̂ / (1 − L̂) * (1 + safety_margin),
                         min_overhead, max_overhead )
```
- `safety_margin` (default ~0.2) keeps headroom above the measured loss.
- `min_overhead` can be 0 so a clean WAN carries **zero** redundancy.
- If the measured loss exceeds what the configured FEC can compensate, the
  circuit breaker starts to pull that WAN out of service (the FEC "limps
  along" first; the breaker handles sustained overload).

### 6.4 Optional: cross-path FEC
A future mode where RS blocks are spread across **all** WANs such that the
block is recoverable as long as a sufficient *fraction* of WANs survive. This
is the only way to reach true zero-loss on whole-WAN cutover, and it costs
capacity. Exposed as a knob: `fec.mode: crosspath` with a
`protection_level` (0.0 = none … 1.0 = full single-WAN protection).
**Default: off** — the common case (random loss + fast failover) does not need it.

### 6.5 Disabling FEC entirely
`fec.enabled: false` (or `fec.mode: off`) turns off all erasure coding. Frames
then carry no parity; the scheduler still works; failover still preserves
connections; you simply accept the link's raw loss. Useful on clean links or
for latency-critical low-bandwidth use.

---

## 7. Packet Scheduler (load balancer)

Two modes, selectable via `scheduler.mode`.

### 7.1 `lb` — active load balancing (default)
Frames are spread across all healthy WANs. Two sub-strategies via
`scheduler.balance_by`:
- **`capacity` (default)** — each WAN receives a share proportional to its
  declared `capacity_mbps` (bandwidth-aware). This is the setting the user
  asked for: a 300 Mbps WAN carries ~3× a 100 Mbps WAN.
  ```
  share_i = weight_i * capacity_i / Σ(weight_j * capacity_j)
  ```
- **`fec`** — like `capacity`, but subtracts the adaptive FEC overhead from
  each path's effective capacity first (paths with heavy FEC get a smaller
  share).
- **`roundrobin`** — ignores weights, rotates evenly (for equal links).

**Per-connection consistency:** for flow-oriented inner traffic (TCP), the
scheduler hashes on inner 4-tuple so a connection sticks to one WAN while
healthy, avoiding intra-connection reordering. When a WAN is pulled, only its
connections move — consistent hashing keeps the reshuffle minimal.

### 7.2 `standby` — warm standby
One WAN is active (highest priority / weight), the rest are kept **warm**
(transport up, keepalives flowing, FEC live) but carry no data. On failure the
scheduler switches to the next warm standby. Because the standby is already a
live, authenticated transport with the server, the switch is a near-instant
data-plane change (no cold handshake). This is the "minimal loss, no load
splitting" profile.

### 7.3 Graceful drain
Before a degraded WAN is disabled, the scheduler **stops scheduling new flows**
onto it and lets its in-flight frames drain (`health.down_grace_sec`). This
reduces loss versus an abrupt cut.

---

## 8. Health Monitoring & Circuit Breaker

The health monitor is the "self-contained WANFAIL" — FlexBraid decides link
state from its **own** traffic, no OPNsense dependency.

### 8.1 Per-path metrics
- **Loss** — derived from gaps in the received `seq` stream (passive) and from
  keepalive echoes (active).
- **RTT** — from timestamps echoed in keepalive/control frames.
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
   session across endpoint changes.
3. **Fast data-plane switch.** Standby warm path / graceful drain keeps the
   switch inside session timeouts (TCP: seconds; games: tens of seconds).
4. **Reorder + jitter buffers** smooth the transition so the inner layer sees
   in-order, low-jitter delivery instead of a burst.
5. **TCP self-heals the residual gap.** Any frames lost at the exact cutover
   instant are recovered by TCP retransmission; games tolerate a sub-second
   blip via prediction.

---

## 10. Transport Modes (per WAN)

Pluggable wire formats, configured per WAN (`wan.transport`):

| Mode | Use case |
|---|---|
| `udp` | Default. Encrypted UDP tunnel. |
| `faketcp` | Disguises the tunnel as TCP (3-way handshake + seq/ack simulation) to bypass UDP blocking/QoS. Derived from udp2raw's FakeTCP. Requires raw-socket + RST-suppression (iptables/nftables on Linux, pf on FreeBSD). |
| `icmp` | Last-resort tunnel over ICMP echo for UDP-blocked links. |

Each transport is a self-contained `Transport` interface (open/close/send/recv)
so new wire formats are drop-in.

---

## 11. Security

- **Cipher:** ChaCha20-Poly1305 (AEAD, constant-time, fast on CPUs without
  AES-NI, matches WireGuard's own primitives). AES-256-GCM available.
  *(Upgrade over udp2raw's AES-CBC + HMAC-SHA1.)*
- **Authentication / integrity:** AEAD tag over header+payload; replay window
  (anti-replay) to reject replayed frames.
- **Key:** shared secret from config (`crypto.key`); server may also issue
  ephemeral keys at connect.
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
- `fec.enabled`, `fec.mode` (`adaptive`/`fixed`/`off`), `fec.max_loss_pct`,
  `fec.block_timeout_ms` — per-link FEC; can be disabled entirely.
- `scheduler.mode` (`lb`/`standby`), `scheduler.balance_by`
  (`capacity`/`fec`/`roundrobin`).
- `health.*` — EWMA weights, `degrade_sec`, `recover_min`, `probe_interval`.
- `crypto.cipher`, `crypto.key`.

---

## 14. Roadmap

- **M0 — Foundation** *(this repo):* repo, docs, config package + validation,
  build system, CI.
- **M1 — Data path:** session, sequence, frame framing, crypto (ChaCha20-Poly1305),
  UDP transport, one-WAN client/server that passes WireGuard traffic.
- **M2 — FEC:** RS encoder/decoder, adaptive redundancy, per-path config, `off`.
- **M3 — Scheduler + health:** `lb` (capacity-weighted) and `standby` modes,
  EWMA monitoring, circuit breaker, graceful drain, reorder/jitter buffers.
- **M4 — Multi-WAN resilience:** endpoint migration (`session_id`), warm
  standby failover, cross-path FEC (optional), FakeTCP + ICMP transports.
- **M5 — Ops:** telemetry, runtime reload, OPNsense/Debian packaging, docs site.

---

## 15. Testing Strategy

- **Unit:** FEC against scripted loss patterns; reorder buffer; EWMA + state
  machine transitions; scheduler weighting math; config validation.
- **Integration (Linux):** `tc netem` to simulate per-path loss/latency/jitter
  and hard link loss; verify WireGuard traffic flows end-to-end and that a WAN
  cutover preserves an in-flight TCP session (`ss` / `nethogs` / throughput
  tests).
- **Resilience:** kill a path mid-transfer, assert bounded packet loss and
  session survival; assert `recover_min` re-add behaviour.
