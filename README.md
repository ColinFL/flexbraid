<div align="center">

# FlexBraid

[![CI](https://github.com/ColinFL/flexbraid/actions/workflows/ci.yml/badge.svg)](https://github.com/ColinFL/flexbraid/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/Platform-FreeBSD%20%26%20Linux-blue.svg)](#)
[![Status](https://img.shields.io/badge/Status-M0%E2%80%93M5.5%20implemented-green.svg)](#)

**Many WANs. One connection. No dropped sessions.**

*Flexible multi-WAN bonding tunnel — weave several uplinks into one unbreakable link.*

</div>

---

## What is FlexBraid?

FlexBraid is a **user-space, multi-WAN bonding tunnel**. It weaves several
physically independent uplinks — cable, LTE, Starlink, a second ISP — into a
**single logical link**, so that anything layered on top experiences one
stable, loss-corrected, in-order connection.

It sits **underneath your VPN**: point WireGuard at FlexBraid and WireGuard
believes it has one rock-solid link, even while FlexBraid silently balances
traffic across your WANs and instantly re-routes around a dead one.

```
  WAN 1 (300 Mbps) ──┐
  WAN 2 (100 Mbps) ──┼──► FlexBraid client ──► FlexBraid server ──► internet
  WAN 3 ( 50 Mbps) ──┘         │                        │
                               └──── one stable UDP link for WireGuard ────┘
```

### Why FlexBraid?

- **Connections survive failover.** Game and TCP sessions stay alive across a
  WAN cutover — sessions are keyed by a stable ID, not your changing source IP.
- **Self-contained WAN health.** FlexBraid measures loss/RTT/jitter from its
  own traffic and acts with a hysteresis circuit breaker. No dependence on
  OPNsense `WANFAIL`, `dpinger`, or any external monitor.
- **Active load balancing**, weighted by each WAN's real bandwidth — or a
  **warm-standby** mode for near-zero-loss failover with no load splitting.
- **Forward error correction, fully disable-able** — Reed–Solomon erasure
  coding with a tunable compensable-loss percentage per path. **Live-adaptive**:
  on a clean link it runs pass-through (zero latency, zero overhead); when
  loss appears it codes with redundancy sized to the measured loss. A
  **cross-path** mode spreads blocks across all WANs to survive the loss of an
  entire uplink.
- **Measured, not assumed.** Per-path loss is observed from real traffic
  (pass-through frame counters make loss visible even under full load), so the
  adaptive codec engages exactly when the wire is actually lossy.
- **Flexible & configurable**: any number of WANs, per-link transport
  (`udp` / `faketcp` / `icmp`), per-link FEC %, scheduler policy, health
  thresholds — all from one YAML file.
- **Secure**: ChaCha20-Poly1305 (or AES-256-GCM) AEAD with per-session keys
  from an ephemeral X25519 + HKDF handshake — **perfect forward secrecy**,
  the shared PSK reduced to an authenticator.
- **Cross-platform**: FreeBSD (OPNsense) and Linux (Debian), client *and*
  server, with packaged services for both.

---

## Status

**Implemented and field-tested.** All roadmap milestones M0–M5.5 are done:
the full data path, adaptive/cross-path FEC, multi-WAN scheduling with health
monitoring and circuit breaking, OPS tooling (telemetry, live reload,
packaging), and an authenticated X25519+HKDF key exchange with perfect
forward secrecy.

The integration suite in [`tests/netem/`](tests/netem/README.md) runs the
whole stack (client + server + echo) inside isolated veth namespaces with
`tc netem` fault injection — including **sustained 20 Mbps load** — and
currently passes all checks, including FEC-on recovery, hard link loss, and
failover under load.

> **Work in progress:** none of the core data path is WIP anymore. Ongoing
> work is hardening and polish — configuration validation edge cases,
> telemetry surface, documentation alignment — tracked in
> [`CHANGELOG.md`](CHANGELOG.md) (the `Unreleased` section) and the
> [design doc §15](docs/DESIGN.md#15-testing-strategy).

---

## Quick start

Requires Go 1.26+ and (for binding to a real WAN device) root. Build:

```bash
make build                 # ./flexbraid
# or: go build -o flexbraid ./cmd/flexbraid
```

Run a server (FEC geometry and MTU are configured **here** and announced to
clients at connect):

```bash
sudo ./flexbraid -c server.yaml
```

Run a client (config points at the server, lists your WANs):

```bash
sudo ./flexbraid -c client.yaml
```

Minimal configs (full reference: **[docs/CONFIG.md](docs/CONFIG.md)**):

```yaml
# server.yaml — FEC + MTU are server-side settings; clients adopt them
mode: server
listen: 0.0.0.0:4096          # FlexBraid clients connect here
wg_peer: 127.0.0.1:51820      # inner WireGuard peer (egress target)
mtu: 1388                     # announced to clients (1500 − overhead)
fec:
  enabled: true
  mode: adaptive              # live: pass-through on clean links
  data_shards: 10
  max_loss_pct: 20
crypto:
  key: "change-me"

# client.yaml — FEC/MTU come from the server at connect; do NOT set them here
mode: client
listen: 0.0.0.0:51820         # WireGuard points here
server: 203.0.113.1:4096
scheduler: { mode: lb, balance_by: capacity }
wans:
  - { id: w1, transport: udp, capacity_mbps: 300 }
  - { id: w2, transport: udp, capacity_mbps: 100 }
crypto:
  key: "change-me"            # must match the server
```

Point WireGuard at the client's `listen` address (e.g.
`sudo wg-quick up` on a peer configured with `Endpoint = 127.0.0.1:51820`
and set the interface MTU to the announced value). The client encapsulates
it over both WANs; the server de-capsulates to `wg_peer`.

> ⭐ **Non-Goal:** FlexBraid is a tunnel transport, not a router/firewall —
> it is not a replacement for OPNsense routing. See
> [DESIGN.md §2](docs/DESIGN.md#2-goals--non-goals).

---

## Documentation

| Document | Contents |
|---|---|
| [DESIGN.md](docs/DESIGN.md) | Vision, goals, architecture, FEC & scheduler math, health state machine, testing strategy |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component design, Go package layout, interfaces |
| [PROTOCOL.md](docs/PROTOCOL.md) | On-the-wire frame format (v0.02), PFS key exchange, sequence & session semantics |
| [CONFIG.md](docs/CONFIG.md) | Complete configuration reference |
| [DEPLOY_OPNSENSE.md](docs/DEPLOY_OPNSENSE.md) | Install & run FlexBraid on OPNsense (FreeBSD 15 notes, rc.d, firewall) |
| [packaging/opnsense](packaging/opnsense/README.md) | OPNsense rc.d service + installer |
| [packaging/debian](packaging/debian/README.md) | Debian `.deb` build (systemd) |
| [tests/netem](tests/netem/README.md) | Linux `tc netem` integration harness (loss / jitter / hard-loss / failover under load) |

---

## Design at a glance

- **Inner layer contract:** WireGuard sees *one* reliable UDP socket.
- **FEC:** adaptive Reed–Solomon erasure coding, per-link tunable, disable-able.
  **Cross-path** mode spreads blocks across all WANs so a whole-WAN loss is
  survivable at a capacity cost; a `protection_level` floor guarantees minimum
  redundancy. Triggered by **raw per-path loss from real traffic**
  (pass-through frame counters), never by probes alone.
- **Scheduler:** `lb` (capacity-weighted load balance, packet or flow
  affinity) or `standby` (warm standby), with graceful drain.
- **Health:** EWMA loss/RTT/jitter with "fast rise, slow decay" +
  circuit-breaker state machine (HEALTHY → DEGRADED → DOWN → HEALTHY); the low
  pass-through loss signal and the high unrecovered-block-loss signal are kept
  deliberately separate.
- **Delivery:** an in-order reassembly buffer (configurable gap window) hides
  per-path reordering and jitter from the inner layer.
- **Security:** ChaCha20-Poly1305 or AES-256-GCM AEAD + anti-replay, with
  **perfect forward secrecy** via an ephemeral X25519 handshake (PSK
  authenticates, ECDH keys each session; HKDF derives the per-session keys).
- **Server-pushed parameters:** FEC geometry and inner MTU are configured
  once, on the server, and announced to each client in the key-exchange ACK —
  no more "identical settings on both ends" drift.

---

## Inspiration

FlexBraid is inspired by — and reuses the core ideas of —
[`udp2raw-tunnel`](https://github.com/wangyu-/udp2raw-tunnel) (transport
obfuscation, FakeTCP and connection recovery) and
[`UDPspeeder`](https://github.com/wangyu-/UDPspeeder) (Reed–Solomon FEC),
while the multi-WAN bonding, per-path adaptivity and traffic-derived
telemetry are its own design. Neither project contributes code or
dependencies; the implementation is independent.

---

## License

[MIT](LICENSE) © 2026 ColinFL
