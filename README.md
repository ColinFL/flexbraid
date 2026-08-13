<div align="center">

# 🧵 FlexBraid

**Flexible multi-WAN bonding tunnel — weave several uplinks into one unbreakable connection.**

[![Go Version](https://img.shields.io/badge/Go-1.26-blue.svg)](https://golang.org/dl)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/FreeBSD-OPNsense-blue.svg)](#)
[![Platforms](https://img.shields.io/badge/Linux-Debian-orange.svg)](#)
![Status](https://img.shields.io/badge/Status-M1%20data%20path-blue.svg)

*Many WANs. One connection. No dropped sessions.*

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
- **Adaptive forward error correction** (Reed–Solomon) that follows the link —
  and can be switched off entirely on clean lines.
- **Flexible & configurable**: any number of WANs, per-link transport
  (`udp` / `faketcp` / `icmp`), per-link FEC %, scheduler policy, health
  thresholds — all from one YAML file.
- **Cross-platform**: FreeBSD (OPNsense) and Linux (Debian), client *and*
  server.

---

## Quick start

> ⚠️ Work in progress — the data path is under active development (see
> [Roadmap](docs/DESIGN.md#14-roadmap)). Config parsing and validation work today.

```bash
# build
make build

# run a server
sudo ./flexbraid -c server.yaml

# run a client (config points at the server, lists your WANs)
sudo ./flexbraid -c client.yaml
```

```yaml
# client.yaml (minimal)
mode: client
listen: 0.0.0.0:51820     # WireGuard points here
server: 203.0.113.1:4096
scheduler: { mode: lb, balance_by: capacity }
fec:
  enabled: true
  mode: adaptive
  max_loss_pct: 20
wans:
  - { id: w1, transport: faketcp, capacity_mbps: 300 }
  - { id: w2, transport: udp,     capacity_mbps: 100 }
```

Full reference: **[docs/CONFIG.md](docs/CONFIG.md)**.

---

## Documentation

| Document | Contents |
|---|---|
| [DESIGN.md](docs/DESIGN.md) | Vision, goals, architecture, FEC & scheduler math, health state machine, roadmap |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Component design, Go package layout, interfaces |
| [PROTOCOL.md](docs/PROTOCOL.md) | On-the-wire frame format, sequence & session semantics |
| [CONFIG.md](docs/CONFIG.md) | Complete configuration reference |

---

## Design at a glance

- **Inner layer contract:** WireGuard sees *one* reliable UDP socket.
- **FEC:** adaptive Reed–Solomon erasure coding, per-link tunable, disable-able.
  Optional cross-path coding to survive whole-WAN loss (costs capacity).
- **Scheduler:** `lb` (capacity-weighted load balance) or `standby` (warm
  standby), with graceful drain.
- **Health:** EWMA loss/RTT/jitter with "fast rise, slow decay" +
  circuit-breaker state machine (HEALTHY → DEGRADED → DOWN → HEALTHY).
- **Security:** ChaCha20-Poly1305 AEAD + anti-replay.

---

## Roadmap

- **M0 — Foundation** *(done)*: repo, docs, config package + validation.
- **M1 — Data path** *(done)*: session, framing, crypto (ChaCha20-Poly1305,
  shared-PSK), anti-replay, UDP transport, one-WAN client/server tunnel —
  integration-tested end-to-end.
- **M2 — FEC:** RS encode/decode, adaptive redundancy.
- **M3 — Scheduler + health:** `lb`/`standby`, EWMA monitor, circuit breaker.
- **M4 — Resilience:** endpoint migration, warm failover, FakeTCP/ICMP.
- **M5 — Ops:** telemetry, runtime reload, OPNsense/Debian packaging.

See [DESIGN.md §14](docs/DESIGN.md#14-roadmap) for details.

---

## License

[MIT](LICENSE) © 2026 ColinFL
