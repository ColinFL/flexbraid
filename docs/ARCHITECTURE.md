# FlexBraid — Architecture

This document describes the intended component design and Go package layout.
It is the map for implementation; the authoritative behavioural spec is
[DESIGN.md](DESIGN.md) and [PROTOCOL.md](PROTOCOL.md).

> ⚠️ **WIP.** Only `internal/config` exists today. Packages below are the
> target design.

---

## Package layout

```
cmd/flexbraid/        CLI entry point (flags, config load, orchestration, signals)
internal/
  config/             YAML config load + validation        [IMPLEMENTED]
  log/                leveled logger (debug..error)
  session/            session identity & lifecycle (client + server)
  frame/              on-the-wire frame encode/decode, sequence allocation
  crypto/             ChaCha20-Poly1305 AEAD + anti-replay window
  fec/                Reed–Solomon encoder/decoder, adaptive redundancy controller
  scheduler/          load balancer: lb (capacity/fec/roundrobin) + standby
  transport/          Transport interface + udp/faketcp/icmp implementations
  health/             EWMA loss/RTT/jitter + circuit-breaker state machine
  tunnel/             orchestrator wiring the pipeline together
  telemetry/          per-path stats, control/FIFO, runtime reload
```

---

## Core interfaces

### Transport (per-WAN wire format)

```go
// Transport is one physical path between client and server.
type Transport interface {
    ID() string
    Open() error
    Send(frame []byte) error
    Recv() ([]byte, error)     // delivers authenticated frames from the peer
    Close() error
}
```

Implementations: `udp` (plain encrypted UDP), `faketcp` (raw-socket TCP
disguise), `icmp`. Platform-specific socket logic lives behind these.

### Scheduler

```go
type Scheduler interface {
    // Pick returns which WAN should carry this frame (or nil if none ready).
    Pick(frame *frame.Frame) *transport.Transport
    // OnHealth lets the scheduler react to path state changes.
    OnHealth(update health.Snapshot)
    SetConfig(cfg config.Sched)
}
```

### Health monitor

```go
type Monitor struct { ... }
func (m *Monitor) Observe(wanID string, loss, rtt, jitter float64)
func (m *Monitor) State(wanID string) State // HEALTHY | DEGRADED | DOWN
func (m *Monitor) Score(wanID string) float64
```

State transitions follow the circuit breaker in [DESIGN.md §8](DESIGN.md#8-health-monitoring--circuit-breaker).

---

## Client data path (planned)

1. `tunnel.Ingress` listens on the one UDP socket the inner layer uses.
2. Each datagram → `frame.Encoder` adds header (magic/version/session/seq/flags)
   and is queued to the FEC block builder.
3. `fec.Encoder` produces a coded block; parity frames are flagged
   `FEC_PARITY`.
4. `scheduler.Pick` chooses a WAN for each frame; `health` gates which WANs are
   eligible.
5. `transport.Send` → crypto AEAD seal → socket → WAN.
6. `health.Observe` feeds the EWMA filters from recv-side seq gaps and
   keepalive timestamps.

## Server data path (planned)

1. Any socket delivers an authenticated frame → `session.Manager` looks it up
   by `session_id`.
2. `fec.Decoder` reassembles per-WAN blocks (tolerating up to `n−k` losses).
3. The **delivery buffer** (reorder + jitter in one window) restores global
   `seq` order across interleaved paths and smooths latency.
4. `tunnel.Egress` writes the ordered inner datagram to the WireGuard-side UDP
   socket.

---

## Concurrency model

Go goroutines mirror the pipeline: one goroutine per transport socket, one per
FEC encoder/decoder, one per reorder/jitter buffer, one for the health monitor,
one for the CLI/control plane. Packets move over buffered channels. This is why
Go fits the problem well — each WAN and each pipeline stage is naturally
independent, and cross-compilation to FreeBSD/Linux is trivial.

---

## Cross-platform isolation

| Concern | Linux (Debian) | FreeBSD (OPNsense) |
|---|---|---|
| UDP transport | `net.UDPConn` | `net.UDPConn` |
| FakeTCP RST suppression | `nftables`/`iptables` rule | `pf` equivalent |
| Raw socket for faketcp | `golang.org/x/net/ipv4`/unix | same (build tags) |
| Service unit | `systemd` | `rc.d` |

Platform-specific code is confined to `internal/transport` behind build tags
(`//go:build linux`, `//go:build freebsd`).
