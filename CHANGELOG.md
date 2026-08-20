# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions are [SemVer](https://semver.org/spec/v2.0.0.html).

## [v0.1.0] — 2026-08-20

First release. The full multi-WAN bonding tunnel with adaptive FEC, health
monitoring, resilience transports and ops tooling. Incompatible wire
protocol from earlier forks: the handshake now uses **perfect forward
secrecy** (ephemeral X25519 + HKDF), so binaries built before this release
cannot talk to it.

### Milestone history (all merged into v0.1.0)

- **M0 — Foundation:** repo, docs, config package + validation, CI.
- **M1 — Data path:** session/seq/framing, ChaCha20-Poly1305, anti-replay,
  UDP transport, one-WAN tunnel.
- **M2 — FEC:** per-WAN Reed–Solomon (self-describing parity), adaptive/
  fixed/off, short-block flush; end-to-end loss recovery.
- **M3 — Scheduler + health:** `lb`/`standby`, EWMA monitoring, circuit
  breaker, delivery buffer, per-WAN binding, live-adaptive FEC.
- **M4 — Resilience:** cross-path FEC, FakeTCP + ICMP wire formats,
  endpoint migration / warm failover.
- **M5 — Ops:** telemetry (HTTP JSON + periodic log), SIGHUP reload,
  per-WAN queue + rate limiter, packaging, PFS key-exchange.

### Added (release highlights)
- **Perfect forward secrecy** key-exchange (M5.5): PSK demoted to
  authenticator; per-session AEAD from ephemeral X25519 + HKDF.
- **Cross-path FEC**: one codec across all WANs, whole-WAN loss survivable
  at `protection_level` capacity cost.
- **FakeTCP** and **ICMP** transports for UDP-blocked links.
- **Telemetry**: HTTP JSON snapshot (`telemetry.listen`) and periodic log.
- **Runtime reload**: SIGHUP applies the live config subset.
- **Per-WAN send queue** + token-bucket rate limiter.
- **Packaging**: OPNsense `rc.d` service and Debian/Ubuntu `.deb`.

### Changed
- Wire protocol hardened: key exchange moved from PSK-only session keys to
  authenticated ephemeral ECDH (forward secrecy).
- Example/test deployments use a neutral public UDP port (4096) and RFC 5737
  documentation IPs; the operator's own network layout is kept out of the
  public repository.

### Fixed
- FEC decoder dropped all frames from an FEC-off sender (`blockSeq=0`
  tripped the `lastFlushed` guard) — mixed FEC modes now interoperate.
- SIGTERM deadlock: blocking recv loops stalled shutdown until sockets were
  closed; sockets now close on `ctx.Done()` (~200 ms graceful stop).
- Data race in the server health tick loop (`st.paths` vs `registerPath`).
- FreeBSD 15: removed `IP_BOUND_IF` gives a clear
  `ErrDeviceBindUnsupported` + `local_ip`/plain-dial fallback instead of a
  cryptic `protocol not available`.
- Config smoke test and stale docs/roadmap entries brought in line with the
  implemented feature set.
