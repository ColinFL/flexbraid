# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions are [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Server-pushed parameters (`config.ServerAnnounce`)**: FEC geometry and
  the inner MTU are now configured **only on the server** and announced to
  the client in the key-exchange ACK (`KEX_ACK`). The client rebuilds its
  codecs from the announced values before the session key is published, so
  a client config no longer has to — and should not — copy `fec:`/`mtu:`.
  Simpler client setups and no more "identical settings on both ends" drift.
  A pre-announce (old) server cannot be used by a current client: the
  handshake aborts with a "server too old" log and keeps retrying.
- **Wire protocol version bumped to `0x02`**: PFS + ServerAnnounce were both
  payload-breaking changes that previously rode the same 0x01 version; 0x02
  peers now refuse 0x01/0x00 frames at the header instead of misbehaving.
- **Pass-through frame telemetry (`PASS_SEQ`)**: every uncoded frame now
  carries a per-path monotonic counter (in `block_seq`), so the receiver can
  measure **raw per-path loss** from counter gaps even under sustained load —
  where keepalive probes are suppressed by traffic. This is the adaptive FEC
  trigger (docs/DESIGN.md §15.6). Wiring-documented in docs/PROTOCOL.md §5.1.

### Fixed
- **`fec.max_loss_pct` defaulted to 20 when omitted (or 0)** in an enabled
  FEC block (`config.DefaultMaxLossPct`). 0 passed validation but the codec
  math demands `0 < x < 100`, so an adaptive server without an explicit
  `max_loss_pct` crashed at startup ("invalid fec max_loss_pct 0") — found by
  a field netem run on the VPS. The client also normalizes a 0 ceiling in a
  received announce instead of failing the handshake.
- **Idle CPU spin with FEC off**: the FEC-flush tickers on **both the client
  and the server** spun at 1 ms when the codecs were pass-through (FEC block
  timeout 0), burning ~5% of an idle core (measured 0.578s/10s CPU vs
  0.3125s with FEC on). The client's tick is now paced off the delivery gap
  timeout and re-evaluated as codecs change; the server (no gap timer) idles
  at 250 ms when FEC is off. Measured after the fix: FEC-off 0.156s/10s,
  FEC-on 0.094s/10s — the FEC-off penalty is gone.
- **`delivery.max_pending` clamped to the anti-replay window (4096, DESIGN
  §5 invariant)**: values above it are rejected at validation — they would
  silently drop legitimately reordered frames as replays on multi-path links.
- **netem harness actually checks things**: probe output is now
  `loss=<pct>%`, the harness parses it robustly (no more vacuous
  awk-syntax-error "ok"), and the tunnel path is isolated in veth pairs in
  a network namespace so netem hits each direction exactly once (previously
  `lo` applied it ~6×, including the unrecoverable probe/echo legs).
- **netem harness grew a load + failover suite**: a new `udp-load.py`
  drives sustained, paced traffic into the tunnel, and the harness now
  asserts every scenario (baseline, lossy FEC off/on, hard loss, delay)
  both idle **and under load** (loss bounded + goodput sanity). Two veth
  pairs model two independent ISPs: test 6 pulls one ISP dark and verifies
  the session keeps flowing on the other with ~0 loss, then re-balances;
  test 7 does the same crossing a **cutover mid-load** (bounded loss, no
  collapse), plus steady-state assertions on the surviving WAN and after
  restore. Verified on the VPS field rig end-to-end (all checks pass except
  the FEC-on gate below).
- **Version arity**: `cmd/flexbraid` default version is now a neutral `dev`;
  the Makefile remains the single source of truth for release versions
  (previously the baked-in `0.1.0-m5` drifted from `Makefile`'s `0.2.0`).
- **Docs statuses** (`ARCHITECTURE`/`PROTOCOL`/`CONFIG`) brought up to
  M0–M5.5; `PROTOCOL.md` documents the ServerAnnounce in the KEX_ACK. The
  top-level `README.md` was rewritten to the current state (M0–M5.5 all
  implemented, field-tested, no data-path WIP; config examples validated
  against `config.Load`).
- **Client log hygiene**: "session established" now reports the FEC mode
  actually adopted from the server, not the (empty) client config.
- **`fec.mode: adaptive` now engages under sustained lossy load (П5, Variant
  A — pass-through telemetry).** The new load harness caught it: with
  `netem loss 5%` on a two-WAN path and 20 Mbps of traffic, `adaptive`
  recovered nothing (9.9% vs 9.8% for `off`) while `fixed` recovered to 0.6% —
  the RS codec was fine, the adaptation *trigger* was blind while traffic
  flowed (keepalive probes only count misses on a silent path; the FEC
  decoder's stats only exist at coded-block flushes, absent in pass-through).
  Fix: uncoded frames now carry a per-path monotonic counter (`PASS_SEQ` in
  `block_seq`), and the receiver feeds the raw counter-gap loss into the
  health EWMA (`ObserveRaw` → `SetLossRate`), so coding engages exactly when
  the wire is lossy, measured receiver-side and valid under load. The old
  unrecovered-loss path (`ObserveInBand`) still drives the circuit breaker —
  the two signals are deliberately separate (DESIGN §8.1/§15.6). The harness's
  FEC-on load assertion is green again.

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
