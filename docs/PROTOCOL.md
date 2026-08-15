# FlexBraid — Wire Protocol

> **Status:** M1 implemented. The single-WAN data path (session, framing,
> crypto, UDP transport) is working and tested; multi-WAN scheduling (M3) and
> FEC (M2) are still being built. This document is the contract to build
> against — changes must be reflected here.

---

## 1. Overview

Client and server exchange **frames** over one or more WAN transports. Each
transport is an independent pipe; the multi-WAN weaving happens above it via
global sequence numbers and FEC blocks. The protocol is symmetric: both
directions use the same frame format.

All multi-byte integers are **big-endian**. All frames are AEAD-sealed with a
Poly1305 tag over the header+payload.

---

## 2. Frame layout

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           magic (u32)                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  version (u8) |  flags (u8)   |        reserved (u16)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                       session_id (u64)                        +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           seq (u32)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        block_seq (u32)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         payload_len (u16)      |           reserved (u16)      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                         payload (variable)                     +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     auth tag (Poly1305, 16B)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Header size (before payload): **28 bytes**. Tag: 16 bytes.

### Field notes
- **magic** — `0x46 0x4C 0x58 0x42` (`FLXB`). Used to detect garbage/wrong key.
- **version** — protocol version, currently `0x01`.
- **flags**:
  - `0x01` `FEC_PARITY` — payload is FEC parity, not inner data.
  - `0x02` `KEEPALIVE` — no inner data; used for liveness/RTT probing.
  - `0x04` `CONTROL` — control/telemetry payload (see §5).
  - `0x08` `FIRST` — first frame of a session (client handshake).
- **session_id** — 64-bit random value chosen by the client. The server keys
  the tunnel by this and **ignores source IP/port changes** (the basis of
  seamless failover).
- **seq** — global, monotonically increasing across **all** WANs. Basis for the
  server's delivery (reorder) buffer.
- **block_seq** — identifies the FEC block a frame belongs to. Data and parity
  frames of the same block share `block_seq`. Because **FEC blocks are built per
  WAN** (§4), `block_seq` is scoped to one WAN; frames on different WANs may
  reuse `block_seq` values.

---

## 3. Session lifecycle

### Connect
1. Client sends a frame with `FIRST`, a fresh random `session_id`, and its
   capabilities (cipher, FEC params) in the payload.
2. Server replies `CONTROL` `SESSION_ACK`, echoing the `session_id` and its own
   parameters. From then on both sides use that `session_id`.

### Endpoint migration (failover)
Because `session_id` — not source IP — identifies a session, a client that
moves from WAN A to WAN B simply keeps sending frames from the new socket. The
server keys the session by `session_id` and tracks a **per-path endpoint**:
each WAN's frames arrive from a distinct source address, and the server routes
replies back on the path they came from (§9.1 of the design).

- **`standby` mode:** one endpoint is active at a time; on failover the first
  valid frame from the new WAN simply switches which per-path endpoint is used.
  No re-handshake, no session reset.
- **`lb` mode:** several endpoints may be active concurrently; the server
  answers each path independently. The inner layer never observes any of this.

### Keepalive
Each side sends a `KEEPALIVE` frame every `health.probe_interval` on every
path (M3.1: probes default to 1s — they are the secondary loss signal; the
primary is in-band unrecovered-loss telemetry from the FEC decoder, which
needs no probes at all). The payload carries a timestamp echoed back in the
reply, giving the health monitor its RTT sample. A probe counts as missed
only while the path is otherwise silent (no data frames arrived either), so
probe jitter on a busy path cannot false-trip the circuit breaker. Total
silence is caught by the watchdog in the health tick loop.

---

## 4. FEC blocks

**Blocks are constructed per WAN.** Each WAN's transport encodes *its own*
outbound frames into self-contained RS(`n`,`k`) blocks (data + parity on the
same path). This keeps within-path FEC coherent regardless of the scheduler and
is the enforcement of the FEC ↔ scheduler invariant (design §7.4).

A block contains `k` data frames and `n−k` parity frames. A block is
recoverable if at least `k` of its `n` frames arrive.

**Parity frames** carry `FEC_PARITY` and a **self-describing payload**
(sub-header, all big-endian):

```
[0:2]   u16 k            — number of data frames in the block
[2:4]   u16 parity index — this shard's position in the parity list
[4:6]   u16 max_len      — padded shard size in bytes
[6:6+4k]     k × u32     — data seqs of the block, in order
[6+4k:6+6k]  k × u16     — original payload length of each data frame
[6+6k:]       max_len    — the parity shard itself
```

The sub-header makes parity frames fully self-describing: the decoder needs no
parameter negotiation, knows exactly which data frames are missing, and can
reconstruct byte-exact payloads (including the length of a lost frame, which
only lives in its own header). `k` is fixed per session in M2
(`fec.DefaultDataShards = 10`), but the on-wire format carries it so it can
vary freely.

**Timing.** The encoder waits up to `fec.block_timeout_ms` to collect `k` data
frames, then emits data + parity. A block with fewer than `k` frames at the
timeout is flushed *without* parity (short block); the decoder delivers it on
its own timeout. This bounds FEC latency for sparse traffic (e.g. keepalives).

> Cross-path FEC (design §6.4) is a separate, optional mode that spans blocks
> across **all** WANs; it is only valid with `scheduler.affinity: packet` and is
> not implemented until M4.

---

## 5. Control channel

`CONTROL` frames carry a typed sub-protocol used for:
- handshake (`SESSION_ACK`),
- parameter negotiation (cipher, FEC params, `capacity_mbps`),
- telemetry / per-path stats,
- runtime control (reconfigure, drain, shutdown) — the in-band counterpart to
  the CLI signal/FIFO interface.

**`CONTROL`/`KEEPALIVE` frames bypass FEC** — they are sent directly on the
path (not erasure-coded), so a keepalive round-trip is a clean RTT sample
rather than one gated behind block decoding (design §8.1).

Sub-protocol message types are defined in code as `internal/frame` control
messages; wire numbering is reserved here and documented there.

---

## 6. Security

- **Keying: shared PSK only.** ChaCha20-Poly1305 (default) or AES-256-GCM, key
  derived from `crypto.key`. There is **no unauthenticated ephemeral-key path**:
  without a shared secret nothing prevents a MITM from impersonating either
  side. (Authenticated key-exchange is a roadmap item, not v1.)
- **Per-session keys:** the handshake (FIRST/SESSION_ACK) uses the *base* key
  HKDF(PSK, "channel-key"). Once the server has authenticated a FIRST frame
  it derives the *session* key HKDF(PSK, "session:"+session_id), and every
  later frame in both directions uses it. This guarantees a (dir, seq) nonce
  is never reused under the same key across sessions — AEAD nonce reuse
  would be catastrophic.
- **Authentication before state:** frames are AEAD-authenticated **before**
  the replay window is touched and before session state is created or
  updated. An unauthenticated attacker therefore cannot slide the replay
  window (window poisoning → permanent DoS) nor grow the session table
  (memory DoS).
- **Authentication / integrity:** the AEAD tag authenticates header + payload,
  including `session_id`, so a forged/hijacked session cannot inject frames
  without the key. (There is no integrity-only mode — removed in M3.1; the
  CPU saving was negligible and the tunnel's own headers need authentication
  regardless of WireGuard's inner encryption.)
- **Anti-replay:** a sliding-window replay filter rejects replayed `seq`s. The
  window is sized **≥ the delivery-buffer window** (design §5) so it never
  drops legitimate frames that multi-path delivery reordered.
- The header (excluding the variable payload) is authenticated by the tag, so
  a corrupted/forged header fails decryption.

---

## 7. Versioning & compatibility

- `version` is bumped on breaking wire changes. The `magic` + `version` pair is
  negotiated at handshake; mismatched peers refuse to connect and log a clear
  error.
