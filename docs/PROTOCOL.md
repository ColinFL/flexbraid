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
When idle, each side sends a `KEEPALIVE` frame. It carries a timestamp in the
payload, echoed back in the reply, giving the health monitor its RTT sample and
liveness signal. Frequency: `health.probe_interval` while a path is DOWN,
otherwise adaptive to traffic.

---

## 4. FEC blocks

**Blocks are constructed per WAN.** Each WAN's transport encodes *its own*
outbound frames into self-contained RS(`n`,`k`) blocks (data + parity on the
same path). This keeps within-path FEC coherent regardless of the scheduler and
is the enforcement of the FEC ↔ scheduler invariant (design §7.4).

A block contains `k` data frames and `n−k` parity frames. Parity frames carry
`FEC_PARITY` and reference the block's data-frame `seq`s so the decoder can map
parity to the right data positions. A block is recoverable if at least `k` of
its `n` frames arrive.

The encoder waits up to `fec.block_timeout_ms` to fill `k` data frames, then
emits the parity. This bounds added latency.

> Cross-path FEC (design §6.4) is a separate, optional mode that spans blocks
> across **all** WANs; it is only valid with `scheduler.affinity: packet` and is
> off by default.

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
- **Authentication / integrity:** the AEAD tag (or the Poly1305 MAC in
  `crypto.integrity_only` mode) authenticates header + payload, including
  `session_id`, so a forged/hijacked session cannot inject frames without the
  key.
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
