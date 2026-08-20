# Deploying FlexBraid on OPNsense

Step-by-step guide for running the FlexBraid **client** on an OPNsense
router (FreeBSD). The field-tested setup at this project's reference
installation: OPNsense client ↔ Debian VPS server over **UDP 4096**.

> **Real-world constraint this project hit (FreeBSD 15):** the `IP_BOUND_IF`
> socket option was removed from the FreeBSD kernel (`setsockopt` →
> `ENOPROTOOPT`, verified against `releng/15.1`). The transport code now
> returns an explicit `ErrDeviceBindUnsupported` and falls back to
> `local_ip` / plain dial. True per-interface socket binding on OPNsense is
> **not available** — see [“Multi-WAN caveats”](#multi-wan-caveats) below.

---

## 1. Prerequisites

- OPNsense ≥ 25 (FreeBSD ≥ 14.1) with console/SSH shell access.
- A VPS running the FlexBraid **server**. Server listening port must be
  **≤ 50** when the VPS has a DNAT that forwards high UDP ports into another
  tunnel (this project: `udp dport 50-65535 != 51820 → office tunnel`;
  port 4096 was taken by WireGuard, so **44** was chosen).
- A pre-shared key (PSK) generated and kept **outside** the public repo:
  ```sh
  openssl rand -hex 32   # → use as crypto.key (ChaCha20-Poly1305, 32 bytes)
  ```

---

## 2. Build the FreeBSD binary

On any build box with Go ≥ 1.26 (the repo uses standard library + build tags):

```sh
# from the repo root
GOOS=freebsd GOARCH=amd64 go build -trimpath \
  -ldflags '-s -w' -o flexbraid-freebsd-amd64 ./cmd/flexbraid
# or: make cross   (also does linux/windows)
```

Copy it to the router and place it where `rc.d` can find it:

```sh
scp flexbraid-freebsd-amd64 root@<router>:/usr/local/bin/flexbraid
ssh root@<router> chmod 0755 /usr/local/bin/flexbraid
```

---

## 3. Client configuration

Create `/etc/flexbraid/client.yaml` (mode `0600` — it holds the key):

```yaml
# FlexBraid client — OPNsense office router.
mode: client
listen: 127.0.0.1:51820        # WireGuard / inner service connects here
server: 203.0.113.10:4096
mtu: 1390                      # reduce if you enable FEC (see CONFIG.md)

scheduler:
  mode: lb
  affinity: packet             # required for fec.mode: crosspath
  balance_by: capacity

fec:
  enabled: true
  mode: adaptive               # | fixed | off | crosspath
  data_shards: 4
  max_loss_pct: 20
  block_timeout_ms: 15

wans:
  - id: w1
    transport: udp
    capacity_mbps: 300
    # On FreeBSD 15 binding to an interface is NOT supported (IP_BOUND_IF
    # removed). If your WAN has a real address you can instead set:
    #   local_ip: 192.0.2.10

delivery:
  gap_timeout_ms: 150
  max_pending: 4096

health:
  probe_interval: 1
  down_after_misses: 3
  down_grace_sec: 1
  recover_min: 2

crypto:
  key: "<your 32-byte hex PSK, kept outside the repo>"
  cipher: chacha20poly1305

log:
  level: info
```

### FreeBSD 15 device-binding note

Remove any `iface:` under a WAN on OPNsense **or** the client will fail with
`dial ... protocol not available` / `ErrDeviceBindUnsupported`. The working
single-WAN config does **not** use `iface:` or `local_ip:` at all — the
kernel routes via the default route and nothing breaks.

---

## 4. Run it (system service)

There is **no** `rc.d` script deployed in the field test yet (client was run
manually). Two options:

**Option A — manual / foreground (test):**
```sh
mkdir -p /etc/flexbraid && chmod 700 /etc/flexbraid
# write client.yaml as above, chmod 600
/usr/local/bin/flexbraid -c /etc/flexbraid/client.yaml
```

**Option B — rc.d service (recommended for production):**
create `/usr/local/etc/rc.d/flexbraid`:

```sh
#!/bin/sh
# PROVIDE: flexbraid
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="flexbraid"
rcvar=flexbraid_enable
command="/usr/local/bin/flexbraid"
command_args="-c /etc/flexbraid/client.yaml"
pidfile="/var/run/flexbraid.pid"

load_rc_config $name
run_rc_command "$1"
```

then:

```sh
chmod 0755 /usr/local/etc/rc.d/flexbraid
echo 'flexbraid_enable="YES"' >> /etc/rc.conf
service flexbraid start
service flexbraid status   # should show a running pid
tail -f /var/log/flexbraid.log   # set log.file in config to capture output
```

> **Note (privileged port):** FlexBraid client **binds only `127.0.0.1:listen`
> locally and dials out** — no root needed beyond placing files. The VPS
> **server** binds `0.0.0.0:4096` (< 1024 ⇒ requires `CAP_NET_BIND_SERVICE` /
> root — the reference VPS runs it as a `systemd` root service).

---

## 5. Firewall / OPNsense notes

**Outbound (client):**
- The client *dials out* UDP to the VPS on port 4096 — standard outbound UDP
  is enough.
- If you enable **pf** (this OPNsense currently runs with pf disabled — see
  memory/notes), allow `pass out proto udp to <vps> port 4096`.
- For **FakeTCP** transport (M4.2, not yet implemented) a
  `pass out proto tcp flags RST` rule will be required to suppress RSTs.

**Keep in mind for the WAN-failover setup on this router:**
- With pf **disabled**, OPNsense's own `WANFAIL` failover group and
  `dpinger` cannot steer per-socket policies — FlexBraid's in-tunnel health
  is the source of truth instead (by design, see DESIGN.md). FlexBraid
  itself does not depend on OPNsense routing.
- True **multi-WAN** with distinct source interfaces per path needs either
  **pf policy routing** (`route-to`) or **FIBs** (`net.fibs > 1`). The
  reference router has `net.fibs=1`; FlexBraid currently runs **single-WAN**
  there. See DESIGN.md §7.4 and the [Multi-WAN caveats](#multi-wan-caveats).

---

## 6. Verify the tunnel

The reference VPS also runs a UDP echo (`udp-echo.py` on `127.0.0.1:51821`)
and the FlexBraid server is configured with `wg_peer: 127.0.0.1:51821` so
the server's egress lands on a local echo during **staging** (no production
traffic switched yet). Verify from the router:

```sh
# 1. client must show a live session
tail -n 20 /var/log/flexbraid.log | grep -i "wan\|session\|health"
# 2. send frames through the tunnel: any UDP payload written to the client's
#    listen socket (127.0.0.1:51820) comes back echoed through the whole
#    path. A quick netcat check from a LAN host:
#    (the inner path is 127.0.0.1 → tunnel → VPS → echo → back)
```

Expected field results (reference OPNsense ↔ VPS, ~12.5 ms clean ping):
no-FEC avg RTT ~50 ms, FEC k=4/T15 avg ~125 ms, 0% loss (10/10, 50/50).

---

## 7. Multi-WAN caveats (FreeBSD 15 / OPNsense)

- `IP_BOUND_IF` is **gone** in FreeBSD 15 (checked `releng/15.1`
  `sys/netinet/in.h`; options 25/26 removed; `setsockopt` → `ENOPROTOOPT`).
- `SO_BINDTODEVICE` (Linux) has no FreeBSD equivalent for this use case.
- Current options for real per-path source binding on OPNsense:
  1. **pf policy routing** — `route-to (interface gateway)` rules per
     source/destination, gives you true multiple-WAN steering (also fixes
     OPNsense's own WAN-failover once pf is enabled);
  2. **multi-FIB** — set `net.fibs=2` in `/boot/loader.conf.d/`, reboot,
     add a second default route, then the client can use `SO_SETFIB`.
- Until then FlexBraid on this OPNsense runs **single-WAN**, which still
  works (all egress over one uplink) — the client code already contains
  explicit `ErrDeviceBindUnsupported` + plain-dial fallback.
