# FlexBraid on Debian/Ubuntu (VPS) — packaged install

The reference deployment runs the FlexBraid **server** on a >Debian
VPS. This directory builds a proper `.deb`.

## Files

| File | Purpose |
|---|---|
| `build_deb.sh` | Cross-compile + assemble a `.deb` (binary, systemd unit, config, postinst) |
| `flexbraid.service` | systemd unit with `ExecReload` = SIGHUP |
| `server.yaml.example` | Server config: UDP **44** (≤50 constraint), placeholder PSK |
| `README.md` | This file |

## Build & install

```sh
# from the repo root (needs Go + dpkg-deb; fine on the VPS itself):
packaging/debian/build_deb.sh
scp dist/flexbraid_0.1.0-m5_amd64.deb root@<vps>:/
ssh root@<vps> 'apt-get install -y ./flexbraid_0.1.0-m5_amd64.deb
                 vi /etc/flexbraid/server.yaml     # set crypto.key + wg_peer
                 systemctl enable --now flexbraid
                 systemctl status flexbraid'
```

## Why port 4096 (read this — it's a hard constraint)

The reference VPS DNATs **UDP 50–65535** (except 51820 = WireGuard) into the
office tunnel, so any FlexBraid port ≥ 50 would be grabbed by that tunnel
and never reach the service. Port selection rule:
1. pick in **1–50** (VPS-side services live here),
2. avoid already-taken lows (this box: 43 = WireGuard),
3. **44** was free → chosen.

Privileged port note: `0.0.0.0:4096 < 1024` requires root or
`CAP_NET_BIND_SERVICE`; the service unit runs ***REMOVED***

## Live reload

Edit `/etc/flexbraid/server.yaml`, then:
```sh
systemctl reload flexbraid     # SIGHUP → applies live subset
```
See `docs/CONFIG.md` for what's applied live vs. requires a restart.
