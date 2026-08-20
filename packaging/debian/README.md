# FlexBraid on Debian/Ubuntu (VPS) — packaged install

The server typically runs on a Debian/Ubuntu VPS. This directory builds a
proper `.deb`.

## Files

| File | Purpose |
|---|---|
| `build_deb.sh` | Cross-compile + assemble a `.deb` (binary, systemd unit, config, postinst) |
| `flexbraid.service` | systemd unit with `ExecReload` = SIGHUP |
| `server.yaml.example` | Server config: UDP **4096** (any port works), placeholder PSK |
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

## Choose a server port

***REMOVED***
***REMOVED***
***REMOVED***

## Live reload

Edit `/etc/flexbraid/server.yaml`, then:
```sh
systemctl reload flexbraid     # SIGHUP → applies live subset
```
See `docs/CONFIG.md` for what's applied live vs. requires a restart.
