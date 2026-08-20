# FlexBraid on OPNsense (FreeBSD) — packaged install

Everything you need to run FlexBraid as a proper OPNsense service.
The full guide lives in [`docs/DEPLOY_OPNSENSE.md`](../../docs/DEPLOY_OPNSENSE.md);
this directory holds the packaged pieces.

## Files

| File | Purpose |
|---|---|
| `flexbraid.rc` | FreeBSD `rc.d` script: start/stop/status/`reload` (SIGHUP) |
| `client.yaml.example` | Client config template (fill in PSK, WANs, server) |
| `install.sh` | One-shot installer: cross-compiles, copies binary + rc + config |

## Install

```sh
# on a build box (has Go), from the repo root:
packaging/opnsense/install.sh

# on the router:
scp flexbraid-freebsd-amd64 root@<router>:/usr/local/bin/flexbraid
scp packaging/opnsense/flexbraid.rc root@<router>:/usr/local/etc/rc.d/flexbraid
scp packaging/opnsense/client.yaml.example root@<router>:/etc/flexbraid/client.yaml
ssh root@<router> 'chmod 0755 /usr/local/bin/flexbraid /usr/local/etc/rc.d/flexbraid
                    chmod 700 /etc/flexbraid && chmod 600 /etc/flexbraid/client.yaml
                    echo "flexbraid_enable=\"YES\"" >> /etc/rc.conf
                    service flexbraid start'

# test a live reload after editing the config:
service flexbraid reload
```

## FreeBSD 15 note (read this — it bit us)

`IP_BOUND_IF` was **removed** from the FreeBSD 15 kernel, so per-WAN
interface binding (`iface:`) fails with `ErrDeviceBindUnsupported`. In the
client config either omit `iface:` (single-WAN via the kernel default route)
or use `local_ip:` when the WAN has a real address. True multi-WAN source
binding needs pf policy routing or multi-FIB (`net.fibs > 1`).
