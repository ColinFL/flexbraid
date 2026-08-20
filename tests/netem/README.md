# netem integration harness

Linux-only test harness that realises the **Integration (Linux)** and
**Resilience** bullets of [docs/DESIGN.md §15](../../docs/DESIGN.md#15-testing-strategy):
`tc netem` simulates per-path loss / latency / jitter and hard link loss,
and the stack (server + client + local echo) runs over loopback on one box.

## What it checks

1. **Baseline** — no netem: loss ≈ 0 over the whole tunnel path.
2. **Lossy link, FEC off** — `netem loss 5%`: inner loss ≈ link loss
   (proves the link-loss is visible end-to-end, not swallowed).
3. **Lossy link, FEC on** — same 5% link loss with adaptive FEC: recovery to
   ≤ `EXPECT_LOSS` (default 2%) — the actual erasure-coding benefit.
4. **Hard link loss** — `netem loss 100%`: tunnel goes dark, both processes
   survive (no crash under a dead path), and after the link is restored the
   tunnel recovers and traffic flows again.
5. **Delay / jitter** — `netem delay 30ms 10ms`: measured tunnel RTT
   reflects the applied delay (not hidden by buffering).

## Usage

Requires a Linux host with `tc` (iproute2), `python3`, and a Go-built
`flexbraid` binary. Run from the repo root:

```sh
# build the linux binary first
GOOS=linux GOARCH=amd64 go build -o dist/flexbraid-linux-amd64 ./cmd/flexbraid

# full run (defaults: lo, 40 probes)
tests/netem/run-netem.sh

# tune it
FLEXBRAID_BIN=./dist/flexbraid-linux-amd64 \
NETEM_IF=eth0 \
COUNT=100 \
EXPECT_LOSS=1 \
tests/netem/run-netem.sh
```

Exit code 0 = all checks passed; the script cleans up its own netem
discipline and background processes (including on failure).

## Files

| File | Purpose |
|---|---|
| `run-netem.sh` | The harness: stack + netem + 5 checks + cleanup |
| `udp-probe.py` | Sends N UDP probes into the client's ingress socket and reports delivered / loss / min-avg-max RTT |
| `udp-echo.py` | Local echo the server's `wg_peer` points at (staging target, same pattern as docs/DEPLOY_OPNSENSE.md §6) |

## Going further (manual)

For a **two-WAN cutover** test (DESIGN.md §15: "kill a path mid-transfer"),
run the same stack with a second WAN and drop one path's traffic with an
iptables rule instead of netem — the in-tunnel health monitor + scheduler
should keep the session alive:

```sh
# block one WAN's source in the egress direction
iptables -A OUTPUT -p udp --dport 4096 -s 192.0.2.10 -j DROP
# ... run probes, then
iptables -D OUTPUT -p udp --dport 4096 -s 192.0.2.10 -j DROP
```

Assert with `ss -uap` that the session survives and that the deliverable is
bounded packet loss (the delivery buffer + FEC cover the transition).
