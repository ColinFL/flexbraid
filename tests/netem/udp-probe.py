#!/usr/bin/env python3
"""UDP probe through the FlexBraid tunnel: send N payloads to the client's
ingress listen socket and measure how many come back echoed (via the whole
path) plus RTT stats.

Usage: udp-probe.py <listen-host> <listen-port> <count> [interval-ms]

Prints one line:  sent=<n> received=<n> loss=<pct> min=<ms> avg=<ms> max=<ms>
"""
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
count = int(sys.argv[3])
interval = (float(sys.argv[4]) if len(sys.argv) > 4 else 0.05) / 1000.0

payload = b"flexbraid-netem-probe-" + bytes(range(256))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
s.settimeout(0.5)

rtt = []
received = 0
for i in range(count):
    # monotonically increasing payload so each echo carries its own tag
    pkt = payload + i.to_bytes(4, "big")
    t0 = time.perf_counter()
    s.sendto(pkt, (host, port))
    try:
        d, _ = s.recvfrom(65535)
        rtt.append((time.perf_counter() - t0) * 1000.0)
        received += 1
    except socket.timeout:
        pass
    time.sleep(interval)

def fmt(v):
    return f"{v:.1f}"

if rtt:
    rtt.sort()
    avg = sum(rtt) / len(rtt)
    print(f"sent={count} received={received} loss={(count - received) / count * 100.0:.1f} "
          f"min={fmt(rtt[0])} avg={fmt(avg)} max={fmt(rtt[-1])}")
else:
    print(f"sent={count} received=0 loss=100.0 min=- avg=- max=-")
