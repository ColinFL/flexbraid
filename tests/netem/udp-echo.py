#!/usr/bin/env python3
"""Minimal UDP echo used as the FlexBraid server's `wg_peer` target during
netem tests (tests/netem + docs/DEPLOY_OPNSENSE.md staging check).

Usage: udp-echo.py [port]   (default 15123)
"""
import socket
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 15123
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
print(f"udp-echo on 127.0.0.1:{port}", flush=True)
while True:
    d, a = s.recvfrom(65535)
    s.sendto(d, a)
