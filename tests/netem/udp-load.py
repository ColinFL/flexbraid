#!/usr/bin/env python3
"""Sustained UDP load driver for the FlexBraid netem harness (tests/netem).

Sends a paced stream of sequenced datagrams to the client's inner listen
socket; the whole tunnel round-trips them through the echo (udp-echo.py).
Counts what comes back to measure round-trip loss/RTT and reports the
offered forward load as goodput.

Usage: udp-load.py <host> <port> [--dur 5] [--mbps 20] [--size 1200]

Payload is padded to <size> bytes (must be <= inner MTU, default 1388) with
a monotonically increasing sequence number so each echo is self-identifying.

Prints one line:
  load sent=<n> received=<n> loss=<pct>% rtt_avg=<ms>ms goodput=<mbps>Mbps
"""
import argparse
import socket
import time

MAGIC = b"flexbraid-netem-load-"


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("host")
    ap.add_argument("port", type=int)
    ap.add_argument("--dur", type=float, default=5.0, help="seconds (default 5)")
    ap.add_argument("--mbps", type=float, default=20.0, help="target rate (default 20)")
    ap.add_argument("--size", type=int, default=1200, help="payload bytes (default 1200)")
    a = ap.parse_args()

    hdr = len(MAGIC) + 4
    size = max(hdr, min(a.size, 1388))
    payload = bytearray(size)
    payload[:len(MAGIC)] = MAGIC

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    # The tunnel hands delivered datagrams back to this socket in large
    # batches (the receiver's reorder/delivery buffer flushes at its gap
    # timeout). A default rcvbuf (~200 KiB) would overflow and record fake
    # loss that never happened on the wire. SO_RCVBUFFORCE bypasses the
    # rmem_max clamp (we run as root); fall back to SO_RCVBUF otherwise.
    rcv = getattr(socket, "SO_RCVBUFFORCE", None)
    try:
        opt = rcv if rcv is not None else socket.SO_RCVBUF
        s.setsockopt(socket.SOL_SOCKET, opt, 64 * 1024 * 1024)
    except OSError:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024 * 1024)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 16 * 1024 * 1024)
    s.setblocking(False)

    rate_bps = max(a.mbps * 1_000_000 / 8.0, 1.0)
    per_pkt = size / rate_bps  # seconds between datagrams to hit the rate

    sent = received = 0
    start = time.monotonic()
    tx_t = start
    times = {}  # seq -> perf_counter at send
    rtt = []
    deadline = start + a.dur

    def drain():
        # Non-blocking: never stalls the pacing loop waiting for echoes.
        nonlocal received, rtt
        while True:
            try:
                d, _ = s.recvfrom(65535)
            except BlockingIOError:
                return
            if len(d) < hdr or d[:len(MAGIC)] != MAGIC:
                continue
            seq = int.from_bytes(d[len(MAGIC):hdr], "big")
            t0 = times.pop(seq, None)
            if t0 is not None:
                received += 1
                rtt.append((time.perf_counter() - t0) * 1000.0)

    while True:
        now = time.monotonic()
        if now >= deadline:
            break
        # Send in small bounded batches so a scheduling hiccup never dumps a
        # huge burst into the client's ingress socket (which would overflow
        # its receive buffer and look like tunnel loss).
        burst = 0
        while tx_t <= now and burst < 16:
            seq = sent
            payload[hdr - 4:hdr] = seq.to_bytes(4, "big")
            try:
                s.sendto(bytes(payload), (a.host, a.port))
            except OSError:
                pass
            times[seq] = time.perf_counter()
            sent += 1
            burst += 1
            tx_t += per_pkt
        drain()
        time.sleep(0.0002)

    # Drain echoes still in flight after the send window closed.
    end = time.monotonic() + 1.0
    while time.monotonic() < end:
        drain()
        time.sleep(0.005)

    elapsed = max(time.monotonic() - start, 1e-6)
    # Offered forward goodput over the SEND window (a.dur), not the wall
    # time after the in-flight drain.
    goodput = sent * size / a.dur * 8.0 / 1e6  # Mbps offered forward
    if rtt:
        avg = sum(rtt) / len(rtt)
        print(f"load sent={sent} received={received} "
              f"loss={(sent - received) / sent * 100.0:.1f}% "
              f"rtt_avg={avg:.1f}ms goodput={goodput:.1f}Mbps")
    else:
        print(f"load sent={sent} received=0 loss=100.0% rtt_avg=- goodput={goodput:.1f}Mbps")


if __name__ == "__main__":
    main()
