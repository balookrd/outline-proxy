#!/usr/bin/env python3
"""Capture QUIC Initial datagrams into a pcap for transport-parameter checks.

Receives UDP datagrams on 127.0.0.1:<port> and writes them to a pcap
(LINKTYPE_RAW) with synthetic IPv4/UDP headers, so tshark can decrypt the
Initial (keys derive from the DCID). The Initial leaves the client before any
certificate check, so no server is needed.

Usage: quic-initial-sink.py <port> <out.pcap> <seconds>

    python3 -I scripts/quic-initial-sink.py 4433 out.pcap 15 &
    # Chrome:  "Google Chrome" --headless=new --no-proxy-server --user-data-dir=<tmp> \\
    #          --origin-to-force-quic-on=127.0.0.1:4433 --dump-dom https://127.0.0.1:4433/
    # ours:    outline-ws-rust --config <cfg with tcp_ws_url=wss://127.0.0.1:4433/x, tcp_mode=h3>
    tshark -r out.pcap -d udp.port==4433,quic -V | grep 'Parameter: '
"""
import socket
import struct
import sys
import time

port, out, secs = int(sys.argv[1]), sys.argv[2], float(sys.argv[3])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", port))
s.settimeout(0.5)
f = open(out, "wb")
f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))  # LINKTYPE_RAW


def csum(b):
    if len(b) % 2:
        b += b"\0"
    t = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    t = (t >> 16) + (t & 0xFFFF)
    t += t >> 16
    return ~t & 0xFFFF


end = time.time() + secs
n = 0
while time.time() < end:
    try:
        data, (ip, sport) = s.recvfrom(65535)
    except socket.timeout:
        continue
    udp = struct.pack("!HHHH", sport, port, 8 + len(data), 0) + data
    iph = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), n & 0xFFFF, 0, 64, 17, 0,
        socket.inet_aton(ip), socket.inet_aton("127.0.0.1"),
    )
    iph = iph[:10] + struct.pack("!H", csum(iph)) + iph[12:]
    pkt = iph + udp
    t = time.time()
    f.write(struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(pkt), len(pkt)) + pkt)
    n += 1
f.close()
print("captured", n, "datagrams")
