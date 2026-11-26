#!/usr/bin/env python3
"""SOCKS5 TCP + UDP + metrics smoke check run inside the Docker stand network."""

import socket
import struct
import sys
import urllib.request


def socks5_tcp_echo(socks_host: str, socks_port: int, target_host: str, target_port: int, payload: bytes) -> None:
    with socket.create_connection((socks_host, socks_port), timeout=10) as s:
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            raise AssertionError("SOCKS5 TCP auth failed")
        host_b = target_host.encode()
        req = b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack("!H", target_port)
        s.sendall(req)
        resp = s.recv(4)
        if len(resp) != 4 or resp[1] != 0:
            raise AssertionError(f"SOCKS5 CONNECT failed: {resp!r}")
        atyp = resp[3]
        if atyp == 1:
            s.recv(4 + 2)
        elif atyp == 3:
            ln = s.recv(1)[0]
            s.recv(ln + 2)
        elif atyp == 4:
            s.recv(16 + 2)
        s.sendall(payload)
        got = b""
        while len(got) < len(payload):
            chunk = s.recv(len(payload) - len(got))
            if not chunk:
                break
            got += chunk
        if got != payload:
            raise AssertionError(f"TCP echo mismatch: got={got!r}, want={payload!r}")


def socks5_udp_echo(socks_host: str, socks_port: int, target_host: str, target_port: int, payload: bytes) -> None:
    with socket.create_connection((socks_host, socks_port), timeout=10) as ctrl:
        ctrl.sendall(b"\x05\x01\x00")
        if ctrl.recv(2) != b"\x05\x00":
            raise AssertionError("SOCKS5 UDP auth failed")
        ctrl.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        resp = ctrl.recv(4)
        if len(resp) != 4 or resp[1] != 0:
            raise AssertionError(f"SOCKS5 UDP ASSOCIATE failed: {resp!r}")
        atyp = resp[3]
        if atyp == 1:
            ip = socket.inet_ntoa(ctrl.recv(4))
            port = struct.unpack("!H", ctrl.recv(2))[0]
        elif atyp == 4:
            ip = socket.inet_ntop(socket.AF_INET6, ctrl.recv(16))
            port = struct.unpack("!H", ctrl.recv(2))[0]
        else:
            raise AssertionError(f"Unexpected SOCKS5 ATYP: {atyp}")
        relay_ip = socks_host if ip in ("0.0.0.0", "::") else ip
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(10)
            host_b = target_host.encode()
            pkt = b"\x00\x00\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack("!H", target_port) + payload
            udp.sendto(pkt, (relay_ip, port))
            data, _ = udp.recvfrom(4096)
            if not data.endswith(payload):
                raise AssertionError(f"UDP echo mismatch: got={data!r}, expected suffix={payload!r}")


def check_metrics(url: str, label: str) -> None:
    with urllib.request.urlopen(url, timeout=5) as resp:
        if resp.status != 200:
            raise AssertionError(f"{label} metrics returned HTTP {resp.status}")
        body = resp.read().decode("utf-8", errors="replace")
        if not body.strip():
            raise AssertionError(f"{label} metrics body is empty")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit("Usage: smoke.py <label> [socks_host] [socks_port] [echo_host] [tcp_port] [udp_port]")
    label = sys.argv[1]
    socks_host = sys.argv[2] if len(sys.argv) > 2 else "cli"
    socks_port = int(sys.argv[3]) if len(sys.argv) > 3 else 1080
    echo_host = sys.argv[4] if len(sys.argv) > 4 else "echo"
    tcp_port = int(sys.argv[5]) if len(sys.argv) > 5 else 19001
    udp_port = int(sys.argv[6]) if len(sys.argv) > 6 else 19002

    socks5_tcp_echo(socks_host, socks_port, echo_host, tcp_port, f"tcp-{label}".encode())
    socks5_udp_echo(socks_host, socks_port, echo_host, udp_port, f"udp-{label}".encode())
    check_metrics("http://srv:9091/metrics", "server")
    check_metrics("http://cli:9092/metrics", "client")
    print(f"OK {label}: TCP + UDP round-trip and metrics passed")
