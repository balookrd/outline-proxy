#!/usr/bin/env python3
"""Minimal TCP + UDP echo server for the Docker smoke stand."""

import socket
import threading


def handle_tcp(conn: socket.socket) -> None:
    try:
        while data := conn.recv(4096):
            conn.sendall(data)
    finally:
        conn.close()


def tcp_loop() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 19001))
    srv.listen(64)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_tcp, args=(conn,), daemon=True).start()


def udp_loop() -> None:
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", 19002))
    while True:
        data, addr = udp.recvfrom(65535)
        udp.sendto(data, addr)


if __name__ == "__main__":
    threading.Thread(target=tcp_loop, daemon=True).start()
    udp_loop()
