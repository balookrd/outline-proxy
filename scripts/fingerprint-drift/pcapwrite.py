"""Write synthetic IPv4/TCP packets into a LINKTYPE_RAW pcap.

The sinks know the bytes a client sent, not the packets it sent them in; a
synthetic segment per chunk is enough for tshark's TLS / HTTP dissectors
(`-d tcp.port==<port>,tls|http2`). Thread-safe: one sink thread per
connection appends to the same file.
"""
import socket
import struct
import threading
import time

LINKTYPE_RAW = 101
CHUNK = 16000


def _checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


class PcapWriter:
    def __init__(self, path, server_port):
        self.server_port = server_port
        self.lock = threading.Lock()
        self.file = open(path, "wb")
        self.file.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_RAW))
        self.file.flush()

    def write_stream(self, client_port, data):
        """`data` as consecutive segments from 127.0.0.1:<client_port>."""
        with self.lock:
            seq = 1
            for i in range(0, max(len(data), 1), CHUNK):
                chunk = data[i:i + CHUNK]
                tcp = struct.pack("!HHIIBBHHH", client_port, self.server_port, seq, 1,
                                  0x50, 0x18, 65535, 0, 0) + chunk
                ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                                 socket.inet_aton("127.0.0.1"), socket.inet_aton("127.0.0.1"))
                ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
                packet = ip + tcp
                now = time.time()
                self.file.write(struct.pack("<IIII", int(now), int(now % 1 * 1e6),
                                            len(packet), len(packet)) + packet)
                seq += len(chunk)
            self.file.flush()

    def close(self):
        with self.lock:
            self.file.close()
