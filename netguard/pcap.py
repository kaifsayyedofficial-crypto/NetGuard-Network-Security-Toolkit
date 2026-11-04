"""Packet crafting and parsing from first principles.

Covers the TCP/IP stack layer by layer:
    L2  Ethernet II, ARP
    L3  IPv4, ICMP
    L4  TCP, UDP
    L7  DNS (via dnsutil), HTTP/FTP payloads (inspected by the IDS)
plus the classic libpcap file format so captures open in Wireshark.
"""

import socket
import struct
from dataclasses import dataclass, field

from . import dnsutil

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
ETH_IPV4, ETH_ARP = 0x0800, 0x0806
PROTO_ICMP, PROTO_TCP, PROTO_UDP = 1, 6, 17

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


# ----------------------------------------------------------------- helpers
def checksum(data):
    """Internet checksum (RFC 1071): ones-complement sum of 16-bit words."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def mac_to_bytes(mac):
    return bytes(int(x, 16) for x in mac.split(":"))


def bytes_to_mac(raw):
    return ":".join(f"{b:02x}" for b in raw)


def flags_to_str(flags):
    names = [(FIN, "FIN"), (SYN, "SYN"), (RST, "RST"), (PSH, "PSH"), (ACK, "ACK"), (URG, "URG")]
    return "|".join(n for bit, n in names if flags & bit) or "NULL"


# ---------------------------------------------------------------- builders
def build_ethernet(dst_mac, src_mac, ethertype, payload):
    return mac_to_bytes(dst_mac) + mac_to_bytes(src_mac) + struct.pack("!H", ethertype) + payload


def build_arp(op, sender_mac, sender_ip, target_mac, target_ip):
    """op 1 = who-has (request), op 2 = is-at (reply)."""
    return struct.pack(
        "!HHBBH6s4s6s4s", 1, ETH_IPV4, 6, 4, op,
        mac_to_bytes(sender_mac), socket.inet_aton(sender_ip),
        mac_to_bytes(target_mac), socket.inet_aton(target_ip),
    )


def build_ipv4(src, dst, proto, payload, ttl=64, ident=0):
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, ttl, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    chk = checksum(header)
    return header[:10] + struct.pack("!H", chk) + header[12:] + payload


def _pseudo_header(src, dst, proto, length):
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, proto, length)


def build_tcp(src_ip, dst_ip, sport, dport, seq=0, ack=0, flags=SYN, payload=b"", window=64240):
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, window, 0, 0)
    segment = header + payload
    chk = checksum(_pseudo_header(src_ip, dst_ip, PROTO_TCP, len(segment)) + segment)
    return segment[:16] + struct.pack("!H", chk) + segment[18:]


def build_udp(src_ip, dst_ip, sport, dport, payload=b""):
    length = 8 + len(payload)
    segment = struct.pack("!HHHH", sport, dport, length, 0) + payload
    chk = checksum(_pseudo_header(src_ip, dst_ip, PROTO_UDP, length) + segment) or 0xFFFF
    return segment[:6] + struct.pack("!H", chk) + segment[8:]


def build_icmp(icmp_type, code=0, ident=1, seq=1, payload=b"abcdefghijklmnop"):
    """type 8 = echo request, 0 = echo reply."""
    body = struct.pack("!BBHHH", icmp_type, code, 0, ident, seq) + payload
    return body[:2] + struct.pack("!H", checksum(body)) + body[4:]


# ------------------------------------------------------------ pcap writer
class PcapWriter:
    def __init__(self, path):
        self._fh = open(path, "wb")
        self._fh.write(struct.pack("!IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET))
        self.count = 0

    def write(self, ts, frame):
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        self._fh.write(struct.pack("!IIII", sec, usec, len(frame), len(frame)) + frame)
        self.count += 1

    def close(self):
        self._fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ------------------------------------------------------------ pcap reader
@dataclass
class Packet:
    ts: float
    length: int
    eth_src: str = ""
    eth_dst: str = ""
    ethertype: int = 0
    proto_name: str = "OTHER"          # ARP / TCP / UDP / ICMP / OTHER
    ip_src: str = ""
    ip_dst: str = ""
    ttl: int = 0
    sport: int = 0
    dport: int = 0
    tcp_flags: int = 0
    payload: bytes = field(default=b"", repr=False)
    arp_op: int = 0
    arp_sha: str = ""
    arp_spa: str = ""
    arp_tpa: str = ""
    icmp_type: int = -1
    dns_qname: str = ""


def parse_frame(ts, frame):
    pkt = Packet(ts=ts, length=len(frame))
    if len(frame) < 14:
        return pkt
    pkt.eth_dst = bytes_to_mac(frame[0:6])
    pkt.eth_src = bytes_to_mac(frame[6:12])
    pkt.ethertype = struct.unpack("!H", frame[12:14])[0]
    body = frame[14:]

    if pkt.ethertype == ETH_ARP and len(body) >= 28:
        _, _, _, _, op, sha, spa, _tha, tpa = struct.unpack("!HHBBH6s4s6s4s", body[:28])
        pkt.proto_name, pkt.arp_op = "ARP", op
        pkt.arp_sha, pkt.arp_spa, pkt.arp_tpa = bytes_to_mac(sha), socket.inet_ntoa(spa), socket.inet_ntoa(tpa)
        return pkt

    if pkt.ethertype != ETH_IPV4 or len(body) < 20:
        return pkt
    ihl = (body[0] & 0x0F) * 4
    pkt.ttl, proto = body[8], body[9]
    pkt.ip_src, pkt.ip_dst = socket.inet_ntoa(body[12:16]), socket.inet_ntoa(body[16:20])
    seg = body[ihl:struct.unpack("!H", body[2:4])[0]]

    if proto == PROTO_TCP and len(seg) >= 20:
        pkt.proto_name = "TCP"
        pkt.sport, pkt.dport = struct.unpack("!HH", seg[:4])
        offset = (seg[12] >> 4) * 4
        pkt.tcp_flags = seg[13] & 0x3F
        pkt.payload = seg[offset:]
    elif proto == PROTO_UDP and len(seg) >= 8:
        pkt.proto_name = "UDP"
        pkt.sport, pkt.dport = struct.unpack("!HH", seg[:4])
        pkt.payload = seg[8:]
        if 53 in (pkt.sport, pkt.dport) and len(pkt.payload) > 12:
            try:
                pkt.dns_qname = dnsutil.read_name(pkt.payload, 12)[0]
            except (ValueError, IndexError):
                pass
    elif proto == PROTO_ICMP and len(seg) >= 4:
        pkt.proto_name = "ICMP"
        pkt.icmp_type = seg[0]
        pkt.payload = seg[8:]
    return pkt


def read_pcap(path):
    """Yield Packet objects from a classic libpcap file."""
    with open(path, "rb") as fh:
        head = fh.read(24)
        if len(head) < 24:
            raise ValueError("not a pcap file (too short)")
        # The writer's byte order is revealed by how the magic number reads back.
        if struct.unpack("<I", head[:4])[0] == PCAP_MAGIC:
            endian = "<"
        elif struct.unpack(">I", head[:4])[0] == PCAP_MAGIC:
            endian = ">"
        else:
            raise ValueError("not a classic pcap file (pcapng is not supported)")
        linktype = struct.unpack(endian + "I", head[20:24])[0]
        if linktype != LINKTYPE_ETHERNET:
            raise ValueError(f"unsupported link type {linktype} (need Ethernet)")
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                return
            sec, usec, incl, _orig = struct.unpack(endian + "IIII", rec)
            frame = fh.read(incl)
            yield parse_frame(sec + usec / 1_000_000, frame)
