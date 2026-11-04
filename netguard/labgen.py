"""Synthetic lab traffic: realistic normal behaviour + 8 attack scenarios.

Real packets are crafted byte-by-byte (valid checksums) and written to a
.pcap you can also open in Wireshark. Everything is private-range
(192.168.1.0/24) and entirely fictional.

Network map
    192.168.1.1    gateway / DNS resolver
    192.168.1.10   web + FTP + SSH server  (the victim)
    192.168.1.20-23  employee workstations
    192.168.1.66   attacker
"""

import random

from . import dnsutil
from .pcap import (ACK, ETH_ARP, ETH_IPV4, FIN, PROTO_ICMP, PROTO_TCP, PROTO_UDP, PSH, SYN, URG,
                   PcapWriter, build_arp, build_ethernet, build_icmp, build_ipv4, build_tcp,
                   build_udp)

BASE_TS = 1_767_000_000.0
GATEWAY = ("192.168.1.1", "aa:aa:aa:00:00:01")
SERVER = ("192.168.1.10", "aa:aa:aa:00:00:10")
CLIENTS = [(f"192.168.1.{20 + i}", f"aa:aa:aa:00:00:{20 + i:02x}") for i in range(4)]
ATTACKER = ("192.168.1.66", "de:ad:be:ef:00:66")
BROADCAST = "ff:ff:ff:ff:ff:ff"

NORMAL_SITES = ["www.example.com", "mail.example.com", "intranet.example.com",
                "docs.example.com", "update.example.com"]


class _Lab:
    def __init__(self, seed):
        self.rng = random.Random(seed)
        self.frames = []          # (ts, bytes)

    def _add(self, ts, frame):
        self.frames.append((ts, frame))

    def ip(self, ts, src, dst, proto, l4):
        frame = build_ethernet(dst[1], src[1], ETH_IPV4,
                               build_ipv4(src[0], dst[0], proto, l4, ident=self.rng.randint(1, 65535)))
        self._add(ts, frame)

    def tcp(self, ts, src, dst, sport, dport, flags, payload=b"", seq=1000, ack=0):
        self.ip(ts, src, dst, PROTO_TCP, build_tcp(src[0], dst[0], sport, dport, seq, ack, flags, payload))

    def udp(self, ts, src, dst, sport, dport, payload):
        self.ip(ts, src, dst, PROTO_UDP, build_udp(src[0], dst[0], sport, dport, payload))

    def arp(self, ts, op, sender, target, eth_dst):
        self._add(ts, build_ethernet(eth_dst, sender[1], ETH_ARP,
                                     build_arp(op, sender[1], sender[0], target[1], target[0])))

    def handshake(self, ts, client, server, dport, request=b"", response=b""):
        """Full TCP session: SYN, SYN/ACK, ACK, data, ACK, FIN."""
        sport = self.rng.randint(40000, 60000)
        self.tcp(ts, client, server, sport, dport, SYN, seq=100)
        self.tcp(ts + 0.01, server, client, dport, sport, SYN | ACK, seq=500, ack=101)
        self.tcp(ts + 0.02, client, server, sport, dport, ACK, seq=101, ack=501)
        if request:
            self.tcp(ts + 0.03, client, server, sport, dport, PSH | ACK, request, seq=101, ack=501)
        if response:
            self.tcp(ts + 0.05, server, client, dport, sport, PSH | ACK, response, seq=501, ack=101 + len(request))
        self.tcp(ts + 0.08, client, server, sport, dport, FIN | ACK, seq=101 + len(request), ack=501)


# ---------------------------------------------------------------- scenarios
def _normal(lab, start, minutes):
    """Boring, healthy traffic: ARP, DNS, web browsing, pings."""
    for host in [GATEWAY, SERVER] + CLIENTS:        # each host announces itself once
        lab.arp(start, 2, host, host, BROADCAST)
    t = start + 1
    end = start + minutes * 60
    while t < end:
        client = lab.rng.choice(CLIENTS)
        name = lab.rng.choice(NORMAL_SITES)
        lab.udp(t, client, GATEWAY, lab.rng.randint(40000, 60000), 53, dnsutil.build_query(name))
        lab.handshake(t + 0.05, client, SERVER, 80,
                      b"GET / HTTP/1.1\r\nHost: intranet.example.com\r\n\r\n",
                      b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello")
        if lab.rng.random() < 0.3:
            lab.ip(t + 0.5, client, GATEWAY, PROTO_ICMP, build_icmp(8))
        t += lab.rng.uniform(1.5, 4.0)


def _arp_spoof(lab, t):
    for i in range(4):                               # poisoning replies to victims
        lab.arp(t + i, 2, (GATEWAY[0], ATTACKER[1]), CLIENTS[i % len(CLIENTS)], CLIENTS[i % len(CLIENTS)][1])


def _port_scans(lab, t):
    for i, port in enumerate(range(1, 101)):         # classic SYN scan
        lab.tcp(t + i * 0.05, ATTACKER, SERVER, 54321, port, SYN)
    for i, port in enumerate(range(200, 230)):       # stealthy NULL scan
        lab.tcp(t + 8 + i * 0.05, ATTACKER, SERVER, 54322, port, 0)
    for i, port in enumerate(range(300, 330)):       # XMAS scan (FIN+PSH+URG)
        lab.tcp(t + 12 + i * 0.05, ATTACKER, SERVER, 54323, port, FIN | PSH | URG)


def _ping_sweep(lab, t):
    for i in range(1, 31):
        target = (f"192.168.1.{i}", "aa:aa:aa:00:00:ff")
        lab.ip(t + i * 0.1, ATTACKER, target, PROTO_ICMP, build_icmp(8, seq=i))


def _ssh_bruteforce(lab, t):
    for i in range(25):
        lab.handshake(t + i * 0.8, ATTACKER, SERVER, 22,
                      b"SSH-2.0-libssh_0.9\r\n", b"SSH-2.0-OpenSSH_9.6\r\n")


def _syn_flood(lab, t):
    for i in range(300):
        spoofed = (f"10.{lab.rng.randint(0, 255)}.{lab.rng.randint(0, 255)}.{lab.rng.randint(1, 254)}", ATTACKER[1])
        lab.tcp(t + i * 0.003, spoofed, SERVER, lab.rng.randint(1024, 65535), 80, SYN)


def _dns_tunnel(lab, t):
    client = CLIENTS[2]
    for i in range(25):
        chunk = "".join(lab.rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(48))
        lab.udp(t + i * 0.4, client, GATEWAY, 41000 + i, 53,
                dnsutil.build_query(f"{chunk}.t.evil-tunnel.example"))


def _cleartext_creds(lab, t):
    body = b"username=alice&password=Winter2026%21"
    http = (b"POST /login HTTP/1.1\r\nHost: intranet.example.com\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    lab.handshake(t, CLIENTS[0], SERVER, 80, http, b"HTTP/1.1 302 Found\r\n\r\n")
    lab.handshake(t + 2, CLIENTS[1], SERVER, 21, b"USER bob\r\n", b"331 Password required\r\n")
    sport = 45000
    lab.tcp(t + 2.2, CLIENTS[1], SERVER, sport, 21, PSH | ACK, b"PASS Spring2026!\r\n")


# --------------------------------------------------------------------- API
SCENARIOS = {
    "arp_spoof": _arp_spoof,
    "port_scans": _port_scans,
    "ping_sweep": _ping_sweep,
    "ssh_bruteforce": _ssh_bruteforce,
    "syn_flood": _syn_flood,
    "dns_tunnel": _dns_tunnel,
    "cleartext_creds": _cleartext_creds,
}


def generate(path, attacks=True, minutes=3, seed=7):
    """Write a lab capture to `path`. Returns the number of packets."""
    lab = _Lab(seed)
    _normal(lab, BASE_TS, minutes)
    if attacks:
        offset = 40
        for fn in SCENARIOS.values():
            fn(lab, BASE_TS + offset)
            offset += 22
    lab.frames.sort(key=lambda item: item[0])
    with PcapWriter(path) as writer:
        for ts, frame in lab.frames:
            writer.write(ts, frame)
        return writer.count
