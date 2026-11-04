"""Rule-based Intrusion Detection System over packet captures.

Each rule maps to a real attack technique (MITRE ATT&CK id) and to a
networking concept it abuses:

    Port scan (SYN/NULL/FIN/XMAS)  TCP flags & handshake        T1046
    SYN flood                      TCP half-open connections    T1498
    Brute force (SSH/FTP/RDP...)   many connection attempts     T1110
    Ping sweep                     ICMP echo, host discovery    T1018
    ARP spoofing                   ARP has no authentication    T1557.002
    DNS tunnelling / DGA           DNS labels carrying data     T1071.004
    Cleartext credentials          HTTP/FTP unencrypted         T1040
"""

import math
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, asdict

from .pcap import FIN, SYN, PSH, URG, flags_to_str

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
BRUTE_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 3389: "RDP", 5900: "VNC"}
WEB_PORTS = {80, 8000, 8080}


@dataclass
class Alert:
    ts: float
    severity: str
    rule: str
    src: str
    dst: str
    detail: str
    mitre: str

    def as_dict(self):
        return asdict(self)


@dataclass
class Thresholds:
    scan_ports: int = 15          # distinct ports within window
    scan_window: float = 10.0
    synflood_rate: int = 100      # SYNs per second at one destination
    brute_attempts: int = 10      # connections to one service within window
    brute_window: float = 30.0
    sweep_hosts: int = 10         # distinct hosts pinged within window
    sweep_window: float = 10.0
    dns_long_label: int = 40
    dns_entropy: float = 3.6
    dns_unique_subdomains: int = 20


def shannon_entropy(text):
    """Bits per character - random-looking strings score high (> ~3.6)."""
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _scan_type(flags):
    return {SYN: "SYN scan", 0: "NULL scan", FIN: "FIN scan", FIN | PSH | URG: "XMAS scan"}.get(flags)


def _prune(window, now, span):
    while window and now - window[0][0] > span:
        window.popleft()


class IDS:
    def __init__(self, thresholds=None):
        self.t = thresholds or Thresholds()
        self.alerts = []
        self._seen = set()                              # de-duplicate alerts
        self._scan = defaultdict(deque)
        self._syn_dst = defaultdict(deque)
        self._brute = defaultdict(deque)
        self._sweep = defaultdict(deque)
        self._arp_table = {}
        self._dns_subs = defaultdict(set)
        # Once a rule fires we keep counting so the final alert shows the true
        # size of the attack, not just the moment the threshold was crossed.
        self._tally = {}          # dedupe key -> [alert, data, formatter]

    # ------------------------------------------------------------------ util
    def _alert(self, key, ts, severity, rule, src, dst, detail, mitre):
        if key in self._seen:
            return None
        self._seen.add(key)
        alert = Alert(ts, severity, rule, src, dst, detail, mitre)
        self.alerts.append(alert)
        return alert

    def _finalize(self):
        for alert, data, fmt in self._tally.values():
            alert.detail = fmt(data)

    # ----------------------------------------------------------------- rules
    def _port_scan(self, p):
        kind = _scan_type(p.tcp_flags)
        if not kind:
            return
        key = ("scan", p.ip_src, p.ip_dst, kind)
        if key in self._tally:
            self._tally[key][1].add(p.dport)
            return
        win = self._scan[(p.ip_src, p.ip_dst, kind)]
        win.append((p.ts, p.dport))
        _prune(win, p.ts, self.t.scan_window)
        ports = {d for _, d in win}
        if len(ports) >= self.t.scan_ports:
            flags = flags_to_str(p.tcp_flags)
            alert = self._alert(key, p.ts, "HIGH", f"Port scan ({kind})", p.ip_src, p.ip_dst, "", "T1046")
            self._tally[key] = [alert, set(ports), lambda s, f=flags: (
                f"{len(s)} distinct ports probed, {self.t.scan_ports}+ within "
                f"{self.t.scan_window:.0f}s (TCP flags: {f})")]

    def _syn_flood(self, p):
        if p.tcp_flags != SYN:
            return
        key = ("flood", p.ip_dst)
        win = self._syn_dst[p.ip_dst]
        win.append((p.ts, p.ip_src, p.dport))
        _prune(win, p.ts, 1.0)
        if key in self._tally:
            data = self._tally[key][1]
            data["peak"] = max(data["peak"], len(win))
            data["sources"].add(p.ip_src)
            return
        if len(win) >= self.t.synflood_rate:
            # A flood hammers ONE service; a fast port scan spreads SYNs over many ports.
            top_port, top_hits = Counter(d for _, _, d in win).most_common(1)[0]
            if top_hits < 0.8 * len(win):
                return
            data = {"peak": len(win), "sources": {s for _, s, _ in win}, "port": top_port}
            alert = self._alert(key, p.ts, "CRITICAL", "SYN flood", "multiple sources", p.ip_dst, "", "T1498")
            self._tally[key] = [alert, data, lambda d: (
                f"peak {d['peak']} SYN packets/second to port {d['port']} from {len(d['sources'])} "
                f"source IP(s){' - likely spoofed' if len(d['sources']) > 10 else ''}; half-open "
                f"connections exhaust the server's backlog")]

    def _brute_force(self, p):
        if p.tcp_flags != SYN or p.dport not in BRUTE_PORTS:
            return
        key = ("brute", p.ip_src, p.ip_dst, p.dport)
        if key in self._tally:
            self._tally[key][1][0] += 1
            return
        win = self._brute[(p.ip_src, p.ip_dst, p.dport)]
        win.append((p.ts, p.sport))
        _prune(win, p.ts, self.t.brute_window)
        if len(win) >= self.t.brute_attempts:
            alert = self._alert(key, p.ts, "HIGH", f"Brute force ({BRUTE_PORTS[p.dport]})",
                                p.ip_src, p.ip_dst, "", "T1110")
            self._tally[key] = [alert, [len(win)], lambda c, port=p.dport: (
                f"{c[0]} connection attempts to port {port}, {self.t.brute_attempts}+ within "
                f"{self.t.brute_window:.0f}s - consider lockout / fail2ban / key-only auth")]

    def _ping_sweep(self, p):
        if p.proto_name != "ICMP" or p.icmp_type != 8:
            return
        win = self._sweep[p.ip_src]
        win.append((p.ts, p.ip_dst))
        _prune(win, p.ts, self.t.sweep_window)
        hosts = {d for _, d in win}
        if len(hosts) >= self.t.sweep_hosts:
            self._alert(("sweep", p.ip_src), p.ts, "MEDIUM", "Ping sweep", p.ip_src, "multiple",
                        f"ICMP echo sent to {len(hosts)} different hosts in "
                        f"<= {self.t.sweep_window:.0f}s (host discovery)", "T1018")

    def _arp(self, p):
        if p.proto_name != "ARP" or p.arp_spa == "0.0.0.0":
            return
        known = self._arp_table.get(p.arp_spa)
        if known is None:
            self._arp_table[p.arp_spa] = p.arp_sha
        elif known != p.arp_sha:
            self._alert(("arp", p.arp_spa, p.arp_sha), p.ts, "CRITICAL", "ARP spoofing",
                        p.arp_sha, p.arp_spa,
                        f"{p.arp_spa} was at {known} but now claims {p.arp_sha} - "
                        f"possible man-in-the-middle", "T1557.002")

    def _dns(self, p):
        if not p.dns_qname or p.dport != 53:
            return
        labels = p.dns_qname.split(".")
        first = labels[0]
        base = ".".join(labels[-2:])
        long_label = max(len(l) for l in labels) >= self.t.dns_long_label
        random_like = len(first) >= 20 and shannon_entropy(first) >= self.t.dns_entropy
        if len(labels) > 2:
            self._dns_subs[(p.ip_src, base)].add(first)
        many = len(self._dns_subs[(p.ip_src, base)]) >= self.t.dns_unique_subdomains
        if long_label or random_like or many:
            reason = ("very long label" if long_label else
                      "high-entropy label" if random_like else "many unique subdomains")
            self._alert(("dns", p.ip_src, base), p.ts, "HIGH", "DNS tunnelling / DGA suspected",
                        p.ip_src, base,
                        f"{reason}; e.g. '{p.dns_qname[:60]}' (entropy {shannon_entropy(first):.2f})",
                        "T1071.004")

    def _cleartext(self, p):
        data = p.payload
        if not data or p.proto_name != "TCP":
            return
        if p.dport in WEB_PORTS:
            low = data.lower()
            if data.startswith(b"POST") and re.search(rb"(password|passwd|pwd)=", low):
                user = re.search(rb"(?:user(?:name)?|login|email)=([^&\s]+)", low)
                who = user.group(1).decode("latin-1") if user else "?"
                self._alert(("http", p.ip_src, p.ip_dst, who), p.ts, "HIGH",
                            "Credentials sent over HTTP", p.ip_src, p.ip_dst,
                            f"Login form POST in cleartext (user '{who}', password ****). "
                            f"Anyone on the path can read it - use HTTPS", "T1040")
            elif b"authorization: basic" in low:
                self._alert(("httpb", p.ip_src, p.ip_dst), p.ts, "HIGH", "HTTP Basic auth in cleartext",
                            p.ip_src, p.ip_dst, "Base64 is encoding, not encryption - use HTTPS", "T1040")
        elif p.dport == 21 and data[:5].upper() in (b"USER ", b"PASS "):
            cmd = data[:4].decode().upper()
            shown = data[5:].strip().decode("latin-1") if cmd == "USER" else "****"
            self._alert(("ftp", p.ip_src, p.ip_dst), p.ts, "HIGH", "Credentials sent over FTP",
                        p.ip_src, p.ip_dst,
                        f"FTP {cmd} {shown} observed in cleartext - use SFTP/FTPS", "T1040")

    # ------------------------------------------------------------------- run
    def run(self, packets):
        stats = {"packets": 0, "bytes": 0, "protocols": Counter(), "talkers": Counter(),
                 "dst_ports": Counter(), "hosts": set(), "first": None, "last": None}
        for p in packets:
            stats["packets"] += 1
            stats["bytes"] += p.length
            stats["protocols"][p.proto_name] += 1
            if p.dns_qname:
                stats["protocols"]["DNS"] += 1
            if p.ip_src:
                stats["talkers"][p.ip_src] += 1
                stats["hosts"].update((p.ip_src, p.ip_dst))
            if p.proto_name in ("TCP", "UDP"):
                stats["dst_ports"][p.dport] += 1
            stats["first"] = p.ts if stats["first"] is None else stats["first"]
            stats["last"] = p.ts

            if p.proto_name == "TCP":
                self._port_scan(p)
                self._syn_flood(p)
                self._brute_force(p)
                self._cleartext(p)
            elif p.proto_name == "ARP":
                self._arp(p)
            elif p.proto_name == "ICMP":
                self._ping_sweep(p)
            elif p.proto_name == "UDP":
                self._dns(p)

        self._finalize()
        self.alerts.sort(key=lambda a: (SEVERITY_ORDER[a.severity], a.ts))
        stats["hosts"] = len(stats["hosts"])
        stats["duration"] = round((stats["last"] or 0) - (stats["first"] or 0), 2)
        return self.alerts, stats
