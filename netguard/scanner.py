"""TCP connect scanner with banner grabbing (Transport layer: TCP 3-way handshake).

A connect() scan completes the full handshake, so it needs no special
privileges. Result meaning:
    open      SYN/ACK received (connect succeeded)
    closed    RST received      (connection refused)
    filtered  no reply          (timeout - typically a firewall dropping packets)

ONLY scan systems you own or have written permission to test.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor

SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    67: "dhcp", 80: "http", 110: "pop3", 123: "ntp", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb", 514: "syslog",
    587: "smtp-submission", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}

RISKY = {
    21: "FTP sends credentials in cleartext - use SFTP/FTPS",
    23: "Telnet is unencrypted - replace with SSH",
    135: "MSRPC exposed - restrict to internal network",
    139: "NetBIOS exposed - disable if unused",
    445: "SMB exposed - common ransomware/worm entry point",
    1433: "Database exposed - restrict by firewall",
    3306: "Database exposed - restrict by firewall",
    3389: "RDP exposed - brute-force target, put behind VPN",
    5900: "VNC exposed - weak auth, put behind VPN",
    6379: "Redis often runs without auth - never expose",
    27017: "MongoDB often runs without auth - never expose",
}

HTTP_PORTS = {80, 8000, 8080, 8443}


def parse_ports(spec):
    """'22,80,8000-8100' -> sorted list of ints."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"invalid port(s): {bad[:3]}")
    return sorted(ports)


def _grab_banner(sock, host, port):
    try:
        sock.settimeout(1.0)
        if port in HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        data = sock.recv(256)
        text = data.decode("utf-8", "replace").strip().replace("\r", "")
        return text.split("\n")[0][:100] if port not in HTTP_PORTS else _http_summary(text)
    except OSError:
        return ""


def _http_summary(text):
    lines = text.split("\n")
    status = lines[0] if lines else ""
    server = next((l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("server:")), "")
    return f"{status} | Server: {server}" if server else status


def scan_port(host, port, timeout=1.0, banner=True):
    started = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except ConnectionRefusedError:
        return {"port": port, "state": "closed"}
    except (socket.timeout, TimeoutError):
        return {"port": port, "state": "filtered"}
    except OSError:
        return {"port": port, "state": "filtered"}
    with sock:
        result = {
            "port": port,
            "state": "open",
            "service": SERVICES.get(port, "unknown"),
            "rtt_ms": round((time.time() - started) * 1000, 2),
        }
        if banner:
            result["banner"] = _grab_banner(sock, host, port)
        if port in RISKY:
            result["risk"] = RISKY[port]
        return result


def scan(host, ports, timeout=1.0, threads=100, banner=True):
    """Scan ports concurrently. Returns dict with ip and per-port results."""
    ip = socket.gethostbyname(host)
    started = time.time()
    with ThreadPoolExecutor(max_workers=threads) as pool:
        results = list(pool.map(lambda p: scan_port(ip, p, timeout, banner), ports))
    counts = {"open": 0, "closed": 0, "filtered": 0}
    for r in results:
        counts[r["state"]] += 1
    return {
        "target": host,
        "ip": ip,
        "scanned": len(ports),
        "counts": counts,
        "elapsed_s": round(time.time() - started, 2),
        "open_ports": [r for r in results if r["state"] == "open"],
    }


def host_alive(host, ports=(80, 443, 22, 445), timeout=0.5):
    """TCP 'ping': a host is alive if any port answers or actively refuses.
    (ICMP ping needs raw sockets/root, so we use the handshake instead.)"""
    for port in ports:
        try:
            socket.create_connection((host, port), timeout=timeout).close()
            return True
        except ConnectionRefusedError:
            return True
        except OSError:
            continue
    return False
