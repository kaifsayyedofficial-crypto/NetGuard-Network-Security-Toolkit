"""Live packet capture on Linux using an AF_PACKET raw socket.

Needs root (or CAP_NET_RAW):   sudo python3 netguard.py sniff -i eth0 -c 200 -o live.pcap
The result is a standard .pcap, so feed it straight into `analyze`.
"""

import socket
import sys
import time

from .pcap import PcapWriter

ETH_P_ALL = 0x0003


def available():
    if not sys.platform.startswith("linux"):
        return False, "live capture is Linux-only (AF_PACKET)"
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        sock.close()
        return True, ""
    except PermissionError:
        return False, "permission denied - run with sudo / as root"
    except OSError as exc:
        return False, str(exc)


def capture(iface, out_path, count=100, seconds=30):
    """Capture up to `count` frames or `seconds`, whichever comes first."""
    ok, why = available()
    if not ok:
        raise RuntimeError(why)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    sock.bind((iface, 0))
    sock.settimeout(1.0)
    deadline = time.time() + seconds
    with PcapWriter(out_path) as writer, sock:
        while writer.count < count and time.time() < deadline:
            try:
                frame, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            # On loopback every packet is delivered twice (once as OUTGOING, once as
            # incoming), which would double all counts - keep only one copy.
            if iface == "lo" and addr[2] == socket.PACKET_OUTGOING:
                continue
            writer.write(time.time(), frame)
        return writer.count
