"""A tiny DNS client built from scratch (RFC 1035) - UDP port 53."""

import random
import socket
import struct

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
QTYPE_NAMES = {v: k for k, v in QTYPES.items()}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def build_query(name, qtype="A", txid=None):
    """Build a standard recursive DNS query packet."""
    txid = random.randint(0, 0xFFFF) if txid is None else txid
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    qname = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if not 0 < len(raw) < 64:
            raise ValueError(f"bad label length in {name!r}")
        qname += bytes([len(raw)]) + raw
    qname += b"\x00"
    code = QTYPES[qtype] if isinstance(qtype, str) else qtype
    return header + qname + struct.pack("!HH", code, 1)  # class IN


def read_name(data, offset):
    """Read a (possibly compressed) domain name. Returns (name, next_offset)."""
    labels, jumped, next_offset, hops = [], False, offset, 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated name")
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:                      # compression pointer
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
            offset, jumped = pointer, True
            hops += 1
            if hops > 20:
                raise ValueError("compression loop")
            continue
        labels.append(data[offset + 1: offset + 1 + length].decode("ascii", "replace"))
        offset += 1 + length
    if not jumped:
        next_offset = offset
    return ".".join(labels), next_offset


def _rdata(rtype, data, offset, rdlength):
    raw = data[offset: offset + rdlength]
    if rtype == 1 and rdlength == 4:
        return socket.inet_ntoa(raw)
    if rtype == 28 and rdlength == 16:
        return socket.inet_ntop(socket.AF_INET6, raw)
    if rtype in (2, 5):
        return read_name(data, offset)[0]
    if rtype == 15:
        pref = struct.unpack("!H", raw[:2])[0]
        return f"{pref} {read_name(data, offset + 2)[0]}"
    if rtype == 16:
        out, i = [], 0
        while i < len(raw):
            n = raw[i]
            out.append(raw[i + 1: i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
        return " ".join(out)
    return raw.hex()


def parse_response(data):
    """Parse a DNS response into a dict."""
    if len(data) < 12:
        raise ValueError("short DNS message")
    txid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    questions = []
    for _ in range(qd):
        name, offset = read_name(data, offset)
        qtype, _qclass = struct.unpack("!HH", data[offset: offset + 4])
        offset += 4
        questions.append((name, QTYPE_NAMES.get(qtype, str(qtype))))
    answers = []
    for _ in range(an):
        name, offset = read_name(data, offset)
        rtype, _rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset: offset + 10])
        offset += 10
        answers.append({
            "name": name,
            "type": QTYPE_NAMES.get(rtype, str(rtype)),
            "ttl": ttl,
            "data": _rdata(rtype, data, offset, rdlength),
        })
        offset += rdlength
    return {
        "id": txid,
        "response": bool(flags & 0x8000),
        "rcode": RCODES.get(flags & 0xF, str(flags & 0xF)),
        "recursion_available": bool(flags & 0x0080),
        "questions": questions,
        "answers": answers,
    }


def system_resolver():
    """First nameserver from /etc/resolv.conf, falling back to 8.8.8.8."""
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "nameserver" and ":" not in parts[1]:
                    return parts[1]
    except OSError:
        pass
    return "8.8.8.8"


def query(name, qtype="A", server=None, timeout=3.0):
    """Send a query over UDP and return the parsed response."""
    server = server or system_resolver()
    packet = build_query(name, qtype)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(4096)
    result = parse_response(data)
    result["server"] = server
    return result
