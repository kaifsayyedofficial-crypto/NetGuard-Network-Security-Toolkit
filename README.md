# NetGuard - Network Security Toolkit

A small, working network-security project written in pure Python (standard library only, no installs).
It builds packets byte by byte, scans hosts, performs DNS lookups, captures live traffic and runs an
intrusion-detection engine that spots 8 real attack techniques - then produces an HTML report.

```
python3 netguard.py demo     
```

Requires Python 3.9+. Works on Linux/macOS/Windows (live capture is Linux-only).

## What it demonstrates

| Networking fundamental | Where it shows up | File |
|---|---|---|
| IP addressing, CIDR, subnet masks, VLSM | `subnet` / `vlsm` commands | `netguard/subnet.py` |
| Ethernet frames, MAC addresses | packet builder + parser | `netguard/pcap.py` |
| ARP (IP to MAC resolution) | ARP packets, spoofing detection | `pcap.py`, `ids.py` |
| IPv4 header, TTL, checksums | `build_ipv4`, RFC 1071 checksum | `pcap.py` |
| ICMP (ping) | echo requests, ping-sweep detection | `pcap.py`, `ids.py` |
| TCP: flags, 3-way handshake, ports | connect scanner, scan-type detection | `scanner.py`, `ids.py` |
| UDP | DNS transport | `pcap.py`, `dnsutil.py` |
| DNS (query format, record types, compression) | from-scratch resolver | `netguard/dnsutil.py` |
| HTTP / FTP (cleartext vs encrypted) | credential-exposure detection | `ids.py` |
| Packet capture, pcap format, Wireshark | live sniffer + `.pcap` reader/writer | `sniffer.py`, `pcap.py` |

## Commands

```bash
python3 netguard.py subnet 192.168.10.0/24 --split 26     # CIDR calculator
python3 netguard.py vlsm 192.168.20.0/24 100 50 25 10     # variable-length subnet plan
python3 netguard.py scan 127.0.0.1 -p 1-1024               # TCP scan + banner grab + risk flags
python3 netguard.py dns example.com --type MX              # hand-built DNS client
python3 netguard.py lab -o lab.pcap                        # synthetic traffic with 8 attacks
python3 netguard.py lab -o clean.pcap --clean              # normal traffic only
python3 netguard.py analyze lab.pcap --html report.html    # IDS + HTML report (add --json for JSON)
sudo python3 netguard.py sniff -i eth0 -c 500 -o live.pcap # live capture, then analyze it
```

### Live demo recipe (works on one machine)

```bash
sudo python3 netguard.py sniff -i lo -c 1000 -s 10 -o live.pcap &   # terminal 1
python3 netguard.py scan 127.0.0.1 -p 1-300 --no-banner             # terminal 2
python3 netguard.py analyze live.pcap                               # after sniff finishes
```
The IDS reports `Port scan (SYN scan)` - you attacked yourself and caught it.

## Detection rules

| Rule | How it works | MITRE ATT&CK |
|---|---|---|
| Port scan (SYN / NULL / FIN / XMAS) | 15+ distinct ports from one source within 10s, classified by TCP flags | T1046 |
| SYN flood | 100+ SYNs/second concentrated on one port (a scan spreads over many ports) | T1498 |
| Brute force (SSH/FTP/Telnet/RDP/VNC) | 10+ connections to one service within 30s | T1110 |
| Ping sweep | ICMP echo to 10+ different hosts within 10s | T1018 |
| ARP spoofing | an IP suddenly claimed by a different MAC address | T1557.002 |
| DNS tunnelling / DGA | very long labels, high Shannon entropy, or many unique subdomains | T1071.004 |
| Cleartext credentials | HTTP login POST / Basic auth, FTP `USER`/`PASS` (passwords are masked in output) | T1040 |

Thresholds live in `Thresholds` (top of `ids.py`) and are easy to tune.

## Tests

```bash
python3 -m unittest discover -s tests -v     # 22 tests
```
Covers subnet maths, VLSM, checksums, packet build/parse round-trips, DNS compression parsing, the
scanner against a real local server, and the IDS: clean traffic raises zero alerts, every attack is
detected and attributed to the right host, passwords never leak into alerts, and a fast port scan is
not misreported as a SYN flood.

## Project layout

```
netguard.py          CLI entry point (demo, subnet, vlsm, scan, dns, lab, analyze, sniff)
netguard/
  subnet.py          CIDR, split, VLSM
  scanner.py         threaded TCP connect scan, banners, risky-service hints
  dnsutil.py         DNS packet builder/parser over UDP
  pcap.py            Ethernet/ARP/IPv4/TCP/UDP/ICMP builders, pcap read/write
  ids.py             detection engine
  labgen.py          synthetic network + attack scenarios
  sniffer.py         AF_PACKET live capture
  report.py          HTML report
tests/               unit tests
output/              sample results from a demo run (report.html, .pcap files)
INTERVIEW.md         talk track + Q&A
```

## Limitations (be upfront about these)

- A connect scan is noisy and slower than a raw SYN scan; real tools (Nmap) use raw sockets.
- IPv4 and Ethernet only; classic `.pcap` only (no pcapng, no IPv6, no VLAN tags, no fragmentation reassembly).
- Rule-based detection catches known patterns; it will not catch novel attacks and can false-positive
  (e.g., a legitimate vulnerability scanner). Production IDS tools: Suricata, Snort, Zeek.
- Cannot inspect encrypted (TLS) payloads - only metadata.
- The lab traffic is synthetic. The `.pcap` files were checked with this project's own reader, not with Wireshark, so open one in Wireshark yourself before the interview.

## Ethics

Scan and capture only networks you own or have written permission to test. The lab generator uses
private address space and fictional credentials.
