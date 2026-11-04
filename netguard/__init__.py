"""NetGuard - a small, dependency-free network security toolkit.

Modules
-------
subnet   IPv4 addressing: CIDR maths, VLSM, binary view
scanner  TCP connect scanner with banner grabbing and risk flags
dnsutil  Hand-built DNS client (UDP/53) and parser
pcap     Packet builders + pcap reader/writer (Ethernet, ARP, IPv4, TCP, UDP, ICMP)
ids      Rule-based intrusion detection over packet captures
labgen   Synthetic lab traffic: normal behaviour plus 8 attack scenarios
sniffer  Live capture on Linux (AF_PACKET raw socket, needs root)
report   Self-contained HTML report
"""

__version__ = "1.0.0"
