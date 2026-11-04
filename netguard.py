#!/usr/bin/env python3
"""NetGuard - network security toolkit.

  python3 netguard.py demo                      full end-to-end run (start here)
  python3 netguard.py subnet 192.168.10.0/24 --split 26
  python3 netguard.py vlsm 192.168.0.0/24 100 50 25 10
  python3 netguard.py scan 127.0.0.1 -p 1-1024
  python3 netguard.py dns example.com --type MX
  python3 netguard.py lab -o lab.pcap           generate attack traffic
  python3 netguard.py analyze lab.pcap --html report.html
  sudo python3 netguard.py sniff -i eth0 -c 200 -o live.pcap
"""

import argparse
import http.server
import json
import os
import socket
import sys
import threading

from netguard import __version__, dnsutil, ids, labgen, pcap, report, scanner, sniffer, subnet

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
SEV_ANSI = {"CRITICAL": "1;41", "HIGH": "1;31", "MEDIUM": "1;33", "LOW": "1;32"}


def paint(text, code):
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text


def heading(text):
    print("\n" + paint(f"== {text} ", "1;36") + paint("=" * max(0, 66 - len(text)), "36"))


# ------------------------------------------------------------------ commands
def cmd_subnet(args):
    info = subnet.describe(args.cidr)
    heading(f"Subnet analysis: {info['cidr']}")
    rows = [("Network", info["network"]), ("Broadcast", info["broadcast"]),
            ("Netmask", f"{info['netmask']}  (/{info['prefix']})"), ("Wildcard", info["wildcard"]),
            ("Host range", f"{info['first_host']} - {info['last_host']}"),
            ("Usable hosts", f"{info['usable_hosts']:,}  (of {info['total_addresses']:,} addresses)"),
            ("Class", info["class"]), ("Private (RFC 1918)", "yes" if info["private"] else "no"),
            ("Mask (binary)", info["netmask_binary"]), ("Network (binary)", info["network_binary"])]
    for k, v in rows:
        print(f"  {k:<20}{v}")
    if args.split:
        subs = subnet.split(args.cidr, args.split)
        heading(f"Split into {len(subs)} x /{args.split}")
        for s in subs:
            d = subnet.describe(s)
            print(f"  {s:<18} {d['first_host']:>15} - {d['last_host']:<15} {d['usable_hosts']} hosts")


def cmd_vlsm(args):
    plan = subnet.vlsm(args.cidr, args.hosts)
    heading(f"VLSM plan for {args.cidr}")
    print(f"  {'Need':>6}  {'Subnet':<18}{'Mask':<16}{'Usable':>7}  Range")
    for p in plan:
        print(f"  {p['requested_hosts']:>6}  {p['subnet']:<18}{p['netmask']:<16}{p['usable_hosts']:>7}  "
              f"{p['first_host']} - {p['last_host']}")


def print_scan(result):
    c = result["counts"]
    heading(f"Port scan: {result['target']} ({result['ip']})")
    print(f"  {result['scanned']} ports in {result['elapsed_s']}s  ->  "
          f"{c['open']} open, {c['closed']} closed, {c['filtered']} filtered")
    if not result["open_ports"]:
        print("  No open ports found.")
        return
    print(f"\n  {'PORT':<10}{'SERVICE':<12}{'BANNER / NOTES'}")
    for r in result["open_ports"]:
        print(f"  {str(r['port']) + '/tcp':<10}{r['service']:<12}{r.get('banner', '')}")
        if "risk" in r:
            print(f"  {'':<22}" + paint(f"! {r['risk']}", "33"))


def cmd_scan(args):
    ports = scanner.parse_ports(args.ports)
    if args.target not in ("127.0.0.1", "localhost", "::1"):
        print(paint("Reminder: only scan systems you own or are authorised to test.", "33"))
    print_scan(scanner.scan(args.target, ports, args.timeout, args.threads, not args.no_banner))


def cmd_dns(args):
    try:
        res = dnsutil.query(args.name, args.type, args.server, args.timeout)
    except (OSError, ValueError) as exc:
        sys.exit(f"DNS query failed: {exc}")
    heading(f"DNS {args.type} {args.name}  via {res['server']}")
    print(f"  status: {res['rcode']}   recursion available: {res['recursion_available']}")
    for a in res["answers"]:
        print(f"  {a['name']:<30}{a['ttl']:>6}s  {a['type']:<6}{a['data']}")
    if not res["answers"]:
        print("  (no answers)")


def cmd_lab(args):
    n = labgen.generate(args.out, attacks=not args.clean, minutes=args.minutes)
    print(f"Wrote {n:,} packets to {args.out}" + (" (clean baseline)" if args.clean else " (normal + 8 attacks)"))


def print_analysis(alerts, stats):
    heading("Traffic summary")
    protos = ", ".join(f"{k} {v}" for k, v in stats["protocols"].most_common())
    print(f"  {stats['packets']:,} packets / {stats['bytes']:,} bytes / {stats['hosts']} hosts / "
          f"{stats['duration']}s")
    print(f"  protocols : {protos}")
    print("  top talkers: " + ", ".join(f"{ip} ({n})" for ip, n in stats["talkers"].most_common(4)))
    top_ports = ", ".join(f"{p}/{scanner.SERVICES.get(p, '?')} ({n})" for p, n in stats["dst_ports"].most_common(5))
    print(f"  top dst ports: {top_ports}")
    heading(f"Detections: {len(alerts)}")
    if not alerts:
        print("  " + paint("No suspicious activity detected.", "32"))
    for a in alerts:
        print(f"  {paint(f'[{a.severity}]', SEV_ANSI[a.severity])} {a.rule}  ({a.mitre})")
        print(f"      {a.src} -> {a.dst}")
        print(f"      {a.detail}")


def cmd_analyze(args):
    alerts, stats = ids.IDS().run(pcap.read_pcap(args.pcap))
    if args.json:
        payload = {"stats": {**stats, "protocols": dict(stats["protocols"]),
                             "talkers": dict(stats["talkers"]), "dst_ports": dict(stats["dst_ports"])},
                   "alerts": [a.as_dict() for a in alerts]}
        print(json.dumps(payload, indent=2))
    else:
        print_analysis(alerts, stats)
    if args.html:
        print(f"\nHTML report: {report.build(args.html, alerts, stats)}")
    return alerts


def cmd_sniff(args):
    ok, why = sniffer.available()
    if not ok:
        sys.exit(f"Cannot capture: {why}")
    print(f"Capturing up to {args.count} packets on {args.iface} (max {args.seconds}s)...")
    n = sniffer.capture(args.iface, args.out, args.count, args.seconds)
    print(f"Saved {n} packets to {args.out}. Analyse with: python3 netguard.py analyze {args.out}")


# ---------------------------------------------------------------------- demo
class _QuietHTTP(http.server.BaseHTTPRequestHandler):
    server_version = "NetGuardLab/1.0"

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    do_GET = do_HEAD

    def log_message(self, *a):
        pass


def _banner_server(sock, banner):
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        with conn:
            try:
                conn.sendall(banner)
            except OSError:
                pass


def start_lab_servers():
    """Start tiny local services so the scanner has something real to find."""
    specs = [(21, b"220 NetGuard-Lab FTP ready\r\n"), (22, b"SSH-2.0-OpenSSH_9.6 (lab)\r\n"),
             (23, b"Lab Telnet login: "), (8080, None)]
    socks, ports = [], []
    for want, banner in specs:
        port = want
        for attempt in (want, 0):                   # privileged port may be refused -> pick a free one
            try:
                if banner is None:
                    srv = http.server.ThreadingHTTPServer(("127.0.0.1", attempt), _QuietHTTP)
                    threading.Thread(target=srv.serve_forever, daemon=True).start()
                    socks.append(srv)
                    port = srv.server_address[1]
                else:
                    s = socket.socket()
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # survive TIME_WAIT
                    s.bind(("127.0.0.1", attempt))
                    s.listen(8)
                    threading.Thread(target=_banner_server, args=(s, banner), daemon=True).start()
                    socks.append(s)
                    port = s.getsockname()[1]
                break
            except OSError:
                continue
        ports.append(port)
    return ports, socks


def cmd_demo(args):
    out_dir = args.out
    os.makedirs(out_dir, exist_ok=True)
    print(paint(f"NetGuard {__version__} - end-to-end demo", "1;35"))

    heading("1/5  Addressing: subnet 192.168.10.0/24 and VLSM")
    cmd_subnet(argparse.Namespace(cidr="192.168.10.0/24", split=26))
    cmd_vlsm(argparse.Namespace(cidr="192.168.20.0/24", hosts=[100, 50, 25, 10]))

    heading("2/5  Transport layer: TCP scan of local lab services")
    ports, socks = start_lab_servers()
    try:
        spec = ",".join(str(p) for p in sorted(set(ports))) + ",1-1024"
        scan_result = scanner.scan("127.0.0.1", scanner.parse_ports(spec), timeout=0.5)
        print_scan(scan_result)
    finally:
        for s in socks:
            try:
                if isinstance(s, http.server.HTTPServer):
                    s.shutdown()
                    s.server_close()
                else:
                    s.close()
            except OSError:
                pass

    heading("3/5  Application layer: hand-built DNS lookup")
    try:
        cmd_dns(argparse.Namespace(name="example.com", type="A", server=None, timeout=2.0))
    except SystemExit as exc:
        print(f"  skipped - {exc} (no network / DNS in this environment)")

    heading("4/5  Packet analysis: lab traffic with 8 hidden attacks")
    pcap_path = os.path.join(out_dir, "lab_traffic.pcap")
    cmd_lab(argparse.Namespace(out=pcap_path, clean=False, minutes=3))
    alerts, stats = ids.IDS().run(pcap.read_pcap(pcap_path))
    print_analysis(alerts, stats)

    heading("5/5  Reporting")
    path = report.build(os.path.join(out_dir, "report.html"), alerts, stats, scan_result)
    print(f"  HTML report : {path}\n  Packet file : {pcap_path}  (open in Wireshark)")


# ----------------------------------------------------------------------- CLI
def build_parser():
    p = argparse.ArgumentParser(prog="netguard", description="Network security toolkit")
    p.add_argument("--version", action="version", version=f"netguard {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("demo", help="run everything end to end")
    s.add_argument("-o", "--out", default="output")
    s.set_defaults(fn=cmd_demo)

    s = sub.add_parser("subnet", help="CIDR calculator")
    s.add_argument("cidr")
    s.add_argument("--split", type=int, metavar="PREFIX", help="split into /PREFIX subnets")
    s.set_defaults(fn=cmd_subnet)

    s = sub.add_parser("vlsm", help="variable-length subnet plan")
    s.add_argument("cidr")
    s.add_argument("hosts", type=int, nargs="+", help="hosts needed per subnet")
    s.set_defaults(fn=cmd_vlsm)

    s = sub.add_parser("scan", help="TCP connect scan")
    s.add_argument("target")
    s.add_argument("-p", "--ports", default="1-1024")
    s.add_argument("-t", "--timeout", type=float, default=1.0)
    s.add_argument("--threads", type=int, default=100)
    s.add_argument("--no-banner", action="store_true")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("dns", help="DNS lookup over UDP/53")
    s.add_argument("name")
    s.add_argument("--type", default="A", choices=list(dnsutil.QTYPES))
    s.add_argument("--server")
    s.add_argument("--timeout", type=float, default=3.0)
    s.set_defaults(fn=cmd_dns)

    s = sub.add_parser("lab", help="generate lab pcap")
    s.add_argument("-o", "--out", default="lab_traffic.pcap")
    s.add_argument("--clean", action="store_true", help="normal traffic only (no attacks)")
    s.add_argument("--minutes", type=int, default=3)
    s.set_defaults(fn=cmd_lab)

    s = sub.add_parser("analyze", help="run the IDS over a pcap")
    s.add_argument("pcap")
    s.add_argument("--html", metavar="FILE")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_analyze)

    s = sub.add_parser("sniff", help="live capture (Linux, root)")
    s.add_argument("-i", "--iface", default="eth0")
    s.add_argument("-c", "--count", type=int, default=100)
    s.add_argument("-s", "--seconds", type=int, default=30)
    s.add_argument("-o", "--out", default="live.pcap")
    s.set_defaults(fn=cmd_sniff)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        args.fn(args)
    except (ValueError, OSError, RuntimeError) as exc:
        sys.exit(f"error: {exc}")


if __name__ == "__main__":
    main()
