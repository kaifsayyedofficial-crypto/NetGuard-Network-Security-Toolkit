"""Run with:  python3 -m unittest discover -s tests -v"""

import os
import socket
import struct
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netguard import dnsutil, ids, labgen, pcap, scanner, subnet  # noqa: E402


class SubnetTests(unittest.TestCase):
    def test_slash24(self):
        d = subnet.describe("192.168.1.77/24")          # host bits are ignored
        self.assertEqual(d["network"], "192.168.1.0")
        self.assertEqual(d["broadcast"], "192.168.1.255")
        self.assertEqual(d["usable_hosts"], 254)
        self.assertEqual(d["first_host"], "192.168.1.1")
        self.assertEqual(d["class"], "C")
        self.assertTrue(d["private"])

    def test_edge_prefixes(self):
        self.assertEqual(subnet.describe("10.0.0.0/30")["usable_hosts"], 2)
        self.assertEqual(subnet.describe("10.0.0.0/31")["usable_hosts"], 2)
        self.assertEqual(subnet.describe("10.0.0.5/32")["usable_hosts"], 1)

    def test_split(self):
        self.assertEqual(subnet.split("10.0.0.0/24", 26),
                         ["10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"])

    def test_vlsm_no_overlap_and_big_first(self):
        plan = subnet.vlsm("192.168.0.0/24", [10, 100, 50, 25])
        self.assertEqual([p["subnet"] for p in plan],
                         ["192.168.0.0/25", "192.168.0.128/26", "192.168.0.192/27", "192.168.0.224/28"])
        for p in plan:
            self.assertGreaterEqual(p["usable_hosts"], p["requested_hosts"])

    def test_vlsm_too_big(self):
        with self.assertRaises(ValueError):
            subnet.vlsm("192.168.0.0/25", [100, 50])

    def test_same_subnet(self):
        self.assertTrue(subnet.same_subnet("10.0.0.5", "10.0.0.200", "255.255.255.0"))
        self.assertFalse(subnet.same_subnet("10.0.0.5", "10.0.1.5", 24))


class PacketTests(unittest.TestCase):
    def test_ip_header_checksum_verifies_to_zero(self):
        header = pcap.build_ipv4("10.0.0.1", "10.0.0.2", 6, b"")[:20]
        self.assertEqual(pcap.checksum(header), 0)

    def test_tcp_roundtrip(self):
        seg = pcap.build_tcp("10.0.0.1", "10.0.0.2", 1234, 80, flags=pcap.SYN | pcap.ACK, payload=b"hi")
        frame = pcap.build_ethernet("aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:01", pcap.ETH_IPV4,
                                    pcap.build_ipv4("10.0.0.1", "10.0.0.2", pcap.PROTO_TCP, seg))
        p = pcap.parse_frame(1.0, frame)
        self.assertEqual((p.proto_name, p.ip_src, p.ip_dst, p.sport, p.dport),
                         ("TCP", "10.0.0.1", "10.0.0.2", 1234, 80))
        self.assertEqual(p.tcp_flags, pcap.SYN | pcap.ACK)
        self.assertEqual(p.payload, b"hi")

    def test_arp_roundtrip(self):
        frame = pcap.build_ethernet("ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:01", pcap.ETH_ARP,
                                    pcap.build_arp(2, "aa:bb:cc:dd:ee:01", "10.0.0.1", "aa:bb:cc:dd:ee:02", "10.0.0.2"))
        p = pcap.parse_frame(0, frame)
        self.assertEqual((p.proto_name, p.arp_op, p.arp_spa, p.arp_sha),
                         ("ARP", 2, "10.0.0.1", "aa:bb:cc:dd:ee:01"))

    def test_pcap_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "t.pcap")
            self.assertGreater(labgen.generate(path, attacks=False, minutes=1), 20)
            packets = list(pcap.read_pcap(path))
            self.assertTrue(all(b.ts >= a.ts for a, b in zip(packets, packets[1:])))

    def test_rejects_garbage_file(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap") as fh:
            fh.write(b"this is definitely not a capture file")
            fh.flush()
            with self.assertRaises(ValueError):
                list(pcap.read_pcap(fh.name))


class DnsTests(unittest.TestCase):
    def test_query_wire_format(self):
        q = dnsutil.build_query("www.example.com", "A", txid=0x1234)
        self.assertEqual(q[:2], b"\x12\x34")
        self.assertIn(b"\x03www\x07example\x03com\x00", q)

    def test_parse_response_with_compression(self):
        q = dnsutil.build_query("example.com", "A", txid=7)
        header = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton("93.184.216.34")
        r = dnsutil.parse_response(header + q[12:] + answer)
        self.assertEqual(r["rcode"], "NOERROR")
        self.assertEqual(r["answers"][0]["data"], "93.184.216.34")
        self.assertEqual(r["answers"][0]["name"], "example.com")
        self.assertEqual(r["answers"][0]["ttl"], 300)


class ScannerTests(unittest.TestCase):
    def test_parse_ports(self):
        self.assertEqual(scanner.parse_ports("80, 22,8000-8002"), [22, 80, 8000, 8001, 8002])
        with self.assertRaises(ValueError):
            scanner.parse_ports("70000")

    def test_open_and_closed(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        open_port = srv.getsockname()[1]

        def serve():
            conn, _ = srv.accept()
            conn.sendall(b"SSH-2.0-TestServer\r\n")
            conn.close()

        threading.Thread(target=serve, daemon=True).start()
        tmp = socket.socket()
        tmp.bind(("127.0.0.1", 0))
        closed_port = tmp.getsockname()[1]
        tmp.close()                                      # nothing listens here any more
        res = scanner.scan("127.0.0.1", [open_port, closed_port], timeout=1)
        srv.close()
        states = {r["port"]: r["state"] for r in res["open_ports"]}
        self.assertEqual(states, {open_port: "open"})
        self.assertEqual(res["counts"]["closed"], 1)
        self.assertIn("SSH-2.0-TestServer", res["open_ports"][0]["banner"])


class IdsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.attack = os.path.join(cls.tmp.name, "attack.pcap")
        cls.clean = os.path.join(cls.tmp.name, "clean.pcap")
        labgen.generate(cls.attack, attacks=True)
        labgen.generate(cls.clean, attacks=False)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_clean_traffic_has_no_alerts(self):
        alerts, stats = ids.IDS().run(pcap.read_pcap(self.clean))
        self.assertEqual([a.rule for a in alerts], [])
        self.assertGreater(stats["packets"], 50)

    def test_every_attack_is_detected(self):
        alerts, _ = ids.IDS().run(pcap.read_pcap(self.attack))
        rules = {a.rule for a in alerts}
        expected = {"ARP spoofing", "SYN flood", "Port scan (SYN scan)", "Port scan (NULL scan)",
                    "Port scan (XMAS scan)", "Brute force (SSH)", "DNS tunnelling / DGA suspected",
                    "Credentials sent over HTTP", "Credentials sent over FTP", "Ping sweep"}
        self.assertEqual(rules, expected)

    def test_attributes_the_right_host(self):
        alerts, _ = ids.IDS().run(pcap.read_pcap(self.attack))
        by_rule = {a.rule: a for a in alerts}
        self.assertEqual(by_rule["Port scan (SYN scan)"].src, "192.168.1.66")
        self.assertEqual(by_rule["Port scan (SYN scan)"].dst, "192.168.1.10")
        self.assertEqual(by_rule["ARP spoofing"].src, "de:ad:be:ef:00:66")
        self.assertEqual(by_rule["DNS tunnelling / DGA suspected"].src, "192.168.1.22")

    def test_final_counts_reflect_whole_attack(self):
        alerts, _ = ids.IDS().run(pcap.read_pcap(self.attack))
        by_rule = {a.rule: a for a in alerts}
        self.assertIn("100 distinct ports", by_rule["Port scan (SYN scan)"].detail)
        self.assertIn("25 connection attempts", by_rule["Brute force (SSH)"].detail)

    def test_passwords_are_redacted(self):
        alerts, _ = ids.IDS().run(pcap.read_pcap(self.attack))
        text = " ".join(a.detail for a in alerts)
        self.assertNotIn("Winter2026", text)
        self.assertNotIn("Spring2026", text)

    def test_fast_port_scan_is_not_a_syn_flood(self):
        """300 SYNs/second across 300 DIFFERENT ports is a scan, not a flood."""
        path = os.path.join(self.tmp.name, "fastscan.pcap")
        with pcap.PcapWriter(path) as w:
            for i in range(300):
                seg = pcap.build_tcp("10.0.0.9", "10.0.0.10", 40000, 1 + i, flags=pcap.SYN)
                ip = pcap.build_ipv4("10.0.0.9", "10.0.0.10", pcap.PROTO_TCP, seg)
                w.write(1000 + i * 0.003, pcap.build_ethernet("aa:aa:aa:00:00:10", "aa:aa:aa:00:00:09",
                                                             pcap.ETH_IPV4, ip))
        alerts, _ = ids.IDS().run(pcap.read_pcap(path))
        self.assertEqual([a.rule for a in alerts], ["Port scan (SYN scan)"])

    def test_entropy(self):
        self.assertLess(ids.shannon_entropy("www"), 2)
        self.assertGreater(ids.shannon_entropy("yk4pja5mckoexi4gybe4vuo6hxjvodl4"), 4)


if __name__ == "__main__":
    unittest.main()
