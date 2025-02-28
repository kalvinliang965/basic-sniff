
import unittest
from scapy.layers.tls.handshake import TLSClientHello
from scapy.all import * 
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNSQR, DNS
from capture import PacketProcessor


class TestProcessPakcet(unittest.TestCase):

    def setUp(self):
        self.base_ip = IP(src="192.168.1.1", dst = "8.8.8.8")
        self.base_tcp = TCP(sport=52013)
        self.base_tcp_nonstd = TCP(sport=54321, dport=6969)
        self.base_udp = UDP(sport=52013, dport=53)
        self.base_udp_nonstd = TCP(sport=54321, dport=8001)


    def test_standard_http(self):
        pkt = self.base_ip / self.base_tcp / HTTPRequest(
            Host = "stollerfanclub@com",
            Method = "Get",
            Path = "/"
        )
        self.assertTrue(PacketProcessor.read_packet(pkt))
    
    def test_non_standard_http_port(self):
        http_payload = b"Get / HTTP/1.1\r\nHost: hidden.example\r\n\rn\n"
        pkt = self.base_ip / self.base_tcp_nonstd / Raw(load=http_payload)
        self.assertTrue(PacketProcessor.read_packet(pkt))
    
    def test_tls_standard_port(self):
        pkt = self.base_ip /self.base_tcp/TLSClientHello()
        self.assertTrue(PacketProcessor.read_packet(pkt))

    def test_tls_non_standard_port(self):
        tls_payload = bytes.fromhex("160301000101")

        pkt = self.base_ip/self.base_tcp_nonstd/Raw(load=tls_payload)
        self.assertTrue(PacketProcessor.read_packet(pkt))

    def test_dns_tcp_non_standard(self):
        dns_payload = bytes(DNS(qd=DNSQR(qname="pornhub.example")))
        pkt = self.base_ip / self.base_tcp_nonstd/ Raw(load=dns_payload)
        self.assertTrue(PacketProcessor.read_packet(pkt))

    def test_nah_id_win(self):
        target_ip = "1.1.1.1"
        domain = "www.example.com"
        dns_query = IP(dst=target_ip) / UDP(dport=555, sport=12345) / DNS(rd=1, qd=DNSQR(qname=domain))
        self.assertTrue(PacketProcessor.read_packet(dns_query))
    def test_invalid_protocol(self):
        pkt = self.base_ip / self.base_tcp/ Raw(load=b"GARBASE")
        self.assertFalse(PacketProcessor.read_packet(pkt))

    def test_dns_over_https_conflict(self):
        dns_payload = DNS(qd=DNSQR(qname="conflict.example"))
        dns_bytes = bytes(dns_payload)
        http_header = (
            b"POST /dns-query HTTP/1.1\r\n"
            b"Host: dns.example\r\n\r\n"
        )
        https_payload = http_header + dns_bytes
        tcp_layer = TCP(sport=12345, dport=443) 
        pkt = self.base_ip / tcp_layer / Raw(load=https_payload)
        
        self.assertEqual(PacketProcessor._identify_protocol(pkt), "http")       
        self.assertTrue(PacketProcessor.read_packet(pkt))


    def test_tls_custom_port_tcp(self):
        tcp_layer = self.base_tcp.copy()
        tcp_layer.dport = 8888 
        tls_hello = TLSClientHello()
        pkt = self.base_ip / tcp_layer / tls_hello
        
        self.assertEqual(
            PacketProcessor._identify_protocol(pkt), 
            "tls"
        )

    def test_tls_non_standard_tcp_port(self):
        tls_payload = bytes.fromhex(
            "16030100a0"
            "0100009c0303"
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            "0020c02bc02fc02cc030cca9cca8c009c013c00ac014009c009d002f0035" 
            "0100"
            "000d000b000403000102"
        )
        tcp_layer = self.base_tcp.copy()
        tcp_layer.dport = 6969  # 自定义非标准端口
        pkt = self.base_ip / tcp_layer / Raw(load=tls_payload)
        
        self.assertEqual(
            PacketProcessor._identify_protocol(pkt), 
            "tls"
        )

    def test_tls_version_range(self):
        test_cases = [
            (b"\x16\x03\x00", False),
            (b"\x16\x03\x01", True), 
            (b"\x16\x03\x03", True),
            (b"\x16\x03\x04", True),
            (b"\x16\x03\x05", False),
            (b"\x16\xfe\xfd", False)
        ]
        
        for payload, expected in test_cases:
            result = PacketProcessor._is_tls_packet(payload)
            self.assertEqual(result, expected, f"Payload: {payload.hex()}")

if __name__ == "__main__":
    unittest.main(verbosity=2)
