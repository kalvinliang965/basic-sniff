
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
