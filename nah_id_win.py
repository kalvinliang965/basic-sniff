from scapy.all import send, IP, UDP, DNS, DNSQR

target_ip = "1.1.1.1"

domain = "www.example.com"

dns_query = IP(dst=target_ip) / UDP(dport=555, sport=12345) / bytes(DNS(rd=1, qd=DNSQR(qname=domain)))

send(dns_query, verbose=True)
