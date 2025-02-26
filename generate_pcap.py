from scapy.all import sniff, wrpcap


packets = []

def packet_handler(packet):
    global packets
    packets.append(packet)

sniff(prn=packet_handler, count=2) 

wrpcap("two-dns.pcap", packets)

print("Packets saved to two-dns.pcap")
