import argparse
from scapy.all import sniff, get_if_list, load_layer, DNS, DNSQR, DNSRR, IP
from scapy.layers.tls.extensions import TLS_Ext_ServerName
from scapy.layers.tls.all import TLS, TLSClientHello
from scapy.layers.http import HTTPRequest
import sys
from datetime import datetime
import logging

class Config():
    
    def __init__(self, interface, tracefile, expression):
        # validate the interface
        if not self._validate_interface(interface):
            raise Exception(f"Invalid interface:{interface}")

        self.interface = interface 
        self.tracefile = tracefile
        self.expression = None 
    
    @classmethod
    def _validate_interface(cls, interface):
        available_ifaces = get_if_list()
        # check valid interface
        if interface not in available_ifaces:
           return False
        return True
    
    @classmethod 
    def build(cls):
        parser = argparse.ArgumentParser(description="command-line parser")
        parser.add_argument("-i", type=str, help="interface", default="eth0")
        parser.add_argument("-r", type=str, help="tracefile in tcpdump format", default=None)
        parser.add_argument("expression", type=str,help="expression", nargs='?',default=None)

        args = parser.parse_args()
        
        return cls(args.i, args.r, args.expression)
    
    def __str__(self):
        return f"interface: {self.interface}, tracefile: {self.tracefile}"



def process_packet(pkt):
    
    if IP in pkt:
        ip_src=pkt[IP].src
        ip_dst=pkt[IP].dst

    current_date = datetime.now().strftime("%Y-%m-%d")
    current_time = datetime.now().strftime("%H:%M:%S:%f")
    if pkt.haslayer(HTTPRequest):
        http_request = pkt[HTTPRequest]
        print(f"{current_date} {current_time} HTTP {ip_src} -> {ip_dst} {http_request.Host.decode()} {http_request.Method.decode()} {http_request.Path.decode()}")
    elif pkt.haslayer(TLS) and pkt.haslayer(TLSClientHello):
        tls_client_hello = pkt[TLSClientHello]
        if hasattr(tls_client_hello, 'ext'):
            for ext in tls_client_hello.ext:
                # 0x00 here represent sni
                if ext.type == 0x00:
                    servernames = ext.servernames
                    for sn in servernames:
                        # 0x00 here represent host
                        if sn.nametype == 0x00:
                            servername = sn.servername
                            try:
                                sni = servername.decode('utf-8')
                                print(f"{current_date} {current_time} TLS {ip_src} -> {ip_dst} {sni}")
                            except UnicodeDecodeError:
                                print("Failed to decode SNI extension data.")
                            break
                    else:
                        print("Does not contain host data")
                    break
            else:
                print(f"{current_date} {current_time} TLS {pkt.src} -> {pkt.dst} NO_SERVER_NAME")

        else:
            print("No extensions in TLS Client Hello")

    # qtype==1 here refer to A(address) which mean IPv4
    elif pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNSQR].qtype == 1: 
        qname = pkt.getlayer(DNSQR).qname.decode()
        print(f"{current_date} {current_time} DNS {ip_src} -> {ip_dst} {qname} ")
    else:
        # print(pkt.summary())
        print("Not intersting")

    

def init():
    # scapy dont have them load in by default
    load_layer("http")
    load_layer("tls")

if __name__ == "__main__":
    
    init()

    try:
        config = Config.build()
        print("Confgi build successfully:",config)
        # 1. tracefile is basically a pcap file we pass in to sniff()
        #       e.g. sniff(offline="trace.pcap", prn=callback)
        sniff(iface=config.interface, offline=config.tracefile, filter=config.expression, prn=process_packet, count = 100)
    except Exception as e:
        logging.error(f"An error occured:{e}")
        sys.exit(1)


