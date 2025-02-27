import argparse
from scapy.all import * 
from scapy.layers.tls.extensions import TLS_Ext_ServerName
from scapy.layers.http import HTTP, HTTPRequest
from scapy.layers.tls.all import TLS
from scapy.packet import bind_layers
from datetime import datetime
import logging
import sys

TIME_WIDTH = 26
PROTO_WIDTH = 5
SRC_WIDTH = 25
DST_WIDTH = 25
INFO_WIDTH = 50

SNI_HOST_NAME = 0x00
logging.basicConfig(level=logging.WARNING)


def format_row(timestamp, proto, src, dst, info):
    return (f"{timestamp:<{TIME_WIDTH}} "
            f"{proto:<{PROTO_WIDTH}} "
            f"{src:<{SRC_WIDTH}} "
            f"{dst:<{DST_WIDTH}} "
            f"{info:<{INFO_WIDTH}}")

class PacketProcessor:
    @staticmethod
    def process(pkt):
        # print("process")
        if not pkt.haslayer(IP):
            return
        timestamp = float(pkt.time)
        meta = {
            "time": datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f"),
            "src": f"{pkt[IP].src}:{pkt.sport}",
            "dst": f"{pkt[IP].dst}:{pkt.dport}"
        }
        
        pkt = PacketProcessor._process_packet(pkt)
        if http := PacketProcessor._process_http(pkt):
            print(format_row(meta['time'], "HTTP", meta['src'], meta['dst'], http))
        elif tls := PacketProcessor._process_tls(pkt):
            print(format_row(meta['time'], "TLS", meta['src'], meta['dst'], tls))
            # print(f"{meta['time']} TLS {meta['src']} -> {meta['dst']} {tls}")
            sys.exit(0)
        elif dns := PacketProcessor._process_dns(pkt):
            print(format_row(meta['time'], "DNS", meta['src'], meta['dst'], dns))
            # print(f"{meta['time']} DNS {meta['src']} -> {meta['dst']} {dns}")
        else:
            pass
            # IGNORE!!
            # pkt.summary()
    
    def _is_dns_packet(raw_bytes):
        # DNS have 12 bytes long header
        if len(raw_bytes) < 12:
            return False 

        transaction_id = raw_bytes[0:2]
        flags = raw_bytes[2:4]
        qdcount = int.from_bytes(raw_bytes[4:6], "big")
        if flags[0] & 0xb10000000 == 0 or flags[0] & 0b00001111 == 0:
            return True
        return False

    # convert pkt to TLS/HTTP/DNS/not parse it
    def _process_packet(pkt):
        if pkt.haslayer(TCP) or pkt.haslayer(UDP):
            payload = bytes(pkt[TCP].payload) if pkt.haslayer(TCP) else bytes(pkt[UDP].payload)
            if len(payload) > 2:
                if payload[0] == 0x16 and payload[1] == 0x03:
                    return TLS(payload)
                elif PacketProcess._is_dns_packet(pkt):
                    return DNS(payload)
                elif payload.startswith(b"GET") or payload.startswith(b"POST"):
                    return HTTP(payload)
        # cannot parse it
        return pkt

    def _process_http(pkt):
        # print("http")
        load_layer("http")
        if not pkt.haslayer(HTTPRequest):
            return None

        http=pkt[HTTPRequest]
        try:
            return f"{http.Host.decode()} {http.Method.decode()} {http.Path.decode()}"
        except Exception as e:
            logging.warning(f"Unknown HTTP Error: {e}")
            return None

    def _process_tls(pkt):
        # print("tls")
        client_hello=pkt.getlayer(TLSClientHello)
        if not client_hello:
            return None
        if sni := client_hello.getlayer(TLS_Ext_ServerName):
            for name in sni.servernames:
                if name.nametype == SNI_HOST_NAME:
                    try:
                        return name.servername.decode('utf-8', errors='ignore')
                    except Exception as e:
                        logging.warning(f"Unknown TLS Error: {e}")
                        return None
        return None

    def _process_dns(pkt):
        # print("dns")
        dnsqr = pkt.getlayer(DNSQR)
        if dnsqr and dnsqr.qtype == 1:
            try:
                return dnsqr.qname.decode('utf-8').rstrip('.')
            except UnicodeDecodeError:
                return dnsqr.qname.decode('latin-1').rstrip('.')
            except Exception as e:
                logging.warning(f"Unknown DNS Error: {e}")
                return None
        return None

class Config():
    
    def __init__(self, interface, tracefile, expression):
        # validate the interface
        if not Config._validate_interface(interface):
            raise Exception(f"Config: invalid interface:{interface}")

        self.interface = interface 
        self.tracefile = tracefile
        self.expression = expression 
    
    @staticmethod
    def _validate_interface(interface):
        available_ifaces = get_if_list()
        # check valid interface
        if interface not in available_ifaces:
           return False
        return True
    
    @staticmethod 
    def build():
        parser = argparse.ArgumentParser(description="command-line parser")
        parser.add_argument("-i", type=str, help="interface", default="eth0")
        parser.add_argument("-r", type=str, help="tracefile", default=None)
        parser.add_argument("expression", type=str,nargs='?',default=None, help="expressio; BFS Filter (e.g. 'host 192.168.1.1')")

        args = parser.parse_args()
        
        return Config(args.i, args.r, args.expression)
    
    def __str__(self):
        return f"interface: {self.interface}, tracefile: {self.tracefile}, expression: {self.expression}"


#def process_packet(pkt):
#    
#    if IP in pkt:
#        ip_src=pkt[IP].src
#        ip_dst=pkt[IP].dst
#
#    timestamp = datetime.fromtimestamp(pkt.time)
#    if pkt.haslayer(HTTPRequest):
#        http_request = pkt[HTTPRequest]
#        print(f"{current_date} {current_time} HTTP {ip_src} -> {ip_dst} {http_request.Host.decode()} {http_request.Method.decode()} {http_request.Path.decode()}")
#    elif pkt.haslayer(TLS) and pkt.haslayer(TLSClientHello):
#        tls_client_hello = pkt[TLSClientHello]
#        if hasattr(tls_client_hello, 'ext'):
#            for ext in tls_client_hello.ext:
#                # 0x00 here represent sni
#                if ext.type == 0x00:
#                    servernames = ext.servernames
#                    for sn in servernames:
#                        # 0x00 here represent host
#                        if sn.nametype == 0x00:
#                            servername = sn.servername
#                            try:
#                                sni = servername.decode('utf-8')
#                                print(f"{current_date} {current_time} TLS {ip_src} -> {ip_dst} {sni}")
#                            except UnicodeDecodeError:
#                                print("Failed to decode SNI extension data.")
#                            break
#                    else:
#                        print("Does not contain host data")
#                    break
#            else:
#                print(f"{current_date} {current_time} TLS {pkt.src} -> {pkt.dst} NO_SERVER_NAME")
#
#        else:
#            print("No extensions in TLS Client Hello")
#
#    # qtype==1 here refer to A(address) which mean IPv4
#    elif pkt.haslayer(DNS) and pkt.haslayer(DNSQR) and pkt[DNSQR].qtype == 1: 
#        qname = pkt.getlayer(DNSQR).qname.decode()
#        print(f"{current_date} {current_time} DNS {ip_src} -> {ip_dst} {qname} ")
#    else:
#        # print(pkt.summary())
#        print("Not intersting")

    

def init():
    #if TCP in HTTP.overloaded_fields:
    #    del HTTP.overloaded_fields[TCP]
    #if TCP in TLS.overloaded_fields:
    #    del TLS.overloaded_fields[TCP]
    
    bind_layers(TCP, HTTP, dport=[8081])
    bind_layers(TCP, HTTP, sport=[8081])
    bind_layers(TCP, TLS, dport=[8081])
    bind_layers(TCP, TLS, sport=[8081])
    # scapy dont have them load in by default
    load_layer("http")
    load_layer("tls")
    conf.verb = 2


def test_dns():
    dns_req = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="google.com"))
    if not 

def test():

    if not test_dns():
        print("DNS Failed")
    else:
        print("DNS ok")


if __name__ == "__main__":
    
    init()


    test()

#    try:
#        config = Config.build()
#        print("Confgi build successfully:",config)
#        print(f"{'Time':<{TIME_WIDTH}} {'Proto':<{PROTO_WIDTH}} {'Source':<{SRC_WIDTH}} {'Destination':<{DST_WIDTH}} {'Info':<{INFO_WIDTH}}")
#        print("-"*(TIME_WIDTH+PROTO_WIDTH+SRC_WIDTH+DST_WIDTH+INFO_WIDTH+3))
#        # 1. tracefile is basically a pcap file we pass in to sniff()
#        #       e.g. sniff(offline="trace.pcap", prn=callback)
#        # if the tracefile is not provided -> it will be `None` and sniff function will sniff `online`
#        
#        if config.tracefile:
#            sniff(offline=config.tracefile, filter=config.expression, prn=PacketProcessor.process)
#        else:
#            sniff(iface=config.interface, filter=config.expression, prn=PacketProcessor.process)
#    except Exception as e:
#        logging.error(f"An error occured:{e}")
#        sys.exit(1)


