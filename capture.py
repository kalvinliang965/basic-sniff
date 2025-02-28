import argparse
from scapy.layers.tls.handshake import TLSClientHello
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
        if not pkt.haslayer(IP):
            return
        timestamp = float(pkt.time)
        meta = {
            "time": datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f"),
            "src": f"{pkt[IP].src}:{pkt.sport}",
            "dst": f"{pkt[IP].dst}:{pkt.dport}"
        }
        
        proto = PacketProcessor._identify_protocol(pkt)

        handlers = {
            "http": PacketProcessor._process_http,
            "tls": PacketProcessor._process_tls,
            "dns": PacketProcessor._process_dns
        }

        if proto in handlers:
            print(proto)
            print(pkt)
            result = handlers[proto](pkt)
            print(result)
            if result:
                print(format_row(meta['time'], proto.upper(), meta['src'], meta['dst'], result))
#        if http := PacketProcessor._process_http(pkt):
#            print(format_row(meta['time'], "HTTP", meta['src'], meta['dst'], http))
#        elif tls := PacketProcessor._process_tls(pkt):
#            print(format_row(meta['time'], "TLS", meta['src'], meta['dst'], tls))
#            # print(f"{meta['time']} TLS {meta['src']} -> {meta['dst']} {tls}")
#            sys.exit(0)
#        elif dns := PacketProcessor._process_dns(pkt):
#            print(format_row(meta['time'], "DNS", meta['src'], meta['dst'], dns))
#            # print(f"{meta['time']} DNS {meta['src']} -> {meta['dst']} {dns}")
#        else:
#            pass
#            # IGNORE!!
#            # pkt.summary()
    
    @staticmethod
    def _is_dns_packet(payload):
        # DNS have 12 bytes long header
        try:
            if len(payload) < 12:
                return False 
            flags = payload[2:4]
            qr = (flags[0] & 0x80) >> 7
            opcode = (flags[0] & 0x78) >> 3
            return qr == 0 and opcode == 0
        except:
            return False
    
    @staticmethod
    def _is_tls_packet(payload):
        return len(payload) >= 3 and (
                payload[0] == 0x16 and 
                payload[1:3] in (b"\x03\x01", b"\x03\x02", b"\x03\x03")
        )
    
    @staticmethod
    def _is_http_packet(payload):
        return payload.upper().startswith((b"GET", b"POST", b"HTTP/", b"HEAD"))

    # convert pkt to TLS/HTTP/DNS/not parse it
    @staticmethod
    def _identify_protocol(pkt):
        if pkt.haslayer(HTTPRequest):
            return "http"
        if pkt.haslayer(TLSClientHello):
            return "tls"
        if pkt.haslayer(DNSQR):
            return "dns"
        
        layer = pkt.getlayer(TCP) or pkt.getlayer(UDP)
        if layer and layer.payload:
            payload = bytes(layer.payload)
            if PacketProcessor._is_tls_packet(payload):
                return "tls"
            if PacketProcessor._is_http_packet(payload):
                return "http"
            if PacketProcessor._is_dns_packet(payload):
                return "dns"
        # cannot parse it
        return None 

    @staticmethod
    def _process_http(pkt):
        if pkt.haslayer(Raw):
            pkt = HTTP(pkt[Raw].payload)

        if pkt.haslayer(HTTPRequest):
           return None

        http=pkt[HTTPRequest]
        try:
            return f"{http.Host.decode()} {http.Method.decode()} {http.Path.decode()}"
        except Exception as e:
            logging.warning(f"Unknown HTTP Error: {e}")
            return None
    @staticmethod
    def _process_tls(pkt):
        
        if pkt.haslayer(Raw):
            pkt = TLS(pkt[Raw].payload)

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

    # assume pkt pass in is dns
    @staticmethod
    def _process_dns(pkt):
        print("inside process dns")
        # pkt.show()
        try:
            if pkt.haslayer(Raw):
                pkt = DNS(pkt[Raw].payload)
            if pkt.haslayer(DNS):
                dnsqr = pkt.getlayer(DNSQR)
                if dnsqr:
                    return dnsqr.qname.decode('utf-8').rstrip('.')
        
            layer = pkt.getlayer(UDP) or pkt.getlayer(TCP)
            if not layer or not layer.payload:
                return None

            payload = bytes(layer.payload)

            domain_parts = []
            # before 12 are the header
            ptr = 12
            while ptr < len(payload):
                length = payload[ptr]
                if length == 0:
                    break
                ptr += 1
                if ptr + length > len(payload):
                    return None
                label = payload[ptr:ptr+length].decode('utf-8', 'ignore')
                domain_parts.append(label)
                ptr += length
            return ".".join(domain_parts).rstrip('.')
        except UnicodeDecodeError:
            return dnsqr.qname.decode('latin-1').rstrip('.')
        except Exception as e:
            logging.warning(f"process DNS error: {e}")
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
    
    # scapy dont have them load in by default
    load_layer("http")
    load_layer("tls")
    conf.verb = 2



if __name__ == "__main__":
    
    init()


#    test()

    try:
        config = Config.build()
        print("Confgi build successfully:",config)
        print(f"{'Time':<{TIME_WIDTH}} {'Proto':<{PROTO_WIDTH}} {'Source':<{SRC_WIDTH}} {'Destination':<{DST_WIDTH}} {'Info':<{INFO_WIDTH}}")
        print("-"*(TIME_WIDTH+PROTO_WIDTH+SRC_WIDTH+DST_WIDTH+INFO_WIDTH+3))
        # 1. tracefile is basically a pcap file we pass in to sniff()
        #       e.g. sniff(offline="trace.pcap", prn=callback)
        # if the tracefile is not provided -> it will be `None` and sniff function will sniff `online`
        
        if config.tracefile:
            sniff(offline=config.tracefile, filter=config.expression, prn=PacketProcessor.process)
        else:
            sniff(iface=config.interface, filter=config.expression, prn=PacketProcessor.process)
    except Exception as e:
        logging.error(f"An error occured:{e}")
        sys.exit(1)


