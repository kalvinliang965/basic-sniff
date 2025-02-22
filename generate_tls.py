import requests
from scapy.all import *
from scapy.layers.tls.all import TLS, TLSClientHello

#target = "www.google.com"

#ip = socket.gethostbyname(target) # get ip

#while True:
#    syn = IP(dst = ip) / TCP(dport=443, flags="S")
#    # send packet and wait for response
#    syn_ack = sr1(syn, timeout=1)
#    
#    # if they responded and is a valid syn_ack packet (TCP)
#    if syn_ack and syn_ack.haslayer(TCP):
#        ack = IP(dst = ip) / TCP(dport=443, flags="A", seq=syn_ack.ack, ack=syn_ack.seq + 1)
#        send(ack)
#
#        tls_client_hello = IP(dst=ip) / TCP(dport=443, flags="PA", seq=syn_ack.ack, ack=syn_ack.seq+1)/TLSClientHello()
#        send(tls_client_hello)

url = "https://google.com"
while True: 
    response = requests.get(url)
    print(response.status_code)
