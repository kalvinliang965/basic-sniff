# basic-sniff


## overview of my code

### Config

- This class contain the parsed command-line user enter with validation.
    - Raise Error if user enter invalid value (e.g. invalid interface format)

## ProcessPacket

- This class contain helper method and will specifies the output format

- For the helper function, it will return None when the packet dont match the validation. From there, the static function of this class will continue to next case until the deafult case, which is to ignore this packet.

- The helper function will raise errors if it cannot decode some value (e.g. hostname)

## sample output

### Testing basic

run 'sudo python3 capture.py' on one temrinal and run `dig google.come` on another terminal. on the first temrinal it should display the following

```
Confgi build successfully: interface: eth0, tracefile: None, expression: None
Time                       Proto Source                    Destination               Info                                              
--------------------------------------------------------------------------------------------------------------------------------------
2025-02-26 18:47:56.120298 DNS   192.168.18.128:41202      192.168.18.2:53           google.com                                        
2025-02-26 18:47:56.136412 DNS   192.168.18.2:53           192.168.18.128:41202      google.com                                        
^C  
```

### Testing tracefile

- run `sudo python3 capture.py -r two-dns.pcap`                                      

```
Confgi build successfully: interface: eth0, tracefile: two-dns.pcap, expression: None
Time                       Proto Source                    Destination               Info                                              
--------------------------------------------------------------------------------------------------------------------------------------
2025-02-26 17:49:56.172200 DNS   192.168.18.128:45228      192.168.18.2:53           google.com                                        
2025-02-26 17:49:56.180809 DNS   192.168.18.2:53           192.168.18.128:45228      google.com      

// This is expected as the `two-dns.pcap` contain packets from running the command `dig google.com`
```

- run `sudo python3 capture.py -i eth0 -r two-dns.pcap "udp src port 53"`   

```
Confgi build successfully: interface: eth0, tracefile: two-dns.pcap, expression: udp src port 53
Time                       Proto Source                    Destination               Info                                              
--------------------------------------------------------------------------------------------------------------------------------------
reading from file two-dns.pcap, link-type EN10MB (Ethernet), snapshot length 65535
2025-02-26 17:49:56.180809 DNS   192.168.18.2:53           192.168.18.128:45228      google.com   

// This is expected as only packet with sport of 52 is print
```

- run `sudo python3 capture.py -r two-dns.pcap "udp src port 45228"

```
Confgi build successfully: interface: eth0, tracefile: two-dns.pcap, expression: udp src port 45228
Time                       Proto Source                    Destination               Info                                              
--------------------------------------------------------------------------------------------------------------------------------------
reading from file two-dns.pcap, link-type EN10MB (Ethernet), snapshot length 65535
2025-02-26 17:49:56.172200 DNS   192.168.18.128:45228      192.168.18.2:53           google.com                                        

// This is expected as only packet with sport of 45228 is capture
```

- run 'sudo python3 capture.py -r two-dns.pcap "udp src port 41202"

```
Confgi build successfully: interface: eth0, tracefile: two-dns.pcap, expression: udp src port 41202
Time                       Proto Source                    Destination               Info                                              
--------------------------------------------------------------------------------------------------------------------------------------
reading from file two-dns.pcap, link-type EN10MB (Ethernet), snapshot length 65535

// This is expected as neither packet have sport of 41202
```

## installing dependencies and running my program

- run `python3 -m venv venv` to install the virtual environment (Optional)
    - run `source venv/bin/activate` to activate the virtual environment

- run `pip install scapy'

- run the program with `sudo capture.py -i <interface> -r <tracefile> <expression>`


