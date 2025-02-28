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
2025-02-28 10:05:58.640461 DNS   192.168.18.128:43400      192.168.18.2:53           google.com                                        
2025-02-28 10:05:58.643493 DNS   192.168.18.2:53           192.168.18.128:43400      google.com   
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


## Testing nonstandard port and localhost

- open three terminal.

- The first terminal will host a localhost server using python. run `python3 -m http.server 8080 &` on the first terminal

- The second terminal will be use in sending requests.

- The third terminal will be use to run capture.py. run `sudo python3 capture.py -i lo "tcp port 6969"`

- run the following command on the second terminal `after` running `capture.py`
    - run `curl http://localhost:6969 &`
    - run `curl -X POST http://localhost:6969 -d 'testdata'`
    - run `echo -e "GET / HTTP/1.1\r\n\Host: localhost\r\n\r\n" | nc localhost 6969`

### In python server terminal:

```
127.0.0.1 - - [28/Feb/2025 10:21:55] "GET / HTTP/1.1" 200 -
127.0.0.1 - - [28/Feb/2025 10:22:26] code 501, message Unsupported method ('POST')
127.0.0.1 - - [28/Feb/2025 10:22:26] "POST / HTTP/1.1" 501 -
127.0.0.1 - - [28/Feb/2025 10:23:14] code 404, message File not found
127.0.0.1 - - [28/Feb/2025 10:23:14] "GET /HTTP/1.1" 404 -
```

### In capture.py terminal:

```
Confgi build successfully: interface: lo, tracefile: None, expression: tcp port 6969
Time                       Proto Source                    Destination               Info                                              
--------------------------------------------------------------------------------------------------------------------------------------
2025-02-28 10:21:55.451011 HTTP  127.0.0.1:35028           127.0.0.1:6969            localhost:6969 GET /                              
2025-02-28 10:21:55.451012 HTTP  127.0.0.1:35028           127.0.0.1:6969            localhost:6969 GET /                              
2025-02-28 10:22:26.100554 HTTP  127.0.0.1:54864           127.0.0.1:6969            localhost:6969 POST /                             
2025-02-28 10:22:26.100555 HTTP  127.0.0.1:54864           127.0.0.1:6969            localhost:6969 POST /                             
2025-02-28 10:23:14.017620 HTTP  127.0.0.1:38214           127.0.0.1:6969            localhost GET /                                   
2025-02-28 10:23:14.017621 HTTP  127.0.0.1:38214           127.0.0.1:6969            localhost GET /                                   
^C   
 ```

- run `pip install pytest`

- run `python3 -m pytest test_` to run one of the test file

## Testing TLS on localhost

- first we have to create the certificate. I did it using apache2
    - i followed this video `https://youtu.be/l9-BkbI-7vA?si=LLcKoG2fK7ZebBMx## Running my unittest`
- run `sudo capture.py -i lo`

- curl -k https://127.0.0.1/:443

```
Confgi build successfully: interface: lo, tracefile: None, expression: None
Time                       Proto Source                    Destination               Info                                              
--------------------------------------------------------------------------------------------------------------------------------------
2025-02-28 12:41:18.810912 TLS   127.0.0.1:41472           127.0.0.1:443             UNKNOWN                                           
2025-02-28 12:41:18.810913 TLS   127.0.0.1:41472           127.0.0.1:443             UNKNOWN                                           
2025-02-28 12:41:18.812458 TLS   127.0.0.1:443             127.0.0.1:41472           UNKNOWN                                           
2025-02-28 12:41:18.812461 TLS   127.0.0.1:443             127.0.0.1:41472           UNKNOWN 
```

## installing dependencies and running my program

- run `python3 -m venv venv` to install the virtual environment (Optional)
    - run `source venv/bin/activate` to activate the virtual environment

- run `pip install scapy-http`

- run `pip install scapy'

- run the program with `sudo capture.py -i <interface> -r <tracefile> <expression>`


