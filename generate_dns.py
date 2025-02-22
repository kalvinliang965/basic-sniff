import dns.resolver

while True:
    result = dns.resolver.resolve("google.com","A") #A specifies it is ipv4
    for ip in result:
        print(ip.to_text())

