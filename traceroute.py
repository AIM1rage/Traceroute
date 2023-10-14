import socket
from time import time
from scapy.all import *
from scapy.layers.inet import IP, ICMP, UDP, TCP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest

host = 'habrahabr.ru'
port = 80
max_hops = 10
repeats_count = 1

destination = socket.gethostbyname(host)

for ttl in range(1, max_hops + 1):
    total_time = 0
    src = None
    for _ in range(repeats_count):
        package = IP(dst=destination, ttl=ttl) / ICMP()

        start = time.time()
        reply = sr(package, timeout=2, verbose=False)
        end = reply[0][0].answer.time

        total_time += end - start

        answer = reply[0][0].answer
        src = answer.src
        package_type = answer[ICMP].type
        # print((end - start) * 1000)
        print(answer[ICMP].type)
        # answer[ICMP].show()
        # answer.show2()
        # print(answer.src)
        # print(answer.haslayer('ICMP'))

    print(f'IP: {src}')
    print(f'PING: {round(total_time * 1000 / repeats_count)} ms')
    print()
    if package_type == 0:
        break
