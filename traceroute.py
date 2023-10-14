import argparse
from scapy.all import *
from scapy.layers.inet import IP, ICMP


class Traceroute:
    MIN_SIZE = 28

    def __init__(self, host, timeout=1, delay=0, max_ttl=30, count=3, size=40):
        self.host = socket.gethostbyname(host)

        self.max_hops = max_ttl
        self.repeats = count

        self.timeout = timeout
        self.delay = delay

        self.size = size
        if size < Traceroute.MIN_SIZE:
            raise ValueError('Packet size must be at least 28 bytes')

    def trace(self):
        for ttl in range(1, self.max_hops + 1):
            src = None
            pings = []
            icmp_type = None
            for _ in range(self.repeats):
                start = time.time()
                reply = self.get_ipv4_reply(self.get_ipv4_packet(ttl))
                if not reply[0]:
                    pings.append(None)
                    continue
                answer = reply[0][0].answer
                end = answer.time
                src = answer.src
                icmp_type = answer[ICMP].type
                pings.append(round((end - start) * 1000))
                time.sleep(self.delay)
            Traceroute.print_row(ttl, pings, src)
            if icmp_type == 0:
                break

    def get_ipv4_packet(self, ttl):
        return IP(dst=self.host, ttl=ttl, len=self.size) / ICMP()

    def get_ipv4_reply(self, ipv4_packet):
        return sr(ipv4_packet, timeout=self.timeout, verbose=False)

    @staticmethod
    def print_row(ttl, pings, src):
        parts = [str(ttl).rjust(3)]
        parts.extend(
            (f'{str(ping).rjust(4)} ms' if ping is not None else '   *   ') for
            ping in
            pings)
        parts.append(
            str(src) if src is not None else 'Request timeout exceeded')
        print('  '.join(parts))


if __name__ == '__main__':
    traceroute = Traceroute('habrahabr.ru', 2, 0, size=28)
    traceroute.trace()
