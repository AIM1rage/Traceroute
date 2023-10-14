import argparse
import sys
from scapy.all import *
from scapy.layers.inet import IP, ICMP


class Traceroute:
    MIN_SIZE = 28
    MAX_SIZE = 65535

    def __init__(self, host, timeout=1, delay=0, max_ttl=30, count=3, size=40):
        self.host = socket.gethostbyname(host)

        self.max_hops = max_ttl
        self.count = count

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
            for _ in range(self.count):
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
    parser = argparse.ArgumentParser(prog='traceroute',
                                     description='Traceroute traces network packet paths and identifies intermediate routers and their timings.')
    parser.add_argument('host', nargs=1, type=str,
                        help='host name or ip-address')
    parser.add_argument('-ttl', nargs=1, default=30, type=int,
                        help='maximum time-to-live value')
    parser.add_argument('-c', nargs=1, default=3, type=int,
                        help='requests count')
    parser.add_argument('-d', nargs=1, default=0, type=int,
                        help='delay between requests in seconds')
    parser.add_argument('-t', nargs=1, default=1, type=int,
                        help='request timeout in seconds')
    parser.add_argument('-s', nargs=1, default=40, type=int,
                        help='packet size')
    args = parser.parse_args()
    traceroute = Traceroute(host=args.host[0],
                            timeout=args.t,
                            delay=args.d,
                            count=args.c,
                            size=args.s)
    traceroute.trace()
