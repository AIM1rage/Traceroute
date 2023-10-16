import argparse
import socket

from scapy.all import *
from scapy.layers.inet import IP, ICMP
from ipwhois import IPWhois, exceptions


class Traceroute:
    MIN_SIZE = 28
    MAX_SIZE = 65535

    def __init__(self, host,
                 seq=42, timeout=1, delay=0, max_ttl=30, count=3, size=40):
        self.host = socket.gethostbyname(host)
        self.name = Traceroute.get_host_name(self.host)

        self.seq = seq

        self.max_ttl = max_ttl
        self.count = count

        self.timeout = timeout
        self.delay = delay

        self.size = size
        self.data = ('0' * (self.size - Traceroute.MIN_SIZE)).encode()
        if not (Traceroute.MIN_SIZE <= size <= Traceroute.MAX_SIZE):
            raise ValueError('Packet size must be at least 28 bytes')

    def print_trace_table(self):
        print(
            f'Tracing the route to {self.host} ({self.name}) with a maximum of {self.max_ttl} hops:')
        print()
        for row in self.get_trace_data():
            Traceroute.print_row(*row)
        print()
        print('Tracing completed.')

    def get_trace_data(self):
        for ttl in range(1, self.max_ttl + 1):
            src = None
            pings = []
            icmp_type = None
            for _ in range(self.count):
                start = time.time()
                reply = self.get_ipv4_reply(self.get_ipv4_packet(ttl))
                if reply is None:
                    pings.append(None)
                    continue
                end = reply.time
                src = reply.src
                icmp_type = reply[ICMP].type
                pings.append(round((end - start) * 1000))
            yield ttl, pings, src
            if icmp_type == 0:
                break

    def get_ipv4_packet(self, ttl):
        return IP(
            dst=self.host, ttl=ttl, len=self.size) / ICMP(
            type=8, seq=self.seq) / self.data

    def get_ipv4_reply(self, ipv4_packet):
        return sr1(ipv4_packet,
                   timeout=self.timeout,
                   inter=self.delay,
                   verbose=0,
                   retry=-3)

    @staticmethod
    def print_row(ttl, pings, src):
        parts = [str(ttl).rjust(3)]
        parts.extend(
            (f'{str(ping).rjust(4)} ms' if ping is not None else '   *   ') for
            ping in
            pings)
        parts.append(
            f'{src} ({Traceroute.get_host_name(src)})' if src is not None else 'Request timeout exceeded')
        print('  '.join(parts))

    @staticmethod
    def get_host_name(host):
        try:
            return IPWhois(
                host).lookup_whois()['nets'][0]['address'].replace('\n', ', ')
        except exceptions.IPDefinedError:
            return host


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='traceroute',
                                     description='Traceroute traces network packet paths and identifies intermediate routers and their timings.')
    parser.add_argument('host', type=str,
                        help='host name or ip-address')
    parser.add_argument('-seq', default=42, type=int,
                        help='additional sequence number')
    parser.add_argument('-ttl', default=30, type=int,
                        help='maximum time-to-live value')
    parser.add_argument('-c', default=3, type=int,
                        help='requests count')
    parser.add_argument('-d', default=0, type=float,
                        help='delay between requests in seconds')
    parser.add_argument('-t', default=1, type=int,
                        help='request timeout in seconds')
    parser.add_argument('-s', default=40, type=int,
                        help='packet size')
    args = parser.parse_args()
    traceroute = Traceroute(host=args.host,
                            seq=args.seq,
                            timeout=args.t,
                            delay=args.d,
                            max_ttl=args.ttl,
                            count=args.c,
                            size=args.s)
    traceroute.print_trace_table()
