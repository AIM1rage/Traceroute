import argparse
import socket

from scapy.all import *
from scapy.layers.inet import IP, ICMP
from ipwhois import IPWhois, exceptions


class Traceroute:
    MIN_SIZE = 28
    MAX_SIZE = 65535

    def __init__(self, host,
                 seq=42, timeout=0.5, delay=0, max_ttl=30, count=3, size=40):
        self.ip_address = socket.gethostbyname(host)
        self.host_name = Traceroute.get_host_name(self.ip_address)
        self.host_location = Traceroute.get_host_location(self.ip_address)

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
        if self.host_name is not None:
            print(
                f'Tracing the route to {self.ip_address} ({self.host_name}) with a maximum of {self.max_ttl} hops:')
        else:
            print(
                f'Tracing the route to {self.ip_address} with a maximum of {self.max_ttl} hops:')
        if self.host_location is not None:
            print(f'Location:')
            print(self.host_location)
        print()
        for row in self.get_trace_data():
            Traceroute.print_row(*row)
        print()
        print('Tracing completed.')

    def get_trace_data(self):
        for ttl in range(1, self.max_ttl + 1):
            pings, icmp_type = self.get_fixed_ttl_data(ttl)
            yield ttl, pings
            if icmp_type == 0:
                break

    def get_fixed_ttl_data(self, ttl):
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
            pings.append((round((end - start) * 1000), src))
        return pings, icmp_type

    def get_ipv4_packet(self, ttl):
        return IP(
            dst=self.ip_address, ttl=ttl, len=self.size) / ICMP(
            type=8, seq=self.seq) / self.data

    def get_ipv4_reply(self, ipv4_packet):
        return sr1(ipv4_packet,
                   timeout=self.timeout,
                   inter=self.delay,
                   verbose=0,
                   retry=-3)

    @staticmethod
    def print_row(ttl, pings):
        parts = [str(ttl).rjust(3)]
        parts.extend((f'{ping[0]} ms ({ping[1]})'
                      if ping is not None
                      else '*') for ping in pings)
        print('  '.join(parts))

    @staticmethod
    def get_host_name(ip_address):
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            return None

    @staticmethod
    def get_host_location(ip_address):
        try:
            return IPWhois(ip_address).lookup_whois()['nets'][0]['address']
        except exceptions.IPDefinedError:
            return None


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
    parser.add_argument('-t', default=0.5, type=float,
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
