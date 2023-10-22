import argparse

from ipwhois import IPWhois, exceptions
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import *


class Traceroute:
    IPV4_MIN_SIZE = 28
    IPV4_MAX_SIZE = 65535

    IPV6_MIN_SIZE = 8
    IPV6_MAX_SIZE = 65535

    def __init__(self, host, src=None,
                 seq=42, timeout=0.5, delay=0, max_ttl=30, count=3, size=40):
        self.host = host
        self.src = src
        self.ip_address = socket.getaddrinfo(
            host, None, proto=socket.IPPROTO_TCP)[0][-1][0]
        if '.' in self.ip_address:
            self.ip_version = 4
            self.size, self.data = Traceroute.get_data(
                size, Traceroute.IPV4_MIN_SIZE, Traceroute.IPV4_MAX_SIZE)
        else:
            self.ip_version = 6
            self.size, self.data = Traceroute.get_data(
                size, Traceroute.IPV6_MIN_SIZE, Traceroute.IPV6_MAX_SIZE)

        self.host_location = Traceroute.get_host_location(self.ip_address)

        self.seq = seq

        self.max_ttl = max_ttl
        self.count = count

        self.timeout = timeout
        self.delay = delay

    def print_trace_table(self):
        print(
            f'Tracing the route to {self.ip_address} ({self.host}) with a maximum of {self.max_ttl} hops:')
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
            pings, icmp_reply_type = self.get_fixed_ttl_data(ttl)
            yield ttl, pings
            if icmp_reply_type in (0, 129):
                break

    def get_fixed_ttl_data(self, ttl):
        pings = []
        icmp_reply_type = None
        for _ in range(self.count):
            start = time.time()
            packet = self.get_packet(ttl)
            reply = self.get_reply(self.get_packet(ttl))
            if reply is None:
                pings.append(None)
                continue
            end = reply.time
            src = reply.src
            icmp_reply_type = self.get_reply_type(reply)
            pings.append((round((end - start) * 1000), src))
        return pings, icmp_reply_type

    def get_packet(self, ttl):
        if self.ip_version == 4:
            return IP(dst=self.ip_address, src=self.src,
                      ttl=ttl, len=self.size) / ICMP(
                type=8, seq=self.seq) / self.data
        return IPv6(dst=self.ip_address, src=self.src,
                    hlim=ttl, plen=self.size) / ICMPv6EchoRequest(
            type=128, seq=self.seq, data=self.data)

    def get_reply(self, ip_packet):
        return sr1(ip_packet,
                   timeout=self.timeout,
                   inter=self.delay,
                   verbose=0,
                   retry=-3)

    def get_reply_type(self, reply):
        if self.ip_version == 4:
            return reply[ICMP].type
        try:
            return reply[ICMPv6TimeExceeded].type
        except IndexError:
            return reply[ICMPv6EchoReply].type

    @staticmethod
    def print_row(ttl, pings):
        parts = [str(ttl).rjust(3)]
        parts.extend((f'{ping[0]} ms ({ping[1]})'
                      if ping is not None
                      else '*') for ping in pings)
        print('  '.join(parts))

    @staticmethod
    def get_host_location(ip_address):
        try:
            return IPWhois(ip_address).lookup_whois()['nets'][0]['address']
        except (exceptions.IPDefinedError, exceptions.ASNRegistryError):
            return None

    @staticmethod
    def get_data(size, min_size, max_size):
        if not (min_size <= size <= max_size):
            raise ValueError(
                f'Packet size must be between {min_size} and {max_size}')
        data = ('1' * (size - min_size)).encode()
        return size, data


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='traceroute',
                                     description='Traceroute traces network packet paths and identifies intermediate routers and their timings.')
    parser.add_argument('host', type=str,
                        help='host name or ip-address')
    parser.add_argument('-src', default=None, type=str,
                        help='source address')
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
                            src=args.src,
                            seq=args.seq,
                            timeout=args.t,
                            delay=args.d,
                            max_ttl=args.ttl,
                            count=args.c,
                            size=args.s)
    traceroute.print_trace_table()
