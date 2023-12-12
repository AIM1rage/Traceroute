import time
import socket
from ipwhois import exceptions
from ipwhois.net import Net
from ipwhois.asn import IPASN
from scapy.sendrecv import sr1
from scapy.layers.inet import IP, ICMP
from scapy.layers.inet6 import (ICMPv6EchoRequest,
                                ICMPv6EchoReply,
                                ICMPv6TimeExceeded,
                                IPv6,
                                )


class Tracer:
    IPV4_MIN_SIZE = 28
    IPV4_MAX_SIZE = 65535

    IPV6_MIN_SIZE = 8
    IPV6_MAX_SIZE = 65535

    def __init__(self, host, timeout=0.5, max_ttl=30, verbose=False):
        self.host = host
        self.ip_address = socket.getaddrinfo(
            host, None, proto=socket.IPPROTO_IPV4)[0][-1][0]
        if '.' in self.ip_address:
            self.ip_version = 4
            self.size, self.data = Tracer.generate_packet_data(
                40,
                Tracer.IPV4_MIN_SIZE,
            )
        else:
            self.ip_version = 6
            self.size, self.data = Tracer.generate_packet_data(
                40,
                Tracer.IPV6_MIN_SIZE,
            )

        self.timeout = timeout
        self.max_ttl = max_ttl
        self.verbose = verbose

    def print_trace_table(self):
        if self.verbose:
            title = f'Tracing the route to {self.ip_address} ({self.host}) with a maximum of {self.max_ttl} hops:'
            print(title)
        if self.verbose:
            print(f'NUM  IP                                       TIME,ms  AS')
        else:
            print(f'NUM  IP                                       TIME,ms')
        for ttl, ping, src in self.get_trace_data():
            self.print_row(ttl, ping, src)

    def get_trace_data(self):
        for ttl in range(1, self.max_ttl + 1):
            ping, src, icmp_reply_type = self.get_data_with_fixed_ttl(ttl)
            yield ttl, ping, src
            if icmp_reply_type in (0, 129):
                break

    def get_data_with_fixed_ttl(self, ttl):
        icmp_reply_type = None
        start = time.time()
        reply = self.get_reply(self.get_packet(ttl))
        if reply is None:
            return None, None, icmp_reply_type
        end = reply.time
        src = reply.src
        icmp_reply_type = self.get_reply_type(reply)
        ping, src = round((end - start) * 1000), src
        return ping, src, icmp_reply_type

    def get_packet(self, ttl):
        if self.ip_version == 4:
            return (IP(dst=self.ip_address, ttl=ttl, len=self.size) /
                    ICMP(type=8) /
                    self.data)
        return (IPv6(dst=self.ip_address, hlim=ttl, plen=self.size) /
                ICMPv6EchoRequest(type=128, data=self.data))

    def get_reply(self, ip_packet):
        return sr1(ip_packet,
                   timeout=self.timeout,
                   verbose=0,
                   retry=-3)

    def get_reply_type(self, reply):
        if self.ip_version == 4:
            return reply[ICMP].type
        try:
            return reply[ICMPv6TimeExceeded].type
        except IndexError:
            return reply[ICMPv6EchoReply].type

    def print_row(self, ttl, ping, src):
        number = str(ttl).ljust(3)
        ip = ('*' if src is None else src).ljust(39)
        response_time = ('*' if ping is None else str(ping) + ' ms').ljust(7)
        if self.verbose:
            asn = Tracer.get_autonomous_system_number(src)
            asn = asn if asn is not None else '*'
            print(f'{number}  {ip}  {response_time}  {asn}')
        else:
            print(f'{number}  {ip}  {response_time}')

    @staticmethod
    def get_autonomous_system_number(ip):
        try:
            net = Net(ip)
            ip_asn = IPASN(net)
            lookup_result = ip_asn.lookup()
            return lookup_result['asn']
        except (TypeError, ValueError,
                exceptions.IPDefinedError,
                exceptions.ASNRegistryError,
                exceptions.ASNLookupError,
                exceptions.ASNOriginLookupError,
                ):
            return None

    @staticmethod
    def generate_packet_data(size, min_size):
        data = ('1' * (size - min_size)).encode()
        return size, data
