import argparse
from src.tracer import Tracer

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='traceroute',
                                     description='Traceroute traces network packet paths and identifies intermediate routers and their timings.')
    parser.add_argument('host', type=str,
                        help='host name or ip-address')
    parser.add_argument('-n', default=30, type=int,
                        dest='ttl',
                        help='maximum time-to-live value')
    parser.add_argument('-t', default=0.5, type=float,
                        dest='timeout',
                        help='request timeout in seconds')
    parser.add_argument('-v', action='store_true',
                        dest='verbose',
                        help='output the autonomous system number for each IP address')
    args = parser.parse_args()
    traceroute = Tracer(host=args.host,
                        timeout=args.timeout,
                        max_ttl=args.ttl,
                        verbose=args.verbose,
                        )
    traceroute.print_trace_table()
