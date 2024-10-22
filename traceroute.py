import ipaddress
import socket
import struct
from tabulate import tabulate
from ping import Ping


class Traceroute:
    def get_traceroute(self, TTL, waiting_for_host, packet_size, ips):
        print(ips)
        ping = Ping()
        sequence = 1
        current_ttl = 1

        while ips:
            destination_address = ips.pop(0)
            ip_type = ipaddress.ip_address(destination_address).version

            for ttl in range(current_ttl, TTL + 1):
                print(f'{ttl: >3}', end='  ')

                if ip_type == 4:
                    sock = socket.socket(family=socket.AF_INET,
                                         type=socket.SOCK_RAW,
                                         proto=socket.IPPROTO_ICMP)
                    sock.setsockopt(socket.IPPROTO_IP,
                                    socket.IP_TTL,
                                    struct.pack('I', ttl))
                else:
                    sock = socket.socket(family=socket.AF_INET6,
                                         type=socket.SOCK_RAW,
                                         proto=socket.IPPROTO_ICMPV6)
                    sock.setsockopt(socket.IPPROTO_IPV6,
                                    socket.IPV6_UNICAST_HOPS, ttl)

                sock.settimeout(waiting_for_host)

                check_trace_complete = ping.make_hop(destination_address,
                                                     sock, sequence,
                                                     ttl, packet_size, ip_type)
                print("target host:", destination_address)
                sequence += 1

                if check_trace_complete:
                    current_ttl = ttl + 1
                    break

        table = tabulate(ping.data, headers="firstrow", tablefmt="grid")
        print(table)
