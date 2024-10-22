import socket
import ipaddress
import sys
from tabulate import tabulate

from ping import Ping
from traceroute import Traceroute


class Target:

    def __init__(self, target_name, TTL, waiting_for_host,
                 packet_size, intermediate_nodes):
        self.target_name = target_name
        self.TTL = TTL
        self.waiting_for_host = waiting_for_host
        self.packet_size = packet_size
        self.intermediate_nodes = intermediate_nodes
        self.ips = []

    def target_address(self, target_name):
        try:
            addr_info = socket.getaddrinfo(target_name,
                                           None, socket.AF_INET6)
            target_address = addr_info[0][4][0]
        except (socket.gaierror, IndexError):
            try:
                target_address = socket.gethostbyname(target_name)
            except socket.gaierror:
                print(f'{target_name} is invalid')
                sys.exit()

        return target_address

    def handle_target(self):
        ping = Ping()
        tracer = Traceroute()
        self.ips = self.list_of_ips()

        try:
            for ip in self.ips:
                if ping.is_local(ip):
                    new_row = [0, ip, "local", '', '', 0]
                    ping.data.append(new_row)
                else:
                    tracer.get_traceroute(self.TTL,
                                          self.waiting_for_host,
                                          self.packet_size, self.ips)
                    break
            else:
                table = tabulate(ping.data,
                                 headers="firstrow", tablefmt="grid")
                print(table)
        except PermissionError:
            print("Permission error")
            sys.exit()

    def list_of_ips(self):
        while len(self.intermediate_nodes) != 0:
            for address in self.intermediate_nodes:
                self.ips.append(self.target_address(address))
                del self.intermediate_nodes[0]
        self.ips.append(self.target_address(self.target_name))

        return self.ips
