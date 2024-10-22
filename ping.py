import ipaddress
import socket
import struct
import time

from whois import Whois


class Ping:

    def __init__(self):
        self.data = [['ttl', 'IP', 'network', 'AS', 'country', 'time']]

    def create_pack(self, sequence, packet_size, ip_type):

        if ip_type == 4:
            icmp_type = 8  # ICMPv4 Echo Request
        else:
            icmp_type = 128  # ICMPv6 Echo Request

        icmp_code = 0
        icmp_id = socket.htons(1)

        if ip_type == 4:
            header_format = "bbHHH"  # Формат для IPv4
        else:
            header_format = "!BBHHH"  # Формат для IPv6

        header = struct.pack(header_format, icmp_type,
                             icmp_code, 0, icmp_id, sequence)

        data = b'\xAA' * (packet_size - 8)

        pack = bytearray(header + data)

        if len(pack) % 2 != 0:
            pack += b'\x00'

        checksum = self.calculate_checksum(pack)
        header_with_checksum = struct.pack(header_format, icmp_type,
                                           icmp_code, checksum,
                                           icmp_id, sequence)

        packet = header_with_checksum + data
        return packet

    def calculate_checksum(self, packet):
        checksum = 0
        for i in range(0, len(packet), 2):
            if i + 1 < len(packet):
                this_val = packet[i] + (packet[i + 1] << 8)
                checksum += this_val
                if checksum > 0xffff:
                    checksum = (checksum & 0xffff) + 1
        checksum = ~checksum & 0xffff
        checksum = checksum >> 8 | ((checksum << 8) & 0xff00)

        return socket.htons(checksum)

    def make_hop(self, destination_address, sock, sequence, ttl,
                 packet_size, ip_type, attempts=2):
        whois_Client = Whois()

        sock.sendto(self.create_pack(sequence, packet_size, ip_type),
                    (destination_address, 0))
        start_time = time.time()

        try:
            recv_packet, address = sock.recvfrom(2048)
            received_time = time.time()

            icmp_type = self.get_icmp_type(recv_packet, ip_type)

            destination_unreachable = {4: 3, 6: 1}
            time_exceeded = {4: 11, 6: 3}
            echo_reply = {4: 0, 6: 129}

            if icmp_type in (destination_unreachable[ip_type],
                             time_exceeded[ip_type], echo_reply[ip_type]):
                time_difference = (received_time - start_time)
                hop_time = round(time_difference * 1000)
                print(f'{address[0] : <17}{hop_time : >4} ms', end='\r\n')

                if self.is_local(address[0]):
                    self.handle_hop(ttl, address[0], 'local',
                                    '', '', hop_time)
                else:
                    netname, origin, country = whois_Client.whois(address[0])
                    self.handle_hop(ttl, address[0], netname, origin,
                                    country, hop_time)

            if (icmp_type == echo_reply[4] or icmp_type == echo_reply[6]):
                return True
            return False

        except socket.timeout:

            if attempts <= 0:
                self.handle_timeout(ttl)
                return False
            else:
                print("a", attempts)
                return self.make_hop(destination_address, sock,
                                     sequence, ttl, packet_size,
                                     ip_type, attempts - 1)

    def get_icmp_type(self, packet, ip_type):
        if ip_type == 4:
            icmp_type = struct.unpack('BB', packet[20:22])[0]
        else:
            icmp_type = struct.unpack('BB', packet[0:2])[0]
        return icmp_type

    def handle_hop(self, ttl, address, netname, origin, country, hop_time):
        print(f'{address : <17}{hop_time : >4} ms', end='\r\n')
        new_row = [ttl, address, netname, origin, country, hop_time]
        self.data.append(new_row)

    def handle_timeout(self, ttl):
        new_row = [ttl, "*", "*", '*', '*', "*"]
        self.data.append(new_row)

    def is_local(self, target_address):
        ip = ipaddress.ip_address(target_address)
        if ip.version == 4:
            ip_octets = list(map(int, target_address.split('.')))
            ip = ((ip_octets[0] << 24) | (ip_octets[1] << 16) |
                  (ip_octets[2] << 8) | ip_octets[3])

            if ((ip & 0xFF000000) == 0x0A000000) or \
                    ((ip & 0xFFF00000) == 0xAC100000) or \
                    ((ip & 0xFFFF0000) == 0xC0A80000) or \
                    ((ip & 0xFFC00000) == 0x64400000) or \
                    ((ip & 0xFF000000) == 0x7F000000):
                return True
        else:
            if (ip in ipaddress.IPv6Network('fc00::/7') or
                    ip in ipaddress.IPv6Network('fe80::/10') or
                    ip == ipaddress.IPv6Address('::1')):
                return True
            else:
                return False
