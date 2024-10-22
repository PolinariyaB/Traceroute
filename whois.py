import socket

from pip._vendor import requests


class Whois:
    def whois_query(self, address, server):
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.connect((server, 43))
            sock.send((address + "\r\n").encode())
            response = b""
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            try:
                response = response.decode()
            except UnicodeDecodeError:
                return ''
        return response

    def whoisIANA(self, address):
        response_first = self.whois_query(address, "whois.iana.org")
        if not response_first:
            return ''

        whois_server = ''
        for line in response_first.split('\n'):
            if "whois:" in line.lower():
                whois_server = line.split()[-1]
        return whois_server

    def whois(self, address):
        netname, origin, country = "", "", ""
        whois_server = self.whoisIANA(address)
        if not whois_server:
            return netname, origin, country

        response_second = self.whois_query(address, whois_server)
        if not response_second:
            return netname, origin, country

        for line in response_second.split('\n'):
            line = line.lower()
            if 'netname' in line:
                netname = line.split(':')[1].strip()
            elif 'origin' in line:
                origin = line.split(':')[1].strip()
            elif 'country' in line:
                if line.split(':')[1].strip() == "eu":
                    country = self.get_country_by_ip(address)
                else:
                    country = line.split(':')[1].strip()

        return netname, origin, country

    def get_country_by_ip(self, ip_address):
        url = f"http://ip-api.com/json/{ip_address}"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                json_data = response.json()
                country = json_data.get('country')
                return country
            else:
                print(f"Error: {response.status_code}")
        except Exception as e:
            print(f"Error: {e}")
