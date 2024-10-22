import argparse
from typing import List, Tuple


class Parser:
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="Parse network tool arguments")
        self.parser.add_argument("TTL",
                                 type=int, help="Time to live for packets")
        self.parser.add_argument("target_name",
                                 type=str, help="Target hostname")
        self.parser.add_argument("waiting_for_host",
                                 type=int, help="Time to wait for the host in ms")
        self.parser.add_argument("packet_size",
                                 type=int, help="Size of the packet in bytes")
        self.parser.add_argument("intermediate_nodes",
                                 nargs='+', help="List of intermediate nodes")
        self.args = vars(self.parser.parse_args())

    def parse_arguments(self) -> Tuple[int, str, int, int, List[str]]:
        TTL = int(self.args["TTL"])
        target_name = self.args["target_name"]
        waiting_for_host = int(self.args["waiting_for_host"])
        packet_size = int(self.args["packet_size"])
        intermediate_nodes = self.args["intermediate_nodes"]

        return TTL, target_name, waiting_for_host, packet_size, intermediate_nodes
