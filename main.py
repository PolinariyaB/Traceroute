from parser import Parser
from target import Target


def main():
    parser = Parser()
    (TTL, target_name, waiting_for_host, packet_size,
     intermediate_nodes) = parser.parse_arguments()
    handler = Target(target_name, TTL,
                     waiting_for_host, packet_size, intermediate_nodes)

    print(intermediate_nodes)
    handler.handle_target()


if __name__ == '__main__':
    main()
