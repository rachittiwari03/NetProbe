import argparse
from scapy.all import *

def network_scan(ip_address):
    request_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
    answered, unanswered = srp(request_packet, timeout=2, retry=1)
    scan_result = []

    for sent, received in answered:
        scan_result.append({'IP': received.psrc, 'MAC': received.hwsrc})

    return scan_result

def perform_tcp_scan(ip, target_ports):
    try:
        syn_packet = IP(dst=ip) / TCP(dport=target_ports, flags="S")
    except socket.gaierror:
        raise ValueError('Hostname {} could not be resolved.'.format(ip))

    answered, unanswered = sr(syn_packet, timeout=2, retry=1)
    open_ports = []

    for sent, received in answered:
        if received[TCP].flags == "SA":
            open_ports.append(received[TCP].sport)

    return open_ports

def main():
    argument_parser = argparse.ArgumentParser()
    subparsers = argument_parser.add_subparsers(
        dest="command", help="Command to perform.", required=True
    )

    arp_subparser = subparsers.add_parser(
        'ARP', help='Perform a network scan using ARP requests.'
    )
    arp_subparser.add_argument(
        'IP', help='An IP address (e.g. 192.168.1.1) or address range (e.g. 192.168.1.1/24) to scan.'
    )

    tcp_subparser = subparsers.add_parser(
        'TCP', help='Perform a TCP scan using SYN packets.'
    )
    tcp_subparser.add_argument('IP', help='An IP address or hostname to target.')
    tcp_subparser.add_argument(
        'ports', nargs='+', type=int,
        help='Ports to scan, delimited by spaces. When --range is specified, scan a range of ports. Otherwise, scan individual ports.'
    )
    tcp_subparser.add_argument(
        '--range', action='store_true',
        help='Specify a range of ports. When this option is specified, <ports> should be given as <low_port> <high_port>.'
    )

    args = argument_parser.parse_args()

    if args.command == 'ARP':
        result = network_scan(args.IP)

        for mapping in result:
            print('{} ==> {}'.format(mapping['IP'], mapping['MAC']))

    elif args.command == 'TCP':
        if args.range:
            target_ports = tuple(args.ports)
        else:
            target_ports = args.ports
        
        try:
            result = perform_tcp_scan(args.IP, target_ports)
        except ValueError as error:
            print(error)
            exit(1)

        for port in result:
            print('Port {} is open.')

if __name__ == '__main__':
    main()
