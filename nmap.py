import socket
import pprint
import argparse

import scapy.all as sp

from pynmap6.port_scan import PortScanner

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--iface', default=sp.conf.iface)
parser.add_argument('-p', '--port', default='22,80,443')
parser.add_argument('target')
args = parser.parse_args()

iface = args.iface
target = args.target
ports = (int(port) for port in args.port.split(','))

ai = socket.getaddrinfo(host=target,
                        port=0,
                        family=socket.AF_INET6,
                        type=socket.SOCK_DGRAM)

if not ai:
    raise RuntimeError('resolve failed')

target = ai[0][-1][0]

targets = ((target, port) for port in ports)

scanner = PortScanner(targets, iface=iface)

scanner.run()

results = scanner.parse()

pprint.pprint(results)
