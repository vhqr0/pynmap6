import socket
import argparse

from pynmap6.port_scan import PortScanner

parser = argparse.ArgumentParser()
parser.add_argument('-p', '--port', default='22,80,443')
parser.add_argument('target')
args = parser.parse_args()

target = args.target
ports = (int(port) for port in args.port.split(','))

ai = socket.getaddrinfo(target, 0, family=socket.AF_INET6, type=socket.SOCK_DGRAM)

if not ai:
    raise RuntimeError('resolve failed')

target = ai[0][-1][0]

targets = ((target, port) for port in ports)

scanner = PortScanner(targets)

scanner.run()

print(scanner.exc)
print(scanner.results)
