import pprint
import argparse

import scapy.all as sp

from pynmap6.port_scan import PortScanner
from pynmap6.target_generate import TargetGenerator

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--iface', default=sp.conf.iface)
parser.add_argument('-p', '--ports', default='22,80,443')
parser.add_argument('addrs', nargs=argparse.REMAINDER)
args = parser.parse_args()

iface = args.iface
ports = args.ports.split(',')
addrs = args.addrs

targets = TargetGenerator(addrs, ports).new()
scanner = PortScanner(targets, iface=iface)

scanner.run()
results = scanner.parse()

pprint.pprint(results)
