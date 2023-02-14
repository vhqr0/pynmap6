import pprint
import argparse

import scapy.all as sp

from pynmap6.port_scan import PortScanner
from pynmap6.target_generate import TargetGenerator

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--iface', default=str(sp.conf.iface))
parser.add_argument('-p', '--ports', default='22,80,443')
parser.add_argument('-I', '--interval', type=float, default=1.0)
parser.add_argument('addrs', nargs=argparse.REMAINDER)
args = parser.parse_args()

iface = args.iface
addrs = args.addrs
ports = args.ports.split(',')
interval = args.interval

sp.conf.iface = iface

targets = TargetGenerator(addrs, ports).gen_targets()
scanner = PortScanner(targets, interval=interval)

scanner.run()
results = scanner.parse()

pprint.pprint(results)
