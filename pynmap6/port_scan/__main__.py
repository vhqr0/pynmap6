import sys
import json
import argparse

import scapy.all as sp

from .port_scan import PortScanner
from .target_generate import TargetGenerator, pop_ports


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output')
    parser.add_argument('-i', '--iface', default=str(sp.conf.iface))
    parser.add_argument('-p', '--ports', default=pop_ports)
    parser.add_argument('-I', '--interval', type=float, default=1.0)
    parser.add_argument('addrs', nargs=argparse.REMAINDER)
    args = parser.parse_args()

    output = args.output
    iface = args.iface
    addrs = args.addrs
    ports = args.ports.split(',')
    interval = args.interval

    sp.conf.iface = iface

    if not addrs:
        for line in sys.stdin:
            line = line.strip()
            if not line or line[0] == '#':
                continue
            addrs.append(line)

    targets = TargetGenerator(addrs, ports).get_targets()
    scanner = PortScanner(targets, interval=interval)
    scanner.run()
    results = scanner.parse()

    if output:
        json.dump(results, open(output, 'w'))
    else:
        for addr, port, state in results:
            print(f'[{addr}]:{port}\t{state}')


if __name__ == '__main__':
    main()
