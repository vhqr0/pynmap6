import sys
import json
import argparse

import scapy.all as sp

from .os_scan import os_scan


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output')
    parser.add_argument('-i', '--iface', default=str(sp.conf.iface))
    parser.add_argument('-r', '--retry', type=int, default=2)
    parser.add_argument('-T', '--timewait', type=float, default=1.0)
    parser.add_argument('-I', '--interval', type=float, default=0.1)
    parser.add_argument('target')
    args = parser.parse_args()

    output = args.output
    iface = args.iface
    target = args.target
    retry = args.retry
    timewait = args.timewait
    interval = args.interval

    sp.conf.iface = iface

    results = os_scan(target,
                      retry=retry,
                      timewait=timewait,
                      interval=interval)

    if output:
        json.dump(results, open(output, 'w'))
    else:
        for name, fp in results.items():
            print(f'{name}\t{fp}')


if __name__ == '__main__':
    main()
