import argparse

import scapy.all as sp

from pynmap6.os_scan.os_scan import os_scan, OSScanCtx

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--iface', default=str(sp.conf.iface))
parser.add_argument('-r', '--retry', type=int, default=2)
parser.add_argument('-T', '--timewait', type=float, default=1.0)
parser.add_argument('-I', '--interval', type=float, default=0.1)
parser.add_argument('target')
args = parser.parse_args()

iface = args.iface
retry = args.retry
timewait = args.timewait
interval = args.interval
target = args.target

sp.conf.iface = iface

ctx = OSScanCtx(target,
                retry=retry,
                timewait=timewait,
                interval=interval,
                target=target)

results = os_scan.scan(ctx)

for name, fp in results.items():
    print('{}({})'.format(name, fp))
