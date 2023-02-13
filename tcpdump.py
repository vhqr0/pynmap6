import select
import argparse

import pcap
import scapy.all as sp

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--iface', default=str(sp.conf.iface))
parser.add_argument('-d', '--direction', default='inout')
parser.add_argument('-I', '--interval', type=float, default=1.0)
parser.add_argument('filterstr', nargs=argparse.REMAINDER)
args = parser.parse_args()

iface = args.iface
direction = pcap.PCAP_D_INOUT
if args.direction == 'in':
    direction = pcap.PCAP_D_IN
elif args.direction == 'out':
    direction = pcap.PCAP_D_OUT
interval = args.interval
filterstr = ' '.join(args.filterstr)

sniffer = pcap.pcap(name=iface, promisc=False, timeout_ms=1)
sniffer.setfilter(filterstr)
sniffer.setdirection(direction)
sniffer.setnonblock()


def prn(ts, pkt, *args):
    print(ts, sp.Ether(pkt).summary())


while True:
    rlist, [], [] = select.select([sniffer.fd], [], [], interval)
    if rlist:
        sniffer.dispatch(1, prn)
    else:
        print('timeout')
