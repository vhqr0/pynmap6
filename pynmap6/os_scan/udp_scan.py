import random

import scapy.all as sp

from typing import List

from .os_basic_scan import OSScanCtx, OSBasicScanner


class U1Scanner(OSBasicScanner):
    target: str
    port: int

    filter_tpl = 'ip6 src {} and ' \
        'icmp6[icmp6type]==icmp6-destinationunreach and ' \
        'icmp6[icmp6code]==4'

    def __init__(self, ctx: OSScanCtx):
        self.target = ctx.target
        self.port = random.getrandbits(16)
        super().__init__(ctx)

    def get_filter(self) -> str:
        return self.filter_tpl.format(self.target)

    def get_pkts(self) -> List[sp.IPv6]:
        pkts = []
        for _ in range(3):
            pkt = sp.IPv6(dst=self.target) / \
                sp.UDP(sport=self.port, dport=random.getrandbits(16)) / \
                random.randbytes(random.randint(20, 40))
            pkts.append(pkt)
        return pkts
