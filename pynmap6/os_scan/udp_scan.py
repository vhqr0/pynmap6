import random

import scapy.all as sp

from typing import Optional, Tuple, List

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

    def parse(self) -> Optional[bytes]:
        if self.results:
            pkt = sp.Ether(self.results[0])
            ippkt = pkt[sp.IPv6]
            return sp.raw(ippkt)

    def get_filter(self) -> str:
        return self.filter_tpl.format(self.target)

    def get_pkts(self) -> List[Tuple[str, sp.Packet]]:
        pkts = []
        for _ in range(3):
            pkt = sp.IPv6(dst=self.target) / \
                sp.UDP(sport=self.port, dport=random.getrandbits(16)) / \
                random.randbytes(120)
            pkts.append((self.target, pkt))
        return pkts
