import random

import scapy.all as sp

from typing import Optional, List

from .os_basic_scan import OSScanCtx, OSBasicScanner


class TECNScanner(OSBasicScanner):
    target: str
    open_port: int
    port: int

    filter_tpl = 'ip6 and ' \
        'tcp dst port {} and ' \
        'tcp src port {}'

    def __init__(self, ctx: OSScanCtx):
        if ctx.open_port is None:
            raise ValueError('TECN need open port')
        self.target = ctx.target
        self.open_port = ctx.open_port
        self.port = random.getrandbits(16)
        super().__init__(ctx)

    def parse(self) -> Optional[bytes]:
        if not self.results:
            return None
        pkt = sp.Ether(self.results[0])
        ippkt = pkt[sp.IPv6]
        return sp.raw(ippkt)

    def get_filter(self) -> str:
        return self.filter_tpl.format(self.port, self.open_port)

    def get_pkts(self) -> List[sp.IPv6]:
        pkt = sp.IPv6(dst=self.port) / \
            sp.TCP(sport=self.port,
                   dport=self.open_port,
                   seq=random.getrandbits(32),
                   flags='SEC',  # SYN ECE CWR
                   window=3,
                   urgptr=0xf7f5,
                   options=[
                       ('WScale', 10),
                       ('NOP', None),
                       ('MSS', 1460),
                       ('SAckOK', None),
                       ('NOP', None)
                       ('NOP', None)
                   ])
        return [pkt]
