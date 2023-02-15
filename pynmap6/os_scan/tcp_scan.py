import random

import scapy.all as sp

from typing import List

from .os_basic_scan import OSScanCtx, OSBasicScanner


class TCPBaseScanner(OSBasicScanner):
    target: str
    target_port: int
    port: int

    filter_tpl = 'ip6 and ' \
        'tcp dst port {} and ' \
        'tcp src port {}'

    def __init__(self, ctx: OSScanCtx, target_port: int):
        self.target = ctx.target
        self.target_port = target_port
        self.port = random.getrandbits(16)
        super().__init__(ctx)

    def get_filter(self) -> str:
        return self.filter_tpl.format(self.port, self.target_port)


class TCPOpenScanner(TCPBaseScanner):

    def __init__(self, ctx: OSScanCtx):
        if ctx.open_port is None:
            raise ValueError('open port is None')
        super().__init__(ctx, ctx.open_port)


class TCPClosedScanner(TCPBaseScanner):

    def __init__(self, ctx: OSScanCtx):
        if ctx.closed_port is None:
            raise ValueError('closed port is None')
        super().__init__(ctx, ctx.closed_port)


class TECNScanner(TCPOpenScanner):

    def get_pkts(self) -> List[sp.IPv6]:
        pkt = sp.IPv6(dst=self.target) / \
            sp.TCP(sport=self.port,
                   dport=self.target_port,
                   seq=random.getrandbits(32),
                   flags='SEC',  # SYN ECE CWR
                   window=3,
                   urgptr=0xf7f5,
                   options=[
                       ('WScale', 10),
                       ('NOP', None),
                       ('MSS', 1460),
                       ('SAckOK', b''),
                       ('NOP', None),
                       ('NOP', None),
                   ])
        return [pkt]
