import random

import scapy.all as sp

from typing import List

from .os_basic_scan import OSScanCtx, OSBasicScanner

Pad4 = sp.PadN(optdata=b'\x00\x00\x00\x00')


class IE1Scanner(OSBasicScanner):
    target: str
    ieid: int

    filter_tpl = 'ip6 src {} and ' \
        'icmp6[icmp6type]==icmp6-echoreply and ' \
        'icmp6[4:2]=={}'

    def __init__(self, ctx: OSScanCtx):
        self.target = ctx.target
        self.ieid = random.getrandbits(16)
        super().__init__(ctx)

    def get_filter(self) -> str:
        return self.filter_tpl.format(self.target, self.ieid)

    def get_pkts(self) -> List[sp.IPv6]:
        pkt = sp.IPv6(dst=self.target) / \
            sp.IPv6ExtHdrHopByHop(options=[Pad4]) / \
            sp.ICMPv6EchoRequest(code=128 + random.getrandbits(7),
                                 id=self.ieid,
                                 seq=random.getrandbits(16),
                                 data=random.randbytes(120))
        return [pkt]


class IE2Scanner(OSBasicScanner):
    target: str
    ieid: int

    # Notice: icmpv6 parameter problem need deeper analysis
    filter_tpl = 'ip6 src {} and ' \
        '(' \
        ' (icmp6[icmp6type]==icmp6-echoreply and icmp6[4:2]=={}) or ' \
        ' icmp6[icmp6type]==icmp6-parameterproblem' \
        ')'

    def __init__(self, ctx: OSScanCtx):
        self.target = ctx.target
        self.ieid = random.getrandbits(16)
        super().__init__(ctx)

    # TODO: deeper analysis
    # def parse(self) -> Optional[bytes]:
    #     pass

    def get_filter(self) -> str:
        return self.filter_tpl.format(self.target, self.ieid)

    def get_pkts(self) -> List[sp.IPv6]:
        pkt = sp.IPv6(dst=self.target) / \
            sp.IPv6ExtHdrHopByHop(options=[Pad4]) / \
            sp.IPv6ExtHdrDestOpt(options=[Pad4]) / \
            sp.IPv6ExtHdrRouting() / \
            sp.IPv6ExtHdrHopByHop(options=[Pad4]) / \
            sp.ICMPv6EchoRequest(id=self.ieid,
                                 seq=random.getrandbits(16),
                                 data=random.randbytes(120))
        return [pkt]
