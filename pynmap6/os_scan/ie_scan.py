import random

import scapy.all as sp

from typing import Optional, Tuple, List

from .os_basic_scan import OSScanCtx, OSBasicScanner


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

    def parse(self) -> Optional[bytes]:
        if self.results:
            pkt = sp.Ether(self.results[0])
            ippkt = pkt[sp.IPv6]
            return sp.raw(ippkt)

    def get_filter(self) -> str:
        return self.filter_tpl.format(self.target, self.ieid)

    def get_pkts(self) -> List[Tuple[str, sp.Packet]]:
        pkt = sp.IPv6(dst=self.target) / \
            sp.ICMPv6EchoRequest(code=9,
                                 id=self.ieid,
                                 seq=random.getrandbits(16),
                                 data=random.randbytes(120))
        return [(self.target, pkt)]


class IE2Scanner(OSBasicScanner):
    target: str
    ieid: int

    # Notice: icmpv6 parameter problem need deeper analysis
    filter_tpl = 'ip6 src {} and ' \
        '(' \
        ' (icmp6[icmp6type]==icmp6-echoreply and icmp6[4:2]=={}) or ' \
        ' icmp6[icmp6type]==icmp6-parameterproblem' \
        ')'

    Pad4 = sp.PadN(optdata=b'\x00\x00\x00\x00')

    def __init__(self, ctx: OSScanCtx):
        self.target = ctx.target
        self.ieid = random.getrandbits(16)
        super().__init__(ctx)

    def parse(self) -> Optional[bytes]:
        for buf in self.results:
            pkt = sp.Ether(buf)
            ippkt = pkt[sp.IPv6]
            if sp.ICMPv6EchoReply in ippkt:
                return sp.raw(ippkt)
            if sp.ICMPv6ParamProblem in ippkt:
                # TODO: deeper analysis
                return sp.raw(ippkt)

    def get_filter(self) -> str:
        return self.filter_tpl.format(self.target, self.ieid)

    def get_pkts(self) -> List[Tuple[str, sp.Packet]]:
        pkt = sp.IPv6(dst=self.target) / \
            sp.IPv6ExtHdrHopByHop(options=[self.Pad4]) / \
            sp.IPv6ExtHdrDestOpt(options=[self.Pad4]) / \
            sp.IPv6ExtHdrRouting() / \
            sp.IPv6ExtHdrHopByHop(options=[self.Pad4]) / \
            sp.ICMPv6EchoRequest(id=self.ieid,
                                 seq=random.getrandbits(16),
                                 data=random.randbytes(120))
        return [(self.target, pkt)]
