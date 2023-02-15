import time
import random
import logging

import scapy.all as sp

from typing import Optional, Generator, List

from ..basic_scan import StatelessScanner
from .os_basic_scan import OSScanCtx


class TCPSScaner(StatelessScanner):
    target: str
    target_port: int
    port: int
    initial_seq: int
    timewait: float
    s_results: List[List[bytes]]

    logger = logging.getLogger('tcp_s_scanner')

    filter_tpl = 'ip6 and ' \
        'tcp dst port {} and ' \
        'tcp src port {}'

    def __init__(self, ctx: OSScanCtx):
        if ctx.open_port is None:
            raise ValueError('open port is None')
        self.target = ctx.target
        self.target_port = ctx.open_port
        self.port = random.getrandbits(16)
        self.initial_seq = random.getrandbits(31)

        self.timewait = ctx.timewait
        self.s_results = [[], [], []]

        super().__init__(filter=self.get_filter(),
                         pkts=self.get_pkts(),
                         iface=ctx.iface,
                         interval=0.1)  # Notice: force 0.1s

    def parse(self) -> List[List[Optional[bytes]]]:
        results: List[List[Optional[bytes]]] = [
            [None, None, None, None, None, None],
            [None, None, None, None, None, None],
            [None, None, None, None, None, None],
        ]
        for i in range(3):
            s_results = self.s_results[i]
            for result in s_results:
                pkt = sp.Ether(result)
                ippkt = pkt[sp.IPv6]
                tcppkt = ippkt[sp.TCP]
                seq = tcppkt.seq
                idx = seq - self.initial_seq - 1
                if 0 <= idx < 6:
                    results[i][idx] = sp.raw(ippkt)
        return results

    def run(self):  # force run 3 times
        for i in range(3):
            super().run()
            time.sleep(self.timewait)
            self.s_results[i] = self.results

    def get_filter(self) -> str:
        return self.filter_tpl.format(self.port, self.target_port)

    def get_pkts(self) -> Generator[sp.IPv6, None, None]:
        pkts: List[sp.IPv6] = [
            self.s1(),
            self.s2(),
            self.s3(),
            self.s4(),
            self.s5(),
            self.s6(),
        ]
        return pkts

    def s1(self) -> sp.IPv6:
        pkt = sp.IPv6(dst=self.target) / \
            sp.TCP(sport=self.port,
                   dport=self.target_port,
                   seq=self.initial_seq+1,
                   flags='S',
                   window=1,
                   options=[
                       ('WScale', 10),
                       ('NOP', None),
                       ('MSS', 1460),
                       ('Timestamp', (0xffffffff, 0)),
                       ('SAckOK', b''),
                   ])
        return pkt

    def s2(self) -> sp.IPv6:
        pkt = sp.IPv6(dst=self.target) / \
            sp.TCP(sport=self.port,
                   dport=self.target_port,
                   seq=self.initial_seq+2,
                   flags='S',
                   window=63,
                   options=[
                       ('MSS', 1400),
                       ('WScale', 0),
                       ('SAckOK', b''),
                       ('Timestamp', (0xffffffff, 0)),
                       ('EOL', None),
                   ])
        return pkt

    def s3(self) -> sp.IPv6:
        pkt = sp.IPv6(dst=self.target) / \
            sp.TCP(sport=self.port,
                   dport=self.target_port,
                   seq=self.initial_seq+3,
                   flags='S',
                   window=4,
                   options=[
                       ('Timestamp', (0xffffffff, 0)),
                       ('NOP', None),
                       ('NOP', None),
                       ('WScale', 5),
                       ('NOP', None),
                       ('MSS', 640),
                   ])
        return pkt

    def s4(self) -> sp.IPv6:
        pkt = sp.IPv6(dst=self.target) / \
            sp.TCP(sport=self.port,
                   dport=self.target_port,
                   seq=self.initial_seq+4,
                   flags='S',
                   window=4,
                   options=[
                       ('SAckOK', b''),
                       ('Timestamp', (0xffffffff, 0)),
                       ('WScale', 10),
                       ('EOL', None),
                   ])
        return pkt

    def s5(self) -> sp.IPv6:
        pkt = sp.IPv6(dst=self.target) / \
            sp.TCP(sport=self.port,
                   dport=self.target_port,
                   seq=self.initial_seq+5,
                   flags='S',
                   window=16,
                   options=[
                       ('MSS', 536),
                       ('SAckOK', b''),
                       ('Timestamp', (0xffffffff, 0)),
                       ('WScale', 10),
                       ('EOL', None),
                   ])
        return pkt

    def s6(self) -> sp.IPv6:
        pkt = sp.IPv6(dst=self.target) / \
            sp.TCP(sport=self.port,
                   dport=self.target_port,
                   seq=self.initial_seq+6,
                   flags='S',
                   window=512,
                   options=[
                       ('MSS', 265),
                       ('SAckOK', b''),
                       ('Timestamp', (0xffffffff, 0)),
                   ])
        return pkt
