import random
import logging

import scapy.all as sp

from typing import Optional, Generator, Tuple, List

from .basic_scan import StatelessScanner


class PortScanner(StatelessScanner):
    targets: Generator[Tuple[str, int], None, None]
    port: int

    logger = logging.getLogger('port_scanner')

    def __init__(self,
                 targets: Generator[Tuple[str, int], None, None],
                 iface: Optional[str] = None,
                 interval: float = 1.0):
        self.targets = targets
        self.port = random.getrandbits(16)
        super().__init__(filter=self.gen_filter(),
                         pkts=self.gen_pkts(),
                         iface=iface,
                         interval=interval)

    def parse(self) -> List[Tuple[str, int, str]]:
        if self.exc:
            raise self.exc
        results = [self.parse1(buf) for buf in self.results]
        return [result for result in results if result is not None]

    def parse1(self, buf) -> Tuple[str, int, str]:
        try:
            pkt = sp.Ether(buf)
            ippkt = pkt[sp.IPv6]
            tcppkt = ippkt[sp.TCP]
            flags = tcppkt.flags
            if 'R' in flags:
                return ippkt.src, tcppkt.sport, 'close'
            if 'S' in flags and 'A' in flags:
                return ippkt.src, tcppkt.sport, 'open'
            raise ValueError('invalid tcp flags')
        except Exception as e:
            self.logger.warning('except while parsing: %s', e)

    def gen_filter(self) -> str:
        return f'ip6 and tcp dst port {self.port}'

    def gen_pkts(self) -> Generator[Tuple[str, sp.Packet], None, None]:
        return (self.gen_pkt(target) for target in self.targets)

    def gen_pkt(self, target: Tuple[str, int]) -> Tuple[str, sp.Packet]:
        pkt = sp.IPv6(dst=target[0]) / \
            sp.TCP(sport=self.port,
                   dport=target[1],
                   seq=random.getrandbits(32),
                   flags='S',
                   window=1024,
                   options=[('MSS', 1460)])
        return target[0], pkt
