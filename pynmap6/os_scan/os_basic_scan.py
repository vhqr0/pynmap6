import logging

import scapy.all as sp

from typing import Optional, Tuple, List

from ..basic_scan import StatefulScanner


class OSScanCtx:
    target: str
    iface: str
    retry: int
    timewait: float
    interval: float

    def __init__(self,
                 target: str,
                 iface: Optional[str] = None,
                 retry: int = 2,
                 timewait: float = 1.0,
                 interval: float = 0.1):
        self.target = target
        self.iface = iface or str(sp.conf.iface)
        self.retry = retry
        self.timewait = timewait
        self.interval = interval


class OSBasicScanner(StatefulScanner):

    logger = logging.getLogger('os_basic_scanner')

    def __init__(self, ctx: OSScanCtx):
        super().__init__(filter=self.get_filter(),
                         pkts=self.get_pkts(),
                         iface=ctx.iface,
                         retry=ctx.retry,
                         timewait=ctx.timewait,
                         interval=ctx.interval)

    def parse(self) -> Optional[bytes]:
        raise NotImplementedError

    def get_filter(self) -> str:
        raise NotImplementedError

    def get_pkts(self) -> List[Tuple[str, sp.Packet]]:
        raise NotImplementedError
