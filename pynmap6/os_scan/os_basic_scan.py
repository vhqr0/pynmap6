import logging

import scapy.all as sp

from typing import Optional, List

from ..basic_scan import StatefulScanner


class OSScanCtx:
    target: str
    iface: str
    retry: int
    timewait: float
    interval: float
    open_port: Optional[int]
    closed_port: Optional[int]

    def __init__(self,
                 target: str,
                 iface: Optional[str] = None,
                 retry: int = 2,
                 timewait: float = 1.0,
                 interval: float = 0.1,
                 open_port: Optional[int] = None,
                 closed_port: Optional[int] = None):
        self.target = target
        self.iface = iface or str(sp.conf.iface)
        self.retry = retry
        self.timewait = timewait
        self.interval = interval
        self.open_port = open_port
        self.closed_port = closed_port


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

    def get_pkts(self) -> List[sp.IPv6]:
        raise NotImplementedError
