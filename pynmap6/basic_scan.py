import time
import select
import threading
import logging

import pcap
import scapy.all as sp

from typing import Optional, List


class BasicScanner:
    filter: str
    pkts: List[sp.IPv6]
    iface: str
    interval: float
    done: bool
    exc: Optional[Exception]
    results: List[bytes]

    logger = logging.getLogger('basic_scanner')

    def __init__(self,
                 filter: str,
                 pkts: List[sp.IPv6],
                 iface: Optional[str] = None,
                 interval: float = 0.1):
        self.filter = filter
        self.pkts = pkts
        self.iface = iface or str(sp.conf.iface)
        self.interval = interval
        self.done = False
        self.exc = None
        self.results = []

    def run(self):
        self.done = False
        self.exc = None
        self.results = []

        receiver = threading.Thread(target=self.receiver)
        receiver.start()

        try:
            self.sender()
        except Exception as e:
            self.exc = e
            self.logger.error('except while sending: %s', e)
        finally:
            self.done = True
            receiver.join()

        if self.exc is not None:
            raise self.exc

    def sender(self):
        raise NotImplementedError

    def send(self, pkt: sp.IPv6):
        dst = pkt.dst
        if sp.conf.route6.route(dst)[0] != self.iface:
            self.logger.warning('dst to other iface: %s', dst)
            return
        sp.send(pkt, iface=self.iface, verbose=0)
        time.sleep(self.interval)

    def receiver(self):
        sniffer = pcap.pcap(name=self.iface, promisc=False, timeout_ms=1)
        sniffer.setfilter(self.filter)
        sniffer.setnonblock()
        while not self.done:
            rlist, _, _ = select.select([sniffer.fd], [], [], 1)
            if rlist:
                sniffer.dispatch(1, self.receive_cb)

    def receive_cb(self, _ts: float, buf: bytes):
        self.results.append(buf)


class StatelessScanner(BasicScanner):
    logger = logging.getLogger('stateless_scanner')

    def __init__(self,
                 filter: str,
                 pkts: List[sp.IPv6],
                 iface: Optional[str] = None,
                 interval: float = 1.0):
        super().__init__(filter=filter,
                         pkts=pkts,
                         iface=iface,
                         interval=interval)

    def sender(self):
        for pkt in self.pkts:
            self.send(pkt)


class StatefulScanner(BasicScanner):
    retry: int
    timewait: float

    logger = logging.getLogger('stateful_scanner')

    def __init__(self,
                 filter: str,
                 pkts: List[sp.IPv6],
                 iface: Optional[str] = None,
                 retry: int = 2,
                 timewait: float = 1.0,
                 interval: float = 0.1):
        self.retry = retry
        self.timewait = timewait
        super().__init__(filter=filter,
                         pkts=pkts,
                         iface=iface,
                         interval=interval)

    def sender(self):
        for _ in range(self.retry):
            for pkt in self.pkts:
                self.send(pkt)
            time.sleep(self.timewait)
            if self.results:
                break
