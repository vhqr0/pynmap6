import time
import select
import threading
import logging

import pcap
import scapy.all as sp

from typing import Optional, Generator, Tuple, List


class BasicScanner:
    filter: str
    iface: str
    interval: float
    done: bool
    exc: Optional[Exception]
    results: List[bytes]

    logger = logging.getLogger('basic_scanner')

    def __init__(self,
                 filter: str,
                 iface: Optional[str] = None,
                 interval: float = 0.1):
        self.filter = filter
        self.iface = iface or str(sp.conf.iface)
        self.interval = interval

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
            self.logger.error('sender except: %s', e)
        finally:
            self.done = True
            receiver.join()

    def sender(self):
        raise NotImplementedError

    def send(self, dst: str, pkt: sp.Packet):
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
    pkts: Generator[Tuple[str, sp.Packet], None, None]

    logger = logging.getLogger('stateless_scanner')

    def __init__(self,
                 filter: str,
                 pkts: Generator[Tuple[str, sp.Ether], None, None],
                 iface: Optional[str] = None,
                 interval: float = 1.0):
        self.pkts = pkts
        super().__init__(filter, iface, interval)

    def sender(self):
        for dst, pkt in self.pkts:
            self.send(dst, pkt)


class StatefulScanner(BasicScanner):
    pkts: List[Tuple[str, sp.Packet]]
    retry: int
    timewait: float

    logger = logging.getLogger('stateful_scanner')

    def __init__(self,
                 filter: str,
                 pkts: List[Tuple[str, sp.Packet]],
                 iface: Optional[str] = None,
                 retry: int = 2,
                 timewait: float = 1.0,
                 interval: float = 0.1):
        self.pkts = pkts
        self.retry = retry
        self.timewait = timewait
        super().__init__(filter, iface, interval)

    def sender(self):
        for _ in range(self.retry):
            for dst, pkt in self.pkts:
                self.send(dst, pkt)
            time.sleep(self.timewait)
            if self.results:
                break
