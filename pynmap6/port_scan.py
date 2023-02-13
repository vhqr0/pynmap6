import random
import select
import threading
import logging

import pcap
import scapy.all as sp

from typing import Optional, Generator, Tuple, List


class PortScanner:
    targets: Generator[Tuple[str, int], None, None]
    port: int
    iface: str
    done: bool
    exc: Optional[Exception]
    results: List[bytes]

    logger = logging.getLogger('port_scanner')

    def __init__(self,
                 targets: Generator[Tuple[str, int], None, None],
                 iface: Optional[str] = None):
        self.targets = targets
        self.port = random.getrandbits(16)
        self.iface = iface if iface else str(sp.conf.iface)
        self.done = False
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
            self.logger.error('sender except: %s', e)
        finally:
            self.done = True
            receiver.join()

    def sender(self):
        for target in self.targets:
            if sp.conf.route6.route(target[0])[0] != self.iface:
                self.logger.warning('target to other iface: %s', target)
                continue
            pkt = sp.IPv6(dst=target[0]) / \
                sp.TCP(sport=self.port, dport=target[1], flags='S')
            sp.send(pkt, verbose=0)  # auto add eth header

    def receiver(self):
        sniffer = pcap.pcap(name=self.iface, promisc=False, timeout_ms=1)
        sniffer.setfilter(f'tcp dst port {self.port}')
        sniffer.setdirection(pcap.PCAP_D_IN)
        sniffer.setnonblock()
        while not self.done:
            rlist, _, _ = select.select([sniffer.fd], [], [], 1)
            if rlist:
                sniffer.dispatch(1, self.receive_callback)

    def receive_callback(self, ts, pkt, *args):
        self.results.append(pkt)
