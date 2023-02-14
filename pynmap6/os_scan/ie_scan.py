import time
import random
import threading
import select
import logging

import pcap
import scapy.all as sp

from typing import Optional, List, Mapping


class IEScanner:
    target: str
    ieid: int
    iface: str
    done: bool
    exc: Optional[Exception]
    results: Mapping[str, List[bytes]]

    logger = logging.getLogger('ie_scanner')

    def __init__(self,
                 target: str,
                 iface: Optional[str] = None,
                 interval: float = 1.0):
        self.target = target
        self.ieid = random.getrandbits(16)
        self.iface = iface if iface else sp.conf.iface
        self.interval = interval
        self.done = False
        self.exc = None
        self.results = {'ie1': [], 'ie2': []}

    def run(self):
        self.done = False
        self.exc = None
        self.results['ie1'] = []
        self.results['ie2'] = []

        if sp.conf.route6.route(self.target)[0] != self.iface:
            self.logger.warning('target to other iface: %s', self.target)
            return

        receiver = threading.Thread(target=self.receiver,
                                    args=(self.results['ie1'], ))
        receiver.start()

        try:
            self.ie1_send()
        except Exception as e:
            self.exc = e
            self.logger.error('sender excpet: %s', e)
        finally:
            self.done = True
            receiver.join()

        if self.exc is not None:
            return

        self.done = False

        receiver = threading.Thread(target=self.receiver,
                                    args=(self.results['ie2'], ))
        receiver.start()

        try:
            self.ie2_send()
        except Exception as e:
            self.exc = e
            self.logger.error('sender except: %s', e)
        finally:
            self.done = True
            receiver.join()

    def ie1_send(self):
        pkt = sp.IPv6(dst=self.target) / \
            sp.ICMPv6EchoRequest(code=9,
                                 id=self.ieid,
                                 seq=random.getrandbits(16),
                                 data=(b'\x00' * 120))
        sp.send(pkt, iface=self.iface, verbose=0)
        time.sleep(self.interval)

    def ie2_send(self):
        pkt = sp.IPv6(dst=self.target) / \
            sp.IPv6ExtHdrHopByHop(
                options=[sp.PadN(optdata=(b'\x00' * 4))]) / \
            sp.ICMPv6EchoRequest(id=self.ieid,
                                 seq=random.getrandbits(16),
                                 data=(b'\x00' * 120))
        sp.send(pkt, iface=self.iface, verbose=0)
        time.sleep(self.interval)

    def receiver(self, results: List[bytes]):
        sniffer = pcap.pcap(name=self.iface, promisc=False, timeout_ms=1)
        sniffer.setfilter(
            'ip6 src {} and '
            '('
            ' (icmp6[icmp6type]==icmp6-echoreply and icmp6[4:2]=={}) or '
            # Notice: icmpv6 parameter problem need deeper analysis
            ' icmp6[icmp6type]==icmp6-parameterproblem'
            ')'.format(self.target, self.ieid))
        sniffer.setdirection(pcap.PCAP_D_IN)
        sniffer.setnonblock()
        while not self.done:
            rlist, _, _ = select.select([sniffer.fd], [], [], 1)
            if rlist:
                sniffer.dispatch(1, lambda ts, pkt: results.append(pkt))
