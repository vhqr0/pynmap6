import random
import re
import socket

from typing import Generator, Tuple, List

# from nmap/portlist.cc::random_port_cheat::pop_ports
pop_ports = '80,23,443,21,22,25,3389,110,445,139,' \
    '143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720'


class AddrGenerator:
    addrs: List[str]

    def __init__(self, addrs: List[str]):
        self.addrs = []
        for addr in addrs:
            self.addrs.append(self.resolve(addr))

    @staticmethod
    def resolve(addr):
        info = socket.getaddrinfo(host=addr,
                                  port=0,
                                  family=socket.AF_INET6,
                                  type=socket.SOCK_DGRAM)
        return random.choice(info)[-1][0]


class PortGenerator:
    ports: List[int]

    single_port_re = re.compile(r'^\d+$')
    range_ports_re = re.compile(r'^(\d+)-(\d+)$')

    def __init__(self, ports: List[str]):
        self.ports = []
        for port in ports:
            res = self.single_port_re.match(port)
            if res is not None:
                self.add_single_port(port)
                continue
            res = self.range_ports_re.match(port)
            if res is not None:
                self.add_range_ports(res[1], res[2])
                continue
            raise ValueError(f'invalid port {port}')

    def add_single_port(self, port_str: str):
        port = int(port_str)
        if not 0 < port <= 65535:
            raise ValueError(f'invalid single port: {port}')
        self.ports.append(port)

    def add_range_ports(self, port_beg_str: str, port_end_str: str):
        port_beg, port_end = int(port_beg_str), int(port_end_str)
        if not 0 < port_beg < port_end <= 65535:
            raise ValueError(f'invalid range ports {port_beg}-{port_end}')
        for port in range(port_beg, port_end + 1):
            self.ports.append(port)


class TargetGenerator:
    addrs: List[str]
    ports: List[int]

    def __init__(self, addrs: List[str], ports: List[str]):
        self.addrs = AddrGenerator(addrs).addrs
        self.ports = PortGenerator(ports).ports

    def get_targets(self) -> Generator[Tuple[str, int], None, None]:
        return ((addr, port) for addr in self.addrs for port in self.ports)
