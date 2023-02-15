"""
Links:

https://nmap.org/book/osdetect.html
https://nmap.org/book/osdetect-methods.html
https://nmap.org/book/osdetect-ipv6-methods.html
"""

import base64

from typing import Optional, Type, Mapping, Dict, List

from .os_basic_scan import OSScanCtx, OSBasicScanner
from .tcp_s_scan import TCPSScanner
from .tcp_scan import TECNScanner, T2Scanner, T3Scanner, T4Scanner, \
    T5Scanner, T6Scanner, T7Scanner
from .udp_scan import U1Scanner
from .ie_scan import IE1Scanner, IE2Scanner

scanner_clses: Mapping[str, Type[OSBasicScanner]] = {
    'TECN': TECNScanner,
    'T2': T2Scanner,
    'T3': T3Scanner,
    'T4': T4Scanner,
    'T5': T5Scanner,
    'T6': T6Scanner,
    'T7': T7Scanner,
    'U1': U1Scanner,
    'IE1': IE1Scanner,
    'IE2': IE2Scanner,
}


def os_scan(target: str,
            iface: Optional[str] = None,
            retry: int = 2,
            timewait: float = 1.0,
            interval: float = 0.1,
            open_port: Optional[int] = None,
            closed_port: Optional[int] = None,
            finger_prints: List[str] = []) -> Mapping[str, Optional[str]]:

    results: Dict[str, Optional[str]] = dict()

    if not finger_prints:
        finger_prints = list(scanner_clses)
        finger_prints.append('S')

    ctx = OSScanCtx(target,
                    iface=iface,
                    retry=retry,
                    timewait=timewait,
                    interval=interval,
                    open_port=open_port,
                    closed_port=closed_port)

    if 'S' in finger_prints:
        try:
            s_scanner = TCPSScanner(ctx)
            s_scanner.run()
            s_results = s_scanner.parse()
            for i in range(3):
                for j in range(6):
                    name = f'S{j+1}#{i+1}'
                    fp = s_results[i][j]
                    if fp:
                        results[name] = base64.b64encode(fp).decode()
                    else:
                        results[name] = None
        except Exception as e:
            TCPSScanner.logger.error('except while os scanning: %s', e)

    for name, scanner_cls in scanner_clses.items():
        if name not in finger_prints:
            continue
        try:
            scanner = scanner_cls(ctx)
            scanner.run()
            fp = scanner.parse()
            if fp:
                results[name] = base64.b64encode(fp).decode()
            else:
                results[name] = None
        except Exception as e:
            OSBasicScanner.logger.error('except while os scanning: %s', e)
    return results
