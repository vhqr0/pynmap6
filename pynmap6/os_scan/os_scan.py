import base64

from typing import Optional, Type, Mapping, Dict

from .os_basic_scan import OSScanCtx, OSBasicScanner
from .ie_scan import IE1Scanner, IE2Scanner
from .udp_scan import U1Scanner

scanner_clses: Mapping[str, Type[OSBasicScanner]] = {
    'IE1': IE1Scanner,
    'IE2': IE2Scanner,
    'U1': U1Scanner,
}


def os_scan(target: str,
            iface: Optional[str] = None,
            retry: int = 2,
            timewait: float = 1.0,
            interval: float = 0.1) -> Mapping[str, Optional[str]]:
    results: Dict[str, Optional[str]] = dict()
    ctx = OSScanCtx(target, iface, retry, timewait, interval)
    for name, scanner_cls in scanner_clses.items():
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
