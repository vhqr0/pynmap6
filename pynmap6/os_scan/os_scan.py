import base64

from typing import Optional, Type, Mapping

from .os_basic_scan import OSScanCtx, OSBasicScanner
from .ie_scan import IE1Scanner, IE2Scanner

scanner_clses: Mapping[str, Type[OSBasicScanner]] = {
    'IE1': IE1Scanner,
    'IE2': IE2Scanner,
}


def os_scan(target: str,
            iface: Optional[str] = None,
            retry: int = 2,
            timewait: float = 1.0,
            interval: float = 0.1) -> Mapping[str, str]:
    results: Mapping[str, str] = dict()
    ctx = OSScanCtx(target, iface, retry, timewait, interval)
    for name, scanner_cls in scanner_clses.items():
        try:
            scanner = scanner_cls(ctx)
            scanner.run()
            fp = scanner.parse()
            if fp:
                results[name] = base64.b64encode(fp).decode()
            else:
                raise ValueError('no finger print')
        except Exception as e:
            OSBasicScanner.logger.error('except while os scanning %s', e)
    return results
