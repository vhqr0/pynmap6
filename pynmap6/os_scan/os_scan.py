import base64

from typing import Type, Mapping

from .os_basic_scan import OSScanCtx, OSBasicScanner
from .ie_scan import IE1Scanner, IE2Scanner

scanner_clses: Mapping[str, Type[OSBasicScanner]] = {
    'ie1': IE1Scanner,
    'ie2': IE2Scanner,
}


def os_scan(ctx: OSScanCtx) -> Mapping[str, str]:
    results: Mapping[str, str] = dict()
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
