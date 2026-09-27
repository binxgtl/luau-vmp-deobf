"""Small, non-executing Luraph family classifier for pipeline routing."""
from __future__ import annotations

import re


_V15_HEADER = re.compile(r"Luraph\s+Obfuscator\s+v15(?:\.\d+)?\b", re.I)


def looks_like_v15(source: str) -> bool:
    """Identify known v15 wrappers without treating an LPH token as enough."""
    if _V15_HEADER.search(source):
        return True
    return (
        "LPH:" in source
        and ("buffer.fromstring" in source or "buffer.writeu8" in source)
        and (":mS()" in source or "mS=function" in source)
    )
