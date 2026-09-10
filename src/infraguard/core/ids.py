"""식별자 생성."""

from __future__ import annotations

import secrets
from datetime import datetime


def new_scan_id(now: datetime | None = None) -> str:
    """SCAN-YYYYMMDD-NNNNNN (뒤 6자리는 충돌 방지용 난수)."""
    d = (now or datetime.now()).strftime("%Y%m%d")
    return f"SCAN-{d}-{secrets.randbelow(1_000_000):06d}"


def new_host_id(now: datetime | None = None) -> str:
    return "H-" + secrets.token_hex(4)
