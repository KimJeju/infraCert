"""완전 삭제 및 잔류물 검증.

한계 명시: 논리적 삭제만 보장한다.
SSD 의 wear leveling, 저널링 파일시스템, 볼륨 섀도카피 환경에서는
덮어쓰기가 물리적 소거를 보장하지 못한다. 안전 삭제로 광고하지 않는다.
"""

from __future__ import annotations

import logging
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from infraguard.workspace.layout import Layout

log = logging.getLogger(__name__)


@dataclass
class SanitizeReport:
    removed: list[str] = field(default_factory=list)
    leftovers: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.leftovers and not self.errors


def _force_writable(func, path, _exc):  # type: ignore[no-untyped-def]
    """읽기전용 속성 때문에 삭제가 막히는 경우 해제 후 재시도."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception as e:  # noqa: BLE001
        log.warning("cannot remove %s: %s", path, e)


def sanitize(layout: Layout) -> SanitizeReport:
    rep = SanitizeReport()

    if layout.root.exists():
        try:
            shutil.rmtree(layout.root, onerror=_force_writable)
            rep.removed.append(str(layout.root))
        except Exception as e:  # noqa: BLE001
            rep.errors.append(f"{layout.root}: {e}")

    # 삭제 검증 — 조용히 남기지 않는다
    if layout.root.exists():
        for p in layout.root.rglob("*"):
            rep.leftovers.append(str(p))
        if not rep.leftovers:
            rep.leftovers.append(str(layout.root))

    # 시스템 임시폴더에 우리가 만든 잔여물 확인
    sys_tmp = Path(tempfile.gettempdir())
    try:
        for p in sys_tmp.glob("infraguard-*"):
            try:
                if p.is_dir():
                    shutil.rmtree(p, onerror=_force_writable)
                else:
                    p.unlink()
                rep.removed.append(str(p))
            except Exception as e:  # noqa: BLE001
                rep.errors.append(f"{p}: {e}")
    except OSError as e:
        rep.errors.append(f"{sys_tmp}: {e}")

    return rep
