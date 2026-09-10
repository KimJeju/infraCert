"""작업공간 수명 관리."""

from __future__ import annotations

import logging
from pathlib import Path

from infraguard.workspace.layout import Layout
from infraguard.workspace.sanitizer import SanitizeReport, sanitize

log = logging.getLogger(__name__)


class Workspace:
    def __init__(self, root: Path | None = None) -> None:
        self.layout = Layout(root)
        self._open_closers: list[object] = []

    def create(self) -> Layout:
        self.layout.root.mkdir(parents=True, exist_ok=True)
        for d in self.layout.all_dirs():
            d.mkdir(parents=True, exist_ok=True)
        return self.layout

    def register_closable(self, obj: object) -> None:
        """삭제 전에 닫아야 하는 자원(SQLite 연결 등)."""
        self._open_closers.append(obj)

    def close_all(self) -> None:
        for obj in self._open_closers:
            close = getattr(obj, "close", None)
            if callable(close):
                try:
                    close()
                except Exception:  # noqa: BLE001 - 삭제를 막으면 안 된다
                    log.warning("failed to close %r", type(obj).__name__)
        self._open_closers.clear()

    def sanitize(self) -> SanitizeReport:
        """완전 삭제. 열린 자원을 먼저 닫는다."""
        self.close_all()
        return sanitize(self.layout)
