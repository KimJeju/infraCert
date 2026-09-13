"""왼쪽 Nav Rail — 업무 이동은 여기 하나뿐이다(상단 메뉴는 시스템 메뉴만)."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QFrame, QLabel, QPushButton, QVBoxLayout, QWidget

GROUPS: list[tuple[str, list[tuple[str, str]]]] = [
    ("업무", [("overview", "개요"), ("assets", "자산"), ("scan", "진단"), ("findings", "결과"), ("reports", "보고서")]),
    ("도구", [("rulepack", "룰팩"), ("terminal", "터미널"), ("sftp", "SFTP"), ("multiexec", "멀티실행"),
            ("manual", "수동확인")]),
    ("", [("settings", "설정")]),
]


class NavRail(QWidget):
    selected = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("nav")
        self.setFixedWidth(132)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 10, 8, 10)
        lay.setSpacing(2)
        self._btns: dict[str, QPushButton] = {}
        self._labels: dict[str, str] = {}
        for gi, (title, items) in enumerate(GROUPS):
            if gi:
                line = QFrame()
                line.setFrameShape(QFrame.Shape.HLine)
                line.setObjectName("nav-sep")
                lay.addSpacing(6)
                lay.addWidget(line)
                lay.addSpacing(6)
            if title:
                t = QLabel(title)
                t.setObjectName("nav-group")
                lay.addWidget(t)
            for key, label in items:
                b = QPushButton(label)
                b.setObjectName("nav-btn")
                b.setCheckable(True)
                b.setCursor(Qt.CursorShape.PointingHandCursor)
                b.clicked.connect(lambda _c=False, k=key: self.selected.emit(k))
                lay.addWidget(b)
                self._btns[key] = b
                self._labels[key] = label
        lay.addStretch(1)

    def set_current(self, key: str) -> None:
        for k, b in self._btns.items():
            b.setChecked(k == key)

    def set_badge(self, key: str, text: str) -> None:
        """예: 터미널 (2). 빈 문자열이면 배지 제거."""
        b = self._btns.get(key)
        if b:
            b.setText(f"{self._labels[key]}  {text}" if text else self._labels[key])

    def keys(self) -> list[str]:
        return list(self._btns)
