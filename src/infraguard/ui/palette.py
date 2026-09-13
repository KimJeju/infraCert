"""Ctrl+K Command Palette — 명령 + 자산 + 룰을 한 검색창에서. 221룰·여러 고객사를 다룰 때의 발견성."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDialog, QLineEdit, QListWidget, QListWidgetItem, QVBoxLayout, QWidget


@dataclass(slots=True)
class Command:
    category: str
    title: str
    run: Callable[[], None]
    keywords: str = ""

    def text(self) -> str:
        return f"{self.category}  ›  {self.title}"

    def matches(self, q: str) -> bool:
        if not q:
            return True
        hay = f"{self.category} {self.title} {self.keywords}".lower()
        return all(tok in hay for tok in q.lower().split())


Provider = Callable[[str], list[Command]]


class CommandPalette(QDialog):
    MAX = 40

    def __init__(self, commands: list[Command], providers: list[Provider] | None = None,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("명령 검색")
        self.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        self.setObjectName("palette")
        self.resize(640, 420)
        self._commands = commands
        self._providers = providers or []
        self._shown: list[Command] = []
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 8, 8, 8)
        self.input = QLineEdit()
        self.input.setPlaceholderText("명령 · 자산 · 룰 검색  (Esc 닫기, Enter 실행)")
        self.input.textChanged.connect(self.refresh)
        self.input.returnPressed.connect(self._run_current)
        lay.addWidget(self.input)
        self.list = QListWidget()
        self.list.itemActivated.connect(lambda _it: self._run_current())
        lay.addWidget(self.list, 1)
        self.refresh("")

    def refresh(self, q: str) -> None:
        self._shown = [c for c in self._commands if c.matches(q)]
        if q.strip():
            for p in self._providers:
                try:
                    self._shown += p(q)
                except Exception:  # noqa: BLE001,S110 - 검색 제공자 오류가 팔레트를 죽이지 않게
                    pass
        self._shown = self._shown[: self.MAX]
        self.list.clear()
        for c in self._shown:
            self.list.addItem(QListWidgetItem(c.text()))
        if self._shown:
            self.list.setCurrentRow(0)

    def keyPressEvent(self, e) -> None:  # noqa: N802,ANN001
        if e.key() in (Qt.Key.Key_Down, Qt.Key.Key_Up):
            row = self.list.currentRow() + (1 if e.key() == Qt.Key.Key_Down else -1)
            self.list.setCurrentRow(max(0, min(row, self.list.count() - 1)))
            return
        super().keyPressEvent(e)

    def _run_current(self) -> None:
        i = self.list.currentRow()
        if 0 <= i < len(self._shown):
            cmd = self._shown[i]
            self.accept()
            cmd.run()

    def open(self) -> None:  # noqa: A003
        self.input.clear()
        self.refresh("")
        self.input.setFocus()
        if self.parent() is not None:
            g = self.parent().geometry()
            self.move(g.center().x() - self.width() // 2, g.top() + 90)
        super().open()
