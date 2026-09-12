"""외부 라이브러리 없는 QPainter 차트(§4) — 막대 · 호스트×상태 히트맵."""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QWidget

from infraguard.core.status import DISPLAY_KO, ORDER, Status
from infraguard.ui.theme import BG1, BG3, FG0, FG1, STATUS_FG


class BarChart(QWidget):
    """가로 막대. rows: [(라벨, 값, 색)]."""

    def __init__(self, label_w: int = 40) -> None:
        super().__init__()
        self._rows: list[tuple[str, int, str]] = []
        self._label_w = label_w
        self.setMinimumHeight(90)

    def set_rows(self, rows: list[tuple[str, int, str]]) -> None:
        self._rows = rows
        self.setMinimumHeight(max(60, 26 * len(rows) + 12))
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor(BG1))
        if not self._rows:
            p.setPen(QColor(FG1))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "데이터 없음")
            return
        mx = max((v for _, v, _ in self._rows), default=0) or 1
        label_w = self._label_w
        val_w = 36
        bar_x = 12 + label_w
        bar_w = max(10, self.width() - bar_x - val_w - 12)
        f = QFont(self.font())
        f.setPointSize(9)
        p.setFont(f)
        for i, (label, val, color) in enumerate(self._rows):
            y = 8 + i * 26
            p.setPen(QColor(FG0))
            p.drawText(QRectF(8, y, label_w, 18), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, label)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QColor(BG3))
            p.drawRect(QRectF(bar_x, y + 2, bar_w, 14))
            w = bar_w * (val / mx)
            p.setBrush(QColor(color))
            if w > 0:
                p.drawRect(QRectF(bar_x, y + 2, max(6, w), 14))
            p.setPen(QColor(FG0))
            p.drawText(QRectF(bar_x + bar_w + 6, y, val_w, 18),
                       Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, str(val))
        p.end()


class HostHeatmap(QWidget):
    """호스트별 상태 분포를 한 줄 스택 막대로. rows: [(호스트명, {Status: n})]."""

    def __init__(self) -> None:
        super().__init__()
        self._rows: list[tuple[str, dict[Status, int]]] = []
        self.setMinimumHeight(90)

    def set_rows(self, rows: list[tuple[str, dict[Status, int]]]) -> None:
        self._rows = rows
        self.setMinimumHeight(max(60, 24 * len(rows) + 30))
        self.update()

    def paintEvent(self, _e) -> None:  # noqa: N802
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), QColor(BG1))
        f = QFont(self.font())
        f.setPointSize(9)
        p.setFont(f)
        if not self._rows:
            p.setPen(QColor(FG1))
            p.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "진단 결과 없음")
            p.end()
            return
        label_w = 90
        x0 = 8 + label_w
        w_total = max(10, self.width() - x0 - 12)
        for i, (name, summ) in enumerate(self._rows):
            y = 8 + i * 24
            total = sum(summ.values()) or 1
            p.setPen(QColor(FG0))
            p.drawText(QRectF(8, y, label_w - 6, 16), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                       p.fontMetrics().elidedText(name, Qt.TextElideMode.ElideRight, label_w - 8))
            x = float(x0)
            p.setPen(Qt.PenStyle.NoPen)
            for st in ORDER:
                n = summ.get(st, 0)
                if not n:
                    continue
                w = w_total * n / total
                p.setBrush(QColor(STATUS_FG[st]))
                p.drawRect(QRectF(x, y + 1, w, 14))
                x += w
        # 범례
        ly = 8 + len(self._rows) * 24 + 2
        x = float(x0)
        for st in ORDER:
            p.setBrush(QColor(STATUS_FG[st]))
            p.setPen(Qt.PenStyle.NoPen)
            p.drawRect(QRectF(x, ly + 3, 10, 10))
            p.setPen(QPen(QColor(FG1)))
            p.drawText(QRectF(x + 14, ly, 60, 16), Qt.AlignmentFlag.AlignVCenter, DISPLAY_KO[st])
            x += 70
        p.end()
