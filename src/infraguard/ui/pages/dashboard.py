"""대시보드(§4) — 카운트 카드 + 진행 중 작업 + 중요도별 취약 막대 + 호스트 히트맵 + 최근 진단.

실행오류(ERROR)를 취약(FAIL)과 별도 카드로 분리한다. 제품 절대 원칙의 UI 표현.
차트는 외부 라이브러리 없이 QPainter(ui/charts.py).
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from infraguard.core.status import DISPLAY_KO, ORDER, Status
from infraguard.result import diff as _diff
from infraguard.ui.charts import BarChart, HostHeatmap
from infraguard.ui.theme import BG1, BG3, FG1, STATUS_FG


class _Card(QFrame):
    clicked = Signal(object)  # Status

    def __init__(self, status: Status) -> None:
        super().__init__()
        self._status = status
        self.setFixedSize(150, 92)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        c = STATUS_FG[status]
        self.setStyleSheet(
            f"QFrame {{ background:{BG1}; border:1px solid {BG3}; border-left:4px solid {c}; }}"
            f" QFrame:hover {{ border-color:{c}; }}"
        )
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 12, 10)
        lbl = QLabel(DISPLAY_KO[status])
        lbl.setStyleSheet(f"color:{FG1};font-size:12px;font-weight:600;border:none;background:transparent")
        self.n = QLabel("0")
        self.n.setStyleSheet(f"color:{c};font-size:28px;font-weight:700;border:none;background:transparent")
        lay.addWidget(lbl)
        lay.addWidget(self.n)

    def set_value(self, v: int) -> None:
        self.n.setText(str(v))

    def mousePressEvent(self, _e) -> None:  # noqa: N802
        self.clicked.emit(self._status)


def _panel(title: str, body: QWidget) -> QWidget:
    w = QWidget()
    w.setObjectName("card")
    lay = QVBoxLayout(w)
    lay.setContentsMargins(14, 10, 14, 12)
    t = QLabel(title)
    t.setObjectName("h2")
    lay.addWidget(t)
    lay.addWidget(body, 1)
    return w


class DashboardPage(QWidget):
    start_scan_requested = Signal()
    filter_by_status = Signal(object)  # Status

    def __init__(self) -> None:
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(14)

        top = QHBoxLayout()
        title = QLabel("진단 현황")
        title.setObjectName("h1")
        top.addWidget(title)
        self.subtitle = QLabel("")
        self.subtitle.setObjectName("muted")
        top.addWidget(self.subtitle)
        top.addStretch(1)
        start = QPushButton("▶  새 진단 시작")
        start.setObjectName("primary")
        start.clicked.connect(self.start_scan_requested)
        top.addWidget(start)
        root.addLayout(top)

        cards = QHBoxLayout()
        cards.setSpacing(10)
        self._cards: dict[Status, _Card] = {}
        for s in ORDER:
            c = _Card(s)
            c.clicked.connect(self.filter_by_status)
            self._cards[s] = c
            cards.addWidget(c)
        cards.addStretch(1)
        root.addLayout(cards)

        self.running = QListWidget()
        self.running.setMaximumHeight(110)
        self.running.setStyleSheet("QListWidget{border:none;background:transparent}")
        run_panel = _panel("진행 중 작업", self.running)
        run_panel.setMaximumHeight(160)
        root.addWidget(run_panel)

        grid = QGridLayout()
        grid.setSpacing(12)
        self.sev_chart = BarChart()
        grid.addWidget(_panel("중요도별 취약", self.sev_chart), 0, 0)
        self.heat = HostHeatmap()
        grid.addWidget(_panel("호스트별 분포", self.heat), 0, 1)
        self.recent = QListWidget()
        self.recent.setStyleSheet("QListWidget{border:none;background:transparent}")
        grid.addWidget(_panel("최근 진단", self.recent), 0, 2)
        grid.setColumnStretch(0, 2)
        grid.setColumnStretch(1, 3)
        grid.setColumnStretch(2, 2)
        # 조치 현황: 전회(같은 호스트가 있는 직전 진단) 대비 조치됨/재발/취약 유지/신규 취약
        self.fix_chart = BarChart(label_w=64)
        fix_body = QWidget()
        fl = QVBoxLayout(fix_body)
        fl.setContentsMargins(0, 0, 0, 0)
        self.fix_label = QLabel("전회 진단 없음")
        self.fix_label.setObjectName("muted")
        fl.addWidget(self.fix_label)
        fl.addWidget(self.fix_chart, 1)
        fix_panel = _panel("조치 현황", fix_body)
        fix_panel.setMaximumHeight(190)
        grid.addWidget(fix_panel, 1, 0, 1, 3)
        root.addLayout(grid, 1)

    def update_counts(self, summary: dict[Status, int]) -> None:
        for s, c in self._cards.items():
            c.set_value(summary.get(s, 0))
        total = sum(summary.values())
        self.subtitle.setText(f"항목 {total}건" if total else "아직 진단 결과가 없습니다")

    def update_fix(self, summary: dict[str, int] | None, base_id: str | None) -> None:
        if not summary or base_id is None:
            self.fix_chart.set_rows([])
            self.fix_label.setText("전회 진단 없음 — 같은 호스트를 다시 진단하면 조치 현황이 나온다")
            return
        rate = _diff.fix_rate(summary)
        self.fix_label.setText(f"기준 {base_id} · 조치율 " + (f"{rate:.0%}" if rate is not None else "-(전회 취약 없음)"))
        self.fix_chart.set_rows([(_diff.LABEL_KO[k], summary.get(k, 0), _diff.COLOR[k]) for k in _diff.ORDER])

    def update_severity(self, high: int, mid: int, low: int) -> None:
        self.sev_chart.set_rows([("상", high, "#F85149"), ("중", mid, "#D29922"), ("하", low, "#8B949E")])

    def update_hosts(self, rows: list[tuple[str, dict[Status, int]]]) -> None:
        self.heat.set_rows(rows)

    def set_progress(self, rows: list[tuple[str, str, int]]) -> None:
        """rows: (hostname, stage, percent)."""
        self.running.clear()
        if not rows:
            it = QListWidgetItem("진행 중인 작업 없음")
            it.setForeground(Qt.GlobalColor.gray)
            self.running.addItem(it)
            return
        for name, stage, pct in rows:
            it = QListWidgetItem()
            w = QWidget()
            lay = QHBoxLayout(w)
            lay.setContentsMargins(4, 2, 4, 2)
            n = QLabel(f"◐ {name}")
            n.setStyleSheet("color:#D29922;font-weight:600")
            lay.addWidget(n, 1)
            st = QLabel(stage)
            st.setObjectName("muted")
            lay.addWidget(st, 2)
            bar = QProgressBar()
            bar.setValue(pct)
            bar.setMaximumWidth(180)
            lay.addWidget(bar)
            it.setSizeHint(w.sizeHint())
            self.running.addItem(it)
            self.running.setItemWidget(it, w)

    def set_recent(self, scans: list[tuple[str, dict]]) -> None:
        self.recent.clear()
        if not scans:
            it = QListWidgetItem("기록 없음")
            it.setForeground(Qt.GlobalColor.gray)
            self.recent.addItem(it)
        for sid, meta in scans[:10]:
            started = (meta.get("started_at") or "")[:16].replace("T", " ")
            prof = meta.get("profile") or ""
            self.recent.addItem(f"{started}   {sid}   {prof}")
