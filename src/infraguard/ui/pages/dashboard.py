"""개요(Overview) — "다음에 무엇을 해야 하는가".

결과가 없으면 빈 차트 대신 Empty State + [첫 진단 시작]. 있으면 KPI 4개(자산·마지막 진단·취약점·조치율),
위험 현황, 조치 필요(위험도 높은 취약부터), 최근 진단. 그 아래(스크롤) 조치 현황·호스트별 분포·Top Findings.
실행오류(ERROR)는 취약(FAIL)과 항상 구분한다. 차트는 QPainter(ui/charts.py), 외부 라이브러리 없음.
"""

from __future__ import annotations

from collections import Counter

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
    QScrollArea,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from infraguard.core.status import DISPLAY_KO, ORDER, Status
from infraguard.result import diff as _diff
from infraguard.result import risk as _risk
from infraguard.ui.charts import BarChart, HostHeatmap
from infraguard.ui.theme import BG1, BG3, FG1, STATUS_FG, STATUS_ICON


class _Card(QFrame):
    clicked = Signal(object)  # Status

    def __init__(self, status: Status) -> None:
        super().__init__()
        self._status = status
        self.setFixedSize(150, 84)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        c = STATUS_FG[status]
        self.setStyleSheet(
            f"QFrame {{ background:{BG1}; border:1px solid {BG3}; border-left:4px solid {c}; }}"
            f" QFrame:hover {{ border-color:{c}; }}"
        )
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 8, 12, 8)
        lbl = QLabel(f"{STATUS_ICON[status]} {DISPLAY_KO[status]}")
        lbl.setStyleSheet(f"color:{FG1};font-size:12px;font-weight:600;border:none;background:transparent")
        self.n = QLabel("0")
        self.n.setStyleSheet(f"color:{c};font-size:26px;font-weight:700;border:none;background:transparent")
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


def _kpi(label: str) -> tuple[QWidget, QLabel]:
    w = QWidget()
    w.setObjectName("card")
    lay = QVBoxLayout(w)
    lay.setContentsMargins(16, 10, 16, 10)
    n = QLabel("-")
    n.setObjectName("kpi-n")
    lab = QLabel(label)
    lab.setObjectName("kpi-l")
    lay.addWidget(n)
    lay.addWidget(lab)
    return w, n


class DashboardPage(QWidget):
    start_scan_requested = Signal()
    filter_by_status = Signal(object)  # Status
    filter_by_rule = Signal(str)       # rule id — 결과 검색
    open_finding = Signal(str, str)    # hostname, rule id — 조치 필요 항목 클릭

    def __init__(self) -> None:
        super().__init__()
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.stack = QStackedWidget()
        outer.addWidget(self.stack, 1)

        # ---- Empty State ----
        empty = QWidget()
        el = QVBoxLayout(empty)
        el.setContentsMargins(20, 16, 20, 16)
        top = QHBoxLayout()
        t0 = QLabel("개요")
        t0.setObjectName("h1")
        top.addWidget(t0)
        top.addStretch(1)
        b0 = QPushButton("▶  새 진단 시작")
        b0.setObjectName("primary")
        b0.clicked.connect(self.start_scan_requested)
        top.addWidget(b0)
        el.addLayout(top)
        el.addStretch(2)
        et = QLabel("아직 진단 결과가 없습니다.")
        et.setObjectName("empty-title")
        et.setAlignment(Qt.AlignmentFlag.AlignCenter)
        el.addWidget(et)
        es = QLabel("자산을 선택하고 첫 번째 진단을 시작하세요. 자산이 없으면 [자산] 화면에서 추가하거나 JSON 으로 가져옵니다.")
        es.setObjectName("muted")
        es.setAlignment(Qt.AlignmentFlag.AlignCenter)
        es.setWordWrap(True)
        el.addWidget(es)
        el.addSpacing(12)
        brow = QHBoxLayout()
        brow.addStretch(1)
        self.first_btn = QPushButton("첫 진단 시작")
        self.first_btn.setObjectName("primary")
        self.first_btn.setMinimumWidth(180)
        self.first_btn.clicked.connect(self.start_scan_requested)
        brow.addWidget(self.first_btn)
        brow.addStretch(1)
        el.addLayout(brow)
        el.addStretch(3)
        self.stack.addWidget(empty)

        # ---- 데이터 있음 ----
        body = QWidget()
        root = QVBoxLayout(body)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(12)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(body)
        self.stack.addWidget(scroll)

        top = QHBoxLayout()
        title = QLabel("개요")
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

        kpis = QHBoxLayout()
        kpis.setSpacing(10)
        self.kpi: dict[str, QLabel] = {}
        for key, label in (("assets", "자산"), ("last", "마지막 진단"), ("vulns", "취약점"), ("fix", "조치율")):
            w, n = _kpi(label)
            self.kpi[key] = n
            kpis.addWidget(w, 1)
        root.addLayout(kpis)

        cards = QHBoxLayout()
        cards.setSpacing(8)
        self._cards: dict[Status, _Card] = {}
        for s in ORDER:
            c = _Card(s)
            c.clicked.connect(self.filter_by_status)
            self._cards[s] = c
            cards.addWidget(c)
        cards.addStretch(1)
        root.addLayout(cards)

        grid = QGridLayout()
        grid.setSpacing(12)
        self.risk_chart = BarChart(label_w=44)
        grid.addWidget(_panel("위험 현황 (가이드 중요도 × 자산 중요도)", self.risk_chart), 0, 0)
        self.todo = QListWidget()
        self.todo.setStyleSheet("QListWidget{border:none;background:transparent}")
        self.todo.itemActivated.connect(self._todo_activated)
        grid.addWidget(_panel("조치 필요 — 위험도 높은 취약부터 (더블클릭 → 결과)", self.todo), 0, 1)
        self.recent = QListWidget()
        self.recent.setStyleSheet("QListWidget{border:none;background:transparent}")
        self.recent.setMaximumHeight(150)
        grid.addWidget(_panel("최근 진단", self.recent), 1, 0, 1, 2)
        # 진행 중 작업: 진단 중일 때만 보인다
        self.running = QListWidget()
        self.running.setStyleSheet("QListWidget{border:none;background:transparent}")
        self.run_panel = _panel("진행 중 작업", self.running)
        self.run_panel.setMaximumHeight(150)
        self.run_panel.hide()
        grid.addWidget(self.run_panel, 2, 0, 1, 2)
        # 2차 정보(아래로 스크롤)
        self.fix_chart = BarChart(label_w=64)
        fix_body = QWidget()
        fl = QVBoxLayout(fix_body)
        fl.setContentsMargins(0, 0, 0, 0)
        self.fix_label = QLabel("전회 진단 없음")
        self.fix_label.setObjectName("muted")
        fl.addWidget(self.fix_label)
        fl.addWidget(self.fix_chart, 1)
        grid.addWidget(_panel("조치 현황 (전회 대비)", fix_body), 3, 0)
        self.heat = HostHeatmap()
        grid.addWidget(_panel("호스트별 분포", self.heat), 3, 1)
        self.sev_chart = BarChart()
        grid.addWidget(_panel("가이드 중요도별 취약", self.sev_chart), 4, 0)
        self.top_findings = QListWidget()
        self.top_findings.setStyleSheet("QListWidget{border:none;background:transparent}")
        self.top_findings.itemActivated.connect(lambda it: self.filter_by_rule.emit(it.data(Qt.ItemDataRole.UserRole) or ""))
        grid.addWidget(_panel("Top Findings (영향 호스트 수)", self.top_findings), 4, 1)
        self.top_assets = QListWidget()
        self.top_assets.setStyleSheet("QListWidget{border:none;background:transparent}")
        grid.addWidget(_panel("Top Affected Assets", self.top_assets), 5, 0)
        for r in range(6):
            grid.setRowMinimumHeight(r, 150)
        grid.setColumnStretch(0, 1)
        grid.setColumnStretch(1, 1)
        root.addLayout(grid, 1)
        self.stack.setCurrentIndex(0)

    # ---------------------------------------------------------------- 데이터
    def set_empty(self, empty: bool) -> None:
        self.stack.setCurrentIndex(0 if empty else 1)

    def set_kpi(self, assets: int, last: str | None, vulns: int, fix_rate: float | None) -> None:
        self.kpi["assets"].setText(str(assets))
        self.kpi["last"].setText(last or "-")
        self.kpi["vulns"].setText(str(vulns))
        self.kpi["fix"].setText(f"{fix_rate:.0%}" if fix_rate is not None else "-")

    def update_counts(self, summary: dict[Status, int]) -> None:
        for s, c in self._cards.items():
            c.set_value(summary.get(s, 0))
        total = sum(summary.values())
        self.subtitle.setText(f"항목 {total}건" if total else "")

    def update_risk(self, counts: dict[str, int]) -> None:
        self.risk_chart.set_rows([(_risk.LABEL_KO[k], counts.get(k, 0), _risk.COLOR[k]) for k in _risk.LEVELS])

    def update_severity(self, high: int, mid: int, low: int) -> None:
        self.sev_chart.set_rows([("상", high, "#F85149"), ("중", mid, "#D29922"), ("하", low, "#8B949E")])

    def update_hosts(self, rows: list[tuple[str, dict[Status, int]]]) -> None:
        self.heat.set_rows(rows)

    def update_fix(self, summary: dict[str, int] | None, base_id: str | None) -> None:
        if not summary or base_id is None:
            self.fix_chart.set_rows([])
            self.fix_label.setText("전회 진단 없음 — 같은 호스트를 다시 진단하면 조치 현황이 나온다")
            return
        rate = _diff.fix_rate(summary)
        self.fix_label.setText(f"기준 {base_id} · 조치율 " + (f"{rate:.0%}" if rate is not None else "-(전회 취약 없음)"))
        self.fix_chart.set_rows([(_diff.LABEL_KO[k], summary.get(k, 0), _diff.COLOR[k]) for k in _diff.ORDER])

    def update_todo(self, scan) -> None:  # noqa: ANN001
        """조치 필요: 취약 항목을 위험도 순으로. (rule, host, 위험도)."""
        self.todo.clear()
        if scan is None:
            return
        order = {k: i for i, k in enumerate(_risk.LEVELS)}
        rows = []
        for h in scan.hosts:
            crit = h.asset.get("criticality")
            for r in h.results:
                if r.status is Status.FAIL:
                    lvl = _risk.level(r.severity, crit)
                    rows.append((order[lvl], r.rule_id, h.hostname, lvl, r.name))
        rows.sort()
        for _o, rid, hn, lvl, name in rows[:12]:
            it = QListWidgetItem(f"{STATUS_ICON[Status.FAIL]} {rid:<7} {hn:<18} {_risk.LABEL_KO[lvl]:<4} {name[:34]}")
            it.setForeground(Qt.GlobalColor.white)
            it.setData(Qt.ItemDataRole.UserRole, (hn, rid))
            self.todo.addItem(it)
        if not rows:
            self.todo.addItem("취약 없음 — 조치할 항목이 없습니다")

    def _todo_activated(self, it: QListWidgetItem) -> None:
        data = it.data(Qt.ItemDataRole.UserRole)
        if data:
            self.open_finding.emit(*data)

    def update_top(self, scan) -> None:  # noqa: ANN001
        self.top_assets.clear()
        self.top_findings.clear()
        if scan is None:
            return
        per_host = Counter()
        per_rule: dict[str, set[str]] = {}
        names: dict[str, str] = {}
        for h in scan.hosts:
            for r in h.results:
                if r.status is Status.FAIL:
                    per_host[h.hostname] += 1
                    per_rule.setdefault(r.rule_id, set()).add(h.hostname)
                    names[r.rule_id] = r.name
        for hn, n in per_host.most_common(8):
            self.top_assets.addItem(f"{hn:<24} {n}")
        for rid, hs in sorted(per_rule.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:8]:
            it = QListWidgetItem(f"{rid:<7} {len(hs)} hosts   {names.get(rid, '')[:40]}")
            it.setData(Qt.ItemDataRole.UserRole, rid)
            self.top_findings.addItem(it)
        if not per_host:
            self.top_assets.addItem("취약 없음")
            self.top_findings.addItem("취약 없음")

    def set_progress(self, rows: list[tuple[str, str, int]]) -> None:
        """rows: (hostname, stage, percent). 비어 있으면 패널 숨김."""
        self.running.clear()
        self.run_panel.setVisible(bool(rows))
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

    def set_recent(self, scans: list[tuple[str, dict]], details: dict[str, str] | None = None) -> None:
        """details: scan_id → '3대 · 64 rules · 3 VULN · 완료' 같은 요약."""
        self.recent.clear()
        if not scans:
            it = QListWidgetItem("기록 없음")
            it.setForeground(Qt.GlobalColor.gray)
            self.recent.addItem(it)
        for sid, meta in scans[:8]:
            started = (meta.get("started_at") or "")[:16].replace("T", " ")
            prof = meta.get("profile") or ""
            extra = (details or {}).get(sid, "")
            self.recent.addItem(f"{started}   {prof:<16} {extra}   {sid}")
