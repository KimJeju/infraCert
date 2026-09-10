"""결과 페이지 — 필터 · 표 · 상세 · 매트릭스 뷰 · 내보내기(§6.1)."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from infraguard.core.models import CheckResult, ScanResult
from infraguard.core.status import DISPLAY_KO, Status
from infraguard.result.engine import _sort_key
from infraguard.ui.theme import STATUS_BG

COLS = ["호스트", "항목코드", "점검항목", "중요도", "결과", "판정근거"]
_DISPLAY_TO_STATUS = {v: k for k, v in DISPLAY_KO.items()}


class ResultPage(QWidget):
    export_requested = Signal(str)  # "xlsx" | "html"

    def __init__(self) -> None:
        super().__init__()
        self._scan: ScanResult | None = None
        self._flat: list[tuple[str, CheckResult]] = []
        self._matrix = False
        root = QVBoxLayout(self)

        bar = QHBoxLayout()
        self.host_f = QComboBox()
        self.status_f = QComboBox()
        self.sev_f = QComboBox()
        self.host_f.addItem("호스트 전체", "")
        self.status_f.addItem("상태 전체", "")
        for s in Status:
            self.status_f.addItem(DISPLAY_KO[s], s.value)
        self.sev_f.addItem("중요도 전체", "")
        for s in ("상", "중", "하"):
            self.sev_f.addItem(s, s)
        self.search = QLineEdit()
        self.search.setPlaceholderText("항목코드/이름 검색…")
        for w in (self.host_f, self.status_f, self.sev_f):
            w.currentIndexChanged.connect(self._apply)
        self.search.textChanged.connect(self._apply)
        bar.addWidget(self.host_f)
        bar.addWidget(self.status_f)
        bar.addWidget(self.sev_f)
        bar.addWidget(self.search, 1)
        self.matrix_btn = QPushButton("매트릭스 뷰")
        self.matrix_btn.setCheckable(True)
        self.matrix_btn.toggled.connect(self._toggle_matrix)
        bar.addWidget(self.matrix_btn)
        xlsx = QPushButton("XLSX")
        html = QPushButton("HTML")
        xlsx.clicked.connect(lambda: self.export_requested.emit("xlsx"))
        html.clicked.connect(lambda: self.export_requested.emit("html"))
        bar.addWidget(xlsx)
        bar.addWidget(html)
        root.addLayout(bar)

        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.itemSelectionChanged.connect(self._show_detail)
        root.addWidget(self.table, 3)

        root.addWidget(QLabel("상세"))
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMaximumHeight(160)
        root.addWidget(self.detail, 1)

    def load(self, scan: ScanResult | None) -> None:
        self._scan = scan
        self._flat = []
        if scan:
            for h in scan.hosts:
                for r in h.results:
                    self._flat.append((h.hostname, r))
            self._flat.sort(key=lambda t: (t[0], _sort_key(t[1].rule_id)))
        hosts = sorted({hn for hn, _ in self._flat})
        cur = self.host_f.currentData()
        self.host_f.blockSignals(True)
        self.host_f.clear()
        self.host_f.addItem("호스트 전체", "")
        for hn in hosts:
            self.host_f.addItem(hn, hn)
        idx = self.host_f.findData(cur)
        self.host_f.setCurrentIndex(idx if idx >= 0 else 0)
        self.host_f.blockSignals(False)
        self._apply()

    def set_status_filter(self, status: Status) -> None:
        i = self.status_f.findData(status.value)
        if i >= 0:
            self.status_f.setCurrentIndex(i)

    def _filtered(self) -> list[tuple[str, CheckResult]]:
        hf = self.host_f.currentData()
        sf = self.status_f.currentData()
        vf = self.sev_f.currentData()
        q = self.search.text().strip().lower()
        out = []
        for hn, r in self._flat:
            if hf and hn != hf:
                continue
            if sf and r.status.value != sf:
                continue
            if vf and (not r.severity or r.severity.value != vf):
                continue
            if q and q not in f"{r.rule_id} {r.name}".lower():
                continue
            out.append((hn, r))
        return out

    def _apply(self) -> None:
        if self._matrix:
            self._render_matrix()
        else:
            self._render_flat()

    def _render_flat(self) -> None:
        self.table.setColumnCount(len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        rows = self._filtered()
        self.table.setRowCount(len(rows))
        for i, (hn, r) in enumerate(rows):
            # 판정근거 컬럼은 수집 근거 첫 줄. 근거가 없으면 엔진 사유(누락·미등록 어휘 등)를 보인다.
            ev = (r.evidence or "").strip().splitlines()
            vals = [hn, r.rule_id, r.name, r.severity.value if r.severity else "",
                    DISPLAY_KO[r.status], ev[0] if ev else r.reason]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 4:
                    it.setBackground(QColor(STATUS_BG[r.status]))
                    it.setForeground(QColor("#1a1a1a"))
                    it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                it.setData(Qt.ItemDataRole.UserRole, (hn, r.rule_id))
                self.table.setItem(i, c, it)

    def _render_matrix(self) -> None:
        rows = self._filtered()
        hosts = sorted({hn for hn, _ in rows})
        rule_ids = sorted({r.rule_id for _, r in rows}, key=_sort_key)
        names = {r.rule_id: r.name for _, r in rows}
        cell: dict[tuple[str, str], Status] = {(hn, r.rule_id): r.status for hn, r in rows}
        self.table.setColumnCount(2 + len(hosts))
        self.table.setHorizontalHeaderLabels(["항목코드", "점검항목", *hosts])
        self.table.setRowCount(len(rule_ids))
        for i, rid in enumerate(rule_ids):
            self.table.setItem(i, 0, QTableWidgetItem(rid))
            self.table.setItem(i, 1, QTableWidgetItem(names.get(rid, "")))
            for j, hn in enumerate(hosts):
                st = cell.get((hn, rid))
                it = QTableWidgetItem(DISPLAY_KO[st][:2] if st else "")
                if st:
                    it.setBackground(QColor(STATUS_BG[st]))
                    it.setForeground(QColor("#1a1a1a"))
                    it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                self.table.setItem(i, 2 + j, it)

    def _toggle_matrix(self, on: bool) -> None:
        self._matrix = on
        self._apply()

    def _show_detail(self) -> None:
        if self._matrix or not self.table.selectedItems():
            return
        data = self.table.selectedItems()[0].data(Qt.ItemDataRole.UserRole)
        if not data:
            return
        hn, rid = data
        for h2, r in self._flat:
            if h2 == hn and r.rule_id == rid:
                self.detail.setPlainText(
                    f"[{r.rule_id}] {r.name}  ({hn})\n"
                    f"판정: {DISPLAY_KO[r.status]}  (출처: "
                    f"{'분석자' if r.verdict_source == 'analyst' else '스크립트'})\n"
                    f"사유: {r.reason}\n"
                    f"근거:\n{r.evidence or '-'}\n"
                    f"원본추적: {r.source.artifact or '-'} "
                    f"line {r.source.line or '-'} / profile {r.source.profile or '-'}"
                    + (f"\n경고: {'; '.join(r.warnings)}" if r.warnings else "")
                )
                return
