"""결과(Findings) — 3-pane 분석 화면: FINDINGS 목록 · FINDING DETAIL · EVIDENCE.

한 취약점에서 판정 → Expected/Actual → 위험도 → 조치 방법 → 근거(명령·출력·판정식) → [파일][터미널][룰][재진단] 이 끊기지 않는다.
상태는 색 + 아이콘 + 텍스트로 표시한다.
"""

from __future__ import annotations

import re

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from infraguard.assets.exceptions import RiskException
from infraguard.core.models import CheckResult, ScanResult
from infraguard.core.status import DISPLAY_KO, Status
from infraguard.result import diff as _diff
from infraguard.result import risk as _risk
from infraguard.result.engine import _sort_key
from infraguard.ui.theme import STATUS_BG, STATUS_ICON, STATUS_TEXT, status_label

COLS = ["결과", "항목코드", "호스트", "점검항목", "위험도", "변화"]
_C_STATUS, _C_ID, _C_HOST, _C_NAME, _C_RISK, _C_DIFF = range(6)
CHANGED_FG = "#F0883E"   # 전회와 달라진 결과
_PATH_RE = re.compile(r"(?<![\w.])(/(?:etc|var|opt|usr|home|root|boot|srv|tmp|u0\d|oracle|app)(?:/[\w.@+-]+)+)")
_VERDICT_EN = {Status.PASS: "GOOD", Status.FAIL: "VULNERABLE", Status.UNKNOWN: "MANUAL", Status.SKIPPED: "N/A",
               Status.ERROR: "ERROR"}


def evidence_paths(text: str) -> list[str]:
    """근거 텍스트에서 원격 절대경로 후보(중복 제거, 등장 순)."""
    out: list[str] = []
    for m in _PATH_RE.finditer(text):
        p = m.group(1).rstrip(".,:;)")
        if p not in out:
            out.append(p)
    return out[:12]


def _esc(s: object) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


class ResultPage(QWidget):
    export_requested = Signal(str)  # "xlsx" | "html"
    exception_requested = Signal(str, str, str)   # host_id, rule_id, label — 예외 승인/수정 다이얼로그
    exception_cleared = Signal(str, str)          # host_id, rule_id
    open_terminal = Signal(str)                   # host_id — 취약 항목에서 바로 SSH
    open_file = Signal(str, str)                  # host_id, remote path — SFTP 로 근거 파일
    open_rule = Signal(str)                       # rule_id — 룰팩 화면 해당 룰(테스터)
    rescan_host = Signal(str)                     # host_id — 이 호스트만 다시 진단(Re-test)
    manual_requested = Signal()                   # 수동확인 워크벤치로

    def __init__(self) -> None:
        super().__init__()
        self._scan: ScanResult | None = None
        self._flat: list[tuple[str, CheckResult]] = []
        self._matrix = False
        self._base: dict[tuple[str, str], Status] = {}   # (hostname, rule_id) → 전회 결과
        self._base_id: str | None = None
        self._base_scan: ScanResult | None = None
        self._diff: dict[tuple[str, str], tuple[Status | None, str | None]] = {}
        self._host_ids: dict[str, str] = {}            # hostname → host_id
        self._crit: dict[str, str] = {}                # hostname → 자산 중요도(스냅샷)
        self._exc: dict[tuple[str, str], RiskException] = {}   # (host_id, rule_id) → 예외
        self._guide: dict[str, dict] = {}              # rule id → 가이드(점검 목적·조치)
        self._remediation: dict[str, str] = {}         # rule id → 조치방법
        self._rule_shas: dict[str, str] = {}           # 현재 룰팩 rule id → SHA (진단 당시와 다르면 '룰 변경')
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(8)

        head = QHBoxLayout()
        t = QLabel("결과")
        t.setObjectName("h1")
        head.addWidget(t)
        self.scan_label = QLabel("")
        self.scan_label.setObjectName("muted")
        head.addWidget(self.scan_label)
        head.addStretch(1)
        self.manual_btn = QPushButton("수동확인 워크벤치")
        self.manual_btn.clicked.connect(self.manual_requested)
        head.addWidget(self.manual_btn)
        self.exc_btn = QPushButton("예외 승인…")
        self.exc_btn.setToolTip("선택한 취약 항목에 예외/보상통제 승인(만료일 포함)을 단다. 판정은 바뀌지 않는다")
        self.exc_btn.clicked.connect(self._request_exception)
        head.addWidget(self.exc_btn)
        self.matrix_btn = QPushButton("매트릭스 뷰")
        self.matrix_btn.setCheckable(True)
        self.matrix_btn.toggled.connect(self._toggle_matrix)
        head.addWidget(self.matrix_btn)
        xlsx = QPushButton("XLSX")
        html = QPushButton("HTML")
        xlsx.clicked.connect(lambda: self.export_requested.emit("xlsx"))
        html.clicked.connect(lambda: self.export_requested.emit("html"))
        head.addWidget(xlsx)
        head.addWidget(html)
        root.addLayout(head)

        bar = QHBoxLayout()
        self.host_f = QComboBox()
        self.status_f = QComboBox()
        self.sev_f = QComboBox()
        self.host_f.addItem("호스트 전체", "")
        self.status_f.addItem("상태 전체", "")
        for s in Status:
            self.status_f.addItem(status_label(s), s.value)
        self.sev_f.addItem("중요도 전체", "")
        for s in ("상", "중", "하"):
            self.sev_f.addItem(s, s)
        self.risk_f = QComboBox()
        self.risk_f.addItem("위험도 전체", "")
        for k in _risk.LEVELS:
            self.risk_f.addItem(_risk.LABEL_KO[k], k)
        self.diff_f = QComboBox()
        self.diff_f.addItem("변화 전체", "")
        for k in _diff.ORDER:
            self.diff_f.addItem(_diff.LABEL_KO[k], k)
        self.diff_f.setEnabled(False)
        self.search = QLineEdit()
        self.search.setPlaceholderText("항목코드/이름 검색…")
        for w in (self.host_f, self.status_f, self.sev_f, self.risk_f, self.diff_f):
            w.currentIndexChanged.connect(self._apply)
        self.search.textChanged.connect(self._apply)
        for w in (self.host_f, self.status_f, self.sev_f, self.risk_f, self.diff_f):
            bar.addWidget(w)
        bar.addWidget(self.search, 1)
        self.changed_only = QCheckBox("변경만")
        self.changed_only.setToolTip("전회 진단(같은 호스트가 있는 직전 결과)과 결과가 달라진 항목만")
        self.changed_only.setEnabled(False)
        self.changed_only.toggled.connect(self._apply)
        bar.addWidget(self.changed_only)
        self.base_label = QLabel("")
        self.base_label.setObjectName("muted")
        bar.addWidget(self.base_label)
        root.addLayout(bar)

        # ---- 3-pane ----
        split = QSplitter(Qt.Orientation.Horizontal)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(4)
        lt = QLabel("FINDINGS")
        lt.setObjectName("sidebar-title")
        ll.addWidget(lt)
        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.horizontalHeader().setSectionResizeMode(_C_NAME, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.setColumnWidth(_C_STATUS, 86)
        self.table.setColumnWidth(_C_ID, 64)
        self.table.setColumnWidth(_C_HOST, 110)
        self.table.setColumnWidth(_C_RISK, 56)
        self.table.setColumnWidth(_C_DIFF, 70)
        self.table.verticalHeader().setVisible(False)
        self.table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._show_detail)
        ll.addWidget(self.table, 1)
        self.count_label = QLabel("")
        self.count_label.setObjectName("muted")
        ll.addWidget(self.count_label)
        split.addWidget(left)

        mid = QWidget()
        ml = QVBoxLayout(mid)
        ml.setContentsMargins(6, 0, 6, 0)
        ml.setSpacing(4)
        mt = QLabel("FINDING DETAIL")
        mt.setObjectName("sidebar-title")
        ml.addWidget(mt)
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        ml.addWidget(self.detail, 1)
        drow = QHBoxLayout()
        self.btn_file = QComboBox()
        self.btn_file.setToolTip("근거에 나온 원격 파일 경로 — 고르면 SFTP 로 연다(읽기 전용 보기)")
        self.btn_file.setMinimumWidth(170)
        self.btn_term = QPushButton("터미널")
        self.btn_rule = QPushButton("해당 룰")
        self.btn_rescan = QPushButton("재진단")
        self.btn_rescan.setToolTip("이 호스트만 같은 프로파일로 다시 진단(Re-test)")
        for b in (self.btn_term, self.btn_rule, self.btn_rescan):
            b.setEnabled(False)
        self.btn_file.setEnabled(False)
        self.btn_term.clicked.connect(self._link_terminal)
        self.btn_file.activated.connect(self._link_file)
        self.btn_rule.clicked.connect(self._link_rule)
        self.btn_rescan.clicked.connect(self._link_rescan)
        for w in (self.btn_file, self.btn_term, self.btn_rule, self.btn_rescan):
            drow.addWidget(w)
        drow.addStretch(1)
        ml.addLayout(drow)
        split.addWidget(mid)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(4)
        rt = QLabel("EVIDENCE")
        rt.setObjectName("sidebar-title")
        rl.addWidget(rt)
        self.evidence = QPlainTextEdit()
        self.evidence.setReadOnly(True)
        self.evidence.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.evidence.setStyleSheet("font-family: Consolas, 'Malgun Gothic', monospace;")
        rl.addWidget(self.evidence, 1)
        split.addWidget(right)
        split.setStretchFactor(0, 5)
        split.setStretchFactor(1, 3)
        split.setStretchFactor(2, 3)
        split.setSizes([560, 340, 340])
        root.addWidget(split, 1)

    # ---------------------------------------------------------------- 데이터 주입
    def set_baseline(self, prev: ScanResult | None) -> None:
        """전회 결과. load() 전에 부른다. 없으면 '변화' 컬럼은 비고 '변경만' 은 꺼진다."""
        self._base = {(h.hostname, r.rule_id): r.status for h in (prev.hosts if prev else []) for r in h.results}
        self._base_id = prev.scan_id if prev else None
        self._base_scan = prev
        self.changed_only.setEnabled(bool(self._base))
        self.diff_f.setEnabled(bool(self._base))
        if not self._base:
            self.changed_only.setChecked(False)
            self.diff_f.setCurrentIndex(0)
        self.base_label.setText(f"기준 {self._base_id}" if self._base_id else "")

    def changed(self, hn: str, r: CheckResult) -> bool:
        prev = self._base.get((hn, r.rule_id))
        return prev is not None and prev is not r.status

    def diff_summary(self) -> dict[str, int]:
        return _diff.summary(self._diff)

    def set_exceptions(self, exc: dict[tuple[str, str], RiskException]) -> None:
        self._exc = dict(exc)
        self._apply()

    def set_guide(self, guide: dict[str, dict]) -> None:
        self._guide = guide

    def set_remediation(self, rem: dict[str, str]) -> None:
        self._remediation = dict(rem)

    def set_rule_shas(self, shas: dict[str, str]) -> None:
        self._rule_shas = dict(shas)
        self._apply()

    def stale(self, r: CheckResult) -> bool:
        p = r.provenance or {}
        cur = self._rule_shas.get(r.rule_id)
        return bool(p.get("rule_sha256") and cur and p["rule_sha256"] != cur)

    def load(self, scan: ScanResult | None) -> None:
        self._scan = scan
        self._flat = []
        self._diff = _diff.diff(scan, self._base_scan) if scan else {}
        self._host_ids = {h.hostname: h.host_id for h in (scan.hosts if scan else [])}
        self._crit = {h.hostname: h.asset.get("criticality", "") for h in (scan.hosts if scan else [])}
        if scan:
            for h in scan.hosts:
                for r in h.results:
                    self._flat.append((h.hostname, r))
            # 취약 먼저, 그 다음 오류·수동 — 분석 순서대로
            order = {Status.FAIL: 0, Status.ERROR: 1, Status.UNKNOWN: 2, Status.PASS: 3, Status.SKIPPED: 4}
            self._flat.sort(key=lambda t: (order[t[1].status], t[0], _sort_key(t[1].rule_id)))
        self.scan_label.setText(f"{scan.scan_id} · 호스트 {len(scan.hosts)}대 · {scan.profile or ''}" if scan else "")
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

    def select_finding(self, hostname: str, rule_id: str) -> bool:
        for i in range(self.table.rowCount()):
            it = self.table.item(i, 0)
            if it and it.data(Qt.ItemDataRole.UserRole) == (hostname, rule_id):
                self.table.selectRow(i)
                return True
        return False

    # ---------------------------------------------------------------- 선택·링크
    def _selected(self) -> tuple[str, str, CheckResult] | None:
        if self._matrix or not self.table.selectedItems():
            return None
        data = self.table.selectedItems()[0].data(Qt.ItemDataRole.UserRole)
        if not data:
            return None
        hn, rid = data
        for h2, r in self._flat:
            if h2 == hn and r.rule_id == rid:
                return hn, rid, r
        return None

    def _request_exception(self) -> None:
        sel = self._selected()
        if sel is None:
            return
        hn, rid, r = sel
        self.exception_requested.emit(self._host_ids.get(hn, ""), rid, f"{hn} · {rid} {r.name}")

    def _exc_of(self, hn: str, rid: str) -> RiskException | None:
        return self._exc.get((self._host_ids.get(hn, ""), rid))

    def _link_terminal(self) -> None:
        sel = self._selected()
        if sel:
            self.open_terminal.emit(self._host_ids.get(sel[0], ""))

    def _link_rule(self) -> None:
        sel = self._selected()
        if sel:
            self.open_rule.emit(sel[1])

    def _link_rescan(self) -> None:
        sel = self._selected()
        if sel:
            self.rescan_host.emit(self._host_ids.get(sel[0], ""))

    def _link_file(self, _i: int) -> None:
        sel = self._selected()
        path = self.btn_file.currentData()
        if sel and path:
            self.open_file.emit(self._host_ids.get(sel[0], ""), path)

    # ---------------------------------------------------------------- 목록
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
            if self.changed_only.isChecked() and not self.changed(hn, r):
                continue
            df = self.diff_f.currentData()
            if df and self._diff.get((hn, r.rule_id), (None, None))[1] != df:
                continue
            rf = self.risk_f.currentData()
            if rf and (r.status is not Status.FAIL or _risk.level(r.severity, self._crit.get(hn)) != rf):
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
            cls = self._diff.get((hn, r.rule_id), (None, None))[1]
            lvl = _risk.level(r.severity, self._crit.get(hn)) if r.status is Status.FAIL else None
            vals = [status_label(r.status), r.rule_id, hn, r.name + ("  ⚠ 룰 변경" if self.stale(r) else ""),
                    _risk.LABEL_KO[lvl] if lvl else "", _diff.LABEL_KO[cls] if cls else ""]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == _C_STATUS:
                    it.setBackground(QColor(STATUS_BG[r.status]))
                    it.setForeground(QColor(STATUS_TEXT[r.status]))
                if c == _C_RISK and lvl:
                    it.setForeground(QColor(_risk.COLOR[lvl]))
                    it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if c == _C_DIFF and cls:
                    it.setForeground(QColor(_diff.COLOR[cls]))
                    it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                it.setData(Qt.ItemDataRole.UserRole, (hn, r.rule_id))
                self.table.setItem(i, c, it)
        n_fail = sum(1 for _, r in rows if r.status is Status.FAIL)
        self.count_label.setText(f"{len(rows)}건 표시 · 취약 {n_fail}")
        if rows:
            self.table.selectRow(0)
        else:
            self.detail.clear()
            self.evidence.clear()

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
                it = QTableWidgetItem(STATUS_ICON[st] if st else "")
                if st:
                    it.setBackground(QColor(STATUS_BG[st]))
                    it.setForeground(QColor(STATUS_TEXT[st]))
                    it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                    it.setToolTip(DISPLAY_KO[st])
                self.table.setItem(i, 2 + j, it)

    def _toggle_matrix(self, on: bool) -> None:
        self._matrix = on
        self._apply()

    # ---------------------------------------------------------------- 상세·근거
    def _show_detail(self) -> None:
        sel = self._selected()
        if sel is None:
            return
        hn, rid, r = sel
        self.btn_term.setEnabled(True)
        self.btn_rule.setEnabled(True)
        self.btn_rescan.setEnabled(True)
        self.btn_file.clear()
        paths = evidence_paths(r.evidence or "")
        self.btn_file.addItem("파일 열기…" if paths else "근거에 파일 경로 없음", None)
        for p in paths:
            self.btn_file.addItem(p, p)
        self.btn_file.setEnabled(bool(paths))
        self.detail.setHtml(self._detail_html(hn, rid, r))
        self.evidence.setPlainText(self._evidence_text(r))

    def _detail_html(self, hn: str, rid: str, r: CheckResult) -> str:
        color = STATUS_TEXT[r.status]
        p = r.provenance or {}
        ext = p.get("extracted") or {}
        exp_act = ""
        if r.expected is not None or r.value is not None:
            exp_act = f"<tr><td class=k>Expected</td><td>{_esc(r.expected)}</td></tr><tr><td class=k>Actual</td><td>{_esc(r.value)}</td></tr>"
        elif p.get("matched"):
            exp_act = f"<tr><td class=k>판정식</td><td><code>{_esc(p['matched'])}</code></td></tr>"
            if ext:
                exp_act += "<tr><td class=k>Actual</td><td>" + ", ".join(f"{_esc(k)} = <b>{_esc(v)}</b>" for k, v in ext.items()) + "</td></tr>"
        lvl = _risk.level(r.severity, self._crit.get(hn)) if r.status is Status.FAIL else None
        ex = self._exc_of(hn, rid)
        prev = self._base.get((hn, rid))
        cls = self._diff.get((hn, rid), (None, None))[1]
        g = self._guide.get(rid, {})
        rem = self._remediation.get(rid) or g.get("remediation") or ""
        j = g.get("judgment") or {}
        parts = [
            "<style>td.k{color:#7D8794;padding-right:14px;vertical-align:top} table{border-collapse:collapse} td{padding:2px 0}"
            " h3{margin:10px 0 4px 0;font-size:12px;color:#7D8794;letter-spacing:1px} code{color:#D7DDE6}</style>",
            f"<div style='font-size:15px;font-weight:700;color:{color}'>{STATUS_ICON[r.status]} {_VERDICT_EN[r.status]}"
            f"<span style='color:#7D8794;font-size:11px;font-weight:400'> &nbsp; {'분석자 판정' if r.verdict_source == 'analyst' else '스크립트 판정'}</span></div>",
            f"<div style='font-size:14px;font-weight:600;margin:4px 0 8px 0'>{_esc(rid)}. {_esc(r.name)}</div>",
            "<table>",
            f"<tr><td class=k>호스트</td><td>{_esc(hn)}</td></tr>",
            f"<tr><td class=k>판정</td><td style='color:{color}'>{_esc(DISPLAY_KO[r.status])} — {_esc(r.reason)}</td></tr>",
            exp_act,
            f"<tr><td class=k>가이드 중요도</td><td>{_esc(r.severity.value if r.severity else '-')}</td></tr>",
        ]
        if lvl:
            parts.append(f"<tr><td class=k>위험도</td><td style='color:{_risk.COLOR[lvl]};font-weight:600'>{_risk.LABEL_KO[lvl]}"
                         f"</td></tr><tr><td class=k>자산 중요도</td><td>{_esc(self._crit.get(hn) or '-')}</td></tr>")
        if prev is not None:
            parts.append(f"<tr><td class=k>전회({_esc(self._base_id)})</td><td>{status_label(prev)}"
                         + (f" → <span style='color:{_diff.COLOR[cls]}'>{_diff.LABEL_KO[cls]}</span>" if cls else
                            (" → 변경됨" if self.changed(hn, r) else " (동일)")) + "</td></tr>")
        if ex:
            parts.append(f"<tr><td class=k>예외</td><td>{_esc(ex.label())} · 승인자 {_esc(ex.approver or '-')} · 만료 {_esc(ex.expires_at or '-')}"
                         f"<br>{_esc(ex.reason)}" + (f"<br>보상통제: {_esc(ex.control)}" if ex.control else "") + "</td></tr>")
        parts.append("</table>")
        if self.stale(r):
            parts.append("<div style='color:#D29922;margin-top:6px'>⚠ 룰 변경됨 — 진단 이후 이 룰의 판정 조건이 바뀌었습니다. 재진단 권장</div>")
        if r.warnings:
            parts.append(f"<div style='color:#D29922;margin-top:4px'>경고: {_esc('; '.join(r.warnings))}</div>")
        if g.get("purpose"):
            parts.append(f"<h3>점검 목적</h3><div>{_esc(g['purpose'])}</div>")
        if j:
            parts.append(f"<h3>판단 기준</h3><div>양호: {_esc(j.get('good', ''))}<br>취약: {_esc(j.get('vuln', ''))}</div>")
        if rem:
            parts.append(f"<h3>조치 방법</h3><div>{_esc(rem)}</div>")
        if g.get("impact"):
            parts.append(f"<div style='color:#7D8794'>조치 시 영향: {_esc(g['impact'])}</div>")
        return "".join(parts)

    def _evidence_text(self, r: CheckResult) -> str:
        p = r.provenance or {}
        out: list[str] = []
        cmds = p.get("commands") or []
        if cmds:
            out.append("Command")
            out.append("─" * 40)
            for c in cmds:
                argv = c.get("argv") or []
                out.append(f"$ {argv[-1] if argv else ''}")
                out.append(f"   rc={c.get('exit_code')}  sha={str(c.get('stdout_sha256', ''))[:12]}  {c.get('duration_ms', 0)}ms"
                           + (f"  ERROR={c['error']}" if c.get("error") else ""))
            out.append("")
        out.append("Output")
        out.append("─" * 40)
        out.append(r.evidence or "(근거 없음)")
        out.append("")
        if p.get("extracted") or p.get("matched"):
            out.append("Evaluation")
            out.append("─" * 40)
            for k, v in (p.get("extracted") or {}).items():
                out.append(f"{k} = {v!r}")
            if p.get("matched"):
                out.append(f"→ {p['matched']}")
            out.append("")
        meta = [f"transport={p.get('transport')}" if p.get("transport") else "",
                f"impl={p.get('impl')}" if p.get("impl") else "",
                f"rule_sha={str(p.get('rule_sha256', ''))[:12]}" if p.get("rule_sha256") else "",
                f"artifact={r.source.artifact}" if r.source.artifact else "",
                f"line={r.source.line}" if r.source.line else ""]
        out.append("  ".join(m for m in meta if m))
        return "\n".join(out)
