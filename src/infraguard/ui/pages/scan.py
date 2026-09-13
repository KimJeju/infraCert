"""진단 화면 — 3-step(① 대상 ② 프로파일 ③ 실행 설정) → 시작하면 진행 화면으로 전환.

사용자가 가장 궁금한 것은 "지금 뭐 하고 있지?" — 진행 화면은 전체 %, 완료/진행/대기 수, 호스트별 상태, 현재 작업(호스트/룰)을 크게.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from infraguard.assets.models import Host
from infraguard.core.models import HostResult
from infraguard.core.status import Status
from infraguard.ui.theme import STATUS_ICON

TARGET_COLS = ["호스트", "플랫폼", "환경", "중요도", "주소"]
PROG_COLS = ["HOST", "PROFILE", "진행률", "상태", "VULN", "비고"]
AUTO = "__auto__"


def _card(title: str) -> tuple[QWidget, QVBoxLayout]:
    w = QWidget()
    w.setObjectName("card")
    lay = QVBoxLayout(w)
    lay.setContentsMargins(14, 10, 14, 12)
    lay.setSpacing(8)
    t = QLabel(title)
    t.setObjectName("h2")
    lay.addWidget(t)
    return w, lay


class ScanPage(QWidget):
    start_requested = Signal(int, int)   # concurrency, timeout
    cancel_requested = Signal()
    retry_requested = Signal()           # 실패·미완료 호스트만 같은 scan 으로 다시
    dryrun_requested = Signal()          # 실행 계획(어떤 명령이 나가는지) 정적 열거
    add_targets_requested = Signal()     # 자산에서 대상 추가
    view_results_requested = Signal()    # 진행 화면 [결과 보기]
    profile_changed = Signal(str)        # 프로파일 카드 갱신용
    rule_detail_requested = Signal(str)  # [룰 상세 보기] → 룰팩 화면

    def __init__(self) -> None:
        super().__init__()
        self._rows: dict[str, int] = {}
        self._state: dict[str, str] = {}     # host_id → pending | running | done | error
        self._hosts: list[Host] = []
        self._profile_of: dict[str, str] = {}  # host_id → 이번 진단에 쓴 프로파일 id
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.stack = QStackedWidget()
        outer.addWidget(self.stack, 1)
        self.stack.addWidget(self._build_setup())
        self.stack.addWidget(self._build_progress())
        self.stack.setCurrentIndex(0)

    # ---------------------------------------------------------------- 설정(3-step)
    def _build_setup(self) -> QWidget:
        page = QWidget()
        root = QVBoxLayout(page)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(12)
        head = QHBoxLayout()
        t = QLabel("진단")
        t.setObjectName("h1")
        head.addWidget(t)
        head.addStretch(1)
        root.addLayout(head)

        row = QHBoxLayout()
        row.setSpacing(12)
        # ① 대상
        c1, l1 = _card("① 대상")
        self.count = QLabel("선택된 자산 0대")
        self.count.setObjectName("muted")
        hb = QHBoxLayout()
        hb.addWidget(self.count, 1)
        add = QPushButton("자산에서 추가…")
        add.clicked.connect(self.add_targets_requested)
        rm = QPushButton("선택 제거")
        rm.clicked.connect(self._remove_selected)
        hb.addWidget(add)
        hb.addWidget(rm)
        l1.addLayout(hb)
        self.targets = QTableWidget(0, len(TARGET_COLS))
        self.targets.setHorizontalHeaderLabels(TARGET_COLS)
        self.targets.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.targets.horizontalHeader().setStretchLastSection(True)
        self.targets.verticalHeader().setVisible(False)
        self.targets.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.targets.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        l1.addWidget(self.targets, 1)
        row.addWidget(c1, 5)

        # ② 프로파일
        c2, l2 = _card("② 진단 프로파일")
        self.profile = QComboBox()
        l2.addWidget(self.profile)
        self.profile_card = QLabel("")
        self.profile_card.setWordWrap(True)
        self.profile_card.setTextFormat(Qt.TextFormat.RichText)
        l2.addWidget(self.profile_card)
        self.detect = QLabel("")
        self.detect.setObjectName("muted")
        self.detect.setWordWrap(True)
        l2.addWidget(self.detect)
        l2.addStretch(1)
        self.rule_detail = QPushButton("룰 상세 보기")
        self.rule_detail.clicked.connect(lambda: self.rule_detail_requested.emit(self.current_profile() or ""))
        l2.addWidget(self.rule_detail)
        row.addWidget(c2, 3)

        # ③ 실행 설정
        c3, l3 = _card("③ 실행 설정")
        form = QFormLayout()
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(6)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.FieldsStayAtSizeHint)
        self.concurrency = QSpinBox()
        self.concurrency.setRange(1, 20)
        self.concurrency.setValue(5)
        self.concurrency.setFixedWidth(100)
        self.timeout = QSpinBox()
        self.timeout.setRange(30, 86400)
        self.timeout.setValue(1800)
        self.timeout.setFixedWidth(100)
        form.addRow("동시 실행", self.concurrency)
        form.addRow("타임아웃(초)", self.timeout)
        l3.addLayout(form)
        self.preflight = QCheckBox("연결 사전검증")
        self.preflight.setToolTip("probe 직후 sqlplus 유무·권한(sudo -n)·/tmp 여유·시간 편차를 확인해 진행 표에 표시한다(진단은 계속)")
        self.preflight.setChecked(True)
        self.auto_retry = QCheckBox("실패한 호스트 자동 재시도 (1회)")
        self.auto_open = QCheckBox("완료 후 결과 자동 열기")
        self.auto_open.setChecked(True)
        for cb in (self.preflight, self.auto_retry, self.auto_open):
            l3.addWidget(cb)
        self.summary = QLabel("")
        self.summary.setObjectName("muted")
        self.summary.setTextFormat(Qt.TextFormat.RichText)
        self.summary.setWordWrap(True)
        l3.addWidget(self.summary)
        l3.addStretch(1)
        self.dryrun = QPushButton("실행 계획 확인")
        self.dryrun.setToolTip("원격에 붙지 않고 이 프로파일이 실행할 명령·번들·예상 잔류물을 나열한다")
        self.dryrun.clicked.connect(self.dryrun_requested)
        l3.addWidget(self.dryrun)
        self.start = QPushButton("▶  진단 시작")
        self.start.setObjectName("primary")
        self.start.setMinimumHeight(34)
        self.start.clicked.connect(
            lambda: self.start_requested.emit(self.concurrency.value(), self.timeout.value())
        )
        l3.addWidget(self.start)
        row.addWidget(c3, 3)
        root.addLayout(row, 1)
        return page

    # ---------------------------------------------------------------- 진행
    def _build_progress(self) -> QWidget:
        page = QWidget()
        root = QVBoxLayout(page)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(10)
        head = QHBoxLayout()
        self.prog_title = QLabel("진단 진행 중")
        self.prog_title.setObjectName("h1")
        head.addWidget(self.prog_title)
        self.prog_pct = QLabel("0%")
        self.prog_pct.setObjectName("h1")
        head.addWidget(self.prog_pct)
        head.addStretch(1)
        self.cancel = QPushButton("중단")
        self.cancel.setObjectName("danger")
        self.cancel.clicked.connect(self.cancel_requested)
        head.addWidget(self.cancel)
        root.addLayout(head)
        self.prog_bar = QProgressBar()
        self.prog_bar.setTextVisible(False)
        self.prog_bar.setFixedHeight(8)
        root.addWidget(self.prog_bar)
        self.prog_sub = QLabel("")
        self.prog_sub.setObjectName("muted")
        root.addWidget(self.prog_sub)
        self.table = QTableWidget(0, len(PROG_COLS))
        self.table.setHorizontalHeaderLabels(PROG_COLS)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(0, 180)
        self.table.setColumnWidth(1, 140)
        self.table.setColumnWidth(3, 90)
        self.table.setColumnWidth(4, 60)
        self.table.setHorizontalScrollMode(QTableWidget.ScrollMode.ScrollPerPixel)
        self.table.verticalHeader().setVisible(False)
        root.addWidget(self.table, 1)
        cur = QWidget()
        cur.setObjectName("card")
        cl = QVBoxLayout(cur)
        cl.setContentsMargins(14, 8, 14, 8)
        cl.addWidget(QLabel("현재 작업"))
        self.current = QLabel("-")
        self.current.setStyleSheet("font-size:14px;font-weight:600")
        cl.addWidget(self.current)
        root.addWidget(cur)
        brow = QHBoxLayout()
        self.results_btn = QPushButton("결과 보기")
        self.results_btn.setObjectName("primary")
        self.results_btn.clicked.connect(self.view_results_requested)
        self.retry = QPushButton("실패·미완료 재진단")
        self.retry.setToolTip("오류가 났거나 중단으로 못 돈 호스트만 같은 진단 ID 로 다시 돌린다(완료된 호스트 결과는 유지)")
        self.retry.clicked.connect(self.retry_requested)
        self.new_btn = QPushButton("새 진단")
        self.new_btn.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        for b in (self.results_btn, self.retry, self.new_btn):
            b.setEnabled(False)
            brow.addWidget(b)
        brow.addStretch(1)
        root.addLayout(brow)
        return page

    # ---------------------------------------------------------------- 프로파일
    def set_profiles(self, items: list[tuple[str, str, str]]) -> None:
        """items: (id, 표시명, 설명). 맨 앞에 Auto Detect."""
        cur = self.profile.currentData()
        self.profile.blockSignals(True)
        self.profile.clear()
        self.profile.addItem("Auto Detect — 대상 플랫폼/Discovery 로 추천", AUTO)
        for pid, name, desc in items:
            self.profile.addItem(name, pid)
            self.profile.setItemData(self.profile.count() - 1, desc, Qt.ItemDataRole.ToolTipRole)
        i = self.profile.findData(cur) if cur else -1
        self.profile.setCurrentIndex(i if i >= 0 else 0)
        self.profile.blockSignals(False)
        if not getattr(self, "_profile_wired", False):
            self.profile.currentIndexChanged.connect(self._on_profile)
            self._profile_wired = True
        self._on_profile()

    def _on_profile(self) -> None:
        self.profile_changed.emit(self.current_profile() or "")

    def current_profile(self) -> str | None:
        return self.profile.currentData()

    def is_auto(self) -> bool:
        return self.profile.currentData() == AUTO

    def set_profile_card(self, html: str, detect: str = "") -> None:
        self.profile_card.setText(html)
        self.detect.setText(detect)

    def set_summary(self, html: str) -> None:
        self.summary.setText(html)

    # ---------------------------------------------------------------- 대상
    def set_targets(self, hosts: list[Host]) -> None:
        self._hosts = list(hosts)
        self.targets.setRowCount(len(hosts))
        for i, h in enumerate(hosts):
            for c, v in enumerate((f"{STATUS_ICON[Status.PASS]} {h.label}", h.platform, h.environment or "-",
                                   h.criticality or "-", f"{h.address}:{h.port}")):
                it = QTableWidgetItem(v)
                it.setData(Qt.ItemDataRole.UserRole, h.host_id)
                self.targets.setItem(i, c, it)
        self.count.setText(f"선택된 자산 {len(hosts)}대")
        self.profile_changed.emit(self.current_profile() or "")

    def target_hosts(self) -> list[Host]:
        return list(self._hosts)

    def _remove_selected(self) -> None:
        rows = sorted({i.row() for i in self.targets.selectedIndexes()}, reverse=True)
        keep = [h for i, h in enumerate(self._hosts) if i not in rows]
        self.set_targets(keep)

    # ---------------------------------------------------------------- 진행
    def begin(self, hosts: list[Host], profiles: dict[str, str] | None = None) -> None:
        self.stack.setCurrentIndex(1)
        self.table.setRowCount(0)
        self._rows.clear()
        self._state = {h.host_id: "pending" for h in hosts}
        self._profile_of = dict(profiles or {})
        for b in (self.results_btn, self.retry, self.new_btn):
            b.setEnabled(False)
        self.cancel.setEnabled(True)
        self.prog_title.setText("진단 진행 중")
        for h in hosts:
            r = self.table.rowCount()
            self.table.insertRow(r)
            self._rows[h.host_id] = r
            self.table.setItem(r, 0, QTableWidgetItem(h.label))
            self.table.setItem(r, 1, QTableWidgetItem(self._profile_of.get(h.host_id, "")))
            bar = QProgressBar()
            bar.setValue(0)
            self.table.setCellWidget(r, 2, bar)
            self.table.setItem(r, 3, QTableWidgetItem("대기"))
            for c in (4, 5):
                self.table.setItem(r, c, QTableWidgetItem(""))
        self.current.setText("연결 준비 중…")
        self._refresh_header()

    def _refresh_header(self) -> None:
        total = len(self._state)
        done = sum(1 for s in self._state.values() if s in ("done", "error"))
        running = sum(1 for s in self._state.values() if s == "running")
        pending = total - done - running
        pcts = []
        for r in self._rows.values():
            bar = self.table.cellWidget(r, 2)
            pcts.append(bar.value() if bar else 0)
        pct = int(sum(pcts) / len(pcts)) if pcts else 0
        self.prog_pct.setText(f"{pct}%")
        self.prog_bar.setValue(pct)
        self.prog_sub.setText(f"전체 {total}대 · 완료 {done} · 진행 {running} · 대기 {pending}")

    def on_stage(self, host_id: str, stage: str) -> None:
        r = self._rows.get(host_id)
        if r is None:
            return
        if self._state.get(host_id) == "pending":
            self._state[host_id] = "running"
        self.table.setItem(r, 3, QTableWidgetItem("진단중"))
        label = self.table.item(r, 0).text()
        self.current.setText(f"{label}  /  {stage}")
        self._refresh_header()

    def on_progress(self, host_id: str, done: int, total: int) -> None:
        r = self._rows.get(host_id)
        if r is not None:
            bar = self.table.cellWidget(r, 2)
            if bar:
                bar.setValue(int(done / total * 100) if total else 0)
        self._refresh_header()

    def on_result(self, host_id: str, host: HostResult) -> None:
        r = self._rows.get(host_id)
        if r is None:
            return
        bar = self.table.cellWidget(r, 2)
        if bar:
            bar.setValue(100)
        summ = host.summary()
        ok = not host.error
        self._state[host_id] = "done" if ok else "error"
        st = QTableWidgetItem(f"{STATUS_ICON[Status.PASS]} 완료" if ok else f"{STATUS_ICON[Status.ERROR]} 오류")
        st.setForeground(QColor("#3FB950" if ok else "#F85149"))
        self.table.setItem(r, 3, st)
        v = QTableWidgetItem(str(summ[Status.FAIL]) if ok else "-")
        if ok and summ[Status.FAIL]:
            v.setForeground(QColor("#F85149"))
        self.table.setItem(r, 4, v)
        note = host.error or (("⚠ 사전검증: " + "; ".join(host.preflight)) if host.preflight else "")
        if host.cleanup_ok is False:
            note = "⚠ 정리 미완료: " + "; ".join(host.cleanup_leftovers)
        self.table.setItem(r, 5, QTableWidgetItem(note))
        self._refresh_header()

    def pending_or_failed(self) -> list[str]:
        """이번 진단에서 완료되지 못한 호스트(중단으로 못 돈 것 + 오류)."""
        return [hid for hid, st in self._state.items() if st != "done"]

    def finished(self) -> None:
        self.cancel.setEnabled(False)
        self.prog_title.setText("진단 완료")
        self.current.setText("완료")
        for b in (self.results_btn, self.new_btn):
            b.setEnabled(True)
        self.retry.setEnabled(bool(self.pending_or_failed()))
        self._refresh_header()
