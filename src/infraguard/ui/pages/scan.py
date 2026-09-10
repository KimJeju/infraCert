"""진단 실행 페이지 — 대상 · 실행 설정 · 진행 뷰(§5)."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from infraguard.assets.models import Host
from infraguard.core.models import HostResult
from infraguard.core.status import Status

PROG_COLS = ["호스트", "단계", "진행", "경과", "결과", "오류"]


class ScanPage(QWidget):
    start_requested = Signal(int, int)   # concurrency, timeout
    cancel_requested = Signal()

    def __init__(self) -> None:
        super().__init__()
        self._rows: dict[str, int] = {}
        root = QVBoxLayout(self)

        top = QHBoxLayout()

        left = QVBoxLayout()
        left.addWidget(QLabel("1. 대상"))
        self.targets = QListWidget()
        self.targets.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        left.addWidget(self.targets)
        self.count = QLabel("선택 0")
        self.count.setObjectName("muted")
        left.addWidget(self.count)
        top.addLayout(left, 2)

        right = QVBoxLayout()
        right.addWidget(QLabel("2. 프로파일"))
        self.profile = QComboBox()
        right.addWidget(self.profile)
        self.profile_info = QLabel("")
        self.profile_info.setObjectName("muted")
        self.profile_info.setWordWrap(True)
        right.addWidget(self.profile_info)
        right.addWidget(QLabel("3. 실행 설정"))
        crow = QHBoxLayout()
        crow.addWidget(QLabel("동시 실행"))
        self.concurrency = QSpinBox()
        self.concurrency.setRange(1, 20)
        self.concurrency.setValue(5)
        crow.addWidget(self.concurrency)
        right.addLayout(crow)
        trow = QHBoxLayout()
        trow.addWidget(QLabel("타임아웃(초)"))
        self.timeout = QSpinBox()
        self.timeout.setRange(30, 86400)
        self.timeout.setValue(1800)
        trow.addWidget(self.timeout)
        right.addLayout(trow)
        self.preflight = QCheckBox("실행 전 환경점검")
        self.preflight.setChecked(True)
        right.addWidget(self.preflight)
        right.addStretch(1)
        self.start = QPushButton("진단 시작")
        self.start.setObjectName("primary")
        self.start.clicked.connect(
            lambda: self.start_requested.emit(self.concurrency.value(), self.timeout.value())
        )
        right.addWidget(self.start)
        top.addLayout(right, 1)

        root.addLayout(top)

        root.addWidget(QLabel("진행"))
        self.table = QTableWidget(0, len(PROG_COLS))
        self.table.setHorizontalHeaderLabels(PROG_COLS)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        root.addWidget(self.table)

        brow = QHBoxLayout()
        brow.addStretch(1)
        self.cancel = QPushButton("중단")
        self.cancel.setObjectName("danger")
        self.cancel.setEnabled(False)
        self.cancel.clicked.connect(self.cancel_requested)
        brow.addWidget(self.cancel)
        root.addLayout(brow)

    def set_profiles(self, items: list[tuple[str, str, str]]) -> None:
        """items: (id, 표시명, 설명)."""
        cur = self.profile.currentData()
        self.profile.blockSignals(True)
        self.profile.clear()
        for pid, name, desc in items:
            self.profile.addItem(name, pid)
            self.profile.setItemData(self.profile.count() - 1, desc, Qt.ItemDataRole.ToolTipRole)
        i = self.profile.findData(cur)
        self.profile.setCurrentIndex(i if i >= 0 else 0)
        self.profile.blockSignals(False)
        self._on_profile()
        self.profile.currentIndexChanged.connect(self._on_profile)

    def _on_profile(self) -> None:
        self.profile_info.setText(self.profile.currentData(Qt.ItemDataRole.ToolTipRole) or "")

    def current_profile(self) -> str | None:
        return self.profile.currentData()

    def set_targets(self, hosts: list[Host]) -> None:
        self.targets.clear()
        for h in hosts:
            it = QListWidgetItem(f"☑ {h.label}   {h.address}  [{h.platform}]")
            it.setData(Qt.ItemDataRole.UserRole, h.host_id)
            self.targets.addItem(it)
        self.count.setText(f"선택 {len(hosts)}")

    def begin(self, hosts: list[Host]) -> None:
        self.table.setRowCount(0)
        self._rows.clear()
        for h in hosts:
            r = self.table.rowCount()
            self.table.insertRow(r)
            self._rows[h.host_id] = r
            self.table.setItem(r, 0, QTableWidgetItem(h.label))
            self.table.setItem(r, 1, QTableWidgetItem("대기"))
            bar = QProgressBar()
            bar.setValue(0)
            self.table.setCellWidget(r, 2, bar)
            for c in (3, 4, 5):
                self.table.setItem(r, c, QTableWidgetItem(""))
        self.start.setEnabled(False)
        self.cancel.setEnabled(True)

    def on_stage(self, host_id: str, stage: str) -> None:
        r = self._rows.get(host_id)
        if r is not None:
            self.table.setItem(r, 1, QTableWidgetItem(stage))

    def on_progress(self, host_id: str, done: int, total: int) -> None:
        r = self._rows.get(host_id)
        if r is not None:
            bar = self.table.cellWidget(r, 2)
            if bar:
                bar.setValue(int(done / total * 100) if total else 0)

    def on_result(self, host_id: str, host: HostResult) -> None:
        r = self._rows.get(host_id)
        if r is None:
            return
        bar = self.table.cellWidget(r, 2)
        if bar:
            bar.setValue(100)
        summ = host.summary()
        res = f"{summ[Status.PASS]}/{summ[Status.FAIL]}/{summ[Status.UNKNOWN]}"
        self.table.setItem(r, 1, QTableWidgetItem("완료" if not host.error else "오류"))
        self.table.setItem(r, 4, QTableWidgetItem(res))
        self.table.setItem(r, 5, QTableWidgetItem(host.error or ""))
        if host.cleanup_ok is False:
            self.table.setItem(r, 5, QTableWidgetItem("⚠ 정리 미완료: " + "; ".join(host.cleanup_leftovers)))

    def finished(self) -> None:
        self.start.setEnabled(True)
        self.cancel.setEnabled(False)
