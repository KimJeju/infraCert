"""보고서 화면 — 진단 선택 · 품질 게이트 · XLSX/HTML · 세션 패키지."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from infraguard.result.gate import GateItem


class ReportsPage(QWidget):
    export_requested = Signal(str)          # xlsx | html
    scan_selected = Signal(str)             # scan_id
    session_export_requested = Signal()
    session_import_requested = Signal()

    def __init__(self) -> None:
        super().__init__()
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 16, 20, 16)
        root.setSpacing(12)
        top = QHBoxLayout()
        t = QLabel("보고서")
        t.setObjectName("h1")
        top.addWidget(t)
        self.current = QLabel("")
        self.current.setObjectName("muted")
        top.addWidget(self.current)
        top.addStretch(1)
        self.btn_xlsx = QPushButton("XLSX 보고서")
        self.btn_xlsx.setObjectName("primary")
        self.btn_html = QPushButton("HTML 보고서")
        self.btn_xlsx.clicked.connect(lambda: self.export_requested.emit("xlsx"))
        self.btn_html.clicked.connect(lambda: self.export_requested.emit("html"))
        top.addWidget(self.btn_xlsx)
        top.addWidget(self.btn_html)
        root.addLayout(top)

        split = QSplitter(Qt.Orientation.Horizontal)
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.addWidget(QLabel("진단 선택 (최근순)"))
        self.scans = QListWidget()
        self.scans.itemClicked.connect(lambda it: self.scan_selected.emit(it.data(Qt.ItemDataRole.UserRole)))
        ll.addWidget(self.scans, 1)
        split.addWidget(left)
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.addWidget(QLabel("보고서 품질 검사 — 통과 못 해도 막지 않는다. 사실을 보고 결정한다"))
        self.gate = QListWidget()
        rl.addWidget(self.gate, 1)
        srow = QHBoxLayout()
        exp = QPushButton("진단 세션 내보내기(zip)")
        exp.setToolTip("자산·예외·결과·감사기록을 zip 하나로. 크리덴셜은 포함되지 않는다")
        imp = QPushButton("진단 세션 가져오기(zip)")
        exp.clicked.connect(self.session_export_requested)
        imp.clicked.connect(self.session_import_requested)
        srow.addWidget(exp)
        srow.addWidget(imp)
        srow.addStretch(1)
        rl.addLayout(srow)
        split.addWidget(right)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 2)
        root.addWidget(split, 1)

    def set_scans(self, scans: list[tuple[str, dict]], current: str | None) -> None:
        self.scans.clear()
        for sid, meta in scans:
            started = (meta.get("started_at") or "")[:16].replace("T", " ")
            it = QListWidgetItem(f"{started}   {sid}   {meta.get('profile') or ''}")
            it.setData(Qt.ItemDataRole.UserRole, sid)
            self.scans.addItem(it)
            if sid == current:
                self.scans.setCurrentItem(it)
        self.current.setText(f"현재: {current}" if current else "진단 결과 없음")
        self.btn_xlsx.setEnabled(bool(current))
        self.btn_html.setEnabled(bool(current))

    def set_gate(self, items: list[GateItem]) -> None:
        self.gate.clear()
        for i in items:
            it = QListWidgetItem(i.line())
            it.setForeground(Qt.GlobalColor.green if i.ok else Qt.GlobalColor.red)
            self.gate.addItem(it)
        if not items:
            self.gate.addItem("진단을 선택하면 검사 결과가 나옵니다")
