"""수동확인 워크벤치(§6.2) — UNKNOWN 항목을 키보드만으로 처리.

저장 시 verdict_source=analyst, analyst_note 를 남긴다. 스크립트 판정과 섞지 않는다.
단축키: 1 양호 / 2 취약 / 3 해당없음, Ctrl+Enter 저장 후 다음.
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QRadioButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from infraguard.core.models import ScanResult
from infraguard.core.status import Status

# 분석자가 선택 가능한 최종 판정
CHOICES = [("양호", Status.PASS), ("취약", Status.FAIL), ("해당없음", Status.SKIPPED)]


class ManualBenchPage(QWidget):
    verdict_saved = Signal(str, str, str, str, bool)  # host_id, rule_id, status, note, batch

    def __init__(self) -> None:
        super().__init__()
        self._scan: ScanResult | None = None
        self._guide: dict[str, dict] = {}          # rule id → 가이드 항목
        self._remediation: dict[str, str] = {}     # rule id → 조치방법(가이드 없을 때의 대체)
        root = QHBoxLayout(self)

        left = QVBoxLayout()
        self.header = QLabel("수동확인 항목")
        left.addWidget(self.header)
        self.items = QListWidget()
        self.items.currentRowChanged.connect(self._on_select)
        left.addWidget(self.items)
        self.only_pending = QCheckBox("미판정만")
        self.only_pending.setChecked(True)
        self.only_pending.toggled.connect(lambda: self.load(self._scan))
        left.addWidget(self.only_pending)
        root.addLayout(left, 1)

        right = QVBoxLayout()
        self.title = QLabel("-")
        self.title.setObjectName("h1")
        right.addWidget(self.title)
        self.meta = QLabel("")
        self.meta.setObjectName("muted")
        right.addWidget(self.meta)
        right.addWidget(QLabel("수집 근거"))
        self.evidence = QTextEdit()
        self.evidence.setReadOnly(True)
        right.addWidget(self.evidence, 1)
        right.addWidget(QLabel("가이드 — 판단기준 · 조치 · 점검사례 (룰팩 guide/ 또는 manifest 메타)"))
        self.guide = QTextEdit()
        self.guide.setReadOnly(True)
        right.addWidget(self.guide, 1)

        vrow = QHBoxLayout()
        vrow.addWidget(QLabel("판정"))
        self.group = QButtonGroup(self)
        self.radios: list[QRadioButton] = []
        for i, (label, _st) in enumerate(CHOICES):
            rb = QRadioButton(f"{i + 1} {label}")
            self.group.addButton(rb, i)
            self.radios.append(rb)
            vrow.addWidget(rb)
        vrow.addStretch(1)
        self.batch = QCheckBox("같은 항목코드 일괄")
        vrow.addWidget(self.batch)
        right.addLayout(vrow)

        right.addWidget(QLabel("사유"))
        self.note = QLineEdit()
        right.addWidget(self.note)

        brow = QHBoxLayout()
        brow.addStretch(1)
        self.prev = QPushButton("◀ 이전")
        self.save = QPushButton("저장 후 다음 ▶")
        self.save.setObjectName("primary")
        self.prev.clicked.connect(lambda: self._step(-1))
        self.save.clicked.connect(self._save_next)
        brow.addWidget(self.prev)
        brow.addWidget(self.save)
        right.addLayout(brow)
        root.addLayout(right, 2)

        for key, idx in (("1", 0), ("2", 1), ("3", 2)):
            QShortcut(QKeySequence(key), self, lambda i=idx: self.radios[i].setChecked(True))
        QShortcut(QKeySequence("Ctrl+Return"), self, self._save_next)

    def set_guide(self, guide: dict[str, dict], remediation: dict[str, str]) -> None:
        self._guide, self._remediation = guide, remediation

    def _guide_text(self, rule_id: str) -> str:
        g = self._guide.get(rule_id)
        if not g:
            rem = self._remediation.get(rule_id)
            return f"조치방법: {rem}" if rem else "(이 항목의 가이드 없음 — 룰팩에 guide/ 가 없거나 항목 미포함)"
        j = g.get("judgment") or {}
        out = []
        if j:
            out.append(f"양호: {j.get('good', '')}\n취약: {j.get('vuln', '')}")
        if g.get("remediation"):
            out.append(f"조치방법: {g['remediation']}")
        if g.get("impact"):
            out.append(f"조치 시 영향: {g['impact']}")
        for pr in g.get("procedures") or []:
            out.append(f"[{pr.get('platform', '')}]")
            for k, v in (pr.get("variants") or {}).items():
                out.append(f"  ({k})")
                out.extend("   " + st for st in v.get("steps") or [])
            out.extend("  " + st for st in pr.get("steps") or [])
        return "\n".join(out)

    def load(self, scan: ScanResult | None) -> None:
        self._scan = scan
        self.items.blockSignals(True)
        self.items.clear()
        if scan:
            for h in scan.hosts:
                for r in h.results:
                    if r.status is not Status.UNKNOWN:
                        continue
                    if self.only_pending.isChecked() and r.verdict_source == "analyst":
                        continue
                    it = QListWidgetItem(f"{h.hostname}  {r.rule_id}  {r.name}")
                    it.setData(Qt.ItemDataRole.UserRole, (h.host_id, h.hostname, r.rule_id))
                    self.items.addItem(it)
        self.items.blockSignals(False)
        self.header.setText(f"수동확인 항목 ({self.items.count()})")
        if self.items.count():
            self.items.setCurrentRow(0)
        else:
            self.title.setText("남은 수동확인 항목 없음")
            self.evidence.clear()
            self.guide.clear()

    def _current(self):
        it = self.items.currentItem()
        return it.data(Qt.ItemDataRole.UserRole) if it else None

    def _on_select(self, _row: int) -> None:
        data = self._current()
        if not data or not self._scan:
            return
        host_id, hostname, rule_id = data
        for h in self._scan.hosts:
            if h.host_id != host_id:
                continue
            for r in h.results:
                if r.rule_id == rule_id:
                    self.title.setText(f"{r.rule_id}  {r.name}")
                    self.meta.setText(f"호스트: {hostname}   중요도: {r.severity.value if r.severity else '-'}")
                    self.evidence.setPlainText(r.evidence or r.reason or "")
                    self.guide.setPlainText(self._guide_text(r.rule_id))
                    self.note.setText(r.analyst_note or "")
                    for rb in self.radios:
                        rb.setChecked(False)
                    return

    def _save_next(self) -> None:
        data = self._current()
        if not data:
            return
        bid = self.group.checkedId()
        if bid < 0:
            return
        host_id, _hostname, rule_id = data
        status = CHOICES[bid][1].value
        self.verdict_saved.emit(host_id, rule_id, status, self.note.text().strip(),
                                self.batch.isChecked())

    def _step(self, delta: int) -> None:
        row = self.items.currentRow() + delta
        if 0 <= row < self.items.count():
            self.items.setCurrentRow(row)
