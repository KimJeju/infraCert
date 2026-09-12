"""Rule Tester 패널(룰팩 탭 오른쪽 아래) — 선언형 룰에 샘플 출력을 넣고 판정을 즉시 본다."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from infraguard.core.status import Status
from infraguard.evaluation.verdict_map import normalize_verdict
from infraguard.rules import tester
from infraguard.rules.declarative import RuleSpec
from infraguard.ui.theme import STATUS_TEXT


class RuleTesterPanel(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._spec: RuleSpec | None = None
        self._editors: dict[str, QPlainTextEdit] = {}
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(4)
        head = QHBoxLayout()
        self.title = QLabel("룰 테스터 — 선언형(YAML) 룰을 고르면 수집 명령별로 샘플 출력을 넣어 볼 수 있다")
        self.title.setObjectName("muted")
        head.addWidget(self.title, 1)
        self.platform = QComboBox()
        self.platform.currentIndexChanged.connect(lambda _i: self._rebuild())
        head.addWidget(self.platform)
        self.run_btn = QPushButton("▶ 테스트")
        self.run_btn.setObjectName("primary")
        self.run_btn.clicked.connect(self.run)
        self.run_btn.setEnabled(False)
        head.addWidget(self.run_btn)
        root.addLayout(head)
        self._body = QWidget()
        self._bl = QVBoxLayout(self._body)
        self._bl.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(self._body)
        root.addWidget(scroll, 1)
        self.result = QLabel("")
        self.result.setWordWrap(True)
        self.result.setTextInteractionFlags(self.result.textInteractionFlags() |
                                            __import__("PySide6.QtCore", fromlist=["Qt"]).Qt.TextInteractionFlag.TextSelectableByMouse)
        root.addWidget(self.result)

    def set_spec(self, spec: RuleSpec | None) -> None:
        self._spec = spec
        self.platform.blockSignals(True)
        self.platform.clear()
        if spec:
            self.platform.addItems(list(spec.all_platforms()))
        self.platform.blockSignals(False)
        self.run_btn.setEnabled(spec is not None)
        self.result.setText("")
        self._rebuild()

    def _rebuild(self) -> None:
        while self._bl.count():
            it = self._bl.takeAt(0)
            if it.widget():
                it.widget().deleteLater()
        self._editors.clear()
        if not self._spec:
            self.title.setText("룰 테스터 — 선언형(YAML) 룰을 고르면 수집 명령별로 샘플 출력을 넣어 볼 수 있다")
            return
        blk = self._spec.for_platform(self.platform.currentText() or None)
        self.title.setText(f"룰 테스터 — {self._spec.id} [{blk.shell}]  "
                           f"추출 {len(blk.extract)} · 판정 절 {len(blk.verdict)}")
        for c in blk.collect:
            lab = QLabel(f"{c.key}:  $ {c.cmd}")
            lab.setWordWrap(True)
            lab.setStyleSheet("font-family: Consolas, monospace;")
            ed = QPlainTextEdit()
            ed.setPlaceholderText("이 명령의 샘플 출력 (비우면 '명령 실패/출력 없음' 으로 평가)")
            ed.setMaximumHeight(72)
            self._bl.addWidget(lab)
            self._bl.addWidget(ed)
            self._editors[c.key] = ed
        self._bl.addStretch(1)

    def outputs(self) -> dict[str, str]:
        return {k: ed.toPlainText() for k, ed in self._editors.items() if ed.toPlainText().strip()}

    def run(self) -> str | None:
        if not self._spec:
            return None
        try:
            out = tester.run(self._spec, self.outputs(), platform=self.platform.currentText() or None)
        except Exception as e:  # noqa: BLE001 - 룰 오류를 화면에 보여준다
            self.result.setStyleSheet(f"color:{STATUS_TEXT[Status.ERROR]}")
            self.result.setText(f"오류: {type(e).__name__}: {e}")
            return "ERROR"
        st, _ = normalize_verdict(out.verdict_raw)
        self.result.setStyleSheet(f"color:{STATUS_TEXT.get(st, '#D7DDE6')}")
        ext = out.detail.get("extracted") or {}
        self.result.setText(
            f"판정: {out.verdict_raw}    판정식: {out.detail.get('matched', '-')}\n"
            f"추출: {', '.join(f'{k}={v!r}' for k, v in ext.items()) or '-'}\n"
            f"근거: {out.evidence[:300]}"
        )
        return out.verdict_raw
