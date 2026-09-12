"""원격 파일 읽기 전용 뷰어 — 설정 변경은 지원하지 않는다(제품 철학: 진단 도구는 대상을 바꾸지 않는다).

받은 사본은 workspace/tmp/view/ 에만 두고(완전삭제 대상), 표시 전에 값 패턴 마스킹을 건다(비밀번호·키 노출 방지).
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QDialog, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from infraguard.result.masking import mask
from infraguard.transport.local import decode_output


class FileViewerDialog(QDialog):
    def __init__(self, remote: str, local: Path, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"[읽기 전용] {remote}")
        self.resize(900, 620)
        lay = QVBoxLayout(self)
        head = QHBoxLayout()
        head.addWidget(QLabel(f"<b>{remote}</b>  ·  읽기 전용 · 값 마스킹 적용 · 사본은 종료 시 삭제"))
        head.addStretch(1)
        self.search = QLineEdit()
        self.search.setPlaceholderText("찾기 (Enter)")
        self.search.returnPressed.connect(self._find)
        head.addWidget(self.search)
        lay.addLayout(head)
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        self.text.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.text.setStyleSheet("font-family: Consolas, 'Malgun Gothic', monospace;")
        try:
            raw = local.read_bytes()
            body = decode_output(raw)[0] if raw else ""
        except OSError as e:
            body = f"(읽기 실패: {e})"
        self.text.setPlainText(mask(body) or "")
        lay.addWidget(self.text, 1)
        row = QHBoxLayout()
        row.addWidget(QLabel(f"{len(body.splitlines())} 줄"))
        row.addStretch(1)
        close = QPushButton("닫기")
        close.clicked.connect(self.close)
        row.addWidget(close)
        lay.addLayout(row)

    def _find(self) -> None:
        q = self.search.text()
        if q and not self.text.find(q):
            c = self.text.textCursor()
            c.movePosition(c.MoveOperation.Start)
            self.text.setTextCursor(c)
            self.text.find(q)
