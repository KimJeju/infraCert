"""호스트 카드(사이드바 하단) — 세션 매니저의 "선택한 호스트" 요약.

MobaXterm 의 세션 목록에 InfraGuard 의 자산·진단 정보를 합친 것:
OS · 주소 · 메타 · 마지막 진단(프로파일·시각·판정 분포) · [진단][터미널][SFTP][Discovery][결과].
"""

from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget

from infraguard.assets.models import Host
from infraguard.core.status import Status
from infraguard.ui.theme import STATUS_FG

ACTIONS = (("scan", "▶ 진단"), ("terminal", "터미널"), ("sftp", "SFTP"), ("discovery", "Discovery"), ("results", "결과"))


class HostCard(QWidget):
    action = Signal(str, str)   # action, host_id

    def __init__(self) -> None:
        super().__init__()
        self.setObjectName("card")
        self._host_id: str | None = None
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 8, 10, 8)
        lay.setSpacing(6)
        self.title = QLabel("호스트를 선택하세요")
        self.title.setObjectName("h2")
        lay.addWidget(self.title)
        self.grid = QGridLayout()
        self.grid.setHorizontalSpacing(10)
        self.grid.setVerticalSpacing(2)
        self._rows: dict[str, QLabel] = {}
        for i, key in enumerate(("OS", "IP", "메타", "Profile", "Last")):
            k = QLabel(key)
            k.setObjectName("muted")
            v = QLabel("-")
            v.setWordWrap(True)
            self.grid.addWidget(k, i, 0)
            self.grid.addWidget(v, i, 1)
            self._rows[key] = v
        self.grid.setColumnStretch(1, 1)
        lay.addLayout(self.grid)
        self.summary = QLabel("")
        self.summary.setTextFormat(Qt.TextFormat.RichText)
        self.title.setTextFormat(Qt.TextFormat.RichText)
        lay.addWidget(self.summary)
        row = QHBoxLayout()
        row.setSpacing(4)
        self._btns: dict[str, QPushButton] = {}
        for key, label in ACTIONS:
            b = QPushButton(label)
            b.setEnabled(False)
            b.clicked.connect(lambda _c=False, k=key: self._emit(k))
            row.addWidget(b)
            self._btns[key] = b
        lay.addLayout(row)

    def _emit(self, key: str) -> None:
        if self._host_id:
            self.action.emit(key, self._host_id)

    def clear(self) -> None:
        self._host_id = None
        self.title.setText("호스트를 선택하세요")
        for v in self._rows.values():
            v.setText("-")
        self.summary.setText("")
        for b in self._btns.values():
            b.setEnabled(False)

    def show_host(self, host: Host, *, os_text: str | None = None, profile: str | None = None,
                  last_at: datetime | str | None = None, summary: dict[str, int] | None = None) -> None:
        self._host_id = host.host_id
        self.title.setText(f"{host.label}   <span style='color:#7D8794;font-weight:400'>{host.project} / {host.group}</span>")
        self._rows["OS"].setText(os_text or host.platform)
        self._rows["IP"].setText(f"{host.address}:{host.port}  ({host.username})")
        meta = " · ".join(x for x in (host.environment, host.criticality, host.role, ", ".join(host.tags)) if x)
        self._rows["메타"].setText(meta or "-")
        self._rows["Profile"].setText(profile or "-")
        if isinstance(last_at, datetime):
            last_at = last_at.strftime("%Y-%m-%d %H:%M")
        self._rows["Last"].setText(str(last_at) if last_at else "진단 이력 없음")
        s = summary or host.last_summary or {}
        if s:
            parts = [f"<span style='color:{STATUS_FG[st]}'>{name} {s.get(st.value, 0)}</span>"
                     for st, name in ((Status.PASS, "GOOD"), (Status.FAIL, "VULN"), (Status.UNKNOWN, "MANUAL"),
                                      (Status.ERROR, "ERROR"))]
            self.summary.setText(" &nbsp; ".join(parts))
        else:
            self.summary.setText("")
        for k, b in self._btns.items():
            b.setEnabled(k != "results" or bool(host.last_scan_id))
        self._btns["terminal"].setEnabled(host.platform not in ("windows", "pc"))
        self._btns["sftp"].setEnabled(host.platform not in ("windows", "pc", "network"))
