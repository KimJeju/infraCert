"""Discovery 다이얼로그 — 포트/배너(+크리덴셜 있으면 SSH 읽기전용 탐색) → 발견 목록 → 추천 프로파일 → [진단]."""

from __future__ import annotations

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from infraguard.assets.models import Host
from infraguard.orchestrator import discovery
from infraguard.rulepack.loader import RulePack


class _Worker(QObject):
    finished = Signal(object)   # Discovery
    failed = Signal(str)

    def __init__(self, host: Host, cred, bridge) -> None:  # noqa: ANN001
        super().__init__()
        self._host, self._cred, self._bridge = host, cred, bridge

    def run(self) -> None:
        try:
            d = discovery.probe_ports(self._host.address)
            if self._cred is not None and self._host.platform not in ("windows", "pc", "network"):
                from infraguard.ui.workers import build_connection
                conn = build_connection(self._host, self._cred, self._bridge.ask, self._bridge.ask_changed)
                try:
                    conn.connect()
                    discovery.probe_ssh(conn, d)
                except Exception as e:  # noqa: BLE001
                    d.notes.append(f"SSH 탐색 생략: {e}")
                finally:
                    try:
                        conn.close()
                    except Exception:  # noqa: BLE001,S110
                        pass
            else:
                discovery.probe_ssh.__doc__  # noqa: B018 - 자리표시
                for p, n in d.ports.items():
                    tag = {"ssh": "ssh", "http": "http", "https": "http", "oracle": "oracle", "winrm": "winrm",
                           "tomcat/http-alt": "tomcat", "weblogic": "weblogic"}.get(n, "")
                    if tag and tag not in d.services:
                        d.services.append(tag)
            self.finished.emit(d)
        except Exception as e:  # noqa: BLE001
            self.failed.emit(f"{type(e).__name__}: {e}")


class DiscoveryDialog(QDialog):
    def __init__(self, host: Host, cred, pack: RulePack | None, bridge, parent: QWidget | None = None) -> None:  # noqa: ANN001
        super().__init__(parent)
        self.setWindowTitle(f"Discovery — {host.label}")
        self.resize(640, 520)
        self._host, self._pack = host, pack
        self._disc: discovery.Discovery | None = None
        lay = QVBoxLayout(self)
        self.status = QLabel(f"{host.address} 포트 탐색 중… (TCP connect {len(discovery.TCP_PORTS)}개"
                             + (", SSH 읽기전용 탐색" if cred is not None else ", 크리덴셜 없음 → 포트만") + ")")
        self.status.setObjectName("muted")
        lay.addWidget(self.status)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setStyleSheet("font-family: Consolas, monospace;")
        lay.addWidget(self.out, 1)
        lay.addWidget(QLabel("추천 프로파일 (하나 골라 [진단] → 진단 탭으로)"))
        self.rec_box = QVBoxLayout()
        lay.addLayout(self.rec_box)
        self._group = QButtonGroup(self)
        self._radios: list[QRadioButton] = []
        bb = QDialogButtonBox()
        self.btn_scan = bb.addButton("▶ 진단", QDialogButtonBox.ButtonRole.AcceptRole)
        self.btn_scan.setObjectName("primary")
        self.btn_scan.setEnabled(False)
        bb.addButton(QDialogButtonBox.StandardButton.Close)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

        self._thread = QThread(self)
        self._w = _Worker(host, cred, bridge)
        self._w.moveToThread(self._thread)
        self._thread.started.connect(self._w.run)
        self._w.finished.connect(self._on_done)
        self._w.failed.connect(self._on_fail)
        self._thread.start()

    def _on_done(self, d: discovery.Discovery) -> None:
        self._disc = d
        self.status.setText("탐색 완료")
        lines = ["Detected", "─" * 40]
        for p in sorted(d.ports):
            lines.append(f"{p:>5}/tcp  {d.ports[p]:<16} {d.banners.get(p, '')}")
        if not d.ports:
            lines.append("(열린 포트 없음 — 방화벽/주소 확인)")
        if d.os:
            lines += ["", f"OS        {d.os}"]
        if d.services:
            lines += [f"Services  {', '.join(d.services)}"]
        for k, v in d.hints.items():
            lines.append(f"{k:<9} {v}   ← 자산 파라미터 후보")
        for n in d.notes:
            lines.append(f"note: {n}")
        self.out.setPlainText("\n".join(lines))
        ids = list(self._pack.profiles) if self._pack else []
        rec = discovery.recommend_profiles(d, self._host.platform, ids)
        for i, pid in enumerate(rec):
            prof = self._pack.profiles[pid] if self._pack else None
            rb = QRadioButton(f"{pid}  —  {prof.name if prof else ''}")
            rb.setChecked(i == 0)
            self._group.addButton(rb, i)
            self._radios.append(rb)
            self.rec_box.addWidget(rb)
        if not rec:
            self.rec_box.addWidget(QLabel("추천 없음 — 플랫폼/포트로 판단 불가"))
        self.btn_scan.setEnabled(bool(rec))
        self._thread.quit()

    def _on_fail(self, msg: str) -> None:
        self.status.setText(f"✕ {msg}")
        self._thread.quit()

    def result_discovery(self) -> dict | None:
        return self._disc.to_dict() if self._disc else None

    def chosen_profile(self) -> str | None:
        i = self._group.checkedId()
        if i < 0 or i >= len(self._radios):
            return None
        return self._radios[i].text().split("  —  ")[0]

    def closeEvent(self, e) -> None:  # noqa: N802,ANN001
        self._thread.quit()
        self._thread.wait(2000)
        super().closeEvent(e)
