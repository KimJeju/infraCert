"""설정 페이지(§10) — 실행 폴더 config.json. 호스트·계정·비밀번호는 절대 저장하지 않는다."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from infraguard import config
from infraguard.workspace.layout import Layout


def _dir_size(p: Path) -> int:
    total = 0
    try:
        for f in p.rglob("*"):
            if f.is_file():
                total += f.stat().st_size
    except OSError:
        pass
    return total


class SettingsPage(QWidget):
    saved = Signal(dict)
    sanitize_requested = Signal()

    def __init__(self, cfg: dict, layout: Layout, engine_version: str, pack_label: str) -> None:
        super().__init__()
        self._layout = layout
        # 그룹 5개가 창 높이보다 길어질 수 있다(형 스크린샷: 행이 겹침) → 스크롤 영역 안에 쌓는다
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        body = QWidget()
        root = QVBoxLayout(body)
        root.setContentsMargins(16, 12, 16, 12)
        root.setSpacing(10)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setWidget(body)
        outer.addWidget(scroll, 1)

        def form(box: QGroupBox) -> QFormLayout:
            f = QFormLayout(box)
            f.setHorizontalSpacing(16)
            f.setVerticalSpacing(8)
            f.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            f.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.FieldsStayAtSizeHint)
            return f

        g_run = QGroupBox("실행")
        f = form(g_run)
        self.concurrency = QSpinBox()
        self.concurrency.setRange(1, 20)
        self.timeout = QSpinBox()
        self.timeout.setRange(30, 86400)
        self.max_out = QSpinBox()
        self.max_out.setRange(64, 65536)
        self.max_out.setSuffix(" KB")
        self.use_sudo = QCheckBox("sudo 사용 (-n, 비대화형)")
        f.addRow("동시 실행 수", self.concurrency)
        f.addRow("기본 타임아웃(초)", self.timeout)
        f.addRow("출력 상한", self.max_out)
        f.addRow("", self.use_sudo)
        root.addWidget(g_run)

        g_sec = QGroupBox("접속 · 보안")
        f = form(g_sec)
        self.connect_timeout = QSpinBox()
        self.connect_timeout.setRange(3, 120)
        self.idle_lock = QSpinBox()
        self.idle_lock.setRange(1, 240)
        self.idle_lock.setSuffix(" 분")
        self.term_rec = QCheckBox("터미널 입력·출력 기록 (비밀번호는 마스킹)")
        f.addRow("연결 타임아웃(초)", self.connect_timeout)
        f.addRow("크리덴셜 idle 잠금", self.idle_lock)
        f.addRow("", self.term_rec)
        root.addWidget(g_sec)

        g_rep = QGroupBox("리포트")
        f = form(g_rep)
        self.export_fmt = QComboBox()
        self.export_fmt.addItems(["xlsx", "html"])
        self.company = QLineEdit()
        self.company.setPlaceholderText("보고서 머리말에 표시할 회사명")
        f.addRow("기본 내보내기 형식", self.export_fmt)
        f.addRow("회사명", self.company)
        root.addWidget(g_rep)
        for w in (self.concurrency, self.timeout, self.max_out, self.connect_timeout,
                  self.idle_lock, self.export_fmt):
            w.setFixedWidth(160)
        self.company.setFixedWidth(420)

        g_ws = QGroupBox("작업공간")
        f = form(g_ws)
        self.ws_path = QLabel(str(layout.root))
        self.ws_size = QLabel("")
        wipe = QPushButton("지금 완전삭제")
        wipe.setObjectName("danger")
        wipe.setFixedWidth(160)
        wipe.clicked.connect(self.sanitize_requested)
        f.addRow("경로", self.ws_path)
        f.addRow("사용량", self.ws_size)
        f.addRow("", wipe)
        root.addWidget(g_ws)

        g_info = QGroupBox("정보")
        f = form(g_info)
        f.addRow("엔진", QLabel(engine_version))
        f.addRow("룰팩", QLabel(pack_label))
        f.addRow("네트워크", QLabel("오프라인 전용 — 업데이트 확인·텔레메트리 없음"))
        f.addRow("설정 파일", QLabel(str(config.config_path())))
        root.addWidget(g_info)

        root.addStretch(1)
        brow = QHBoxLayout()
        brow.setContentsMargins(16, 8, 16, 10)
        brow.addStretch(1)
        save = QPushButton("저장")
        save.setObjectName("primary")
        save.clicked.connect(self._save)
        brow.addWidget(save)
        outer.addLayout(brow)              # 저장은 스크롤 밖 하단 고정

        self.load(cfg)

    def load(self, cfg: dict) -> None:
        self.concurrency.setValue(int(cfg.get("concurrency", 5)))
        self.timeout.setValue(int(cfg.get("default_timeout", 1800)))
        self.max_out.setValue(int(cfg.get("max_output_kb", 1024)))
        self.use_sudo.setChecked(bool(cfg.get("use_sudo", False)))
        self.connect_timeout.setValue(int(cfg.get("connect_timeout", 15)))
        self.idle_lock.setValue(int(cfg.get("idle_lock_minutes", 15)))
        self.term_rec.setChecked(bool(cfg.get("terminal_recording", True)))
        self.export_fmt.setCurrentText(str(cfg.get("export_format", "xlsx")))
        self.company.setText(str(cfg.get("company_name", "")))
        self.refresh_usage()

    def refresh_usage(self) -> None:
        n = _dir_size(self._layout.root)
        self.ws_size.setText(f"{n / 1024 / 1024:.1f} MB")

    def values(self) -> dict:
        return {
            "concurrency": self.concurrency.value(),
            "default_timeout": self.timeout.value(),
            "max_output_kb": self.max_out.value(),
            "use_sudo": self.use_sudo.isChecked(),
            "connect_timeout": self.connect_timeout.value(),
            "idle_lock_minutes": self.idle_lock.value(),
            "terminal_recording": self.term_rec.isChecked(),
            "export_format": self.export_fmt.currentText(),
            "company_name": self.company.text().strip(),
        }

    def _save(self) -> None:
        v = self.values()
        config.save(v)          # 금지 키(호스트·계정·비밀번호)는 config.save 가 걸러낸다
        self.saved.emit(v)
