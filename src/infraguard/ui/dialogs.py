"""다이얼로그 — 크리덴셜 입력 · 호스트키 승인 · 자산 편집.

크리덴셜: QLineEdit.text() 로 받은 평문 str 은 지역변수로만 두고 즉시 Secret 으로 감싼다.
반환 후 str 참조를 남기지 않는다(§5.2).
"""

from __future__ import annotations

from PySide6.QtCore import QDate, Qt
from PySide6.QtWidgets import (
    QDateEdit,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from infraguard.assets.exceptions import RiskException
from infraguard.assets.models import Host
from infraguard.core.ids import new_host_id
from infraguard.core.models import Platform
from infraguard.credentials.secret import Secret
from infraguard.credentials.session import Credential
from infraguard.orchestrator.remote_runner import validate_env
from infraguard.result import risk as _risk

PLATFORMS = [Platform.LINUX, Platform.UNIX, Platform.WINDOWS, Platform.DBMS,
             Platform.NETWORK, Platform.CLOUD, Platform.PC]


class CredPromptDialog(QDialog):
    """세션에 없는 크리덴셜 1건을 입력받는다."""

    def __init__(self, cred_id: str, username: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("접속 크리덴셜")
        self._cred_id = cred_id

        form = QFormLayout()
        form.addRow(QLabel(f"<b>{cred_id}</b> — 세션 메모리에만 보관됩니다"))

        self.user = QLineEdit(username)
        self.kind = QComboBox()
        self.kind.addItems(["password", "key", "agent"])
        self.pw = QLineEdit()
        self.pw.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_path = QLineEdit()
        self.key_pass = QLineEdit()
        self.key_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.sudo = QLineEdit()
        self.sudo.setEchoMode(QLineEdit.EchoMode.Password)
        for w in (self.pw, self.key_pass, self.sudo):
            w.setClearButtonEnabled(False)

        form.addRow("계정", self.user)
        form.addRow("인증방식", self.kind)
        form.addRow("비밀번호", self.pw)
        form.addRow("키 경로", self.key_path)
        form.addRow("키 암호", self.key_pass)
        form.addRow("sudo 비밀번호", self.sudo)

        self.kind.currentTextChanged.connect(self._on_kind)
        self._on_kind(self.kind.currentText())

        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)

        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(bb)

    def _on_kind(self, kind: str) -> None:
        self.pw.setEnabled(kind == "password")
        self.key_path.setEnabled(kind == "key")
        self.key_pass.setEnabled(kind == "key")

    def credential(self) -> Credential:
        """입력값을 Secret 으로 감싸 반환한다. 평문 str 은 이 스코프를 벗어나지 않는다."""
        kind = self.kind.currentText()
        pw = Secret(self.pw.text()) if kind == "password" and self.pw.text() else None
        kp = Secret(self.key_pass.text()) if kind == "key" and self.key_pass.text() else None
        sudo = Secret(self.sudo.text()) if self.sudo.text() else None
        return Credential(
            cred_id=self._cred_id,
            username=self.user.text().strip() or "root",
            kind=kind,  # type: ignore[arg-type]
            password=pw,
            key_path=self.key_path.text().strip() or None,
            key_passphrase=kp,
            sudo_password=sudo,
        )


class HostKeyDialog(QDialog):
    """미등록 호스트키 승인. 지문(SHA256)을 크게 보여준다(§5.3)."""

    def __init__(self, host: str, key_type: str, fingerprint: str,
                 changed: bool = False, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("호스트키 확인")
        lay = QVBoxLayout(self)
        lay.addWidget(QLabel(f"<b>{host}</b> ({key_type})"))
        if changed:
            warn = QLabel("⚠ 호스트키가 이전과 다릅니다. 중간자 공격 가능성이 있습니다.")
            warn.setStyleSheet("color:#F85149;font-weight:bold")
            lay.addWidget(warn)
        lay.addWidget(QLabel("지문(SHA256):"))
        fp = QLabel(fingerprint)
        fp.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        fp.setStyleSheet("font-family:Consolas,monospace;font-size:14px;padding:6px")
        lay.addWidget(fp)

        row = QHBoxLayout()
        reject = QPushButton("거부")
        approve = QPushButton("승인")
        approve.setObjectName("primary")
        reject.clicked.connect(self.reject)
        approve.clicked.connect(self.accept)
        row.addStretch(1)
        row.addWidget(reject)
        row.addWidget(approve)
        lay.addLayout(row)


class AssetEditDialog(QDialog):
    """호스트 등록·수정. 비밀번호는 여기서 받지 않는다(진단 시작 시 별도 입력)."""

    def __init__(self, host: Host | None = None, parent: QWidget | None = None,
                 param_hints: list[dict] | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("자산 편집" if host else "자산 추가")
        self._param_hints = param_hints or []
        self._host_id = host.host_id if host else new_host_id()
        h = host or Host(host_id=self._host_id, name="", address="")

        form = QFormLayout()
        self.name = QLineEdit(h.name)
        self.project = QLineEdit(h.project)
        self.group = QLineEdit(h.group)
        self.address = QLineEdit(h.address)
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(h.port)
        self.platform = QComboBox()
        self.platform.addItems(PLATFORMS)
        self.platform.setCurrentText(h.platform)
        self.username = QLineEdit(h.username)
        self.auth = QComboBox()
        self.auth.addItems(["password", "key", "agent"])
        self.auth.setCurrentText(h.auth_kind)
        self.timeout = QSpinBox()
        self.timeout.setRange(30, 86400)
        self.timeout.setValue(h.timeout)
        self.sudo = QCheckBox("sudo 사용 (-n)")
        self.sudo.setChecked(h.use_sudo)
        self.use_bastion = QCheckBox("bastion 경유")
        self.use_bastion.setChecked(h.use_bastion)
        self.bastion_host = QLineEdit(h.bastion_host or "")
        self.bastion_user = QLineEdit(h.bastion_user or "")
        # 자산 메타(위험도 축): 환경·중요도·담당·역할·태그
        self.environment = QComboBox()
        self.environment.addItems(list(_risk.ENVIRONMENTS))
        self.environment.setCurrentText(h.environment)
        self.criticality = QComboBox()
        self.criticality.addItems(list(_risk.CRITICALITIES))
        self.criticality.setCurrentText(h.criticality or _risk.DEFAULT_CRITICALITY)
        self.owner = QLineEdit(h.owner)
        self.role = QLineEdit(h.role)
        self.tags = QLineEdit(", ".join(h.tags))
        self.tags.setPlaceholderText("쉼표로 구분")

        form.addRow("이름", self.name)
        form.addRow("고객사", self.project)
        form.addRow("분류", self.group)
        form.addRow("주소", self.address)
        form.addRow("포트", self.port)
        form.addRow("플랫폼", self.platform)
        form.addRow("계정", self.username)
        form.addRow("인증방식", self.auth)
        form.addRow("타임아웃(초)", self.timeout)
        meta = QHBoxLayout()
        meta.addWidget(QLabel("환경"))
        meta.addWidget(self.environment)
        meta.addWidget(QLabel("중요도"))
        meta.addWidget(self.criticality)
        meta.addWidget(QLabel("역할"))
        meta.addWidget(self.role, 1)
        form.addRow("자산 메타", meta)
        form.addRow("담당자", self.owner)
        form.addRow("태그", self.tags)
        # 번들 파라미터: 한 줄에 NAME=value. 스크립트가 환경변수로 받는다(TOMCAT_HOME 등).
        self.params = QPlainTextEdit()
        self.params.setPlainText("\n".join(f"{k}={v}" for k, v in h.params.items()))
        self.params.setMaximumHeight(90)
        hint = "\n".join(f"{p['name']}={p.get('example', '')}   # {p.get('label', '')} [{p.get('bundle', '')}]"
                         for p in self._param_hints) or "NAME=value (한 줄에 하나)"
        self.params.setPlaceholderText(hint)
        self.params.setToolTip("스크립트 번들에 환경변수로 전달됩니다. 경로·식별자 문자만 허용.\n" + hint)
        form.addRow("번들 파라미터", self.params)
        form.addRow("", self.sudo)
        form.addRow("", self.use_bastion)
        form.addRow("bastion 주소", self.bastion_host)
        form.addRow("bastion 계정", self.bastion_user)

        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._validate_accept)
        bb.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(bb)

    def _parse_params(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for ln in self.params.toPlainText().splitlines():
            ln = ln.split("#", 1)[0].strip()
            if not ln:
                continue
            if "=" not in ln:
                raise ValueError(f"'{ln}' — NAME=value 형식이어야 합니다")
            k, v = ln.split("=", 1)
            out[k.strip()] = v.strip()
        validate_env(out)      # 셸 메타문자·잘못된 이름은 여기서 거부
        return out

    def _validate_accept(self) -> None:
        if not self.address.text().strip():
            self.address.setPlaceholderText("주소는 필수입니다")
            self.address.setStyleSheet("border:1px solid #F85149")
            return
        try:
            self._parse_params()
        except ValueError as e:
            self.params.setStyleSheet("border:1px solid #F85149")
            self.params.setToolTip(str(e))
            return
        self.accept()

    def host(self) -> Host:
        return Host(
            host_id=self._host_id,
            name=self.name.text().strip() or self.address.text().strip(),
            address=self.address.text().strip(),
            port=self.port.value(),
            platform=self.platform.currentText(),
            project=self.project.text().strip() or "기본",
            group=self.group.text().strip() or "서버",
            username=self.username.text().strip() or "root",
            auth_kind=self.auth.currentText(),
            params=self._parse_params(),
            timeout=self.timeout.value(),
            use_sudo=self.sudo.isChecked(),
            use_bastion=self.use_bastion.isChecked(),
            bastion_host=self.bastion_host.text().strip() or None,
            bastion_user=self.bastion_user.text().strip() or None,
            environment=self.environment.currentText(),
            criticality=self.criticality.currentText(),
            owner=self.owner.text().strip(),
            role=self.role.text().strip(),
            tags=[t.strip() for t in self.tags.text().split(",") if t.strip()],
        )


class ExceptionDialog(QDialog):
    """예외/보상통제 승인 — 판정은 그대로 두고 옆에 승인·만료를 단다."""

    def __init__(self, host_id: str, rule_id: str, label: str, current: RiskException | None = None,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(f"예외 승인 — {rule_id}")
        self._host_id, self._rule_id = host_id, rule_id
        form = QFormLayout()
        form.addRow(QLabel(f"<b>{label}</b>"))
        self.reason = QPlainTextEdit(current.reason if current else "")
        self.reason.setPlaceholderText("왜 예외인가 — 업무상 필요, 대체 통제 등")
        self.reason.setMaximumHeight(90)
        self.control = QLineEdit(current.control if current else "")
        self.control.setPlaceholderText("보상통제: AD 정책 중앙관리 + MFA + PAM …")
        self.approver = QLineEdit(current.approver if current else "")
        self.expires = QDateEdit()
        self.expires.setCalendarPopup(True)
        self.expires.setDisplayFormat("yyyy-MM-dd")
        self.expires.setDate(QDate.fromString(current.expires_at, "yyyy-MM-dd") if current and current.expires_at
                             else QDate.currentDate().addMonths(6))
        form.addRow("사유", self.reason)
        form.addRow("보상통제", self.control)
        form.addRow("승인자", self.approver)
        form.addRow("만료일", self.expires)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._validate_accept)
        bb.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(bb)

    def _validate_accept(self) -> None:
        if not self.reason.toPlainText().strip():
            self.reason.setStyleSheet("border:1px solid #F85149")
            return
        self.accept()

    def exception(self) -> RiskException:
        return RiskException(host_id=self._host_id, rule_id=self._rule_id,
                             reason=self.reason.toPlainText().strip(), control=self.control.text().strip(),
                             approver=self.approver.text().strip(),
                             expires_at=self.expires.date().toString("yyyy-MM-dd"))
