"""멀티실행 페이지 — 체크한 호스트들에 같은 읽기전용 명령을 동시에.

왼쪽 호스트 체크리스트 · 가운데 명령(셸별) + 라이브러리 · 아래 결과표/출력.
실행 전 확인창(읽기 전용 · 대상 N대 · 예상 변경 없음). 쓰기 명령은 정책이 막는다(UI·워커 양쪽).
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QObject, QRunnable, Qt, QThreadPool, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from infraguard.assets.models import Host
from infraguard.orchestrator import multiexec as mx

SHELL_LABEL = {"sh": "sh (Unix/Linux)", "powershell": "PowerShell (Windows)", "raw": "장비 CLI"}


class _Emitter(QObject):
    done = Signal(object)   # ExecOutcome


class _Job(QRunnable):
    def __init__(self, host: Host, cred, cmd: str, approve, changed, emitter: _Emitter, timeout: int) -> None:  # noqa: ANN001
        super().__init__()
        self.args = (host, cred, cmd, approve, changed, timeout)
        self.emitter = emitter

    def run(self) -> None:
        host, cred, cmd, approve, changed, timeout = self.args
        self.emitter.done.emit(mx.run_one(host, cred, cmd, approve, changed, timeout=timeout))


class AddEntryDialog(QDialog):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle("라이브러리에 명령 추가 (읽기 전용만)")
        form = QFormLayout()
        self.category = QLineEdit("Custom")
        self.name = QLineEdit()
        self.sh = QLineEdit()
        self.ps = QLineEdit()
        self.raw = QLineEdit()
        form.addRow("분류", self.category)
        form.addRow("이름", self.name)
        form.addRow("sh", self.sh)
        form.addRow("powershell", self.ps)
        form.addRow("장비 CLI", self.raw)
        self.err = QLabel("")
        self.err.setStyleSheet("color:#F85149")
        self.err.setWordWrap(True)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._validate)
        bb.rejected.connect(self.reject)
        lay = QVBoxLayout(self)
        lay.addLayout(form)
        lay.addWidget(self.err)
        lay.addWidget(bb)

    def commands(self) -> dict[str, str]:
        return {k: v for k, v in (("sh", self.sh.text().strip()), ("powershell", self.ps.text().strip()),
                                  ("raw", self.raw.text().strip())) if v}

    def _validate(self) -> None:
        bad = mx.validate_entry(self.commands())
        if not self.name.text().strip():
            bad.append("이름이 비어 있음")
        if bad:
            self.err.setText("등록 거부: " + "; ".join(bad))
            return
        self.accept()

    def entry(self) -> dict:
        return {"category": self.category.text().strip() or "Custom", "name": self.name.text().strip(), **self.commands()}


class MultiExecPage(QWidget):
    """ensure_cred(host) -> Credential|None 은 메인윈도가 준다(UI 스레드에서 입력)."""

    library_changed = Signal(list)   # 사용자 항목 목록(config 저장용)

    def __init__(self, ensure_cred: Callable[[Host], object], approve, changed, log_dir: Path,  # noqa: ANN001
                 user_entries: list[dict] | None = None) -> None:
        super().__init__()
        self._ensure_cred, self._approve, self._changed, self._log_dir = ensure_cred, approve, changed, log_dir
        self._user_entries: list[dict] = list(user_entries or [])
        self._hosts: list[Host] = []
        self._results: dict[str, mx.ExecOutcome] = {}
        self._pending = 0
        self._pool = QThreadPool(self)
        self._pool.setMaxThreadCount(8)
        self._emitter = _Emitter()
        self._emitter.done.connect(self._on_done)

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 10)
        split = QSplitter(Qt.Orientation.Horizontal)

        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.addWidget(QLabel("대상 호스트 (체크)"))
        self.host_filter = QLineEdit()
        self.host_filter.setPlaceholderText("필터")
        self.host_filter.textChanged.connect(self._fill_hosts)
        ll.addWidget(self.host_filter)
        self.hosts = QListWidget()
        ll.addWidget(self.hosts, 1)
        hb = QHBoxLayout()
        all_b = QPushButton("전체")
        none_b = QPushButton("해제")
        all_b.clicked.connect(lambda: self._check_all(True))
        none_b.clicked.connect(lambda: self._check_all(False))
        hb.addWidget(all_b)
        hb.addWidget(none_b)
        hb.addStretch(1)
        ll.addLayout(hb)
        split.addWidget(left)

        mid = QWidget()
        ml = QVBoxLayout(mid)
        ml.setContentsMargins(0, 0, 0, 0)
        ml.addWidget(QLabel("명령 라이브러리 (클릭 → 아래 명령칸에 채움)"))
        self.lib = QTreeWidget()
        self.lib.setHeaderHidden(True)
        self.lib.itemClicked.connect(self._on_lib_click)
        ml.addWidget(self.lib, 1)
        lb = QHBoxLayout()
        add = QPushButton("+ 라이브러리 추가")
        add.clicked.connect(self._add_entry)
        lb.addWidget(add)
        lb.addStretch(1)
        ml.addLayout(lb)
        ml.addWidget(QLabel("명령 (호스트 플랫폼별로 그 셸의 명령이 나간다)"))
        self.cmd: dict[str, QLineEdit] = {}
        for sh, label in SHELL_LABEL.items():
            row = QHBoxLayout()
            lab = QLabel(label)
            lab.setFixedWidth(150)
            ed = QLineEdit()
            ed.setPlaceholderText("읽기 전용 명령")
            row.addWidget(lab)
            row.addWidget(ed, 1)
            ml.addLayout(row)
            self.cmd[sh] = ed
        rb = QHBoxLayout()
        self.timeout = QComboBox()
        for t in (30, 60, 120, 300):
            self.timeout.addItem(f"타임아웃 {t}s", t)
        self.timeout.setCurrentIndex(1)
        rb.addWidget(self.timeout)
        rb.addStretch(1)
        self.run_btn = QPushButton("▶ 실행 (확인 후)")
        self.run_btn.setObjectName("primary")
        self.run_btn.clicked.connect(self._run)
        rb.addWidget(self.run_btn)
        ml.addLayout(rb)
        split.addWidget(mid)
        split.setStretchFactor(0, 1)
        split.setStretchFactor(1, 2)
        root.addWidget(split, 2)

        bottom = QSplitter(Qt.Orientation.Horizontal)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["호스트", "셸", "rc", "ms", "첫 줄"])
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.itemSelectionChanged.connect(self._show_output)
        bottom.addWidget(self.table)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.output.setStyleSheet("font-family: Consolas, monospace;")
        bottom.addWidget(self.output)
        root.addWidget(bottom, 3)
        fb = QHBoxLayout()
        self.status = QLabel("")
        self.status.setObjectName("muted")
        fb.addWidget(self.status, 1)
        self.export_btn = QPushButton("결과 내보내기(txt)")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self._export)
        fb.addWidget(self.export_btn)
        root.addLayout(fb)
        self._fill_library()

    # ---------------------------------------------------------------- 호스트
    def set_hosts(self, hosts: list[Host]) -> None:
        self._hosts = list(hosts)
        self._fill_hosts()

    def _fill_hosts(self) -> None:
        checked = {self.hosts.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.hosts.count())
                   if self.hosts.item(i).checkState() == Qt.CheckState.Checked}
        self.hosts.clear()
        q = self.host_filter.text().strip().lower()
        for h in sorted(self._hosts, key=lambda x: (x.project, x.group, x.label)):
            if q and q not in f"{h.project} {h.group} {h.label} {h.address} {h.platform}".lower():
                continue
            it = QListWidgetItem(f"{h.label}   {h.address}  [{h.platform}]  {h.project}/{h.group}")
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(Qt.CheckState.Checked if h.host_id in checked else Qt.CheckState.Unchecked)
            it.setData(Qt.ItemDataRole.UserRole, h.host_id)
            self.hosts.addItem(it)

    def _check_all(self, on: bool) -> None:
        for i in range(self.hosts.count()):
            self.hosts.item(i).setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)

    def checked_hosts(self) -> list[Host]:
        ids = {self.hosts.item(i).data(Qt.ItemDataRole.UserRole) for i in range(self.hosts.count())
               if self.hosts.item(i).checkState() == Qt.CheckState.Checked}
        return [h for h in self._hosts if h.host_id in ids]

    # ---------------------------------------------------------------- 라이브러리
    def _fill_library(self) -> None:
        self.lib.clear()
        cats: dict[str, QTreeWidgetItem] = {}
        for e in mx.load_library(self._user_raw()):
            if e.category not in cats:
                cats[e.category] = QTreeWidgetItem([e.category])
                self.lib.addTopLevelItem(cats[e.category])
            it = QTreeWidgetItem([e.name + ("  (사용자)" if e.user else "")])
            it.setData(0, Qt.ItemDataRole.UserRole, e.commands)
            it.setToolTip(0, "\n".join(f"[{k}] {v}" for k, v in e.commands.items()))
            cats[e.category].addChild(it)
        self.lib.expandAll()

    def _user_raw(self) -> dict:
        raw: dict[str, list] = {}
        for e in self._user_entries:
            raw.setdefault(e.get("category", "Custom"), []).append(e)
        return raw

    def _on_lib_click(self, it: QTreeWidgetItem, _c: int) -> None:
        cmds = it.data(0, Qt.ItemDataRole.UserRole)
        if not cmds:
            return
        for sh, ed in self.cmd.items():
            ed.setText(cmds.get(sh, ""))

    def _add_entry(self) -> None:
        dlg = AddEntryDialog(self)
        if dlg.exec():
            self._user_entries.append(dlg.entry())
            self._fill_library()
            self.library_changed.emit(list(self._user_entries))

    # ---------------------------------------------------------------- 실행
    def cmd_by_shell(self) -> dict[str, str]:
        return {sh: ed.text().strip() for sh, ed in self.cmd.items() if ed.text().strip()}

    def _run(self) -> None:
        hosts = self.checked_hosts()
        if not hosts:
            QMessageBox.information(self, "멀티실행", "대상 호스트를 체크하세요.")
            return
        p = mx.plan(hosts, self.cmd_by_shell())
        text = p.summary()
        if not p.read_only:
            QMessageBox.warning(self, "실행 불가 — 읽기 전용 명령만", text)
            return
        if QMessageBox.question(self, "실행 전 확인", "읽기 전용 명령 ✓\n" + text + "\n\n실행할까요?",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        creds = {}
        for h in hosts:
            c = self._ensure_cred(h)
            if c is None:
                QMessageBox.information(self, "멀티실행", f"{h.label}: 크리덴셜 없음 — 중단")
                return
            creds[h.host_id] = c
        self._results.clear()
        self.table.setRowCount(0)
        self.output.clear()
        self._pending = len(hosts)
        self.run_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.status.setText(f"실행 중… 0/{len(hosts)}")
        self._cmds = p.cmd_by_shell
        timeout = int(self.timeout.currentData())
        for h in hosts:
            self._pool.start(_Job(h, creds[h.host_id], p.cmd_by_shell[mx.shell_for(h)], self._approve, self._changed,
                                  self._emitter, timeout))

    def _on_done(self, r: mx.ExecOutcome) -> None:
        self._results[r.host_id] = r
        row = self.table.rowCount()
        self.table.insertRow(row)
        vals = [r.label, r.shell, "" if r.exit_code is None else str(r.exit_code), str(r.duration_ms),
                (f"✕ {r.error}" if r.error else r.first_line())]
        for c, v in enumerate(vals):
            it = QTableWidgetItem(v)
            it.setData(Qt.ItemDataRole.UserRole, r.host_id)
            if c == 2 and not r.ok:
                it.setForeground(QColor("#F85149"))
            self.table.setItem(row, c, it)
        self._pending -= 1
        done = len(self._results)
        self.status.setText(f"실행 중… {done}/{done + self._pending}" if self._pending else
                            f"완료 {done}대 · 실패 {sum(1 for x in self._results.values() if not x.ok)}대")
        if self._pending == 0:
            self.run_btn.setEnabled(True)
            self.export_btn.setEnabled(True)
            try:
                path = mx.write_audit(self._log_dir, self._cmds, list(self._results.values()))
                self.status.setText(self.status.text() + f" · 감사기록 {path.name}")
            except OSError as e:
                self.status.setText(self.status.text() + f" · 감사기록 실패 {e}")

    def _show_output(self) -> None:
        sel = self.table.selectedItems()
        if not sel:
            return
        r = self._results.get(sel[0].data(Qt.ItemDataRole.UserRole))
        if r:
            self.output.setPlainText((r.stdout or "") + (("\n[stderr]\n" + r.stderr) if r.stderr.strip() else "")
                                     + (f"\n[error] {r.error}" if r.error else ""))

    def _export(self) -> None:
        from PySide6.QtWidgets import QFileDialog
        path, _ = QFileDialog.getSaveFileName(self, "결과 내보내기", "multiexec.txt", "*.txt")
        if path:
            Path(path).write_text(mx.render_text(self._cmds, list(self._results.values())), encoding="utf-8")
            self.status.setText(f"저장됨: {path}")
