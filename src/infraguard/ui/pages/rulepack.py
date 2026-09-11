"""룰팩 관리 페이지(§9) — 카테고리 트리 + 항목 체크 → 프로파일 저장.

- 조치형(write) 스크립트·해시 불일치는 로더가 이미 거부했다. 여기서는 그 목록을 **보여준다**.
- 프로파일은 workspace 가 아니라 rulepacks/<pack>/profiles/ 에 저장(반출 대상).
"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QStandardItem, QStandardItemModel
from PySide6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from infraguard.rulepack.loader import Profile, RulePack, save_profile

ID_ROLE = int(Qt.ItemDataRole.UserRole) + 1
KIND_ROLE = int(Qt.ItemDataRole.UserRole) + 2   # "bundle" | "native"


class RulePackPage(QWidget):
    profiles_changed = Signal()
    import_requested = Signal()          # zip 가져오기 (파일 선택·풀기는 메인윈도가)
    pack_selected = Signal(str)          # rulepacks/<name> 전환

    def __init__(self) -> None:
        super().__init__()
        self._pack: RulePack | None = None
        root = QVBoxLayout(self)

        top = QHBoxLayout()
        self.title = QLabel("룰팩: (없음)")
        self.title.setObjectName("h1")
        top.addWidget(self.title)
        top.addStretch(1)
        self.integrity = QLabel("")
        top.addWidget(self.integrity)
        self.packs = QComboBox()
        self.packs.setToolTip("rulepacks/ 아래 룰팩. 컨설턴트가 자산에 맞게 만든 부분 룰팩을 골라 쓴다.")
        self.packs.activated.connect(lambda _i: self.pack_selected.emit(self.packs.currentData() or ""))
        top.addWidget(self.packs)
        imp = QPushButton("룰팩 가져오기(.zip)")
        imp.clicked.connect(self.import_requested.emit)
        top.addWidget(imp)
        root.addLayout(top)

        body = QHBoxLayout()
        self.tree = QTreeView()
        self.tree.setHeaderHidden(True)
        self.model = QStandardItemModel()
        self.tree.setModel(self.model)
        self.tree.clicked.connect(self._show_detail)
        body.addWidget(self.tree, 2)

        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        body.addWidget(self.detail, 1)
        root.addLayout(body, 1)

        prow = QHBoxLayout()
        prow.addWidget(QLabel("프로파일"))
        self.profile = QComboBox()
        self.profile.currentIndexChanged.connect(self._apply_profile_checks)
        prow.addWidget(self.profile, 1)
        save = QPushButton("현재 선택으로 저장")
        save.clicked.connect(self._save_as)
        prow.addWidget(save)
        root.addLayout(prow)

    # ---------------------------------------------------------------- 표시
    def set_packs(self, names: list[str], current: str | None) -> None:
        self.packs.blockSignals(True)
        self.packs.clear()
        for n in names:
            self.packs.addItem(n, n)
        if current and (i := self.packs.findData(current)) >= 0:
            self.packs.setCurrentIndex(i)
        self.packs.blockSignals(False)

    def load(self, pack: RulePack | None) -> None:
        self._pack = pack
        self.model.clear()
        self.profile.blockSignals(True)
        self.profile.clear()
        if pack is None:
            self.title.setText("룰팩: (없음)")
            self.integrity.setText("")
            self.profile.blockSignals(False)
            return
        self.title.setText(f"룰팩: {pack.name} ({pack.version})"
                           + (f" · 가이드 {len(pack.guide)}항목" if pack.guide else ""))
        if pack.runnable:
            self.integrity.setText("무결성 ✓ 검증됨")
            self.integrity.setStyleSheet("color:#3FB950")
        else:
            self.integrity.setText(f"⚠ 문제 {len(pack.problems)}건 — 실행 차단")
            self.integrity.setStyleSheet("color:#F85149")

        root = self.model.invisibleRootItem()
        b_root = QStandardItem(f"번들 스크립트 ({len(pack.bundles)})")
        b_root.setEditable(False)
        for b in pack.bundles.values():
            it = QStandardItem(f"{b.id}  —  {b.description or b.script.name}   [{', '.join(b.platforms)}]")
            it.setEditable(False)
            it.setCheckable(True)
            it.setData(b.id, ID_ROLE)
            it.setData("bundle", KIND_ROLE)
            b_root.appendRow(it)
        root.appendRow(b_root)

        n_root = QStandardItem(f"네이티브 룰 — SSH 직접점검 ({len(pack.native)})")
        n_root.setEditable(False)
        for rid in pack.native:
            m = pack.rules.get(rid)
            it = QStandardItem(f"{rid}  {m.name if m else ''}   {m.severity if m else ''}")
            it.setEditable(False)
            it.setCheckable(True)
            it.setData(rid, ID_ROLE)
            it.setData("native", KIND_ROLE)
            n_root.appendRow(it)
        root.appendRow(n_root)

        cats: dict[str, QStandardItem] = {}
        m_root = QStandardItem(f"항목 메타 ({len(pack.rules)})")
        m_root.setEditable(False)
        for r in pack.rules.values():
            c = r.category or "기타"
            if c not in cats:
                cats[c] = QStandardItem(c)
                cats[c].setEditable(False)
                m_root.appendRow(cats[c])
            it = QStandardItem(f"{r.id}  {r.name}   {r.severity}")
            it.setEditable(False)
            it.setData(r.id, ID_ROLE)
            cats[c].appendRow(it)
        root.appendRow(m_root)

        if pack.problems:
            p_root = QStandardItem(f"⚠ 로드 거부/문제 ({len(pack.problems)})")
            p_root.setEditable(False)
            for p in pack.problems:
                it = QStandardItem(p)
                it.setEditable(False)
                p_root.appendRow(it)
            root.appendRow(p_root)

        self.tree.expandToDepth(0)
        for pid, prof in pack.profiles.items():
            self.profile.addItem(f"{prof.name} ({pid})", pid)
        self.profile.blockSignals(False)
        self._apply_profile_checks()

    def _show_detail(self, index) -> None:  # noqa: ANN001
        if not self._pack:
            return
        rid = index.data(ID_ROLE)
        kind = index.data(KIND_ROLE)
        if kind == "bundle":
            b = self._pack.bundles[rid]
            self.detail.setPlainText(
                f"{b.id}\n{b.description}\n\n스크립트: {b.script.name}\nSHA-256: {b.sha256}\n"
                f"인터프리터: {b.interpreter or 'shebang'}\n플랫폼: {', '.join(b.platforms)}\n"
                f"타임아웃: {b.timeout}s\nside_effects: {b.side_effects}\n"
                f"동반파일: {', '.join(e.name for e in b.extra_files) or '-'}\n"
                f"provides ({len(b.provides)}): {', '.join(b.provides)}"
            )
        elif rid and rid in self._pack.rules:
            r = self._pack.rules[rid]
            self.detail.setPlainText(
                f"{r.id}  {r.name}\n중요도: {r.severity or '-'}   분류: {r.category or '-'}\n"
                f"수동확인 선언: {'예' if r.manual else '아니오'}\n"
                + ({"yaml": "네이티브 룰 — 선언형 YAML (rulepacks/…/rules/, 해시 검증)",
                    "python": "네이티브 룰 — 파이썬 (앱 동봉, 분기 로직)"}.get(r.kind, "")) + "\n"
                f"{('조치권고: ' + r.remediation) if r.remediation else ''}"
            )

    # ---------------------------------------------------------------- 프로파일
    def _iter_checkable(self):  # noqa: ANN202
        root = self.model.invisibleRootItem()
        for i in range(root.rowCount()):
            grp = root.child(i)
            for j in range(grp.rowCount()):
                it = grp.child(j)
                if it.isCheckable():
                    yield it

    def _apply_profile_checks(self) -> None:
        if not self._pack:
            return
        pid = self.profile.currentData()
        prof = self._pack.profiles.get(pid) if pid else None
        for it in self._iter_checkable():
            rid, kind = it.data(ID_ROLE), it.data(KIND_ROLE)
            on = bool(prof) and ((kind == "bundle" and rid in prof.bundles) or
                                 (kind == "native" and rid in prof.native))
            it.setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)

    def current_selection(self) -> tuple[list[str], list[str]]:
        bundles, native = [], []
        for it in self._iter_checkable():
            if it.checkState() == Qt.CheckState.Checked:
                (bundles if it.data(KIND_ROLE) == "bundle" else native).append(it.data(ID_ROLE))
        return bundles, native

    def _save_as(self) -> None:
        if not self._pack:
            return
        bundles, native = self.current_selection()
        if not bundles and not native:
            QMessageBox.information(self, "프로파일", "선택된 번들/룰이 없습니다.")
            return
        pid, ok = QInputDialog.getText(self, "프로파일 저장", "프로파일 ID (영문/숫자/-)")
        if not ok or not pid.strip():
            return
        pid = "".join(c for c in pid.strip() if c.isalnum() or c in "-_")
        prof = Profile(id=pid, name=pid, bundles=bundles, native=native)
        path = save_profile(self._pack, prof)
        self._pack.profiles[pid] = prof
        QMessageBox.information(self, "프로파일", f"저장됨: {path}")
        self.load(self._pack)
        i = self.profile.findData(pid)
        if i >= 0:
            self.profile.setCurrentIndex(i)
        self.profiles_changed.emit()
