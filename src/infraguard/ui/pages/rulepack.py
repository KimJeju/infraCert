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
    QHeaderView,
    QInputDialog,
    QLabel,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTextEdit,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from infraguard.rulepack.guide import format_guide
from infraguard.rulepack.loader import Profile, RulePack, save_profile
from infraguard.ui.pages.rule_tester import RuleTesterPanel

ID_ROLE = int(Qt.ItemDataRole.UserRole) + 1
KIND_ROLE = int(Qt.ItemDataRole.UserRole) + 2   # "bundle" | "native" | "group"
PLATFORM_GROUP = {"U": "Unix (Linux/AIX/Solaris/HP-UX)", "W": "Windows 서버", "D": "Oracle DB",
                  "N": "네트워크 장비 (Cisco IOS / Junos)", "WEB": "웹 서비스", "PC": "PC", "HV": "가상화", "CA": "클라우드"}


class RulePackPage(QWidget):
    profiles_changed = Signal()
    import_requested = Signal()          # zip 가져오기 (파일 선택·풀기는 메인윈도가)
    build_requested = Signal(list, list) # (bundles, native) 체크한 항목으로 부분 룰팩 zip
    export_requested = Signal()          # 현재 룰팩 전체를 zip 으로
    delete_requested = Signal(str)       # rulepacks/<name> 삭제(확인은 메인윈도가)
    pack_selected = Signal(str)          # rulepacks/<name> 전환
    diff_requested = Signal()            # 다른 룰팩(설치본 또는 zip)과 manifest 비교

    def __init__(self) -> None:
        super().__init__()
        self._pack: RulePack | None = None
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 10, 12, 10)
        root.setSpacing(8)

        # 1행: 제목 · 무결성 ─── 룰팩 선택
        top = QHBoxLayout()
        self.title = QLabel("룰팩: (없음)")
        self.title.setObjectName("h1")
        top.addWidget(self.title)
        self.integrity = QLabel("")
        top.addWidget(self.integrity)
        top.addStretch(1)
        top.addWidget(QLabel("룰팩"))
        self.packs = QComboBox()
        self.packs.setMinimumWidth(220)
        self.packs.setToolTip("rulepacks/ 아래 룰팩. 컨설턴트가 자산에 맞게 만든 부분 룰팩을 골라 쓴다.")
        self.packs.activated.connect(lambda _i: self.pack_selected.emit(self.packs.currentData() or ""))
        top.addWidget(self.packs)
        root.addLayout(top)

        # 2행: 룰팩 단위 동작(가져오기 · 내보내기 · 삭제)
        tb = QHBoxLayout()
        imp = QPushButton("가져오기(.zip)")
        imp.setToolTip("컨설턴트가 만든 룰팩 zip 을 rulepacks/ 에 푼다(경로탈출·심볼릭링크 거부, 무결성 검사)")
        imp.clicked.connect(self.import_requested.emit)
        exp = QPushButton("내보내기(전체 zip)")
        exp.setToolTip("현재 룰팩 전체(번들·룰·프로파일·가이드)를 zip 으로")
        exp.clicked.connect(self.export_requested.emit)
        zipb = QPushButton("내보내기(선택 항목만)")
        zipb.setToolTip("체크한 번들·룰(+그 항목의 가이드)만 담은 부분 룰팩. 고객사 반입용.")
        zipb.clicked.connect(lambda: self.build_requested.emit(*self.current_selection()))
        cmp = QPushButton("비교…")
        cmp.setToolTip("현재 룰팩과 다른 룰팩(설치본 또는 zip)의 manifest 를 비교 — 추가/삭제/판정 조건·메타 변경/프로파일")
        cmp.clicked.connect(self.diff_requested.emit)
        rm = QPushButton("삭제")
        rm.setObjectName("danger")
        rm.setToolTip("현재 선택한 룰팩 폴더를 rulepacks/ 에서 지운다(가져온 부분 룰팩 정리용)")
        rm.clicked.connect(lambda: self.delete_requested.emit(self.packs.currentData() or ""))
        for b in (imp, exp, zipb, cmp):
            tb.addWidget(b)
        tb.addStretch(1)
        tb.addWidget(rm)
        root.addLayout(tb)

        # 본문: 트리 | 상세 (스플리터, 기본 3:2)
        self.tree = QTreeView()
        self.tree.setHeaderHidden(True)
        # 헤더 숨김 + stretchLastSection(기본 True) 조합은 긴 룰 이름을 잘라 버리고 가로 스크롤바를 안 만든다
        self.tree.header().setStretchLastSection(False)
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.tree.setHorizontalScrollMode(QTreeView.ScrollMode.ScrollPerPixel)
        self.tree.setMinimumWidth(360)
        self.model = QStandardItemModel()
        self.tree.setModel(self.model)
        self._syncing = False
        self.model.itemChanged.connect(self._on_item_changed)
        self.tree.clicked.connect(self._show_detail)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(4)
        rl.addWidget(QLabel("상세 — 항목을 누르면 스크립트/룰 정보와 가이드(판단기준·조치·사례)"))
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        self.detail.setMinimumWidth(300)
        self.detail.setPlaceholderText("왼쪽에서 번들·룰·항목을 선택하세요.")
        rl.addWidget(self.detail, 2)
        self.tester = RuleTesterPanel()
        rl.addWidget(self.tester, 3)

        self.split = QSplitter(Qt.Orientation.Horizontal)
        self.split.addWidget(self.tree)
        self.split.addWidget(right)
        self.split.setStretchFactor(0, 3)
        self.split.setStretchFactor(1, 2)
        self.split.setSizes([600, 400])
        root.addWidget(self.split, 1)

        # 하단: 프로파일(체크 상태의 이름)
        prow = QHBoxLayout()
        prow.addWidget(QLabel("프로파일"))
        self.profile = QComboBox()
        self.profile.setMinimumWidth(260)
        self.profile.currentIndexChanged.connect(self._apply_profile_checks)
        prow.addWidget(self.profile)
        save = QPushButton("현재 체크 상태를 프로파일로 저장")
        save.clicked.connect(self._save_as)
        prow.addWidget(save)
        prow.addStretch(1)
        self.sel_label = QLabel("")
        self.sel_label.setObjectName("muted")
        prow.addWidget(self.sel_label)
        self.model.itemChanged.connect(lambda _i: self._update_sel_label())
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
            self.integrity.setText(f"무결성 ✓ 검증됨 · sha256 {pack.sha256[:12]}"
                                   + (f" · {pack.meta.get('framework', '')} {pack.meta.get('guide_version', '')}".rstrip()
                                      if pack.meta.get("framework") or pack.meta.get("guide_version") else ""))
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

        # 네이티브 룰: 플랫폼 → 분류 → 룰. 그룹 체크는 하위 전부 토글(_on_item_changed).
        n_root = QStandardItem(f"네이티브 룰 — 직접점검 ({len(pack.native)})")
        n_root.setEditable(False)
        plat_nodes: dict[str, QStandardItem] = {}
        cat_nodes: dict[tuple[str, str], QStandardItem] = {}
        for rid in pack.native:
            m = pack.rules.get(rid)
            plat = PLATFORM_GROUP.get(rid.split("-")[0], "기타")
            if plat not in plat_nodes:
                g = QStandardItem(plat)
                g.setEditable(False)
                g.setCheckable(True)
                g.setData("group", KIND_ROLE)
                plat_nodes[plat] = g
                n_root.appendRow(g)
            cat = (m.category if m and m.category else "기타")
            key = (plat, cat)
            if key not in cat_nodes:
                c = QStandardItem(cat)
                c.setEditable(False)
                c.setCheckable(True)
                c.setData("group", KIND_ROLE)
                cat_nodes[key] = c
                plat_nodes[plat].appendRow(c)
            it = QStandardItem(f"{rid}  {m.name if m else ''}   {m.severity if m else ''}")
            it.setEditable(False)
            it.setCheckable(True)
            it.setData(rid, ID_ROLE)
            it.setData("native", KIND_ROLE)
            cat_nodes[key].appendRow(it)
        for plat, g in plat_nodes.items():
            n = sum(cat_nodes[k].rowCount() for k in cat_nodes if k[0] == plat)
            g.setText(f"{plat} ({n})")
        for (_, cat), c in cat_nodes.items():
            c.setText(f"{cat} ({c.rowCount()})")
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
            self.tester.set_spec(None)
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
            self.tester.set_spec(self._pack.specs.get(rid))
            self.detail.setPlainText(
                f"{r.id}  {r.name}\n중요도: {r.severity or '-'}   분류: {r.category or '-'}\n"
                f"수동확인 선언: {'예' if r.manual else '아니오'}\n"
                + ({"yaml": "네이티브 룰 — 선언형 YAML (rulepacks/…/rules/, 해시 검증)",
                    "python": "네이티브 룰 — 파이썬 (앱 동봉, 분기 로직)"}.get(r.kind, "")) + "\n"
                f"{('조치권고: ' + r.remediation) if r.remediation else ''}"
                + (("\n\n— 가이드 —\n" + format_guide(self._pack.guide[rid])) if rid in self._pack.guide else "")
            )

    def select_rule(self, rule_id: str) -> bool:
        """트리에서 룰을 찾아 선택·상세·테스터를 띄운다(결과 탭 '해당 룰' 링크)."""
        for it in self._iter_checkable():
            if it.data(ID_ROLE) == rule_id:
                idx = it.index()
                self.tree.scrollTo(idx)
                self.tree.setCurrentIndex(idx)
                self._show_detail(idx)
                return True
        return False

    # ---------------------------------------------------------------- 프로파일
    def _iter_checkable(self):  # noqa: ANN202
        """체크 가능한 말단(번들·룰)만. 그룹 노드는 제외 — 깊이 무관하게 재귀."""
        def walk(node):  # noqa: ANN001,ANN202
            for i in range(node.rowCount()):
                ch = node.child(i)
                if ch.data(KIND_ROLE) in ("bundle", "native"):
                    yield ch
                else:
                    yield from walk(ch)
        yield from walk(self.model.invisibleRootItem())

    def _on_item_changed(self, item) -> None:  # noqa: ANN001
        """그룹 체크 → 하위 전부. 말단 체크 → 상위 그룹 상태(전부/일부/없음) 갱신."""
        if self._syncing:
            return
        self._syncing = True
        try:
            if item.data(KIND_ROLE) == "group":
                st = item.checkState()
                if st != Qt.CheckState.PartiallyChecked:
                    def down(node):  # noqa: ANN001
                        for i in range(node.rowCount()):
                            ch = node.child(i)
                            if ch.isCheckable():
                                ch.setCheckState(st)
                            down(ch)
                    down(item)
            parent = item.parent()
            while parent is not None and parent.data(KIND_ROLE) == "group":
                states = {parent.child(i).checkState() for i in range(parent.rowCount())}
                parent.setCheckState(Qt.CheckState.Checked if states == {Qt.CheckState.Checked}
                                     else Qt.CheckState.Unchecked if states == {Qt.CheckState.Unchecked}
                                     else Qt.CheckState.PartiallyChecked)
                parent = parent.parent()
        finally:
            self._syncing = False

    def _apply_profile_checks(self) -> None:
        if not self._pack:
            return
        pid = self.profile.currentData()
        prof = self._pack.profiles.get(pid) if pid else None
        self._syncing = True
        try:
            for it in self._iter_checkable():
                rid, kind = it.data(ID_ROLE), it.data(KIND_ROLE)
                on = bool(prof) and ((kind == "bundle" and rid in prof.bundles) or
                                     (kind == "native" and rid in prof.native))
                it.setCheckState(Qt.CheckState.Checked if on else Qt.CheckState.Unchecked)
        finally:
            self._syncing = False
        for it in list(self._iter_checkable()):
            self._on_item_changed(it)          # 상위 그룹 상태 재계산
        self._update_sel_label()

    def _update_sel_label(self) -> None:
        if self._syncing or not self._pack:
            return
        b, n = self.current_selection()
        self.sel_label.setText(f"체크: 번들 {len(b)} · 룰 {len(n)}")

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
