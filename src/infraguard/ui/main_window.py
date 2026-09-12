"""메인 윈도우 — 사이드바 + 탭 + 상태바 조립, 스캔 오케스트레이션(§1·§2)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox,
    QCheckBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTreeView,
    QVBoxLayout,
    QWidget,
)

from infraguard import config
from infraguard.assets.models import Host
from infraguard.assets.store import AssetStore
from infraguard.core.ids import new_scan_id
from infraguard.core.models import HostResult, ScanResult
from infraguard.core.status import Severity, Status
from infraguard.credentials.session import CredentialSession
from infraguard.orchestrator.results_store import ResultsStore
from infraguard.reporting import html as html_report
from infraguard.reporting import xlsx as xlsx_report
from infraguard.result import diff as _diff
from infraguard.result import risk as _risk
from infraguard.rulepack import loader as rp_loader
from infraguard.rulepack.loader import RulePack
from infraguard.ui.dialogs import AssetEditDialog, CredPromptDialog, HostKeyDialog
from infraguard.ui.exit_flow import CONFIRM_SCANNING, WARN_UNEXPORTED, ExitState, exit_gate
from infraguard.ui.host_card import HostCard
from infraguard.ui.models_qt import HOST_ID_ROLE, AssetTreeModel, StatusDelegate
from infraguard.ui.pages.dashboard import DashboardPage
from infraguard.ui.pages.manual import ManualBenchPage
from infraguard.ui.pages.multiexec import MultiExecPage
from infraguard.ui.pages.result import ResultPage
from infraguard.ui.pages.rulepack import RulePackPage
from infraguard.ui.pages.scan import ScanPage
from infraguard.ui.pages.settings import SettingsPage
from infraguard.ui.pages.sftp import SftpPage
from infraguard.ui.terminal import TerminalPage
from infraguard.ui.titlebar import CURSORS, TitleBar, edges_at
from infraguard.ui.workers import ScanController, build_job
from infraguard.workspace.manager import Workspace

TERMINAL_NOTICE = (
    "자동 진단(Bundle 실행)은 Read-only 이며 대상 시스템을 변경하지 않습니다.\n\n"
    "터미널 탭에서 사용자가 직접 입력하는 명령은 이 보장의 대상이 아니며 사용자 책임입니다.\n"
    "입력·출력은 workspace/logs/terminal/ 에 기록되며(비밀번호는 마스킹) 종료 시 삭제됩니다."
)
log = logging.getLogger(__name__)


@dataclass
class AppContext:
    workspace: Workspace
    assets: AssetStore
    results: ResultsStore
    creds: CredentialSession
    config: dict


class MainWindow(QMainWindow):
    RESIZE_MARGIN = 5

    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.setWindowTitle("InfraGuard")
        self.setObjectName("root")
        self.resize(1360, 860)
        self.setMinimumSize(1100, 700)
        # OS 창 테두리 없이 자체 타이틀바. 리사이즈는 contentsMargins 띠(RESIZE_MARGIN)에서.
        self.setWindowFlags(Qt.WindowType.Window | Qt.WindowType.FramelessWindowHint)
        self.setContentsMargins(*([self.RESIZE_MARGIN] * 4))
        self.setMouseTracking(True)

        self._scan_id: str | None = None
        self._scanning = False
        self._unexported = False
        self._stages: dict[str, str] = {}
        self._pcts: dict[str, int] = {}
        self._terminals: list[TerminalPage] = []
        self._sftps: list[SftpPage] = []
        self._notice_shown = False

        self.controller = ScanController()
        self.controller.host_key_bridge.request.connect(self._on_host_key)
        self.pack: RulePack | None = self._load_rulepack()

        self._build_menu()
        self._build_body()
        self._wire_controller()
        self._refresh_assets()
        self._refresh_dashboard()
        self._refresh_profiles()

    def _load_rulepack(self, name: str | None = None) -> RulePack | None:
        """rulepacks/<name>. name 없으면 config 의 rulepack, 그것도 없으면 첫 번째."""
        packs = rp_loader.list_packs()
        if not packs:
            return None
        want = name or str(self.ctx.config.get("rulepack") or "")
        chosen = next((p for p in packs if p.name == want), packs[0])
        try:
            return rp_loader.load(chosen)
        except Exception as e:  # noqa: BLE001 - 룰팩 깨져도 앱은 떠야 한다(문제를 보여준다)
            log.exception("rulepack load failed")
            return RulePack(name=chosen.name, version="?", root=chosen, bundles={}, native=[],
                            rules={}, profiles={}, integrity_ok=False, problems=[f"로드 실패: {e}"])

    def _switch_rulepack(self, name: str) -> None:
        if not name or self._scanning:
            return
        self.pack = self._load_rulepack(name)
        self.ctx.config["rulepack"] = name
        config.save(self.ctx.config)
        self._refresh_profiles()

    def _import_rulepack(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "룰팩 가져오기", "", "룰팩 zip (*.zip)")
        if not path:
            return
        from pathlib import Path

        from infraguard.rulepack import importer
        try:
            name = importer.pack_name(Path(path))
            replace = False
            if (rp_loader.rulepacks_root() / name).exists():
                if QMessageBox.question(self, "룰팩 가져오기", f"'{name}' 이(가) 이미 있습니다. 덮어쓸까요?") \
                        != QMessageBox.StandardButton.Yes:
                    return
                replace = True
            dest, pack = importer.import_zip(Path(path), replace=replace)
        except Exception as e:  # noqa: BLE001 - zip 검사 실패·manifest 오류 전부 사용자에게
            QMessageBox.warning(self, "룰팩 가져오기 실패", str(e))
            return
        msg = f"{dest.name}: 번들 {len(pack.bundles)} · 네이티브 {len(pack.native)} · 가이드 {len(pack.guide)}항목"
        if not pack.runnable:
            msg += f"\n⚠ 문제 {len(pack.problems)}건 — 실행 차단 (룰팩 탭에서 확인)"
        QMessageBox.information(self, "룰팩 가져오기", msg)
        self._switch_rulepack(dest.name)

    def _build_rulepack(self, bundles: list, native: list) -> None:
        """룰팩 탭에서 체크한 항목만 담은 zip. 가이드는 현재 팩의 guide/ 에서 해당 항목만 딸려간다."""
        if not self.pack:
            return
        if not bundles and not native:
            QMessageBox.information(self, "룰팩 zip", "체크된 번들/룰이 없습니다.")
            return
        name, ok = QInputDialog.getText(self, "룰팩 zip", "룰팩 이름 (영문/숫자/-)", text=f"{self.pack.name}-subset")
        if not ok or not name.strip():
            return
        name = "".join(c for c in name.strip() if c.isalnum() or c in "-_.") or "subset"
        path, _ = QFileDialog.getSaveFileName(self, "룰팩 zip 저장", f"{name}.rulepack.zip", "zip (*.zip)")
        if not path:
            return
        from pathlib import Path

        from infraguard.rulepack import builder
        try:
            st = builder.build(self.pack.root, name, Path(path), rules=list(native), bundles=list(bundles),
                               guide_items=list(self.pack.guide.values()), version=self.pack.version or "1.0")
        except Exception as e:  # noqa: BLE001 - 파일 없음·스키마 오류 전부 사용자에게
            QMessageBox.warning(self, "룰팩 zip 실패", str(e))
            return
        QMessageBox.information(
            self, "룰팩 zip",
            f"저장됨: {path}\n번들 {st['bundles']} · 네이티브 룰 {st['native']} · 항목 메타 {st['rules_meta']} · 가이드 {st['guide']}",
        )

    def _export_rulepack(self) -> None:
        """현재 룰팩 전체(번들·룰·프로파일·가이드)를 zip 으로. 다른 PC 의 '가져오기'로 그대로 복원된다."""
        if not self.pack:
            return
        path, _ = QFileDialog.getSaveFileName(self, "룰팩 내보내기", f"{self.pack.name}.rulepack.zip", "zip (*.zip)")
        if not path:
            return
        from pathlib import Path

        from infraguard.rulepack import builder
        try:
            st = builder.build(self.pack.root, self.pack.name, Path(path), profiles=list(self.pack.profiles),
                               rules=list(self.pack.native), bundles=list(self.pack.bundles),
                               guide_items=list(self.pack.guide.values()), version=self.pack.version or "1.0")
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "룰팩 내보내기 실패", str(e))
            return
        QMessageBox.information(self, "룰팩 내보내기",
                                f"저장됨: {path}\n번들 {st['bundles']} · 룰 {st['native']} · 가이드 {st['guide']}")

    def _diff_rulepack(self) -> None:
        """현재 룰팩 vs (설치된 다른 룰팩 | zip). manifest 만 읽는다."""
        if self.pack is None:
            return
        from PySide6.QtWidgets import QInputDialog

        from infraguard.rulepack import diff as rp_diff
        others = [p.name for p in rp_loader.list_packs() if p.name != self.pack.name]
        choices = [*others, "zip 파일 선택…"]
        pick, ok = QInputDialog.getItem(self, "룰팩 비교", f"기준: {self.pack.name} {self.pack.version}\n비교 대상:",
                                        choices, 0, False)
        if not ok:
            return
        from pathlib import Path
        if pick == "zip 파일 선택…":
            path, _ = QFileDialog.getOpenFileName(self, "룰팩 zip", "", "*.zip")
            if not path:
                return
            target = Path(path)
        else:
            target = rp_loader.rulepacks_root() / pick
        try:
            d = rp_diff.diff(rp_diff.load_manifest(self.pack.root), rp_diff.load_manifest(target))
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "룰팩 비교 실패", str(e))
            return
        self._show_text(f"룰팩 비교 — {d.a} → {d.b}", rp_diff.render(d))

    def _delete_rulepack(self, name: str) -> None:
        import shutil

        root = rp_loader.rulepacks_root().resolve()
        target = (root / name).resolve() if name else None
        if not name or target.parent != root or not target.exists():
            return
        if self._scanning:
            QMessageBox.information(self, "룰팩 삭제", "진단 중에는 삭제할 수 없습니다.")
            return
        if QMessageBox.question(self, "룰팩 삭제", f"'{name}' 폴더를 완전히 지울까요?\n{target}") \
                != QMessageBox.StandardButton.Yes:
            return
        shutil.rmtree(target)
        self.pack = self._load_rulepack()
        self.ctx.config["rulepack"] = self.pack.name if self.pack else ""
        config.save(self.ctx.config)
        self._refresh_profiles()

    def _refresh_profiles(self) -> None:
        self.rulepack.set_packs([p.name for p in rp_loader.list_packs()], self.pack.name if self.pack else None)
        self.rulepack.load(self.pack)
        self.manual.set_guide(self.pack.guide if self.pack else {},
                              self.pack.remediation_map() if self.pack else {})
        items = []
        if self.pack:
            for pid, p in self.pack.profiles.items():
                desc = (f"번들 {len(p.bundles)}개 · 네이티브 룰 {len(p.native)}개"
                        + (f" · 제외 {len(p.exclude)}" if p.exclude else ""))
                items.append((pid, f"{p.name}", desc))
        self.scan.set_profiles(items)

    # ------------------------------------------------------------------ 구성
    def _build_menu(self) -> None:
        # 타이틀바 + 메뉴바를 한 컨테이너에 쌓아 메뉴 영역으로 올린다(프레임리스라 OS 타이틀바가 없다)
        self.titlebar = TitleBar("INFRAGUARD", self)
        mb = self.menuBar()
        self._top = QWidget(self)
        tl = QVBoxLayout(self._top)
        tl.setContentsMargins(0, 0, 0, 0)
        tl.setSpacing(0)
        tl.addWidget(self.titlebar)
        tl.addWidget(mb)
        self.setMenuWidget(self._top)
        m_file = mb.addMenu("파일")
        m_file.addAction("진단 세션 내보내기(zip)…", self._export_session)
        m_file.addAction("진단 세션 가져오기(zip)…", self._import_session)
        m_file.addSeparator()
        m_file.addAction("완전삭제 후 종료", self.close)
        m_asset = mb.addMenu("자산")
        m_asset.addAction("자산 추가", self._add_asset)
        m_asset.addAction("자산 가져오기(JSON)", self._import_assets)
        m_scan = mb.addMenu("진단")
        m_scan.addAction("선택 호스트 진단 (Ctrl/Shift 다중선택, 그룹 선택 시 하위 전부)", self._start_scan)
        m_scan.addAction("모든 호스트 진단", self._start_scan_all)
        mb.addMenu("도구").addAction("지금 완전삭제", self._sanitize_now)
        mb.addMenu("도움말").addAction("정보", self._about)

        # 참조를 self 에 붙잡아 둔다. 지역변수로 두면 파이썬 GC 가 회수해 코너 위젯이 사라진다.
        self._menu_corner = QWidget(mb)
        cl = QHBoxLayout(self._menu_corner)
        cl.setContentsMargins(0, 0, 8, 0)
        cl.setSpacing(10)
        self.cred_lbl = QLabel("● 크리덴셜 잠김")
        self.cred_lbl.setStyleSheet("color:#8B949E")
        cl.addWidget(self.cred_lbl)
        wipe = QPushButton("완전삭제")
        wipe.setObjectName("danger")
        wipe.clicked.connect(self._sanitize_now)
        cl.addWidget(wipe)
        mb.setCornerWidget(self._menu_corner, Qt.Corner.TopRightCorner)

    def _build_body(self) -> None:
        splitter = QSplitter(Qt.Orientation.Horizontal)

        side = QWidget()
        side.setObjectName("sidebar")
        sl = QVBoxLayout(side)
        sl.setContentsMargins(10, 10, 10, 10)
        sl.setSpacing(8)
        st = QLabel("자산")
        st.setObjectName("sidebar-title")
        sl.addWidget(st)
        self.filter = QLineEdit()
        self.filter.setClearButtonEnabled(True)
        self.filter.setPlaceholderText("필터 / 쿼리: os=linux env=PROD crit=CRITICAL tag=dmz")
        self.filter.setToolTip("공백 = AND. key=a,b = OR. key!=v 제외. 키: os env crit role tag group project owner name addr\n"
                               "그 외 단어는 이름·주소·그룹·고객사 부분일치")
        self.filter.textChanged.connect(self._refresh_assets)
        sl.addWidget(self.filter)
        grow = QHBoxLayout()
        self.groups = QComboBox()
        self.groups.setToolTip("동적 그룹 — 저장한 쿼리. 새 자산이 조건에 맞으면 자동으로 포함된다")
        self.groups.activated.connect(self._apply_group)
        grow.addWidget(self.groups, 1)
        gsave = QPushButton("그룹 저장")
        gsave.setToolTip("현재 필터 쿼리를 동적 그룹으로 저장(config.json)")
        gsave.clicked.connect(self._save_group)
        grow.addWidget(gsave)
        gdel = QPushButton("×")
        gdel.setFixedWidth(28)
        gdel.setToolTip("선택한 동적 그룹 삭제")
        gdel.clicked.connect(self._delete_group)
        grow.addWidget(gdel)
        sl.addLayout(grow)
        self._fill_groups()
        self.tree = QTreeView()
        self.tree.setHeaderHidden(True)
        self.tree.header().setStretchLastSection(False)          # 긴 호스트 이름 → 가로 스크롤(잘림 대신)
        self.tree.header().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.tree.setHorizontalScrollMode(QTreeView.ScrollMode.ScrollPerPixel)
        self.tree.setSelectionMode(QTreeView.SelectionMode.ExtendedSelection)
        self.model = AssetTreeModel()
        self.tree.setModel(self.model)
        self.tree.setItemDelegate(StatusDelegate())
        self.tree.doubleClicked.connect(self._edit_selected)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._tree_menu)
        sl.addWidget(self.tree, 1)
        self.card = HostCard()                       # 세션 매니저: 선택 호스트 요약 + 바로가기
        self.card.action.connect(self._card_action)
        sl.addWidget(self.card)
        self.tree.selectionModel().selectionChanged.connect(lambda *_a: self._update_card())
        brow = QHBoxLayout()
        add = QPushButton("+ 자산")
        imp = QPushButton("가져오기")
        add.clicked.connect(self._add_asset)
        imp.clicked.connect(self._import_assets)
        brow.addWidget(add)
        brow.addWidget(imp)
        sl.addLayout(brow)
        splitter.addWidget(side)

        self.tabs = QTabWidget()
        self.dashboard = DashboardPage()
        self.scan = ScanPage()
        self.result = ResultPage()
        self.manual = ManualBenchPage()
        # 탭 라벨은 폰트 의존 글리프를 쓰지 않는다(고객사 PC 폰트가 제각각). ▶ 는 맑은고딕에 있다.
        self.tabs.addTab(self.dashboard, "대시보드")
        self.tabs.addTab(self.scan, "▶ 진단")
        self.tabs.addTab(self.result, "결과")
        self.tabs.addTab(self.manual, "수동확인")
        self.rulepack = RulePackPage()
        self.rulepack.profiles_changed.connect(self._refresh_profiles)
        self.rulepack.import_requested.connect(self._import_rulepack)
        self.rulepack.build_requested.connect(self._build_rulepack)
        self.rulepack.export_requested.connect(self._export_rulepack)
        self.rulepack.delete_requested.connect(self._delete_rulepack)
        self.rulepack.pack_selected.connect(self._switch_rulepack)
        self.rulepack.diff_requested.connect(self._diff_rulepack)
        self.tabs.addTab(self.rulepack, "룰팩")
        pk_label = f"{self.pack.name} {self.pack.version}" if self.pack else "(없음)"
        self.settings = SettingsPage(self.ctx.config, self.ctx.workspace.layout,
                                     self._engine_version(), pk_label)
        self.settings.saved.connect(self._on_settings_saved)
        self.settings.sanitize_requested.connect(self._sanitize_now)
        self.multi = MultiExecPage(self._ensure_cred, self.controller.host_key_bridge.ask,
                                   self.controller.host_key_bridge.ask_changed,
                                   self.ctx.workspace.layout.logs / "multiexec",
                                   user_entries=list(self.ctx.config.get("command_library") or []))
        self.multi.library_changed.connect(self._save_library)
        self.tabs.addTab(self.multi, "멀티실행")
        self.tabs.addTab(self.settings, "설정")
        self.FIXED_TABS = self.tabs.count()          # 고정 탭은 닫히지 않는다
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self._close_tab)
        for i in range(self.FIXED_TABS):
            self.tabs.tabBar().setTabButton(i, self.tabs.tabBar().ButtonPosition.RightSide, None)

        # 브로드캐스트 툴바 (§7.4): 실수 위험이 커서 토글 + 대상 수 상시 표시
        self.bcast = QCheckBox("브로드캐스트")
        self.bcast.setToolTip("체크한 터미널 탭 전부에 같은 입력을 보냅니다")
        self.bcast_n = QLabel("")
        self.bcast_n.setObjectName("muted")
        self._tab_corner = QWidget(self.tabs)
        cl = QHBoxLayout(self._tab_corner)
        cl.setContentsMargins(4, 0, 8, 0)
        cl.addWidget(self.bcast)
        cl.addWidget(self.bcast_n)
        self.tabs.setCornerWidget(self._tab_corner, Qt.Corner.TopRightCorner)
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([280, 1080])
        splitter.setHandleWidth(1)
        self.setCentralWidget(splitter)

        self.dashboard.start_scan_requested.connect(self._start_scan)
        self.dashboard.filter_by_status.connect(self._jump_to_result_status)
        self.dashboard.filter_by_rule.connect(self._jump_to_result_rule)
        self.scan.start_requested.connect(self._run_scan)
        self.scan.cancel_requested.connect(self.controller.cancel)
        self.scan.retry_requested.connect(self._retry_failed)
        self.result.export_requested.connect(self._export)
        self.scan.dryrun_requested.connect(self._dry_run)
        self.result.exception_requested.connect(self._edit_exception)
        self.result.open_terminal.connect(lambda hid: self._open_terminal_by_id(hid))
        self.result.open_file.connect(self._open_file_by_id)
        self.result.open_rule.connect(self._open_rule)
        self.controller.host_key_bridge.changed_request.connect(self._on_host_key_changed)
        self.manual.verdict_saved.connect(self._save_verdict)

        self.sb_hosts = QLabel("")
        self.statusBar().addWidget(self.sb_hosts)
        pk = f"{self.pack.name} {self.pack.version}" if self.pack else "(룰팩 없음)"
        self.statusBar().addPermanentWidget(QLabel(f"룰팩 {pk} · 엔진 {self._engine_version()}"))
        self.titlebar.set_subtitle(f"v{self._engine_version()} · {pk}")

    def _wire_controller(self) -> None:
        c = self.controller
        c.scan_started.connect(lambda sid: self._set_scanning(True))
        c.scan_progress.connect(self._on_scan_progress)
        c.scan_finished.connect(self._on_scan_finished)
        c.host_started.connect(lambda hid: self.model.set_state(hid, "running"))
        c.host_stage.connect(self._on_host_stage)
        c.host_progress.connect(self._on_host_progress)
        c.host_result.connect(self._on_host_result)
        c.host_failed.connect(lambda hid, msg: self.model.set_state(hid, "failed"))

    # --------------------------------------------------------------- 자산 CRUD
    def _refresh_assets(self) -> None:
        hosts = self.ctx.assets.all()
        self.model.rebuild(hosts, self.filter.text())
        self.tree.expandAll()
        self.sb_hosts.setText(f"자산 {len(hosts)}대")
        self._update_card()
        if hasattr(self, "multi"):
            self.multi.set_hosts(hosts)

    # ------------------------------------------------------------ 동적 그룹
    def _fill_groups(self) -> None:
        self.groups.blockSignals(True)
        self.groups.clear()
        self.groups.addItem("동적 그룹…", "")
        for g in self.ctx.config.get("asset_groups") or []:
            self.groups.addItem(f"{g.get('name')}  ({g.get('query')})", g.get("query", ""))
        self.groups.blockSignals(False)

    def _apply_group(self, _i: int) -> None:
        q = self.groups.currentData()
        if q:
            self.filter.setText(q)
            self.tree.selectAll()          # 그룹 = 필터 결과 전부 선택 → 바로 "선택 호스트 진단"

    def _save_group(self) -> None:
        from PySide6.QtWidgets import QInputDialog
        q = self.filter.text().strip()
        if not q:
            QMessageBox.information(self, "동적 그룹", "먼저 필터에 쿼리를 입력하세요. 예: os=linux env=PROD")
            return
        name, ok = QInputDialog.getText(self, "동적 그룹 저장", f"쿼리: {q}\n그룹 이름:")
        if not ok or not name.strip():
            return
        groups = [g for g in (self.ctx.config.get("asset_groups") or []) if g.get("name") != name.strip()]
        groups.append({"name": name.strip(), "query": q})
        self.ctx.config["asset_groups"] = groups
        config.save(self.ctx.config)
        self._fill_groups()
        self.groups.setCurrentIndex(self.groups.count() - 1)

    def _delete_group(self) -> None:
        q = self.groups.currentData()
        if not q:
            return
        self.ctx.config["asset_groups"] = [g for g in (self.ctx.config.get("asset_groups") or []) if g.get("query") != q]
        config.save(self.ctx.config)
        self._fill_groups()

    def _selected_hosts(self) -> list[Host]:
        """선택된 호스트. 고객사/분류 노드를 고르면 그 아래 호스트 전부(다건 진단). 중복 제거, 트리 순서 유지."""
        ids: list[str] = []

        def walk(idx) -> None:  # noqa: ANN001
            hid = idx.data(HOST_ID_ROLE)
            if hid:
                if hid not in ids:
                    ids.append(hid)
                return
            m = idx.model()
            for r in range(m.rowCount(idx)):
                walk(m.index(r, 0, idx))

        for idx in self.tree.selectionModel().selectedIndexes():
            if idx.column() == 0:
                walk(idx)
        hosts = [self.ctx.assets.get(h) for h in ids]
        return [h for h in hosts if h]

    def _start_scan_all(self) -> None:
        self.tree.selectAll()
        self._start_scan()

    def _param_hints(self) -> list[dict]:
        """룰팩의 모든 번들이 선언한 파라미터(중복 제거) — 자산 편집 힌트용."""
        seen: dict[str, dict] = {}
        for b in (self.pack.bundles.values() if self.pack else []):
            for p in b.params:
                seen.setdefault(str(p.get("name")), {**p, "bundle": b.id})
        return list(seen.values())

    def _add_asset(self) -> None:
        dlg = AssetEditDialog(parent=self, param_hints=self._param_hints())
        if dlg.exec():
            self.ctx.assets.upsert(dlg.host())
            self._refresh_assets()

    def _edit_selected(self, index) -> None:  # noqa: ANN001
        hid = index.data(HOST_ID_ROLE)
        if not hid:
            return
        host = self.ctx.assets.get(hid)
        if not host:
            return
        dlg = AssetEditDialog(host, parent=self, param_hints=self._param_hints())
        if dlg.exec():
            self.ctx.assets.upsert(dlg.host())
            self._refresh_assets()

    def _tree_menu(self, pos) -> None:  # noqa: ANN001
        from PySide6.QtWidgets import QMenu
        idx = self.tree.indexAt(pos)
        hid = idx.data(HOST_ID_ROLE) if idx.isValid() else None
        m = QMenu(self)
        if hid:
            host = self.ctx.assets.get(hid)
            if host:
                m.addAction("터미널 열기", lambda: self._open_terminal(host))
                m.addAction("파일 브라우저 열기", lambda: self._open_sftp(host))
                m.addSeparator()
                m.addAction("▶ 이 호스트 진단", self._start_scan)
                m.addAction("편집", lambda: self._edit_selected(idx))
                m.addAction("삭제", lambda: self._delete_host(host))
                m.addSeparator()
        m.addAction("+ 자산 추가", self._add_asset)
        m.exec(self.tree.viewport().mapToGlobal(pos))

    def _delete_host(self, host: Host) -> None:
        if QMessageBox.question(self, "자산 삭제", f"{host.label} ({host.address}) 을 삭제할까요?") \
                == QMessageBox.StandardButton.Yes:
            self.ctx.assets.delete(host.host_id)
            self._refresh_assets()

    # ------------------------------------------------------------ 터미널 · SFTP
    def _ensure_cred(self, host: Host):  # noqa: ANN202
        """세션에 없으면 입력받는다. 취소 시 None."""
        if self.ctx.creds.is_locked:
            self.ctx.creds.unlock()
        cred = self.ctx.creds.get(host.cred_id)
        if cred is None:
            dlg = CredPromptDialog(host.cred_id, host.username, parent=self)
            if not dlg.exec():
                return None
            self._put_cred(dlg.credential(), host, dlg.apply_project.isChecked())
            cred = self.ctx.creds.get(host.cred_id)
            self._update_cred_label()
        return cred

    def _put_cred(self, cred, host: Host, apply_project: bool) -> None:  # noqa: ANN001
        """세션에 넣는다. apply_project 면 같은 고객사·같은 계정의 다른 호스트 cred_id 에도 복제(메모리만)."""
        import dataclasses
        self.ctx.creds.put(cred)
        if not apply_project:
            return
        for h in self.ctx.assets.all():
            if h.project == host.project and h.username == host.username and h.cred_id != host.cred_id \
                    and h.cred_id not in self.ctx.creds.ids():
                self.ctx.creds.put(dataclasses.replace(cred, cred_id=h.cred_id))

    def _open_terminal(self, host: Host) -> None:
        cred = self._ensure_cred(host)
        if cred is None:
            return
        if not self._notice_shown:
            QMessageBox.information(self, "터미널 보안 경계", TERMINAL_NOTICE)
            self._notice_shown = True
        page = TerminalPage(host, cred, self.controller.host_key_bridge.ask,
                            self.ctx.workspace.layout.logs / "terminal",
                            record=bool(self.ctx.config.get("terminal_recording", True)),
                            changed=self.controller.host_key_bridge.ask_changed)
        page.broadcast_input.connect(lambda b, src=page: self._broadcast(b, src))
        page.broadcast.toggled.connect(self._update_bcast_label)
        self._terminals.append(page)
        i = self.tabs.addTab(page, f"● {host.label}")
        self.tabs.setCurrentIndex(i)
        page.state_changed.connect(lambda st, p=page: self._tab_state(p, st))
        self._tab_state(page, "connecting")
        self._update_bcast_label()

    _TAB_STATE = {"connecting": ("●", "#D29922"), "connected": ("●", "#2EA043"), "idle": ("●", "#8B949E"),
                  "closed": ("○", "#6E7681"), "error": ("●", "#F85149")}

    def _tab_state(self, page: QWidget, state: str) -> None:
        """터미널 탭에 상태 점(연결 중·연결됨·유휴·종료·오류)."""
        i = self.tabs.indexOf(page)
        if i < 0:
            return
        dot, color = self._TAB_STATE.get(state, ("●", "#8B949E"))
        label = getattr(page, "host", None)
        self.tabs.setTabText(i, f"{dot} {label.label if label else ''}")
        from PySide6.QtGui import QColor
        self.tabs.tabBar().setTabTextColor(i, QColor(color))

    def _open_sftp(self, host: Host, start_path: str | None = None, open_file: str | None = None) -> None:
        cred = self._ensure_cred(host)
        if cred is None:
            return
        page = SftpPage(host, cred, self.controller.host_key_bridge.ask, self.ctx.workspace.layout,
                        start_path=start_path, changed=self.controller.host_key_bridge.ask_changed)
        if open_file:
            page.open_on_connect(open_file)
        self._sftps.append(page)
        i = self.tabs.addTab(page, f"파일 · {host.label}")
        self.tabs.setCurrentIndex(i)

    def _broadcast(self, data: bytes, src: TerminalPage) -> None:
        if not self.bcast.isChecked():
            return
        for t in self._terminals:
            if t is not src and t.broadcast.isChecked():
                t.send(data)

    def _update_bcast_label(self) -> None:
        n = sum(1 for t in self._terminals if t.broadcast.isChecked())
        self.bcast_n.setText(f"대상 {n}개 탭" if n else "")

    def _close_tab(self, i: int) -> None:
        if i < self.FIXED_TABS:
            return
        w = self.tabs.widget(i)
        self.tabs.removeTab(i)
        if isinstance(w, TerminalPage):
            w.shutdown()
            self._terminals.remove(w)
            self._update_bcast_label()
        elif isinstance(w, SftpPage):
            w.shutdown()
            self._sftps.remove(w)
        w.deleteLater()

    def _shutdown_sessions(self) -> None:
        """터미널·SFTP 세션을 전부 닫는다. 로그 파일 핸들이 sanitize 를 막지 않게 먼저 호출."""
        for t in list(self._terminals):
            t.shutdown()
        for s in list(self._sftps):
            s.shutdown()
        for i in range(self.tabs.count() - 1, self.FIXED_TABS - 1, -1):
            w = self.tabs.widget(i)
            self.tabs.removeTab(i)
            w.deleteLater()
        self._terminals.clear()
        self._sftps.clear()
        self._update_bcast_label()

    def _save_library(self, entries: list) -> None:
        self.ctx.config["command_library"] = entries
        config.save(self.ctx.config)

    def _on_settings_saved(self, values: dict) -> None:
        self.ctx.config.update(values)
        self.scan.concurrency.setValue(int(values.get("concurrency", 5)))
        self.scan.timeout.setValue(int(values.get("default_timeout", 1800)))
        self.statusBar().showMessage("설정 저장됨 (config.json)", 3000)

    def _import_assets(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "자산 가져오기", "", "JSON (*.json)")
        if not path:
            return
        import json
        try:
            data = json.loads(open(path, encoding="utf-8").read())
            rows = data if isinstance(data, list) else [data]
            for row in rows:
                self.ctx.assets.upsert(Host.model_validate(row))
            self._refresh_assets()
            QMessageBox.information(self, "가져오기", f"{len(rows)}건 반영")
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "가져오기 실패", str(e))

    # ------------------------------------------------------------------ 스캔
    def _start_scan(self) -> None:
        hosts = self._selected_hosts()
        if not hosts:
            QMessageBox.information(self, "진단", "사이드바에서 대상 호스트를 선택하세요.")
            return
        self.scan.set_targets(hosts)
        self._pending_hosts = hosts
        self.tabs.setCurrentWidget(self.scan)

    def _run_scan(self, concurrency: int, timeout: int) -> None:
        hosts = getattr(self, "_pending_hosts", None) or self._selected_hosts()
        if not hosts:
            return
        # 세션에 없는 크리덴셜만 입력받는다. 같은 cred_id 는 한 번만.
        needed: dict[str, Host] = {}
        for h in hosts:
            if h.cred_id not in self.ctx.creds.ids() and h.cred_id not in needed:
                needed[h.cred_id] = h
        if self.ctx.creds.is_locked:
            self.ctx.creds.unlock()
        for cred_id, h in needed.items():
            if cred_id in self.ctx.creds.ids():        # 앞선 일괄 적용으로 이미 채워졌을 수 있다
                continue
            dlg = CredPromptDialog(cred_id, h.username, parent=self)
            if not dlg.exec():
                QMessageBox.information(self, "진단", "크리덴셜 입력이 취소되어 중단합니다.")
                return
            self._put_cred(dlg.credential(), h, dlg.apply_project.isChecked())
        self._update_cred_label()

        if self.pack is None or not self.pack.runnable:
            QMessageBox.warning(self, "룰팩", "실행 가능한 룰팩이 없습니다. 룰팩 탭의 문제 목록을 확인하세요.")
            return
        pid = self.scan.current_profile()
        profile = self.pack.profiles.get(pid or "")
        if profile is None:
            QMessageBox.information(self, "진단", "프로파일을 선택하세요.")
            return
        jobs = []
        for h in hosts:
            cred = self.ctx.creds.get(h.cred_id)
            if cred is None:
                continue
            # 호스트별 파라미터(TOMCAT_HOME 등)가 다르므로 job 도 호스트별로 만든다
            jobs.append((h, cred, build_job(self.pack, profile, timeout=timeout, host_params=h.params,
                                            preflight=self.scan.preflight.isChecked())))

        self._scan_id = new_scan_id()
        self.ctx.results.start_scan(ScanResult(
            scan_id=self._scan_id, engine_version=self._engine_version(),
            rule_pack_version=f"{self.pack.name} {self.pack.version}", rule_pack_sha256=self.pack.sha256,
            profile=profile.id, started_at=datetime.now(),
        ))
        self.scan.begin([h for h, _, _ in jobs])
        self._stages.clear()
        self._pcts.clear()
        self.controller.start(
            jobs, scan_id=self._scan_id, store=self.ctx.results,
            local_root=self.ctx.workspace.layout.scan_dir(self._scan_id),
            concurrency=concurrency,
        )

    def _on_host_stage(self, host_id: str, stage: str) -> None:
        self._stages[host_id] = stage
        self.scan.on_stage(host_id, stage)
        self._refresh_running()

    def _on_host_progress(self, host_id: str, done: int, total: int) -> None:
        self._pcts[host_id] = int(done / total * 100) if total else 0
        self.scan.on_progress(host_id, done, total)
        self._refresh_running()

    def _on_host_result(self, host_id: str, host: HostResult) -> None:
        self.scan.on_result(host_id, host)
        state = "warn" if (host.error or any(r.status is Status.FAIL for r in host.results)) else "connected"
        self.model.set_state(host_id, state)
        # 트리 배지 요약 되쓰기
        stored = self.ctx.assets.get(host_id)
        if stored:
            stored.last_summary = {k.value: v for k, v in host.summary().items()}
            stored.last_scan_id = self._scan_id
            self.ctx.assets.upsert(stored)
        self._stages[host_id] = "완료"
        self._pcts[host_id] = 100
        self._refresh_running()

    def _on_scan_progress(self, done: int, total: int) -> None:
        self.sb_hosts.setText(f"진단 {done}/{total}")

    def _baseline_for(self, scan: ScanResult) -> ScanResult | None:
        """같은 호스트를 하나라도 포함한 직전 진단(전회 대비 표시용). 없으면 None."""
        names = {h.hostname for h in scan.hosts}
        for sid, _meta in self.ctx.results.list_scans():
            if sid == scan.scan_id:
                continue
            prev = self.ctx.results.load_scan(sid)
            if prev and names & {h.hostname for h in prev.hosts}:
                return prev
        return None

    def _show_results(self, scan: ScanResult) -> None:
        self.result.set_baseline(self._baseline_for(scan))
        if self.pack:
            self.result.set_guide(self.pack.guide)
            self.result.set_rule_shas(self.pack.rule_shas)
        self.result.load(scan)
        self.result.set_exceptions(self.ctx.assets.exception_map())

    # ------------------------------------------------------------ 호스트 카드 · 링크
    def _update_card(self) -> None:
        hosts = self._selected_hosts()
        if len(hosts) != 1:
            self.card.clear()
            return
        h = hosts[0]
        os_text = profile = last_at = None
        summary = None
        if h.last_scan_id:
            hr = self.ctx.results.get_host(h.last_scan_id, h.host_id)
            if hr is not None:
                env = hr.environment
                os_text = " ".join(x for x in (env.os, env.os_version) if x) or None
                summary = {k.value: v for k, v in hr.summary().items()}
            meta = dict(self.ctx.results.list_scans()).get(h.last_scan_id) or {}
            profile = meta.get("profile")
            last_at = (meta.get("started_at") or "")[:16].replace("T", " ") or None
        self.card.show_host(h, os_text=os_text, profile=profile, last_at=last_at, summary=summary)

    def _card_action(self, action: str, host_id: str) -> None:
        host = self.ctx.assets.get(host_id)
        if host is None:
            return
        if action == "scan":
            self._start_scan()
        elif action == "terminal":
            self._open_terminal(host)
        elif action == "sftp":
            self._open_sftp(host)
        elif action == "discovery":
            self._run_discovery(host)
        elif action == "results" and host.last_scan_id:
            scan = self.ctx.results.load_scan(host.last_scan_id)
            if scan:
                self._scan_id = scan.scan_id
                self._show_results(scan)
                self.result.host_f.setCurrentIndex(max(0, self.result.host_f.findData(host.label)))
                self.tabs.setCurrentWidget(self.result)

    def _run_discovery(self, host: Host) -> None:
        from infraguard.ui.discovery_dialog import DiscoveryDialog
        cred = self.ctx.creds.get(host.cred_id) if not self.ctx.creds.is_locked else None
        dlg = DiscoveryDialog(host, cred, self.pack, self.controller.host_key_bridge, parent=self)
        if dlg.exec():
            disc = dlg.result_discovery()
            if disc is not None:
                host.discovered = disc
                self.ctx.assets.upsert(host)
                self._refresh_assets()
            pid = dlg.chosen_profile()
            if pid and self.pack and pid in self.pack.profiles:
                it = self.model.find_host_item(host.host_id)
                if it is not None:
                    self.tree.setCurrentIndex(it.index())
                self._start_scan()
                i = self.scan.profile.findData(pid)
                if i >= 0:
                    self.scan.profile.setCurrentIndex(i)

    def _open_terminal_by_id(self, host_id: str) -> None:
        host = self.ctx.assets.get(host_id)
        if host is None:
            QMessageBox.information(self, "터미널", "이 결과의 호스트가 자산 목록에 없습니다(삭제됨 또는 가져온 세션).")
            return
        self._open_terminal(host)

    def _open_file_by_id(self, host_id: str, path: str) -> None:
        import posixpath
        host = self.ctx.assets.get(host_id)
        if host is None:
            QMessageBox.information(self, "파일", "이 결과의 호스트가 자산 목록에 없습니다.")
            return
        self._open_sftp(host, start_path=posixpath.dirname(path) or "/", open_file=path)

    def _open_rule(self, rule_id: str) -> None:
        self.tabs.setCurrentWidget(self.rulepack)
        if not self.rulepack.select_rule(rule_id):
            QMessageBox.information(self, "룰", f"{rule_id} 는 현재 룰팩의 네이티브 룰이 아닙니다(번들 파싱 항목).")

    def _edit_exception(self, host_id: str, rule_id: str, label: str) -> None:
        from infraguard.ui.dialogs import ExceptionDialog
        cur = self.ctx.assets.get_exception(host_id, rule_id)
        if cur and QMessageBox.question(
            self, "예외", f"{label}\n이미 예외가 있습니다({cur.label()}). 수정할까요? (아니오=예외 해제)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No | QMessageBox.StandardButton.Cancel,
        ) == QMessageBox.StandardButton.No:
            self.ctx.assets.remove_exception(host_id, rule_id)
            self.result.set_exceptions(self.ctx.assets.exception_map())
            return
        dlg = ExceptionDialog(host_id, rule_id, label, cur, parent=self)
        if dlg.exec():
            self.ctx.assets.set_exception(dlg.exception())
            self.result.set_exceptions(self.ctx.assets.exception_map())

    def _rulepack_meta(self) -> dict:
        return {"name": self.pack.name, "version": self.pack.version, "sha256": self.pack.sha256} if self.pack else {}

    def _export_session(self) -> None:
        from infraguard.workspace import package
        default = str(self.ctx.workspace.layout.exports / f"session_{datetime.now():%Y%m%d_%H%M}.zip")
        path, _ = QFileDialog.getSaveFileName(self, "진단 세션 내보내기", default, "*.zip")
        if not path:
            return
        from pathlib import Path
        try:
            package.export_session(Path(path), assets=self.ctx.assets, results=self.ctx.results,
                                   engine_version=self._engine_version(), rulepack=self._rulepack_meta(),
                                   audit_dir=self.ctx.workspace.layout.logs)
            self._unexported = False
            QMessageBox.information(self, "세션 내보내기", f"저장됨: {path}\n(크리덴셜은 포함되지 않습니다)")
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "세션 내보내기 실패", str(e))

    def _import_session(self) -> None:
        from infraguard.workspace import package
        path, _ = QFileDialog.getOpenFileName(self, "진단 세션 가져오기", "", "*.zip")
        if not path:
            return
        from pathlib import Path
        try:
            s = package.import_session(Path(path), assets=self.ctx.assets, results=self.ctx.results,
                                       audit_dir=self.ctx.workspace.layout.logs)
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "세션 가져오기 실패", str(e))
            return
        self._refresh_assets()
        self._refresh_dashboard()
        rp = s.session.get("rulepack") or {}
        note = ""
        if self.pack and rp.get("sha256") and rp["sha256"] != self.pack.sha256:
            note = f"\n⚠ 패키지 룰팩 {rp.get('name')} {rp.get('version')} ≠ 현재 룰팩(SHA 불일치)"
        QMessageBox.information(self, "세션 가져오기",
                                f"호스트 {s.hosts} · 진단 {s.scans} · 예외 {s.exceptions} · 감사기록 {s.audit_files}"
                                + (f"\n무시된 멤버 {len(s.skipped)}" if s.skipped else "") + note)

    def _dry_run(self) -> None:
        hosts = getattr(self, "_pending_hosts", None) or self._selected_hosts()
        if self.pack is None:
            return
        profile = self.pack.profiles.get(self.scan.current_profile() or "")
        if profile is None:
            QMessageBox.information(self, "실행 계획", "프로파일을 선택하세요.")
            return
        from collections import Counter

        from infraguard.orchestrator import dryrun
        counts = Counter(h.platform for h in hosts) or Counter({"linux": 0})
        text = dryrun.render([dryrun.plan(self.pack, profile, p) for p in counts], hosts_by_platform=dict(counts))
        self._show_text("실행 계획 (dry-run) — " + profile.name, text)

    def _show_text(self, title: str, text: str) -> None:
        from PySide6.QtWidgets import QDialog, QDialogButtonBox, QPlainTextEdit, QVBoxLayout
        d = QDialog(self)
        d.setWindowTitle(title)
        d.resize(900, 600)
        lay = QVBoxLayout(d)
        ed = QPlainTextEdit(text)
        ed.setReadOnly(True)
        ed.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)      # 명령 목록은 줄바꿈 대신 가로 스크롤
        ed.setStyleSheet("font-family: Consolas, 'Malgun Gothic', monospace;")
        lay.addWidget(ed)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(d.reject)
        lay.addWidget(bb)
        d.exec()

    def _retry_failed(self) -> None:
        """실패·미완료 호스트만 같은 scan_id 로 다시. 완료된 호스트의 체크포인트는 그대로."""
        ids = self.scan.pending_or_failed()
        hosts = [h for h in (self.ctx.assets.get(i) for i in ids) if h]
        if not hosts or not self._scan_id or self.pack is None:
            return
        profile = self.pack.profiles.get(self.scan.current_profile() or "")
        if profile is None:
            return
        jobs = []
        for h in hosts:
            cred = self.ctx.creds.get(h.cred_id)
            if cred is None:
                QMessageBox.information(self, "재진단", f"{h.label}: 세션에 크리덴셜이 없습니다. '진단 시작'으로 다시 입력하세요.")
                return
            jobs.append((h, cred, build_job(self.pack, profile, host_params=h.params)))
        self.scan.begin(hosts)
        self._set_scanning(True)
        self.controller.start(jobs, scan_id=self._scan_id, store=self.ctx.results,
                              local_root=self.ctx.workspace.layout.scan_dir(self._scan_id),
                              concurrency=int(self.ctx.config.get("concurrency", 5)))

    def _on_scan_finished(self, scan: ScanResult) -> None:
        self._set_scanning(False)
        self._unexported = True
        self.scan.finished()
        self._show_results(scan)
        self.manual.load(scan)
        self._refresh_dashboard(scan)
        self._refresh_assets()
        QMessageBox.information(
            self, "진단 완료",
            f"{scan.scan_id} — 호스트 {len(scan.hosts)}대 완료. 결과 탭에서 확인하세요.",
        )

    def _refresh_running(self) -> None:
        rows = []
        for hid, stage in self._stages.items():
            if stage == "완료":
                continue
            host = self.ctx.assets.get(hid)
            rows.append((host.label if host else hid, stage, self._pcts.get(hid, 0)))
        self.dashboard.set_progress(rows)

    # ---------------------------------------------------------------- 호스트키
    def _on_host_key(self, host: str, key_type: str, fp: str) -> None:
        dlg = HostKeyDialog(host, key_type, fp, parent=self)
        self.controller.host_key_bridge.answer(bool(dlg.exec()))

    def _on_host_key_changed(self, host: str, key_type: str, old_fp: str, new_fp: str) -> None:
        dlg = HostKeyDialog(host, key_type, new_fp, changed=True, old_fingerprint=old_fp, parent=self)
        self.controller.host_key_bridge.answer(bool(dlg.exec()))

    # ---------------------------------------------------------------- 수동확인
    def _save_verdict(self, host_id: str, rule_id: str, status: str, note: str, batch: bool) -> None:
        if not self._scan_id:
            return
        targets = [(host_id, rule_id)]
        if batch:
            scan = self.ctx.results.load_scan(self._scan_id)
            if scan:
                for h in scan.hosts:
                    for r in h.results:
                        if r.rule_id == rule_id and r.status is Status.UNKNOWN and h.host_id != host_id:
                            targets.append((h.host_id, rule_id))
        for hid, rid in targets:
            self.ctx.results.set_verdict(self._scan_id, hid, rid, status, note)
        scan = self.ctx.results.load_scan(self._scan_id)
        self.manual.load(scan)
        self._show_results(scan)
        self._refresh_dashboard(scan)
        self._unexported = True

    # ------------------------------------------------------------------ 내보내기
    def _export(self, fmt: str) -> None:
        if not self._scan_id:
            QMessageBox.information(self, "내보내기", "내보낼 진단 결과가 없습니다.")
            return
        scan = self.ctx.results.load_scan(self._scan_id)
        if not scan:
            return
        # 리포트 품질 게이트 — 통과 못 해도 막지 않는다. 사실을 보여주고 사용자가 고른다.
        from infraguard.result import gate
        rem = self.pack.remediation_map() if self.pack else {}
        exc = self.ctx.assets.exception_map()
        items = gate.run(scan, pack_sha256=self.pack.sha256 if self.pack else None, remediation=rem,
                         db_ok=self.ctx.results.integrity_ok(), exceptions=exc,
                         rule_shas=self.pack.rule_shas if self.pack else None)
        if not gate.passed(items) and QMessageBox.question(
            self, "리포트 품질 검사", "\n".join(i.line() for i in items) + "\n\n그래도 내보낼까요?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        ext = "xlsx" if fmt == "xlsx" else "html"
        default = str(self.ctx.workspace.layout.exports / f"{scan.scan_id}.{ext}")
        path, _ = QFileDialog.getSaveFileName(self, "내보내기", default, f"*.{ext}")
        if not path:
            return
        from pathlib import Path
        try:
            crit = self.pack.criteria_map() if self.pack else {}
            base = self._baseline_for(scan)
            purpose = self.pack.purpose_map() if self.pack else {}
            if fmt == "xlsx":
                xlsx_report.build(scan, Path(path), rem, crit, baseline=base, exceptions=exc, purpose=purpose)
            else:
                html_report.build(scan, Path(path), rem, crit, baseline=base, exceptions=exc, purpose=purpose)
            self._unexported = False
            QMessageBox.information(self, "내보내기", f"저장됨: {path}")
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "내보내기 실패", str(e))

    # ------------------------------------------------------------------ 대시보드
    def _refresh_dashboard(self, scan: ScanResult | None = None) -> None:
        if scan is None and self._scan_id:
            scan = self.ctx.results.load_scan(self._scan_id)
        if scan is None:
            recent = self.ctx.results.list_scans()
            if recent:
                scan = self.ctx.results.load_scan(recent[0][0])
        summ = scan.summary() if scan else {s: 0 for s in Status}
        self.dashboard.update_counts(summ)
        sev = {Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}
        host_rows: list[tuple[str, dict[Status, int]]] = []
        if scan:
            for h in scan.hosts:
                host_rows.append((h.hostname, h.summary()))
                for r in h.results:
                    if r.status is Status.FAIL and r.severity:
                        sev[r.severity] += 1
        self.dashboard.update_severity(sev[Severity.HIGH], sev[Severity.MEDIUM], sev[Severity.LOW])
        self.dashboard.update_risk(_risk.summary(scan) if scan else {})
        self.dashboard.update_hosts(host_rows)
        base = self._baseline_for(scan) if scan else None
        self.dashboard.update_fix(_diff.summary(_diff.diff(scan, base)) if scan and base else None,
                                  base.scan_id if base else None)
        self.dashboard.update_top(scan)
        self.dashboard.set_progress([])
        self.dashboard.set_recent(self.ctx.results.list_scans())

    def _jump_to_result_rule(self, rule_id: str) -> None:
        self.result.search.setText(rule_id)
        self.tabs.setCurrentWidget(self.result)

    def _jump_to_result_status(self, status: Status) -> None:
        self.result.set_status_filter(status)
        self.tabs.setCurrentWidget(self.result)

    # ------------------------------------------------------------------ 상태
    def _set_scanning(self, on: bool) -> None:
        self._scanning = on

    def _update_cred_label(self) -> None:
        n = len(self.ctx.creds.ids()) if not self.ctx.creds.is_locked else 0
        self.cred_lbl.setText(f"● 크리덴셜 {n}건 (메모리)" if n else "● 크리덴셜 잠김")
        self.cred_lbl.setStyleSheet("color:#3FB950" if n else "color:#8B949E")

    def _engine_version(self) -> str:
        from infraguard import ENGINE_VERSION
        return ENGINE_VERSION

    # ------------------------------------------------------------------ 정리·종료
    def _sanitize_now(self) -> None:
        if QMessageBox.question(
            self, "완전삭제", "작업공간(assets.db·결과·로그)을 모두 삭제합니다. 계속할까요?"
        ) != QMessageBox.StandardButton.Yes:
            return
        self._shutdown_sessions()
        self.ctx.creds.lock()
        rep = self.ctx.workspace.sanitize()
        if rep.clean:
            QMessageBox.information(self, "완전삭제", "삭제 완료. 잔류물 없음.")
        else:
            QMessageBox.warning(
                self, "잔류물 발견",
                "다음 경로가 남았습니다:\n" + "\n".join(rep.leftovers + rep.errors),
            )
        self.ctx.workspace.create()
        self._scan_id = None
        self._unexported = False
        self.result.load(None)
        self.manual.load(None)
        self._refresh_assets()
        self._refresh_dashboard()
        self.settings.refresh_usage()

    # ------------------------------------------------------------ 프레임리스 리사이즈
    def _edges(self, pos) -> Qt.Edge:  # noqa: ANN001
        if self.isMaximized():
            return Qt.Edge(0)
        return edges_at(pos, self.width(), self.height(), self.RESIZE_MARGIN)

    def mouseMoveEvent(self, e) -> None:  # noqa: N802,ANN001
        edges = self._edges(e.position().toPoint())
        self.setCursor(CURSORS.get(edges, Qt.CursorShape.ArrowCursor))
        super().mouseMoveEvent(e)

    def mousePressEvent(self, e) -> None:  # noqa: N802,ANN001
        edges = self._edges(e.position().toPoint())
        if e.button() == Qt.MouseButton.LeftButton and edges and self.windowHandle() is not None:
            self.windowHandle().startSystemResize(edges)
            return
        super().mousePressEvent(e)

    def closeEvent(self, event) -> None:  # noqa: N802
        gate = exit_gate(ExitState(scanning=self._scanning, unexported=self._unexported))
        if gate == CONFIRM_SCANNING:
            if QMessageBox.question(
                self, "종료", "진단이 진행 중입니다. 중단하고 종료할까요?"
            ) != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.controller.cancel()
        wipe = bool(self.ctx.config.get("sanitize_on_exit", True))
        if gate == WARN_UNEXPORTED and wipe:
            resp = QMessageBox.question(
                self, "종료", "아직 내보내지 않은 결과가 있습니다.\n"
                "종료하면 작업공간이 완전삭제됩니다(설정 → 작업공간에서 끌 수 있음).\n"
                "파일 → 진단 세션 내보내기(zip) 로 남길 수 있습니다.\n\n삭제하고 종료할까요? (아니오=취소)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if resp != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
        self._shutdown_sessions()
        self.ctx.creds.lock()
        if wipe:
            rep = self.ctx.workspace.sanitize()
            if not rep.clean:
                QMessageBox.warning(
                    self, "잔류물", "삭제되지 않은 경로:\n" + "\n".join(rep.leftovers + rep.errors),
                )
        else:
            self.ctx.workspace.close_all()        # 삭제 없이 DB 핸들만 정리 — 다음 실행에 결과·자산 유지
        event.accept()

    def _about(self) -> None:
        QMessageBox.information(
            self, "InfraGuard",
            f"InfraGuard {self._engine_version()}\n인프라 진단 실행·표준화 플랫폼\n폐쇄망 전용 · 무잔류",
        )
