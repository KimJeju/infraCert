"""메인 윈도 — Nav Rail(왼쪽) + 워크스페이스(QStackedWidget). 상단 메뉴는 시스템 메뉴만.

정보 구조(docs/UI_재설계.md): 개요 / 자산 / 진단 / 결과 / 보고서 — 룰팩 / 터미널 / SFTP / 멀티실행 / 수동확인 — 설정.
기능·엔진·데이터 모델은 그대로. 파괴적 동작(완전삭제)은 상시 버튼이 아니라 파일 → 세션 종료 다이얼로그에서만.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QFileDialog,
    QInputDialog,
    QLabel,
    QMainWindow,
    QMessageBox,
    QSplitter,
    QStackedWidget,
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
from infraguard.ui.exit_dialog import SessionEndDialog
from infraguard.ui.exit_flow import CONFIRM_SCANNING, WARN_UNEXPORTED, ExitState, exit_gate
from infraguard.ui.models_qt import HOST_ID_ROLE
from infraguard.ui.nav import NavRail
from infraguard.ui.pages.assets import AssetsPage
from infraguard.ui.pages.dashboard import DashboardPage
from infraguard.ui.pages.manual import ManualBenchPage
from infraguard.ui.pages.multiexec import MultiExecPage
from infraguard.ui.pages.reports import ReportsPage
from infraguard.ui.pages.result import ResultPage
from infraguard.ui.pages.rulepack import RulePackPage
from infraguard.ui.pages.scan import AUTO, ScanPage
from infraguard.ui.pages.sessions import SessionTabs
from infraguard.ui.pages.settings import SettingsPage
from infraguard.ui.pages.sftp import SftpPage
from infraguard.ui.palette import Command, CommandPalette
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
    PAGES = ("overview", "assets", "scan", "findings", "reports", "rulepack", "terminal", "sftp", "multiexec",
             "manual", "settings")

    def __init__(self, ctx: AppContext) -> None:
        super().__init__()
        self.ctx = ctx
        self.setWindowTitle("InfraGuard")
        self.setObjectName("root")
        self.resize(1365, 860)
        self.setMinimumSize(1280, 720)
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
        self._retried_once = False

        self.controller = ScanController()
        self.controller.host_key_bridge.request.connect(self._on_host_key)
        self.pack: RulePack | None = self._load_rulepack()

        self._build_menu()
        self._build_body()
        self._wire_controller()
        self._build_palette()
        self._refresh_assets()
        self._refresh_dashboard()
        self._refresh_profiles()
        self._refresh_reports()
        self.show_page("overview")

    # ---------------------------------------------------------------- 룰팩
    def _load_rulepack(self, name: str | None = None) -> RulePack | None:
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
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "룰팩 가져오기 실패", str(e))
            return
        msg = f"{dest.name}: 번들 {len(pack.bundles)} · 네이티브 {len(pack.native)} · 가이드 {len(pack.guide)}항목"
        if not pack.runnable:
            msg += f"\n⚠ 문제 {len(pack.problems)}건 — 실행 차단 (룰팩 화면에서 확인)"
        QMessageBox.information(self, "룰팩 가져오기", msg)
        self._switch_rulepack(dest.name)

    def _build_rulepack(self, bundles: list, native: list) -> None:
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
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "룰팩 zip 실패", str(e))
            return
        QMessageBox.information(
            self, "룰팩 zip",
            f"저장됨: {path}\n번들 {st['bundles']} · 네이티브 룰 {st['native']} · 항목 메타 {st['rules_meta']} · 가이드 {st['guide']}",
        )

    def _export_rulepack(self) -> None:
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
        if self.pack is None:
            return
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
        pk = f"{self.pack.name} {self.pack.version}" if self.pack else "(룰팩 없음)"
        ok = "✓ 검증됨" if (self.pack and self.pack.runnable) else "✗ 문제"
        self.sb_pack.setText(f"룰팩 {pk} {ok}")
        self.titlebar.set_subtitle(f"v{self._engine_version()} · {pk}")

    # ---------------------------------------------------------------- 구성
    def _build_menu(self) -> None:
        self.titlebar = TitleBar("INFRAGUARD", self)
        mb = self.menuBar()
        self._top = QWidget(self)
        from PySide6.QtWidgets import QVBoxLayout
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
        m_file.addAction("세션 종료 및 완전삭제…", self._end_session)
        m_file.addAction("종료", self.close)
        m_view = mb.addMenu("보기")
        for key, label in (("overview", "개요"), ("assets", "자산"), ("scan", "진단"), ("findings", "결과"),
                           ("reports", "보고서")):
            m_view.addAction(label, lambda k=key: self.show_page(k))
        m_view.addSeparator()
        m_view.addAction("명령 검색 (Ctrl+K)", self._open_palette)
        m_tools = mb.addMenu("도구")
        m_tools.addAction("Discovery (선택 호스트)", self._discovery_selected)
        m_tools.addAction("멀티실행", lambda: self.show_page("multiexec"))
        m_tools.addAction("룰팩", lambda: self.show_page("rulepack"))
        m_tools.addSeparator()
        m_tools.addAction("지금 완전삭제…", self._sanitize_now)
        mb.addMenu("도움말").addAction("정보", self._about)

        self._menu_corner = QWidget(mb)
        from PySide6.QtWidgets import QHBoxLayout
        cl = QHBoxLayout(self._menu_corner)
        cl.setContentsMargins(0, 0, 12, 0)
        self.cred_lbl = QLabel("● 크리덴셜 잠김")
        self.cred_lbl.setStyleSheet("color:#8B949E")
        cl.addWidget(self.cred_lbl)
        mb.setCornerWidget(self._menu_corner, Qt.Corner.TopRightCorner)

    def _build_body(self) -> None:
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.nav = NavRail()
        self.nav.selected.connect(self.show_page)
        splitter.addWidget(self.nav)
        self.stack = QStackedWidget()
        splitter.addWidget(self.stack)
        splitter.setStretchFactor(1, 1)
        splitter.setHandleWidth(0)
        splitter.setCollapsible(0, False)
        self.setCentralWidget(splitter)

        self.dashboard = DashboardPage()
        self.assets_page = AssetsPage()
        self.scan = ScanPage()
        self.result = ResultPage()
        self.reports = ReportsPage()
        self.rulepack = RulePackPage()
        self.terminals = SessionTabs("terminal", "열린 터미널이 없습니다. 자산 화면 → 호스트 → [터미널], 또는 결과의 [터미널]")
        self.sftps = SessionTabs("sftp", "열린 SFTP 세션이 없습니다. 자산 화면 → 호스트 → [SFTP], 또는 결과의 [파일 열기]")
        self.multi = MultiExecPage(self._ensure_cred, self.controller.host_key_bridge.ask,
                                   self.controller.host_key_bridge.ask_changed,
                                   self.ctx.workspace.layout.logs / "multiexec",
                                   user_entries=list(self.ctx.config.get("command_library") or []))
        self.manual = ManualBenchPage()
        pk_label = f"{self.pack.name} {self.pack.version}" if self.pack else "(없음)"
        self.settings = SettingsPage(self.ctx.config, self.ctx.workspace.layout, self._engine_version(), pk_label)
        self._pages: dict[str, QWidget] = {
            "overview": self.dashboard, "assets": self.assets_page, "scan": self.scan, "findings": self.result,
            "reports": self.reports, "rulepack": self.rulepack, "terminal": self.terminals, "sftp": self.sftps,
            "multiexec": self.multi, "manual": self.manual, "settings": self.settings,
        }
        for key in self.PAGES:
            self.stack.addWidget(self._pages[key])

        # 자산 탐색기(테스트·기존 코드 호환: tree/model/filter 별칭)
        self.tree = self.assets_page.tree
        self.model = self.assets_page.model
        self.filter = self.assets_page.filter
        self.assets_page.filter_changed.connect(lambda _t: self._refresh_assets())
        self.assets_page.group_apply.connect(self._apply_group)
        self.assets_page.group_save.connect(self._save_group)
        self.assets_page.group_delete.connect(self._delete_group)
        self.assets_page.add_requested.connect(self._add_asset)
        self.assets_page.import_requested.connect(self._import_assets)
        self.assets_page.edit_requested.connect(self._edit_selected)
        self.assets_page.context_menu.connect(self._tree_menu)
        self.assets_page.detail.action.connect(self._card_action)
        self.tree.selectionModel().selectionChanged.connect(lambda *_a: self._update_card())
        self._fill_groups()

        self.dashboard.start_scan_requested.connect(self._start_scan)
        self.dashboard.filter_by_status.connect(self._jump_to_result_status)
        self.dashboard.filter_by_rule.connect(self._jump_to_result_rule)
        self.dashboard.open_finding.connect(self._jump_to_finding)
        self.scan.start_requested.connect(self._run_scan)
        self.scan.cancel_requested.connect(self.controller.cancel)
        self.scan.retry_requested.connect(self._retry_failed)
        self.scan.dryrun_requested.connect(self._dry_run)
        self.scan.add_targets_requested.connect(self._add_targets)
        self.scan.view_results_requested.connect(lambda: self.show_page("findings"))
        self.scan.profile_changed.connect(self._update_profile_card)
        self.scan.rule_detail_requested.connect(self._show_profile_rules)
        self.result.export_requested.connect(self._export)
        self.result.exception_requested.connect(self._edit_exception)
        self.result.open_terminal.connect(self._open_terminal_by_id)
        self.result.open_file.connect(self._open_file_by_id)
        self.result.open_rule.connect(self._open_rule)
        self.result.rescan_host.connect(self._rescan_host)
        self.result.manual_requested.connect(lambda: self.show_page("manual"))
        self.reports.export_requested.connect(self._export)
        self.reports.scan_selected.connect(self._select_scan)
        self.reports.session_export_requested.connect(self._export_session)
        self.reports.session_import_requested.connect(self._import_session)
        self.rulepack.profiles_changed.connect(self._refresh_profiles)
        self.rulepack.import_requested.connect(self._import_rulepack)
        self.rulepack.build_requested.connect(self._build_rulepack)
        self.rulepack.export_requested.connect(self._export_rulepack)
        self.rulepack.delete_requested.connect(self._delete_rulepack)
        self.rulepack.pack_selected.connect(self._switch_rulepack)
        self.rulepack.diff_requested.connect(self._diff_rulepack)
        self.terminals.close_requested.connect(self._close_session)
        self.sftps.close_requested.connect(self._close_session)
        self.terminals.count_changed.connect(lambda n: self.nav.set_badge("terminal", f"({n})" if n else ""))
        self.sftps.count_changed.connect(lambda n: self.nav.set_badge("sftp", f"({n})" if n else ""))
        self.multi.library_changed.connect(self._save_library)
        self.manual.verdict_saved.connect(self._save_verdict)
        self.settings.saved.connect(self._on_settings_saved)
        self.settings.sanitize_requested.connect(self._sanitize_now)
        self.controller.host_key_bridge.changed_request.connect(self._on_host_key_changed)

        self.sb_pack = QLabel("")
        self.sb_hosts = QLabel("")
        self.sb_session = QLabel("")
        sb = self.statusBar()
        sb.addWidget(self.sb_pack)
        sb.addWidget(QLabel("  ·  "))
        sb.addWidget(self.sb_hosts)
        sb.addWidget(QLabel("  ·  "))
        sb.addWidget(self.sb_session)
        sb.addPermanentWidget(QLabel(f"엔진 {self._engine_version()}"))
        self._update_session_status()

    def show_page(self, key: str) -> None:
        w = self._pages.get(key)
        if w is None:
            return
        self.stack.setCurrentWidget(w)
        self.nav.set_current(key)
        if key == "reports":
            self._refresh_reports()

    def current_page(self) -> str:
        for k, w in self._pages.items():
            if w is self.stack.currentWidget():
                return k
        return ""

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

    # ---------------------------------------------------------------- 팔레트 (Ctrl+K)
    def _build_palette(self) -> None:
        cmds = [
            Command("이동", "개요", lambda: self.show_page("overview"), "overview dashboard"),
            Command("이동", "자산", lambda: self.show_page("assets"), "assets hosts"),
            Command("이동", "진단", lambda: self.show_page("scan"), "scan diagnosis"),
            Command("이동", "결과", lambda: self.show_page("findings"), "findings results"),
            Command("이동", "보고서", lambda: self.show_page("reports"), "report export"),
            Command("이동", "룰팩", lambda: self.show_page("rulepack"), "rulepack rules"),
            Command("이동", "터미널", lambda: self.show_page("terminal"), "terminal ssh"),
            Command("이동", "SFTP", lambda: self.show_page("sftp"), "sftp files"),
            Command("이동", "멀티실행", lambda: self.show_page("multiexec"), "multi exec"),
            Command("이동", "수동확인 워크벤치", lambda: self.show_page("manual"), "manual"),
            Command("이동", "설정", lambda: self.show_page("settings"), "settings config"),
            Command("진단", "선택 자산 진단", self._start_scan, "scan selected"),
            Command("진단", "모든 자산 진단", self._start_scan_all, "scan all"),
            Command("진단", "실패 자산 재진단", self._retry_failed, "retry failed"),
            Command("진단", "Discovery 실행 (선택 호스트)", self._discovery_selected, "discovery ports"),
            Command("진단", "실행 계획 확인 (dry-run)", self._dry_run, "dry run plan"),
            Command("분석", "취약만 보기", lambda: self._jump_to_result_status(Status.FAIL), "vuln filter"),
            Command("분석", "수동확인만 보기", lambda: self._jump_to_result_status(Status.UNKNOWN), "manual filter"),
            Command("분석", "이전 진단과 비교 (변경만)", self._show_changed_only, "diff compare baseline"),
            Command("도구", "터미널 열기 (선택 호스트)", self._terminal_selected, "terminal open"),
            Command("도구", "SFTP 열기 (선택 호스트)", self._sftp_selected, "sftp open"),
            Command("도구", "보고서 생성 (XLSX)", lambda: self._export("xlsx"), "export xlsx report"),
            Command("도구", "보고서 생성 (HTML)", lambda: self._export("html"), "export html report"),
            Command("도구", "진단 세션 내보내기(zip)", self._export_session, "session export"),
            Command("자산", "자산 추가", self._add_asset, "add host"),
            Command("자산", "자산 가져오기(JSON)", self._import_assets, "import hosts"),
            Command("시스템", "세션 종료 및 완전삭제…", self._end_session, "exit wipe sanitize"),
        ]
        self.palette = CommandPalette(cmds, providers=[self._search_assets, self._search_rules, self._search_findings],
                                      parent=self)
        QShortcut(QKeySequence("Ctrl+K"), self, self._open_palette)
        QShortcut(QKeySequence("Ctrl+P"), self, self._open_palette)

    def _open_palette(self) -> None:
        self.palette.open()

    def _search_assets(self, q: str) -> list[Command]:
        ql = q.lower()
        out = []
        for h in self.ctx.assets.all():
            if ql in f"{h.label} {h.address} {h.project} {h.group} {h.role}".lower():
                out.append(Command("자산", f"{h.label}  ({h.address} · {h.project}/{h.group})",
                                   lambda hid=h.host_id: self._select_host(hid), h.address))
        return out[:10]

    def _search_rules(self, q: str) -> list[Command]:
        if not self.pack:
            return []
        ql = q.lower()
        out = []
        for rid, meta in self.pack.rules.items():
            if ql in f"{rid} {meta.name}".lower():
                out.append(Command("룰", f"{rid}  {meta.name}", lambda r=rid: self._open_rule(r), meta.category))
        return out[:10]

    def _search_findings(self, q: str) -> list[Command]:
        if not self._scan_id:
            return []
        scan = self.ctx.results.load_scan(self._scan_id)
        if not scan:
            return []
        ql = q.lower()
        out = []
        for h in scan.hosts:
            for r in h.results:
                if r.status is Status.FAIL and ql in f"{r.rule_id} {r.name} {h.hostname}".lower():
                    out.append(Command("취약점", f"✗ {r.rule_id} {h.hostname}  {r.name}",
                                       lambda hn=h.hostname, rid=r.rule_id: self._jump_to_finding(hn, rid)))
        return out[:10]

    # ---------------------------------------------------------------- 자산
    def _refresh_assets(self) -> None:
        hosts = self.ctx.assets.all()
        self.model.rebuild(hosts, self.filter.text())
        self.tree.expandAll()
        self.sb_hosts.setText(f"자산 {len(hosts)}대")
        self._update_card()
        if hasattr(self, "multi"):
            self.multi.set_hosts(hosts)

    def _fill_groups(self) -> None:
        self.assets_page.set_groups(self.ctx.config.get("asset_groups") or [])

    def _apply_group(self, q: str) -> None:
        if q:
            self.filter.setText(q)
            self.tree.selectAll()

    def _save_group(self) -> None:
        q = self.filter.text().strip()
        if not q:
            QMessageBox.information(self, "동적 그룹", "먼저 검색칸에 쿼리를 입력하세요. 예: os=linux env=PROD")
            return
        name, ok = QInputDialog.getText(self, "동적 그룹 저장", f"쿼리: {q}\n그룹 이름:")
        if not ok or not name.strip():
            return
        groups = [g for g in (self.ctx.config.get("asset_groups") or []) if g.get("name") != name.strip()]
        groups.append({"name": name.strip(), "query": q})
        self.ctx.config["asset_groups"] = groups
        config.save(self.ctx.config)
        self._fill_groups()

    def _delete_group(self, q: str) -> None:
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

    def _select_host(self, host_id: str) -> None:
        it = self.model.find_host_item(host_id)
        if it is None:
            self.filter.clear()
            self._refresh_assets()
            it = self.model.find_host_item(host_id)
        if it is not None:
            self.tree.setCurrentIndex(it.index())
        self.show_page("assets")

    def _start_scan_all(self) -> None:
        self.tree.selectAll()
        self._start_scan()

    def _param_hints(self) -> list[dict]:
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
                m.addAction("▶ 진단", self._start_scan)
                m.addAction("Discovery", lambda: self._run_discovery(host))
                m.addAction("터미널", lambda: self._open_terminal(host))
                m.addAction("SFTP", lambda: self._open_sftp(host))
                m.addSeparator()
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

    def _update_card(self) -> None:
        hosts = self._selected_hosts()
        detail = self.assets_page.detail
        if len(hosts) != 1:
            detail.clear(len(hosts))
            return
        h = hosts[0]
        os_text = profile = last_at = None
        summary = None
        recent: list[str] = []
        if h.last_scan_id:
            hr = self.ctx.results.get_host(h.last_scan_id, h.host_id)
            if hr is not None:
                env = hr.environment
                os_text = " ".join(x for x in (env.os, env.os_version) if x) or None
                summary = {k.value: v for k, v in hr.summary().items()}
                recent = [r.rule_id for r in hr.results if r.status is Status.FAIL]
            meta = dict(self.ctx.results.list_scans()).get(h.last_scan_id) or {}
            profile = meta.get("profile")
            last_at = (meta.get("started_at") or "")[:16].replace("T", " ") or None
        detail.show_host(h, os_text=os_text, profile=profile, last_at=last_at, summary=summary, recent_vulns=recent)

    def _card_action(self, action: str, host_id: str) -> None:
        host = self.ctx.assets.get(host_id) if host_id else None
        if action == "scan":
            self._start_scan()
            return
        if host is None:
            return
        if action == "terminal":
            self._open_terminal(host)
        elif action == "sftp":
            self._open_sftp(host)
        elif action == "discovery":
            self._run_discovery(host)
        elif action == "edit":
            it = self.model.find_host_item(host.host_id)
            if it is not None:
                self._edit_selected(it.index())
        elif action == "results" and host.last_scan_id:
            scan = self.ctx.results.load_scan(host.last_scan_id)
            if scan:
                self._scan_id = scan.scan_id
                self._show_results(scan)
                self.result.host_f.setCurrentIndex(max(0, self.result.host_f.findData(host.label)))
                self.show_page("findings")

    def _discovery_selected(self) -> None:
        hosts = self._selected_hosts()
        if len(hosts) != 1:
            QMessageBox.information(self, "Discovery", "자산 화면에서 호스트 한 대를 선택하세요.")
            return
        self._run_discovery(hosts[0])

    def _terminal_selected(self) -> None:
        hosts = self._selected_hosts()
        if hosts:
            self._open_terminal(hosts[0])

    def _sftp_selected(self) -> None:
        hosts = self._selected_hosts()
        if hosts:
            self._open_sftp(hosts[0])

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
                self._select_host(host.host_id)
                self._start_scan()
                i = self.scan.profile.findData(pid)
                if i >= 0:
                    self.scan.profile.setCurrentIndex(i)

    # ---------------------------------------------------------------- 크리덴셜 · 세션
    def _ensure_cred(self, host: Host):  # noqa: ANN202
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
        page.broadcast.setText("동시 입력 참여")
        self._terminals.append(page)
        self.terminals.add(page, f"● {host.label}")
        page.state_changed.connect(lambda st, p=page: self.terminals.set_state(p, st, p.host.label))
        self.terminals.set_state(page, "connecting", host.label)
        self._update_bcast_label()
        self.show_page("terminal")

    def _open_sftp(self, host: Host, start_path: str | None = None, open_file: str | None = None) -> None:
        cred = self._ensure_cred(host)
        if cred is None:
            return
        page = SftpPage(host, cred, self.controller.host_key_bridge.ask, self.ctx.workspace.layout,
                        start_path=start_path, changed=self.controller.host_key_bridge.ask_changed)
        if open_file:
            page.open_on_connect(open_file)
        self._sftps.append(page)
        self.sftps.add(page, f"파일 · {host.label}")
        self.show_page("sftp")

    def _broadcast(self, data: bytes, src: TerminalPage) -> None:
        if not self.terminals.multi.isChecked():
            return
        for t in self._terminals:
            if t is not src and t.broadcast.isChecked():
                t.send(data)

    def _update_bcast_label(self) -> None:
        self.terminals.set_multi_count(sum(1 for t in self._terminals if t.broadcast.isChecked()))

    def _close_session(self, w: QWidget) -> None:
        if isinstance(w, TerminalPage):
            self.terminals.remove(w)
            w.shutdown()
            if w in self._terminals:
                self._terminals.remove(w)
            self._update_bcast_label()
        elif isinstance(w, SftpPage):
            self.sftps.remove(w)
            w.shutdown()
            if w in self._sftps:
                self._sftps.remove(w)
        w.deleteLater()

    def _shutdown_sessions(self) -> None:
        for t in list(self._terminals):
            self._close_session(t)
        for s in list(self._sftps):
            self._close_session(s)

    def _save_library(self, entries: list) -> None:
        self.ctx.config["command_library"] = entries
        config.save(self.ctx.config)

    def _on_settings_saved(self, values: dict) -> None:
        self.ctx.config.update(values)
        self.scan.concurrency.setValue(int(values.get("concurrency", 5)))
        self.scan.timeout.setValue(int(values.get("default_timeout", 1800)))
        self.statusBar().showMessage("설정 저장됨 (config.json)", 3000)

    # ---------------------------------------------------------------- 진단
    def _start_scan(self) -> None:
        hosts = self._selected_hosts()
        if not hosts:
            self.show_page("scan")
            if not self.scan.target_hosts():
                self._add_targets()
            return
        self.scan.set_targets(hosts)
        self.show_page("scan")

    def _add_targets(self) -> None:
        """자산 목록에서 체크해 대상에 추가."""
        from PySide6.QtWidgets import (
            QDialog,
            QDialogButtonBox,
            QListWidget,
            QListWidgetItem,
            QVBoxLayout,
        )
        hosts = self.ctx.assets.all()
        if not hosts:
            QMessageBox.information(self, "대상 추가", "자산이 없습니다. 자산 화면에서 추가하세요.")
            self.show_page("assets")
            return
        d = QDialog(self)
        d.setWindowTitle("자산에서 대상 추가")
        d.resize(520, 480)
        lay = QVBoxLayout(d)
        lst = QListWidget()
        have = {h.host_id for h in self.scan.target_hosts()}
        for h in sorted(hosts, key=lambda x: (x.project, x.group, x.label)):
            it = QListWidgetItem(f"{h.label}   {h.address}  [{h.platform}]  {h.project}/{h.group}")
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(Qt.CheckState.Checked if h.host_id in have else Qt.CheckState.Unchecked)
            it.setData(Qt.ItemDataRole.UserRole, h.host_id)
            lst.addItem(it)
        lay.addWidget(lst)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(d.accept)
        bb.rejected.connect(d.reject)
        lay.addWidget(bb)
        if d.exec():
            ids = [lst.item(i).data(Qt.ItemDataRole.UserRole) for i in range(lst.count())
                   if lst.item(i).checkState() == Qt.CheckState.Checked]
            self.scan.set_targets([h for h in hosts if h.host_id in ids])

    def _auto_profile_for(self, host: Host) -> str | None:
        """Auto Detect: Discovery 결과 → 추천, 없으면 플랫폼 기본."""
        if not self.pack:
            return None
        from infraguard.orchestrator import discovery
        d = discovery.Discovery()
        disc = host.discovered or {}
        d.ports = {int(k): v for k, v in (disc.get("ports") or {}).items()}
        d.services = list(disc.get("services") or [])
        rec = discovery.recommend_profiles(d, host.platform, list(self.pack.profiles))
        return rec[0] if rec else None

    def _profiles_for_targets(self, hosts: list[Host]) -> dict[str, str | None]:
        pid = self.scan.current_profile()
        if pid == AUTO:
            return {h.host_id: self._auto_profile_for(h) for h in hosts}
        return {h.host_id: pid for h in hosts}

    def _update_profile_card(self, _pid: str = "") -> None:
        hosts = self.scan.target_hosts()
        if not self.pack:
            self.scan.set_profile_card("룰팩 없음")
            return
        pid = self.scan.current_profile()
        if pid == AUTO:
            per = self._profiles_for_targets(hosts)
            from collections import Counter
            c = Counter(v or "(추천 없음)" for v in per.values())
            lines = "<br>".join(f"{k} &nbsp;<span style='color:#7D8794'>{n}대</span>" for k, n in c.most_common())
            total = sum(len(self.pack.profiles[p].native) + sum(len(self.pack.bundles[b].provides)
                        for b in self.pack.profiles[p].bundles if b in self.pack.bundles)
                        for p in c if p in self.pack.profiles)
            self.scan.set_profile_card(f"<b>Auto Detect</b><br>{lines or '대상을 추가하면 추천'}",
                                       f"예상 진단 항목 {total} rules (호스트별 프로파일)" if hosts else "")
        else:
            p = self.pack.profiles.get(pid or "")
            if p is None:
                self.scan.set_profile_card("프로파일을 선택하세요")
                return
            kind = "SCRIPT BUNDLE" if p.bundles and not p.native else ("NATIVE" if p.native and not p.bundles else "BUNDLE + NATIVE")
            n_native = len(p.native)
            n_bundle = sum(len(self.pack.bundles[b].provides) for b in p.bundles if b in self.pack.bundles)
            manual = sum(1 for r in p.native if r in self.pack.manual_rules())
            self.scan.set_profile_card(
                f"<b>{p.name}</b><br><span style='color:#7D8794;letter-spacing:1px'>{kind}</span><br>"
                f"{n_native + n_bundle} items &nbsp; <span style='color:#3FB950'>✓ {n_native + n_bundle - manual} 자동</span>"
                + (f" &nbsp; <span style='color:#D29922'>? {manual} 수동</span>" if manual else ""),
                p.description or "")
        rules = 0
        for h in hosts:
            pp = self._profiles_for_targets([h]).get(h.host_id)
            if pp and pp in self.pack.profiles:
                pr = self.pack.profiles[pp]
                rules += len(pr.native) + sum(len(self.pack.bundles[b].provides) for b in pr.bundles if b in self.pack.bundles)
        ok = "✓ Verified" if self.pack.runnable else "✗ 문제"
        self.scan.set_summary(
            f"Rulepack <b>{self.pack.name} {self.pack.version}</b> &nbsp; SHA-256 {ok}<br>"
            f"예상 대상 <b>{len(hosts)}</b> hosts &nbsp;·&nbsp; 예상 Rule <b>{rules}</b> &nbsp;·&nbsp; 실행 방식 <b>Read-only</b>")

    def _show_profile_rules(self, pid: str) -> None:
        self.show_page("rulepack")
        if pid and pid != AUTO:
            i = self.rulepack.profile.findData(pid)
            if i >= 0:
                self.rulepack.profile.setCurrentIndex(i)

    def _run_scan(self, concurrency: int, timeout: int) -> None:
        hosts = self.scan.target_hosts()
        if not hosts:
            QMessageBox.information(self, "진단", "① 대상에 자산을 추가하세요.")
            return
        if self.pack is None or not self.pack.runnable:
            QMessageBox.warning(self, "룰팩", "실행 가능한 룰팩이 없습니다. 룰팩 화면의 문제 목록을 확인하세요.")
            return
        per = self._profiles_for_targets(hosts)
        missing = [h.label for h in hosts if not per.get(h.host_id) or per[h.host_id] not in self.pack.profiles]
        if missing:
            QMessageBox.information(self, "진단", "프로파일을 정할 수 없는 호스트: " + ", ".join(missing[:6])
                                    + "\nDiscovery 를 돌리거나 프로파일을 직접 고르세요.")
            return
        needed: dict[str, Host] = {}
        for h in hosts:
            if h.cred_id not in self.ctx.creds.ids() and h.cred_id not in needed:
                needed[h.cred_id] = h
        if self.ctx.creds.is_locked:
            self.ctx.creds.unlock()
        for cred_id, h in needed.items():
            if cred_id in self.ctx.creds.ids():
                continue
            dlg = CredPromptDialog(cred_id, h.username, parent=self)
            if not dlg.exec():
                QMessageBox.information(self, "진단", "크리덴셜 입력이 취소되어 중단합니다.")
                return
            self._put_cred(dlg.credential(), h, dlg.apply_project.isChecked())
        self._update_cred_label()

        jobs = []
        for h in hosts:
            cred = self.ctx.creds.get(h.cred_id)
            if cred is None:
                continue
            profile = self.pack.profiles[per[h.host_id]]
            jobs.append((h, cred, build_job(self.pack, profile, timeout=timeout, host_params=h.params,
                                            preflight=self.scan.preflight.isChecked())))
        first = per[hosts[0].host_id] if hosts else None
        self._scan_id = new_scan_id()
        self._retried_once = False
        self.ctx.results.start_scan(ScanResult(
            scan_id=self._scan_id, engine_version=self._engine_version(),
            rule_pack_version=f"{self.pack.name} {self.pack.version}", rule_pack_sha256=self.pack.sha256,
            profile=first if len(set(per.values())) == 1 else "auto", started_at=datetime.now(),
        ))
        self._profile_per_host = {k: v for k, v in per.items() if v}
        self.scan.begin([h for h, _, _ in jobs], profiles=self._profile_per_host)
        self._stages.clear()
        self._pcts.clear()
        self.controller.start(
            jobs, scan_id=self._scan_id, store=self.ctx.results,
            local_root=self.ctx.workspace.layout.scan_dir(self._scan_id),
            concurrency=concurrency,
        )

    def _rescan_host(self, host_id: str) -> None:
        """결과 화면 [재진단]: 이 호스트만 같은 프로파일로 새 진단."""
        host = self.ctx.assets.get(host_id)
        if host is None:
            QMessageBox.information(self, "재진단", "이 결과의 호스트가 자산 목록에 없습니다.")
            return
        self.scan.set_targets([host])
        pid = (getattr(self, "_profile_per_host", {}) or {}).get(host_id)
        if pid:
            i = self.scan.profile.findData(pid)
            if i >= 0:
                self.scan.profile.setCurrentIndex(i)
        self.show_page("scan")
        self._run_scan(self.scan.concurrency.value(), self.scan.timeout.value())

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
        stored = self.ctx.assets.get(host_id)
        if stored:
            stored.last_summary = {k.value: v for k, v in host.summary().items()}
            stored.last_scan_id = self._scan_id
            self.ctx.assets.upsert(stored)
        self._stages[host_id] = "완료"
        self._pcts[host_id] = 100
        self._refresh_running()

    def _on_scan_progress(self, done: int, total: int) -> None:
        self.sb_session.setText(f"세션 ● 진단 중 {done}/{total}")

    def _retry_failed(self) -> None:
        ids = self.scan.pending_or_failed()
        hosts = [h for h in (self.ctx.assets.get(i) for i in ids) if h]
        if not hosts or not self._scan_id or self.pack is None:
            return
        per = getattr(self, "_profile_per_host", {}) or {}
        jobs = []
        for h in hosts:
            cred = self.ctx.creds.get(h.cred_id)
            profile = self.pack.profiles.get(per.get(h.host_id) or self.scan.current_profile() or "")
            if cred is None or profile is None:
                QMessageBox.information(self, "재진단", f"{h.label}: 세션에 크리덴셜/프로파일이 없습니다. '진단 시작'으로 다시.")
                return
            jobs.append((h, cred, build_job(self.pack, profile, host_params=h.params)))
        self.scan.begin(hosts, profiles=per)
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
        self._refresh_reports()
        failed = self.scan.pending_or_failed()
        if failed and self.scan.auto_retry.isChecked() and not self._retried_once:
            self._retried_once = True
            self.statusBar().showMessage(f"실패 {len(failed)}대 자동 재시도…", 4000)
            self._retry_failed()
            return
        if self.scan.auto_open.isChecked():
            self.show_page("findings")
        else:
            self.statusBar().showMessage(f"{scan.scan_id} — 호스트 {len(scan.hosts)}대 완료", 6000)

    def _refresh_running(self) -> None:
        rows = []
        for hid, stage in self._stages.items():
            if stage == "완료":
                continue
            host = self.ctx.assets.get(hid)
            rows.append((host.label if host else hid, stage, self._pcts.get(hid, 0)))
        self.dashboard.set_progress(rows)

    def _dry_run(self) -> None:
        hosts = self.scan.target_hosts() or self._selected_hosts()
        if self.pack is None:
            return
        from collections import Counter

        from infraguard.orchestrator import dryrun
        per = self._profiles_for_targets(hosts)
        plans = []
        counts = Counter((per.get(h.host_id), h.platform) for h in hosts)
        for pid, plat in counts:
            if pid and pid in self.pack.profiles:
                plans.append(dryrun.plan(self.pack, self.pack.profiles[pid], plat))
        if not plans:
            QMessageBox.information(self, "실행 계획", "대상과 프로파일을 먼저 정하세요.")
            return
        text = dryrun.render(plans, hosts_by_platform={pl.platform: sum(n for (pid, plat), n in counts.items() if plat == pl.platform) for pl in plans})
        self._show_text("실행 계획 (dry-run)", text)

    def _show_text(self, title: str, text: str) -> None:
        from PySide6.QtWidgets import QDialog, QDialogButtonBox, QPlainTextEdit, QVBoxLayout
        d = QDialog(self)
        d.setWindowTitle(title)
        d.resize(900, 600)
        lay = QVBoxLayout(d)
        ed = QPlainTextEdit(text)
        ed.setReadOnly(True)
        ed.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        ed.setStyleSheet("font-family: Consolas, 'Malgun Gothic', monospace;")
        lay.addWidget(ed)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(d.reject)
        lay.addWidget(bb)
        d.exec()

    # ---------------------------------------------------------------- 결과
    def _baseline_for(self, scan: ScanResult) -> ScanResult | None:
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
            self.result.set_remediation(self.pack.remediation_map())
            self.result.set_rule_shas(self.pack.rule_shas)
        self.result.load(scan)
        self.result.set_exceptions(self.ctx.assets.exception_map())
        self._update_session_status()

    def _select_scan(self, scan_id: str) -> None:
        scan = self.ctx.results.load_scan(scan_id)
        if scan:
            self._scan_id = scan_id
            self._show_results(scan)
            self.manual.load(scan)
            self._refresh_dashboard(scan)
            self._refresh_reports()

    def _show_changed_only(self) -> None:
        self.show_page("findings")
        if self.result.changed_only.isEnabled():
            self.result.changed_only.setChecked(True)

    def _jump_to_finding(self, hostname: str, rule_id: str) -> None:
        self.show_page("findings")
        self.result.search.clear()
        self.result.status_f.setCurrentIndex(0)
        self.result.host_f.setCurrentIndex(0)
        self.result.select_finding(hostname, rule_id)

    def _jump_to_result_rule(self, rule_id: str) -> None:
        self.result.search.setText(rule_id)
        self.show_page("findings")

    def _jump_to_result_status(self, status: Status) -> None:
        self.result.set_status_filter(status)
        self.show_page("findings")

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
        self.show_page("rulepack")
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

    # ---------------------------------------------------------------- 보고서 · 세션 패키지
    def _gate_items(self, scan: ScanResult) -> list:
        from infraguard.result import gate
        rem = self.pack.remediation_map() if self.pack else {}
        return gate.run(scan, pack_sha256=self.pack.sha256 if self.pack else None, remediation=rem,
                        db_ok=self.ctx.results.integrity_ok(), exceptions=self.ctx.assets.exception_map(),
                        rule_shas=self.pack.rule_shas if self.pack else None)

    def _refresh_reports(self) -> None:
        self.reports.set_scans(self.ctx.results.list_scans(), self._scan_id)
        scan = self.ctx.results.load_scan(self._scan_id) if self._scan_id else None
        self.reports.set_gate(self._gate_items(scan) if scan else [])

    def _export(self, fmt: str) -> None:
        if not self._scan_id:
            QMessageBox.information(self, "내보내기", "내보낼 진단 결과가 없습니다.")
            return
        scan = self.ctx.results.load_scan(self._scan_id)
        if not scan:
            return
        from infraguard.result import gate
        items = self._gate_items(scan)
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
            rem = self.pack.remediation_map() if self.pack else {}
            crit = self.pack.criteria_map() if self.pack else {}
            exc = self.ctx.assets.exception_map()
            base = self._baseline_for(scan)
            purpose = self.pack.purpose_map() if self.pack else {}
            if fmt == "xlsx":
                xlsx_report.build(scan, Path(path), rem, crit, baseline=base, exceptions=exc, purpose=purpose)
            else:
                html_report.build(scan, Path(path), rem, crit, baseline=base, exceptions=exc, purpose=purpose)
            self._unexported = False
            self._update_session_status()
            QMessageBox.information(self, "내보내기", f"저장됨: {path}")
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "내보내기 실패", str(e))

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
            self._update_session_status()
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
        self._refresh_reports()
        rp = s.session.get("rulepack") or {}
        note = ""
        if self.pack and rp.get("sha256") and rp["sha256"] != self.pack.sha256:
            note = f"\n⚠ 패키지 룰팩 {rp.get('name')} {rp.get('version')} ≠ 현재 룰팩(SHA 불일치)"
        QMessageBox.information(self, "세션 가져오기",
                                f"호스트 {s.hosts} · 진단 {s.scans} · 예외 {s.exceptions} · 감사기록 {s.audit_files}"
                                + (f"\n무시된 멤버 {len(s.skipped)}" if s.skipped else "") + note)

    # ---------------------------------------------------------------- 개요
    def _refresh_dashboard(self, scan: ScanResult | None = None) -> None:
        if scan is None and self._scan_id:
            scan = self.ctx.results.load_scan(self._scan_id)
        if scan is None:
            recent = self.ctx.results.list_scans()
            if recent:
                scan = self.ctx.results.load_scan(recent[0][0])
                if scan and not self._scan_id:      # 이전 실행의 마지막 결과를 결과·수동확인 화면에도 올린다
                    self._scan_id = scan.scan_id
                    self._show_results(scan)
                    self.manual.load(scan)
        self.dashboard.set_empty(scan is None)
        if scan is None:
            return
        summ = scan.summary()
        self.dashboard.update_counts(summ)
        sev = {Severity.HIGH: 0, Severity.MEDIUM: 0, Severity.LOW: 0}
        host_rows: list[tuple[str, dict[Status, int]]] = []
        for h in scan.hosts:
            host_rows.append((h.hostname, h.summary()))
            for r in h.results:
                if r.status is Status.FAIL and r.severity:
                    sev[r.severity] += 1
        self.dashboard.update_severity(sev[Severity.HIGH], sev[Severity.MEDIUM], sev[Severity.LOW])
        self.dashboard.update_risk(_risk.summary(scan))
        self.dashboard.update_hosts(host_rows)
        base = self._baseline_for(scan)
        dsum = _diff.summary(_diff.diff(scan, base)) if base else None
        self.dashboard.update_fix(dsum, base.scan_id if base else None)
        self.dashboard.update_top(scan)
        self.dashboard.update_todo(scan)
        self.dashboard.set_progress([])
        scans = self.ctx.results.list_scans()
        details = {}
        for sid, _m in scans[:8]:
            s = self.ctx.results.load_scan(sid)
            if s:
                sm = s.summary()
                n_rules = sum(len(h.results) for h in s.hosts)
                details[sid] = f"{len(s.hosts)}대 · {n_rules} rules · {sm[Status.FAIL]} VULN · " + \
                               ("완료" if s.finished_at else "미완료")
        self.dashboard.set_recent(scans, details)
        self.dashboard.set_kpi(len(self.ctx.assets.all()), scan.started_at.strftime("%Y-%m-%d %H:%M"),
                               summ[Status.FAIL], _diff.fix_rate(dsum) if dsum else None)

    # ---------------------------------------------------------------- 상태
    def _set_scanning(self, on: bool) -> None:
        self._scanning = on
        self._update_session_status()

    def _update_session_status(self) -> None:
        if self._scanning:
            txt = "세션 ● 진단 중"
        elif self._unexported:
            txt = "세션 ● 미반출 결과 있음"
        elif self._scan_id:
            txt = f"세션 ● {self._scan_id}"
        else:
            txt = "세션 ○ 진단 없음"
        self.sb_session.setText(txt)

    def _update_cred_label(self) -> None:
        n = len(self.ctx.creds.ids()) if not self.ctx.creds.is_locked else 0
        self.cred_lbl.setText(f"● 크리덴셜 {n}건 (메모리)" if n else "● 크리덴셜 잠김")
        self.cred_lbl.setStyleSheet("color:#3FB950" if n else "color:#8B949E")

    def _engine_version(self) -> str:
        from infraguard import ENGINE_VERSION
        return ENGINE_VERSION

    # ---------------------------------------------------------------- 정리·종료
    def _on_host_key(self, host: str, key_type: str, fp: str) -> None:
        dlg = HostKeyDialog(host, key_type, fp, parent=self)
        self.controller.host_key_bridge.answer(bool(dlg.exec()))

    def _on_host_key_changed(self, host: str, key_type: str, old_fp: str, new_fp: str) -> None:
        dlg = HostKeyDialog(host, key_type, new_fp, changed=True, old_fingerprint=old_fp, parent=self)
        self.controller.host_key_bridge.answer(bool(dlg.exec()))

    def _sanitize_now(self) -> None:
        if QMessageBox.question(
            self, "완전삭제", "작업공간(assets.db·결과·로그)을 모두 삭제합니다. 계속할까요?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        self._shutdown_sessions()
        self.ctx.creds.lock()
        rep = self.ctx.workspace.sanitize()
        if rep.clean:
            QMessageBox.information(self, "완전삭제", "삭제 완료. 잔류물 없음.")
        else:
            QMessageBox.warning(self, "잔류물 발견", "다음 경로가 남았습니다:\n" + "\n".join(rep.leftovers + rep.errors))
        self.ctx.workspace.create()
        self._scan_id = None
        self._unexported = False
        self.result.load(None)
        self.manual.load(None)
        self._refresh_assets()
        self._refresh_dashboard()
        self._refresh_reports()
        self.settings.refresh_usage()
        self._update_cred_label()
        self._update_session_status()

    def _end_session(self) -> None:
        """파일 → 세션 종료 및 완전삭제: 체크박스로 무엇을 지울지 명시하고 종료."""
        dlg = SessionEndDialog(unexported=self._unexported,
                               default_wipe=bool(self.ctx.config.get("sanitize_on_exit", True)), parent=self)
        if not dlg.exec():
            return
        self._exit_choice = (dlg.wipe_workspace, dlg.wipe_temp)
        self.close()

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
            if QMessageBox.question(self, "종료", "진단이 진행 중입니다. 중단하고 종료할까요?") \
                    != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self.controller.cancel()
        wipe = bool(self.ctx.config.get("sanitize_on_exit", True))
        choice = getattr(self, "_exit_choice", None)
        if choice is None and gate == WARN_UNEXPORTED and wipe:
            # 미반출 결과 + 완전삭제 기본값: 무엇을 지울지 확인받는다(결과를 잃는 사고 > 잔류물)
            dlg = SessionEndDialog(unexported=True, default_wipe=True, parent=self)
            if not dlg.exec():
                event.ignore()
                return
            choice = (dlg.wipe_workspace, dlg.wipe_temp)
        wipe_ws, wipe_tmp = choice if choice else (wipe, False)
        self._shutdown_sessions()
        self.ctx.creds.lock()
        if wipe_ws:
            rep = self.ctx.workspace.sanitize()
            if not rep.clean:
                QMessageBox.warning(self, "잔류물", "삭제되지 않은 경로:\n" + "\n".join(rep.leftovers + rep.errors))
        else:
            if wipe_tmp:
                import shutil
                for d in (self.ctx.workspace.layout.tmp, self.ctx.workspace.layout.artifacts):
                    shutil.rmtree(d, ignore_errors=True)
            self.ctx.workspace.close_all()
        event.accept()

    def _about(self) -> None:
        QMessageBox.information(
            self, "InfraGuard",
            f"InfraGuard {self._engine_version()}\n인프라 진단 실행·표준화 플랫폼\n폐쇄망 전용 · 무잔류\n\nCtrl+K: 명령 검색",
        )
